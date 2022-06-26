/* Stage 3. Fix virtual memory layout. Assign addresses to every Segment and OutSect. */

use anyhow::{bail, Result};
use vec_map::VecDict;

use crate::misc::Align;
use crate::misc::Permissions;
use crate::misc::{FileToken, OutSectToken, SegmentToken};
use crate::processing_stage_1::{Layout, PreprocessedFile};
use crate::processing_stage_2::{Symbol, SymbolOffset};
use crate::schemes::AddrScheme;

#[derive(Debug)]
pub struct FinalSegment {
    pub infile_size: u64,
    pub virtmem_size: u64,
    pub virtmem_address: u64,
    pub offset_in_output_file: u64,
    pub permissions: Permissions,
}

#[derive(Debug, Clone)]
pub struct SlotsOffset {
    pub progbits: u64,
    pub nobits: u64,
}

#[derive(Debug, Clone)]
pub struct FinalOutSect {
    pub progbits_size: u64,
    pub nobits_size: u64,
    pub input_file_slots_offsets: VecDict<FileToken, SlotsOffset>,
    pub progbits_virtmem_address: u64,
    pub nobits_virtmem_address: u64,
    pub offset_in_output_file: u64,
    pub permissions: Permissions,
}

#[derive(Debug)]
pub struct FinalLayout<'a> {
    pub layout: &'a Layout<'a>,
    pub final_segments: VecDict<SegmentToken, FinalSegment>,
    pub final_outsects: VecDict<OutSectToken, FinalOutSect>,
}

impl Symbol {
    pub fn get_symbol_address(&self, layout: &FinalLayout) -> u64 {
        match self.symbol_offset {
            SymbolOffset::ProgBits(token, offset) => {
                let outsect = &layout.final_outsects[&token];
                outsect.progbits_virtmem_address
                    + outsect.input_file_slots_offsets[&self.file_token].progbits
                    + offset
            }
            SymbolOffset::NoBits(token, offset) => {
                let outsect = &layout.final_outsects[&token];
                outsect.nobits_virtmem_address
                    + outsect.input_file_slots_offsets[&self.file_token].nobits
                    + offset
            }
        }
    }
}

type FinalOutSects = VecDict<OutSectToken, FinalOutSect>;

fn append_empty_outsects<'a>(
    layout: &'a Layout<'a>,
    preprocessed_files: &'a Vec<PreprocessedFile>,
) -> FinalOutSects {
    let files_count = preprocessed_files.capacity();
    let mut final_outsects = FinalOutSects::new(layout.outsect_count);

    let is_outsect_present_in_any_file = |token: &OutSectToken| -> bool {
        preprocessed_files
            .iter()
            .any(|file| file.outsects_this_file.contains_key(token))
    };

    let insert_empty_outsect = |token: OutSectToken| {
        final_outsects.insert(
            &token,
            FinalOutSect {
                progbits_size: 0,
                nobits_size: 0,
                input_file_slots_offsets: VecDict::new(files_count),
                progbits_virtmem_address: 0,
                nobits_virtmem_address: 0,
                offset_in_output_file: 0,
                permissions: Permissions::default(),
            },
        );
    };

    (0..layout.outsect_count)
        .map(OutSectToken)
        .filter(is_outsect_present_in_any_file)
        .for_each(insert_empty_outsect);

    final_outsects
}

fn append_input_file_slots<'a>(
    final_outsects: &mut FinalOutSects,
    preprocessed_files: &'a [PreprocessedFile],
) {
    for (outsect_token, outsect) in final_outsects.tok_iter_mut() {
        let mut relative_offset_progbits: u64 = 0;
        let mut relative_offset_nobits: u64 = 0;

        for file in preprocessed_files
            .iter()
            .filter(|file| file.outsects_this_file.contains_key(&outsect_token))
        {
            relative_offset_progbits.align_inplace(16); /* TODO: proper alignment */
            relative_offset_nobits.align_inplace(16); /* TODO: proper alignment */

            outsect.input_file_slots_offsets.insert(
                &file.token,
                SlotsOffset {
                    progbits: relative_offset_progbits,
                    nobits: relative_offset_nobits,
                },
            );

            relative_offset_progbits += file.outsects_this_file[&outsect_token].progbits;
            relative_offset_nobits += file.outsects_this_file[&outsect_token].nobits;
            outsect.permissions |= file.outsects_this_file[&outsect_token].permissions;
        }

        outsect.progbits_size = relative_offset_progbits;
        outsect.nobits_size = relative_offset_nobits;
    }
}

pub fn fix_layout<'a>(
    layout: &'a Layout<'a>,
    preprocessed_files: &'a Vec<PreprocessedFile>,
) -> Result<FinalLayout<'a>> {
    let mut final_outsects = append_empty_outsects(layout, preprocessed_files);
    append_input_file_slots(&mut final_outsects, preprocessed_files);

    let outsect_too_large_error = |abs_address| {
        bail!(
            "Cannot fit OutSects into LayoutScheme (cannot fit OutSects below \
             next OutSect {:#x} virtual address boundary)",
            abs_address
        );
    };

    let segment_count = layout.scheme.segments.len();
    let mut final_segments = VecDict::<SegmentToken, FinalSegment>::new(segment_count);

    let mut current_address = 0x0;
    let mut current_offset_in_file = crate::schemes::MAXPAGESIZE;

    let mut outsect_num = 0;

    for (index, segment) in layout.scheme.segment_iter().enumerate() {
        let token = SegmentToken(index);

        current_address = match segment.start {
            AddrScheme::Absolute(abs_address) => {
                if current_address > abs_address {
                    return outsect_too_large_error(abs_address);
                } else {
                    abs_address
                }
            }
            AddrScheme::CurrentLocation => current_address.align(segment.alignment),
        };

        current_offset_in_file.align_inplace(segment.alignment);

        let virtmem_address = current_address;
        let offset_in_output_file = current_offset_in_file;
        let mut any_outsect_present_in_segment = false;

        let mut segment_permissions = Permissions::default();
        let outsect_base = outsect_num;
        outsect_num += segment.sections.len();

        for (outsect_index, _) in segment.sections.iter().enumerate() {
            let token = OutSectToken(outsect_base + outsect_index);

            let next_outsect = match final_outsects.get_mut(&token) {
                Some(outsect) => {
                    any_outsect_present_in_segment = true;
                    outsect
                }
                None => continue,
            };

            if next_outsect.progbits_size != 0 {
                current_address.align_inplace(16); /* TODO: proper alignment */
                current_offset_in_file.align_inplace(16); /* TODO: proper alignment */

                next_outsect.progbits_virtmem_address = current_address;
                next_outsect.offset_in_output_file = current_offset_in_file;

                current_address += next_outsect.progbits_size;
                current_offset_in_file += next_outsect.progbits_size;
            }
        }

        for (outsect_index, _) in segment.sections.iter().enumerate() {
            let token = OutSectToken(outsect_base + outsect_index);

            let next_outsect = match final_outsects.get_mut(&token) {
                Some(outsect) => {
                    any_outsect_present_in_segment = true;
                    outsect
                }
                None => continue,
            };

            if next_outsect.nobits_size != 0 {
                current_address.align_inplace(16);
                next_outsect.nobits_virtmem_address = current_address;
                current_address += next_outsect.nobits_size;
            }

            segment_permissions |= next_outsect.permissions;
        }

        if any_outsect_present_in_segment {
            final_segments.insert(
                &token,
                FinalSegment {
                    infile_size: current_offset_in_file - offset_in_output_file,
                    virtmem_size: current_address - virtmem_address,
                    virtmem_address,
                    offset_in_output_file,
                    permissions: segment_permissions,
                },
            );
        }
    }

    Ok(FinalLayout {
        layout,
        final_segments,
        final_outsects,
    })
}
