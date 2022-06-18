/* Stage 3. Fix virtual memory array. Assign addresses to every Segment and OutSect. */

use std::io::Result as IoResult;
use std::io::{Error, ErrorKind};
use vec_map::VecDict;

use crate::misc::align;
use crate::misc::{FileToken, SegmentToken, OutSectToken};
use crate::schemes::AddrScheme;
use crate::processing_stage_1::{Layout, PreprocessedFile};
use crate::processing_stage_2::Symbol;


#[derive(Debug)]
pub struct FinalSegment {
    pub size: u64,
    pub virtmem_address: u64,
    pub offset_in_output_file: u64,
}

#[derive(Debug, Clone)]
pub struct FinalOutSect {
    pub size: u64,
    pub input_file_slots_offsets: VecDict<FileToken, u64>,
    pub virtmem_address: u64,
    pub offset_in_output_file: u64,
}

#[derive(Debug)]
pub struct FinalLayout<'a> {
    pub layout: &'a Layout<'a>,
    pub final_segments: VecDict<SegmentToken, FinalSegment>,
    pub final_outsects: VecDict<OutSectToken, FinalOutSect>,
}

impl Symbol {
    pub fn get_symbol_address(&self, layout: &FinalLayout) -> u64 {
        let Symbol {
            outsect_token,
            file_token,
            outsect_offset, /* outsec_offset == symbol offset + insect offset in outsect file par */
            visibility: _,
        } = self;

        let outsect = &layout.final_outsects[outsect_token];

        /* Address */
        outsect.virtmem_address + outsect.input_file_slots_offsets[file_token] + outsect_offset
    }
}

pub fn fix_layout<'a>(
    layout: &'a Layout<'a>,
    preprocessed_files: &'a Vec<PreprocessedFile>,
) -> IoResult<FinalLayout<'a>> {
    let files_count = preprocessed_files.len();
    let mut final_outsects = VecDict::<OutSectToken, FinalOutSect>::new(layout.outsect_count);

    for num in 0..layout.outsect_count {
        let token = OutSectToken(num);

        let is_present = preprocessed_files
            .iter()
            .any(|file| file.outsects_per_file_size.contains_key(&token));

        if is_present {
            final_outsects.insert(
                &token,
                FinalOutSect {
                    size: 0,
                    input_file_slots_offsets: VecDict::new(files_count),
                    virtmem_address: 0,
                    offset_in_output_file: 0,
                },
            );
        }
    }

    for (outsect_token, outsect) in final_outsects.tok_iter_mut() {
        let mut relative_offset: u64 = 0;

        for file in preprocessed_files.iter() {
            relative_offset = align(relative_offset, 16); /* TODO: proper alignment */
            outsect
                .input_file_slots_offsets
                .insert(&file.token, relative_offset);
            relative_offset += file
                .outsects_per_file_size
                .get(&outsect_token)
                .unwrap_or(&0);
        }

        outsect.size = relative_offset;
    }

    let segment_count = layout.scheme.segments.len();
    let mut final_segments = VecDict::<SegmentToken, FinalSegment>::new(segment_count);

    let mut current_address = 0x0;
    let mut current_offset_in_file = crate::schemes::MAXPAGESIZE;

    let mut outsects_iter = final_outsects.tok_iter_mut();

    for (index, segment) in layout.scheme.segment_iter().enumerate() {
        let token = SegmentToken(index);

        let file_to_large_error = |abs_address| {
            Err(Error::new(
                ErrorKind::FileTooLarge,
                format!(
                    "Cannot fit OutSects into LayoutScheme (cannot fit OutSects below \
                                 next OutSect {:#x} virtual address boundary)",
                    abs_address
                ),
            ))
        };

        current_address = match segment.start {
            AddrScheme::Absolute(abs_address) => {
                if current_address > abs_address {
                    return file_to_large_error(abs_address);
                } else {
                    abs_address
                }
            }
            AddrScheme::CurrentLocation => align(current_address, segment.alignment),
        };

        current_offset_in_file = align(current_offset_in_file, segment.alignment);

        let virtmem_address = current_address;
        let offset_in_output_file = current_offset_in_file;
        let mut any_outsect_present_in_segment = false;

        for _ in segment.sections {
            let next_outsect = match outsects_iter.next() {
                Some((_, outsect)) => {
                    any_outsect_present_in_segment = true;
                    outsect
                }
                None => continue,
            };

            current_address = align(current_address, 16); /* TODO: proper alignment */
            current_offset_in_file = align(current_offset_in_file, 16); /* TODO: proper alignment */

            next_outsect.virtmem_address = current_address;
            next_outsect.offset_in_output_file = current_offset_in_file;

            current_address += next_outsect.size;
            current_offset_in_file += next_outsect.size;
        }

        if any_outsect_present_in_segment {
            final_segments.insert(
                &token,
                FinalSegment {
                    size: current_offset_in_file - offset_in_output_file,
                    virtmem_address,
                    offset_in_output_file,
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
