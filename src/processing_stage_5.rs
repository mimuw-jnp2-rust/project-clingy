/* Stage 5. Create executable. */

use anyhow::{anyhow, bail, Result};
use std::io::{Seek, SeekFrom, Write};

use crate::elf_file::PT_LOAD;
use crate::elf_file::{ElfHeader, ElfProgramHeaderEntry};
use crate::misc::{Align, SegmentToken};
use crate::schemes::MAXPAGESIZE;

use crate::processing_stage_1::InpSectFileMapping;
use crate::processing_stage_2::SymbolMap;
use crate::processing_stage_3::FinalLayout;
use crate::processing_stage_4::RelocatedFile;

pub fn generate_output_executable(
    relocated_files: &Vec<RelocatedFile>,
    layout: &FinalLayout,
    symbol_map: &SymbolMap,
) -> Result<Vec<u8>> {
    let elf_header_size = std::mem::size_of::<ElfHeader>();

    let prolog_size = {
        let program_header_size = std::mem::size_of::<ElfProgramHeaderEntry>();
        let program_headers_count = layout.final_segments.len();

        elf_header_size + program_header_size * program_headers_count
    };

    if prolog_size > 0x1000 {
        bail!(
            "Cannot fit file header, section headers and program headers \
             in MAGPAGESIZE: {:#x}; for now, the whole (`prolog`) has to fit \
             in MAGPAGESIZE",
            MAXPAGESIZE
        );
    }

    let start = symbol_map
        .get("_start")
        .ok_or_else(|| anyhow!("Cannot find `_start` symbol"))?
        .value()
        .get_symbol_address(layout);

    use crate::elf_file as ef;

    let elf_header = ef::ElfHeader {
        e_ident_magic: ef::ELF_IDENT_MAGIC,
        e_ident_class: ef::ELF_IDENT_CLASS_X86_64,
        e_ident_endianness: ef::ELF_IDENT_ENDIANNESS_LITTLE,
        e_ident_hversion: ef::ELF_IDENT_HVERSION_CURRENT,
        e_ident_osabi: ef::ELF_IDENT_OSABI_SYSV,
        e_ident_pad: 0,
        e_type: ef::ELF_TYPE_EXECUTABLE,
        e_machine: ef::ELF_MACHINE_X86_64,
        e_version: ef::ELF_VERSION_CURRENT,
        e_entry: start,
        e_phoff: elf_header_size as u64,
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: std::mem::size_of::<ef::ElfHeader>() as u16,
        e_phentsize: std::mem::size_of::<ef::ElfProgramHeaderEntry>() as u16,
        e_phnum: layout.final_segments.len() as u16,
        e_shentsize: 0,
        e_shnum: 0,
        e_shstrndx: 0,
    };

    let segments_offset = (prolog_size as u64).align(MAXPAGESIZE);

    let file_size = layout
        .final_segments
        .tok_iter()
        .map(|(_, segment)| segment)
        .fold(segments_offset, |acc, segment| {
            acc.align(MAXPAGESIZE) + segment.infile_size
        });

    let mut final_content = vec![0u8; file_size as usize];
    let mut content_writer = std::io::Cursor::new(&mut final_content[..]);

    content_writer.seek(SeekFrom::Start(0))?;
    content_writer.write_all(bytemuck::bytes_of(&elf_header))?;

    for (token, segment) in layout.final_segments.tok_iter() {
        let SegmentToken(index) = token;
        let scheme = &layout.layout.scheme.segments[index];

        let elf_program_header_entry = crate::elf_file::ElfProgramHeaderEntry {
            p_type: PT_LOAD,
            p_flags: segment.permissions.to_elf_pf(),
            p_offset: segment.offset_in_output_file,
            p_vaddr: segment.virtmem_address,
            p_paddr: segment.virtmem_address,
            p_filesz: segment.infile_size,
            p_memsz: segment.virtmem_size,
            p_align: scheme.alignment,
        };

        content_writer.write_all(bytemuck::bytes_of(&elf_program_header_entry))?;
    }

    assert!(content_writer.seek(SeekFrom::Current(0))? <= segments_offset);
    content_writer.seek(SeekFrom::Start(segments_offset))?;

    for file in relocated_files {
        for (token, section_content) in file.inpsects.tok_iter() {
            let mapping = match file.preprocessed.inpsect_to_outsect.get(&token) {
                Some(mapping) => mapping,
                None => continue,
            };

            match mapping {
                InpSectFileMapping::ProgBits(token, inpsect_this_file_offset) => {
                    let final_outsect = &layout.final_outsects[token];

                    let inpsect_start = final_outsect.offset_in_output_file
                        + inpsect_this_file_offset
                        + final_outsect.input_file_slots_offsets[&file.preprocessed.token].progbits;

                    content_writer.seek(SeekFrom::Start(inpsect_start))?;
                    content_writer.write_all(section_content)?;
                }

                InpSectFileMapping::NoBits(_, _) => {
                    () /* NoBits sections are not outputed, obviously */
                }
            }
        }
    }

    Ok(final_content)
}
