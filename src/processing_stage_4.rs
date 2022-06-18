/* Stage 4. Perform relocations. */

use std::io::Result as IoResult;
use std::io::{Error, ErrorKind};
use vec_map::VecDict;

use crate::misc::write_ne_at_pos;
use crate::misc::{FileToken, InpSectToken};
use crate::elf_file::STN_UNDEF;
use crate::elf_file::{ElfSymtabEntry, ElfRelaEntry, ElfRelaAdapter};
use crate::elf_file::{R_X86_64_64, R_X86_64_32S, R_X86_64_PC32};
use crate::processing_stage_1::{PreprocessedFile, InpSectFileMapping};
use crate::processing_stage_2::{Symbol, SymbolMap, SymbolVisibility};
use crate::processing_stage_3::FinalLayout;

type SectionContent = Vec<u8>;

struct SectionRelocationData<'a> {
    file: &'a PreprocessedFile,
    layout: &'a FinalLayout<'a>,
    inpsect_token: InpSectToken,
    rela_token: Option<InpSectToken>,
    symbol_map: &'a SymbolMap,
}

impl<'a> SectionRelocationData<'a> {
    fn get_rela_address(&self, entry: &ElfRelaEntry, inpsect_token: &InpSectToken) -> u64 {
        let mapping = &self.file.inpsect_to_outsect[inpsect_token];
        let outsect = &self.layout.final_outsects[&mapping.outsect_token];

        /* Address */
        outsect.virtmem_address
            + outsect.input_file_slots_offsets[&self.file.token]
            + mapping.inpsect_offset_in_outsect_file_part
            + entry.r_offset
    }

    fn get_rela_offset(&self, entry: &ElfRelaEntry, inpsect_token: &InpSectToken) -> u64 {
        let mapping = &self.file.inpsect_to_outsect[inpsect_token];
        let outsect = &self.layout.final_outsects[&mapping.outsect_token];

        /* Offset */
        outsect.offset_in_output_file
            + outsect.input_file_slots_offsets[&self.file.token]
            + mapping.inpsect_offset_in_outsect_file_part
            + entry.r_offset
    }

    fn relocate_section(&self) -> IoResult<SectionContent> {
        let InpSectToken(inpsect_num) = self.inpsect_token;
        let section = self.file.content.get_section_entry(inpsect_num as u16)?;

        let offset_begin = section.sh_offset as usize;
        let offset_end = offset_begin + section.sh_size as usize;

        let mut section_copy: SectionContent =
            self.file.content.content[offset_begin..offset_end].to_owned();

        let rela_token = match self.rela_token {
            None => return Ok(section_copy), /* No need to relocate, just output copy */
            Some(rela_token) => rela_token,
        };

        let InpSectToken(rela_num) = rela_token;

        let rela = ElfRelaAdapter::adapt(rela_num as u16, &self.file.content)?;
        let mut section_writer = std::io::Cursor::new(&mut section_copy[..]);

        for i in 0..rela.entries_count {
            let entry: &ElfRelaEntry = rela.get(i)?;
            let symbol: &ElfSymtabEntry = rela.symtab.get(entry.r_info_sym as u64)?;

            let e = |desc: String| Err(Error::new(ErrorKind::InvalidData, desc));
            let inpsect_token = InpSectToken(symbol.st_shndx as usize);

            let symbol =
                /* Symbol in .rela has direct link to .symtab */
                if symbol.st_shndx != STN_UNDEF {
                    let InpSectFileMapping {outsect_token, inpsect_offset_in_outsect_file_part} =
                        match &self.file.inpsect_to_outsect.get(&inpsect_token) {
                            None => return e("Symbol from referenced in .rela is not reachable in \
                                              final executable".into()),
                            Some(mapping) => mapping.clone(),
                        };

                    Symbol {
                        outsect_token: outsect_token.clone(),
                        file_token: self.file.token,
                        outsect_offset: inpsect_offset_in_outsect_file_part + symbol.st_value,
                        /* TODO: placeholder value or fetching the real one */
                        visibility: SymbolVisibility::Strong,
                    }
                /* Symbol is defined in separate file: consult the map. */
                } else {
                    let name = rela.symtab.strtab.get(symbol.st_name)?;

                    match self.symbol_map.get(name) {
                        None => {
                            let FileToken(file_number) = self.file.token;
                            /* TODO: better diagnostics (file name) */
                            return e(format!("Undefined symbol {} referenced in a file \
                                              with number {}", name, file_number));
                        }
                        Some(symbol) => symbol.value().clone()
                    }
                };

            let symbol_address = symbol.get_symbol_address(self.layout);
            let rela_address = self.get_rela_address(entry, &self.inpsect_token);
            let rela_file_offset = self.get_rela_offset(entry, &self.inpsect_token);
            let rela_offset = entry.r_offset as u64;
            let value = symbol_address.checked_add_signed(entry.r_addend).unwrap();

            /* Just a few relocations types, enough to carry us forward */
            match entry.r_info_type {
                /* direct 64 bit  */
                R_X86_64_64 => {
                    println!(
                        "relocation:\n    \
                                  {:#x} (u64, absolute) inserted at:\n    \
                                  {:#x} (in output file: {:#x})",
                        value, rela_address, rela_file_offset
                    );

                    write_ne_at_pos(rela_offset, value, &mut section_writer)?;
                }
                /* direct 32 bit sign extended */
                R_X86_64_32S => {
                    let value_signed: i64 = bytemuck::cast(value);
                    let value_trimmed = i32::try_from(value_signed).map_err(|_| {
                        Error::new(
                            ErrorKind::InvalidData,
                            "R_X86_64_32S relocation requested, \
                            but the symbol address cannot be sign-extended from 32 bits",
                        )
                    })?;

                    println!(
                        "relocation:\n    \
                                  {:#x} (i32, sign-extended absolute) inserted at:\n    \
                                  {:#x} (in output file: {:#x})",
                        value_trimmed, rela_address, rela_file_offset
                    );

                    write_ne_at_pos(rela_offset, value_trimmed, &mut section_writer)?;
                }
                /* PC relative 32 bit signed */
                R_X86_64_PC32 => {
                    let get_error = |_| {
                        Error::new(
                            ErrorKind::InvalidData,
                            "R_X86_64_PC32 relocation requested, \
                            but the relative symbol address cannot be sign-extended from 32 bits",
                        )
                    };

                    let value_trimmed: i32 =
                        if let Some(value_sub) = value.checked_sub(rela_address) {
                            i32::try_from(value_sub).map_err(get_error)?
                        } else if let Some(value_sub) = rela_address.checked_sub(value) {
                            let intermediary = -i64::try_from(value_sub).map_err(get_error)?;
                            i32::try_from(intermediary).map_err(get_error)?
                        } else {
                            unreachable!()
                        };

                    println!(
                        "relocation:\n    \
                                  {:#x} (i32, PC relative) inserted at:\n    \
                                  {:#x} (in output file: {:#x})",
                        value_trimmed, rela_address, rela_file_offset
                    );

                    write_ne_at_pos(rela_offset, value_trimmed, &mut section_writer)?;
                }

                _ => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "Requested relocation type is not implemented yet",
                    ))
                }
            };
        }

        Ok(section_copy)
    }
}

#[derive(Debug)]
pub struct RelocatedFile<'a> {
    pub preprocessed: &'a PreprocessedFile,
    pub inpsects: VecDict<InpSectToken, SectionContent>,
}

impl<'a> RelocatedFile<'a> {
    pub fn process(
        file: &'a PreprocessedFile,
        layout: &FinalLayout,
        symbol_map: &SymbolMap,
    ) -> IoResult<Self> {
        let inpsect_count = file.inpsect_to_outsect.len();
        let mut inpsects = VecDict::new(file.inpsect_to_rela.len());

        (0..inpsect_count).try_for_each::<_, IoResult<()>>(|num| {
            let token = InpSectToken(num);
            let rela_token = file.inpsect_to_rela.get(&InpSectToken(num)).cloned();

            let relocation_data = SectionRelocationData {
                file,
                layout,
                inpsect_token: token,
                rela_token,
                symbol_map,
            };

            inpsects.insert(&token, relocation_data.relocate_section()?);

            Ok(())
        })?;

        Ok(RelocatedFile {
            preprocessed: file,
            inpsects,
        })
    }
}
