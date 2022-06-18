/* For brevity, sections from input files are called `InpSects` and sections from output files -
 * `OutSects`. Program headers are called `Segments`. This is the convention used in the entire
 * project.
 *
 * Stage 1. PreprocessedFile::new method is executed in parallel for every file. It does some
 * initial preprocessing (sanitizing file, finding symtab, mapping InpSect to OutSect using
 * provided LayoutScheme, computing the size occupied in every OutSect by this file).
 */

use std::io::Error;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use vec_map::VecDict;

use crate::elf_file::{ElfFileContent, ElfSectionEntry, ElfStringTableAdapter};
use crate::elf_file::{SHT_NOBITS, SHT_NULL, SHT_PROGBITS, SHT_RELA, SHT_STRTAB, SHT_SYMTAB};

use crate::misc::align;
use crate::misc::{FileToken, InpSectToken, OutSectToken};
use crate::schemes::LayoutScheme;

type OutSectMatchers = VecDict<OutSectToken, Vec<globset::GlobMatcher>>;

#[derive(Debug)]
pub struct Layout<'a> {
    pub scheme: &'a LayoutScheme<'a>,
    pub outsect_count: usize,
    outsect_matchers: OutSectMatchers,
}

impl<'a> Layout<'a> {
    pub fn new(scheme: &'a LayoutScheme<'a>) -> IoResult<Self> {
        Ok(Layout {
            scheme,
            outsect_count: scheme.outsect_iter().count(),
            outsect_matchers: Layout::generate_outsects_matchers(scheme)?,
        })
    }

    fn generate_outsects_matchers(scheme: &'a LayoutScheme<'a>) -> IoResult<OutSectMatchers> {
        let outsect_count = scheme.outsect_iter().count();
        let mut outsect_matchers = OutSectMatchers::new(outsect_count);

        for (index, outsect_scheme) in scheme.outsect_iter().enumerate() {
            let token = OutSectToken(index);
            let mut matchers = Vec::new();

            for pattern in outsect_scheme.inpsects {
                let matcher = globset::Glob::new(pattern)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?
                    .compile_matcher();
                matchers.push(matcher);
            }

            outsect_matchers.insert(&token, matchers);
        }

        Ok(outsect_matchers)
    }

    fn match_inpsect(&self, inpsect_name: &str) -> Option<OutSectToken> {
        for (token, matchers) in self.outsect_matchers.tok_iter() {
            for matcher in matchers {
                if matcher.is_match(inpsect_name) {
                    return Some(token);
                }
            }
        }

        None
    }
}

/* Every InpSect has assigned relative address consisting of two fields:
 *  (OutSect number,
 *   offset of InpSect in a part of OutSect from the current file*);
 * because a file can have (and often has) several InpSects that will end up in one OutSect. */
#[derive(Clone, Debug)]
pub struct InpSectFileMapping {
    pub outsect_token: OutSectToken,
    pub inpsect_offset_in_outsect_file_part: u64,
}

type InpSectToOutSect = VecDict<InpSectToken, InpSectFileMapping>;
type OutSectPerFileOffsets = VecDict<OutSectToken, u64>;
type InpSectToRela = VecDict<InpSectToken, InpSectToken>;

#[derive(Debug)]
pub struct PreprocessedFile {
    pub token: FileToken,
    pub content: ElfFileContent,
    pub symtab_token: InpSectToken,
    pub inpsect_to_outsect: InpSectToOutSect,
    pub inpsect_to_rela: InpSectToRela,
    pub outsects_per_file_size: OutSectPerFileOffsets,
}

impl PreprocessedFile {
    pub fn new(file: &mut std::fs::File, number: usize, layout: &Layout) -> IoResult<Self> {
        let content = ElfFileContent::read(file)?;
        let mut outsects_per_file_size = OutSectPerFileOffsets::new(layout.outsect_count);

        let header = content.get_elf_header()?;
        let section_names = ElfStringTableAdapter::adapt(header.e_shstrndx, &content)?;
        let inpsects_count = header.e_shnum as usize;

        let mut inpsect_to_outsect = InpSectToOutSect::new(inpsects_count);
        let mut inpsect_to_rela = InpSectToRela::new(inpsects_count);

        let e = |desc| Err(Error::new(ErrorKind::Other, desc));

        let mut map_inpsect_to_outsect = |inpsect_token, inpsect_size, outsect_token| {
            let current_outsect_per_file_size =
                *outsects_per_file_size.get(&outsect_token).unwrap_or(&0);

            /* TODO: Alignment. Right now we are aligning to the nearest multiple of 16. Use
             * real alignment field from InpSect. */
            let offset_aligned = align(current_outsect_per_file_size, 16);

            inpsect_to_outsect.insert(
                &inpsect_token,
                InpSectFileMapping {
                    outsect_token,
                    inpsect_offset_in_outsect_file_part: offset_aligned,
                },
            );

            outsects_per_file_size.insert(&outsect_token, offset_aligned + inpsect_size);
        };

        let mut symtab_token: Option<InpSectToken> = None;

        for index in 0..header.e_shnum {
            let token = InpSectToken(index as usize);

            let section = content.get_section_entry(index)?;
            PreprocessedFile::section_type_implemented_assert(section)?;

            if let SHT_SYMTAB = section.sh_type {
                if symtab_token.is_none() {
                    symtab_token = Some(token)
                } else {
                    return e("A file cannot contain more than one symbol table".to_string());
                }
            }

            if let SHT_RELA = section.sh_type {
                let linked_token = InpSectToken(section.sh_info as usize);

                match inpsect_to_rela.get(&linked_token) {
                    None => inpsect_to_rela.insert(&linked_token, token),
                    Some(_) => {
                        return e(format!(
                            "More than one relocation tables reference section '{}'",
                            section_names.get(section.sh_name)?
                        ))
                    }
                }
            }

            if let SHT_PROGBITS | SHT_NOBITS = section.sh_type {
                let name = section_names.get(section.sh_name)?;
                let outsect_num = layout.match_inpsect(name).ok_or_else(|| {
                    Error::new(
                        ErrorKind::Other,
                        format!(
                            "None output section in LayoutScheme matches input section name: {}",
                            name
                        ),
                    )
                })?;

                map_inpsect_to_outsect(token, section.sh_size, outsect_num);
            }
        }

        let symtab_token = match symtab_token {
            None => return e("A file must contain a symbol table".to_string()),
            Some(token) => token,
        };

        Ok(PreprocessedFile {
            content,
            token: FileToken(number),
            symtab_token,
            inpsect_to_outsect,
            inpsect_to_rela,
            outsects_per_file_size,
        })
    }

    fn section_type_implemented_assert(section: &ElfSectionEntry) -> IoResult<()> {
        let e = |desc| Err(Error::new(ErrorKind::Other, desc));

        match section.sh_type {
            SHT_PROGBITS | SHT_NOBITS | SHT_NULL | SHT_STRTAB | SHT_SYMTAB | SHT_RELA => Ok(()),
            _ => e("Cannot recognize some section header type (not implemented yet)".to_string()),
        }
    }

    pub fn get_inpsect_file_mapping(&self, token: InpSectToken) -> IoResult<&InpSectFileMapping> {
        self.inpsect_to_outsect.get(&token).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "Entry in symbol table points to a special section.",
            )
        })
    }
}
