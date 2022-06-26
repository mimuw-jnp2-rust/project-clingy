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
use crate::misc::Align;
use crate::misc::Permissions;
use crate::misc::{FileToken, InpSectToken, OutSectToken};
use crate::schemes::{LayoutScheme, OutSectScheme};

#[derive(Debug)]
pub struct OutSectMatcher<'a> {
    pub globs: Vec<globset::GlobMatcher>,
    pub scheme: &'a OutSectScheme<'a>,
}

impl OutSectMatcher<'_> {
    fn matches(&self, inpsect_name: &str) -> bool {
        self.globs
            .iter()
            .any(|matcher| matcher.is_match(inpsect_name))
    }
}

type OutSectMatchers<'a> = VecDict<OutSectToken, OutSectMatcher<'a>>;

#[derive(Debug)]
pub struct Layout<'a> {
    pub scheme: &'a LayoutScheme<'a>,
    pub outsect_count: usize,
    pub outsect_matchers: OutSectMatchers<'a>,
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
            let mut globs = Vec::new();

            for pattern in outsect_scheme.inpsects {
                let glob = globset::Glob::new(pattern)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?
                    .compile_matcher();

                globs.push(glob);
            }

            outsect_matchers.insert(
                &token,
                OutSectMatcher {
                    globs,
                    scheme: outsect_scheme,
                },
            );
        }

        Ok(outsect_matchers)
    }

    fn match_inpsect(&self, inpsect_name: &str) -> Option<OutSectToken> {
        self.outsect_matchers
            .tok_iter()
            .find_map(|(token, matcher)| {
                if matcher.matches(inpsect_name) {
                    return Some(token);
                } else {
                    return None;
                }
            })
    }

    fn match_inpsect_with_err(&self, inpsect_name: &str) -> IoResult<OutSectToken> {
        self.match_inpsect(inpsect_name).ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                format!(
                    "None output section in LayoutScheme matches input section name: {}",
                    inpsect_name
                ),
            )
        })
    }
}

#[derive(Clone, Debug)]
pub enum InpSectFileMapping {
    /* (Token, progbits offset of InpSect in a part of OutSect from the current file) */
    ProgBits(OutSectToken, u64),
    /* (Token, nobits offset of InpSect in a part of OutSect from the current file) */
    NoBits(OutSectToken, u64),
}

#[derive(Default, Clone, Debug)]
pub struct OutSectThisFileInfo {
    pub progbits: u64,
    pub nobits: u64,
    pub permissions: Permissions,
}

type InpSectToOutSect = VecDict<InpSectToken, InpSectFileMapping>;
type OutSectThisFile = VecDict<OutSectToken, OutSectThisFileInfo>;
type InpSectToRela = VecDict<InpSectToken, InpSectToken>;

#[derive(Debug)]
pub struct PreprocessedFile {
    pub token: FileToken,
    pub content: ElfFileContent,
    pub symtab_token: InpSectToken,
    pub inpsect_to_outsect: InpSectToOutSect,
    pub inpsect_to_rela: InpSectToRela,
    pub outsects_this_file: OutSectThisFile,
}

impl PreprocessedFile {
    fn map_inpsect_to_outsect(
        inpsect_token: InpSectToken,
        outsect_token: OutSectToken,
        inpsect_entry: &ElfSectionEntry,
        outsects_this_file: &mut OutSectThisFile,
        inpsect_to_outsect: &mut InpSectToOutSect,
    ) {
        if let None = outsects_this_file.get(&outsect_token) {
            outsects_this_file.insert(&outsect_token, OutSectThisFileInfo::default())
        }

        outsects_this_file[&outsect_token].permissions |= Permissions::from_elf_shf(inpsect_entry);

        let current_outsect_offset = match inpsect_entry.sh_type {
            SHT_PROGBITS => &mut outsects_this_file[&outsect_token].progbits,
            SHT_NOBITS => &mut outsects_this_file[&outsect_token].nobits,
            _ => unreachable!(),
        };

        /* TODO: Alignment. Right now we are aligning to the nearest multiple of 16. Use
         * real alignment field from InpSect. */
        let offset_aligned = current_outsect_offset.align(16);
        *current_outsect_offset = offset_aligned + inpsect_entry.sh_size;

        inpsect_to_outsect.insert(
            &inpsect_token,
            match inpsect_entry.sh_type {
                SHT_PROGBITS => InpSectFileMapping::ProgBits(outsect_token, offset_aligned),
                SHT_NOBITS => InpSectFileMapping::NoBits(outsect_token, offset_aligned),
                _ => unreachable!(),
            },
        );
    }

    pub fn new(file: &mut std::fs::File, number: usize, layout: &Layout) -> IoResult<Self> {
        let content = ElfFileContent::read(file)?;
        let mut outsects_this_file = OutSectThisFile::new(layout.outsect_count);

        let header = content.get_elf_header()?;
        let section_names = ElfStringTableAdapter::adapt(header.e_shstrndx, &content)?;
        let inpsects_count = header.e_shnum as usize;

        let mut inpsect_to_outsect = InpSectToOutSect::new(inpsects_count);
        let mut inpsect_to_rela = InpSectToRela::new(inpsects_count);

        let e = |desc| Err(Error::new(ErrorKind::Other, desc));

        let mut symtab_token: Option<InpSectToken> = None;

        for index in 0..header.e_shnum {
            let token = InpSectToken(index as usize);

            let section = content.get_section_entry(index)?;
            PreprocessedFile::section_type_implemented_assert(section)?;

            match section.sh_type {
                SHT_SYMTAB => {
                    if symtab_token.is_none() {
                        symtab_token = Some(token)
                    } else {
                        return e("A file cannot contain more than one symbol table".to_string());
                    }
                }
                SHT_RELA => {
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
                SHT_PROGBITS | SHT_NOBITS => {
                    let name = section_names.get(section.sh_name)?;
                    let outsect_token = layout.match_inpsect_with_err(name)?;

                    PreprocessedFile::map_inpsect_to_outsect(
                        token,
                        outsect_token,
                        section,
                        &mut outsects_this_file,
                        &mut inpsect_to_outsect,
                    );
                }
                _ => (),
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
            outsects_this_file,
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
