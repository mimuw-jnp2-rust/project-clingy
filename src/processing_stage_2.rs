/* Stage 2. Function `process_symbols_from_file` is executed for every file in parallel. It gathers
 * global symbols from file into a parallel HashMap (`dash_map` crate).
 *
 * One thing can be significantly improved; the "string interning" can take place at the time of
 * file loading and a number can be used in a HashMap instead of String, so that every string in
 * .strtab is hashed only once in stage 2 (and not subsequenty in stage 3 each time it is
 * referenced in .rela table).
 */

use std::io::Error;
use std::io::ErrorKind;
use std::io::Result as IoResult;

use crate::elf_file::{ElfSymtabAdapter, ElfSymtabEntry};
use crate::elf_file::{STB_GLOBAL, STB_LOCAL, STB_WEAK, STN_UNDEF};
use crate::misc::{FileToken, InpSectToken, OutSectToken};
use crate::processing_stage_1::{InpSectFileMapping, PreprocessedFile};

pub type SymbolMap = dashmap::DashMap<String, Symbol>;

#[derive(Debug, Clone)]
pub enum SymbolVisibility {
    Strong,
    Weak,
    Local,
}

impl SymbolVisibility {
    fn new(entry: &ElfSymtabEntry) -> Self {
        match entry.get_stb() {
            STB_GLOBAL => SymbolVisibility::Strong,
            STB_WEAK => SymbolVisibility::Weak,
            STB_LOCAL => SymbolVisibility::Local,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum SymbolOffset {
    ProgBits(OutSectToken, u64),
    NoBits(OutSectToken, u64),
}

impl SymbolOffset {
    pub fn from_mapping(entry: &ElfSymtabEntry, mapping: &InpSectFileMapping) -> SymbolOffset {
        match mapping {
            InpSectFileMapping::NoBits(token, off) => {
                SymbolOffset::NoBits(*token, off + entry.st_value)
            }
            InpSectFileMapping::ProgBits(token, off) => {
                SymbolOffset::ProgBits(*token, off + entry.st_value)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub symbol_offset: SymbolOffset,
    pub file_token: FileToken,
    pub visibility: SymbolVisibility,
}

impl Symbol {
    pub fn new(entry: &ElfSymtabEntry, file: &PreprocessedFile) -> IoResult<Self> {
        let symbol_inpsect = InpSectToken(entry.st_shndx as usize);
        let mapping = file.get_inpsect_file_mapping(symbol_inpsect)?;

        Ok(Symbol {
            symbol_offset: SymbolOffset::from_mapping(entry, mapping),
            file_token: file.token,
            visibility: SymbolVisibility::new(entry),
        })
    }
}

struct InpSectRelativeAddress {
    outsect_num: u16,
    offset: u64,
}

pub fn process_symbols_from_file(file: &PreprocessedFile, symbol_map: &SymbolMap) -> IoResult<()> {
    let InpSectToken(symtab_index) = file.symtab_token;
    let symtab = ElfSymtabAdapter::adapt(symtab_index as u16, &file.content)?;

    let e = |desc| Err(Error::new(ErrorKind::Other, desc));

    let append_global_symbol = |entry: &ElfSymtabEntry| {
        let name: &str = symtab.strtab.get(entry.st_name)?;
        let symbol = Symbol::new(entry, file)?;

        use dashmap::mapref::entry::Entry::{Occupied, Vacant};

        match symbol_map.entry(name.to_string()) {
            Vacant(entry) => {
                entry.insert(symbol);
                Ok(())
            }

            Occupied(mut entry) => {
                use SymbolVisibility::{Strong, Weak};

                match (&entry.get().visibility, &symbol.visibility) {
                    (Weak, Weak) => Ok(()), /* TODO: select greater weak symbol */
                    (Strong, Weak) => Ok(()),
                    (Weak, Strong) => {
                        entry.insert(symbol);
                        Ok(())
                    }
                    (Strong, Strong) => e(format!(
                        "Strong symbol `{}` is defined multiple times.",
                        name
                    )),
                    _ => unreachable!()
                }
            }
        }
    };

    for i in 0..symtab.symbols_count {
        let symbol = symtab.get(i)?;

        /* At this stage of processing we ignore undefined symbols. */
        if symbol.st_shndx == STN_UNDEF {
            continue;
        }

        match symbol.get_stb() {
            STB_LOCAL => (),
            STB_GLOBAL | STB_WEAK => append_global_symbol(symbol)?,
            _ => return e("Unrecognized symbol bind".to_string()),
        }
    }

    Ok(())
}
