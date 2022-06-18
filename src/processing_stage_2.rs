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

use crate::misc::{InpSectToken, OutSectToken, FileToken};
use crate::elf_file::{STN_UNDEF, STB_WEAK, STB_GLOBAL, STB_LOCAL};
use crate::elf_file::{ElfSymtabEntry, ElfSymtabAdapter};
use crate::processing_stage_1::PreprocessedFile;

pub type SymbolMap = dashmap::DashMap<String, Symbol>;

#[derive(Debug, Clone)]
pub enum SymbolVisibility {
    Strong,
    Weak,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub outsect_token: OutSectToken,
    pub file_token: FileToken,
    pub outsect_offset: u64,
    pub visibility: SymbolVisibility,
}


struct InpSectRelativeAddress {
    outsect_num: u16,
    offset: u64,
}

pub fn process_symbols_from_file(file: &PreprocessedFile, symbol_map: &SymbolMap) -> IoResult<()> {
    let InpSectToken(symtab_index) = file.symtab_token;
    let symtab = ElfSymtabAdapter::adapt(symtab_index as u16, &file.content)?;

    let e = |desc| Err(Error::new(ErrorKind::Other, desc));

    let append_global_symbol = |symbol: &ElfSymtabEntry| {
        let symbol_inpsect = InpSectToken(symbol.st_shndx as usize);

        let name: &str = symtab.strtab.get(symbol.st_name)?;
        let mapping = file.get_inpsect_file_mapping(symbol_inpsect)?;

        let symbol_visibility = match symbol.get_stb() {
            STB_GLOBAL => SymbolVisibility::Strong,
            STB_WEAK => SymbolVisibility::Weak,
            _ => unreachable!(),
        };

        let symbol = Symbol {
            outsect_token: mapping.outsect_token,
            outsect_offset: mapping.inpsect_offset_in_outsect_file_part + symbol.st_value,
            file_token: file.token,
            visibility: symbol_visibility,
        };

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
