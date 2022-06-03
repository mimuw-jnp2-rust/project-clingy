#![feature(cstr_from_bytes_until_nul)]
#![feature(io_error_more)]
#![feature(mixed_integer_ops)]
use bytemuck::Pod;
use bytemuck_derive::{Pod, Zeroable};
use memmap::Mmap;
use std::ffi::CStr;
use std::io::{Error, ErrorKind};

use std::io::Result as IoResult;

/* 1. In-file data structures
 *
 * For all the structs loaded directly from ELF file, we are using official member names, even if
 * they are a little bit awkward and cryptic (e_shstrndx!?). My stuff has saner naming conventions.
 *
 * When reading data from file, `bytemuck` crate is used to safely cast &[u8, N] slices into
 * #[repr(packed)] structs. I used `bytemuck` instead of read-based crates, because I like
 * zero-copy solutions and, as far as I know, on modern CPUs unaligned access comes with little or
 * no penalty anyway.
 *
 * To read data from file, `memmap` crate is used to map an input file into read-only [u8] block.
 * `mmap` is amazing system call with great optimizations underneath, but it is unsafe. The file
 * may be modified outside of the process - Linux for example do not have mandatory file locks.
 * Then the page consisting of the mmaped file may be evicted. Then the page may be re-read with
 * different content, causing the read-only mapped region to mutate 😱. I hope that safety of
 * `mmap` will be improved someday. For now, I will take the risk.
 *
 * To write data to file, regular Rust API from std::io is used (File, Write, etc.).
 */

struct ElfFileContent {
    content: Mmap,
}

impl ElfFileContent {
    fn map(file: std::fs::File) -> IoResult<Self> {
        let content = unsafe { Mmap::map(&file)? };
        let file = ElfFileContent { content };
        file.get_elf_header()?.verify()?;
        Ok(file)
    }

    fn get<T: Pod>(&self, offset: u64) -> IoResult<&T> {
        let begin = offset as usize;
        let end = begin + std::mem::size_of::<T>();

        let content = self.content.get(begin..end).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "The POD type crosses the end boundary of the file",
            )
        })?;

        /* Bytemuck performs all checks to ensure safety of this cast. */
        Ok(bytemuck::from_bytes(content))
    }

    fn get_elf_header(&self) -> IoResult<&ElfHeader> {
        self.get::<ElfHeader>(0)
    }

    fn get_section_entry(&self, num: u16) -> IoResult<&ElfSectionEntry> {
        let header = self.get_elf_header()?;

        if num < header.e_shnum {
            let offset = header.e_shoff + num as u64 * header.e_shentsize as u64;
            self.get(offset)
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Section index out-of-bounds",
            ))
        }
    }
}

/* Type aliases from ELF specification (Elf64_*). */
type ElfAddr = u64; /* Type of addresses. */
type ElfOffset = u64; /* Type of file offsets.  */
type ElfVerSym = u16; /* Type of version symbol. */
type ElfSectionIndex = u16; /* Type of... */

#[derive(Copy, Clone, Zeroable, Pod, Debug)]
#[repr(C, packed)]
struct ElfHeader {
    e_ident_magic: [u8; 4],
    e_ident_class: u8,
    e_ident_endianness: u8,
    e_ident_hversion: u8,
    e_ident_osabi: u8,
    #[allow(dead_code)]
    e_ident_pad: u64,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: ElfAddr,
    e_phoff: ElfOffset,
    e_shoff: ElfOffset,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

impl ElfHeader {
    fn verify(&self) -> IoResult<()> {
        let e = |desc| Err(Error::new(ErrorKind::InvalidData, desc));

        match true {
            _ if &self.e_ident_magic != b"\x7fELF" => e("Bad magic. Not an ELF file?"),
            _ if self.e_ident_class != 2 => {
                e("Bad file class. Was the object file built for x86_64 CPU?")
            }
            _ if self.e_ident_endianness != 1 => {
                e("Bad endianness. Was the object file built for x86_64 CPU?")
            }
            _ if self.e_ident_hversion != 1 => {
                e("Unrecognized header version (should be 1). File corrupted?")
            }
            _ if self.e_ident_osabi != 0 => {
                e("File is not a static relocatable file (.o) or is not compatible with Linux")
            }
            _ if self.e_type != 1 => e("Not a relocatable (.o) file"),
            _ if self.e_machine != 0x3E => e("File not built for x86_64 CPU"),
            _ if self.e_version != 1 => {
                e("Unrecognized file version (should be 1). File corrupted?")
            }
            _ if self.e_shentsize < std::mem::size_of::<ElfSectionEntry>() as u16 => {
                e("Reported ELF section header entry is too small. File corrupted?")
            }
            _ if self.e_shstrndx >= self.e_shnum => e(
                "Section header string table section entry is located outside section header \
                 table. File corrupted?",
            ),
            _ => Ok(()),
        }
    }
}

/* For now, we support only small subset of all possible section types... */
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;

/* ...and section flags. */
const SHF_WRITE: u32 = 1 << 0;
const SHF_ALLOC: u32 = 1 << 1;
const SHF_EXECINSTR: u32 = 1 << 2;
const SHF_MERGE: u32 = 1 << 4;
const SHF_STRINGS: u32 = 1 << 5;
const SHF_INFO_LINK: u32 = 1 << 6;
const SHF_GROUP: u32 = 1 << 9;

/* ELF section header entry. */
#[derive(Copy, Clone, Zeroable, Pod, Debug)]
#[repr(C, packed)]
struct ElfSectionEntry {
    sh_name: u32,
    sh_type: u32,  /* see SHT_* constants */
    sh_flags: u64, /* see SHF_* constants */
    sh_addr: ElfAddr,
    sh_offset: ElfOffset,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

/* ELF .symtab entry. */
#[derive(Copy, Clone, Zeroable, Pod, Debug)]
#[repr(C, packed)]
struct ElfSymtabEntry {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: ElfAddr,
    st_size: u64,
}

/* Bit flipping makes my heart melt */
impl ElfSymtabEntry {
    fn get_stt(&self) -> u8 {
        self.st_info & 0xf
    }
    fn get_stb(&self) -> u8 {
        self.st_info >> 4
    }
}

const STN_UNDEF: u16 = 0; /* Undefined symbol.  */

const STB_LOCAL: u8 = 0; /* Local symbol */
const STB_GLOBAL: u8 = 1; /* Global symbol */
const STB_WEAK: u8 = 2; /* Weak symbol */

const STT_NOTYPE: u8 = 0; /* Symbol type is unspecified */
const STT_OBJECT: u8 = 1; /* Symbol is a data object */
const STT_FUNC: u8 = 2; /* Symbol is a code object */
const STT_SECTION: u8 = 3; /* Symbol associated with a section */
const STT_FILE: u8 = 4; /* Symbol's name is file name */
const STT_COMMON: u8 = 5; /* Symbol is a common data object */
const STT_TLS: u8 = 6; /* Symbol is thread-local data object*/

/* ELF .rela. entry. */
#[derive(Copy, Clone, Zeroable, Pod, Debug)]
#[repr(C, packed)]
struct ElfRelaEntry {
    r_offset: ElfAddr, /* Offset of relocated bytes. */
    r_info_type: u32,  /* Relocation type. */
    r_info_sym: u32,   /* Symbol index. */
    r_addend: i64,
}

/* A tiny subset of all possible relocation types */
const R_X86_64_64: u32 = 1; /* Direct 64 bit  */
const R_X86_64_PC32: u32 = 2; /* PC relative 32 bit signed */
const R_X86_64_32S: u32 = 11; /* Direct 32 bit sign extended */

/* TODO: support .rel entries. (They are abandoned now, everyone uses .rela, so it's not really
 * that important). */

struct ElfStringTableAdapter<'a> {
    offset: u64,
    size: u64,
    file: &'a ElfFileContent,
}

/* Adapts section entry into string table */
impl<'a> ElfStringTableAdapter<'a> {
    pub fn adapt(section_entry_num: u16, file: &'a ElfFileContent) -> IoResult<Self> {
        let entry = file.get_section_entry(section_entry_num)?;

        if let SHT_STRTAB = entry.sh_type {
            Ok(ElfStringTableAdapter {
                offset: entry.sh_addr,
                size: entry.sh_size,
                file,
            })
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Trying to interpret section, which is not a string table, as a string table",
            ))
        }
    }

    pub fn get(&self, position: u32) -> IoResult<&str> {
        let e = |desc| Error::new(ErrorKind::InvalidData, desc);

        if position == 0 {
            return Err(e("Invalid query in .strtab (position 0 is reserved)"));
        }

        let begin = self.offset as usize + position as usize;
        let end = begin + self.size as usize;

        let content = &self.file.content[begin..end];

        CStr::from_bytes_until_nul(content)
            .map_err(|_| e("String in the string table is not null-terminated. File corrupted?"))?
            .to_str()
            .map_err(|_| {
                e("String in the string table contains invalid characters. File corrupted?")
            })
    }
}

struct ElfSymtabAdapter<'a> {
    file: &'a ElfFileContent,
    offset: u64,
    symbol_size: u64,
    symbols_count: u64,
    strtab: ElfStringTableAdapter<'a>,
}

impl<'a> ElfSymtabAdapter<'a> {
    pub fn adapt(section_num: ElfSectionIndex, file: &'a ElfFileContent) -> IoResult<Self> {
        let entry = file.get_section_entry(section_num)?;

        let e = |desc: String| Err(Error::new(ErrorKind::Other, desc));

        if entry.sh_type != SHT_SYMTAB {
            return e("Trying to interpret section, which is not a .symtab, as a .symtab".into());
        }

        if entry.sh_entsize < std::mem::size_of::<ElfSymtabEntry>() as u64 {
            return e("Invalid reported .symtab entry size. File corrupted?".into());
        }

        let size = entry.sh_size;
        let symbol_size = entry.sh_entsize;

        let symbols_count = match size % symbol_size {
            0 => size / symbol_size,
            _ => {
                return e(format!(
                    "Invalid combination of symbol table size and symbol size: {}, {}",
                    size, symbol_size
                ))
            }
        };

        let strtab = ElfStringTableAdapter::adapt(entry.sh_link as u16, file)?;

        Ok(ElfSymtabAdapter {
            file,
            offset: entry.sh_offset,
            symbol_size,
            symbols_count,
            strtab,
        })
    }

    pub fn get(&self, entry_no: u64) -> IoResult<&ElfSymtabEntry> {
        let symtab_entry_offset = self.offset + entry_no * self.symbol_size;
        let symtab_entry: &ElfSymtabEntry = self.file.get(symtab_entry_offset)?;
        Ok(symtab_entry)
    }
}

struct ElfRelaAdapter<'a> {
    file: &'a ElfFileContent,
    offset: u64,
    entry_size: u64,
    entries_count: u64,
    symtab: ElfSymtabAdapter<'a>,
}

//
// TODO: This code is quite similar to code of ElfSymtabAdapter struct. Maybe abstract something?
//
impl<'a> ElfRelaAdapter<'a> {
    pub fn adapt(section_num: ElfSectionIndex, file: &'a ElfFileContent) -> IoResult<Self> {
        let entry = file.get_section_entry(section_num)?;

        let e = |desc: String| Err(Error::new(ErrorKind::Other, desc));

        if entry.sh_type != SHT_RELA {
            return e("Trying to interpret section, which is not a .rela, as a .rela".into());
        }

        if entry.sh_entsize < std::mem::size_of::<ElfRelaEntry>() as u64 {
            return e("Invalid reported .rela entry size. File corrupted?".into());
        }

        let size = entry.sh_size;
        let entry_size = entry.sh_entsize;

        let entries_count = match size % entry_size {
            0 => size / entry_size,
            _ => {
                return e(format!(
                    "Invalid combination of .rela table size and relocation entry size: {}, {}",
                    size, entry_size
                ));
            }
        };

        let symtab = ElfSymtabAdapter::adapt(entry.sh_link as u16, file)?;

        Ok(ElfRelaAdapter {
            file,
            offset: entry.sh_offset,
            entry_size,
            entries_count,
            symtab,
        })
    }

    pub fn get(&self, entry_no: u64) -> IoResult<&ElfRelaEntry> {
        let rela_entry_offset = self.offset + entry_no * self.entry_size;
        let rela_entry: &ElfRelaEntry = self.file.get(rela_entry_offset)?;
        Ok(rela_entry)
    }
}

/* 2. In-memory data structures for processing */

/* For brevity let's call sections from input files `InpSects` and sections created in output file
 * `OutSects`. Let's call program headers `Segments`. */

const MAXPAGESIZE: u64 = 0x1000;

const DEFAULT_SCHEME: LayoutScheme<'static> = LayoutScheme {
    entry: "_start",
    segments: &[
        SegmentScheme {
            name: "text-segment",
            start: AddrScheme::Absolute(0x400000),
            alignment: MAXPAGESIZE,
            sections: &[OutSectScheme {
                name: ".text",
                inpsects: &[".text", ".text.*"],
            }],
        },
        SegmentScheme {
            name: "rodata-segment",
            start: AddrScheme::CurrentLocation,
            alignment: MAXPAGESIZE,
            sections: &[OutSectScheme {
                name: ".rodata",
                inpsects: &[".rodata", ".rodata.*"],
            }],
        },
        SegmentScheme {
            name: "data-segment",
            start: AddrScheme::CurrentLocation,
            alignment: MAXPAGESIZE,
            sections: &[
                OutSectScheme {
                    name: ".data",
                    inpsects: &[".data", ".data.*"],
                },
                OutSectScheme {
                    name: ".bss",
                    inpsects: &[".bss", ".bss.*"],
                },
            ],
        },
    ],
};

/* The DEFAULT_SCHEME object constant corresponds to the following linker script. (Note: This is
 * not enough to link any serious project, but enough to carry us forward. Write a runtime
 * converter of a linker scripts to the LayoutScheme).
 *
 * ENTRY(_start)
 * SECTIONS
 * {
 *   . = ALIGN(CONSTANT (MAXPAGESIZE));
 *   . = SEGMENT_START("text-segment", 0x400000);
 *   .text : { *(.text .text.*) }
 *
 *   . = ALIGN(CONSTANT (MAXPAGESIZE));
 *   . = SEGMENT_START("rodata-segment", .);
 *   .rodata : { *(.rodata .rodata.*) }
 *
 *   . = ALIGN(CONSTANT (MAXPAGESIZE));
 *   . = SEGMENT_START("data-segment", .);
 *   .data : { *(.data .data.*) }
 *   .bss : { *(.bss .bss.*) }
 * }
 *
 */

type FileIndex = u16;
type SegmentIndex = u16;

enum AddrScheme {
    CurrentLocation,
    Absolute(ElfAddr),
}

struct OutSectScheme<'a> {
    name: &'a str,
    inpsects: &'a [&'a str],
}

struct SegmentScheme<'a> {
    name: &'a str,     /* Segment name */
    start: AddrScheme, /* Starting address of segment */
    alignment: u64,    /* Segment alignment (in bytes) */
    sections: &'a [OutSectScheme<'a>],
}

struct LayoutScheme<'a> {
    entry: &'a str,
    segments: &'a [SegmentScheme<'a>],
}

impl<'a> LayoutScheme<'a> {
    fn segment_iter(&self) -> impl Iterator<Item = &SegmentScheme<'a>> {
        self.segments.iter()
    }

    fn outsect_iter(&self) -> impl Iterator<Item = &OutSectScheme<'a>> {
        self.segment_iter()
            .flat_map(|segment| segment.sections.iter())
    }
}

/*
 * We use following algorithm. Disclaimer: It probably can be improved, it's just a quick solution.
 *
 * For every file in parallel:
 *   *  We match every InpSect with a corresponding OutSect using given LayoutScheme, so that
 *      every InpSect has assigned relative address consisting of two fields:
 *        (OutSect number,
 *         offset of InpSect in a part of OutSect from the current file*).
 *      *Because a file can have (and often has) several InpSects that will end up in one OutSect.
 *
 *   *  We go through the .symtab, we append every global symbol to a hashtable. The key is a
 *      symbol name. The value contains some symbol info and a relative address consisting of
 *      three fields:
 *        (input file number, OutSect number, offset).
 *
 *  Then we fix virtual memory layout. We assign addresses to every Segment and OutSect. We create
 *  some auxilary arrays to help us relocating.
 *
 *  For every file in parallel:
 *    *  We copy each InpSect that needs some relocations. We go through the .rela and .rel tables and,
 *       using hashtable and .symtab, we relocate.
 *
 */

type OutSectIndex = u16;
type InpSectIndex = u16;
type OutSectMatchersVec = Vec<Vec<globset::GlobMatcher>>;

struct Layout<'a> {
    scheme: &'a LayoutScheme<'a>,
    outsect_count: usize,
    outsect_matchers: OutSectMatchersVec,
}

impl<'a> Layout<'a> {
    fn new(scheme: &'a LayoutScheme<'a>) -> IoResult<Self> {
        Ok(Layout {
            scheme,
            outsect_count: scheme.outsect_iter().count(),
            outsect_matchers: Layout::generate_outsects_matchers(scheme)?,
        })
    }

    fn generate_outsects_matchers(scheme: &'a LayoutScheme<'a>) -> IoResult<OutSectMatchersVec> {
        let mut outsect_matchers = Vec::new();

        for outsect_scheme in scheme.outsect_iter() {
            let mut matchers = Vec::new();

            for pattern in outsect_scheme.inpsects {
                let matcher = globset::Glob::new(pattern)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?
                    .compile_matcher();
                matchers.push(matcher);
            }
            outsect_matchers.push(matchers);
        }
        Ok(outsect_matchers)
    }

    fn match_inpsect(&self, inpsect_name: &str) -> Option<OutSectIndex> {
        for (outsect_num, matchers) in self.outsect_matchers.iter().enumerate() {
            for matcher in matchers {
                if matcher.is_match(inpsect_name) {
                    return Some(outsect_num as OutSectIndex);
                }
            }
        }

        None
    }
}

/* TODO: find some crate to do that? */
fn align(num: u64, bound: u64) -> u64 {
    ((num + (bound - 1)) / bound) * bound
}

#[derive(Clone)]
struct InpSectFileMapping {
    outsect_num: OutSectIndex,
    per_file_offset_in_outsect: u64,
}

/* This is per-file vector indexed by InpSectIndex */
type InpSectToOutSectVec = Vec<Option<InpSectFileMapping>>;

/* This is per-file vector indexed by OutSectIndex */
type OutSectPerFileOffsetsVec = Vec<u64>;

struct PreprocessedFile<'a> {
    number: usize,
    content: ElfFileContent,
    layout: &'a Layout<'a>,
    symtab_index: InpSectIndex,
    inpsect_to_outsect: InpSectToOutSectVec,
    outsects_per_file_size: OutSectPerFileOffsetsVec,
}

impl<'a> PreprocessedFile<'a> {
    fn new(file: std::fs::File, number: usize, layout: &'a Layout) -> IoResult<Self> {
        let content = ElfFileContent::map(file)?;
        let mut symtab_index: Option<InpSectIndex> = None;
        let mut inpsect_to_outsect: InpSectToOutSectVec = Vec::new();
        let mut outsects_per_file_size: Vec<u64> = Vec::new();
        outsects_per_file_size.resize(layout.outsect_count, 0);

        let header = content.get_elf_header()?;
        let section_names = ElfStringTableAdapter::adapt(header.e_shstrndx, &content)?;

        inpsect_to_outsect.resize(header.e_shnum as usize, None);

        let e = |desc| Err(Error::new(ErrorKind::Other, desc));

        let mut map_inpsect_to_outsect = |inpsect_idx, inpsect_size, outsect_num| {
            /* TODO: Alignment. Right now we are aligning to the nearest multiple of 16. Use
             * real alignment field from InpSect. */
            let offset_aligned = align(outsects_per_file_size[outsect_num as usize], 16);

            inpsect_to_outsect[inpsect_idx as usize] = Some(InpSectFileMapping {
                outsect_num,
                per_file_offset_in_outsect: offset_aligned + inpsect_size,
            });

            outsects_per_file_size[outsect_num as usize] = offset_aligned + inpsect_size;
        };

        for section_idx in 0..header.e_shnum {
            let section = content.get_section_entry(section_idx)?;
            PreprocessedFile::section_type_implemented_assert(section)?;

            if let SHT_SYMTAB = section.sh_type {
                if symtab_index.is_none() {
                    symtab_index = Some(section_idx)
                } else {
                    return e("A file cannot contain more than one symbol table".to_string());
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

                map_inpsect_to_outsect(section_idx, section.sh_size, outsect_num);
            }
        }

        let symtab_index = match symtab_index {
            None => return e("A file must contain a symbol table".to_string()),
            Some(index) => index,
        };

        Ok(PreprocessedFile {
            content,
            number,
            layout,
            symtab_index,
            inpsect_to_outsect,
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

    fn get_inpsect_file_mapping(
        &self,
        section_index: ElfSectionIndex,
    ) -> IoResult<InpSectFileMapping> {
        self.inpsect_to_outsect[section_index as usize]
            .clone()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "Entry in symbol table points to a special section.",
                )
            })
    }
}

type SymbolMap = dashmap::DashMap<String, Symbol>;

#[derive(Clone)]
enum SymbolVisibility {
    Strong,
    Weak,
}

#[derive(Clone)]
struct Symbol {
    outsect_num: u16,
    file_num: usize,
    outsect_offset: u64,
    visibility: SymbolVisibility,
}

struct InpSectRelativeAddress {
    outsect_num: u16,
    offset: u64,
}

fn process_symbols_from_file(file: &PreprocessedFile, symbol_map: &SymbolMap) -> IoResult<()> {
    let symtab = ElfSymtabAdapter::adapt(file.symtab_index, &file.content)?;

    let e = |desc| Err(Error::new(ErrorKind::Other, desc));

    let append_global_symbol = |symbol: &ElfSymtabEntry| {
        let name: &str = symtab.strtab.get(symbol.st_name)?;
        let mapping = file.get_inpsect_file_mapping(symbol.st_shndx)?;

        let symbol_visibility = match symbol.get_stb() {
            STB_GLOBAL => SymbolVisibility::Strong,
            STB_WEAK => SymbolVisibility::Weak,
            _ => unreachable!(),
        };

        let symbol = Symbol {
            outsect_num: mapping.outsect_num,
            outsect_offset: mapping.per_file_offset_in_outsect + symbol.st_value,
            file_num: file.number,
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
                    (Weak, Weak) => Ok(()), /* TODO: select bigger weak symbol (like other linkers) */
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

type OutSectsVirtMemAddress = Vec<u64>;
type PerFileOutSectsOffset = Vec<Vec<u64>>;
type OutSectsSize = Vec<u64>;

struct FinalSegment {
    virtmem_addr: u64,
    virtmem_size: u64,
}

struct FinalLayout<'a> {
    layout: &'a Layout<'a>,
    final_segments: Vec<FinalSegment>,
    outsects_virtmem_address: OutSectsVirtMemAddress,
    per_file_outsects_offsets: PerFileOutSectsOffset,
    outsects_size: OutSectsSize,
}

fn fix_layout<'a>(
    layout: &'a Layout<'a>,
    preprocessed_files: Vec<&PreprocessedFile>,
) -> IoResult<FinalLayout<'a>> {
    let files_count = preprocessed_files.len();

    let mut outsects_size = vec![0; layout.outsect_count];
    let mut per_file_outsects_offsets = vec![vec![0; layout.outsect_count]; files_count];

    for (outsect_num, cur_outsect_size) in outsects_size.iter_mut().enumerate() {
        let mut relative_offset: u64 = 0;

        for (file_num, file) in preprocessed_files.iter().enumerate() {
            relative_offset = align(relative_offset, 16); // TODO: proper alignment
            per_file_outsects_offsets[file_num][outsect_num] = relative_offset;
            relative_offset += file.outsects_per_file_size[outsect_num];
        }

        *cur_outsect_size = relative_offset;
    }

    let mut outsects_virtmem_address = vec![0; layout.outsect_count];
    let mut final_segments = Vec::<FinalSegment>::new();
    let mut address = 0x0;

    let mut outsects_iter = outsects_size
        .iter()
        .zip(outsects_virtmem_address.iter_mut());

    for segment in layout.scheme.segment_iter() {
        address = match segment.start {
            AddrScheme::Absolute(abs_address) => {
                if address > abs_address {
                    return Err(Error::new(
                        ErrorKind::FileTooLarge,
                        "Cannot fit output files into LayoutScheme",
                    ));
                }
                abs_address
            }
            AddrScheme::CurrentLocation => align(address, segment.alignment),
        };

        let segment_virtmem_start = address;

        for _ in segment.sections {
            address = align(address, 16); // TODO: proper alignment
            let (size, virtmem_address) = outsects_iter.next().unwrap();
            *virtmem_address = address;
            address += size;
        }

        final_segments.push(FinalSegment {
            virtmem_addr: segment_virtmem_start,
            virtmem_size: address - segment_virtmem_start,
        });
    }

    Ok(FinalLayout {
        layout,
        final_segments,
        outsects_virtmem_address,
        per_file_outsects_offsets,
        outsects_size,
    })
}

type SectionFinalContent = Vec<u8>;

trait WritePrimitive {
    fn write_ne_bytes<T: std::io::Write>(self, writer: &mut T) -> IoResult<()>;
}

impl WritePrimitive for u64 {
    fn write_ne_bytes<T: std::io::Write>(self, writer: &mut T) -> IoResult<()> {
        writer.write_all(&self.to_ne_bytes())
    }
}

impl WritePrimitive for i32 {
    fn write_ne_bytes<T: std::io::Write>(self, writer: &mut T) -> IoResult<()> {
        writer.write_all(&self.to_ne_bytes())
    }
}

struct RelocationData<'a> {
    file: &'a PreprocessedFile<'a>,
    inpsect_num: ElfSectionIndex,
    global_map: &'a SymbolMap,
    layout: &'a FinalLayout<'a>,
    rela_index: ElfSectionIndex,
}

fn write_ne_at_pos<T, V>(pos: u64, val: T, writer: &mut V) -> IoResult<()>
where
    T: WritePrimitive,
    V: std::io::Write + std::io::Seek,
{
    writer.seek(std::io::SeekFrom::Start(pos))?;
    val.write_ne_bytes(writer)
}

impl<'a> RelocationData<'a> {
    fn get_symbol_address(&self, symbol: Symbol) -> u64 {
        let Symbol {
            outsect_num,
            file_num,
            outsect_offset, /* outsec_offset == symbol offset + insect offset in per file outsect */
            visibility: _,
        } = symbol;

        /* Address */
        self.layout.outsects_virtmem_address[outsect_num as usize]
            + self.layout.per_file_outsects_offsets[file_num as usize][outsect_num as usize]
            + outsect_offset
    }

    fn get_rela_address(&self, entry: &ElfRelaEntry, inpsect_num: u16) -> u64 {
        let InpSectFileMapping {
            outsect_num,
            per_file_offset_in_outsect, /* TODO: refactoring: change this name to a more telling one */
        } = self.file.inpsect_to_outsect[inpsect_num as usize]
            .clone()
            .unwrap();

        /* Address */
        self.layout.outsects_virtmem_address[outsect_num as usize]
            + self.layout.per_file_outsects_offsets[self.file.number as usize][outsect_num as usize]
            + per_file_offset_in_outsect
            + entry.r_offset
    }

    fn relocate_section(&self) -> IoResult<SectionFinalContent> {
        let RelocationData {
            file,
            inpsect_num,
            global_map,
            layout: _,
            rela_index,
        } = *self;

        let rela = ElfRelaAdapter::adapt(rela_index, &file.content)?;
        let section = file.content.get_section_entry(inpsect_num)?;

        let offset_begin = section.sh_offset as usize;
        let offset_end = offset_begin + section.sh_size as usize;

        let section_copy: Vec<u8> = file.content.content[offset_begin..offset_end].to_owned();
        let mut section_writer = std::io::Cursor::new(section_copy);

        for i in 0..rela.entries_count {
            let entry: &ElfRelaEntry = rela.get(i)?;
            let symbol: &ElfSymtabEntry = rela.symtab.get(entry.r_info_sym as u64)?;

            let e = |desc: String| Err(Error::new(ErrorKind::InvalidData, desc));

            let symbol =
                /* Symbol in .rela has direct link to .symtab */
                if symbol.st_shndx != STN_UNDEF {
                    let InpSectFileMapping {outsect_num, per_file_offset_in_outsect} =
                        match &file.inpsect_to_outsect[symbol.st_value as usize] {
                            None => return e("Symbol from referenced in .rela is not reachable in final executable".into()),
                            Some(mapping) => mapping.clone(),
                        };

                    Symbol {
                        outsect_num,
                        file_num: file.number,
                        outsect_offset: per_file_offset_in_outsect + symbol.st_value,
                        visibility: SymbolVisibility::Strong, /* TODO: placeholder value or fetching the real one */
                    }
                /* Symbol is defined in separate file: consult the map. */
                } else {
                    let name = rela.symtab.strtab.get(symbol.st_name)?;
                    match global_map.get(name) {
                        None => {
                            /* TODO: better diagnostics (file name) */
                            return e(format!("Undefined symbol {} referenced in a file with number {}", name, file.number));
                        }
                        Some(symbol) => symbol.value().clone()
                    }
                };

            let symbol_address = self.get_symbol_address(symbol);
            let rela_address = self.get_rela_address(entry, inpsect_num);

            let value = symbol_address.checked_add_signed(entry.r_addend).unwrap();

            /* Just a few relocations types, enough to carry as forward */
            match entry.r_info_type {
                /* direct 64 bit  */
                R_X86_64_64 => {
                    write_ne_at_pos(rela_address, value, &mut section_writer)?;
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
                    write_ne_at_pos(rela_address, value_trimmed, &mut section_writer)?;
                }
                /* PC relative 32 bit signed */
                R_X86_64_PC32 => {}

                _ => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "Requested relocation type is not implemented yet",
                    ))
                }
            };
        }

        Ok(section_writer.into_inner())
    }
}

fn main() {}
