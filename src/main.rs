#![feature(cstr_from_bytes_until_nul)]
#![feature(io_error_more)]
#![feature(mixed_integer_ops)]
use bytemuck::Pod;
use bytemuck_derive::{Pod, Zeroable};
use custom_derive::custom_derive;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::ffi::CStr;
use std::io::{Error, ErrorKind, Read, Result as IoResult, Seek, SeekFrom, Write};

mod misc;
use misc::align;

use vec_map::{NumericIndex, Token, VecDict};
use vec_map_derive::{NumericIndexTrait, TokenTrait};

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
 * To read and write data, regular Rust API from std::io is used (File, Write, etc.).
 */

#[derive(Debug)]
struct ElfFileContent {
    content: Vec<u8>,
}

impl ElfFileContent {
    fn read(file: &mut std::fs::File) -> IoResult<Self> {
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
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

const ELF_IDENT_MAGIC: [u8; 4] = *b"\x7fELF";
const ELF_IDENT_CLASS_X86_64: u8 = 2;
const ELF_IDENT_ENDIANNESS_LITTLE: u8 = 1;
const ELF_IDENT_HVERSION_CURRENT: u8 = 1;
const ELF_IDENT_OSABI_SYSV: u8 = 0;
const ELF_TYPE_RELOCATABLE: u16 = 1;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_MACHINE_X86_64: u16 = 0x3E;
const ELF_VERSION_CURRENT: u32 = 1;

impl ElfHeader {
    fn verify(&self) -> IoResult<()> {
        let e = |desc| Err(Error::new(ErrorKind::InvalidData, desc));

        match true {
            _ if &self.e_ident_magic != &ELF_IDENT_MAGIC => e("Bad magic. Not an ELF file?"),
            _ if self.e_ident_class != ELF_IDENT_CLASS_X86_64 => {
                e("Bad file class. Was the object file built for x86_64 CPU?")
            }
            _ if self.e_ident_endianness != ELF_IDENT_ENDIANNESS_LITTLE => {
                e("Bad endianness. Was the object file built for x86_64 CPU?")
            }
            _ if self.e_ident_hversion != ELF_IDENT_HVERSION_CURRENT => {
                e("Unrecognized header version (should be 1). File corrupted?")
            }
            _ if self.e_ident_osabi != ELF_IDENT_OSABI_SYSV => {
                e("File is not a static relocatable file (.o) or is not compatible with Linux")
            }
            _ if self.e_type != ELF_TYPE_RELOCATABLE => e("Not a relocatable (.o) file"),
            _ if self.e_machine != ELF_MACHINE_X86_64 => e("File not built for x86_64 CPU"),
            _ if self.e_version != ELF_VERSION_CURRENT => {
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

const PT_NULL: u32 = 0; /* Program header table entry unused */
const PT_LOAD: u32 = 1; /* Loadable program segment */

const PF_EXEC: u32 = 1 << 0; /* Segment is executable */
const PF_WRITE: u32 = 1 << 1; /* Segment is writable */
const PF_READ: u32 = 1 << 2; /* Segment is readable */

/* ELF program header entry. */
#[derive(Copy, Clone, Zeroable, Pod, Debug)]
#[repr(C, packed)]
struct ElfProgramHeaderEntry {
    p_type: u32,
    p_flags: u32,
    p_offset: ElfOffset,
    p_vaddr: ElfAddr,
    p_paddr: ElfAddr,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
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

#[derive(Debug)]
struct ElfStringTableAdapter<'a> {
    offset: u64,
    end: u64,
    file: &'a ElfFileContent,
}

/* Adapts section entry into string table */
impl<'a> ElfStringTableAdapter<'a> {
    pub fn adapt(section_entry_num: u16, file: &'a ElfFileContent) -> IoResult<Self> {
        let entry = file.get_section_entry(section_entry_num)?;

        if let SHT_STRTAB = entry.sh_type {
            Ok(ElfStringTableAdapter {
                offset: entry.sh_offset,
                end: entry.sh_offset + entry.sh_size,
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
        let end = self.end as usize;

        let content = &self.file.content[begin..end];

        CStr::from_bytes_until_nul(content)
            .map_err(|_| e("String in the string table is not null-terminated. File corrupted?"))?
            .to_str()
            .map_err(|_| {
                e("String in the string table contains invalid characters. File corrupted?")
            })
    }
}

#[derive(Debug)]
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

/*
 * TODO: This code is quite similar to code of ElfSymtabAdapter struct. Maybe abstract something?
 */
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
                /*OutSectScheme {
                    name: ".bss",
                    inpsects: &[".bss", ".bss.*"],
                },*/
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
 * }
 *
 */

type FileIndex = u16;
type SegmentIndex = u16;

#[derive(Debug)]
enum AddrScheme {
    CurrentLocation,
    Absolute(ElfAddr),
}

#[derive(Debug)]
struct OutSectScheme<'a> {
    name: &'a str,
    inpsects: &'a [&'a str],
}

#[derive(Debug)]
struct SegmentScheme<'a> {
    name: &'a str,     /* Segment name */
    start: AddrScheme, /* Starting address of segment */
    alignment: u64,    /* Segment alignment (in bytes) */
    sections: &'a [OutSectScheme<'a>],
}

#[derive(Debug)]
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
 *    *  We copy each InpSect that needs some relocations. We go through the .rela and .rel tables
 *       and, using hashtable and .symtab, we relocate.
 *
 */

custom_derive! {
    #[derive(TokenTrait, NumericIndexTrait, Debug, Clone, Copy)]
    struct InpSectToken(usize);
}

custom_derive! {
    #[derive(TokenTrait, NumericIndexTrait, Debug, Clone, Copy)]
    struct OutSectToken(usize);
}

custom_derive! {
    #[derive(TokenTrait, NumericIndexTrait, Debug, Clone, Copy)]
    struct SegmentToken(usize);
}

custom_derive! {
    #[derive(TokenTrait, NumericIndexTrait, Debug, Clone, Copy)]
    struct FileToken(usize);
}

type OutSectMatchers = VecDict<OutSectToken, Vec<globset::GlobMatcher>>;

#[derive(Debug)]
struct Layout<'a> {
    scheme: &'a LayoutScheme<'a>,
    outsect_count: usize,
    outsect_matchers: OutSectMatchers,
}

impl<'a> Layout<'a> {
    fn new(scheme: &'a LayoutScheme<'a>) -> IoResult<Self> {
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

#[derive(Clone, Debug)]
struct InpSectFileMapping {
    outsect_token: OutSectToken,
    inpsect_offset_in_outsect_file_part: u64,
}

type InpSectToOutSect = VecDict<InpSectToken, InpSectFileMapping>;
type OutSectPerFileOffsets = VecDict<OutSectToken, u64>;
type InpSectToRela = VecDict<InpSectToken, InpSectToken>;

#[derive(Debug)]
struct PreprocessedFile {
    token: FileToken,
    content: ElfFileContent,
    symtab_token: InpSectToken,
    inpsect_to_outsect: InpSectToOutSect,
    inpsect_to_rela: InpSectToRela,
    outsects_per_file_size: OutSectPerFileOffsets,
}

impl PreprocessedFile {
    fn new(file: &mut std::fs::File, number: usize, layout: &Layout) -> IoResult<Self> {
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

    fn get_inpsect_file_mapping(&self, token: InpSectToken) -> IoResult<&InpSectFileMapping> {
        self.inpsect_to_outsect.get(&token).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "Entry in symbol table points to a special section.",
            )
        })
    }
}

type SymbolMap = dashmap::DashMap<String, Symbol>;

#[derive(Debug, Clone)]
enum SymbolVisibility {
    Strong,
    Weak,
}

#[derive(Debug, Clone)]
struct Symbol {
    outsect_token: OutSectToken,
    file_token: FileToken,
    outsect_offset: u64,
    visibility: SymbolVisibility,
}

impl Symbol {
    fn get_symbol_address(&self, layout: &FinalLayout) -> u64 {
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

struct InpSectRelativeAddress {
    outsect_num: u16,
    offset: u64,
}

fn process_symbols_from_file(file: &PreprocessedFile, symbol_map: &SymbolMap) -> IoResult<()> {
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
                    (Weak, Weak) => Ok(()), /* TODO: select bigger weak symbol */
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

#[derive(Debug)]
struct FinalSegment {
    size: u64,
    virtmem_address: u64,
    offset_in_output_file: u64,
}

#[derive(Debug, Clone)]
struct FinalOutSect {
    size: u64,
    input_file_slots_offsets: VecDict<FileToken, u64>,
    virtmem_address: u64,
    offset_in_output_file: u64,
}

#[derive(Debug)]
struct FinalLayout<'a> {
    layout: &'a Layout<'a>,
    final_segments: VecDict<SegmentToken, FinalSegment>,
    final_outsects: VecDict<OutSectToken, FinalOutSect>,
}

fn fix_layout<'a>(
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
    let mut current_offset_in_file = MAXPAGESIZE;

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

fn write_ne_at_pos<T, V>(pos: u64, val: T, writer: &mut V) -> IoResult<()>
where
    T: WritePrimitive,
    V: std::io::Write + std::io::Seek,
{
    writer.seek(std::io::SeekFrom::Start(pos))?;
    val.write_ne_bytes(writer)
}

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
struct RelocatedFile<'a> {
    preprocessed: &'a PreprocessedFile,
    inpsects: VecDict<InpSectToken, SectionContent>,
}

impl<'a> RelocatedFile<'a> {
    fn process(
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

fn generate_output_executable(
    relocated_files: &Vec<RelocatedFile>,
    layout: &FinalLayout,
    symbol_map: &SymbolMap,
) -> IoResult<Vec<u8>> {
    let elf_header_size = std::mem::size_of::<ElfHeader>();

    let prolog_size = {
        let program_header_size = std::mem::size_of::<ElfProgramHeaderEntry>();
        let program_headers_count = layout.final_segments.len();

        elf_header_size + program_header_size * program_headers_count
    };

    if prolog_size > 0x1000 {
        return Err(Error::new(
            ErrorKind::StorageFull,
            format!(
                "For now the whole 'prolog' (file header, \
                 section headers, program headers) have to fit in MAGPAGESIZE: {:#x}",
                MAXPAGESIZE
            ),
        ));
    }

    let start = symbol_map
        .get("_start")
        .ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                "Cannot find _start symbol in the relocated files",
            )
        })?
        .value()
        .get_symbol_address(layout);

    let elf_header = ElfHeader {
        e_ident_magic: ELF_IDENT_MAGIC,
        e_ident_class: ELF_IDENT_CLASS_X86_64,
        e_ident_endianness: ELF_IDENT_ENDIANNESS_LITTLE,
        e_ident_hversion: ELF_IDENT_HVERSION_CURRENT,
        e_ident_osabi: ELF_IDENT_OSABI_SYSV,
        e_ident_pad: 0,
        e_type: ELF_TYPE_EXECUTABLE,
        e_machine: ELF_MACHINE_X86_64,
        e_version: ELF_VERSION_CURRENT,
        e_entry: start,
        e_phoff: elf_header_size as u64,
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: std::mem::size_of::<ElfHeader>() as u16,
        e_phentsize: std::mem::size_of::<ElfProgramHeaderEntry>() as u16,
        e_phnum: layout.final_segments.len() as u16,
        e_shentsize: 0,
        e_shnum: 0,
        e_shstrndx: 0,
    };

    let segments_offset = align(prolog_size as u64, MAXPAGESIZE);

    let file_size = layout
        .final_segments
        .tok_iter()
        .map(|(_, segment)| segment)
        .fold(segments_offset, |acc, segment| {
            align(acc, MAXPAGESIZE) + segment.size
        });

    let mut final_content = vec![0u8; file_size as usize];
    let mut content_writer = std::io::Cursor::new(&mut final_content[..]);

    content_writer.seek(SeekFrom::Start(0))?;
    content_writer.write_all(bytemuck::bytes_of(&elf_header))?;

    let segment_iter = layout.final_segments.tok_iter();

    for (token, segment) in segment_iter {
        let SegmentToken(index) = token;
        let scheme = &layout.layout.scheme.segments[index];

        let elf_program_header_entry = ElfProgramHeaderEntry {
            p_type: PT_LOAD,
            p_flags: PF_EXEC | PF_WRITE | PF_READ, /* uhh that's really bad, URGENT TODO */
            p_offset: segment.offset_in_output_file,
            p_vaddr: segment.virtmem_address,
            p_paddr: segment.virtmem_address,
            p_filesz: segment.size,
            p_memsz: segment.size,
            p_align: scheme.alignment,
        };

        content_writer.write_all(bytemuck::bytes_of(&elf_program_header_entry))?;
    }

    assert!(content_writer.seek(SeekFrom::Current(0))? <= segments_offset);
    content_writer.seek(SeekFrom::Start(segments_offset))?;

    for file in relocated_files {
        for (token, section_content) in file.inpsects.tok_iter() {
            let InpSectFileMapping {
                outsect_token: token,
                inpsect_offset_in_outsect_file_part,
            } = match file.preprocessed.inpsect_to_outsect.get(&token) {
                Some(mapping) => mapping,
                None => continue,
            };

            let FinalOutSect {
                size: _,
                input_file_slots_offsets,
                virtmem_address: _,
                offset_in_output_file,
            } = &layout.final_outsects[&token];

            let inpsect_start = offset_in_output_file
                + inpsect_offset_in_outsect_file_part
                + input_file_slots_offsets[&file.preprocessed.token];

            content_writer.seek(SeekFrom::Start(inpsect_start))?;
            content_writer.write_all(section_content)?;
        }
    }

    Ok(final_content)
}

fn main() {
    let default_layout: Layout = Layout::new(&DEFAULT_SCHEME).unwrap();
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        println!("Usage: relocatable_files... executable_file");
        std::process::exit(1);
    }

    let input_filenames = &args[1..args.len() - 1];
    let output_filename = &args[args.len() - 1];

    println!("[1/5] preprocessing files");

    let preprocessed_files: Vec<_> = input_filenames
        .par_iter()
        .enumerate()
        .map(|(number, filename)| {
            let mut file = std::fs::File::open(filename).unwrap();
            PreprocessedFile::new(&mut file, number, &default_layout).unwrap()
        })
        .collect();

    println!("[2/5] fixing layout");

    let final_layout = fix_layout(&default_layout, &preprocessed_files).unwrap();
    let symbol_map: SymbolMap = SymbolMap::new();

    println!("[3/5] gathering all symbols");

    preprocessed_files
        .par_iter()
        .for_each(|file| process_symbols_from_file(file, &symbol_map).unwrap());

    println!("[4/5] relocating");

    let relocated_files: Vec<_> = preprocessed_files
        .par_iter()
        .map(|file| RelocatedFile::process(file, &final_layout, &symbol_map).unwrap())
        .collect();

    println!("[5/5] outputing");

    let output = generate_output_executable(&relocated_files, &final_layout, &symbol_map).unwrap();

    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.create_new(true).write(true).mode(0o755); /* RWX for owner, RX for others. */
    let mut output_file = options.open(output_filename).unwrap();

    output_file.write_all(&output).unwrap();
}
