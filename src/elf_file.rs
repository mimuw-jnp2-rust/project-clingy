use bytemuck::Pod;
use bytemuck_derive::{Pod, Zeroable};
use std::ffi::CStr;
use std::io::{Error, ErrorKind, Read, Result as IoResult};

/* Reading data from file.
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
 *
 * Elf{Rela, Symtab, StringTable}Adapter convenience structs allow for simple parsing of data from
 * file.
 */

#[derive(Debug)]
pub struct ElfFileContent {
    pub content: Vec<u8>,
}

impl ElfFileContent {
    pub fn read(file: &mut std::fs::File) -> IoResult<Self> {
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

    pub fn get_elf_header(&self) -> IoResult<&ElfHeader> {
        self.get::<ElfHeader>(0)
    }

    pub fn get_section_entry(&self, num: u16) -> IoResult<&ElfSectionEntry> {
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
pub struct ElfHeader {
    pub e_ident_magic: [u8; 4],
    pub e_ident_class: u8,
    pub e_ident_endianness: u8,
    pub e_ident_hversion: u8,
    pub e_ident_osabi: u8,
    pub e_ident_pad: u64,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: ElfAddr,
    pub e_phoff: ElfOffset,
    pub e_shoff: ElfOffset,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

pub const ELF_IDENT_MAGIC: [u8; 4] = *b"\x7fELF";
pub const ELF_IDENT_CLASS_X86_64: u8 = 2;
pub const ELF_IDENT_ENDIANNESS_LITTLE: u8 = 1;
pub const ELF_IDENT_HVERSION_CURRENT: u8 = 1;
pub const ELF_IDENT_OSABI_SYSV: u8 = 0;
pub const ELF_TYPE_RELOCATABLE: u16 = 1;
pub const ELF_TYPE_EXECUTABLE: u16 = 2;
pub const ELF_MACHINE_X86_64: u16 = 0x3E;
pub const ELF_VERSION_CURRENT: u32 = 1;

impl ElfHeader {
    fn verify(&self) -> IoResult<()> {
        let e = |desc| Err(Error::new(ErrorKind::InvalidData, desc));

        match true {
            _ if self.e_ident_magic != ELF_IDENT_MAGIC => e("Bad magic. Not an ELF file?"),
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
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;

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
pub struct ElfSectionEntry {
    pub sh_name: u32,
    pub sh_type: u32,  /* see SHT_* constants */
    sh_flags: u64, /* see SHF_* constants */
    sh_addr: ElfAddr,
    pub sh_offset: ElfOffset,
    pub sh_size: u64,
    sh_link: u32,
    pub sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

pub const PT_NULL: u32 = 0; /* Program header table entry unused */
pub const PT_LOAD: u32 = 1; /* Loadable program segment */

pub const PF_EXEC: u32 = 1 << 0; /* Segment is executable */
pub const PF_WRITE: u32 = 1 << 1; /* Segment is writable */
pub const PF_READ: u32 = 1 << 2; /* Segment is readable */

/* ELF program header entry. */
#[derive(Copy, Clone, Zeroable, Pod, Debug)]
#[repr(C, packed)]
pub struct ElfProgramHeaderEntry {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: ElfOffset,
    pub p_vaddr: ElfAddr,
    pub p_paddr: ElfAddr,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/* ELF .symtab entry. */
#[derive(Copy, Clone, Zeroable, Pod, Debug)]
#[repr(C, packed)]
pub struct ElfSymtabEntry {
    pub st_name: u32,
    st_info: u8,
    st_other: u8,
    pub st_shndx: u16,
    pub st_value: ElfAddr,
    st_size: u64,
}

/* Bit flipping makes my heart melt */
impl ElfSymtabEntry {
    pub fn get_stt(&self) -> u8 {
        self.st_info & 0xf
    }
    pub fn get_stb(&self) -> u8 {
        self.st_info >> 4
    }
}

pub const STN_UNDEF: u16 = 0; /* Undefined symbol.  */

pub const STB_LOCAL: u8 = 0; /* Local symbol */
pub const STB_GLOBAL: u8 = 1; /* Global symbol */
pub const STB_WEAK: u8 = 2; /* Weak symbol */

pub const STT_NOTYPE: u8 = 0; /* Symbol type is unspecified */
pub const STT_OBJECT: u8 = 1; /* Symbol is a data object */
pub const STT_FUNC: u8 = 2; /* Symbol is a code object */
pub const STT_SECTION: u8 = 3; /* Symbol associated with a section */
pub const STT_FILE: u8 = 4; /* Symbol's name is file name */
pub const STT_COMMON: u8 = 5; /* Symbol is a common data object */
pub const STT_TLS: u8 = 6; /* Symbol is thread-local data object*/

/* ELF .rela. entry. */
#[derive(Copy, Clone, Zeroable, Pod, Debug)]
#[repr(C, packed)]
pub struct ElfRelaEntry {
    pub r_offset: ElfAddr, /* Offset of relocated bytes. */
    pub r_info_type: u32,  /* Relocation type. */
    pub r_info_sym: u32,   /* Symbol index. */
    pub r_addend: i64,
}

/* A tiny subset of all possible relocation types */
pub const R_X86_64_64: u32 = 1; /* Direct 64 bit  */
pub const R_X86_64_PC32: u32 = 2; /* PC relative 32 bit signed */
pub const R_X86_64_32S: u32 = 11; /* Direct 32 bit sign extended */

/* TODO: support .rel entries. (They are abandoned now, everyone uses .rela, so it's not really
 * that important). */

#[derive(Debug)]
pub struct ElfStringTableAdapter<'a> {
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
pub struct ElfSymtabAdapter<'a> {
    file: &'a ElfFileContent,
    offset: u64,
    symbol_size: u64,
    pub symbols_count: u64,
    pub strtab: ElfStringTableAdapter<'a>,
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

pub struct ElfRelaAdapter<'a> {
    file: &'a ElfFileContent,
    offset: u64,
    entry_size: u64,
    pub entries_count: u64,
    pub symtab: ElfSymtabAdapter<'a>,
}

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
