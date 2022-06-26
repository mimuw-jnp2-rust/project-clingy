use crate::elf_file::ElfSectionEntry;
use crate::elf_file::{PF_EXEC, PF_READ, PF_WRITE};
use crate::elf_file::{SHF_EXECINSTR, SHF_WRITE};
use bitflags::bitflags;

pub trait Align {
    fn align(&self, bound: Self) -> Self;
    fn align_inplace(&mut self, bound: Self);
}

impl Align for u64 {
    fn align(&self, bound: u64) -> u64 {
        ((*self + (bound - 1)) / bound) * bound
    }

    fn align_inplace(&mut self, bound: u64) {
        *self = self.align(bound)
    }
}

use std::io::Result as IoResult;
use vec_map_derive::{NumericIndex, Token};

macro_attr! {
    #[derive(Token!, NumericIndex!, Debug, Clone, Copy)]
    pub struct InpSectToken(pub usize);
}

macro_attr! {
    #[derive(Token!, NumericIndex!, Debug, Clone, Copy)]
    pub struct OutSectToken(pub usize);
}

macro_attr! {
    #[derive(Token!, NumericIndex!, Debug, Clone, Copy)]
    pub struct SegmentToken(pub usize);
}

macro_attr! {
    #[derive(Token!, NumericIndex!, Debug, Clone, Copy)]
    pub struct FileToken(pub usize);
}

pub trait WritePrimitive {
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

pub fn write_ne_at_pos<T, V>(pos: u64, val: T, writer: &mut V) -> IoResult<()>
where
    T: WritePrimitive,
    V: std::io::Write + std::io::Seek,
{
    writer.seek(std::io::SeekFrom::Start(pos))?;
    val.write_ne_bytes(writer)
}

bitflags! {
    #[derive(Default)]
    pub struct Permissions: u8 {
        const R = 0b001;
        const W = 0b010;
        const X = 0b100;
    }
}

impl Permissions {
    pub fn from_elf_shf(entry: &ElfSectionEntry) -> Self {
        let mut perm = Permissions::R;

        if entry.sh_flags & SHF_WRITE as u64 != 0 {
            perm |= Permissions::W;
        }
        if entry.sh_flags & SHF_EXECINSTR as u64 != 0 {
            perm |= Permissions::X;
        }

        perm
    }

    pub fn to_elf_pf(self) -> u32 {
        let mut flags: u32 = 0;

        if self.contains(Permissions::R) {
            flags |= PF_READ;
        }
        if self.contains(Permissions::W) {
            flags |= PF_WRITE;
        }
        if self.contains(Permissions::X) {
            flags |= PF_EXEC;
        }

        flags
    }
}

pub struct ErrorCollection {}
