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

use vec_map_derive::{Token, NumericIndex};
use std::io::Result as IoResult;

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

