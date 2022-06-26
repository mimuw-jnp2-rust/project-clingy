#![feature(cstr_from_bytes_until_nul)]
#![feature(io_error_more)]
#![feature(mixed_integer_ops)]
#[macro_use]
extern crate macro_attr;
extern crate clap;

use clap::{arg, Command};

mod elf_file;
mod misc;
mod processing_stage_1;
mod processing_stage_2;
mod processing_stage_3;
mod processing_stage_4;
mod processing_stage_5;
mod schemes;

use std::io::Write;

use crate::processing_stage_1::{Layout, PreprocessedFile};
use crate::processing_stage_2::{process_symbols_from_file, SymbolMap};
use crate::processing_stage_3::fix_layout;
use crate::processing_stage_4::RelocatedFile;
use crate::processing_stage_5::generate_output_executable;
use crate::schemes::DEFAULT_SCHEME;

use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;

use clap::Parser;

fn link(output_filename: &str, input_filenames: Vec<&String>) {
    let default_layout: Layout = Layout::new(&DEFAULT_SCHEME).unwrap();

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

fn main() {
    let matches = Command::new("clingy")
        .about("simple linker for elf")
        .arg(arg!(output: -o --output <output_file> "output filename"))
        .arg(arg!(input: <input_file> ... "input filenames"))
        .get_matches();

    let output_file: &String = matches.get_one("output").unwrap();
    let input_files: Vec<&String> = matches.get_many("input").unwrap().collect();

    link(output_file, input_files);
}
