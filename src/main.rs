#![feature(cstr_from_bytes_until_nul)]
#![feature(io_error_more)]
#![feature(mixed_integer_ops)]
#[macro_use]
extern crate macro_attr;

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
