#![feature(cstr_from_bytes_until_nul)]
#![feature(io_error_more)]
#![feature(mixed_integer_ops)]
#[macro_use]
extern crate macro_attr;
extern crate clap;

use anyhow::{anyhow, Error, Result};
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

use crate::misc::ErrorCollection;
use crate::processing_stage_1::{Layout, PreprocessedFile};
use crate::processing_stage_2::{process_symbols_from_file, SymbolMap};
use crate::processing_stage_3::{fix_layout, FinalLayout};
use crate::processing_stage_4::RelocatedFile;
use crate::processing_stage_5::generate_output_executable;
use crate::schemes::DEFAULT_SCHEME;

use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;

impl ErrorCollection {
    fn open<E: std::error::Error>(filename: &str, payload: E) -> Error {
        anyhow!("Cannot open file '{}': {}", filename, payload)
    }

    fn invalid_layout(payload: Error) -> Error {
        payload.context(format!("Error in provided LayoutScheme"))
    }

    fn preprocessing(filename: &str, payload: Error) -> Error {
        payload.context(format!("Error while preprocessing file '{}'", filename))
    }

    fn processing_symbols(filename: &str, payload: Error) -> Error {
        payload.context(format!(
            "Error while gathering symbols from file '{}'",
            filename
        ))
    }

    fn fixing_layout(payload: Error) -> Error {
        payload.context(format!("Error while creating final executable layout"))
    }

    fn relocating(filename: &str, payload: Error) -> Error {
        payload.context(format!("Error while relocating file: {}", filename))
    }

    fn output_final_executable(filename: &str, payload: Error) -> Error {
        payload.context(format!("Error while creating output file '{}'", filename))
    }
}

fn run_stage_1<'a>(
    layout: &Layout,
    input_filenames: Vec<&'a String>,
) -> Result<Vec<PreprocessedFile<'a>>> {
    println!("[1/5] preprocessing files");

    input_filenames
        .par_iter()
        .enumerate()
        .map(|(number, filename)| -> Result<PreprocessedFile<'a>> {
            let mut file =
                std::fs::File::open(filename).map_err(|e| ErrorCollection::open(filename, e))?;

            PreprocessedFile::new(filename, &mut file, number, &layout)
                .map_err(|e| ErrorCollection::preprocessing(filename, e))
        })
        .collect()
}

fn run_stage_2(preprocessed_files: &Vec<PreprocessedFile>) -> Result<SymbolMap> {
    println!("[2/5] gathering all symbols");

    let symbol_map: SymbolMap = SymbolMap::new();

    preprocessed_files.par_iter().try_for_each(|file| {
        process_symbols_from_file(file, &symbol_map)
            .map_err(|e| ErrorCollection::processing_symbols(file.filename, e))
    })?;

    Ok(symbol_map)
}

fn run_stage_3<'a>(
    layout: &'a Layout<'a>,
    preprocessed_files: &'a Vec<PreprocessedFile>,
) -> Result<FinalLayout<'a>> {
    println!("[3/5] fixing layout");
    fix_layout(&layout, &preprocessed_files).map_err(ErrorCollection::fixing_layout)
}

fn run_stage_4<'a>(
    preprocessed_files: &'a Vec<PreprocessedFile>,
    final_layout: &'a FinalLayout,
    symbol_map: &'a SymbolMap,
) -> Result<Vec<RelocatedFile<'a>>> {
    println!("[4/5] relocating");

    preprocessed_files
        .par_iter()
        .map(|file| {
            RelocatedFile::process(file, &final_layout, &symbol_map)
                .map_err(|e| ErrorCollection::relocating(file.filename, e))
        })
        .collect()
}

fn run_stage_5<'a>(
    final_layout: &'a FinalLayout,
    symbol_map: &'a SymbolMap,
    relocated_files: &'a Vec<RelocatedFile<'a>>,
    output_filename: &str,
) -> Result<()> {
    println!("[5/5] outputing");

    let output = generate_output_executable(&relocated_files, &final_layout, &symbol_map)
        .map_err(|e| ErrorCollection::output_final_executable(output_filename, e))?;

    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.create_new(true).write(true).mode(0o755); /* RWX for owner, RX for others. */
    let mut output_file = options
        .open(output_filename)
        .map_err(Error::new)
        .map_err(|e| ErrorCollection::output_final_executable(output_filename, e))?;

    output_file
        .write_all(&output)
        .map_err(Error::new)
        .map_err(|e| ErrorCollection::output_final_executable(output_filename, e))
}

fn link(output_filename: &str, input_filenames: Vec<&String>) -> Result<()> {
    let layout = Layout::new(&DEFAULT_SCHEME).map_err(ErrorCollection::invalid_layout)?;

    let preprocessed_files = run_stage_1(&layout, input_filenames)?;
    let symbol_map = run_stage_2(&preprocessed_files)?;
    let final_layout = run_stage_3(&layout, &preprocessed_files)?;
    let relocated_files = run_stage_4(&preprocessed_files, &final_layout, &symbol_map)?;

    run_stage_5(
        &final_layout,
        &symbol_map,
        &relocated_files,
        output_filename,
    )
}

fn main() -> Result<(), anyhow::Error> {
    let matches = Command::new("clingy")
        .about("simple linker for elf")
        .arg(arg!(output: -o --output <output_file> "output filename"))
        .arg(arg!(input: <input_file> ... "input filenames"))
        .get_matches();

    let output_file: &String = matches.get_one("output").unwrap();
    let input_files: Vec<&String> = matches.get_many("input").unwrap().collect();

    link(output_file, input_files)
}
