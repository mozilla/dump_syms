// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
mod utils;
mod windows;

use clap::{App, Arg};

use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

fn get_writer_for_sym(file_name: &str) -> BufWriter<File> {
    let mut path = PathBuf::from(file_name);
    path.set_extension("sym");

    let output = File::create(&path)
        .unwrap_or_else(|_| panic!("Cannot open file {} for writing", path.to_str().unwrap()));
    BufWriter::new(output)
}

fn main() {
    // Init the logger
    let _ = TermLogger::init(LevelFilter::Warn, Config::default(), TerminalMode::Stderr);

    let matches = App::new("dump_syms")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about("Dump debug symbols to breakpad symbols")
        .arg(
            Arg::with_name("filename")
                .help("File to dump")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let filename = matches.value_of("filename").unwrap();
    let path = PathBuf::from(filename);
    let buf = utils::read_file(&path);
    let filename = path.file_name().unwrap().to_str().unwrap().to_string();

    match path.extension().unwrap().to_str().unwrap() {
        "dll" | "exe" => {
            let res = windows::utils::get_pe_pdb_buf(&path, &buf);
            if let Some((pe, pdb_buf, pdb_name)) = res {
                let output = get_writer_for_sym(&pdb_name);
                windows::pdb::PDBInfo::dump(&pdb_buf, pdb_name, filename, Some(pe), output)
                    .unwrap_or_else(|e| panic!(e));
            } else {
                panic!("No pdb file found");
            }
        }
        "pdb" => {
            let output = get_writer_for_sym(&filename);
            windows::pdb::PDBInfo::dump(&buf, filename, "".to_string(), None, output)
                .unwrap_or_else(|e| panic!(e));
        }
        _ => {}
    }
}
