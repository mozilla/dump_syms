// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
mod cache;
mod common;
mod utils;
mod windows;

use clap::{App, Arg};

use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

fn get_writer_for_sym(file_name: &str) -> BufWriter<Box<dyn Write>> {
    let output: Box<dyn Write> = if file_name.is_empty() || file_name == "-" {
        Box::new(io::stdout())
    } else {
        let path = PathBuf::from(file_name);
        let output = File::create(&path)
            .unwrap_or_else(|_| panic!("Cannot open file {} for writing", path.to_str().unwrap()));
        Box::new(output)
    };
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
                .help("File to dump (.dll, .exe, .pdb or .pd_)")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output")
                .help("Output file or - for stdout")
                .short("o")
                .long("output")
                .default_value("-")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("symbol-server")
                .help("Symbol Server configuration\n(e.g. \"SRV*c:\\symcache\\*https://symbols.mozilla.org/\")\nIt can be in file $HOME/.dump_syms/config too.")
                .long("symbol-server")
                .takes_value(true),
        )
        .get_matches();

    let output = matches.value_of("output").unwrap();
    let filename = matches.value_of("filename").unwrap();
    let symbol_server = matches.value_of("symbol-server");

    let path = PathBuf::from(filename);
    let buf = utils::read_file(&path);
    let filename = path.file_name().unwrap().to_str().unwrap().to_string();

    if let Err(e) = match path.extension().unwrap().to_str().unwrap() {
        "dll" | "exe" => {
            let res = windows::utils::get_pe_pdb_buf(path, &buf, symbol_server);
            if let Some((pe, pdb_buf, pdb_name)) = res {
                let output = get_writer_for_sym(&output);
                windows::pdb::PDBInfo::dump(&pdb_buf, pdb_name, filename, Some(pe), output)
            } else {
                Err(From::from("No pdb file found"))
            }
        }
        "pdb" | "pd_" => {
            let output = get_writer_for_sym(&output);
            windows::pdb::PDBInfo::dump(&buf, filename, "".to_string(), None, output)
        }
        _ => Ok(()),
    } {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
