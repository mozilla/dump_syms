// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod action;
mod cache;
mod common;
mod utils;
mod windows;

use clap::{crate_authors, crate_version, App, Arg};
use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};

use crate::action::{Action, Dumper};

fn main() {
    // Init the logger
    let _ = TermLogger::init(LevelFilter::Info, Config::default(), TerminalMode::Stderr);

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
            Arg::with_name("store")
                .help("Store output file as FILENAME.pdb/DEBUG_ID/FILENAME.sym in the given directory")
                .short("s")
                .long("store")
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
    let store = matches.value_of("store");

    let action = Action::Dump(Dumper {
        output,
        symbol_server,
        store,
    });

    if let Err(e) = action.action(&filename) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
