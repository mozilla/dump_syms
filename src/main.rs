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
            Arg::with_name("debug_id")
                .help("Get the pdb file passed as argument from the cache or from symbol server using the debug id")
                .long("debug-id")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("code_id")
                .help("Get the dll/exe file passed as argument from the cache or from symbol server using the code id")
                .long("code-id")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("symbol-server")
                .help("Symbol Server configuration\n(e.g. \"SRV*c:\\symcache\\*https://symbols.mozilla.org/\")\nIt can be in file $HOME/.dump_syms/config too.")
                .long("symbol-server")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .help("Set the level of verbosity (off (default), error, warn, info, debug, trace)")
                .long("verbose")
                .default_value("off")
                .takes_value(true),
        )
        .get_matches();

    let verbosity = match matches.value_of("verbose").unwrap() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Off,
    };

    // Init the logger
    let _ = TermLogger::init(verbosity, Config::default(), TerminalMode::Stderr);

    let output = matches.value_of("output").unwrap();
    let filename = matches.value_of("filename").unwrap();
    let symbol_server = matches.value_of("symbol-server");
    let store = matches.value_of("store");
    let debug_id = matches.value_of("debug_id");
    let code_id = matches.value_of("code_id");

    let action = Action::Dump(Dumper {
        output,
        symbol_server,
        store,
        debug_id,
        code_id,
    });

    if let Err(e) = action.action(&filename) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
