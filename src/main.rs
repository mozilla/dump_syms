// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod action;
mod cache;
mod common;
mod line;
mod linux;
mod mac;
mod utils;
mod windows;

use clap::{crate_authors, crate_version, App, Arg};
use log::error;
use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};
use std::ops::Deref;
use std::panic;

use crate::action::{Action, Dumper};

fn main() {
    let matches = App::new("dump_syms")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about("Dump debug symbols to breakpad symbols")
        .arg(
            Arg::with_name("filenames")
                .help("Files to dump (.dll, .exe, .pdb, .pd_, .so, .dbg)")
                .required(true)
                .takes_value(true)
                .max_values(2),
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
                .help("Set the level of verbosity (off, error (default), warn, info, debug, trace)")
                .long("verbose")
                .default_value("error")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("arch")
                .help("Set the architecture to select in fat binaries")
                .short("a")
                .long("arch")
                .default_value(common::get_compile_time_arch())
                .takes_value(true),
        )
        .arg(
            Arg::with_name("list_arch")
                .help("List the architectures present in the fat binaries")
                .long("list-arch")
        )
        .get_matches();

    let verbosity = match matches.value_of("verbose").unwrap() {
        "off" => LevelFilter::Off,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Error,
    };

    // Init the logger
    let _ = TermLogger::init(verbosity, Config::default(), TerminalMode::Stderr);

    // Set a panic hook to redirect to the logger
    panic::set_hook(Box::new(|panic_info| {
        let (filename, line) = panic_info
            .location()
            .map(|loc| (loc.file(), loc.line()))
            .unwrap_or(("<unknown>", 0));
        let cause = panic_info
            .payload()
            .downcast_ref::<String>()
            .map(String::deref)
            .unwrap_or_else(|| {
                panic_info
                    .payload()
                    .downcast_ref::<&str>()
                    .copied()
                    .unwrap_or("<cause unknown>")
            });
        error!("A panic occurred at {}:{}: {}", filename, line, cause);
    }));

    let output = matches.value_of("output").unwrap();
    let filenames: Vec<_> = matches.values_of("filenames").unwrap().collect();
    let symbol_server = matches.value_of("symbol-server");
    let store = matches.value_of("store");
    let debug_id = matches.value_of("debug_id");
    let code_id = matches.value_of("code_id");
    let arch = matches.value_of("arch").unwrap();

    let action = if matches.is_present("list_arch") {
        Action::ListArch
    } else {
        Action::Dump(Dumper {
            output,
            symbol_server,
            store,
            debug_id,
            code_id,
            arch,
        })
    };

    if let Err(e) = action.action(&filenames) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
