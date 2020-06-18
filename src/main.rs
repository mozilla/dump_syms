// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod action;
mod cache;
mod common;
mod dumper;
mod line;
mod linux;
mod mac;
mod mapping;
mod utils;
mod windows;

use clap::{crate_authors, crate_version, App, Arg};
use log::error;
use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};
use std::ops::Deref;
use std::panic;

use crate::action::Action;
use crate::common::FileType;

fn main() {
    let matches = App::new("dump_syms")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about("Dump debug symbols to breakpad symbols")
        .arg(
            Arg::with_name("filenames")
                .help("Files to dump (.dll, .exe, .pdb, .pd_, .so, .dbg)")
                .required(true)
                .multiple(true)
                .takes_value(true)
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
            Arg::with_name("type")
                .help("Debug file type, can be elf, macho or pdb")
                .short("t")
                .long("type")
                .default_value("")
                .takes_value(true),
        ).arg(
            Arg::with_name("list_arch")
                .help("List the architectures present in the fat binaries")
                .long("list-arch")
        )
        .arg(
            Arg::with_name("num_jobs")
                .help("Number of jobs")
                .short("j")
                .value_name("NUMBER")
                .default_value("")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mapping_var")
                .help("A pair var=value such as rev=123abcd")
                .long("mapping-var")
                .multiple(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mapping_src")
                .help("Regex to match a path with capturing groups")
                .long("mapping-src")
                .multiple(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mapping_dest")
                .help(r#"A replacement string using groups, variables (set with --mapping-var), special variable like DIGEST or digest.
For example with --mapping-var="rev=123abc" --mapping-src="/foo/bar/(.*)" --mapping-dest="https://my.source.org/{rev}/{digest}/{1}" a path like "/foo/bar/myfile.cpp" will be transformed into "https://my.source.org/123abc/sha512_of_myfile.cpp/myfile.cpp"
"#)
                .long("mapping-dest")
                .multiple(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mapping_file")
                .help("A json file containing mapping")
                .long("mapping-file")
                .takes_value(true),
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
    let mapping_var = matches
        .values_of("mapping_var")
        .map(|v| v.collect::<Vec<_>>());
    let mapping_src = matches
        .values_of("mapping_src")
        .map(|v| v.collect::<Vec<_>>());
    let mapping_dest = matches
        .values_of("mapping_dest")
        .map(|v| v.collect::<Vec<_>>());
    let mapping_file = matches.value_of("mapping_file");
    let num_jobs = if let Ok(num_jobs) = matches.value_of("num_jobs").unwrap().parse::<usize>() {
        num_jobs
    } else {
        num_cpus::get()
    };
    let typ = matches.value_of("type").unwrap();
    let file_type = if filenames.len() >= 2 && typ == "" {
        eprintln!("Since there are several files to dump, the type must be specified with --type");
        std::process::exit(1);
    } else {
        let t = common::FileType::from_str(typ);
        match t {
            FileType::Elf | FileType::Macho | FileType::Pdb => t,
            _ => {
                eprintln!("Type must be one of the values: elf, macho or pdb");
                std::process::exit(1);
            }
        }
    };

    let action = if matches.is_present("list_arch") {
        Action::ListArch
    } else {
        Action::Dump(dumper::Config {
            output,
            symbol_server,
            store,
            debug_id,
            code_id,
            arch,
            file_type,
            num_jobs,
            mapping_var,
            mapping_src,
            mapping_dest,
            mapping_file,
        })
    };

    if let Err(e) = action.action(&filenames) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
