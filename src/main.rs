// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use clap::ArgAction;
use clap::{crate_authors, crate_version, Arg, Command};
use log::error;
use once_cell::sync::Lazy;
use regex::Regex;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::ops::Deref;
use std::panic;

mod action;

use action::Action;
use dump_syms::common::{self, EXTRA_INFO};
use dump_syms::dumper;

fn cli() -> Command {
    Command::new("dump_syms")
    .version(crate_version!())
    .author(crate_authors!("\n"))
    .about("Dump debug symbols to breakpad symbols")
    .arg(
        Arg::new("filenames")
            .help("Files to dump (.dll, .exe, .pdb, .pd_, .so, .dbg)")
            .required(true)
            .num_args(1..)
    )
    .arg(
        Arg::new("output")
            .help("Output file or - for stdout")
            .short('o')
            .long("output")
    )
    .arg(
        Arg::new("store")
            .help("Store output file as FILENAME.pdb/DEBUG_ID/FILENAME.sym in the given directory")
            .short('s')
            .long("store")
    )
    .arg(
        Arg::new("debug_id")
            .help("Get the pdb file passed as argument from the cache or from symbol server using the debug id")
            .long("debug-id")
    )
    .arg(
        Arg::new("code_id")
            .help("Get the dll/exe file passed as argument from the cache or from symbol server using the code id")
            .long("code-id")
    )
    .arg(
        Arg::new("symbol_server")
            .help("Symbol Server configuration\n(e.g. \"SRV*c:\\symcache\\*https://symbols.mozilla.org/\")\nIt can be in file $HOME/.dump_syms/config too.")
            .long("symbol-server")
    )
    .arg(
        Arg::new("check_cfi")
            .help("Fail if there are no CFI data")
            .long("check-cfi")
            .action(ArgAction::SetTrue)
    )
    .arg(
        Arg::new("verbose")
            .help("Set the level of verbosity (off, error (default), warn, info, debug, trace)")
            .long("verbose")
            .default_value("error")
    )
    .arg(
        Arg::new("arch")
            .help("Set the architecture to select in fat binaries")
            .short('a')
            .long("arch")
            .default_value(common::get_compile_time_arch())
    )
    .arg(
        Arg::new("type")
            .help("Ignored, listed for compatibility only")
            .short('t')
            .long("type")
            .default_value("")
    ).arg(
        Arg::new("list_arch")
            .help("List the architectures present in the fat binaries")
            .long("list-arch")
            .action(ArgAction::SetTrue)
    )
    .arg(
        Arg::new("num_jobs")
            .help("Number of jobs")
            .short('j')
            .value_name("NUMBER")
            .default_value("")
    )
    .arg(
        Arg::new("mapping_var")
            .help("A pair var=value such as rev=123abcd")
            .long("mapping-var")
            .action(ArgAction::Append)
    )
    .arg(
        Arg::new("mapping_src")
            .help("Regex to match a path with capturing groups")
            .long("mapping-src")
            .action(ArgAction::Append)
    )
    .arg(
        Arg::new("mapping_dest")
            .help(r#"A replacement string using groups, variables (set with --mapping-var), special variable like DIGEST or digest.
For example with --mapping-var="rev=123abc" --mapping-src="/foo/bar/(.*)" --mapping-dest="https://my.source.org/{rev}/{digest}/{1}" a path like "/foo/bar/myfile.cpp" will be transformed into "https://my.source.org/123abc/sha512_of_myfile.cpp/myfile.cpp"
"#)
            .long("mapping-dest")
            .action(ArgAction::Append)
    )
    .arg(
        Arg::new("mapping_file")
            .help("A json file containing mapping")
            .long("mapping-file")
    )
    .arg(
        Arg::new("inlines")
            .help("Whether to emit INLINE and INLINE_ORIGIN directives")
            .long("inlines")
            .action(ArgAction::SetTrue)
    )
    .arg(Arg::new("extra_info")
             .help("Add an INFO line with the value passed to this argument")
             .long("extra-info")
             .action(ArgAction::Append)
    )
    .arg(Arg::new("no-generator")
             .help("Do not emit an INFO GENERATOR line holding the name and version of the dump_syms tool")
             .long("no-generator")
             .action(ArgAction::SetTrue)
    )
}

fn main() {
    let matches = cli().get_matches();

    let verbosity = match matches.get_one::<String>("verbose").unwrap().as_str() {
        "off" => LevelFilter::Off,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Error,
    };

    // Init the logger
    let mut config = ConfigBuilder::new();
    // Note that this will fail if we have more than 1 thread running, but this
    // should be fine here at startup
    let _res = config.set_time_offset_to_local();
    let _ = TermLogger::init(
        verbosity,
        config.build(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    );

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
        error!("A panic occurred at {filename}:{line}: {cause}");
    }));

    let output = matches.get_one::<String>("output").map(String::as_str);
    let filenames = to_vec(matches.get_many::<String>("filenames").unwrap());
    let symbol_server = matches
        .get_one::<String>("symbol_server")
        .map(String::as_str);
    let store = matches.get_one::<String>("store").map(String::as_str);
    let debug_id = matches.get_one::<String>("debug_id").map(String::as_str);
    let code_id = matches.get_one::<String>("code_id").map(String::as_str);
    let arch = matches.get_one::<String>("arch").unwrap().as_str();
    let check_cfi = matches.get_flag("check_cfi");
    let emit_inlines = matches.get_flag("inlines");
    let mapping_var = matches.get_many("mapping_var").map(to_vec);
    let mapping_src = matches.get_many("mapping_src").map(to_vec);
    let mapping_dest = matches.get_many("mapping_dest").map(to_vec);
    let mapping_file = matches
        .get_one::<String>("mapping_file")
        .map(String::as_str);
    get_extra_info(&matches);

    let num_jobs = if let Ok(num_jobs) = matches
        .get_one::<String>("num_jobs")
        .unwrap()
        .parse::<usize>()
    {
        num_jobs
    } else {
        num_cpus::get()
    };

    let action = if matches.get_flag("list_arch") {
        Action::ListArch
    } else {
        let output = match (output, store) {
            (Some(out), Some(store)) => dumper::Output::FileAndStore {
                file: out.into(),
                store_directory: store.into(),
            },
            (Some(out), None) => dumper::Output::File(out.into()),
            (None, Some(store)) => dumper::Output::Store(store.into()),
            (None, None) => dumper::Output::File(dumper::FileOutput::Stdout),
        };

        Action::Dump(dumper::Config {
            output,
            symbol_server,
            debug_id,
            code_id,
            arch,
            num_jobs,
            check_cfi,
            emit_inlines,
            mapping_var,
            mapping_src,
            mapping_dest,
            mapping_file,
        })
    };

    if let Err(e) = action.action(&filenames) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn to_vec(values: clap::parser::ValuesRef<'_, String>) -> Vec<&str> {
    values.map(String::as_str).collect()
}

fn get_extra_info(matches: &clap::ArgMatches) {
    static INFO_LINE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Z_]+ .*").unwrap());

    let mut extra_info: Vec<String> = matches.get_many::<String>("extra_info").map(|values| {
        values
            .map(|line| {
                if !INFO_LINE_RE.is_match(line) {
                    panic!(
                        "Extra INFO line format is invalid: {}. Valid format is <UPPERCASE_KEYWORD> <string>",
                        line
                    );
                }
                line.to_owned()
            })
            .collect()
    }).unwrap_or_default();

    if !*matches.get_one::<bool>("no-generator").unwrap() {
        extra_info.push(format!(
            "GENERATOR mozilla/dump_syms {}",
            env!("CARGO_PKG_VERSION")
        ));
    }

    EXTRA_INFO.set(extra_info).unwrap();
}

#[test]
fn verify_cli() {
    cli().debug_assert();
}
