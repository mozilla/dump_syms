/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate clap;

use clap::{App, Arg};

fn main() {
    let matches = App::new("dump_syms")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about("Dump debug symbols to breakpad symbols")
        .arg(
            Arg::with_name("paths")
                .help("Files to dump")
                .required(true)
                .multiple(true)
                .takes_value(true),
        )
        .get_matches();

    let mut paths: Vec<_> = matches.values_of("paths").unwrap().collect();
    for _path in paths.drain(..) {}
}
