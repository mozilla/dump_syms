// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::PathBuf;

use crate::common;
use crate::utils;
use crate::windows;

pub(crate) struct Dumper<'a> {
    pub output: &'a str,
    pub symbol_server: Option<&'a str>,
}

pub(crate) enum Action<'a> {
    Dump(Dumper<'a>),
}

impl Action<'_> {
    pub(super) fn action(&self, filename: &str) -> common::Result<()> {
        let path = PathBuf::from(filename);
        let buf = utils::read_file(&path);
        let filename = path.file_name().unwrap().to_str().unwrap().to_string();

        match self {
            Self::Dump(dumper) => match path.extension().unwrap().to_str().unwrap() {
                "dll" | "exe" => {
                    let res = windows::utils::get_pe_pdb_buf(path, &buf, dumper.symbol_server);
                    if let Some((pe, pdb_buf, pdb_name)) = res {
                        match windows::pdb::PDBInfo::new(
                            &pdb_buf,
                            pdb_name,
                            filename,
                            Some(pe),
                            true,
                        ) {
                            Ok(pdb) => {
                                let output = utils::get_writer_for_sym(dumper.output);
                                pdb.dump(output)
                            }
                            Err(e) => Err(e.into()),
                        }
                    } else {
                        Err("No pdb file found".into())
                    }
                }
                "pdb" | "pd_" => {
                    match windows::pdb::PDBInfo::new(&buf, filename, "".to_string(), None, true) {
                        Ok(pdb) => {
                            let output = utils::get_writer_for_sym(&dumper.output);
                            pdb.dump(output)
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                _ => Err(format!("Invalid file {}", filename).into()),
            },
        }
    }
}
