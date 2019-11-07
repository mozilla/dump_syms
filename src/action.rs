// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use log::info;
use std::fs;
use std::path::PathBuf;

use crate::cache;
use crate::common;
use crate::utils;
use crate::windows::{self, pdb::PDBInfo};

pub(crate) struct Dumper<'a> {
    pub output: &'a str,
    pub symbol_server: Option<&'a str>,
    pub store: Option<&'a str>,
    pub debug_id: Option<&'a str>,
    pub code_id: Option<&'a str>,
}

impl Dumper<'_> {
    fn store_pdb(&self, pdb: &PDBInfo) -> common::Result<()> {
        let store = self.store.filter(|p| !p.is_empty()).map(|p| {
            PathBuf::from(p).join(cache::get_path_for_sym(&pdb.pdb_name(), pdb.debug_id()))
        });

        if let Some(store) = store.as_ref() {
            fs::create_dir_all(store.parent().unwrap())?;
            let store = store.to_str().unwrap();
            let output = utils::get_writer_for_sym(store);
            if let Err(e) = pdb.dump(output) {
                return Err(e);
            }
            info!("Write symbols at {}", store);
        }

        if self.output != "-" || store.is_none() {
            let output = utils::get_writer_for_sym(self.output);
            pdb.dump(output)?;
            info!("Write symbols at {}", self.output);
        }
        Ok(())
    }

    fn get_from_id(
        &self,
        path: &PathBuf,
        filename: String,
        id: Option<&str>,
    ) -> common::Result<(Vec<u8>, String)> {
        if let Some(id) = id {
            let symbol_server = cache::get_sym_servers(self.symbol_server);
            let (buf, filename) = cache::search_file(filename, id, symbol_server.as_ref());
            if let Some(buf) = buf {
                Ok((buf, filename))
            } else {
                Err(format!("Impossible to get file {} with id {}", filename, id).into())
            }
        } else {
            Ok((utils::read_file(&path), filename))
        }
    }
}

pub(crate) enum Action<'a> {
    Dump(Dumper<'a>),
}

impl Action<'_> {
    pub(super) fn action(&self, filename: &str) -> common::Result<()> {
        let path = PathBuf::from(filename);
        let filename = path.file_name().unwrap().to_str().unwrap().to_string();

        match self {
            Self::Dump(dumper) => match path.extension().unwrap().to_str().unwrap() {
                "dll" | "dl_" | "exe" | "ex_" => {
                    let (buf, filename) = dumper.get_from_id(&path, filename, dumper.code_id)?;
                    let symbol_server = cache::get_sym_servers(dumper.symbol_server);
                    let res = windows::utils::get_pe_pdb_buf(path, &buf, symbol_server.as_ref());
                    if let Some((pe, pdb_buf, pdb_name)) = res {
                        match windows::pdb::PDBInfo::new(
                            &pdb_buf,
                            pdb_name,
                            filename,
                            Some(pe),
                            true,
                        ) {
                            Ok(pdb) => dumper.store_pdb(&pdb),
                            Err(e) => Err(e.into()),
                        }
                    } else {
                        Err("No pdb file found".into())
                    }
                }
                "pdb" | "pd_" => {
                    let (buf, filename) = dumper.get_from_id(&path, filename, dumper.debug_id)?;
                    match windows::pdb::PDBInfo::new(&buf, filename, "".to_string(), None, true) {
                        Ok(pdb) => dumper.store_pdb(&pdb),
                        Err(e) => Err(e.into()),
                    }
                }
                _ => Err(format!("Invalid file {}", filename).into()),
            },
        }
    }
}
