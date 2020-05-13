// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use log::info;
use std::fs;
use std::path::PathBuf;

use crate::cache;
use crate::common::{self, Dumpable};
use crate::linux;
use crate::utils;
use crate::windows;

pub(crate) struct Dumper<'a> {
    pub output: &'a str,
    pub symbol_server: Option<&'a str>,
    pub store: Option<&'a str>,
    pub debug_id: Option<&'a str>,
    pub code_id: Option<&'a str>,
}

impl Dumper<'_> {
    fn store<D: Dumpable>(&self, dumpable: &D) -> common::Result<()> {
        let store = self.store.filter(|p| !p.is_empty()).map(|p| {
            PathBuf::from(p).join(cache::get_path_for_sym(
                &dumpable.get_name(),
                dumpable.get_debug_id(),
            ))
        });

        if let Some(store) = store.as_ref() {
            fs::create_dir_all(store.parent().unwrap())?;
            let store = store.to_str().unwrap();
            let output = utils::get_writer_for_sym(store);
            if let Err(e) = dumpable.dump(output) {
                return Err(e);
            }
            info!("Write symbols at {}", store);
        }

        if self.output != "-" || store.is_none() {
            let output = utils::get_writer_for_sym(self.output);
            dumpable.dump(output)?;
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

    fn pdb(&self, path: PathBuf, filename: String) -> common::Result<()> {
        let (buf, filename) = self.get_from_id(&path, filename, self.debug_id)?;
        let mut pdb = windows::pdb::PDBInfo::new(
            &buf,
            filename,
            "".to_string(),
            None,
            true, /* with_stack */
        )?;
        windows::utils::try_to_set_pe(&path, &mut pdb, &buf);
        self.store(&pdb)
    }

    fn elf(&self, path: PathBuf, filename: String) -> common::Result<()> {
        let (buf, filename) = self.get_from_id(&path, filename, self.debug_id)?;
        let elf = linux::elf::ElfInfo::new(&buf, filename, true /* with_stack */)?;
        self.store(&elf)
    }

    fn guess(&self, path: PathBuf, filename: String) -> common::Result<()> {
        let (buf, filename) = self.get_from_id(&path, filename, self.code_id)?;
        let symbol_server = cache::get_sym_servers(self.symbol_server);
        let res = windows::utils::get_pe_pdb_buf(path, &buf, symbol_server.as_ref());

        if let Some((pe, pdb_buf, pdb_name)) = res {
            let pdb = windows::pdb::PDBInfo::new(&pdb_buf, pdb_name, filename, Some(pe), true)?;
            self.store(&pdb)
        } else {
            Err("No pdb file found".into())
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
        let extension = path.extension().unwrap().to_str().unwrap().to_lowercase();

        match self {
            Self::Dump(dumper) => match extension.as_str() {
                "pdb" | "pd_" => dumper.pdb(path, filename),
                "dbg" | "so" => dumper.elf(path, filename),
                _ => dumper.guess(path, filename),
            },
        }
    }
}

#[cfg(test)]
mod tests {

    use std::fs::{copy, read};
    use tempfile::Builder;

    use super::*;

    #[test]
    fn test_missing_pe() {
        let tmp_dir = Builder::new().prefix("no_pe").tempdir().unwrap();
        let basic64 = PathBuf::from("./test_data/basic64.pdb");
        let tmp_file = tmp_dir.path().join("basic64.pdb");
        let tmp_out = tmp_dir.path().join("output.sym");

        copy(basic64, &tmp_file).unwrap();

        let action = Action::Dump(Dumper {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
        });

        action.action(tmp_file.to_str().unwrap()).unwrap();

        let data = read(tmp_out).unwrap();
        let data = String::from_utf8(data).unwrap();

        assert!(!data.contains("CODE_ID"));
        assert!(!data.contains("STACK CFI"));
    }

    #[test]
    fn test_missing_pe_but_in_dir() {
        let tmp_dir = Builder::new().prefix("no_pe").tempdir().unwrap();
        let basic64_pdb = PathBuf::from("./test_data/basic64.pdb");
        let tmp_pdb = tmp_dir.path().join("basic64.pdb");
        let basic64_dll = PathBuf::from("./test_data/basic64.dll");
        let tmp_dll = tmp_dir.path().join("basic64.dll");
        let tmp_out = tmp_dir.path().join("output.sym");

        copy(basic64_pdb, &tmp_pdb).unwrap();
        copy(basic64_dll, &tmp_dll).unwrap();

        let action = Action::Dump(Dumper {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
        });

        action.action(tmp_pdb.to_str().unwrap()).unwrap();

        let data = read(tmp_out).unwrap();
        let data = String::from_utf8(data).unwrap();

        assert!(data.contains("CODE_ID"));
        assert!(data.contains("STACK CFI"));
    }
}
