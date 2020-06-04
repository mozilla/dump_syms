// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use log::info;
use std::fs;
use std::path::PathBuf;
use std::thread;

use crate::cache;
use crate::common::{self, Dumpable, FileType};
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

    fn has_id(&self) -> bool {
        self.debug_id.is_some() || self.code_id.is_some()
    }

    fn get_from_id(&self, path: &PathBuf, filename: String) -> common::Result<(Vec<u8>, String)> {
        for id in &[self.debug_id, self.code_id] {
            if let Some(id) = id {
                let symbol_server = cache::get_sym_servers(self.symbol_server);
                let (buf, filename) = cache::search_file(filename, id, symbol_server.as_ref());
                return if let Some(buf) = buf {
                    Ok((buf, filename))
                } else {
                    Err(format!("Impossible to get file {} with id {}", filename, id).into())
                };
            }
        }

        Ok((utils::read_file(&path), filename))
    }

    fn pdb(&self, buf: &[u8], path: PathBuf, filename: String) -> common::Result<()> {
        let mut pdb = windows::pdb::PDBInfo::new(&buf, filename, "".to_string(), None)?;
        windows::utils::try_to_set_pe(&path, &mut pdb, &buf);
        self.store(&pdb)
    }

    fn pdb_pe(
        &self,
        pdb_buf: &[u8],
        pdb_filename: String,
        pe_buf: &[u8],
        pe_path: PathBuf,
        pe_filename: String,
    ) -> common::Result<()> {
        let pe = windows::utils::get_pe(pe_path, pe_buf);
        let pdb = windows::pdb::PDBInfo::new(&pdb_buf, pdb_filename, pe_filename, Some(pe))?;
        self.store(&pdb)
    }

    fn elf(&self, buf: &[u8], filename: String) -> common::Result<()> {
        let elf = linux::elf::ElfInfo::new(&buf, filename)?;
        self.store(&elf)
    }

    fn two_elfs(
        &self,
        buf_1: Vec<u8>,
        filename_1: String,
        buf_2: Vec<u8>,
        filename_2: String,
    ) -> common::Result<()> {
        // Normally we should have a debug file and a stripped executable (or lib)
        // So the thread getting data for the debug file should be a way longer that the oter
        let t_1 = thread::Builder::new()
            .name("Dump_syms 1".to_string())
            .spawn(move || linux::elf::ElfInfo::new(&buf_1, filename_1))
            .unwrap();
        let t_2 = thread::Builder::new()
            .name("Dump_syms 2".to_string())
            .spawn(move || linux::elf::ElfInfo::new(&buf_2, filename_2))
            .unwrap();

        let elf_1 = t_1
            .join()
            .expect("Couldn't join on the associated thread")?;
        let elf_2 = t_2
            .join()
            .expect("Couldn't join on the associated thread")?;

        let elf = linux::elf::ElfInfo::merge(elf_1, elf_2)?;
        self.store(&elf)
    }

    fn pe(&self, buf: &[u8], path: PathBuf, filename: String) -> common::Result<()> {
        let symbol_server = cache::get_sym_servers(self.symbol_server);
        let res = windows::utils::get_pe_pdb_buf(path, &buf, symbol_server.as_ref());

        if let Some((pe, pdb_buf, pdb_name)) = res {
            let pdb = windows::pdb::PDBInfo::new(&pdb_buf, pdb_name, filename, Some(pe))?;
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
    pub(super) fn action(&self, filenames: &[&str]) -> common::Result<()> {
        if filenames.len() == 1 {
            self.one_file(filenames[0])
        } else {
            self.two_files(filenames)
        }
    }

    fn one_file(&self, filename: &str) -> common::Result<()> {
        let path = PathBuf::from(filename);
        let filename = utils::get_filename(&path);

        match self {
            Self::Dump(dumper) => {
                let (buf, filename) = dumper.get_from_id(&path, filename)?;
                match FileType::from_buf(&buf) {
                    FileType::Elf => dumper.elf(&buf, filename),
                    FileType::Pdb => dumper.pdb(&buf, path, filename),
                    FileType::Pe => dumper.pe(&buf, path, filename),
                    FileType::Unknown => Err("Unknown file format".into()),
                }
            }
        }
    }

    fn two_files(&self, filenames: &[&str]) -> common::Result<()> {
        let path_1 = PathBuf::from(filenames[0]);
        let filename_1 = utils::get_filename(&path_1);

        let path_2 = PathBuf::from(filenames[1]);
        let filename_2 = utils::get_filename(&path_2);

        match self {
            Self::Dump(dumper) => {
                if dumper.has_id() {
                    return Err("One filename must be given with --code-id or --debug-id".into());
                }
                let (buf_1, filename_1) = dumper.get_from_id(&path_1, filename_1)?;
                let (buf_2, filename_2) = dumper.get_from_id(&path_2, filename_2)?;

                match (FileType::from_buf(&buf_1), FileType::from_buf(&buf_2)) {
                    (FileType::Elf, FileType::Elf) => {
                        dumper.two_elfs(buf_1, filename_1, buf_2, filename_2)
                    }
                    (FileType::Pdb, FileType::Pe) => {
                        dumper.pdb_pe(&buf_1, filename_1, &buf_2, path_2, filename_2)
                    }
                    (FileType::Pe, FileType::Pdb) => {
                        dumper.pdb_pe(&buf_2, filename_2, &buf_1, path_1, filename_1)
                    }
                    _ => Err("Invalid files: must be two elf or a pdb and a pe".into()),
                }
            }
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
        let basic64 = PathBuf::from("./test_data/windows/basic64.pdb");
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

        action.action(&[tmp_file.to_str().unwrap()]).unwrap();

        let data = read(tmp_out).unwrap();
        let data = String::from_utf8(data).unwrap();

        assert!(!data.contains("CODE_ID"));
        assert!(!data.contains("STACK CFI"));
    }

    #[test]
    fn test_missing_pe_but_in_dir() {
        let tmp_dir = Builder::new().prefix("no_pe").tempdir().unwrap();
        let basic64_pdb = PathBuf::from("./test_data/windows/basic64.pdb");
        let tmp_pdb = tmp_dir.path().join("basic64.pdb");
        let basic64_dll = PathBuf::from("./test_data/windows/basic64.dll");
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

        action.action(&[tmp_pdb.to_str().unwrap()]).unwrap();

        let data = read(tmp_out).unwrap();
        let data = String::from_utf8(data).unwrap();

        assert!(data.contains("CODE_ID"));
        assert!(data.contains("STACK CFI"));
    }

    #[test]
    fn test_pe_and_pdb() {
        let tmp_dir = Builder::new().prefix("pe_pdb").tempdir().unwrap();
        let basic64_pdb = PathBuf::from("./test_data/windows/basic64.pdb");
        let basic64_dll = PathBuf::from("./test_data/windows/basic64.dll");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Dumper {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
        });

        action
            .action(&[basic64_dll.to_str().unwrap(), basic64_pdb.to_str().unwrap()])
            .unwrap();

        let data = read(tmp_out).unwrap();
        let data = String::from_utf8(data).unwrap();

        assert!(data.contains("CODE_ID"));
        assert!(data.contains("STACK CFI"));
    }

    #[test]
    fn test_pdb_and_pe() {
        let tmp_dir = Builder::new().prefix("pdb_pe").tempdir().unwrap();
        let basic64_pdb = PathBuf::from("./test_data/windows/basic64.pdb");
        let basic64_dll = PathBuf::from("./test_data/windows/basic64.dll");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Dumper {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
        });

        action
            .action(&[basic64_pdb.to_str().unwrap(), basic64_dll.to_str().unwrap()])
            .unwrap();

        let data = read(tmp_out).unwrap();
        let data = String::from_utf8(data).unwrap();

        assert!(data.contains("CODE_ID"));
        assert!(data.contains("STACK CFI"));
    }

    #[test]
    fn test_elf_full() {
        let tmp_dir = Builder::new().prefix("full").tempdir().unwrap();
        let full = PathBuf::from("./test_data/linux/basic.full");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Dumper {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
        });

        action.action(&[full.to_str().unwrap()]).unwrap();

        let data = read(tmp_out).unwrap();
        let new: Vec<_> = data.split(|c| *c == b'\n').skip(1).collect();

        let basic = PathBuf::from("./test_data/linux/basic.full.sym");
        let data = read(basic).unwrap();
        let basic: Vec<_> = data.split(|c| *c == b'\n').skip(1).collect();

        assert_eq!(basic, new);
    }

    #[test]
    fn test_elf_stripped_dbg() {
        let tmp_dir = Builder::new().prefix("stripped_dbg").tempdir().unwrap();
        let stripped = PathBuf::from("./test_data/linux/basic.stripped");
        let dbg = PathBuf::from("./test_data/linux/basic.dbg");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Dumper {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
        });

        action
            .action(&[stripped.to_str().unwrap(), dbg.to_str().unwrap()])
            .unwrap();

        let data = read(tmp_out).unwrap();
        let new: Vec<_> = data.split(|c| *c == b'\n').skip(1).collect();

        let basic = PathBuf::from("./test_data/linux/basic.full.sym");
        let data = read(basic).unwrap();
        let basic: Vec<_> = data.split(|c| *c == b'\n').skip(1).collect();

        assert_eq!(basic, new);
    }

    #[test]
    fn test_elf_dbg_stripped() {
        let tmp_dir = Builder::new().prefix("stripped_dbg").tempdir().unwrap();
        let stripped = PathBuf::from("./test_data/linux/basic.stripped");
        let dbg = PathBuf::from("./test_data/linux/basic.dbg");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Dumper {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
        });

        action
            .action(&[dbg.to_str().unwrap(), stripped.to_str().unwrap()])
            .unwrap();

        let data = read(tmp_out).unwrap();
        let new: Vec<_> = data.split(|c| *c == b'\n').skip(1).collect();

        let basic = PathBuf::from("./test_data/linux/basic.full.sym");
        let data = read(basic).unwrap();
        let basic: Vec<_> = data.split(|c| *c == b'\n').skip(1).collect();

        assert_eq!(basic, new);
    }
}
