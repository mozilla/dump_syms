// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::PathBuf;

use crate::common::{self, FileType};
use crate::linux::elf::ElfInfo;
use crate::mac::macho::MachoInfo;
use crate::utils;
use crate::windows::pdb::PDBInfo;

use super::dumper::{self, Config};

pub(crate) enum Action<'a> {
    Dump(Config<'a>),
    ListArch,
}

impl Action<'_> {
    pub(super) fn action(&self, filenames: &[&str]) -> common::Result<()> {
        if filenames.len() == 1 {
            // no need to spawn a thread for one file
            self.single_file(filenames[0])
        } else {
            self.several_files(filenames)
        }
    }

    fn single_file(&self, filename: &str) -> common::Result<()> {
        match self {
            Self::Dump(config) => dumper::single_file(config, filename),
            Self::ListArch => {
                let path = PathBuf::from(filename);
                let filename = utils::get_filename(&path);

                let buf = utils::read_file(&path);
                MachoInfo::print_architectures(&buf, filename)
            }
        }
    }

    fn several_files(&self, filenames: &[&str]) -> common::Result<()> {
        match self {
            Self::Dump(config) => match config.file_type {
                FileType::Elf => dumper::several_files::<ElfInfo>(config, filenames),
                FileType::Macho => dumper::several_files::<MachoInfo>(config, filenames),
                FileType::Pdb => dumper::several_files::<PDBInfo>(config, filenames),
                _ => Ok(()),
            },
            Self::ListArch => {
                for f in filenames {
                    let path = PathBuf::from(f);
                    let filename = utils::get_filename(&path);

                    let buf = utils::read_file(&path);
                    MachoInfo::print_architectures(&buf, filename)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use regex::Regex;
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

        let action = Action::Dump(Config {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            file_type: FileType::Pdb,
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
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

        let action = Action::Dump(Config {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            file_type: FileType::Pdb,
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
        });

        action.action(&[tmp_pdb.to_str().unwrap()]).unwrap();

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

        let action = Action::Dump(Config {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            file_type: FileType::Elf,
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
        });

        action.action(&[full.to_str().unwrap()]).unwrap();

        let data = read(tmp_out).unwrap();
        let new: Vec<_> = data.split(|c| *c == b'\n').skip(1).collect();

        let basic = PathBuf::from("./test_data/linux/basic.full_no_multiple.sym");
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

        let action = Action::Dump(Config {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            file_type: FileType::Elf,
            num_jobs: 2,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
        });

        action
            .action(&[stripped.to_str().unwrap(), dbg.to_str().unwrap()])
            .unwrap();

        let re = Regex::new(r"<procedure linkage table[^>]*>").unwrap();
        let data = read(tmp_out).unwrap();
        let data = String::from_utf8(data).unwrap();
        let data = re.replace_all(&data, "<procedure linkage table>");
        let new: Vec<_> = data.split(|c: char| c == '\n').skip(1).collect();

        let basic = PathBuf::from("./test_data/linux/basic.full.sym");
        let data = read(basic).unwrap();
        let data = String::from_utf8(data).unwrap();
        let data = re.replace_all(&data, "<procedure linkage table>");
        let basic: Vec<_> = data.split(|c: char| c == '\n').skip(1).collect();

        assert_eq!(basic, new);
    }

    #[test]
    fn test_elf_dbg_stripped() {
        let tmp_dir = Builder::new().prefix("stripped_dbg").tempdir().unwrap();
        let stripped = PathBuf::from("./test_data/linux/basic.stripped");
        let dbg = PathBuf::from("./test_data/linux/basic.dbg");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Config {
            output: tmp_out.to_str().unwrap(),
            symbol_server: None,
            store: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            file_type: FileType::Elf,
            num_jobs: 2,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
        });

        action
            .action(&[dbg.to_str().unwrap(), stripped.to_str().unwrap()])
            .unwrap();

        let data = read(tmp_out).unwrap();
        let data = String::from_utf8(data).unwrap();
        let new: Vec<_> = data.split(|c: char| c == '\n').skip(1).collect();

        let basic = PathBuf::from("./test_data/linux/basic.full.sym");
        let data = read(basic).unwrap();
        let data = String::from_utf8(data).unwrap();
        let basic: Vec<_> = data.split(|c: char| c == '\n').skip(1).collect();

        assert_eq!(basic, new);
    }
}
