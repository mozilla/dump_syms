// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::PathBuf;

use dump_syms::common;
use dump_syms::mac::print_macho_architectures;
use dump_syms::utils;

use dump_syms::dumper::{self, Config};

#[allow(clippy::large_enum_variant)]
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
                print_macho_architectures(&buf, filename)
            }
        }
    }

    fn several_files(&self, filenames: &[&str]) -> common::Result<()> {
        match self {
            Self::Dump(config) => dumper::several_files(config, filenames),
            Self::ListArch => {
                for f in filenames {
                    let path = PathBuf::from(f);
                    let filename = utils::get_filename(&path);

                    let buf = utils::read_file(&path);
                    print_macho_architectures(&buf, filename)?;
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

    // Read and process the input so it can be compared with the output
    fn read_input(input_path: &str) -> Vec<String> {
        let basic = PathBuf::from(input_path);
        let data = read(basic).unwrap();
        let data = String::from_utf8(data).unwrap();
        data.split('\n').skip(1).map(String::from).collect()
    }

    fn read_output(output_path: &PathBuf) -> Vec<String> {
        let data = read(output_path).unwrap();
        let data = String::from_utf8(data).unwrap();
        data.split('\n').skip(1).map(String::from).collect()
    }

    #[test]
    fn test_missing_pe() {
        let tmp_dir = Builder::new().prefix("no_pe").tempdir().unwrap();
        let basic64 = PathBuf::from("./test_data/windows/basic64.pdb");
        let tmp_file = tmp_dir.path().join("basic64.pdb");
        let tmp_out = tmp_dir.path().join("output.sym");

        copy(basic64, &tmp_file).unwrap();

        let action = Action::Dump(Config {
            output: tmp_out.clone().into(),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            check_cfi: false,
            emit_inlines: false,
        });

        action.action(&[tmp_file.to_str().unwrap()]).unwrap();

        let data = read(tmp_out).unwrap();
        let data = String::from_utf8(data).unwrap();

        assert!(!data.contains("CODE_ID"));
        assert!(!data.contains("STACK CFI"));
    }

    #[test]
    fn test_missing_cfi() {
        let tmp_dir = Builder::new().prefix("missing_cfi").tempdir().unwrap();
        let basic64 = PathBuf::from("./test_data/windows/basic64.pdb");
        let tmp_file = tmp_dir.path().join("basic64.pdb");
        let tmp_out = tmp_dir.path().join("output.sym");

        copy(basic64, &tmp_file).unwrap();

        let action = Action::Dump(Config {
            output: tmp_out.into(),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            check_cfi: true,
            emit_inlines: false,
        });

        let res = action.action(&[tmp_file.to_str().unwrap()]);
        assert!(res.is_err());
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
        copy(basic64_dll, tmp_dll).unwrap();

        let action = Action::Dump(Config {
            output: tmp_out.clone().into(),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            check_cfi: false,
            emit_inlines: false,
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
            output: tmp_out.clone().into(),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            check_cfi: false,
            emit_inlines: false,
        });

        action.action(&[full.to_str().unwrap()]).unwrap();

        let new = read_output(&tmp_out);
        let basic = read_input("./test_data/linux/basic.full.sym");

        assert_eq!(basic, new);
    }

    #[test]
    fn test_elf_full_with_inlines() {
        let tmp_dir = Builder::new().prefix("full").tempdir().unwrap();
        let full = PathBuf::from("./test_data/linux/basic.full");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Config {
            output: tmp_out.clone().into(),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            check_cfi: false,
            emit_inlines: true,
        });

        action.action(&[full.to_str().unwrap()]).unwrap();

        let new = read_output(&tmp_out);
        let basic = read_input("./test_data/linux/basic.full.inlines.sym");

        assert_eq!(basic, new);
    }

    #[test]
    fn test_elf_stripped_dbg() {
        let tmp_dir = Builder::new().prefix("stripped_dbg").tempdir().unwrap();
        let stripped = PathBuf::from("./test_data/linux/basic.stripped");
        let dbg = PathBuf::from("./test_data/linux/basic.dbg");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Config {
            output: tmp_out.clone().into(),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 2,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            check_cfi: false,
            emit_inlines: true,
        });

        action
            .action(&[stripped.to_str().unwrap(), dbg.to_str().unwrap()])
            .unwrap();

        let re = Regex::new(r"<\.plt[\.a-zA-Z]* ELF section in [^>]*>").unwrap();
        let new = read_output(&tmp_out);
        let new: Vec<_> = new
            .into_iter()
            .map(|s| re.replace(&s, "<.plt ELF section in>").to_string())
            .collect();
        let basic = read_input("./test_data/linux/basic.full.inlines.sym");
        let basic: Vec<_> = basic
            .into_iter()
            .map(|s| re.replace(&s, "<.plt ELF section in>").to_string())
            .collect();

        assert_eq!(basic, new);
    }

    #[test]
    fn test_elf_dbg_stripped() {
        let tmp_dir = Builder::new().prefix("stripped_dbg").tempdir().unwrap();
        let stripped = PathBuf::from("./test_data/linux/basic.stripped");
        let dbg = PathBuf::from("./test_data/linux/basic.dbg");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Config {
            output: tmp_out.clone().into(),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 2,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            check_cfi: false,
            emit_inlines: false,
        });

        action
            .action(&[dbg.to_str().unwrap(), stripped.to_str().unwrap()])
            .unwrap();

        let new = read_output(&tmp_out);
        let basic = read_input("./test_data/linux/basic.dbg.sym");

        assert_eq!(basic, new);
    }

    #[test]
    fn test_elf_dwz_with_inlines() {
        let tmp_dir = Builder::new().prefix("dwz").tempdir().unwrap();
        let full = PathBuf::from("./test_data/linux/basic.dwz");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Config {
            output: tmp_out.clone().into(),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            check_cfi: false,
            emit_inlines: true,
        });

        action.action(&[full.to_str().unwrap()]).unwrap();

        let new = read_output(&tmp_out);
        let basic = read_input("./test_data/linux/basic.dwz.inlines.sym");

        assert_eq!(basic, new);
    }

    #[test]
    fn test_elf_minidebuginfo() {
        let tmp_dir = Builder::new().prefix("minidebuginfo").tempdir().unwrap();
        let minidebuginfo = PathBuf::from("./test_data/linux/basic.minidebuginfo");
        let tmp_out = tmp_dir.path().join("output.sym");

        let action = Action::Dump(Config {
            output: tmp_out.clone().into(),
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 1,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
            check_cfi: false,
            emit_inlines: true,
        });

        action.action(&[minidebuginfo.to_str().unwrap()]).unwrap();

        let new = read_output(&tmp_out);
        let basic = read_input("./test_data/linux/basic.minidebuginfo.sym");

        assert_eq!(basic, new);
    }
}
