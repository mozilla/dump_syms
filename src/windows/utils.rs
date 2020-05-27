// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::PathBuf;
use symbolic_debuginfo::pe::PeObject;
use uuid::Uuid;

use crate::cache::{self, SymbolServer};
use crate::utils;
use crate::windows::pdb::PDBInfo;

fn try_to_find_pdb(path: PathBuf, pdb_filename: &str) -> Option<Vec<u8>> {
    // Just check that the file is in the same directory as the PE one
    let pdb = path.with_file_name(pdb_filename);
    let mut pdb_cab = pdb.clone();
    pdb_cab.set_extension("pd_");

    for pdb in vec![pdb, pdb_cab].drain(..) {
        if pdb.is_file() {
            return Some(utils::read_file(pdb));
        } else {
            // We try in CWD
            let mut pdb =
                std::env::current_dir().expect("Unable to get the current working directory");
            pdb.set_file_name(pdb_filename);
            if pdb.is_file() {
                return Some(utils::read_file(pdb));
            }
        }
    }
    None
}

fn os_specific_try_to_find_pdb(path: PathBuf, pdb_filename: String) -> (Option<Vec<u8>>, String) {
    // We may have gotten either an OS native path, or a Windows path.
    // On Windows, they're both the same. On Unix, they are different, and in that case,
    // we change backslashes to forward slashes for `file_name()` to do its job.
    // But before that, just try wether the file exists.
    #[cfg(unix)]
    let pdb_filename = pdb_filename.replace("\\", "/");
    let pdb_path = PathBuf::from(&pdb_filename);
    let pdb_name = pdb_path.file_name().unwrap().to_str().unwrap().to_string();

    if pdb_path.is_file() {
        (Some(utils::read_file(pdb_path)), pdb_name)
    } else {
        (try_to_find_pdb(path, &pdb_name), pdb_name)
    }
}

pub fn get_pe_pdb_buf<'a>(
    path: PathBuf,
    buf: &'a [u8],
    symbol_server: Option<&Vec<SymbolServer>>,
) -> Option<(PeObject<'a>, Vec<u8>, String)> {
    let pe = PeObject::parse(&buf)
        .unwrap_or_else(|_| panic!("Unable to parse the PE file {}", path.to_str().unwrap()));
    if let Some(pdb_filename) = pe.debug_file_name() {
        let pdb_filename = pdb_filename.into_owned();
        let (pdb, pdb_name) = os_specific_try_to_find_pdb(path, pdb_filename);

        if let Some(pdb_buf) = pdb {
            Some((pe, pdb_buf, pdb_name))
        } else {
            // Not here so try symbol server (or cache)
            let debug_id = get_pe_debug_id(Some(&pe)).unwrap();
            let (pdb, pdb_name) = cache::search_file(pdb_name, &debug_id, symbol_server);
            if let Some(pdb_buf) = pdb {
                Some((pe, pdb_buf, pdb_name))
            } else {
                None
            }
        }
    } else {
        None
    }
}

pub fn get_pe(path: PathBuf, buf: &[u8]) -> PeObject {
    PeObject::parse(&buf)
        .unwrap_or_else(|_| panic!("Unable to parse the PE file {}", path.to_str().unwrap()))
}

pub fn get_pe_debug_id(pe: Option<&PeObject>) -> Option<String> {
    if let Some(pe) = pe {
        let mut buf = Uuid::encode_buffer();
        let debug_id = pe.debug_id();
        let uuid = debug_id.uuid().to_simple().encode_upper(&mut buf);
        let appendix = debug_id.appendix();
        Some(format!("{}{:x}", uuid, appendix))
    } else {
        None
    }
}

fn fix_extension(ext: &str) -> &str {
    match ext {
        "dl_" => "dll",
        "ex_" => "exe",
        _ => ext,
    }
}

pub(crate) fn try_to_set_pe(path: &PathBuf, pdb_info: &mut PDBInfo, pdb_buf: &[u8]) {
    // Just check that the file is in the same directory as the PDB one
    let mut path = path.clone();
    for ext in vec!["dll", "dl_", "exe", "ex_"].drain(..) {
        path.set_extension(ext);
        if path.is_file() {
            let buf = utils::read_file(&path);
            if let Ok(pe) = PeObject::parse(&buf) {
                if ext.ends_with('_') {
                    path.set_extension(fix_extension(ext));
                }
                let filename = utils::get_filename(&path);
                if pdb_info.set_pe(filename, pe, pdb_buf) {
                    break;
                }
            }
        }
    }
}
