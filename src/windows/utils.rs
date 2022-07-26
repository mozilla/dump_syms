// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::Path;
use symbolic::{common::DebugId, debuginfo::pe::PeObject};

#[cfg(feature = "http")]
use crate::cache::{self, SymbolServer};
use crate::utils;

#[cfg(feature = "http")]
fn try_to_find_pdb(path: &Path, pdb_filename: &str) -> Option<Vec<u8>> {
    // Just check that the file is in the same directory as the PE one
    let pdb = path.with_file_name(pdb_filename);
    let pdb_cab = pdb.with_extension("pd_");

    for pdb in vec![pdb, pdb_cab].into_iter() {
        if pdb.is_file() {
            return Some(utils::read_file(pdb));
        }
    }

    // We try in CWD
    let mut pdb = std::env::current_dir().expect("Unable to get the current working directory");
    pdb.set_file_name(pdb_filename);
    if pdb.is_file() {
        Some(utils::read_file(pdb))
    } else {
        None
    }
}

#[cfg(feature = "http")]
fn os_specific_try_to_find_pdb(path: &Path, pdb_filename: &str) -> (Option<Vec<u8>>, String) {
    // We may have gotten either an OS native path, or a Windows path.
    // On Windows, they're both the same. On Unix, they are different, and in that case,
    // we change backslashes to forward slashes for `file_name()` to do its job.
    // But before that, just try wether the file exists.
    #[cfg(unix)]
    let pdb_filename = pdb_filename.replace('\\', "/");
    let pdb_path = Path::new(&pdb_filename);
    if let Some(file_name) = pdb_path.file_name() {
        let pdb_name = file_name.to_str().unwrap().to_string();
        if pdb_path.is_file() {
            (Some(utils::read_file(pdb_path)), pdb_name)
        } else {
            (try_to_find_pdb(path, &pdb_name), pdb_name)
        }
    } else {
        (None, "".to_string())
    }
}

#[cfg(feature = "http")]
pub fn get_pe_pdb_buf<'a>(
    path: &Path,
    buf: &'a [u8],
    symbol_server: Option<&Vec<SymbolServer>>,
) -> Option<(PeObject<'a>, Vec<u8>, String)> {
    let pe = PeObject::parse(buf)
        .unwrap_or_else(|_| panic!("Unable to parse the PE file {}", path.to_str().unwrap()));
    if let Some(pdb_filename) = pe.debug_file_name() {
        let pdb_filename = pdb_filename.into_owned();
        let (pdb, pdb_name) = os_specific_try_to_find_pdb(path, &pdb_filename);
        if pdb_name.is_empty() {
            log::warn!("Invalid pdb filename in PE file: \"{}\"", pdb_filename);
            None
        } else if let Some(pdb_buf) = pdb {
            Some((pe, pdb_buf, pdb_name))
        } else {
            // Not here so try symbol server (or cache)
            let debug_id = pe.debug_id().breakpad().to_string();
            let (pdb, pdb_name) = cache::search_file(pdb_name, &debug_id, symbol_server);
            pdb.map(|pdb_buf| (pe, pdb_buf, pdb_name))
        }
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

/// Tries to find the PE object for a PDB file, by looking for dll/exe files
/// in the same directory with a matching debug ID.
pub(crate) fn find_pe_for_pdb(path: &Path, pdb_debug_id: &DebugId) -> Option<(String, Vec<u8>)> {
    let mut path = path.to_path_buf();
    for ext in vec!["dll", "dl_", "exe", "ex_"].drain(..) {
        path.set_extension(ext);
        if path.is_file() {
            let buf = utils::read_file(&path);
            if let Ok(pe) = PeObject::parse(&buf) {
                if ext.ends_with('_') {
                    path.set_extension(fix_extension(ext));
                }
                let filename = utils::get_filename(&path);
                if &pe.debug_id() == pdb_debug_id {
                    return Some((filename, buf));
                }
            }
        }
    }
    None
}
