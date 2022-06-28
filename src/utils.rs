// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use cab::Cabinet;
use std::fs::{self, File, Metadata};
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

use crate::common;

pub fn read_file<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let metadata = fs::metadata(&path).unwrap_or_else(|_| {
        panic!(
            "Unable to open the file {}",
            path.as_ref().to_str().unwrap()
        )
    });

    let (metadata, path) = get_mac_bundle(&metadata, &path)
        .unwrap_or_else(|| (metadata, PathBuf::from(path.as_ref())));

    let file_size = metadata.len() as usize;
    let mut file = File::open(&path)
        .unwrap_or_else(|_| panic!("Unable to open the file {}", path.to_str().unwrap()));

    let mut buf = Vec::with_capacity(file_size + 1);
    file.read_to_end(&mut buf)
        .unwrap_or_else(|_| panic!("Unable to read the file {}", path.to_str().unwrap()));

    read_cabinet(buf, path.clone())
        .unwrap_or_else(|| panic!("Unable to read the cabinet file {}", path.to_str().unwrap()))
}

pub(crate) fn get_base(file_name: &str) -> PathBuf {
    // The file is stored at cache/xul.pdb/DEBUG_ID/xul.pd_
    // the xul.pdb represents the base
    let mut path = PathBuf::from(file_name);
    if let Some(e) = path.extension() {
        let e = e.to_str().unwrap().to_lowercase();
        match e.as_str() {
            "pd_" => {
                path.set_extension("pdb");
            }
            "ex_" => {
                path.set_extension("exe");
            }
            "dl_" => {
                path.set_extension("dll");
            }
            _ => {}
        }

        path
    } else {
        path
    }
}

#[inline]
pub fn get_path_for_sym(file_name: &str, id: &str) -> PathBuf {
    let mut pb = get_base(file_name);

    pb.push(id);

    let sym_filename = match file_name.rsplit_once('.') {
        Some((basename, ext)) if ext.to_lowercase() == "pdb" => format!("{basename}.sym"),
        _ => format!("{file_name}.sym"),
    };
    pb.push(sym_filename);

    pb
}

pub fn get_mac_bundle<P: AsRef<Path>>(metadata: &Metadata, path: P) -> Option<(Metadata, PathBuf)> {
    if metadata.is_dir() {
        // We may have a dSYM bundle
        let dwarf_path = path.as_ref().to_path_buf().join("Contents/Resources/DWARF");
        if dwarf_path.is_dir() {
            let entries: Vec<_> = fs::read_dir(&dwarf_path).unwrap().collect();
            match entries.len() {
                0 => panic!(
                    "Unable to find DWARF-bearing file in bundle: {}",
                    dwarf_path.to_str().unwrap()
                ),
                1 => {
                    let entry = entries[0].as_ref().unwrap();
                    Some((
                        entry.metadata().unwrap_or_else(|_| {
                            panic!("Unable to open the file {}", entry.path().to_str().unwrap())
                        }),
                        entry.path(),
                    ))
                }
                _ => panic!(
                    "Too many DWARF files in bundle: {}",
                    dwarf_path.to_str().unwrap()
                ),
            }
        } else {
            panic!(
                "File {} is a directory and not a mac bundle",
                path.as_ref().to_str().unwrap()
            )
        }
    } else {
        None
    }
}

pub fn read_cabinet(buf: Vec<u8>, path: PathBuf) -> Option<Vec<u8>> {
    // try to find a pdb in cabinet archive
    // if not a cabinet just return the buffer
    // else return None on error

    let cursor = Cursor::new(&buf);
    let mut cab = match Cabinet::new(cursor) {
        Ok(cab) => cab,
        _ => return Some(buf),
    };

    let (file, size) = match get_cabinet_files(&cab, path) {
        Some(file) => file,
        _ => return None,
    };

    let mut buf = Vec::with_capacity(size + 1);
    let mut reader = match cab.read_file(&file) {
        Ok(reader) => reader,
        _ => return None,
    };

    if reader.read_to_end(&mut buf).is_err() {
        None
    } else {
        Some(buf)
    }
}

fn get_corrected_path(path: PathBuf) -> PathBuf {
    let e = path.extension().unwrap().to_str().unwrap();
    if e.starts_with("pd") {
        path.with_extension("pdb")
    } else if e.starts_with("dl") {
        path.with_extension("dll")
    } else if e.starts_with("ex") {
        path.with_extension("exe")
    } else if e.starts_with("db") {
        path.with_extension("dbg")
    } else {
        path
    }
}

fn get_cabinet_files(cab: &Cabinet<Cursor<&Vec<u8>>>, path: PathBuf) -> Option<(String, usize)> {
    // Try to find in the cabinet the same path with pdb extension
    let path = get_corrected_path(path);
    let file_name = path.file_name().unwrap();
    for folder in cab.folder_entries() {
        for file in folder.file_entries() {
            let file_size = file.uncompressed_size() as usize;
            let path = PathBuf::from(file.name());
            if path.file_name().unwrap() == file_name {
                return Some((file.name().to_string(), file_size));
            }
        }
    }
    None
}

pub fn normalize_path<P: AsRef<Path>>(path: P) -> PathBuf {
    // Copied from Cargo sources
    // https://github.com/rust-lang/cargo/blob/f534844c25cacc5e004404cea835ac85e35ca3fd/src/cargo/util/paths.rs#L60
    let mut components = path.as_ref().components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

pub fn get_filename(path: &Path) -> String {
    path.file_name().unwrap().to_str().unwrap().to_string()
}

pub fn read<P: AsRef<Path>>(path: P) -> common::Result<Vec<u8>> {
    let file_size = fs::metadata(&path)?.len() as usize;
    let mut file = File::open(&path).unwrap_or_else(|_| {
        panic!(
            "Unable to open the file {}",
            path.as_ref().to_str().unwrap()
        )
    });

    let mut buf = Vec::with_capacity(file_size + 1);
    file.read_to_end(&mut buf).unwrap_or_else(|_| {
        panic!(
            "Unable to read the file {}",
            path.as_ref().to_str().unwrap()
        )
    });

    Ok(buf)
}
