// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use cab::Cabinet;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

pub fn read_file<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let mut file = File::open(&path).unwrap_or_else(|_| {
        panic!(
            "Unable to open the file {}",
            path.as_ref().to_str().unwrap()
        )
    });
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap_or_else(|_| {
        panic!(
            "Unable to read the file {}",
            path.as_ref().to_str().unwrap()
        )
    });

    read_cabinet(buf, path.as_ref().to_path_buf()).unwrap_or_else(|| {
        panic!(
            "Unable to read the cabinet file {}",
            path.as_ref().to_str().unwrap()
        )
    })
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

    let file = match get_cabinet_files(&cab, path) {
        Some(file) => file,
        _ => return None,
    };

    let mut buf = Vec::new();
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

fn get_cabinet_files<'a>(cab: &'a Cabinet<Cursor<&Vec<u8>>>, path: PathBuf) -> Option<String> {
    // Try to find in the cabinet the same path with pdb extension
    let path = path.with_extension("pdb");
    let file_name = path.file_name().unwrap();
    for folder in cab.folder_entries() {
        for file in folder.file_entries() {
            let path = PathBuf::from(file.name());
            if path.file_name().unwrap() == file_name {
                return Some(file.name().to_string());
            }
        }
    }
    None
}
