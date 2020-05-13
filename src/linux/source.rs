// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::utils;
use hashbrown::{hash_map, HashMap};
use std::fs;
use std::path::PathBuf;
use symbolic_debuginfo::FileInfo;

type SliceRef = (*const u8, usize);

#[derive(Debug, Default)]
pub(super) struct SourceFiles {
    ref_to_id: HashMap<PathBuf, u32>,
    fake_id_to_ref: Vec<(Option<u32>, String)>,
    id_to_ref: Vec<String>,
    cache: HashMap<(SliceRef, SliceRef, SliceRef), u32>,
}

impl SourceFiles {
    #[inline(always)]
    fn cast_ptr(name: &[u8]) -> SliceRef {
        (name.as_ptr(), name.len())
    }

    #[inline(always)]
    fn path_to_string(name: &[u8]) -> String {
        // Strings in DWARF are encoded either in latin-1 or in utf-8 (likely)
        if let Ok(s) = String::from_utf8(name.to_vec()) {
            s
        } else {
            name.iter().map(|&c| c as char).collect()
        }
    }

    fn get_path(compilation_dir: &[u8], file: &FileInfo) -> PathBuf {
        let dir = Self::path_to_string(file.dir);
        let name = Self::path_to_string(file.name);

        let path = if file.dir.get(0).map_or(false, |&x| x == b'/') {
            // file.dir is absolute
            PathBuf::from(dir).join(name)
        } else {
            let comp_dir = Self::path_to_string(compilation_dir);
            PathBuf::from(comp_dir).join(dir).join(name)
        };

        // Try to get the real path and in case we're on the machine where the files have compiled
        // else fallback on the basic way to normalize a path
        if let Ok(path) = fs::canonicalize(&path) {
            path
        } else {
            utils::normalize_path(&path)
        }
    }

    /// For a given compilation_dir, file return the index in self.ref_to_id
    pub(super) fn get_id(&mut self, compilation_dir: &[u8], file: &FileInfo) -> u32 {
        // A lot of paths are a slice on the same string in the debug file
        // so just use a cache based on the string pointers.
        let cache_key = (
            Self::cast_ptr(compilation_dir),
            Self::cast_ptr(file.dir),
            Self::cast_ptr(file.name),
        );

        match self.cache.entry(cache_key) {
            hash_map::Entry::Occupied(e) => *e.get(),
            hash_map::Entry::Vacant(e) => {
                let path = Self::get_path(compilation_dir, file);
                let id = match self.ref_to_id.entry(path) {
                    hash_map::Entry::Occupied(e) => *e.get(),
                    hash_map::Entry::Vacant(e) => {
                        let id = self.fake_id_to_ref.len() as u32;
                        let path = e.key().to_str().unwrap().to_string();
                        e.insert(id);
                        self.fake_id_to_ref.push((None, path));
                        id
                    }
                };
                e.insert(id);
                id
            }
        }
    }

    // Some file_ids are not consumed because they correspond to some inlinee stuff
    // So in order to have consecutive ids just return an id for really used files
    pub(super) fn get_true_id(&mut self, fake_id: u32) -> u32 {
        let (id, name) = &mut self.fake_id_to_ref[fake_id as usize];
        if let Some(id) = id {
            *id
        } else {
            let true_id = self.id_to_ref.len() as u32;
            *id = Some(true_id);
            self.id_to_ref.push(name.clone());
            true_id
        }
    }

    pub(super) fn get_mapping(self) -> Vec<String> {
        self.id_to_ref
    }
}
