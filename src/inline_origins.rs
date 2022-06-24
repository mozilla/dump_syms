use log::warn;
use symbolic::common::{Language, Name};
use symbolic::demangle::{Demangle, DemangleOptions};

use std::collections::HashMap;

use crate::common;

#[derive(Debug, Default)]
pub struct InlineOrigins<'a> {
    demangled_names: Vec<String>,
    index_for_mangled_name: HashMap<Name<'a>, u32>,
}

impl<'a> InlineOrigins<'a> {
    pub fn get_id(&mut self, name: &Name<'a>) -> u32 {
        if let Some(index) = self.index_for_mangled_name.get(name) {
            return *index;
        }

        let s = Self::demangle(name);
        let index = self.demangled_names.len() as u32;
        self.demangled_names.push(s);
        self.index_for_mangled_name.insert(name.clone(), index);
        index
    }

    pub fn get_list(self) -> Vec<String> {
        self.demangled_names
    }

    fn demangle(name: &Name) -> String {
        let name = common::fix_symbol_name(name);
        if let Language::C = name.language() {
            return name.as_str().to_string();
        }

        match name.demangle(DemangleOptions::complete()) {
            Some(demangled) => demangled,
            None => {
                let aname = name.as_str();
                warn!("Didn't manage to demangle {:?}", name);
                aname.to_string()
            }
        }
    }
}

/// Adds all inline origins from `right` into `left`, and returns
/// a Vec which maps the IDs from right into the IDs in left.
pub fn merge_inline_origins(left: &mut Vec<String>, right: Vec<String>) -> Vec<u32> {
    // Merging is a bit of a silly business. This is used when we feed both a binary
    // and a debug file into dump_syms. In this case, the debug file has all the
    // information about inlines, and the binary file has none of the information about
    // inlines.
    // So we only need to care about the case where either `right` or `left` is empty.
    // The other case is a theoretical possibility but doesn't need to be good or fast.
    if right.is_empty() {
        return Vec::new();
    }
    if left.is_empty() {
        let count = right.len() as u32;
        *left = right;
        return (0..count).collect();
    }
    // Just append the two vecs to each other. We don't bother with deduplication.
    let count = right.len() as u32;
    let offset = left.len() as u32;
    left.extend(right.into_iter());
    (offset..(offset + count)).collect()
}
