use log::warn;
use symbolic::common::{Language, Name};
use symbolic::demangle::Demangle;

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

        let s = Self::demangle_and_sanitize(name);
        let index = self.demangled_names.len() as u32;
        self.demangled_names.push(s);
        self.index_for_mangled_name.insert(name.clone(), index);
        index
    }

    pub fn get_list(self) -> Vec<String> {
        self.demangled_names
    }

    fn demangle_and_sanitize(name: &Name) -> String {
        let mut name = Self::demangle(name);

        // Remove control characters such as \n.
        name.retain(|c| !c.is_ascii_control());

        name
    }

    fn demangle(name: &Name) -> String {
        let name = common::fix_symbol_name(name);
        if let Language::C = name.language() {
            return name.as_str().to_string();
        }

        match name.demangle(common::demangle_options()) {
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

#[cfg(test)]
mod test {
    use symbolic::common::{Language, Name, NameMangling};

    use super::InlineOrigins;

    #[test]
    fn test_demangle() {
        // Make sure that the return types are not part of the demangled inline name.
        // There should be no "void " in front of "draw_depth_span".
        let mut inline_origins = InlineOrigins::default();
        let _ = inline_origins.get_id(&Name::new(
            "_ZL15draw_depth_spanIjEvjPT_R11DepthCursor",
            NameMangling::Mangled,
            Language::Cpp,
        ));
        assert_eq!(
            inline_origins.get_list(),
            vec![
                "draw_depth_span<unsigned int>(unsigned int, unsigned int*, DepthCursor&)"
                    .to_string()
            ]
        );
    }

    #[test]
    fn test_bad_chars() {
        // Make sure that there are no characters in the function name
        // which mess up the .sym format, such as line breaks.
        let mut inline_origins = InlineOrigins::default();
        let _ = inline_origins.get_id(&Name::new(
            "\n\u{fffd}\u{fffd}P\u{fffd}",
            NameMangling::Mangled,
            Language::Cpp,
        ));
        assert_eq!(
            inline_origins.get_list(),
            vec!["\u{fffd}\u{fffd}P\u{fffd}".to_string()]
        );
    }
}
