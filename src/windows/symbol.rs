// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use hashbrown::{hash_map, HashMap};
use log::warn;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::rc::Rc;
use symbolic::common::{Language, Name, NameMangling};
use symbolic::debuginfo::pe::{ExceptionData, PeSymbolIterator};
use symbolic::demangle::Demangle;

use crate::common;
use crate::common::demangle_options;
use crate::common::LineFinalizer;
use crate::line::Lines;

fn is_constant_string(name: &str) -> bool {
    name.starts_with("??_C")
}

fn is_constant_number(name: &str) -> bool {
    if let Some(name) = name.strip_prefix("__") {
        name.starts_with("real@") || name.starts_with("xmm@") || name.starts_with("ymm@")
    } else {
        false
    }
}

fn should_skip_symbol(name: &str) -> bool {
    is_constant_string(name) || is_constant_number(name)
}

/*
pub(super) fn append_dummy_symbol(mut syms: PDBSymbols, name: &str) -> PDBSymbols {
    let (rva, len, id) = if let Some((_, last_sym)) = syms.iter().next_back() {
        (last_sym.rva, last_sym.len, last_sym.id)
    } else {
        return syms;
    };

    let end_rva = if len == 0 { rva + 1 } else { rva + len };

    let name = if name.is_empty() {
        String::from("<unknown>")
    } else {
        format!("<unknown in {}>", name)
    };

    syms.insert(
        rva,
        PDBSymbol {
            name,
            is_public: true,
            is_multiple: false,
            rva,
            len: 0,
            parameter_size: 0,
            source: Rc::new(Lines::new()),
            id: id + 1,
        },
    );

    syms
}
*/

/*
pub(super) fn symbolic_to_pdb_symbols(
    syms: PeSymbolIterator,
    exception_data: Option<&ExceptionData<'_>>,
    module_name: &str,
) -> PDBSymbols {
    let mut pdb_syms = PDBSymbols::default();

    let module_name = if module_name.is_empty() {
        String::from("<unknown>")
    } else {
        format!("<unknown in {}>", module_name)
    };

    if let Some(data) = exception_data {
        data.into_iter()
            .filter_map(|result| result.ok())
            .filter(|function| function.end_address > function.begin_address)
            .for_each(|function| {
                pdb_syms.insert(
                    function.begin_address,
                    PDBSymbol {
                        name: module_name.clone(),
                        is_public: false,
                        is_multiple: false,
                        rva: function.begin_address,
                        len: function.end_address - function.begin_address,
                        parameter_size: 0,
                        source: Rc::new(Lines::new()),
                        id: 0,
                    },
                );
            });
    };

    for sym in syms {
        if let Some(name) = sym.name() {
            let demangled_name = demangle(name);
            let (name, parameter_size) = match demangled_name {
                FuncName::Undecorated(name) => (name, 0),
                FuncName::Unknown((name, parameter_size)) => (name, parameter_size),
            };
            let rva = sym.address as u32;
            pdb_syms
                .entry(rva)
                .and_modify(|e| {
                    e.name = name.clone();
                    e.parameter_size = parameter_size;
                })
                .or_insert(PDBSymbol {
                    name,
                    is_public: true,
                    is_multiple: false,
                    rva: sym.address as u32,
                    len: 0,
                    parameter_size,
                    source: Rc::new(Lines::new()),
                    id: 0,
                });
        }
    }

    pdb_syms
}
 */
