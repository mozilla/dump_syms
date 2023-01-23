// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::Arc;
use symbolic::debuginfo::{pdb::PdbObject, pe::PeObject, Object};

use crate::common;
use crate::mapping::PathMappings;
use crate::object_info::ObjectInfo;
use crate::platform::Platform;

impl ObjectInfo {
    pub fn from_pdb(
        pdb: PdbObject,
        pdb_name: &str,
        pe_name: Option<&str>,
        pe: Option<PeObject>,
        mapping: Option<Arc<PathMappings>>,
        collect_inlines: bool,
    ) -> common::Result<Self> {
        let pdb = Object::Pdb(pdb);
        let pe = pe.map(Object::Pe);

        ObjectInfo::from_object(
            &pdb,
            pdb_name,
            pe.as_ref(),
            pe_name,
            Platform::Win,
            mapping,
            collect_inlines,
        )
    }

    pub fn from_pe(pe_name: &str, pe: PeObject) -> common::Result<Self> {
        let pdb_name = pe.debug_file_name().unwrap_or_default().to_string();
        let pe = Object::Pe(pe);
        let pdb_name = win_path_file_name(&pdb_name).to_string();
        ObjectInfo::from_object(
            &pe,
            &pdb_name,
            None,
            Some(pe_name),
            Platform::Win,
            None,
            false,
        )
    }
}

fn win_path_file_name(pdb_name: &str) -> &str {
    let index = pdb_name.rfind('\\').map_or(0, |i| i + 1);
    &pdb_name[index..]
}

#[cfg(test)]
mod tests {

    use bitflags::bitflags;
    use fxhash::{FxHashMap, FxHashSet};
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{Cursor, Read};
    use std::path::PathBuf;
    use symbolic::debuginfo::breakpad::{
        BreakpadError, BreakpadFileMap, BreakpadFuncRecord, BreakpadLineRecord, BreakpadObject,
    };

    use super::*;

    bitflags! {
        struct TestFlags: u32 {
            const ALL = 0;
            const NO_MULTIPLICITY = 0b1;
            const NO_FILE_LINE = 0b10;
            const NO_FUNCS_LENGTH = 0b100;
        }
    }

    #[derive(Debug, PartialEq)]
    struct StackWin {
        typ: u32,
        rva: u32,
        code_size: u32,
        prolog_size: u32,
        epilog_size: u32,
        params_size: u32,
        regs_size: u32,
        locals_size: u32,
        max_stack_size: u32,
        extra: String,
    }

    const MS: &str = "https://msdl.microsoft.com/download/symbols";

    fn dl_from_server(url: &str) -> Vec<u8> {
        let mut response = reqwest::blocking::get(url).expect("GET request");
        let mut buf = Vec::new();
        response.copy_to(&mut buf).expect("Data from server");
        buf
    }

    fn get_data_from_server(url: &str) -> (Vec<u8>, &str) {
        let toks: Vec<_> = url.rsplitn(4, '/').collect();
        let name = toks[2];
        let pe_buf = dl_from_server(url);
        let pe_buf = crate::utils::read_cabinet(pe_buf, PathBuf::from(name)).unwrap();
        let (pe, pdb_buf, pdb_name) = crate::windows::utils::get_pe_pdb_buf(
            &PathBuf::from("."),
            &pe_buf,
            crate::cache::get_sym_servers(Some(&format!("SRV*~/symcache*{}", MS))).as_ref(),
        )
        .unwrap();

        let pdb = PdbObject::parse(&pdb_buf).unwrap();

        let mut output = Vec::new();
        let cursor = Cursor::new(&mut output);
        let pdb = ObjectInfo::from_pdb(pdb, &pdb_name, Some(name), Some(pe), None, false).unwrap();
        pdb.dump(cursor).unwrap();

        let toks: Vec<_> = name.rsplitn(2, '.').collect();

        (output, toks[1])
    }

    fn get_new_bp(file_name: &str, mapping: Option<Arc<PathMappings>>) -> Vec<u8> {
        let path = PathBuf::from("./test_data/windows");
        let mut path = path.join(file_name);

        if !path.exists() {
            path.set_extension("exe");
        }

        let pe_buf = crate::utils::read_file(&path);
        let (pe, pdb_buf, pdb_name) = crate::windows::utils::get_pe_pdb_buf(
            &path,
            &pe_buf,
            crate::cache::get_sym_servers(Some(&format!("SRV*~/symcache*{}", MS))).as_ref(),
        )
        .unwrap_or_else(|| (PeObject::parse(&pe_buf).unwrap(), vec![], "".to_string()));

        let mut output = Vec::new();
        let cursor = Cursor::new(&mut output);

        if pdb_buf.is_empty() {
            let pe = ObjectInfo::from_pe(file_name, pe).unwrap();
            pe.dump(cursor).unwrap();
        } else {
            let pdb = PdbObject::parse(&pdb_buf).unwrap();
            let pdb =
                ObjectInfo::from_pdb(pdb, &pdb_name, Some(file_name), Some(pe), mapping, false)
                    .unwrap();
            pdb.dump(cursor).unwrap();
        }

        output
    }

    fn get_data(file_name: &str) -> Vec<u8> {
        let path = PathBuf::from("./test_data/windows");
        let mut path = path.join(file_name);
        path.set_extension("sym");

        let mut file = File::open(&path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        buf
    }

    fn clean_old_lines(func: &BreakpadFuncRecord) -> Vec<BreakpadLineRecord> {
        let mut res: Vec<BreakpadLineRecord> = Vec::new();
        func.lines().for_each(|l| {
            let line = l.unwrap();
            if line.line >= 0x00f0_0000 {
                res.last_mut().unwrap().size += line.size
            } else {
                res.push(line);
            }
        });

        res
    }

    fn check_headers(new: &BreakpadObject, old: &BreakpadObject) {
        assert_eq!(new.code_id(), old.code_id(), "Bad code id");
        assert_eq!(new.debug_id(), old.debug_id(), "Bad debug id");
        assert_eq!(new.arch(), old.arch(), "Bad arch");
        assert_eq!(new.name(), old.name(), "Bad name");
        assert_eq!(new.kind(), old.kind(), "Bad kind");
    }

    fn check_func_len(
        func_new: &[std::result::Result<BreakpadFuncRecord<'_>, BreakpadError>],
        func_old: &[std::result::Result<BreakpadFuncRecord<'_>, BreakpadError>],
    ) {
        if func_new.len() != func_old.len() {
            // Try to find the diff in the addresses
            let mut old_addresses = FxHashMap::default();
            let mut old_keys = FxHashSet::default();
            for addr in func_old.iter().map(|f| f.as_ref().unwrap().address) {
                *old_addresses.entry(addr).or_insert(0) += 1;
                old_keys.insert(addr);
            }
            let mut new_addresses = FxHashMap::default();
            let mut new_keys = FxHashSet::default();
            for addr in func_new.iter().map(|f| f.as_ref().unwrap().address) {
                *new_addresses.entry(addr).or_insert(0) += 1;
                new_keys.insert(addr);
            }
            let diff: Vec<_> = old_keys.symmetric_difference(&new_keys).collect();
            for addr in diff.iter() {
                old_addresses.remove(addr);
                new_addresses.remove(addr);
            }

            let mut diff_value = Vec::new();
            for (addr, value) in old_addresses.iter() {
                let new_value = new_addresses.get(addr).unwrap();
                if new_value != value {
                    diff_value.push((addr, new_value, value));
                }
            }

            let diff: Vec<_> = diff.iter().map(|x| format!("0x{:x}", x)).collect();
            let values: Vec<_> = diff_value
                .iter()
                .map(|(a, n, o)| format!("At 0x{:x}: new {}, old: {}", a, n, o))
                .collect();
            panic!(
                "Not the same number of FUNC (new: {}, old: {}):\n - Diff keys: {:?}\n - Diff values: {:?}",
                func_new.len(),
                func_old.len(),
                diff,
                values,
            );
        }
    }

    fn check_func(
        pos: usize,
        new: &BreakpadFuncRecord,
        old: &BreakpadFuncRecord,
        file_map_new: &BreakpadFileMap,
        file_map_old: &BreakpadFileMap,
        flags: TestFlags,
    ) {
        assert_eq!(
            new.address,
            old.address,
            "Not the same address for FUNC at position {}",
            pos + 1
        );
        if !flags.intersects(TestFlags::NO_MULTIPLICITY) {
            assert_eq!(
                new.multiple, old.multiple,
                "Not the same multiplicity for FUNC at rva {:x}",
                new.address
            );
        }
        assert_eq!(
            new.size, old.size,
            "Not the same size for FUNC at rva {:x}",
            new.address
        );
        assert_eq!(
            new.parameter_size, old.parameter_size,
            "Not the same parameter size for FUNC at rva {:x}",
            new.address
        );

        assert_eq!(
            new.name, old.name,
            "Not the same name for FUNC at rva {:x}",
            new.address
        );

        let line_old = clean_old_lines(old);
        let line_new = new.lines();

        assert_eq!(
            line_new.clone().count(),
            line_old.len(),
            "Not the same number of lines for FUNC at rva {:x}",
            new.address
        );
        for (i, (line_n, line_o)) in line_new.zip(line_old.iter()).enumerate() {
            let line_n = line_n.unwrap();

            assert_eq!(
                line_n.address,
                line_o.address,
                "Not the same address for line at position {} in FUNC at rva {:x}",
                i + 1,
                new.address
            );

            if flags.intersects(TestFlags::NO_FILE_LINE) {
                continue;
            }

            if i < line_old.len() - 1 {
                // Sometimes the last line is different
                // For a line, DIA seems to compute the length using the address of next line minus address of the line
                // But it appears that in assembly files we may have several symbols for the same offset
                // and so the length may be incorrect.
                assert_eq!(
                    line_n.size,
                    line_o.size,
                    "Not the same size for line at position {} in FUNC at rva {:x}",
                    i + 1,
                    new.address
                );
            }

            assert_eq!(
                line_n.line,
                line_o.line,
                "Not the same line number for line at position {} in FUNC at rva {:x}",
                i + 1,
                new.address
            );

            assert_eq!(
                file_map_new.get(&line_n.file_id),
                file_map_old.get(&line_o.file_id),
                "Not the same file for line at position {} in FUNC at rva {:x}",
                i + 1,
                new.address
            );
        }
    }

    fn test_file(name: &str, flags: TestFlags) {
        let (out, name) = if name.starts_with("https://") {
            get_data_from_server(name)
        } else {
            let dll = name.to_string() + ".dll";
            (get_new_bp(&dll, None), name)
        };
        let new = BreakpadObject::parse(&out).unwrap();

        let out = get_data(name);
        let old = BreakpadObject::parse(&out).unwrap();

        check_headers(&new, &old);

        let file_map_old = old.file_map();
        let file_map_new = new.file_map();
        let files_old: HashSet<_> = file_map_old.values().collect();
        let files_new: HashSet<_> = file_map_new.values().collect();

        for old_file in &files_old {
            assert!(files_new.contains(old_file), "Missing path: {}", old_file);
        }
        for new_file in &files_new {
            assert!(files_old.contains(new_file), "Extra path: {}", new_file);
        }

        let mut func_old: Vec<_> = old.func_records().collect();
        let mut func_new: Vec<_> = new.func_records().collect();
        func_old.sort_by_key(|f| f.as_ref().unwrap().address);
        func_new.sort_by_key(|f| f.as_ref().unwrap().address);

        if !flags.intersects(TestFlags::NO_FUNCS_LENGTH) {
            check_func_len(&func_new, &func_old);
        }

        for (i, (func_n, func_o)) in func_new.iter().zip(func_old.iter()).enumerate() {
            let func_n = func_n.as_ref().unwrap();
            let func_o = func_o.as_ref().unwrap();

            check_func(i, func_n, func_o, &file_map_new, &file_map_old, flags);
        }

        let public_old = old.public_records();
        // Remove public constants
        let public_old = public_old.filter(|x| {
            let x = x.as_ref().unwrap();
            !x.name.contains("::FNODOBFM::`string'")
        });

        let public_new = new.public_records();

        assert_eq!(
            public_new.clone().count(),
            public_old.clone().count(),
            "Not the same number of PUBLIC"
        );

        for (i, (public_n, public_o)) in public_new.zip(public_old).enumerate() {
            let public_n = public_n.unwrap();
            let public_o = public_o.unwrap();

            assert_eq!(
                public_n.address,
                public_o.address,
                "Not the same address for PUBLIC at position {} ({})",
                i + 1,
                public_n.name
            );
            if !flags.intersects(TestFlags::NO_MULTIPLICITY) {
                assert_eq!(
                    public_n.multiple, public_o.multiple,
                    "Not the same multiplicity for PUBLIC at rva {:x}",
                    public_n.address
                );
            }
            assert_eq!(
                public_n.parameter_size, public_o.parameter_size,
                "Not the same parameter size for PUBLIC at rva {:x}",
                public_n.address
            );
            /*assert_eq!(
                public_n.name, public_o.name,
                "Not the same name for PUBLIC at rva {:x}",
                public_n.address
            );*/
        }
    }

    #[test]
    fn test_basic32() {
        test_file("basic32", TestFlags::ALL);
    }

    #[test]
    fn test_basic32_dwarf() {
        test_file("basic32-dwarf", TestFlags::ALL);
    }

    #[test]
    fn test_basic32_min() {
        test_file("basic32-min", TestFlags::ALL);
    }

    #[test]
    fn test_basic64() {
        test_file("basic64", TestFlags::ALL);
    }

    #[test]
    fn test_basic64_dwarf() {
        test_file("basic64-dwarf", TestFlags::ALL);
    }

    #[test]
    fn test_basic_opt32() {
        test_file("basic-opt32", TestFlags::ALL);
    }

    #[test]
    fn test_basic_opt64() {
        test_file("basic-opt64", TestFlags::ALL);
    }

    #[test]
    fn test_dump_syms_regtest64() {
        test_file("dump_syms_regtest64", TestFlags::ALL);
    }

    #[test]
    fn test_mozwer() {
        test_file("mozwer", TestFlags::ALL);
    }

    #[test]
    fn test_ntdll() {
        test_file(
            &format!("{}/ntdll.dll/5D6AA5581AD000/ntdll.dll", MS),
            TestFlags::NO_MULTIPLICITY,
        );
    }

    #[test]
    fn test_oleaut32() {
        test_file(
            &format!("{}/oleaut32.dll/BCDE805BC4000/oleaut32.dll", MS),
            TestFlags::NO_MULTIPLICITY,
        );
    }

    #[test]
    fn test_win_mapping() {
        let mapping = PathMappings::new(
            &Some(vec!["rev=abcdef"]),
            &Some(vec![r"d:\\agent\\_work\\3\\s\\src\\(.*)"]),
            &Some(vec!["https://source/{rev}/{1}"]),
            &None,
        )
        .unwrap();
        let dll = "basic32.dll";
        let output = get_new_bp(dll, mapping.map(Arc::new));
        let bp = BreakpadObject::parse(&output).unwrap();

        let map = bp.file_map();
        let files: Vec<_> = map.values().collect();

        assert_eq!(
            files[6].replace('\\', "/"),
            "https://source/abcdef/vctools/crt/vcstartup/src/eh/i386/secchk.c"
        );
        assert_eq!(
            files[7].replace('\\', "/"),
            "https://source/abcdef/vctools/crt/vcstartup/src/heap/delete_scalar_size.cpp"
        );
        assert_eq!(
            files[files.len() - 1].replace('\\', "/"),
            "https://source/abcdef/vctools/crt/vcruntime/src/string/i386/memcmp.c"
        );
    }
}
