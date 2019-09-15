/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use goblin::pe::exception::UnwindOperation;
use std::fmt::{Display, Formatter};
use symbolic_debuginfo::pe::{PeError, PeObject};

use crate::utils::get_win_path;

#[derive(Debug, Eq, PartialEq)]
pub struct Func {
    begin_addr: u32,
    end_addr: u32,
    stack_size: u32,
    rip_offset: u32,
}

pub struct FuncInfo {
    functions: Vec<Func>,
}

pub struct PEInfo {
    code_id: String,
    code_file: String,
    debug_file: Option<String>,
    funcs_info: FuncInfo,
}

impl Display for FuncInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        for func in self.functions.iter() {
            writeln!(
                f,
                "STACK CFI INIT {:x} {:x} .cfa: $rsp .ra: .cfa {} - ^",
                func.begin_addr,
                func.end_addr - func.begin_addr,
                func.rip_offset
            )?;
            writeln!(
                f,
                "STACK CFI {:x} .cfa: $rsp {} +",
                func.begin_addr, func.stack_size
            )?;
        }
        Ok(())
    }
}

impl PEInfo {
    ///
    pub fn new(file_path: &str, buf: &[u8]) -> Result<Self, PeError> {
        let pe = PeObject::parse(&buf)?;

        let code_id = pe.code_id().unwrap().as_str().to_uppercase();
        let code_file = get_win_path(file_path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let debug_file = if let Some(debug_file) = pe.debug_file_name() {
            Some(debug_file.to_string())
        } else {
            None
        };
        let funcs_info = Self::get_func_info(pe);

        Ok(PEInfo {
            code_id,
            code_file,
            debug_file,
            funcs_info,
        })
    }

    pub fn name(&self) -> Option<String> {
        let debug_file = self.debug_file.as_ref()?;
        Some(
            get_win_path(debug_file)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        )
    }

    fn get_func_info(pe: PeObject) -> FuncInfo {
        let mut functions = Vec::new();
        let exception_data = pe.exception_data();
        if exception_data.is_none() {
            return FuncInfo { functions };
        }
        let exception_data = exception_data.unwrap();
        let sections = &pe.sections();

        for func in exception_data.functions() {
            if let Ok(func) = func {
                if let Ok(uw_info) = exception_data.get_unwind_info(func, sections) {
                    // For each function, we compute the stack size and the rip offset
                    let mut stack_size = 8; // minimal stack size is 8 for RIP
                    let mut rip_offset = 8;
                    for uw_code in uw_info.unwind_codes() {
                        if let Ok(uw_code) = uw_code {
                            match uw_code.operation {
                                UnwindOperation::PushNonVolatile(_) => stack_size += 8,
                                UnwindOperation::Alloc(n) => stack_size += n,
                                UnwindOperation::PushMachineFrame(is_error) => {
                                    // TODO: add a comment to explain why 88 & 80
                                    // https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=vs-2019 (look for PUSH_MACHFRAME)
                                    // The RSP should be decremented by 48 or 40 !!
                                    // For information: https://breakpad.appspot.com/345002/#ps9001
                                    // patches 1 & 2 contain 48 & 40 but patch 3 changed them to 88 & 80.
                                    // A patch to fix that is in review:
                                    //   https://chromium-review.googlesource.com/c/breakpad/breakpad/+/1425908
                                    stack_size += if is_error { 88 } else { 80 };
                                    rip_offset += 80;
                                }
                                _ => {}
                            }
                        }
                    }
                    functions.push(Func {
                        begin_addr: func.begin_address,
                        end_addr: func.end_address,
                        stack_size,
                        rip_offset,
                    });
                }
            }
        }
        FuncInfo { functions }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use symbolic_debuginfo::breakpad::{BreakpadObject, BreakpadStackRecord};

    use super::*;

    fn get_buffers(path: &str) -> (Vec<u8>, Vec<u8>) {
        let bin_path = PathBuf::from("test_data").join(path);
        let mut sym_path = bin_path.clone();
        sym_path.set_extension("sym");

        // Read the PE file
        let mut file = File::open(bin_path.clone()).unwrap();
        let mut bin_buf = Vec::new();
        file.read_to_end(&mut bin_buf).unwrap();

        // Read the breakpad symbols file
        let mut file = File::open(sym_path.clone()).unwrap();
        let mut sym_buf = Vec::new();
        file.read_to_end(&mut sym_buf).unwrap();

        (bin_buf, sym_buf)
    }

    #[test]
    fn test_func_info() {
        let files = vec!["dump_syms_regtest64.exe"];
        for path in files {
            let (bin_buf, sym_buf) = get_buffers(path);
            let pe_info = PEInfo::new(path, &bin_buf).unwrap();
            let bp_obj = BreakpadObject::parse(&sym_buf).unwrap();

            let mut funcs = Vec::new();
            for record in bp_obj.stack_records() {
                if let BreakpadStackRecord::Cfi(record) = record.unwrap() {
                    let toks: Vec<&str> = record.text.split_whitespace().collect();
                    if toks[0] == "INIT" {
                        let begin_addr = u32::from_str_radix(toks[1], 16).unwrap();
                        let end_addr = u32::from_str_radix(toks[2], 16).unwrap() + begin_addr;
                        let rip_offset = u32::from_str_radix(toks[7], 10).unwrap();
                        funcs.push(Func {
                            begin_addr,
                            end_addr,
                            stack_size: 0,
                            rip_offset,
                        });
                    } else {
                        assert!(!funcs.is_empty());
                        let begin_addr = u32::from_str_radix(toks[0], 16).unwrap();
                        let stack_size = u32::from_str_radix(toks[3], 10).unwrap();

                        assert!(funcs.last().unwrap().begin_addr == begin_addr);
                        funcs.last_mut().unwrap().stack_size = stack_size;
                    }
                }
            }

            assert_eq!(
                pe_info.funcs_info.functions, funcs,
                "Function information are different"
            );
        }
    }

    #[test]
    fn test_meta() {
        let files = vec!["dump_syms_regtest64.exe"];
        for path in files {
            let (bin_buf, sym_buf) = get_buffers(path);
            let pe_info = PEInfo::new(path, &bin_buf).unwrap();
            let bp_obj = BreakpadObject::parse(&sym_buf).unwrap();

            assert_eq!(
                pe_info.code_id,
                bp_obj.code_id().unwrap().as_str().to_uppercase(),
                "Code ids are different"
            );

            assert_eq!(
                pe_info.name().unwrap(),
                bp_obj.name(),
                "Debug file names are different"
            );
        }
    }

}
