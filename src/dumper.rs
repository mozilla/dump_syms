// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crossbeam::channel::{bounded, Receiver, Sender};
use failure::Fail;
use hashbrown::HashMap;
use log::{error, info};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use symbolic::common::Arch;
use symbolic::debuginfo::pe::PeObject;

use crate::cache;
use crate::common::{self, Dumpable, FileType, Mergeable};
use crate::linux::elf::{ElfInfo, Platform};
use crate::mac::macho::MachoInfo;
use crate::mapping::PathMappings;
use crate::utils;
use crate::windows::{self, pdb::PDBInfo, pdb::PEInfo};

pub(crate) struct Config<'a> {
    pub output: &'a str,
    pub symbol_server: Option<&'a str>,
    pub store: Option<&'a str>,
    pub debug_id: Option<&'a str>,
    pub code_id: Option<&'a str>,
    pub arch: &'a str,
    pub file_type: FileType,
    pub num_jobs: usize,
    pub check_cfi: bool,
    pub mapping_var: Option<Vec<&'a str>>,
    pub mapping_src: Option<Vec<&'a str>>,
    pub mapping_dest: Option<Vec<&'a str>>,
    pub mapping_file: Option<&'a str>,
}

pub(crate) trait Creator: Mergeable + Dumpable + Sized {
    fn get_dbg(
        arch: Arch,
        buf: &[u8],
        path: &Path,
        filename: &str,
        mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self>;

    fn get_pe<'a>(
        _conf: &Config<'a>,
        _buf: &[u8],
        _path: &Path,
        _filename: &str,
        _mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        Err("Not implemented".into())
    }
}

impl Creator for ElfInfo {
    fn get_dbg(
        _arch: Arch,
        buf: &[u8],
        _path: &Path,
        filename: &str,
        mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        Self::new(buf, filename, Platform::Linux, mapping)
    }
}

impl Creator for MachoInfo {
    fn get_dbg(
        arch: Arch,
        buf: &[u8],
        _path: &Path,
        filename: &str,
        mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        Self::new(buf, filename, arch, mapping)
    }
}

impl Creator for PDBInfo {
    fn get_dbg(
        _arch: Arch,
        buf: &[u8],
        path: &Path,
        filename: &str,
        mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        let mut pdb = Self::new(buf, filename, "", None, mapping)?;
        windows::utils::try_to_set_pe(path, &mut pdb, buf);
        Ok(pdb)
    }

    fn get_pe<'a>(
        conf: &Config<'a>,
        buf: &[u8],
        path: &Path,
        filename: &str,
        mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        let symbol_server = cache::get_sym_servers(conf.symbol_server);
        let res = windows::utils::get_pe_pdb_buf(path, buf, symbol_server.as_ref());

        if let Some((pe, pdb_buf, pdb_name)) = res {
            let pdb = Self::new(&pdb_buf, &pdb_name, filename, Some(pe), mapping)?;
            Ok(pdb)
        } else {
            Err("No pdb file found".into())
        }
    }
}

impl Creator for PEInfo {
    fn get_dbg(
        _arch: Arch,
        _buf: &[u8],
        _path: &Path,
        _filename: &str,
        _mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        Err("Not implemented".into())
    }

    fn get_pe<'a>(
        _conf: &Config<'a>,
        buf: &[u8],
        path: &Path,
        filename: &str,
        _mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        let pe = PeObject::parse(buf)
            .unwrap_or_else(|_| panic!("Unable to parse the PE file {}", path.to_str().unwrap()));
        let pe = Self::new(filename, pe)?;
        Ok(pe)
    }
}

fn store<D: Dumpable, S1: AsRef<str>, S2: AsRef<str>>(
    output: S1,
    store: Option<S2>,
    check_cfi: bool,
    dumpable: D,
) -> common::Result<()> {
    if check_cfi && !dumpable.has_stack() {
        return Err("No CFI data".into());
    }

    let output = output.as_ref();
    let store = store.filter(|p| !p.as_ref().is_empty()).map(|p| {
        PathBuf::from(p.as_ref()).join(cache::get_path_for_sym(
            dumpable.get_name(),
            dumpable.get_debug_id(),
        ))
    });

    if let Some(store) = store.as_ref() {
        fs::create_dir_all(store.parent().unwrap())?;
        let store = store.to_str().unwrap();
        let output = utils::get_writer_for_sym(store);
        if let Err(e) = dumpable.dump(output) {
            return Err(e);
        }
        info!("Write symbols at {}", store);
    }

    if output != "-" || store.is_none() {
        let output_stream = utils::get_writer_for_sym(output);
        dumpable.dump(output_stream)?;
        info!("Write symbols at {}", output);
    }
    Ok(())
}

fn get_from_id(
    config: &Config,
    path: &Path,
    filename: String,
) -> common::Result<(Vec<u8>, String)> {
    if let Some(id) = config.debug_id.or(config.code_id) {
        let symbol_server = cache::get_sym_servers(config.symbol_server);
        let (buf, filename) = cache::search_file(filename, id, symbol_server.as_ref());
        return if let Some(buf) = buf {
            Ok((buf, filename))
        } else {
            Err(format!("Impossible to get file {} with id {}", filename, id).into())
        };
    }

    Ok((utils::read_file(&path), filename))
}

pub(crate) fn single_file(config: &Config, filename: &str) -> common::Result<()> {
    let path = Path::new(filename);
    let filename = utils::get_filename(path);

    let (buf, filename) = get_from_id(config, path, filename)?;
    let file_mapping = PathMappings::new(
        &config.mapping_var,
        &config.mapping_src,
        &config.mapping_dest,
        &config.mapping_file,
    )?
    .map(Arc::new);
    let arch = Arch::from_str(config.arch).map_err(|e| e.compat())?;

    match FileType::from_buf(&buf) {
        FileType::Elf => store(
            config.output,
            config.store,
            config.check_cfi,
            ElfInfo::get_dbg(arch, &buf, path, &filename, file_mapping)?,
        ),
        FileType::Pdb => store(
            config.output,
            config.store,
            config.check_cfi,
            PDBInfo::get_dbg(arch, &buf, path, &filename, file_mapping)?,
        ),
        FileType::Pe => {
            if let Ok(pdb_info) = PDBInfo::get_pe(config, &buf, path, &filename, file_mapping) {
                store(config.output, config.store, config.check_cfi, pdb_info)
            } else {
                store(
                    config.output,
                    config.store,
                    config.check_cfi,
                    PEInfo::get_pe(config, &buf, path, &filename, None)?,
                )
            }
        }
        FileType::Macho => store(
            config.output,
            config.store,
            config.check_cfi,
            MachoInfo::get_dbg(arch, &buf, path, &filename, file_mapping)?,
        ),
        FileType::Unknown => Err("Unknown file format".into()),
    }
}

enum JobType<D: Dumpable> {
    Get,
    Dump(D),
}

struct JobItem<D: Dumpable> {
    file: String,
    typ: JobType<D>,
    mapping: Option<Arc<PathMappings>>,
}

fn send_store_jobs<T: Creator>(
    sender: &Sender<Option<JobItem<T>>>,
    results: &mut HashMap<String, T>,
    num_threads: usize,
    output: &str,
    store: &Option<String>,
    check_cfi: bool,
) -> common::Result<()> {
    if results.len() == 1 {
        let (_, d) = results.drain().take(1).next().unwrap();
        self::store(&output, store.as_ref(), check_cfi, d)?;
    } else {
        for (_, d) in results.drain() {
            sender
                .send(Some(JobItem {
                    file: "".to_string(),
                    typ: JobType::Dump(d),
                    mapping: None,
                }))
                .unwrap();
        }
    }

    poison_queue(sender, num_threads);
    Ok(())
}

fn poison_queue<T: Dumpable>(sender: &Sender<Option<JobItem<T>>>, num_threads: usize) {
    // Poison the receiver.
    for _ in 0..num_threads {
        sender.send(None).unwrap();
    }
}

#[allow(clippy::too_many_arguments)]
fn consumer<T: Creator>(
    arch: Arch,
    sender: Sender<Option<JobItem<T>>>,
    receiver: Receiver<Option<JobItem<T>>>,
    results: Arc<Mutex<HashMap<String, T>>>,
    counter: Arc<AtomicUsize>,
    num_threads: usize,
    output: String,
    store: Option<String>,
    check_cfi: bool,
) -> common::Result<()> {
    while let Ok(job) = receiver.recv() {
        if job.is_none() {
            return Ok(());
        }

        let JobItem { file, typ, mapping } = job.unwrap();

        match typ {
            JobType::Get => {
                let path = PathBuf::from(file);
                let filename = utils::get_filename(&path);
                let buf = utils::read_file(&path);

                let info = T::get_dbg(arch, &buf, &path, &filename, mapping).map_err(|e| {
                    poison_queue(&sender, num_threads);
                    e
                })?;

                let mut results = results.lock().unwrap();
                let info = if let Some(prev) = results.remove(info.get_debug_id()) {
                    T::merge(info, prev).map_err(|e| {
                        poison_queue(&sender, num_threads);
                        e
                    })?
                } else {
                    info
                };
                results.insert(info.get_debug_id().to_string(), info);
            }
            JobType::Dump(d) => {
                let cwd = ".".to_string();
                let store = Some(store.as_ref().unwrap_or(&cwd));
                self::store(&output, store.as_ref(), check_cfi, d)?;
                continue;
            }
        }

        if counter.load(Ordering::SeqCst) == 1 {
            // it was the last file: so we just have to add jobs to dump & store
            // and then poison the queue
            let mut results = results.lock().unwrap();
            send_store_jobs(
                &sender,
                &mut results,
                num_threads,
                &output,
                &store,
                check_cfi,
            )?;
        } else {
            counter.fetch_sub(1, Ordering::SeqCst);
        }
    }

    Ok(())
}

pub(crate) fn several_files<T: 'static + Creator + std::marker::Send>(
    config: &Config,
    filenames: &[&str],
) -> common::Result<()> {
    let file_mapping = PathMappings::new(
        &config.mapping_var,
        &config.mapping_src,
        &config.mapping_dest,
        &config.mapping_file,
    )?
    .map(Arc::new);
    let arch = Arch::from_str(config.arch).map_err(|e| e.compat())?;
    let results = Arc::new(Mutex::new(HashMap::default()));
    let num_jobs = config.num_jobs.min(filenames.len());
    let counter = Arc::new(AtomicUsize::new(filenames.len()));

    let (sender, receiver) = bounded(num_jobs + 1);

    let mut receivers = Vec::with_capacity(num_jobs);
    for i in 0..num_jobs {
        let sender = sender.clone();
        let receiver = receiver.clone();
        let results = Arc::clone(&results);
        let counter = Arc::clone(&counter);
        let output = config.output.to_string();
        let store = config.store.map(|s| s.to_string());
        let check_cfi = config.check_cfi;

        let t = thread::Builder::new()
            .name(format!("dump-syms {}", i))
            .spawn(move || {
                consumer::<T>(
                    arch, sender, receiver, results, counter, num_jobs, output, store, check_cfi,
                )
            })
            .unwrap();

        receivers.push(t);
    }

    for f in filenames {
        sender
            .send(Some(JobItem {
                file: f.to_string(),
                typ: JobType::Get,
                mapping: file_mapping.as_ref().map(Arc::clone),
            }))
            .unwrap();
    }

    for receiver in receivers {
        if let Err(e) = receiver.join().unwrap() {
            error!("{}", e);
        }
    }

    Ok(())
}
