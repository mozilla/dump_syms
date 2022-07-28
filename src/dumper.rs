// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crossbeam::channel::{bounded, Receiver, Sender};
use hashbrown::HashMap;
use log::{error, info};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use symbolic::common::Arch;
use symbolic::debuginfo::pe::PeObject;

use crate::common::{self, Dumpable, FileType, Mergeable};
use crate::linux::elf::{ElfInfo, Platform};
use crate::mac::macho::MachoInfo;
use crate::mapping::PathMappings;
use crate::utils;
use crate::windows::{self, pdb::PDBInfo, pdb::PEInfo};

/// Different locations for file output
#[derive(Clone)]
pub enum FileOutput {
    Path(PathBuf),
    Stdout,
    Stderr,
}

impl From<&str> for FileOutput {
    fn from(s: &str) -> Self {
        if s == "-" {
            Self::Stdout
        } else {
            Self::Path(s.into())
        }
    }
}

impl fmt::Display for FileOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(p) => write!(f, "{}", p.display()),
            Self::Stdout => f.write_str("stdout"),
            Self::Stderr => f.write_str("stderr"),
        }
    }
}

/// Defines how the final symbols are outputted
#[derive(Clone)]
pub enum Output {
    File(FileOutput),
    /// Store output symbols as FILENAME.<ext>/DEBUG_ID/FILENAME.sym in the
    /// specified directory, ie the symbol store format
    Store(PathBuf),
    /// Writes symbols to a file as well as storing them in the symbol store
    /// format to the specified directory
    FileAndStore {
        file: FileOutput,
        store_directory: PathBuf,
    },
}

impl From<PathBuf> for Output {
    fn from(path: PathBuf) -> Self {
        Self::File(FileOutput::Path(path))
    }
}

pub struct Config<'a> {
    pub output: Output,
    pub symbol_server: Option<&'a str>,
    pub debug_id: Option<&'a str>,
    pub code_id: Option<&'a str>,
    pub arch: &'a str,
    pub file_type: FileType,
    pub num_jobs: usize,
    pub check_cfi: bool,
    pub emit_inlines: bool,
    pub keep_mangled: bool,
    pub mapping_var: Option<Vec<&'a str>>,
    pub mapping_src: Option<Vec<&'a str>>,
    pub mapping_dest: Option<Vec<&'a str>>,
    pub mapping_file: Option<&'a str>,
}

pub trait Creator: Mergeable + Dumpable + Sized {
    fn get_dbg(
        arch: Arch,
        buf: &[u8],
        path: &Path,
        filename: &str,
        mapping: Option<Arc<PathMappings>>,
        collect_inlines: bool,
        keep_mangled: bool,
    ) -> common::Result<Self>;

    fn get_pe<'a>(
        _conf: &Config<'a>,
        _buf: &[u8],
        _path: &Path,
        _filename: &str,
        _mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        anyhow::bail!("Not implemented")
    }
}

impl Creator for ElfInfo {
    fn get_dbg(
        _arch: Arch,
        buf: &[u8],
        _path: &Path,
        filename: &str,
        mapping: Option<Arc<PathMappings>>,
        collect_inlines: bool,
        keep_mangled: bool,
    ) -> common::Result<Self> {
        Self::new(
            buf,
            filename,
            Platform::Linux,
            mapping,
            collect_inlines,
            keep_mangled,
        )
    }
}

impl Creator for MachoInfo {
    fn get_dbg(
        arch: Arch,
        buf: &[u8],
        _path: &Path,
        filename: &str,
        mapping: Option<Arc<PathMappings>>,
        collect_inlines: bool,
        keep_mangled: bool,
    ) -> common::Result<Self> {
        Self::new(buf, filename, arch, mapping, collect_inlines, keep_mangled)
    }
}

impl Creator for PDBInfo {
    fn get_dbg(
        _arch: Arch,
        buf: &[u8],
        path: &Path,
        filename: &str,
        mapping: Option<Arc<PathMappings>>,
        _collect_inlines: bool,
        _keep_mangled: bool,
    ) -> common::Result<Self> {
        let mut pdb = Self::new(buf, filename, "", None, mapping)?;
        windows::utils::try_to_set_pe(path, &mut pdb, buf);
        Ok(pdb)
    }

    fn get_pe<'a>(
        _conf: &Config<'a>,
        _buf: &[u8],
        _path: &Path,
        _filename: &str,
        _mapping: Option<Arc<PathMappings>>,
    ) -> common::Result<Self> {
        #[cfg(feature = "http")]
        {
            let symbol_server = crate::cache::get_sym_servers(_conf.symbol_server);
            let res = windows::utils::get_pe_pdb_buf(_path, _buf, symbol_server.as_ref());

            if let Some((pe, pdb_buf, pdb_name)) = res {
                let pdb = Self::new(&pdb_buf, &pdb_name, _filename, Some(pe), _mapping)?;
                Ok(pdb)
            } else {
                anyhow::bail!("No pdb file found")
            }
        }

        #[cfg(not(feature = "http"))]
        anyhow::bail!("HTTP symbol retrieval not enabled")
    }
}

impl Creator for PEInfo {
    fn get_dbg(
        _arch: Arch,
        _buf: &[u8],
        _path: &Path,
        _filename: &str,
        _mapping: Option<Arc<PathMappings>>,
        _collect_inlines: bool,
        _keep_mangled: bool,
    ) -> common::Result<Self> {
        anyhow::bail!("Not implemented")
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

#[inline]
pub fn get_writer_for_sym(fo: &FileOutput) -> std::io::BufWriter<Box<dyn std::io::Write>> {
    let output: Box<dyn std::io::Write> = match fo {
        FileOutput::Stdout => Box::new(std::io::stdout()),
        FileOutput::Stderr => Box::new(std::io::stderr()),
        FileOutput::Path(path) => {
            let output = std::fs::File::create(path)
                .unwrap_or_else(|_| panic!("Cannot open file {} for writing", path.display()));
            Box::new(output)
        }
    };

    std::io::BufWriter::new(output)
}

fn store<D: Dumpable>(output: &Output, check_cfi: bool, dumpable: D) -> common::Result<()> {
    anyhow::ensure!(!check_cfi || dumpable.has_stack(), "No CFI data");

    let sym_store_path = |dir: &Path| -> Option<PathBuf> {
        if dir.to_str()?.is_empty() {
            return None;
        }

        let mut pb = PathBuf::new();
        pb.push(dir);
        pb.push(utils::get_path_for_sym(
            dumpable.get_name(),
            dumpable.get_debug_id(),
        ));
        Some(pb)
    };

    let (foutput, store) = match output {
        Output::File(fo) => (Some(fo), None),
        Output::Store(store) => (None, sym_store_path(store)),
        Output::FileAndStore {
            file,
            store_directory,
        } => (Some(file), sym_store_path(store_directory)),
    };

    if let Some(store) = store {
        fs::create_dir_all(store.parent().unwrap())?;

        let fo = FileOutput::Path(store);
        let output = get_writer_for_sym(&fo);
        dumpable.dump(output)?;

        info!("Store symbols at {}", fo);
    }

    if let Some(file) = foutput {
        let writer = get_writer_for_sym(file);
        dumpable.dump(writer)?;

        info!("Write symbols at {}", file);
    }
    Ok(())
}

#[cfg(feature = "http")]
fn get_from_id(
    config: &Config,
    path: &Path,
    filename: String,
) -> common::Result<(Vec<u8>, String)> {
    if let Some(id) = config.debug_id.or(config.code_id) {
        let symbol_server = crate::cache::get_sym_servers(config.symbol_server);
        let (buf, filename) = crate::cache::search_file(filename, id, symbol_server.as_ref());
        return if let Some(buf) = buf {
            Ok((buf, filename))
        } else {
            anyhow::bail!("Impossible to get file {} with id {}", filename, id)
        };
    }

    Ok((utils::read_file(&path), filename))
}

#[cfg(not(feature = "http"))]
fn get_from_id(
    _config: &Config,
    path: &Path,
    filename: String,
) -> common::Result<(Vec<u8>, String)> {
    Ok((utils::read_file(path), filename))
}

pub fn single_file(config: &Config, filename: &str) -> common::Result<()> {
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
    let arch = Arch::from_str(config.arch)?;

    match FileType::from_buf(&buf) {
        FileType::Elf => store(
            &config.output,
            config.check_cfi,
            ElfInfo::get_dbg(
                arch,
                &buf,
                path,
                &filename,
                file_mapping,
                config.emit_inlines,
                config.keep_mangled,
            )?,
        ),
        FileType::Pdb => store(
            &config.output,
            config.check_cfi,
            PDBInfo::get_dbg(
                arch,
                &buf,
                path,
                &filename,
                file_mapping,
                config.emit_inlines,
                config.keep_mangled,
            )?,
        ),
        FileType::Pe => {
            if let Ok(pdb_info) = PDBInfo::get_pe(config, &buf, path, &filename, file_mapping) {
                store(&config.output, config.check_cfi, pdb_info)
            } else {
                store(
                    &config.output,
                    config.check_cfi,
                    PEInfo::get_pe(config, &buf, path, &filename, None)?,
                )
            }
        }
        FileType::Macho => store(
            &config.output,
            config.check_cfi,
            MachoInfo::get_dbg(
                arch,
                &buf,
                path,
                &filename,
                file_mapping,
                config.emit_inlines,
                config.keep_mangled,
            )?,
        ),
        FileType::Unknown => anyhow::bail!("Unknown file format"),
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
    collect_inlines: bool,
    keep_mangled: bool,
}

fn send_store_jobs<T: Creator>(
    sender: &Sender<Option<JobItem<T>>>,
    results: &mut HashMap<String, T>,
    num_threads: usize,
    output: Output,
    check_cfi: bool,
    collect_inlines: bool,
    keep_mangled: bool,
) -> common::Result<()> {
    if results.len() == 1 {
        let (_, d) = results.drain().take(1).next().unwrap();
        self::store(&output, check_cfi, d)?;
    } else {
        for (_, d) in results.drain() {
            sender
                .send(Some(JobItem {
                    file: "".to_string(),
                    typ: JobType::Dump(d),
                    mapping: None,
                    collect_inlines,
                    keep_mangled,
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
    output: Output,
    check_cfi: bool,
) -> common::Result<()> {
    while let Ok(job) = receiver.recv() {
        if job.is_none() {
            return Ok(());
        }

        let JobItem {
            file,
            typ,
            mapping,
            collect_inlines,
            keep_mangled,
        } = job.unwrap();

        match typ {
            JobType::Get => {
                let path = PathBuf::from(file);
                let filename = utils::get_filename(&path);
                let buf = utils::read_file(&path);

                let info = T::get_dbg(
                    arch,
                    &buf,
                    &path,
                    &filename,
                    mapping,
                    collect_inlines,
                    keep_mangled,
                )
                .map_err(|e| {
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
                self::store(&output, check_cfi, d)?;
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
                output.clone(),
                check_cfi,
                collect_inlines,
                keep_mangled,
            )?;
        } else {
            counter.fetch_sub(1, Ordering::SeqCst);
        }
    }

    Ok(())
}

pub fn several_files<T: 'static + Creator + std::marker::Send>(
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
    let arch = Arch::from_str(config.arch)?;
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
        let output = config.output.clone();

        let check_cfi = config.check_cfi;

        let t = thread::Builder::new()
            .name(format!("dump-syms {}", i))
            .spawn(move || {
                consumer::<T>(
                    arch, sender, receiver, results, counter, num_jobs, output, check_cfi,
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
                collect_inlines: config.emit_inlines,
                keep_mangled: config.keep_mangled,
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
