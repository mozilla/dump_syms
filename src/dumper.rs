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
use symbolic::debuginfo::pdb::PdbObject;
use symbolic::debuginfo::pe::PeObject;
use symbolic::debuginfo::{peek, FileFormat};

use crate::common;
use crate::mapping::PathMappings;
use crate::object_info::ObjectInfo;
use crate::platform::Platform;
use crate::utils;
use crate::windows;

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
    pub num_jobs: usize,
    pub check_cfi: bool,
    pub emit_inlines: bool,
    pub mapping_var: Option<Vec<&'a str>>,
    pub mapping_src: Option<Vec<&'a str>>,
    pub mapping_dest: Option<Vec<&'a str>>,
    pub mapping_file: Option<&'a str>,
}

impl Config<'_> {
    /// Create a [`Config`] using the given [`Output`], with all other
    /// fields set to reasonable defaults.
    ///
    /// The architecture will be set to the architecture for which
    /// compilation is happening, the number of jobs will be set to one.
    pub fn with_output(output: Output) -> Self {
        Self {
            output,
            symbol_server: None,
            debug_id: None,
            code_id: None,
            arch: common::get_compile_time_arch(),
            num_jobs: 1,
            check_cfi: true,
            emit_inlines: true,
            mapping_var: None,
            mapping_src: None,
            mapping_dest: None,
            mapping_file: None,
        }
    }
}

fn get_pdb_object_info(
    buf: &[u8],
    path: &Path,
    filename: &str,
    mapping: Option<Arc<PathMappings>>,
    collect_inlines: bool,
) -> common::Result<ObjectInfo> {
    let pdb = PdbObject::parse(buf)?;

    let (pe_name, pe_buf) = match windows::utils::find_pe_for_pdb(path, &pdb.debug_id()) {
        Some((pe_name, pe_buf)) => (Some(pe_name), Some(pe_buf)),
        None => (None, None),
    };
    let pe = pe_buf.as_deref().map(|buf| PeObject::parse(buf).unwrap());

    ObjectInfo::from_pdb(
        pdb,
        filename,
        pe_name.as_deref(),
        pe,
        mapping,
        collect_inlines,
    )
}

#[cfg(feature = "http")]
fn get_pe_pdb_object_info(
    buf: &[u8],
    path: &Path,
    filename: &str,
    mapping: Option<Arc<PathMappings>>,
    symbol_server: Option<&str>,
    emit_inlines: bool,
) -> common::Result<ObjectInfo> {
    let symbol_server = crate::cache::get_sym_servers(symbol_server);
    let res = windows::utils::get_pe_pdb_buf(path, buf, symbol_server.as_ref());

    if let Some((pe, pdb_buf, pdb_name)) = res {
        let pdb = PdbObject::parse(&pdb_buf)?;
        let pdb = ObjectInfo::from_pdb(
            pdb,
            &pdb_name,
            Some(filename),
            Some(pe),
            mapping,
            emit_inlines,
        )?;
        Ok(pdb)
    } else {
        anyhow::bail!("No pdb file found")
    }
}

#[cfg(not(feature = "http"))]
fn get_pe_pdb_object_info<'a>(
    buf: &[u8],
    path: &Path,
    filename: &str,
    mapping: Option<Arc<PathMappings>>,
    symbol_server: Option<&str>,
    emit_inlines: bool,
) -> common::Result<ObjectInfo> {
    anyhow::bail!("HTTP symbol retrieval not enabled")
}

fn get_pe_object_info(buf: &[u8], path: &Path, filename: &str) -> common::Result<ObjectInfo> {
    let pe = PeObject::parse(buf)
        .unwrap_or_else(|_| panic!("Unable to parse the PE file {}", path.to_str().unwrap()));
    let pe = ObjectInfo::from_pe(filename, pe)?;
    Ok(pe)
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

fn store(output: &Output, check_cfi: bool, object_info: ObjectInfo) -> common::Result<()> {
    anyhow::ensure!(!check_cfi || object_info.has_stack(), "No CFI data");

    let sym_store_path = |dir: &Path| -> Option<PathBuf> {
        if dir.to_str()?.is_empty() {
            return None;
        }

        let mut pb = PathBuf::new();
        pb.push(dir);
        pb.push(utils::get_path_for_sym(
            object_info.get_name(),
            object_info.get_debug_id(),
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
        object_info.dump(output)?;

        info!("Store symbols at {}", fo);
    }

    if let Some(file) = foutput {
        let writer = get_writer_for_sym(file);
        object_info.dump(writer)?;

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

    Ok((utils::read_file(path), filename))
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

    let path_mappings = PathMappings::new(
        &config.mapping_var,
        &config.mapping_src,
        &config.mapping_dest,
        &config.mapping_file,
    )?
    .map(Arc::new);
    let arch = Arch::from_str(config.arch)?;
    let object_info = get_object_info(
        buf,
        path,
        &filename,
        path_mappings,
        arch,
        config.symbol_server,
        config.emit_inlines,
    )?;
    store(&config.output, config.check_cfi, object_info)
}

/// Detects the object format based on the bytes in the file.
fn get_object_info(
    buf: Vec<u8>,
    path: &Path,
    filename: &str,
    file_mapping: Option<Arc<PathMappings>>,
    arch: Arch,
    symbol_server: Option<&str>,
    emit_inlines: bool,
) -> common::Result<ObjectInfo> {
    let object_info = match peek(&buf, true /* check for fat binary */) {
        FileFormat::Elf => {
            ObjectInfo::from_elf(&buf, filename, Platform::Linux, file_mapping, emit_inlines)?
        }
        FileFormat::Pdb => get_pdb_object_info(&buf, path, filename, file_mapping, emit_inlines)?,
        FileFormat::Pe => {
            if let Ok(pdb_info) = get_pe_pdb_object_info(
                &buf,
                path,
                filename,
                file_mapping,
                symbol_server,
                emit_inlines,
            ) {
                pdb_info
            } else {
                get_pe_object_info(&buf, path, filename)?
            }
        }
        FileFormat::MachO => {
            ObjectInfo::from_macho(&buf, filename, arch, file_mapping, emit_inlines)?
        }
        _ => anyhow::bail!("Unknown file format"),
    };
    Ok(object_info)
}

#[allow(clippy::large_enum_variant)]
enum JobType {
    Get,
    Dump(ObjectInfo),
}

struct JobItem {
    file: String,
    typ: JobType,
    mapping: Option<Arc<PathMappings>>,
    collect_inlines: bool,
}

fn send_store_jobs(
    sender: &Sender<Option<JobItem>>,
    results: &mut HashMap<String, ObjectInfo>,
    num_threads: usize,
    output: Output,
    check_cfi: bool,
    collect_inlines: bool,
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
                }))
                .unwrap();
        }
    }

    poison_queue(sender, num_threads);
    Ok(())
}

fn poison_queue(sender: &Sender<Option<JobItem>>, num_threads: usize) {
    // Poison the receiver.
    for _ in 0..num_threads {
        sender.send(None).unwrap();
    }
}

#[allow(clippy::too_many_arguments)]
fn consumer(
    arch: Arch,
    sender: Sender<Option<JobItem>>,
    receiver: Receiver<Option<JobItem>>,
    results: Arc<Mutex<HashMap<String, ObjectInfo>>>,
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
        } = job.unwrap();

        match typ {
            JobType::Get => {
                let path = PathBuf::from(file);
                let filename = utils::get_filename(&path);
                let buf = utils::read_file(&path);

                let info =
                    get_object_info(buf, &path, &filename, mapping, arch, None, collect_inlines)?;

                let mut results = results.lock().unwrap();
                let info = if let Some(prev) = results.remove(info.get_debug_id()) {
                    ObjectInfo::merge(info, prev).map_err(|e| {
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
            )?;
        } else {
            counter.fetch_sub(1, Ordering::SeqCst);
        }
    }

    Ok(())
}

pub fn several_files(config: &Config, filenames: &[&str]) -> common::Result<()> {
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
            .name(format!("dump-syms {i}"))
            .spawn(move || {
                consumer(
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
