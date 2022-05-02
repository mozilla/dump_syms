// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use dirs::home_dir;
use futures::{stream, StreamExt};
use reqwest::{self, blocking, header::USER_AGENT, Client};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use url::Url;

use crate::common;
use crate::utils;

const DEFAULT_STORE: &str = "https://msdl.microsoft.com/download/symbols";
const DEFAULT_USER_AGENT: &str = "Microsoft-Symbol-Server/6.3.0.0";

#[derive(Debug)]
pub struct SymbolServer {
    cache: Option<String>,
    server: String,
}

#[derive(Clone, Debug)]
struct Job {
    cache: Option<PathBuf>,
    url: String,
}

impl Job {
    fn new(cache: Option<PathBuf>, url: String) -> common::Result<Self> {
        anyhow::ensure!(Url::parse(&url).is_ok(), "Invalid url: {}", url);
        Ok(Self { cache, url })
    }
}

fn correct_path(path: &str) -> String {
    let home = match home_dir() {
        Some(h) => h,
        _ => return path.to_string(),
    };
    if let Some(stripped_pah) = path.strip_prefix('~') {
        format!("{}{}", home.to_str().unwrap(), stripped_pah)
    } else {
        path.to_string()
    }
}

fn parse_srv(path: &str) -> Option<SymbolServer> {
    // srv*symbolstore, or srv*localsymbolcache*symbolstore
    let parts: Vec<_> = path.split('*').map(|p| p.trim()).collect();
    if parts.is_empty() || parts[0].to_lowercase() != "srv" {
        return None;
    }
    let server = match parts.len() {
        1 => SymbolServer {
            cache: None,
            server: DEFAULT_STORE.to_string(),
        },
        2 => SymbolServer {
            cache: None,
            server: parts[1].to_string(),
        },
        3 => SymbolServer {
            cache: Some(correct_path(parts[1])),
            server: parts[2].to_string(),
        },
        _ => return None,
    };

    Some(server)
}

fn parse_sympath(path: &str) -> Vec<SymbolServer> {
    path.split(|c| c == ';' || c == '\n')
        .filter_map(parse_srv)
        .collect()
}

fn read_config() -> Option<Vec<SymbolServer>> {
    let home = match home_dir() {
        Some(h) => h,
        _ => return None,
    };

    let conf = home.join(".dump_syms").join("config");
    if !conf.exists() {
        return None;
    }

    let mut file = File::open(&conf)
        .unwrap_or_else(|_| panic!("Unable to open the file {}", conf.to_str().unwrap()));
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .unwrap_or_else(|_| panic!("Unable to read the file {}", conf.to_str().unwrap()));

    let content = String::from_utf8(buf)
        .unwrap_or_else(|_| panic!("Not utf-8 data in the file {}", conf.to_str().unwrap()));

    read_config_from_str(&content)
}

fn read_config_from_str(s: &str) -> Option<Vec<SymbolServer>> {
    let servers = parse_sympath(s);
    if servers.is_empty() {
        None
    } else {
        Some(servers)
    }
}

pub fn get_sym_servers(symbol_server: Option<&str>) -> Option<Vec<SymbolServer>> {
    symbol_server.map_or_else(read_config, read_config_from_str)
}

fn copy_in_cache(path: Option<PathBuf>, data: &[u8]) -> bool {
    if data.is_empty() || data.starts_with(b"Symbol Not Found") {
        return false;
    }

    let path = match path {
        Some(p) => p,
        _ => return true,
    };

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).unwrap_or_else(|_| {
                panic!(
                    "Unable to create cache directory {}",
                    parent.to_str().unwrap()
                )
            });
        }
    }

    let output = File::create(&path)
        .unwrap_or_else(|_| panic!("Cannot open file {} for writing", path.to_str().unwrap()));
    let mut output = BufWriter::new(output);
    output
        .write_all(data)
        .unwrap_or_else(|_| panic!("Cannot write file {}", path.to_str().unwrap()));

    true
}

fn get_base(file_name: &str) -> PathBuf {
    // The file is stored at cache/xul.pdb/DEBUG_ID/xul.pd_
    // the xul.pdb represents the base
    let path = PathBuf::from(file_name);
    if let Some(e) = path.extension() {
        let e = e.to_str().unwrap().to_lowercase();
        match e.as_str() {
            "pd_" => path.with_extension("pdb"),
            "ex_" => path.with_extension("exe"),
            "dl_" => path.with_extension("dll"),
            _ => path.clone(),
        }
    } else {
        path.clone()
    }
}

pub fn get_path_for_sym(file_name: &str, id: &str) -> PathBuf {
    let base = get_base(file_name);
    let file_name = PathBuf::from(file_name);
    let file_name = file_name.with_extension("sym");
    base.join(id).join(file_name)
}

fn search_in_cache(
    servers: &[SymbolServer],
    id: &str,
    base: &Path,
    file_name: &str,
) -> Option<PathBuf> {
    for cache in servers.iter().filter_map(|x| x.cache.as_ref()) {
        let path = PathBuf::from(cache).join(base).join(id).join(&file_name);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn get_jobs(servers: &[SymbolServer], id: &str, base: &Path, file_name: &str) -> Vec<Job> {
    // The query urls are: https://symbols.mozilla.org/xul.pdb/DEBUG_ID/xul.pd_
    let mut jobs = Vec::new();
    for server in servers.iter() {
        let path = server
            .cache
            .as_ref()
            .map(|cache| PathBuf::from(cache).join(base).join(id).join(&file_name));
        let job = Job::new(
            path.clone(),
            format!("{}/{}/{}/{}", server.server, file_name, id, file_name),
        )
        .unwrap_or_else(|e| panic!("{}", e));
        jobs.push(job);
        if !file_name.ends_with('_') {
            let job = Job::new(
                path,
                format!(
                    "{}/{}/{}/{}_",
                    server.server,
                    file_name,
                    id,
                    &file_name[..file_name.len() - 1]
                ),
            )
            .unwrap_or_else(|e| panic!("{}", e));
            jobs.push(job);
        }
    }

    jobs
}

async fn check_if_file_exists(results: Arc<Mutex<Vec<Job>>>, client: &Client, job: Job) {
    if let Ok(res) = client
        .head(&job.url)
        .header(USER_AGENT, DEFAULT_USER_AGENT)
        .send()
        .await
    {
        if res.status() == 200 {
            let mut results = results.lock().unwrap();
            results.push(job);
        }
    }
}

fn check_data(jobs: Vec<Job>) -> Option<Job> {
    let client = Client::new();
    let n_queries = jobs.len();
    let results = Arc::new(Mutex::new(Vec::new()));

    Runtime::new().unwrap().block_on(async {
        stream::iter(jobs)
            .map({
                let results = &results;
                let client = &client;
                move |job| check_if_file_exists(Arc::clone(results), client, job)
            })
            .buffer_unordered(n_queries)
            .collect::<Vec<()>>()
            .await
    });

    let results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
    results.first().cloned()
}

fn fetch_data(jobs: Vec<Job>) -> Option<Vec<u8>> {
    if let Some(job) = check_data(jobs) {
        let mut buf = Vec::new();
        let client = blocking::Client::new();
        let resp = client
            .get(&job.url)
            .header(USER_AGENT, DEFAULT_USER_AGENT)
            .send();
        if let Ok(mut resp) = resp {
            if resp.copy_to(&mut buf).is_err() {
                None
            } else if copy_in_cache(job.cache, &buf) {
                Some(buf)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

pub fn search_file(
    file_name: String,
    id: &str,
    sym_servers: Option<&Vec<SymbolServer>>,
) -> (Option<Vec<u8>>, String) {
    if file_name.is_empty() {
        return (None, file_name);
    }

    let servers = match sym_servers {
        Some(s) => s,
        _ => return (None, file_name),
    };

    let base = get_base(&file_name);

    // Start with the caches
    if let Some(path) = search_in_cache(servers, id, &base, &file_name) {
        return (Some(utils::read_file(path)), file_name);
    }

    // Try the symbol servers
    // Each job contains the path where to cache data (if one) and a query url
    let jobs = get_jobs(servers, id, &base, &file_name);
    let buf = fetch_data(jobs);

    if let Some(buf) = buf {
        let path = PathBuf::from(&file_name);
        let buf = utils::read_cabinet(buf, path)
            .unwrap_or_else(|| panic!("Unable to read the file {} from the server", file_name));
        (Some(buf), file_name)
    } else {
        (None, file_name)
    }
}
