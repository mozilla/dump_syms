// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use dirs::home_dir;
use futures::{stream, Future, Stream};
use reqwest::r#async::{Client, Decoder};
use std::fs::{self, File};
use std::io::{BufWriter, Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio;
use url::Url;

use crate::common;
use crate::utils;

const DEFAULT_STORE: &str = "https://msdl.microsoft.com/download/symbols";

#[derive(Debug)]
struct SymbolServer {
    cache: Option<String>,
    server: String,
}

#[derive(Debug)]
struct Job {
    cache: Option<PathBuf>,
    url: String,
}

impl Job {
    fn new(cache: Option<PathBuf>, url: String) -> common::Result<Self> {
        if Url::parse(&url).is_err() {
            return Err(From::from(format!("Invalid url: {}", url)));
        }
        Ok(Self { cache, url })
    }
}

fn correct_path(path: &str) -> String {
    let home = match home_dir() {
        Some(h) => h,
        _ => return path.to_string(),
    };
    if path.starts_with('~') {
        format!("{}{}", home.to_str().unwrap(), &path[1..])
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
        .filter_map(|p| parse_srv(p))
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

    let servers = parse_sympath(&content);
    if servers.is_empty() {
        None
    } else {
        Some(servers)
    }
}

fn copy_in_cache(path: Option<PathBuf>, data: &[u8]) -> bool {
    if data.is_empty() || data.starts_with(b"Symbol Not Found") {
        return false;
    }

    if path.is_none() {
        return true;
    }

    let path = path.unwrap();
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

pub fn search_symbol_file(file_name: String, debug_id: &str) -> (Option<Vec<u8>>, String) {
    if file_name.is_empty() {
        return (None, file_name);
    }

    let servers = match read_config() {
        Some(s) => s,
        _ => return (None, file_name),
    };

    // Start with the caches
    for cache in servers.iter().filter_map(|x| x.cache.as_ref()) {
        let path = PathBuf::from(cache).join(debug_id).join(&file_name);
        if path.exists() {
            return (Some(utils::read_file(path)), file_name);
        }
    }

    // Try the symbol servers
    let mut jobs = Vec::new();
    for server in servers.iter() {
        let path = if let Some(cache) = server.cache.as_ref() {
            Some(PathBuf::from(cache).join(debug_id).join(&file_name))
        } else {
            None
        };
        let job = Job::new(
            path.clone(),
            format!("{}/{}/{}/{}", server.server, file_name, debug_id, file_name),
        )
        .unwrap_or_else(|e| panic!("{}", e));
        jobs.push(job);
        if file_name.ends_with(".pdb") {
            let job = Job::new(
                path,
                format!(
                    "{}/{}/{}/{}_",
                    server.server,
                    file_name,
                    debug_id,
                    &file_name[..file_name.len() - 1]
                ),
            )
            .unwrap_or_else(|e| panic!("{}", e));
            jobs.push(job);
        }
    }

    let client = Client::new();
    let n_queries = jobs.len();

    let bodies = stream::iter_ok(jobs)
        .map(move |job| {
            client
                .get(&job.url)
                .send()
                .and_then(|mut res| {
                    let body = std::mem::replace(res.body_mut(), Decoder::empty());
                    body.concat2().map_err(Into::into)
                })
                .and_then(move |body| {
                    Ok(if copy_in_cache(job.cache, &body) {
                        Some(body.to_vec())
                    } else {
                        None
                    })
                })
        })
        .buffer_unordered(n_queries);

    let results = Arc::new(Mutex::new(Vec::new()));
    let work = bodies
        .for_each({
            let results = Arc::clone(&results);
            move |b| {
                if let Some(b) = b {
                    let mut results = results.lock().unwrap();
                    results.push(b);
                }
                Ok(())
            }
        })
        .map_err(|e| panic!("Error while processing: {}", e));

    tokio::run(work);

    let mut results = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
    if results.is_empty() {
        return (None, file_name);
    }

    let buf = results.pop().unwrap();
    let path = PathBuf::from(&file_name);
    let buf = utils::read_cabinet(buf, path)
        .unwrap_or_else(|| panic!("Unable to read the file {} from the server", file_name));
    (Some(buf), file_name)
}
