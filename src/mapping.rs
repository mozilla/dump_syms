// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use hashbrown::{HashMap, HashSet};
use log::warn;
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha512};

use crate::common;
use crate::utils;

#[derive(Debug, Default, Deserialize)]
struct Mapping {
    source: String,
    destination: String,
    files: HashSet<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Mappings {
    variables: HashMap<String, String>,
    mappings: Vec<Mapping>,
}

impl Mappings {
    fn new(path: &str) -> common::Result<Self> {
        let data = utils::read(path)?;
        match serde_json::from_slice::<Self>(&data) {
            Err(e) => Err(e.into()),
            Ok(m) => Ok(m),
        }
    }
}

fn get_digest(file: &str, uppercase: bool) -> common::Result<String> {
    let data = utils::read(file)?;
    let sha = Sha512::digest(&data);
    Ok(if uppercase {
        format!("{:X}", sha)
    } else {
        format!("{:x}", sha)
    })
}

#[derive(Debug)]
pub enum ActionKind {
    Group(usize),
    MappingVar(String),
    Digest(bool),
    None,
}

#[derive(Debug)]
struct Action {
    kind: ActionKind,
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct PathMappingGenerator {
    re: Regex,
    actions: Vec<Action>,
    mapping: Vec<u8>,
    files: HashSet<String>,
}

/*
 A path mapping is composed of a regular expression with groups
 and of a string which contains groups number and special variable between curly braces.
 For example:
   /foo/bar/(.*) => https://my.source.org/{rev}/{DIGEST}/{1}/
 Here "rev" make a reference to a variable passed as argument, i.e. --mapping-vars="rev=abcde",
 DIGEST is for the SHA-512 of the file and 1 is for the the first group in the regular expression
*/
impl PathMappingGenerator {
    pub(crate) fn new(
        re: &str,
        mapping: &str,
        mapping_vars: &HashMap<String, String>,
        files: HashSet<String>,
    ) -> common::Result<Self> {
        let re = Regex::new(re)?;
        let mapping = mapping.as_bytes().to_vec();

        let mut chunk_start = 0;
        let mut chunk_end = 0;
        let mut open = false;
        let mut actions = Vec::new();

        for (i, c) in mapping.iter().enumerate() {
            if *c == b'{' {
                chunk_end = i;
                open = true;
            } else if *c == b'}' {
                if !open {
                    continue;
                }
                let action = &mapping[chunk_end + 1..i];
                let action = std::str::from_utf8(action).unwrap();
                let action = if action == "DIGEST" {
                    ActionKind::Digest(true)
                } else if action == "digest" {
                    ActionKind::Digest(false)
                } else if let Some(val) = mapping_vars.get(action) {
                    ActionKind::MappingVar(val.clone())
                } else if let Ok(group) = action.parse::<usize>() {
                    ActionKind::Group(group)
                } else {
                    return Err(format!("Invalid action {} in mapping string", action).into());
                };
                actions.push(Action {
                    kind: action,
                    start: chunk_start,
                    end: chunk_end,
                });
                open = false;
                chunk_start = i + 1;
            }
        }

        if chunk_start < mapping.len() {
            actions.push(Action {
                kind: ActionKind::None,
                start: chunk_start,
                end: mapping.len(),
            });
        }

        Ok(PathMappingGenerator {
            re,
            actions,
            mapping,
            files,
        })
    }

    pub(crate) fn apply(&self, file: &str) -> common::Result<Option<String>> {
        if self.files.is_empty() || self.files.contains(file) {
            if let Some(caps) = self.re.captures(file) {
                let mut buf = Vec::with_capacity(self.mapping.len() * 3);
                for action in self.actions.iter() {
                    buf.extend_from_slice(&self.mapping[action.start..action.end]);
                    match action.kind {
                        ActionKind::Group(group) => {
                            if let Some(group) = caps.get(group) {
                                buf.extend_from_slice(group.as_str().as_bytes());
                            } else {
                                return Ok(None);
                            }
                        }
                        ActionKind::MappingVar(ref val) => {
                            buf.extend_from_slice(val.as_bytes());
                        }
                        ActionKind::Digest(uppercase) => {
                            buf.extend_from_slice(&get_digest(file, uppercase)?.as_bytes());
                        }
                        ActionKind::None => {}
                    }
                }
                return Ok(Some(unsafe { String::from_utf8_unchecked(buf) }));
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Default)]
pub struct PathMappings {
    mappings: Vec<PathMappingGenerator>,
}

impl PathMappings {
    pub(crate) fn new(
        variables: &Option<Vec<&str>>,
        sources: &Option<Vec<&str>>,
        destinations: &Option<Vec<&str>>,
        file: &Option<&str>,
    ) -> common::Result<Option<Self>> {
        let vars = Self::get_variables(variables)?;
        let mut mappings = Vec::new();

        Self::get_mappings_from_file(&vars, file, &mut mappings)?;
        Self::get_mappings(&vars, sources, destinations, &mut mappings)?;

        Ok(if mappings.is_empty() {
            None
        } else {
            Some(PathMappings { mappings })
        })
    }

    fn get_variables(vars: &Option<Vec<&str>>) -> common::Result<HashMap<String, String>> {
        let mut variables = HashMap::default();
        if let Some(vars) = vars {
            for var in vars {
                let pair = var.splitn(2, '=').collect::<Vec<_>>();
                if pair.len() != 2 {
                    return Err(format!("Invalid pair {}: must be var=value", var).into());
                }
                variables.insert(pair[0].to_string(), pair[1].to_string());
            }
        }
        Ok(variables)
    }

    fn get_mappings(
        vars: &HashMap<String, String>,
        sources: &Option<Vec<&str>>,
        destinations: &Option<Vec<&str>>,
        out: &mut Vec<PathMappingGenerator>,
    ) -> common::Result<()> {
        if sources.is_none() && destinations.is_none() {
            return Ok(());
        }

        if sources.as_ref().map_or(0, |v| v.len()) != destinations.as_ref().map_or(0, |v| v.len()) {
            return Err(
                "mapping-src and mapping-dest must have the same number of elements".into(),
            );
        }

        let sources = sources.as_ref().unwrap();
        let destinations = destinations.as_ref().unwrap();

        for (src, dest) in sources.iter().zip(destinations.iter()) {
            out.push(PathMappingGenerator::new(
                src,
                dest,
                vars,
                HashSet::default(),
            )?);
        }

        Ok(())
    }

    fn get_mappings_from_file(
        vars: &HashMap<String, String>,
        file: &Option<&str>,
        out: &mut Vec<PathMappingGenerator>,
    ) -> common::Result<()> {
        if let Some(file) = file {
            let mut mappings = Mappings::new(file)?;
            for (k, v) in vars {
                mappings.variables.insert(k.to_string(), v.to_string());
            }

            let mut no_files = Vec::new();

            for Mapping {
                source,
                destination,
                files,
            } in mappings.mappings.drain(..)
            {
                if files.is_empty() {
                    no_files.push(PathMappingGenerator::new(
                        &source,
                        &destination,
                        &mappings.variables,
                        files,
                    )?);
                } else {
                    out.push(PathMappingGenerator::new(
                        &source,
                        &destination,
                        &mappings.variables,
                        files,
                    )?);
                }
            }

            for m in no_files.drain(..) {
                out.push(m);
            }
        }

        Ok(())
    }

    pub(crate) fn map(&self, file: &str) -> common::Result<String> {
        for mapping in self.mappings.iter() {
            let mapping = mapping.apply(&file)?;
            if let Some(mapping) = mapping {
                return Ok(mapping);
            }
        }

        warn!("Cannot find a mapping for file {}", file);

        Ok(file.to_string())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_path_mapping_generator() {
        let mut vars_map = HashMap::default();
        vars_map.insert("rev".to_string(), "abcdef".to_string());

        let p = PathMappingGenerator::new(
            r"test_data/linux/(.*)",
            "https://source/{rev}/{digest}/{1}/last",
            &vars_map,
            HashSet::default(),
        )
        .unwrap();
        let s = p.apply("test_data/linux/basic.cpp").unwrap().unwrap();

        assert_eq!(s, "https://source/abcdef/dec67d788155e1895ba4fd1a178ca595798964529aab6a17ea1ecff133499137fc67ebdcf0c768ffb4fb7ec4f1f0fcf558073ec8a3b23c1063d23d62cc76b37a/basic.cpp/last");
    }

    #[test]
    fn test_path_mapping_file() {
        let mappings = PathMappings::new(&None, &None, &None, &Some("./test_data/mapping.json"))
            .unwrap()
            .unwrap();

        let files = vec![
            ("/home/worker/a/c/ddd.cpp", "hg:hg.mozilla.org/mozilla-central:a/c/ddd.cpp:6639deb894172375b05d6791f5f8c7d53ca79723"),
            ("./test_data/mapping/bbb.cpp", "s3:gecko-generated-sources:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e/bbb.cpp"),
            ("/rustc/f3e1a954d2ead4e2fc197c7da7d71e6c61bad196/src/libcore/str/pattern.rs", "git:github.com/rust-lang/rust:src/libcore/str/pattern.rs:f3e1a954d2ead4e2fc197c7da7d71e6c61bad196"),
            ("./test_data/mapping/aaa.cpp", "s3:gecko-generated-sources:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e/aaa.cpp"),
            ("/cargo/registry/src/github.com-1ecc6299db9ec823/backtrace-0.3.40/src/print.rs", "https://doc.rs/0.3.40/backtrace/src/print.rs.html"),
            ("./test_data/mapping/ccc.cpp", "s3:gecko-generated-sources:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e/ccc.cpp"),
        ];

        for (path, expected) in files {
            assert_eq!(mappings.map(path).unwrap(), expected.to_string())
        }
    }
}
