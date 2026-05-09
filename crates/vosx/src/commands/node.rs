//! `vosx node <programs...>` — multi-actor concurrent run
//! without a manifest. Useful as a quick smoke test of N PVM
//! agents + M worker plugins talking through invoke channels.

use std::path::{Path, PathBuf};

use vos::node::{AgentConfig, Consistency, VosNode, WorkerConfig};
use vos::value::{Args, Value};

use crate::util::{die, exit_with_status, load_blob};

pub fn run(
    programs: &[PathBuf],
    registry: Option<&Path>,
    workers: &[String],
    data_dir: Option<&Path>,
    consistency: Consistency,
) {
    let mut node = VosNode::new();

    // Workers first so PVM agents can invoke them.
    for spec in workers {
        let (path_str, args_str) = match spec.split_once(':') {
            Some((p, a)) => (p, Some(a)),
            None => (spec.as_str(), None),
        };
        let path = PathBuf::from(path_str);
        let mut config = match args_str {
            Some(s) if !s.is_empty() => {
                let mut args = Args::new();
                for kv in s.split(',') {
                    let Some((k, v)) = kv.split_once('=') else {
                        die(&format!("invalid worker arg '{kv}', expected KEY=VALUE"));
                    };
                    args = args.with(k, parse_cli_value(v));
                }
                WorkerConfig::with_args(path.clone(), &args)
            }
            _ => WorkerConfig::new(path.clone()),
        };
        if let Some(dir) = data_dir {
            config = config.persist(dir);
        }
        let id = node.register_worker(config);
        eprintln!("vosx: worker '{}' as {id:?}", path.display());
    }

    // Build an AgentConfig with shared consistency + data_dir.
    let mk_agent = |blob: Vec<u8>| -> AgentConfig {
        let mut c = AgentConfig::new(blob).with_consistency(consistency);
        if let Some(dir) = data_dir {
            c = c.persist(dir);
        }
        c
    };

    if let Some(reg_path) = registry {
        let id = node.register(mk_agent(load_blob(reg_path)));
        eprintln!("vosx: registry '{}' as {id}", reg_path.display());
    }
    for path in programs {
        let id = node.register(mk_agent(load_blob(path)));
        eprintln!("vosx: registered '{}' as {id:?}", path.display());
    }

    let total = programs.len() + workers.len();
    eprintln!(
        "vosx: running {total} service(s) ({} PVM + {} worker)...\n",
        programs.len(),
        workers.len(),
    );
    node.run();

    let results = node.collect();
    let panics: u32 = results.iter().map(|r| r.panics).sum();
    let mut host_errors = 0usize;
    for r in &results {
        if let Some(err) = &r.error {
            tracing::error!(id = %r.id, "{err}");
            host_errors += 1;
        }
    }
    if host_errors > 0 {
        std::process::exit(2);
    }
    exit_with_status(panics);
}

/// Parse a worker-init CLI value. Auto-types: integers → U64,
/// `true`/`false` → Bool, anything else → Str. The manifest
/// path uses `manifest::toml_to_value` which is richer; this
/// is just for the `--worker libfoo.so:k=v` shorthand.
fn parse_cli_value(s: &str) -> Value {
    if let Ok(b) = s.parse::<bool>() {
        return Value::Bool(b);
    }
    if let Ok(n) = s.parse::<i64>() {
        return if n >= 0 {
            Value::U64(n as u64)
        } else {
            Value::I64(n)
        };
    }
    Value::Str(s.into())
}
