//! `vosx run <program>` — single-actor PVM executor with no
//! networking, no manifest, no replication. The simplest entry
//! point: load an ELF, queue some FETCH payloads, run until
//! drained.

use std::path::{Path, PathBuf};

use vos::runtime::{GasConfig, VosRuntime};

use crate::util::{die, exit_with_status, hex_decode, load_blob, load_file, read_stdin};

pub fn run(program: &Path, payloads: &[PathBuf], hex: &[String], gas: u64) {
    let blob = load_blob(program);
    let mut rt = VosRuntime::with_gas_config(GasConfig {
        refine_gas: gas,
        accumulate_gas_max: gas,
        accumulate_gas_default: gas,
    });

    let idx = rt.register_service_blob(blob);
    let id = rt.register_service(idx);
    eprintln!("vosx: loaded '{}' as {id:?}", program.display());

    let mut items: Vec<Vec<u8>> = Vec::new();
    for p in payloads {
        items.push(if p.as_os_str() == "-" { read_stdin() } else { load_file(p) });
    }
    for h in hex {
        items.push(hex_decode(h).unwrap_or_else(|| die(&format!("invalid hex '{h}'"))));
    }
    if items.is_empty() {
        items.push(Vec::new());
    }
    for item in items {
        rt.send_to(id, item);
    }

    eprintln!("vosx: running...\n");
    rt.run_blocking();
    exit_with_status(rt.panics);
}
