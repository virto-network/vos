//! `vosx run <program>` — single-actor PVM executor with no
//! networking, no manifest, no replication. The simplest entry
//! point: load an ELF, queue some FETCH payloads, run until
//! drained.

use std::io::Read;
use std::path::{Path, PathBuf};

use vos::runtime::{GasConfig, VosRuntime};

pub fn run(program: &Path, payloads: &[PathBuf], hex: &[String], gas: u64) {
    let blob = load_blob(program);
    let mut rt = VosRuntime::with_gas_config(GasConfig {
        refine_gas: gas,
        accumulate_gas_max: gas,
        accumulate_gas_default: gas,
    });

    let idx = rt.register_service_blob(blob);
    let id = rt.register_service(idx);
    tracing::info!("loaded '{}' as {id:?}", program.display());

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

    tracing::info!("running");
    rt.run_blocking();
    exit_with_status(rt.panics);
}

/// Print an error to stderr and exit with status 1. The
/// `space *` commands return `anyhow::Result` and let the
/// dispatcher print, so this lives only with the legacy
/// non-space `vosx run` path.
fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

/// Read a file or `die`.
fn load_file(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| die(&format!("reading {}: {e}", path.display())))
}

/// Load a PVM blob from disk. `.pvm` files are passed through
/// untouched; anything else is treated as an ELF and run
/// through the JAM transpiler. `die` on any failure.
fn load_blob(path: &Path) -> Vec<u8> {
    let data = load_file(path);
    match path.extension().and_then(|e| e.to_str()) {
        Some("pvm") => data,
        _ => grey_transpiler::link_elf(&data)
            .unwrap_or_else(|e| die(&format!("transpiling '{}': {e:?}", path.display()))),
    }
}

/// Read every byte from stdin. Used by `vosx run --payload -`.
fn read_stdin() -> Vec<u8> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| die(&format!("stdin: {e}")));
    buf
}

/// Decode a `0xHEX` or bare-hex string into bytes, or `None`
/// if any character isn't a hex digit / the length is odd.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim_start_matches("0x");
    hex.len()
        .is_multiple_of(2)
        .then(|| {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                .collect::<Option<Vec<_>>>()
        })
        .flatten()
}

/// `panics > 0` exits with status 1 so CI catches actor panics;
/// otherwise a `done` line + status 0.
fn exit_with_status(panics: u32) {
    if panics > 0 {
        eprintln!("\nvosx: {panics} panic(s)");
        std::process::exit(1);
    }
    eprintln!("\nvosx: done");
}
