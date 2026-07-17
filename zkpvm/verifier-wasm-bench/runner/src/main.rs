//! Wasmtime embedding that measures the F2 verify exports.
//!
//! Usage: vwb-runner <module.wasm> <export> [<export> ...]
//!
//! Per export: 5 iterations, each with a FRESH Store + Instance (PVF-like —
//! no warm heap reuse between calls). Reports per-iteration call wall-time,
//! median/best of 5, instantiation time (median), the return code, and the
//! linear-memory size after the call (memories never shrink, so this is the
//! peak). A 2 GiB StoreLimits cap approximates the PVF memory ceiling —
//! exceeding it fails memory.grow, which the fixture's allocator turns into
//! a trap, which we would see as an error.

use std::time::Instant;
use wasmtime::{Config, Engine, Instance, Module, OptLevel, Store, StoreLimits, StoreLimitsBuilder};

const MEM_CAP: usize = 2 * 1024 * 1024 * 1024; // 2 GiB PVF-class ceiling

struct HostState {
    limits: StoreLimits,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let wasm_path = args.next().expect("first arg: path to .wasm");
    let exports: Vec<String> = args.collect();

    // Single-threaded, default Cranelift codegen at OptLevel::Speed, no fuel,
    // no epoch interruption — plain call-time measurement.
    let mut config = Config::new();
    config.wasm_threads(false);
    config.cranelift_opt_level(OptLevel::Speed);
    let engine = Engine::new(&config)?;

    let bytes = std::fs::read(&wasm_path)?;
    let t = Instant::now();
    let module = Module::new(&engine, &bytes)?;
    println!(
        "module: {} ({} bytes) compile_ms={:.0}",
        wasm_path,
        bytes.len(),
        t.elapsed().as_secs_f64() * 1e3
    );

    for name in &exports {
        let mut call_ms = Vec::new();
        let mut inst_ms = Vec::new();
        let mut ret = None;
        let mut mem_bytes = 0usize;
        for _ in 0..5 {
            let limits = StoreLimitsBuilder::new().memory_size(MEM_CAP).build();
            let mut store = Store::new(&engine, HostState { limits });
            store.limiter(|s| &mut s.limits);

            let t = Instant::now();
            let instance = Instance::new(&mut store, &module, &[])?;
            inst_ms.push(t.elapsed().as_secs_f64() * 1e3);

            let func = instance.get_typed_func::<(), u32>(&mut store, name)?;
            let t = Instant::now();
            let r = func.call(&mut store, ())?;
            call_ms.push(t.elapsed().as_secs_f64() * 1e3);

            match ret {
                None => ret = Some(r),
                Some(prev) => assert_eq!(prev, r, "{name}: nondeterministic return"),
            }
            if let Some(mem) = instance.get_memory(&mut store, "memory") {
                mem_bytes = mem_bytes.max(mem.data_size(&store));
            }
        }
        let best = call_ms.iter().cloned().fold(f64::INFINITY, f64::min);
        println!(
            "{name}: ret={} call_ms={:?} median_ms={:.1} best_ms={:.1} inst_ms_median={:.2} mem_after_call={:.1} MiB",
            ret.unwrap(),
            call_ms.iter().map(|v| (v * 10.0).round() / 10.0).collect::<Vec<_>>(),
            median(call_ms),
            best,
            median(inst_ms),
            mem_bytes as f64 / (1024.0 * 1024.0),
        );
    }
    Ok(())
}
