//! ```text
//! vos-final-verifier-wasm-run <blob.wasm> <client|pvf> <runs> <name.proof>...
//! ```
//!
//! Each `<name>.proof` (a wrap proof, postcard) beside its `<name>.words`
//! (the 24 public words, little-endian `u32`s), as the window kernel's wrap
//! test writes them. Runs the final verifier's blob as sc-executor-wasmtime
//! runs a runtime call (`substrate/client/executor/wasmtime/src/runtime.rs`
//! at polkadot-sdk stable2603):
//! - wasmtime 35.0.0, Cranelift `SpeedAndSize`, every post-MVP extension off;
//! - `RecreateInstanceCopyOnWrite`: a fresh instance per call, from one
//!   compiled module;
//! - sp-io's host allocator: `ext_allocator_{malloc,free}_version_1` served
//!   by `sc_allocator::FreeingBumpHeapAllocator` from `__heap_base`; the
//!   input is allocated with it and passed as `(ptr, len)`;
//! - `client`: no stack metering, NaNs not canonicalized, a 1 MiB native
//!   stack, memory `Static { extra_pages: 2048 }`;
//! - `pvf`: stack-depth metering injected at a logical maximum of 65,536,
//!   NaNs canonicalized, a 256 MiB native stack, memory
//!   `Dynamic { maximum_pages: 2080 }`.
//!
//! Prints, per proof, the user-mode instructions this thread retires over
//! the verify call (the least of `<runs>`), its time, the decode's, the
//! instantiation's, the host allocations and the memory's pages; a tampered
//! copy (one byte flipped at the middle) must not be accepted.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use sc_allocator::{FreeingBumpHeapAllocator, Memory as AllocatorMemory};
use wasmtime::{
    Config, Engine, Extern, Instance, Linker, Memory, MemoryType, Module, OptLevel, Store, Val,
};

const PAGE: u64 = 65536;
const LOGICAL_STACK_MAX: u32 = 65536;
const PVF_NATIVE_STACK_MAX: usize = 256 * 1024 * 1024;
const CLIENT_NATIVE_STACK_MAX: usize = 1024 * 1024;
const PVF_MAX_PAGES: u32 = 32 + 2048;
const CLIENT_EXTRA_PAGES: u32 = 2048;

#[derive(Clone, Copy, PartialEq)]
enum Semantics {
    Client,
    Pvf,
}

struct State {
    memory: Option<Memory>,
    allocator: Option<FreeingBumpHeapAllocator>,
    allocations: u64,
}

/// The instance's memory, as the allocator sees it.
struct Access<'a, T: 'static> {
    memory: Memory,
    store: wasmtime::StoreContextMut<'a, T>,
}

impl<T> AllocatorMemory for Access<'_, T> {
    fn with_access_mut<R>(&mut self, run: impl FnOnce(&mut [u8]) -> R) -> R {
        run(self.memory.data_mut(&mut self.store))
    }
    fn with_access<R>(&self, run: impl FnOnce(&[u8]) -> R) -> R {
        run(self.memory.data(&self.store))
    }
    fn grow(&mut self, additional: u32) -> Result<(), ()> {
        self.memory
            .grow(&mut self.store, u64::from(additional))
            .map(|_| ())
            .map_err(|_| ())
    }
    fn pages(&self) -> u32 {
        (self.memory.data_size(&self.store) as u64 / PAGE) as u32
    }
    fn max_pages(&self) -> Option<u32> {
        self.memory.ty(&self.store).maximum().map(|max| max as u32)
    }
}

fn engine(semantics: Semantics) -> Result<Engine> {
    let mut config = Config::new();
    config.cranelift_opt_level(OptLevel::SpeedAndSize);
    config.cranelift_nan_canonicalization(semantics == Semantics::Pvf);
    config.max_wasm_stack(match semantics {
        Semantics::Pvf => PVF_NATIVE_STACK_MAX,
        Semantics::Client => CLIENT_NATIVE_STACK_MAX,
    });
    config.parallel_compilation(semantics == Semantics::Client);
    config.wasm_reference_types(false);
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
    config.wasm_bulk_memory(false);
    config.wasm_multi_value(false);
    config.wasm_multi_memory(false);
    config.wasm_threads(false);
    config.wasm_memory64(false);
    config.wasm_tail_call(false);
    config.wasm_extended_const(false);
    config.memory_init_cow(true);
    if semantics == Semantics::Pvf {
        config.memory_guaranteed_dense_image_size(u64::from(PVF_MAX_PAGES) * PAGE);
    } else {
        config.memory_guaranteed_dense_image_size(u64::MAX);
    }
    Engine::new(&config)
}

/// The blob as the executor prepares it: stack-depth metering for the PVF.
fn prepare(blob: &[u8], semantics: Semantics) -> Result<Vec<u8>> {
    if semantics == Semantics::Client {
        return Ok(blob.to_vec());
    }
    let module = wasm_instrument::parity_wasm::deserialize_buffer(blob)
        .map_err(|e| anyhow!("parity-wasm: {e}"))?;
    let module = wasm_instrument::inject_stack_limiter(module, LOGICAL_STACK_MAX)
        .map_err(|e| anyhow!("stack limiter: {e}"))?;
    wasm_instrument::parity_wasm::serialize(module).map_err(|e| anyhow!("serialize: {e}"))
}

fn linker(engine: &Engine) -> Result<Linker<State>> {
    let mut linker = Linker::new(engine);
    linker.func_wrap(
        "env",
        "ext_allocator_malloc_version_1",
        |mut caller: wasmtime::Caller<'_, State>, size: u32| -> Result<u32> {
            let memory = caller.data().memory.context("memory")?;
            let mut allocator = caller.data_mut().allocator.take().context("allocator")?;
            caller.data_mut().allocations += 1;
            let result = allocator.allocate(
                &mut Access {
                    memory,
                    store: caller.as_context_mut(),
                },
                size,
            );
            caller.data_mut().allocator = Some(allocator);
            Ok(u32::from(result.map_err(|e| anyhow!("malloc: {e}"))?))
        },
    )?;
    linker.func_wrap(
        "env",
        "ext_allocator_free_version_1",
        |mut caller: wasmtime::Caller<'_, State>, ptr: u32| -> Result<()> {
            let memory = caller.data().memory.context("memory")?;
            let mut allocator = caller.data_mut().allocator.take().context("allocator")?;
            let result = allocator.deallocate(
                &mut Access {
                    memory,
                    store: caller.as_context_mut(),
                },
                ptr.into(),
            );
            caller.data_mut().allocator = Some(allocator);
            result.map_err(|e| anyhow!("free: {e}"))
        },
    )?;
    Ok(linker)
}

use wasmtime::AsContextMut;

/// A fresh instance with its imported memory and allocator.
fn instantiate(
    engine: &Engine,
    module: &Module,
    linker: &Linker<State>,
    semantics: Semantics,
) -> Result<(Store<State>, Instance, Memory)> {
    let mut store = Store::new(
        engine,
        State {
            memory: None,
            allocator: None,
            allocations: 0,
        },
    );
    let declared = module
        .imports()
        .find_map(|import| import.ty().memory().cloned())
        .context("the blob imports its memory")?;
    let initial = declared.minimum() as u32;
    let ty = match semantics {
        Semantics::Pvf => MemoryType::new(initial, Some(PVF_MAX_PAGES)),
        Semantics::Client => {
            let pages = initial + CLIENT_EXTRA_PAGES;
            MemoryType::new(pages, Some(pages))
        }
    };
    let memory = Memory::new(&mut store, ty)?;
    let mut linker = linker.clone();
    linker.define(&store, "env", "memory", memory)?;
    let instance = linker.instantiate(&mut store, module)?;
    let heap_base = match instance.get_export(&mut store, "__heap_base") {
        Some(Extern::Global(global)) => match global.get(&mut store) {
            Val::I32(value) => value as u32,
            _ => bail!("__heap_base is not an i32"),
        },
        _ => bail!("no __heap_base"),
    };
    store.data_mut().memory = Some(memory);
    store.data_mut().allocator = Some(FreeingBumpHeapAllocator::new(heap_base));
    Ok((store, instance, memory))
}

/// Allocate `bytes` with the instance's allocator and write them, as the
/// executor passes call data.
fn write_input(store: &mut Store<State>, memory: Memory, bytes: &[u8]) -> Result<u32> {
    let mut allocator = store.data_mut().allocator.take().context("allocator")?;
    let ptr = allocator
        .allocate(
            &mut Access {
                memory,
                store: store.as_context_mut(),
            },
            bytes.len() as u32,
        )
        .map_err(|e| anyhow!("input: {e}"))?;
    store.data_mut().allocator = Some(allocator);
    let ptr = u32::from(ptr);
    memory.write(&mut *store, ptr as usize, bytes)?;
    Ok(ptr)
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort();
    values[values.len() / 2]
}

fn run(args: &[String]) -> Result<()> {
    let [blob, semantics, runs, proofs @ ..] = args else {
        bail!("usage: <verifier.wasm> <client|pvf> <runs> <name.proof>...");
    };
    let semantics = match semantics.as_str() {
        "client" => Semantics::Client,
        "pvf" => Semantics::Pvf,
        other => bail!("unknown semantics {other}"),
    };
    let runs: usize = runs.parse()?;
    let blob = std::fs::read(blob)?;
    let prepared = prepare(&blob, semantics)?;
    let engine = engine(semantics)?;
    let start = Instant::now();
    let module = Module::new(&engine, &prepared)?;
    println!(
        "blob {} B (prepared {} B), compiled in {:.2?}",
        blob.len(),
        prepared.len(),
        start.elapsed()
    );
    let linker = linker(&engine)?;

    for path in proofs {
        let proof = std::fs::read(path)?;
        let mut input = std::fs::read(path.replace(".proof", ".words"))?;
        input.extend_from_slice(&proof);
        let (mut instantiation, mut verify, mut decode) = (Vec::new(), Vec::new(), Vec::new());
        let mut allocations = 0;
        // User-mode instructions and cycles of this thread over the call:
        // retired instructions do not depend on the machine's load.
        let counter = |event| {
            perf_event::Builder::new(event)
                .observe_self()
                .exclude_kernel(true)
                .exclude_hv(true)
                .build()
        };
        let mut instructions = counter(perf_event::events::Hardware::INSTRUCTIONS)?;
        let mut cycles = counter(perf_event::events::Hardware::CPU_CYCLES)?;
        let (mut instr_min, mut cycles_min) = (u64::MAX, u64::MAX);
        let mut pages = 0;
        for _ in 0..runs {
            let start = Instant::now();
            let (mut store, instance, memory) = instantiate(&engine, &module, &linker, semantics)?;
            instantiation.push(start.elapsed());
            let call = instance.get_typed_func::<(u32, u32), u32>(&mut store, "verify")?;
            let ptr = write_input(&mut store, memory, &input)?;
            instructions.reset()?;
            cycles.reset()?;
            instructions.enable()?;
            cycles.enable()?;
            let start = Instant::now();
            let verdict = call.call(&mut store, (ptr, input.len() as u32))?;
            verify.push(start.elapsed());
            cycles.disable()?;
            instructions.disable()?;
            instr_min = instr_min.min(instructions.read()?);
            cycles_min = cycles_min.min(cycles.read()?);
            if verdict != 1 {
                bail!("{path}: verdict {verdict}");
            }
            allocations = store.data().allocations;
            pages = memory.data_size(&store) as u64 / PAGE;

            let (mut store, instance, memory) = instantiate(&engine, &module, &linker, semantics)?;
            let call = instance.get_typed_func::<(u32, u32), u32>(&mut store, "decode")?;
            let ptr = write_input(&mut store, memory, &input)?;
            let start = Instant::now();
            assert_eq!(call.call(&mut store, (ptr, input.len() as u32))?, 1);
            decode.push(start.elapsed());
        }
        let min = |v: &Vec<Duration>| *v.iter().min().unwrap();
        println!(
            "{path}: {} B; verify min {:.3?} median {:.3?} (decode min {:.3?}); instantiate min {:.3?}; \
             {allocations} host allocations; memory {pages} pages; \
             {instr_min} instructions, {cycles_min} cycles (min)",
            proof.len(),
            min(&verify),
            median(verify.clone()),
            min(&decode),
            min(&instantiation),
        );
        println!(
            "RESULT file={path} semantics={} bytes={} verify_us_min={} verify_us_median={} decode_us_min={} \
             instantiate_us_min={} allocations={allocations} pages={pages} \
             instructions={instr_min} cycles={cycles_min}",
            if semantics == Semantics::Pvf {
                "pvf"
            } else {
                "client"
            },
            proof.len(),
            min(&verify).as_micros(),
            median(verify).as_micros(),
            min(&decode).as_micros(),
            min(&instantiation).as_micros(),
        );
        // A tampered copy: one byte flipped at the middle of the proof.
        let mut tampered = input.clone();
        let middle = tampered.len() - proof.len() / 2;
        tampered[middle] ^= 1;
        let (mut store, instance, memory) = instantiate(&engine, &module, &linker, semantics)?;
        let call = instance.get_typed_func::<(u32, u32), u32>(&mut store, "verify")?;
        let ptr = write_input(&mut store, memory, &tampered)?;
        let verdict = call.call(&mut store, (ptr, tampered.len() as u32))?;
        if verdict == 1 {
            bail!("{path}: a tampered proof accepted");
        }
        println!("{path}: a tampered byte: verdict {verdict}");
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // The PVF's execute thread: 2 MiB plus the native stack maximum
    // (`polkadot/node/core/pvf/execute-worker/src/lib.rs:553-556`).
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024 + PVF_NATIVE_STACK_MAX)
        .spawn(move || run(&args))?
        .join()
        .map_err(|_| anyhow!("runner panicked"))?
}
