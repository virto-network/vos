//! ```text
//! vos-pvm-final-verifier-wasm-run <blob.wasm> <client|pvf> <runs> <name.proof>...
//! ```
//!
//! Each `<name>.proof` (a wrap proof, in its format's encoding) beside its
//! `<name>.format` (the format, a little-endian `u32`) and `<name>.words`
//! (the 24 public words, little-endian `u32`s), as the wrap tests write
//! them. Runs the final verifier's blob as sc-executor-wasmtime
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
//! Compiled for an explicit target with pinned ISA flags (`RESULT`'s `isa`),
//! and held to the performance cores of a hybrid CPU.
//!
//! Prints, per proof, the user-mode instructions this thread retires over
//! the verify call (the least of `<runs>`), its time, the decode's, the
//! instantiation's, the host allocations and the memory's pages; a tampered
//! copy (one byte flipped at the middle) must not be accepted.
//!
//! ```text
//! vos-pvm-final-verifier-wasm-run <blob.wasm> <client|pvf> judge <fixtures> <formats>
//! vos-pvm-final-verifier-wasm-run <blob.wasm> <client|pvf> anchors
//! vos-pvm-final-verifier-wasm-run <blob.wasm> <client|pvf> statements <name.input>...
//! ```
//!
//! `judge`: every golden fixture under `<fixtures>` judged by the blob's
//! `judge`, failing when a verdict is not the one a build linking
//! `<formats>` reaches (comma-separated: `39` for the production blob,
//! `28,39` for the test blob; `Fixture::verdict_linking`) (`just
//! judge-wasm`). `anchors`: every golden vector of `vos-anchor` computed by
//! the blob's `anchor_digests`, failing when its digests are not the pinned
//! bytes, or when a vector cut short is not refused (`just judge-wasm`).
//! `statements`: each judgement's input beside its proof, `<name>.proof`,
//! as the end-to-end tests write them, failing when one is refused.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use perf_event::Counter;
use perf_event::events::Hardware;
use sc_allocator::{FreeingBumpHeapAllocator, Memory as AllocatorMemory};
use wasmtime::{
    AsContextMut, Config, Engine, Extern, Instance, Linker, Memory, MemoryType, Module, OptLevel,
    Store, TypedFunc, Val,
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

impl std::str::FromStr for Semantics {
    type Err = anyhow::Error;

    fn from_str(name: &str) -> Result<Self> {
        match name {
            "client" => Ok(Self::Client),
            "pvf" => Ok(Self::Pvf),
            other => bail!("unknown semantics {other}"),
        }
    }
}

impl Semantics {
    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Pvf => "pvf",
        }
    }
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

/// The ISA flags the blob is compiled with, the same on every host that has
/// them, so a count does not move with the host's CPU features: x86-64-v3,
/// the level of Polkadot's reference validator hardware.
#[cfg(target_arch = "x86_64")]
const ISA_FLAGS: [&str; 11] = [
    "has_sse3",
    "has_ssse3",
    "has_sse41",
    "has_sse42",
    "has_popcnt",
    "has_avx",
    "has_avx2",
    "has_bmi1",
    "has_bmi2",
    "has_lzcnt",
    "has_fma",
];

/// The target the blob is compiled for and its flags, as `RESULT` reports
/// them.
fn isa() -> String {
    #[cfg(target_arch = "x86_64")]
    return format!("x86_64+{}", ISA_FLAGS.join(","));
    #[cfg(not(target_arch = "x86_64"))]
    return "host".into();
}

fn engine(semantics: Semantics) -> Result<Engine> {
    let mut config = Config::new();
    // An explicit target: the host's features are not detected, only the
    // pinned flags enabled.
    #[cfg(target_arch = "x86_64")]
    {
        config.target("x86_64-unknown-linux-gnu")?;
        for flag in ISA_FLAGS {
            // SAFETY: each flag names an x86-64 extension; the engine checks
            // the host has it before running code compiled with it.
            unsafe {
                config.cranelift_flag_enable(flag);
            }
        }
    }
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A counter of this thread's user-mode `event`s.
fn counter(event: Hardware) -> std::io::Result<Counter> {
    perf_event::Builder::new(event)
        .observe_self()
        .exclude_kernel(true)
        .exclude_hv(true)
        .build()
}

/// The blob compiled under its semantics, instantiated afresh per call.
struct Runner {
    engine: Engine,
    module: Module,
    linker: Linker<State>,
    semantics: Semantics,
}

/// A fresh instance, its input written, before its call of an export.
struct Call {
    store: Store<State>,
    instance: Instance,
    memory: Memory,
    export: TypedFunc<(u32, u32), u32>,
    ptr: u32,
    len: u32,
}

impl Call {
    /// `instance`'s `export`, `input` written for it.
    fn new(
        (mut store, instance, memory): (Store<State>, Instance, Memory),
        export: &str,
        input: &[u8],
    ) -> Result<Self> {
        let export = instance.get_typed_func::<(u32, u32), u32>(&mut store, export)?;
        let ptr = write_input(&mut store, memory, input)?;
        Ok(Self {
            store,
            instance,
            memory,
            export,
            ptr,
            len: input.len() as u32,
        })
    }

    fn run(&mut self) -> Result<u32> {
        self.export.call(&mut self.store, (self.ptr, self.len))
    }

    /// The `len` bytes at the address `export` returns.
    fn output(&mut self, export: &str, len: usize) -> Result<Vec<u8>> {
        let at = self
            .instance
            .get_typed_func::<(), u32>(&mut self.store, export)?
            .call(&mut self.store, ())?;
        let mut bytes = vec![0u8; len];
        self.memory.read(&self.store, at as usize, &mut bytes)?;
        Ok(bytes)
    }
}

impl Runner {
    /// The blob at `path`, prepared and compiled under `semantics`.
    fn new(path: &str, semantics: Semantics) -> Result<Self> {
        let blob = std::fs::read(path)?;
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
        Ok(Self {
            engine,
            module,
            linker,
            semantics,
        })
    }

    fn instantiate(&self) -> Result<(Store<State>, Instance, Memory)> {
        instantiate(&self.engine, &self.module, &self.linker, self.semantics)
    }

    /// A fresh instance's `export`, `input` written for it.
    fn call(&self, export: &str, input: &[u8]) -> Result<Call> {
        Call::new(self.instantiate()?, export, input)
    }

    /// A judgement's code, its instructions where the kernel lets this
    /// thread count its own (`perf_event_paranoid` at most 2), and the
    /// statement id it accepted.
    fn judged(&self, name: &str, input: &[u8]) -> Result<(u32, Option<u64>, String)> {
        let mut call = self.call("judge", input)?;
        let mut instructions = counter(Hardware::INSTRUCTIONS).ok();
        if let Some(counter) = &mut instructions {
            counter.enable()?;
        }
        let code = call.run().with_context(|| format!("{name}: the call"))?;
        let instructions = match &mut instructions {
            Some(counter) => {
                counter.disable()?;
                Some(counter.read()?)
            }
            None => None,
        };
        let mut id = String::new();
        if code == 0 {
            id = hex(&call.output("statement_id", 32)?);
        }
        Ok((code, instructions, id))
    }

    /// Every golden fixture under `directory` judged, each verdict the one
    /// a build linking `formats` reaches.
    fn judge(&self, directory: &str, formats: &str) -> Result<()> {
        let linked = formats
            .split(',')
            .map(str::parse)
            .collect::<Result<Vec<u32>, _>>()
            .context("the formats, comma-separated")?;
        let fixtures = vos_statement::fixtures::load(std::path::Path::new(directory));
        let mut differ = 0;
        for fixture in &fixtures {
            let expected = fixture.verdict_linking(&linked);
            let (code, instructions, id) = self.judged(&fixture.name, &fixture.bytes())?;
            println!(
                "JUDGE fixture={:?} expected={expected:#x} code={code:#x} instructions={} id={id}",
                fixture.name,
                count(instructions),
            );
            differ += usize::from(code != expected);
        }
        if differ > 0 {
            bail!("{differ} of {} fixtures judged otherwise", fixtures.len());
        }
        println!(
            "{} fixtures judged as recorded, linking {linked:?}",
            fixtures.len()
        );
        Ok(())
    }

    /// `input`'s anchor digests, `None` when the blob refuses it.
    fn digests(&self, input: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut call = self.call("anchor_digests", input)?;
        if call.run()? != 1 {
            return Ok(None);
        }
        Ok(Some(call.output(
            "digests",
            vos_statement::vos_anchor::vectors::Digests::BYTES,
        )?))
    }

    /// Every golden anchor vector's digests the pinned ones, and the vector
    /// cut short refused.
    fn anchors(&self) -> Result<()> {
        let vectors = vos_statement::vos_anchor::vectors::golden();
        for golden in &vectors {
            let encoded = golden.vector.encode();
            let digests = self
                .digests(&encoded)?
                .with_context(|| format!("{}: the vector refused", golden.name))?;
            println!("ANCHORS vector={:?} digests={}", golden.name, hex(&digests));
            if hex(&digests) != golden.digests {
                bail!(
                    "{}: digests {} not the pinned {}",
                    golden.name,
                    hex(&digests),
                    golden.digests
                );
            }
            if self.digests(&encoded[..encoded.len() - 1])?.is_some() {
                bail!("{}: a vector cut short decoded", golden.name);
            }
        }
        println!("{} vectors computed as pinned", vectors.len());
        Ok(())
    }

    /// Each judgement's input at `paths`, beside its proof, accepted.
    fn statements(&self, paths: &[String]) -> Result<()> {
        for path in paths {
            let input = std::fs::read(path)?;
            let proof = std::fs::read(path.replace(".input", ".proof"))?;
            let (code, instructions, id) = self.judged(path, &[input, proof].concat())?;
            println!(
                "STATEMENT file={path} code={code:#x} instructions={} id={id}",
                count(instructions)
            );
            if code != 0 {
                bail!("{path}: refused, {code:#x}");
            }
        }
        Ok(())
    }

    /// Each proof at `paths` verified `runs` times, measured, and a tampered
    /// copy refused.
    fn bench(&self, runs: usize, paths: &[String]) -> Result<()> {
        for path in paths {
            let proof = std::fs::read(path)?;
            let mut input = std::fs::read(path.replace(".proof", ".format"))?;
            input.extend(std::fs::read(path.replace(".proof", ".words"))?);
            input.extend_from_slice(&proof);
            let (mut instantiation, mut verify, mut decode) = (Vec::new(), Vec::new(), Vec::new());
            let mut allocations = 0;
            // User-mode instructions and cycles of this thread over the call:
            // retired instructions do not depend on the machine's load.
            let mut instructions = counter(Hardware::INSTRUCTIONS)?;
            let mut cycles = counter(Hardware::CPU_CYCLES)?;
            let (mut instr_min, mut cycles_min) = (u64::MAX, u64::MAX);
            let mut pages = 0;
            for _ in 0..runs {
                let start = Instant::now();
                let instance = self.instantiate()?;
                instantiation.push(start.elapsed());
                let mut call = Call::new(instance, "verify", &input)?;
                instructions.reset()?;
                cycles.reset()?;
                instructions.enable()?;
                cycles.enable()?;
                let start = Instant::now();
                let verdict = call.run()?;
                verify.push(start.elapsed());
                cycles.disable()?;
                instructions.disable()?;
                instr_min = instr_min.min(instructions.read()?);
                cycles_min = cycles_min.min(cycles.read()?);
                if verdict != 1 {
                    bail!("{path}: verdict {verdict}");
                }
                allocations = call.store.data().allocations;
                pages = call.memory.data_size(&call.store) as u64 / PAGE;

                let mut call = self.call("decode", &input)?;
                let start = Instant::now();
                assert_eq!(call.run()?, 1);
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
                "RESULT file={path} semantics={} isa={} bytes={} verify_us_min={} verify_us_median={} \
                 decode_us_min={} instantiate_us_min={} allocations={allocations} pages={pages} \
                 instructions={instr_min} cycles={cycles_min}",
                self.semantics.as_str(),
                isa(),
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
            let verdict = self.call("verify", &tampered)?.run()?;
            if verdict == 1 {
                bail!("{path}: a tampered proof accepted");
            }
            println!("{path}: a tampered byte: verdict {verdict}");
        }
        Ok(())
    }
}

fn count(instructions: Option<u64>) -> String {
    instructions.map_or("-".into(), |n| n.to_string())
}

fn run(args: &[String]) -> Result<()> {
    let [blob, semantics, mode, files @ ..] = args else {
        bail!("usage: <verifier.wasm> <client|pvf> <runs|judge|anchors|statements> <file>...");
    };
    let runner = Runner::new(blob, semantics.parse()?)?;
    match mode.as_str() {
        "judge" => {
            let [directory, formats] = files else {
                bail!("judge: one fixtures directory, then the formats the blob links");
            };
            runner.judge(directory, formats)
        }
        "anchors" => {
            if !files.is_empty() {
                bail!("anchors: no files");
            }
            runner.anchors()
        }
        "statements" => runner.statements(files),
        runs => runner.bench(runs.parse()?, files),
    }
}

/// The CPUs of the list `list` (`0-11`, `0,2,4-7`).
fn cpus(list: &str) -> Vec<usize> {
    list.trim()
        .split(',')
        .filter(|range| !range.is_empty())
        .flat_map(|range| match range.split_once('-') {
            Some((from, to)) => {
                let (from, to) = (from.parse().unwrap_or(0), to.parse().unwrap_or(0));
                (from..=to).collect::<Vec<usize>>()
            }
            None => range.parse().into_iter().collect(),
        })
        .collect()
}

/// Holds this thread, and the threads it spawns, to the performance cores
/// it may run on: on a hybrid CPU each core kind counts instructions with
/// its own PMU, and a thread moved to another kind counts nothing there.
/// Nothing on a CPU of one kind.
fn pin_to_performance_cores() -> Result<()> {
    let Ok(list) = std::fs::read_to_string("/sys/devices/cpu_core/cpus") else {
        return Ok(());
    };
    // SAFETY: a zeroed `cpu_set_t` is empty; the calls read and write it.
    unsafe {
        let mut allowed: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut allowed) != 0 {
            bail!("sched_getaffinity: {}", std::io::Error::last_os_error());
        }
        let mut pinned: libc::cpu_set_t = std::mem::zeroed();
        let mut chosen = Vec::new();
        for cpu in cpus(&list) {
            if cpu < libc::CPU_SETSIZE as usize && libc::CPU_ISSET(cpu, &allowed) {
                libc::CPU_SET(cpu, &mut pinned);
                chosen.push(cpu);
            }
        }
        if chosen.is_empty() {
            bail!("no performance core among the allowed CPUs");
        }
        if libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &pinned) != 0 {
            bail!("sched_setaffinity: {}", std::io::Error::last_os_error());
        }
        println!("pinned to the performance cores {chosen:?}");
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    pin_to_performance_cores()?;
    // The PVF's execute thread: 2 MiB plus the native stack maximum
    // (`polkadot/node/core/pvf/execute-worker/src/lib.rs:553-556`).
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024 + PVF_NATIVE_STACK_MAX)
        .spawn(move || run(&args))?
        .join()
        .map_err(|_| anyhow!("runner panicked"))?
}
