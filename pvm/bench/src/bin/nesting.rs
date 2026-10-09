//! Invocation overhead (spike S2): the ledger actor hosted by the agent program as a
//! JAM inner machine (nested path) versus driven by the node directly
//! (fast path), on the interpreter and the JIT, with a machine built per
//! request (fresh), lent from the machine pool per request (pooled), or
//! reused across a batch (warm).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use vos_pvm::inner::{InnerExit, InnerMachines, InvokeState, PageMode};
use vos_pvm::pool::{MachinePool, PoolProgram};
use vos_pvm::refine::{Invocation, Machine, MemoryModel, PreparedProgram};
use vos_pvm::refine_host::RefineContext;
use vos_pvm::{ExitReason, PvmBackend};
use vos_pvm_bench::{LoadedActor, Spi, le, load_actor, parse_standard_program};

const INPUT_NEXT: u64 = 0x100;
const STATE_GET: u64 = 0x101;
const STATE_PUT: u64 = 0x102;
const PROGRAM: u64 = 0x103;
const ACTOR_GET: u64 = 0x200;
const ACTOR_PUT: u64 = 0x201;
const ACTOR_YIELD: u64 = 0x2ff;
const INSTANTIATE: u64 = 0x480;

const HALT: u64 = (1 << 32) - (1 << 16);
const AGENT_GAS: u64 = 1 << 50;
const ACTOR_GAS: u64 = 1_000_000_000;
const ACCOUNTS: u64 = 10_000;
const REPEATS: usize = 7;

type Request = [u8; 32];

static ROUND: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PHASES_PRINTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
type State = HashMap<u64, u64>;

/// Restore a used machine's writable memory to the program image (zeros
/// here, as the actor has no initialized data), as a pool would without
/// dirty-page tracking.
fn native_reset(inner: &mut InnerMachines, actor: &LoadedActor) {
    static ZEROS: [u8; 1 << 20] = [0; 1 << 20];
    for (base, size) in &actor.writable {
        inner
            .poke(actor.id, *base as u32, &ZEROS[..*size as usize])
            .expect("reset");
    }
}

fn peek_u64(inner: &mut InnerMachines, id: u32, address: u64) -> u64 {
    u64::from_le_bytes(
        inner
            .peek(id, address as u32, 8)
            .expect("peek")
            .try_into()
            .unwrap(),
    )
}

#[derive(Default)]
struct Batch {
    overlay: State,
    writes: Vec<(u64, u64)>,
    replies: u32,
    checksum: u64,
}

fn native_call(
    inner: &mut InnerMachines,
    actor: &LoadedActor,
    request: &[u8],
    state: &State,
    batch: &mut Batch,
) {
    inner
        .poke(actor.id, actor.args_base as u32, request)
        .expect("poke request");
    let mut registers = [0u64; 13];
    registers[0] = HALT;
    registers[1] = actor.stack_top;
    registers[7] = actor.args_base;
    registers[8] = request.len() as u64;
    let mut gas = ACTOR_GAS;
    loop {
        let outcome = inner
            .invoke(actor.id, InvokeState { gas, registers })
            .expect("invoke");
        registers = outcome.state.registers;
        gas = outcome.state.gas;
        match outcome.exit {
            InnerExit::Halt => {
                for i in 0..registers[8] / 8 {
                    let word = peek_u64(inner, actor.id, registers[7] + i * 8);
                    batch.checksum = batch.checksum.rotate_left(7) ^ word;
                }
                batch.replies += 1;
                return;
            }
            InnerExit::Host(ACTOR_GET) => {
                let key = peek_u64(inner, actor.id, registers[7]);
                let value = batch
                    .overlay
                    .get(&key)
                    .or_else(|| state.get(&key))
                    .copied()
                    .unwrap_or(0);
                inner
                    .poke(actor.id, registers[9] as u32, &value.to_le_bytes())
                    .expect("poke");
                registers[7] = 8;
            }
            InnerExit::Host(ACTOR_PUT) => {
                let key = peek_u64(inner, actor.id, registers[7]);
                let value = peek_u64(inner, actor.id, registers[9]);
                batch.overlay.insert(key, value);
                batch.writes.push((key, value));
                registers[7] = 0;
            }
            other => panic!("actor exit {other:?}"),
        }
    }
}

/// The node's pool, with the actor installed.
static ACTOR_POOL: OnceLock<(Arc<MachinePool>, Arc<PoolProgram>)> = OnceLock::new();

/// Lend the actor from the pool, with a page mapped for its request at the
/// standard argument address.
fn pooled_actor(inner: &mut InnerMachines, program: &Arc<PoolProgram>) -> LoadedActor {
    const ZONE: u64 = 0x1_0000;
    const INPUT: u64 = 1 << 24;
    let id = inner.instantiate(program).expect("instantiate");
    let args_base = (1 << 32) - ZONE - INPUT;
    inner
        .pages(
            id,
            (args_base / 4096) as u32,
            1,
            PageMode::AllocateReadWrite,
        )
        .expect("request page");
    LoadedActor {
        id,
        stack_top: (1 << 32) - 2 * ZONE - INPUT,
        args_base,
        writable: Vec::new(),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Reuse {
    Fresh,
    /// A machine lent from the pool per request, reset when expunged.
    Pooled,
    Warm,
    /// Warm, with writable memory reset to the image after every request.
    Reset,
}

fn native_batch(
    backend: PvmBackend,
    spi: &Spi,
    requests: &[Request],
    state: &State,
    reuse: Reuse,
) -> (Batch, Duration) {
    let started = Instant::now();
    let mut inner = InnerMachines::with_backend(backend);
    let (pool, program) = ACTOR_POOL.get().expect("actor pool");
    if reuse == Reuse::Pooled {
        inner.set_pool(Arc::clone(pool));
    }
    let mut batch = Batch::default();
    let mut cached = None;
    for request in requests {
        if reuse == Reuse::Pooled {
            let actor = pooled_actor(&mut inner, program);
            native_call(&mut inner, &actor, request, state, &mut batch);
            inner.expunge(actor.id).expect("expunge");
        } else if reuse != Reuse::Fresh {
            let actor = cached.get_or_insert_with(|| load_actor(&mut inner, spi));
            native_call(&mut inner, actor, request, state, &mut batch);
            if reuse == Reuse::Reset {
                native_reset(&mut inner, actor);
            }
        } else {
            let actor = load_actor(&mut inner, spi);
            native_call(&mut inner, &actor, request, state, &mut batch);
            inner.expunge(actor.id).expect("expunge");
        }
    }
    (batch, started.elapsed())
}

// ── Nested: the agent program hosts the actor ───────────────

fn read_u64(machine: &Machine, address: u64) -> u64 {
    let mut bytes = [0u8; 8];
    machine.memory().read_bytes(address as u32, &mut bytes);
    u64::from_le_bytes(bytes)
}

fn run_agent(
    prepared: &PreparedProgram,
    model: MemoryModel,
    args: &[u8],
    pooled: bool,
    host: impl FnMut(u64, &mut Machine) -> Result<(), ExitReason>,
) -> (Invocation, Duration) {
    let started = Instant::now();
    let mut context =
        RefineContext::load_prepared(prepared, args, AGENT_GAS, model).expect("load agent");
    if pooled {
        context = context.with_pool(Arc::clone(&ACTOR_POOL.get().expect("actor pool").0));
    }
    let invocation = context.try_run_with_host(host).expect("backend");
    let elapsed = started.elapsed();
    assert_eq!(invocation.exit, ExitReason::Halt, "agent did not halt");
    (invocation, elapsed)
}

/// How the agent hosts the actor across a batch.
#[derive(Clone, Copy, PartialEq)]
enum Hosting {
    /// Built with `machine`, `pages` and `poke` per request.
    Fresh,
    /// Built once and reused.
    Warm,
    /// Lent from the pool with `instantiate` per request. Without a pool
    /// the host answers `WHAT` and the agent builds the actor itself.
    Pooled { pool: bool },
}

fn nested_batch(
    prepared: &PreparedProgram,
    model: MemoryModel,
    actor_spi: &[u8],
    requests: &[Request],
    state: &State,
    hosting: Hosting,
) -> (Vec<u8>, Duration) {
    let mut next = 0;
    let mut args = vec![b'N'];
    match hosting {
        Hosting::Fresh => args.push(0),
        Hosting::Warm => args.push(1),
        Hosting::Pooled { .. } => {
            args.push(2);
            args.extend_from_slice(&vos_pvm::pool::CodeHash::of(actor_spi).0);
        }
    }
    let pooled = matches!(hosting, Hosting::Pooled { pool: true });
    let (invocation, elapsed) = run_agent(prepared, model, &args, pooled, |id, machine| {
        let registers = *machine.registers();
        let result = match id {
            INPUT_NEXT => match requests.get(next) {
                Some(request) => {
                    next += 1;
                    assert!(
                        machine
                            .memory_mut()
                            .write_bytes_checked(registers[7] as u32, request)
                    );
                    request.len() as u64
                }
                None => u64::MAX,
            },
            STATE_GET => match state.get(&read_u64(machine, registers[7])) {
                Some(value) => {
                    assert!(
                        machine
                            .memory_mut()
                            .write_bytes_checked(registers[9] as u32, &value.to_le_bytes())
                    );
                    8
                }
                None => u64::MAX,
            },
            PROGRAM => {
                assert!(
                    machine
                        .memory_mut()
                        .write_bytes_checked(registers[7] as u32, actor_spi)
                );
                actor_spi.len() as u64
            }
            // A host without a pool answers `instantiate` as JAM does.
            INSTANTIATE => u64::MAX - 1,
            _ => return Err(ExitReason::Panic),
        };
        machine.registers_mut()[7] = result;
        Ok(())
    });
    (
        invocation.output_bounded(1 << 24).expect("work result"),
        elapsed,
    )
}

fn nested_accumulate(
    prepared: &PreparedProgram,
    model: MemoryModel,
    result: &[u8],
    state: &mut State,
) -> Duration {
    let mut args = vec![b'A'];
    args.extend_from_slice(result);
    run_agent(prepared, model, &args, false, |id, machine| {
        if id != STATE_PUT {
            return Err(ExitReason::Panic);
        }
        let registers = *machine.registers();
        state.insert(
            read_u64(machine, registers[7]),
            read_u64(machine, registers[9]),
        );
        Ok(())
    })
    .1
}

fn decode_result(result: &[u8]) -> (Vec<(u64, u64)>, u32, u64) {
    let writes = le(&result[0..4]) as usize;
    let list = (0..writes)
        .map(|i| {
            (
                le(&result[4 + i * 16..12 + i * 16]),
                le(&result[12 + i * 16..20 + i * 16]),
            )
        })
        .collect();
    let at = 4 + writes * 16;
    (
        list,
        le(&result[at..at + 4]) as u32,
        le(&result[at + 4..at + 12]),
    )
}

// ── Workload and measurement ────────────────────────────────

fn requests(n: usize, op: u8, seed: u64) -> Vec<Request> {
    let mut state = seed;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    (0..n)
        .map(|_| {
            let mut request = [0u8; 32];
            request[0] = op;
            request[8..16].copy_from_slice(&(next() % ACCOUNTS).to_le_bytes());
            request[16..24].copy_from_slice(&(next() % ACCOUNTS).to_le_bytes());
            request[24..32].copy_from_slice(&(next() % 1000).to_le_bytes());
            request
        })
        .collect()
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

/// Fixed cost per batch and marginal cost per request, from batches of 1
/// and `n` requests.
fn split(one: Duration, many: Duration, n: usize) -> (f64, f64) {
    let marginal = (us(many) - us(one)) / (n - 1) as f64;
    (us(one) - marginal, marginal)
}

fn backends() -> [(&'static str, PvmBackend, MemoryModel); 2] {
    [
        (
            "interpreter",
            PvmBackend::ForceInterpreter,
            MemoryModel::Sparse,
        ),
        ("JIT", PvmBackend::ForceRecompiler, MemoryModel::Auto),
    ]
}

fn main() {
    let agent_spi = vos_pvm_bench::guest_program("agent");
    let actor_spi = vos_pvm_bench::guest_program("actor");
    let actor = parse_standard_program(&actor_spi);
    let pool = Arc::new(MachinePool::new());
    let program = pool
        .program(&pool.install(&actor_spi).expect("install"))
        .unwrap();
    let _ = ACTOR_POOL.set((pool, program));
    println!(
        "agent {} bytes; actor {} bytes (code {}, ro {}, rw {}, heap pages {}, stack {})",
        agent_spi.len(),
        actor_spi.len(),
        actor.code.len(),
        actor.ro.len(),
        actor.rw.len(),
        actor.heap_pages,
        actor.stack
    );
    let state: State = (0..ACCOUNTS).map(|a| (a, 1_000_000)).collect();
    let n = 1000;
    let transfers = requests(n, b'T', 0x9e37_79b9_7f4a_7c15);
    let queries = requests(n, b'Q', 0x2545_f491_4f6c_dd1d);

    // Profiling: repeat one fixed-cost scenario, e.g. S2_PROFILE=jit:nested.
    if let Ok(profile) = std::env::var("S2_PROFILE") {
        let (backend_name, scenario) = profile.split_once(':').expect("backend:scenario");
        let (_, backend, model) = backends()
            .into_iter()
            .find(|(name, ..)| {
                name.eq_ignore_ascii_case(backend_name)
                    || (backend_name == "interp" && *name == "interpreter")
            })
            .expect("backend");
        let agent = PreparedProgram::new_with_backend(&agent_spi, backend).unwrap();
        let started = Instant::now();
        let rounds = 2000;
        for _ in 0..rounds {
            match scenario {
                "nested" => drop(nested_batch(
                    &agent,
                    model,
                    &actor_spi,
                    &transfers[..1],
                    &state,
                    Hosting::Warm,
                )),
                "fresh" => drop(native_batch(
                    backend,
                    &actor,
                    &transfers[..1],
                    &state,
                    Reuse::Fresh,
                )),
                "pooled" => drop(native_batch(
                    backend,
                    &actor,
                    &transfers[..1],
                    &state,
                    Reuse::Pooled,
                )),
                "agent" => drop(
                    RefineContext::load_prepared(&agent, &[b'N', 1], AGENT_GAS, model).unwrap(),
                ),
                "phases" => {
                    // Timestamps at the node calls the agent makes during a
                    // one-transfer refine.
                    let mut marks = vec![("start", Instant::now())];
                    let context =
                        RefineContext::load_prepared(&agent, &[b'N', 1], AGENT_GAS, model).unwrap();
                    marks.push(("agent loaded", Instant::now()));
                    let mut served = 0;
                    let invocation =
                        context
                            .try_run_with_host(|id, machine| {
                                let registers = *machine.registers();
                                let label = match id {
                                    PROGRAM => "agent started (PROGRAM)",
                                    INPUT_NEXT if served == 0 => "first INPUT_NEXT",
                                    STATE_GET => "actor built and run to its first GET",
                                    INPUT_NEXT => "transfer done",
                                    _ => "other",
                                };
                                if !(id == STATE_GET && marks.iter().any(|(l, _)| *l == label)) {
                                    marks.push((label, Instant::now()));
                                }
                                let result =
                                    match id {
                                        INPUT_NEXT if served == 0 => {
                                            served += 1;
                                            assert!(machine.memory_mut().write_bytes_checked(
                                                registers[7] as u32,
                                                &transfers[0]
                                            ));
                                            32
                                        }
                                        INPUT_NEXT => u64::MAX,
                                        STATE_GET => {
                                            assert!(machine.memory_mut().write_bytes_checked(
                                                registers[9] as u32,
                                                &1_000_000u64.to_le_bytes()
                                            ));
                                            8
                                        }
                                        PROGRAM => {
                                            assert!(machine.memory_mut().write_bytes_checked(
                                                registers[7] as u32,
                                                &actor_spi
                                            ));
                                            actor_spi.len() as u64
                                        }
                                        _ => return Err(ExitReason::Panic),
                                    };
                                machine.registers_mut()[7] = result;
                                Ok(())
                            })
                            .unwrap();
                    marks.push(("agent halted", Instant::now()));
                    drop(invocation);
                    marks.push(("dropped", Instant::now()));
                    if PHASES_PRINTED.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    if ROUND.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 100 {
                        continue;
                    }
                    PHASES_PRINTED.store(true, std::sync::atomic::Ordering::Relaxed);
                    for pair in marks.windows(2) {
                        println!(
                            "   {:>40}: {:>8.1} µs",
                            pair[1].0,
                            us(pair[1].1 - pair[0].1)
                        );
                    }
                }
                _ => panic!("scenario"),
            }
        }
        println!(
            "{profile}: {:.1} µs per round",
            us(started.elapsed()) / rounds as f64
        );
        return;
    }

    for (name, backend, model) in backends() {
        println!("\n== {name}");
        let agent = PreparedProgram::new_with_backend(&agent_spi, backend).unwrap();

        // Correctness: nested and native agree on writes, replies and state.
        let (result, _) =
            nested_batch(&agent, model, &actor_spi, &transfers, &state, Hosting::Warm);
        let (writes, replies, checksum) = decode_result(&result);
        let (native, _) = native_batch(backend, &actor, &transfers, &state, Reuse::Warm);
        assert_eq!(writes, native.writes, "writes differ");
        assert_eq!(
            (replies, checksum),
            (native.replies, native.checksum),
            "replies differ"
        );
        for hosting in [
            Hosting::Fresh,
            Hosting::Pooled { pool: true },
            Hosting::Pooled { pool: false },
        ] {
            let (other, _) = nested_batch(&agent, model, &actor_spi, &transfers, &state, hosting);
            assert_eq!(other, result, "nested hostings differ");
        }
        let mut applied = state.clone();
        nested_accumulate(&agent, model, &result, &mut applied);
        let mut expected = state.clone();
        expected.extend(native.writes.iter().copied());
        assert_eq!(applied, expected, "accumulated state differs");
        println!(
            "   check: {} transfers, {} writes, nested = native, accumulate applied",
            n,
            writes.len()
        );

        // Primitives.
        let count: u64 = 200_000;
        let nop = |k: u64| {
            let mut args = vec![b'H'];
            args.extend_from_slice(&k.to_le_bytes());
            median(
                (0..REPEATS)
                    .map(|_| run_agent(&agent, model, &args, false, |_, _| Ok(())).1)
                    .collect(),
            )
        };
        let per_call = (us(nop(count)) - us(nop(0))) / count as f64;
        let yields = |k: u64| {
            let mut args = vec![b'Y'];
            args.extend_from_slice(&k.to_le_bytes());
            median(
                (0..REPEATS)
                    .map(|_| {
                        run_agent(&agent, model, &args, false, |id, machine| {
                            if id == PROGRAM {
                                let at = machine.registers()[7] as u32;
                                assert!(machine.memory_mut().write_bytes_checked(at, &actor_spi));
                                machine.registers_mut()[7] = actor_spi.len() as u64;
                                Ok(())
                            } else {
                                Err(ExitReason::Panic)
                            }
                        })
                        .1
                    })
                    .collect(),
            )
        };
        let per_yield = (us(yields(count)) - us(yields(1))) / (count - 1) as f64;
        let native_yield = {
            let mut inner = InnerMachines::with_backend(backend);
            let a = load_actor(&mut inner, &actor);
            inner.poke(a.id, a.args_base as u32, b"Y").unwrap();
            let mut registers = [0u64; 13];
            registers[0] = HALT;
            registers[1] = a.stack_top;
            registers[7] = a.args_base;
            registers[8] = 1;
            let started = Instant::now();
            for _ in 0..count {
                let out = inner
                    .invoke(
                        a.id,
                        InvokeState {
                            gas: ACTOR_GAS,
                            registers,
                        },
                    )
                    .unwrap();
                assert_eq!(out.exit, InnerExit::Host(ACTOR_YIELD));
                registers = out.state.registers;
            }
            us(started.elapsed()) / count as f64
        };
        println!(
            "   node host call from the agent: {per_call:.3} µs; actor yield round trip: nested {per_yield:.3} µs, native {native_yield:.3} µs"
        );

        // Program preparation (decode, and compile on the JIT), uncached.
        let prepare = |spi: &[u8]| {
            median(
                (0..REPEATS)
                    .map(|_| {
                        let started = Instant::now();
                        drop(PreparedProgram::new_with_backend(spi, backend).unwrap());
                        started.elapsed()
                    })
                    .collect(),
            )
        };
        println!(
            "   prepare program: agent ({} B) {:.1} µs, actor ({} B) {:.1} µs",
            agent_spi.len(),
            us(prepare(&agent_spi)),
            actor_spi.len(),
            us(prepare(&actor_spi)),
        );

        // Machine creation.
        let load_agent = median(
            (0..REPEATS)
                .map(|_| {
                    let started = Instant::now();
                    let context =
                        RefineContext::load_prepared(&agent, &[b'N', 1], AGENT_GAS, model).unwrap();
                    let elapsed = started.elapsed();
                    drop(context);
                    elapsed
                })
                .collect(),
        );
        let mut create = Vec::new();
        let mut layout = Vec::new();
        let mut first = Vec::new();
        let mut second = Vec::new();
        let mut expunge = Vec::new();
        let query = &queries[0];
        for _ in 0..REPEATS * 3 {
            let mut inner = InnerMachines::with_backend(backend);
            let started = Instant::now();
            let id = inner.create(&actor.code, 0).unwrap();
            create.push(started.elapsed());
            inner.expunge(id).unwrap();
            let started = Instant::now();
            let a = load_actor(&mut inner, &actor);
            layout.push(started.elapsed());
            let mut batch = Batch::default();
            let started = Instant::now();
            native_call(&mut inner, &a, query, &state, &mut batch);
            first.push(started.elapsed());
            let started = Instant::now();
            native_call(&mut inner, &a, query, &state, &mut batch);
            second.push(started.elapsed());
            let started = Instant::now();
            inner.expunge(a.id).unwrap();
            expunge.push(started.elapsed());
        }
        println!(
            "   agent machine per refine: {:.1} µs; actor: create {:.1} µs, create + layout {:.1} µs, \
             first call {:.1} µs, second call {:.1} µs, expunge {:.1} µs",
            us(load_agent),
            us(median(create)),
            us(median(layout)),
            us(median(first)),
            us(median(second)),
            us(median(expunge)),
        );

        // End to end.
        println!(
            "   {:<28} {:>14} {:>16}",
            "path (batch fixed + per request)", "fixed µs", "per request µs"
        );
        for (label, op_requests) in [("transfer", &transfers), ("query", &queries)] {
            for warm in [true, false] {
                if label == "query" && !warm {
                    continue;
                }
                let hostings: &[(Hosting, &str)] = if warm {
                    &[(Hosting::Warm, "warm")]
                } else {
                    &[
                        (Hosting::Fresh, "fresh"),
                        (Hosting::Pooled { pool: true }, "pooled"),
                    ]
                };
                for &(hosting, mode) in hostings {
                    let nested = |k: usize| {
                        median(
                            (0..REPEATS)
                                .map(|_| {
                                    nested_batch(
                                        &agent,
                                        model,
                                        &actor_spi,
                                        &op_requests[..k],
                                        &state,
                                        hosting,
                                    )
                                    .1
                                })
                                .collect(),
                        )
                    };
                    let (fixed, marginal) = split(nested(1), nested(n), n);
                    println!(
                        "   {:<28} {fixed:>14.1} {marginal:>16.2}",
                        format!("nested {label} {mode}")
                    );
                }
                let reuses: &[(Reuse, &str)] = match (label, warm) {
                    ("transfer", true) => &[(Reuse::Warm, "warm"), (Reuse::Reset, "warm + reset")],
                    (_, true) => &[(Reuse::Warm, "warm")],
                    _ => &[(Reuse::Fresh, "fresh"), (Reuse::Pooled, "pooled")],
                };
                for (reuse, mode) in reuses {
                    let native = |k: usize| {
                        median(
                            (0..REPEATS)
                                .map(|_| {
                                    native_batch(backend, &actor, &op_requests[..k], &state, *reuse)
                                        .1
                                })
                                .collect(),
                        )
                    };
                    let (fixed, marginal) = split(native(1), native(n), n);
                    println!(
                        "   {:<28} {fixed:>14.1} {marginal:>16.2}",
                        format!("native {label} {mode}")
                    );
                }
            }
        }

        // Accumulate of the 1,000-transfer work result.
        let accumulate = median(
            (0..REPEATS)
                .map(|_| {
                    let mut applied = state.clone();
                    nested_accumulate(&agent, model, &result, &mut applied)
                })
                .collect(),
        );
        println!(
            "   accumulate {} writes: {:.1} µs ({:.2} µs per write, {:.2} µs per transfer)",
            writes.len(),
            us(accumulate),
            us(accumulate) / writes.len() as f64,
            us(accumulate) / n as f64,
        );
    }
}
