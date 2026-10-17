//! Runs the guest verifier (`../guest`) on the JAM-only refine host against
//! segment proofs, and verifies them natively for comparison: a measuring
//! tool for a proof's verify gas.
//!
//! ```text
//! harness <verify.elf> [--tamper] [--profile] <seg.postcard>:<commitment.postcard>...
//! ```
//!
//! A commitment file is a postcard `vos_pvm_proof::Commitment`, or its
//! 32-byte form. The gas is vos-pvm's: Gray Paper 0.8.0 instruction gas, with
//! PolkaJam's host-call prices (`vos_pvm::refine_host::jam_gas`) for the
//! three calls the guest makes; it is not PolkaJam's own refine gas.
//!
//! Per segment:
//! - **JAM:** `RefineContext::try_run_jam` (the interpreter, PolkaJam's host
//!   prices), the payload as work item 0's and the proof as a preimage of
//!   the running service; gas, verdict, the guest's heap figures and the
//!   pages it wrote.
//! - **Instructions:** the same program on a bare `Machine`, observed,
//!   serving the same three calls at the same prices; its gas must equal
//!   the JAM run's.
//! - **Native:** postcard decode and `verify_standalone`, best of three.
//!
//! `--tamper` adds, for the first segment: one byte flipped at three
//! places (each decoding, each rejected natively), a wrong commitment and
//! a wrong initial root. `--profile` counts the first segment's
//! instructions by function.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use blake2::Blake2b;
use blake2::digest::{Digest, consts::U32};
use vos_pvm::ExitReason;
use vos_pvm::refine::{Machine, MachineObservation, MemoryModel};
use vos_pvm::refine_host::{JamItem, JamRefine, Preimages, RefineContext, jam_gas};
use vos_pvm_proof_verifier::{CommitmentHash, Proof, verify_standalone};

/// A commitment file: a postcard `Commitment`, or its 32-byte form for
/// `proof`'s format's channel.
fn read_commitment(path: &str, proof: &Proof) -> CommitmentHash {
    let bytes = std::fs::read(path).expect("read the commitment");
    if let Ok(commitment) = postcard::from_bytes::<CommitmentHash>(&bytes) {
        return commitment;
    }
    let raw: [u8; 32] = bytes.try_into().expect("a postcard Commitment or 32 bytes");
    let format =
        vos_pvm_proof_verifier::format::lookup(proof.format_version).expect("a registered format");
    CommitmentHash::from_bytes(format.channel, &raw).expect("a hash of the format's channel")
}

const GAS: u64 = 100_000_000_000;
const SERVICE: u64 = 7;
const PAGE: u64 = 4096;

const GP_GAS: u64 = 0;
const GP_FETCH: u64 = 2;
const GP_HISTORICAL_LOOKUP: u64 = 7;
const FETCH_PAYLOAD: u64 = 13;
const NONE: u64 = u64::MAX;

const VERDICTS: [&str; 8] = [
    "REJECT",
    "ACCEPT",
    "BAD_PAYLOAD",
    "NO_PREIMAGE",
    "UNDECODABLE",
    "INITIAL_ROOT",
    "FINAL_ROOT",
    "BAD_COMMITMENT",
];

struct Store(BTreeMap<[u8; 32], Vec<u8>>);

impl Preimages for Store {
    fn preimage(&self, service: u64, hash: &[u8; 32]) -> Option<Vec<u8>> {
        (service == SERVICE)
            .then(|| self.0.get(hash).cloned())
            .flatten()
    }
}

fn blake2b_256(bytes: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(bytes).into()
}

/// The guest's `Report`, decoded.
#[derive(Debug, Default)]
struct Report {
    verdict: u64,
    gas_start: u64,
    gas_after_lookup: u64,
    gas_after_decode: u64,
    gas_end: u64,
    proof_len: u64,
    live_after_decode: u64,
    peak_live: u64,
    high_water: u64,
    total_alloc: u64,
    allocs: u64,
    arena_base: u64,
    stack_base: u64,
    stack_bytes: u64,
    final_root: [u8; 32],
    io_hash: [u8; 32],
    error: String,
}

impl Report {
    fn parse(bytes: &[u8]) -> Self {
        let word = |i: usize| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        let error_len = word(22) as usize;
        Self {
            verdict: word(0),
            gas_start: word(1),
            gas_after_lookup: word(2),
            gas_after_decode: word(3),
            gas_end: word(4),
            proof_len: word(5),
            live_after_decode: word(6),
            peak_live: word(7),
            high_water: word(8),
            total_alloc: word(9),
            allocs: word(10),
            arena_base: word(11),
            stack_base: word(12),
            stack_bytes: word(13),
            final_root: bytes[112..144].try_into().unwrap(),
            io_hash: bytes[144..176].try_into().unwrap(),
            error: String::from_utf8_lossy(&bytes[184..184 + error_len.min(192)]).into_owned(),
        }
    }

    fn verdict_name(&self) -> &'static str {
        VERDICTS.get(self.verdict as usize).copied().unwrap_or("?")
    }
}

/// What one JAM run gave.
struct JamOutcome {
    exit: ExitReason,
    gas: u64,
    wall: Duration,
    report: Option<Report>,
    /// Pages written in the run: in the arena, on the verifier's stack,
    /// elsewhere.
    pages: (u64, u64, u64),
    panic: Option<String>,
}

fn payload(commitment: &[u8; 32], initial: &[u8; 32], last: &[u8; 32], proof: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(132);
    payload.extend_from_slice(commitment);
    payload.extend_from_slice(initial);
    payload.extend_from_slice(last);
    payload.extend_from_slice(&blake2b_256(proof));
    payload.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    payload
}

fn store(proof: &[u8]) -> Arc<Store> {
    Arc::new(Store(BTreeMap::from([(
        blake2b_256(proof),
        proof.to_vec(),
    )])))
}

fn run_jam(program: &[u8], payload: Vec<u8>, proof: &[u8]) -> JamOutcome {
    let jam = JamRefine {
        service: SERVICE,
        parameters: Vec::new(),
        items: vec![JamItem {
            payload,
            imports: Vec::new(),
        }],
        item: 0,
        export_offset: 0,
        preimages: Some(store(proof)),
    };
    let context = RefineContext::load(program, &[], GAS).expect("load the verifier");
    let start = Instant::now();
    let mut run = context.try_run_jam(jam).expect("the JAM-only host");
    let wall = start.elapsed();
    let invocation = &mut run.invocation;
    let report = invocation
        .output_bounded(4096)
        .map(|bytes| Report::parse(&bytes));
    let panic = (invocation.registers[7] == 0xDEAD).then(|| {
        let (address, len) = (invocation.registers[8], invocation.registers[9]);
        let mut bytes = vec![0; len.min(512) as usize];
        invocation.memory().read_bytes(address as u32, &mut bytes);
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let dirty = invocation.memory_mut().take_dirty_pages();
    let mut pages = (0, 0, 0);
    if let Some(report) = &report {
        let arena = report.arena_base / PAGE..(report.arena_base + (192 << 20)) / PAGE;
        let stack = report.stack_base / PAGE..(report.stack_base + report.stack_bytes) / PAGE;
        for range in &dirty {
            for page in range.clone() {
                let page = u64::from(page);
                if arena.contains(&page) {
                    pages.0 += 1;
                } else if stack.contains(&page) {
                    pages.1 += 1;
                } else {
                    pages.2 += 1;
                }
            }
        }
    } else {
        pages.2 = dirty
            .iter()
            .map(|range| u64::from(range.end - range.start))
            .sum();
    }
    JamOutcome {
        exit: invocation.exit.clone(),
        gas: invocation.gas_used,
        wall,
        report,
        pages,
        panic,
    }
}

/// The Gray Paper's copy of `value` out to the guest, as the JAM-only
/// host does it.
fn copy_out(machine: &mut Machine, value: Option<&[u8]>, address: u64, offset: u64, len: u64) {
    let Some(value) = value else {
        machine.registers_mut()[7] = NONE;
        return;
    };
    let start = (offset as usize).min(value.len());
    let end = start + (len as usize).min(value.len() - start);
    assert!(
        machine
            .memory_mut()
            .write_bytes_checked(address as u32, &value[start..end]),
        "copy out to an unwritable range"
    );
    machine.registers_mut()[7] = value.len() as u64;
}

/// The three calls the guest makes, at the JAM-only host's prices.
fn serve(id: u64, machine: &mut Machine, payload: &[u8], proof: &[u8], hash: &[u8; 32]) {
    let r = *machine.registers();
    match id {
        GP_GAS => {
            assert!(machine.charge(jam_gas::GAS));
            machine.registers_mut()[7] = machine.gas_remaining();
        }
        GP_FETCH => {
            assert!(machine.charge(jam_gas::fetch(r[9])));
            let value = (r[10] == FETCH_PAYLOAD && r[11] == 0).then_some(payload);
            copy_out(machine, value, r[7], r[8], r[9]);
        }
        GP_HISTORICAL_LOOKUP => {
            assert!(machine.charge(jam_gas::historical_lookup(r[11])));
            let mut asked = [0u8; 32];
            machine.memory().read_bytes(r[8] as u32, &mut asked);
            let value = (r[7] == NONE && &asked == hash).then_some(proof);
            copy_out(machine, value, r[9], r[10], r[11]);
        }
        other => panic!("unexpected host call {other}"),
    }
}

/// Instructions (and their gas) on a bare machine, observed; with
/// `functions`, the instructions by function.
fn run_counted(
    program: &[u8],
    payload: &[u8],
    proof: &[u8],
    functions: Option<&[(u32, String)]>,
) -> (u64, u64, Option<Vec<(String, u64, u64)>>) {
    let hash = blake2b_256(proof);
    let mut machine =
        Machine::load_with(program, &[], GAS, MemoryModel::Sparse).expect("load the verifier");
    let mut instructions = 0u64;
    let mut by_function = functions.map(|f| vec![(0u64, 0u64); f.len() + 1]);
    loop {
        let exit = machine.resume_observed(|event| {
            if let MachineObservation::Instruction(step) = event {
                instructions += 1;
                if let (Some(counts), Some(functions)) = (by_function.as_mut(), functions) {
                    let at = functions.partition_point(|(offset, _)| *offset <= step.pc_before);
                    counts[at].0 += 1;
                    if at > 0 && functions[at - 1].0 == step.pc_before {
                        counts[at].1 += 1;
                    }
                }
            }
        });
        match exit {
            ExitReason::HostCall(id) => serve(id, &mut machine, payload, proof, &hash),
            _ => break,
        }
    }
    let gas = GAS - machine.gas_remaining();
    let profile = by_function.map(|counts| {
        let functions = functions.unwrap();
        let mut ranked: Vec<(String, u64, u64)> = counts
            .into_iter()
            .enumerate()
            .filter(|(_, (count, _))| *count > 0)
            .map(|(at, (count, entries))| {
                let name = if at == 0 {
                    "?".to_string()
                } else {
                    functions[at - 1].1.clone()
                };
                (name, count, entries)
            })
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked
    });
    (instructions, gas, profile)
}

/// Native decode and verify, best of three.
fn native(bytes: &[u8], commitment: &CommitmentHash) -> (Duration, Duration, Result<(), String>) {
    let mut decode = Duration::MAX;
    let mut verify = Duration::MAX;
    let mut verdict = Ok(());
    for _ in 0..3 {
        let start = Instant::now();
        let proof: Proof = postcard::from_bytes(bytes).expect("decode natively");
        decode = decode.min(start.elapsed());
        let start = Instant::now();
        verdict = verify_standalone(proof, *commitment).map_err(|error| error.to_string());
        verify = verify.min(start.elapsed());
    }
    (decode, verify, verdict)
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1 << 20) as f64
}

fn print_jam(label: &str, outcome: &JamOutcome) {
    match &outcome.report {
        Some(report) => println!(
            "  {label}: exit {:?}, verdict {} ({}), gas {}, wall {:.2?}{}",
            outcome.exit,
            report.verdict_name(),
            report.verdict,
            outcome.gas,
            outcome.wall,
            if report.error.is_empty() {
                String::new()
            } else {
                format!(", error: {}", report.error)
            }
        ),
        None => println!(
            "  {label}: exit {:?}, no report, gas {}, wall {:.2?}, panic {:?}",
            outcome.exit, outcome.gas, outcome.wall, outcome.panic
        ),
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let elf = std::fs::read(args.remove(0)).expect("read the guest ELF");
    let tamper = args.iter().any(|a| a == "--tamper");
    let profile = args.iter().any(|a| a == "--profile");
    args.retain(|a| !a.starts_with("--"));

    let (program, mut functions) =
        vos_pvm_compiler::link_elf_spi_with_symbols(&elf).expect("link the guest");
    assert_eq!(
        program,
        vos_pvm_compiler::link_elf_spi(&elf).expect("link"),
        "the named link is the plain one"
    );
    functions.sort();
    let parsed = vos_pvm::spi::parse_standard_program(&program).expect("parse");
    println!(
        "verifier program: {} bytes (ELF {} bytes); {} functions",
        program.len(),
        elf.len(),
        functions.len()
    );
    let _ = parsed;

    for (index, spec) in args.iter().enumerate() {
        let (proof_path, commitment_path) = spec.split_once(':').expect("<proof>:<commitment>");
        let proof = std::fs::read(proof_path).expect("read the proof");
        let decoded: Proof = postcard::from_bytes(&proof).expect("decode natively");
        let hash = read_commitment(commitment_path, &decoded);
        let commitment = hash.to_bytes();
        let initial = decoded.initial_state.memory_root;
        let last = decoded.final_state.memory_root;
        println!(
            "\n== {proof_path}\n  proof {} B postcard; format {}; components {} (mask {:#x}); \
             log sizes {:?}; pcs {:?}",
            proof.len(),
            decoded.format_version,
            decoded.num_components,
            decoded.component_mask,
            decoded.log_sizes,
            decoded.pcs_config
        );

        let (decode, verify, verdict) = native(&proof, &hash);
        println!("  native: decode {decode:.2?}, verify {verify:.2?}, verdict {verdict:?}");

        let input = payload(&commitment, &initial, &last, &proof);
        let outcome = run_jam(program.as_slice(), input.clone(), &proof);
        print_jam("JAM", &outcome);
        if let Some(report) = &outcome.report {
            assert_eq!(report.final_root, last);
            assert_eq!(report.io_hash, decoded.public_io_hash());
            assert_eq!(report.proof_len as usize, proof.len());
            println!(
                "  gas by phase: start..lookup {}, decode {}, verify {} (gas left at start {})",
                report.gas_start - report.gas_after_lookup,
                report.gas_after_lookup - report.gas_after_decode,
                report.gas_after_decode - report.gas_end,
                report.gas_start
            );
            println!(
                "  heap: live after decode {:.2} MiB, peak live {:.2} MiB, high-water {:.2} MiB, \
                 {} allocations, {:.2} MiB allocated in all",
                mib(report.live_after_decode),
                mib(report.peak_live),
                mib(report.high_water),
                report.allocs,
                mib(report.total_alloc)
            );
            let (arena, stack, other) = outcome.pages;
            println!(
                "  pages written: {} in the arena ({:.2} MiB), {} on the stack ({} KiB), {} elsewhere; \
                 {} in all ({:.2} MiB)",
                arena,
                mib(arena * PAGE),
                stack,
                stack * 4,
                other,
                arena + stack + other,
                mib((arena + stack + other) * PAGE)
            );
        }

        let (instructions, gas, ranked) = run_counted(
            &program,
            &input,
            &proof,
            (profile && index == 0).then_some(functions.as_slice()),
        );
        println!(
            "  instructions {instructions}; observed gas {gas} ({}), {:.3} gas per instruction",
            if gas == outcome.gas {
                "equals the JAM run's"
            } else {
                "DIFFERS from the JAM run's"
            },
            gas as f64 / instructions as f64
        );
        if let Some(ranked) = ranked {
            println!(
                "  instructions by function (top 40; entries: jumps to its first instruction):"
            );
            for (name, count, entries) in ranked.iter().take(40) {
                println!(
                    "    {count:>12} {:>5.1}% {entries:>9} entries  {name}",
                    100.0 * *count as f64 / instructions as f64
                );
            }
        }

        if tamper && index == 0 {
            for fraction in [0.25, 0.5, 0.75] {
                let mut at = (proof.len() as f64 * fraction) as usize;
                let tampered = loop {
                    let mut bytes = proof.clone();
                    bytes[at] ^= 0x01;
                    if let Ok(candidate) = postcard::from_bytes::<Proof>(&bytes) {
                        if candidate.initial_state.memory_root == initial
                            && candidate.final_state.memory_root == last
                        {
                            break bytes;
                        }
                    }
                    at += 1;
                };
                let (_, _, native_verdict) = native(&tampered, &hash);
                let outcome = run_jam(
                    &program,
                    payload(&commitment, &initial, &last, &tampered),
                    &tampered,
                );
                println!(
                    "  tamper: byte {at} of {} (^0x01), native {:?}",
                    proof.len(),
                    native_verdict
                );
                print_jam("  JAM", &outcome);
            }
            let mut wrong = commitment;
            wrong[0] ^= 0x01;
            print_jam(
                "wrong commitment",
                &run_jam(&program, payload(&wrong, &initial, &last, &proof), &proof),
            );
            let mut wrong = initial;
            wrong[0] ^= 0x01;
            print_jam(
                "wrong initial root",
                &run_jam(
                    &program,
                    payload(&commitment, &wrong, &last, &proof),
                    &proof,
                ),
            );
        }
    }
}
