//! Snapshot cost for suspended workflows.
//!
//! For each workflow the harness runs the guest straight through (the
//! reference output and per-suspension prefix times), then runs it again
//! restoring a fresh machine from a snapshot at every suspension. It reports
//! changed pages, capture and restore costs, and the work a replay journal
//! would redo instead.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use blake2::{Blake2b512, Digest};
use vos_pvm::interpreter::{Memory, PERM_RW};
use vos_pvm::refine::{Machine, MemoryModel, PreparedProgram};
use vos_pvm::{ExitReason, PvmBackend};

const AWAIT_AGENT: u64 = 0x200;
const CALL_LOCAL: u64 = 0x201;
const CHECKPOINT: u64 = 0x202;
const PAGE: usize = 4096;
const GAS: u64 = 50_000_000_000;

type Page = Box<[u8; PAGE]>;

/// Bare code blob `c` from a standard program
/// `E3(|o|) E3(|w|) E2(z) E3(s) o w E4(|c|) c`.
fn code_blob(spi: &[u8]) -> Vec<u8> {
    let le = |bytes: &[u8]| bytes.iter().rev().fold(0usize, |acc, b| acc << 8 | *b as usize);
    let ro = le(&spi[0..3]);
    let rw = le(&spi[3..6]);
    let offset = 11 + ro + rw;
    let len = le(&spi[offset..offset + 4]);
    spi[offset + 4..offset + 4 + len].to_vec()
}

fn read_page(memory: &Memory, index: u32) -> Page {
    let mut page = Box::new([0u8; PAGE]);
    memory.read_bytes(index * PAGE as u32, &mut page[..]);
    page
}

fn writable_pages(memory: &Memory) -> Vec<u32> {
    memory
        .page_perms()
        .iter()
        .enumerate()
        .filter(|(_, perm)| **perm == PERM_RW)
        .map(|(index, _)| index as u32)
        .collect()
}

/// Deterministic replies standing in for other agents and local instances.
fn reply(call: u64, message: &[u8], ordinal: usize) -> Vec<u8> {
    let head = match call {
        AWAIT_AGENT => format!("ok:score={} step={ordinal} ", message.len() % 97),
        CALL_LOCAL => format!("receipt:#{ordinal:08} "),
        _ => String::new(),
    };
    let mut bytes = head.into_bytes();
    bytes.resize(bytes.len().max(120), b'.');
    bytes
}

/// Serve one host call on a machine; returns true for a suspension point.
fn serve(machine: &mut Machine, call: u64, ordinal: usize) -> bool {
    let registers = *machine.registers();
    if call == CHECKPOINT {
        machine.registers_mut()[7] = 0;
        return true;
    }
    let mut message = vec![0u8; registers[8] as usize];
    machine.memory().read_bytes(registers[7] as u32, &mut message);
    let answer = reply(call, &message, ordinal);
    let len = answer.len().min(registers[10] as usize);
    assert!(
        machine
            .memory_mut()
            .write_bytes_checked(registers[9] as u32, &answer[..len])
    );
    machine.registers_mut()[7] = len as u64;
    call == AWAIT_AGENT
}

fn output(machine: &Machine) -> String {
    let registers = machine.registers();
    let mut bytes = vec![0u8; registers[8] as usize];
    machine.memory().read_bytes(registers[7] as u32, &mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Run straight through, recording elapsed time at each suspension point.
fn reference(prepared: &PreparedProgram, args: &[u8], model: MemoryModel) -> (String, Vec<Duration>, Duration) {
    let mut machine = Machine::load_prepared(prepared, args, GAS, model).expect("load");
    let started = Instant::now();
    let mut prefixes = Vec::new();
    let mut ordinal = 0;
    loop {
        match machine.try_resume().expect("backend") {
            ExitReason::HostCall(call) => {
                // Elapsed time before serving: what a replay would redo.
                let elapsed = started.elapsed();
                if serve(&mut machine, call, ordinal) {
                    prefixes.push(elapsed);
                }
                ordinal += 1;
            }
            ExitReason::Halt => break,
            other => panic!("unexpected exit {other:?}"),
        }
    }
    (output(&machine), prefixes, started.elapsed())
}

struct Snapshot {
    resume_pc: u32,
    gas: u64,
    registers: [u64; 13],
    /// Every page that differs from the program image.
    pages: BTreeMap<u32, Page>,
}

#[derive(Default)]
struct Row {
    dirty_pages: usize,
    delta_pages: usize,
    delta_lz4: usize,
    scan_us: f64,
    tracked_us: f64,
    restore_interp_us: f64,
    restore_jit_us: f64,
    prefix_us: f64,
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

fn snapshot_run(
    spi: &[u8],
    args: &[u8],
    prefixes: &[Duration],
) -> (String, Vec<Row>) {
    let code = code_blob(spi);
    let interp = PreparedProgram::new_with_backend(spi, PvmBackend::ForceInterpreter).unwrap();
    let jit = PreparedProgram::new_with_backend(spi, PvmBackend::ForceRecompiler).unwrap();
    let template = Machine::load_prepared(&interp, args, GAS, MemoryModel::Sparse).unwrap();
    let image: Memory = template.memory().clone();
    let rw = writable_pages(&image);
    let image_pages: BTreeMap<u32, Page> = rw.iter().map(|i| (*i, read_page(&image, *i))).collect();

    let mut machine = Machine::load_prepared(&interp, args, GAS, MemoryModel::Sparse).unwrap();
    let mut previous: BTreeMap<u32, Page> = BTreeMap::new();
    let mut rows = Vec::new();
    let mut ordinal = 0;
    loop {
        let exit = machine.try_resume().unwrap();
        let call = match exit {
            ExitReason::HostCall(call) => call,
            ExitReason::Halt => return (output(&machine), rows),
            other => panic!("unexpected exit {other:?}"),
        };
        if call == CALL_LOCAL {
            serve(&mut machine, call, ordinal);
            ordinal += 1;
            continue;
        }

        // Capture at the suspension point, before any reply exists.
        let pending = machine.interpreter().pending_host_call().expect("pending host call");
        let memory = machine.memory();
        let scan_started = Instant::now();
        let mut dirty = BTreeMap::new();
        for index in &rw {
            let page = read_page(memory, *index);
            if page[..] != image_pages[index][..] {
                dirty.insert(*index, page);
            }
        }
        let delta: Vec<u32> = dirty
            .iter()
            .filter(|(index, page)| previous.get(*index).is_none_or(|old| old[..] != page[..]))
            .map(|(index, _)| *index)
            .collect();
        let scan_us = scan_started.elapsed().as_secs_f64() * 1e6;

        // Cost with native dirty tracking: copy and hash only changed pages.
        let tracked_started = Instant::now();
        let mut shipped = Vec::with_capacity(delta.len() * PAGE);
        for index in &delta {
            let page = read_page(memory, *index);
            let _hash = Blake2b512::digest(&page[..]);
            shipped.extend_from_slice(&page[..]);
        }
        let tracked_us = tracked_started.elapsed().as_secs_f64() * 1e6;
        let delta_lz4 = lz4_flex::compress_prepend_size(&shipped).len();

        let snapshot = Snapshot {
            resume_pc: pending.resume_pc,
            gas: machine.gas_remaining(),
            registers: *machine.registers(),
            pages: dirty,
        };

        // Restore on the interpreter: image + snapshot pages + registers/pc.
        let mut restore_interp = Vec::new();
        let mut restored = None;
        for _ in 0..5 {
            let started = Instant::now();
            let mut memory = image.clone();
            for (index, page) in &snapshot.pages {
                memory.init_copy(index * PAGE as u32, &page[..]);
            }
            let next = Machine::from_pvm_blob(
                &code,
                u64::from(snapshot.resume_pc),
                snapshot.gas,
                true,
                snapshot.registers,
                memory,
            );
            restore_interp.push(started.elapsed().as_secs_f64() * 1e6);
            restored = Some(next);
        }

        // Restore cost on the JIT: instantiate from the prepared image and
        // write the snapshot pages. (Setting the pc is a field store.)
        let mut restore_jit = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            let mut next = Machine::load_prepared(&jit, args, GAS, MemoryModel::Auto).unwrap();
            for (index, page) in &snapshot.pages {
                next.memory_mut().init_copy(index * PAGE as u32, &page[..]);
            }
            *next.registers_mut() = snapshot.registers;
            restore_jit.push(started.elapsed().as_secs_f64() * 1e6);
        }

        rows.push(Row {
            dirty_pages: snapshot.pages.len(),
            delta_pages: delta.len(),
            delta_lz4,
            scan_us,
            tracked_us,
            restore_interp_us: median(restore_interp),
            restore_jit_us: median(restore_jit),
            prefix_us: prefixes.get(rows.len()).map_or(0.0, |d| d.as_secs_f64() * 1e6),
        });
        previous = snapshot.pages;

        // Continue in the restored machine and deliver the reply there.
        machine = restored.unwrap();
        // `from_pvm_blob` resumes at `resume_pc`; deliver the reply first.
        serve(&mut machine, call, ordinal);
        ordinal += 1;
    }
}

fn main() {
    let elf_path = std::env::args().nth(1).expect("usage: s1-harness <workflows.elf>");
    let elf = std::fs::read(&elf_path).unwrap();
    let spi = vos_pvm_compiler::link_elf_spi(&elf).expect("link");
    println!("program: {} bytes", spi.len());

    let workloads: [(&str, Vec<u8>); 3] = [
        ("transfer", b"Talice|bob|1250|rent october|household|recurring".to_vec()),
        ("saga", b"Sorder-7731 customer=4411 items=3".to_vec()),
        ("compute", b"C".to_vec()),
    ];
    for (name, args) in workloads {
        let interp = PreparedProgram::new_with_backend(&spi, PvmBackend::ForceInterpreter).unwrap();
        let jit = PreparedProgram::new_with_backend(&spi, PvmBackend::ForceRecompiler).unwrap();
        let (expected, prefixes, interp_total) = reference(&interp, &args, MemoryModel::Sparse);
        let (jit_output, jit_prefixes, jit_total) = reference(&jit, &args, MemoryModel::Auto);
        assert_eq!(expected, jit_output, "interpreter and JIT disagree");
        let (restored_output, rows) = snapshot_run(&spi, &args, &prefixes);
        println!(
            "\n== {name}: output {:?}\n   straight run: interpreter {:.0} µs, JIT {:.0} µs; restored output {}",
            expected,
            interp_total.as_secs_f64() * 1e6,
            jit_total.as_secs_f64() * 1e6,
            if restored_output == expected { "MATCHES" } else { "DIFFERS" },
        );
        println!(
            "   {:>3} {:>6} {:>6} {:>9} {:>9} {:>9} {:>10} {:>10} {:>10} {:>10}",
            "#", "dirty", "delta", "delta KiB", "lz4 KiB", "scan µs", "track µs", "rst-int µs", "rst-jit µs", "replay µs"
        );
        for (index, row) in rows.iter().enumerate() {
            let jit_prefix = jit_prefixes.get(index).map_or(0.0, |d| d.as_secs_f64() * 1e6);
            println!(
                "   {:>3} {:>6} {:>6} {:>9.1} {:>9.1} {:>9.0} {:>10.0} {:>10.0} {:>10.0} {:>4.0}/{:<5.0}",
                index,
                row.dirty_pages,
                row.delta_pages,
                row.delta_pages as f64 * 4.0,
                row.delta_lz4 as f64 / 1024.0,
                row.scan_us,
                row.tracked_us,
                row.restore_interp_us,
                row.restore_jit_us,
                row.prefix_us,
                jit_prefix,
            );
        }
    }
}
