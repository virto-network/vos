//! The agent's tracked machines: their writable pages armed read-only, a
//! guest's first store to a page and every write of the agent's marking it
//! written, through the agent's own code, which a test guest (`tracker`)
//! drives.

use vos_pvm::PvmBackend;
use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
use vos_testkit::programs::actor;
use vos_wire::{Decode, Encode, scale};

use crate::common::{Actors, Node};

const PAGE: u64 = 4096;
/// Where the scribbler's read-only data, read-write data and stack lie.
const RO: u64 = 0x1_0000;
const RW: u64 = 0x3_0000;
const STACK_TOP: u64 = (1 << 32) - 2 * 0x1_0000 - (1 << 24);

#[derive(Encode)]
struct Probe {
    program: [u8; 32],
    track: bool,
    gas: u64,
    arguments: Option<Vec<u8>>,
    writes: Vec<(u64, Vec<u8>)>,
    registers: Vec<(u8, u64)>,
    reads: Vec<(u64, u32)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Decode)]
struct Report {
    status: u8,
    detail: u64,
    gas: u64,
    registers: Vec<u64>,
    served: u32,
    written: Option<Vec<u64>>,
    output: Vec<u8>,
    reads: Vec<Vec<u8>>,
}

const HALT: u8 = 0;
const FAULT: u8 = 2;

/// A standard program that stores φ12, eight bytes, at the address in each
/// of φ2 onwards (`stores` of them), calls the BLAKE2b compression with its
/// arguments in φ7 to φ10 when `compress`, and halts. A page of read-only
/// data at [`RO`]; a page of read-write data and four heap pages at [`RW`];
/// a two-page stack under [`STACK_TOP`].
fn scribbler(stores: u8, compress: bool) -> Vec<u8> {
    let mut code = Vec::new();
    let mut starts = Vec::new();
    for store in 0..stores {
        starts.push(code.len());
        code.extend([123, 12 | ((2 + store) << 4)]);
    }
    if compress {
        starts.push(code.len());
        code.extend([10, 0x00, 0x04]);
    }
    starts.push(code.len());
    code.extend([50, 0]);
    let mut bitmask = vec![0; code.len()];
    for start in starts {
        bitmask[start] = 1;
    }
    build_standard_program(&StandardProgram {
        ro_data: vec![1; PAGE as usize],
        rw_data: vec![2; PAGE as usize],
        heap_pages: 4,
        stack_size: 2 * PAGE as u32,
        code: CodeBlob {
            jump_table: vec![],
            code,
            bitmask,
        },
    })
    .unwrap()
}

fn backends() -> Vec<PvmBackend> {
    let mut backends = vec![PvmBackend::ForceInterpreter];
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    backends.push(PvmBackend::ForceRecompiler);
    backends
}

/// `probe` run by the tracker on `node`'s host and `backend`.
fn run(node: &Node, probe: &Probe, backend: PvmBackend) -> Report {
    static TRACKER: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let tracker = TRACKER.get_or_init(|| actor("tracker"));
    let invocation = node.run_outer(tracker, &probe.encode(), backend);
    assert_eq!(
        invocation.exit,
        vos_pvm::ExitReason::Halt,
        "the tracker halts"
    );
    Report::decode(&invocation.output_bounded(1 << 20).unwrap())
        .unwrap()
        .0
}

/// `probe` on a VOS host and a JAM host, each on every backend: the same
/// report everywhere.
fn agreed(program: &[u8], probe: &Probe) -> Report {
    let mut reports = Vec::new();
    for mut node in [Node::new(), Node::jam(false)] {
        node.add(program);
        for backend in backends() {
            reports.push(run(&node, probe, backend));
        }
    }
    for report in &reports[1..] {
        assert_eq!(report, &reports[0], "every host and backend agree");
    }
    reports.remove(0)
}

fn compressed(h: [u64; 8], m: [u64; 16], t: u128, last: bool) -> Vec<u8> {
    vos_pvm::precompile::compress(&h, &m, t, last)
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}

/// Guest stores, the agent's writes and a precompile's output, which the
/// agent writes: the written set is exactly their pages, every byte lands,
/// and the interpreter, the recompiler, a VOS host and a JAM host agree on
/// the exit, the pages and the inner gas.
#[test]
fn the_written_set_is_exact_for_guest_stores_and_agent_writes() {
    let program = scribbler(4, true);
    let value = 0x0123_4567_89ab_cdef_u64;
    let probe = Probe {
        program: vos_testkit::program_hash(&program).0,
        track: true,
        gas: 1_000_000,
        arguments: None,
        // Across the end of the read-write data's page into the first heap
        // page.
        writes: vec![(RW + PAGE - 4, vec![9; 8])],
        registers: vec![
            (2, RW + 8),
            (3, RW + PAGE - 16),
            (4, RW + 2 * PAGE + 16),
            (5, STACK_TOP - 16),
            (7, RW + 3 * PAGE),
            (8, RW + 4 * PAGE),
            (9, 128),
            (10, 1),
            (12, value),
        ],
        reads: vec![
            (RW + 8, 8),
            (RW + PAGE - 16, 8),
            (RW + PAGE - 4, 8),
            (RW + 2 * PAGE + 16, 8),
            (STACK_TOP - 16, 8),
            (RW + 3 * PAGE, 64),
        ],
    };
    let report = agreed(&program, &probe);
    assert_eq!((report.status, report.served), (HALT, 1));
    let page = |address: u64| address / PAGE;
    assert_eq!(
        report.written,
        Some(vec![
            page(RW),
            page(RW + PAGE),
            page(RW + 2 * PAGE),
            page(RW + 3 * PAGE),
            page(STACK_TOP - 1),
        ]),
        "the stores' pages, the agent's write's two and the compression's \
         output; neither the block it read nor the stack's other page"
    );
    let stored = value.to_le_bytes().to_vec();
    assert_eq!(report.reads[0], stored);
    assert_eq!(report.reads[1], stored);
    assert_eq!(report.reads[2], vec![9; 8]);
    assert_eq!(report.reads[3], stored);
    assert_eq!(report.reads[4], stored);
    assert_eq!(report.reads[5], compressed([0; 8], [0; 16], 128, true));

    // Untracked, the machine runs the same: tracking costs it no gas.
    let untracked = agreed(
        &program,
        &Probe {
            track: false,
            ..probe
        },
    );
    assert_eq!(untracked.written, None);
    assert_eq!(
        Report {
            written: report.written.clone(),
            ..untracked
        },
        report
    );
}

/// A store outside the pages the machine may write is a fault still,
/// tracked or not: into its read-only data, or where nothing is mapped.
#[test]
fn a_fault_outside_the_tracked_pages_is_still_a_fault() {
    let program = scribbler(2, false);
    for address in [RO + 8, 0x50_0008] {
        let probe = |track| Probe {
            program: vos_testkit::program_hash(&program).0,
            track,
            gas: 1_000_000,
            arguments: None,
            writes: vec![],
            registers: vec![(2, RW + 8), (3, address), (12, 7)],
            reads: vec![],
        };
        let tracked = agreed(&program, &probe(true));
        assert_eq!(
            (tracked.status, tracked.detail),
            (FAULT, address & !(PAGE - 1))
        );
        assert_eq!(
            tracked.written,
            Some(vec![RW / PAGE]),
            "the first store's page"
        );
        let untracked = agreed(&program, &probe(false));
        assert_eq!(
            (untracked.status, untracked.detail),
            (FAULT, address & !(PAGE - 1))
        );
        assert_eq!(untracked.gas, tracked.gas, "{address:#x}");
    }
}

/// A workflow's program, built by the SDK, run tracked from its arguments
/// to its result: its pages written lie among those it may write, and every
/// host and backend agree on them.
#[test]
fn a_tracked_workflow_program_runs_to_its_result() {
    let tally = Actors::load().tally;
    let amounts: Vec<u64> = (1..=300).collect();
    let probe = Probe {
        program: vos_testkit::program_hash(&tally).0,
        track: true,
        gas: 10_000_000,
        arguments: Some(amounts.encode()),
        writes: vec![],
        registers: vec![],
        reads: vec![],
    };
    let report = agreed(&tally, &probe);
    assert_eq!(report.status, HALT);
    assert_eq!(report.output, 45_150u64.encode());
    let written = report.written.expect("tracked");
    assert!(!written.is_empty());
    let parsed = vos_pvm::spi::parse_standard_program(&tally).unwrap();
    let layout = parsed.layout(&[]).unwrap();
    let pages =
        |region: vos_pvm::spi::SpiRegion| region.base / PAGE..(region.base + region.size) / PAGE;
    assert!(
        written
            .iter()
            .all(|page| pages(layout.rw).contains(page) || pages(layout.stack).contains(page)),
        "{written:x?}"
    );
}
