#![cfg(feature = "prover")]

//! The settlement window's kernel, the `window` test actor's (`just
//! build-test-actors`): a space's pseudo-account rows, checked against the
//! committed-map roots of a window's two anchors by a vos-tree multiproof
//! each, and `cipher_clerk::settlement::window` over them.
//!
//! The space's map holds a million rows at two versions, eight journals'
//! pseudo-account pairs among them. The method runs live on the agent's
//! reference model; its kernel re-runs from the attest to the same output,
//! proves over its shape on the segment format, and verifies as a chain
//! against its program, its io-hash the run's.

mod common;

use std::sync::OnceLock;
use std::time::Instant;

use cipher_clerk::codec;
use cipher_clerk::conventions::PseudoAccount;
use cipher_clerk::ids::JournalId;
use cipher_clerk::kernel::Value;
use cipher_clerk::settlement::{Anchor, Reads, window};
use cipher_clerk::types::{Account, Layer};
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::{KernelTrace, trace_kernel};
use vos_pvm_proof::program_id::KernelEntry;
use vos_pvm_proof::{Proof, program_commitment_of_proof, prove_kernel};
use vos_pvm_proof_verifier::{verify_kernel_chain, verify_kernel_segment};
use vos_testkit::Testkit;
use vos_testkit::programs::{derivation, derived, method, package};
use vos_tree::{BatchProof, Blake2b, Leaf, MemStore, keys};
use vos_wire::Encode;
use vos_wire::abi::cap::Target;
use vos_wire::ids::{AgentId, InstanceId, Principal, ProgramHash};
use vos_wire::result::{Attest, Outcome};

const GAS: u64 = 1 << 32;
const ROWS: usize = 1_000_000;
const JOURNALS: usize = 8;
const SPACE: [u8; 32] = [0xA1; 32];
const PEER: [u8; 32] = [0xB2; 32];
const OPERATOR: [u8; 32] = [0x0C; 32];
const CURRENCY: u32 = 840;
const WINDOW_I: u64 = 41;
const WINDOW_J: u64 = 42;
/// The class a run is cut at: segments of up to 2^15 steps.
const CUT: usize = 1;

/// splitmix64: the other rows' bytes, reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
        }
    }
}

/// Journal `k`'s pseudo-account pair at both anchors: the outgoing
/// account's credits and the incoming account's debits grew in between.
/// Journal 0's incoming account was opened inside the window, so it is
/// absent at the first anchor.
fn pair(k: usize) -> [(Option<Account<Value>>, Account<Value>); 2] {
    let mut journal = [0u8; 16];
    journal[..8].copy_from_slice(&(0x4a4f_0000 + k as u64).to_be_bytes());
    journal[8] = 0x5a;
    let journal = JournalId(journal);
    let n = k as u64 + 1;
    let at = |pseudo: PseudoAccount, dr: u64, cr: u64, timestamp: u64| {
        let mut account: Account<Value> = pseudo.open(OPERATOR);
        let settled = &mut account.balances[Layer::Settled.as_index()];
        settled.dr = Value(dr);
        settled.cr = Value(cr);
        account.timestamp = timestamp;
        account
    };
    let outgoing = PseudoAccount::outgoing_to(journal, PEER, CURRENCY);
    let incoming = PseudoAccount::incoming_from(journal, PEER, CURRENCY);
    [
        (
            Some(at(outgoing, 0, 1_000 * n, 100 + n)),
            at(outgoing, 0, 1_000 * n + 250 * n + 3, 1_000 + n),
        ),
        (
            (k != 0).then(|| at(incoming, 700 * n, 0, 100 + n)),
            at(incoming, 700 * n + 120 * n, 0, 1_000 + n),
        ),
    ]
}

/// The tree's version at `seed` after `writes`, each value salted from it.
fn put(store: &mut MemStore, seed: &[u8; 32], writes: &[(Vec<u8>, Vec<u8>)]) -> [u8; 32] {
    let mut leaves: Vec<(Vec<u8>, Option<Leaf>)> = writes
        .iter()
        .map(|(key, value)| (key.clone(), Some(Leaf::salted(&Blake2b, seed, key, value))))
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    let mut root = [0; 32];
    for batch in leaves.chunks(1 << 16) {
        root = vos_tree::update(&Blake2b, store, batch).expect("the tree updates");
    }
    root
}

/// A row as `state` takes it (`window::Row`): its read at the first
/// anchor, absent for an account opened inside the window, then at the
/// second, each its leaf's salt and its value.
type Row = (Option<([u8; 16], Vec<u8>)>, ([u8; 16], Vec<u8>));

/// The kernel's statuses for rows the first and the second anchor's proofs
/// refuse (`window::REFUSED_I`, `window::REFUSED_J`).
const REFUSED_I: u8 = 3;
const REFUSED_J: u8 = 4;

/// A window's arguments, and the output its kernel gives.
struct Instance {
    root_i: [u8; 32],
    root_j: [u8; 32],
    rows: Vec<Row>,
    proof_i: BatchProof,
    proof_j: BatchProof,
    expected: Vec<u8>,
}

impl Instance {
    /// The arguments as `state` takes them.
    fn arguments(&self, rows: &[Row]) -> Vec<u8> {
        (
            (SPACE, WINDOW_I, self.root_i),
            (WINDOW_J, self.root_j, rows.to_vec()),
            (self.proof_i.encode(), self.proof_j.encode()),
        )
            .encode()
    }
}

/// The window over the eight journals' rows in a map of [`ROWS`] rows,
/// built once.
fn instance() -> &'static Instance {
    static INSTANCE: OnceLock<Instance> = OnceLock::new();
    INSTANCE.get_or_init(build)
}

fn build() -> Instance {
    let accounts: Vec<(Option<Account<Value>>, Account<Value>)> =
        (0..JOURNALS).flat_map(pair).collect();
    let key = |account: &Account<Value>| keys::hashed(&Blake2b, &account.id.0);
    let (seed_i, seed_j) = ([1u8; 32], [2u8; 32]);

    let mut rng = Rng(0x5eed_0000 + ROWS as u64);
    let width = codec::to_bytes(&accounts[0].1).len();
    let others: Vec<(Vec<u8>, Vec<u8>)> = (accounts.len()..ROWS)
        .map(|_| {
            let (mut id, mut value) = ([0u8; 16], vec![0u8; width]);
            rng.fill(&mut id);
            rng.fill(&mut value);
            (keys::hashed(&Blake2b, &id), value)
        })
        .collect();

    let mut store = MemStore::default();
    let mut writes = others.clone();
    writes.extend(
        accounts
            .iter()
            .filter_map(|(at_i, _)| at_i.as_ref())
            .map(|at_i| (key(at_i), codec::to_bytes(at_i))),
    );
    let root_i = put(&mut store, &seed_i, &writes);
    let mut accounts: Vec<&(Option<Account<Value>>, Account<Value>)> = accounts.iter().collect();
    accounts.sort_by_key(|(_, at_j)| key(at_j));
    let keys: Vec<Vec<u8>> = accounts.iter().map(|(_, at_j)| key(at_j)).collect();
    let proof_i = BatchProof::generate(&store, &keys).expect("proves");

    // The second version: the pseudo-accounts grew, and a thousand other
    // rows changed.
    let mut writes: Vec<(Vec<u8>, Vec<u8>)> = others
        .into_iter()
        .take(1_000)
        .map(|(key, mut value)| {
            value[0] ^= 0xff;
            (key, value)
        })
        .collect();
    writes.extend(
        accounts
            .iter()
            .map(|(_, at_j)| (key(at_j), codec::to_bytes(at_j))),
    );
    let root_j = put(&mut store, &seed_j, &writes);
    let proof_j = BatchProof::generate(&store, &keys).expect("proves");

    let rows: Vec<Row> = accounts
        .iter()
        .zip(&keys)
        .map(|((at_i, at_j), key)| {
            (
                at_i.as_ref().map(|at_i| {
                    (
                        vos_tree::salt(&Blake2b, &seed_i, key),
                        codec::to_bytes(at_i),
                    )
                }),
                (
                    vos_tree::salt(&Blake2b, &seed_j, key),
                    codec::to_bytes(at_j),
                ),
            )
        })
        .collect();
    let reads: Vec<Reads> = accounts
        .iter()
        .map(|(at_i, at_j)| Reads {
            at_i: at_i.clone(),
            at_j: at_j.clone(),
        })
        .collect();
    let flow = window(
        SPACE,
        Anchor {
            window: WINDOW_I,
            root: root_i,
        },
        Anchor {
            window: WINDOW_J,
            root: root_j,
        },
        &reads,
    )
    .expect("the window's statement");
    let mut expected = vec![0u8];
    expected.extend_from_slice(&codec::to_bytes(&flow));
    Instance {
        root_i,
        root_j,
        rows,
        proof_i,
        proof_j,
        expected,
    }
}

/// The process's peak resident memory, for the log: A.7 caps a segment's.
fn peak_rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
            line.split_whitespace().nth(1)?.parse::<u64>().ok()
        })
        .map_or(0, |kib| kib / 1024)
}

/// The window kernel, as its install records it, and its attest from a
/// live run of `state` on `arguments`.
struct Kernel {
    blob: Vec<u8>,
    record: vos_wire::records::Kernel,
    attest: Attest,
}

fn run(arguments: &[u8]) -> Kernel {
    let derived = derived("window");
    let install = derivation(&package("window"), &derived);
    let mut kit = Testkit::new(AgentId(7));
    kit.install_derived(Target::Vos, InstanceId(9), &derived, &[])
        .expect("installs");
    let step = kit.command(
        Principal::Client([1; 32]),
        InstanceId(9),
        method(&derived.actor, "state"),
        arguments,
    );
    assert!(
        matches!(step.outcome, Outcome::Done(_)),
        "{:?}",
        step.outcome
    );
    let attest = step.attests.into_iter().next().expect("an attest");
    let blob = derived
        .kernels
        .iter()
        .map(|(_, kernel)| kernel)
        .find(|kernel| ProgramHash::of(kernel) == attest.program)
        .expect("the derived kernel")
        .clone();
    let record = install
        .kernels
        .iter()
        .find(|kernel| kernel.program == attest.program)
        .expect("its install's record")
        .clone();
    Kernel {
        blob,
        record,
        attest,
    }
}

fn traced(kernel: &Kernel) -> KernelTrace {
    let trace = trace_kernel(&kernel.blob, &kernel.attest.witness_input, GAS).expect("re-runs");
    assert_eq!(trace.output, kernel.attest.output);
    trace
}

/// Rows the anchors' roots do not hold are refused, and the window states
/// nothing: a value the second anchor's root does not commit, and a row
/// claimed absent at the first anchor that is present there.
#[test]
fn rows_off_the_roots_are_refused() {
    let instance = instance();
    let mut rows = instance.rows.clone();
    rows[0].1.0[0] ^= 1;
    let refused = run(&instance.arguments(&rows));
    assert_eq!(refused.attest.output, vec![REFUSED_J].encode());
    traced(&refused);

    let mut rows = instance.rows.clone();
    let present = rows.iter().position(|row| row.0.is_some()).unwrap();
    rows[present].0 = None;
    let refused = run(&instance.arguments(&rows));
    assert_eq!(refused.attest.output, vec![REFUSED_I].encode());
}

/// The window's kernel re-runs from its attest to the window's statement,
/// proves over its shape cut at class 1's budgets, each segment at the
/// first class that holds it, and verifies as a chain against its program.
#[test]
fn the_window_proves_and_verifies_over_its_shape() {
    let started = Instant::now();
    let instance = instance();
    let kernel = run(&instance.arguments(&instance.rows));
    assert_eq!(kernel.attest.output, instance.expected.encode());
    let trace = traced(&kernel);
    let program = common::kernel_program(&kernel.blob, &kernel.record, &SEGMENT);
    let shape = &program.shape;
    eprintln!(
        "window: {} steps, {} compressions, witness input {} B, kernel {} B, \
         chips {:#x} ({} of {}) ({:.1}s)",
        trace.side_note.steps.len(),
        trace.side_note.blake2b_calls.len(),
        kernel.attest.witness_input.len(),
        kernel.blob.len(),
        shape.components,
        shape.components.count_ones(),
        vos_pvm_proof::chip_idx::COUNT,
        started.elapsed().as_secs_f64(),
    );
    for (index, class) in shape.classes.iter().enumerate() {
        eprintln!(
            "class {index}: 2^{} steps, {} pages, log sizes {:?}",
            class.log_steps, class.pages, class.log_sizes
        );
    }

    let started = Instant::now();
    let segments = prove_kernel(&trace.side_note, shape, CUT, &SEGMENT).expect("proves");
    eprintln!(
        "proved {} segments in {:.1}s, peak RSS {} MiB",
        segments.len(),
        started.elapsed().as_secs_f64(),
        peak_rss_mib()
    );
    for (index, segment) in segments.iter().enumerate() {
        assert_eq!(
            program_commitment_of_proof(&segment.proof),
            program.preprocessed_roots[segment.class]
        );
        eprintln!(
            "segment {index}: steps {:?} ({}), class {}",
            segment.steps,
            segment.steps.1 - segment.steps.0,
            segment.class
        );
    }
    let first = segments[0].proof.clone();
    assert_eq!(
        verify_kernel_segment(first, &program).unwrap(),
        segments[0].class
    );
    let proofs: Vec<Proof> = segments.into_iter().map(|segment| segment.proof).collect();
    let entry = KernelEntry::of(&program, &kernel.blob).expect("the program's blob");
    let started = Instant::now();
    let registers = verify_kernel_chain(proofs, &program, &entry).expect("verifies");
    eprintln!("chain verified in {:.2}s", started.elapsed().as_secs_f64());
    let io_hash: Vec<u8> = registers[9..13]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    assert_eq!(io_hash, trace.io_hash);
}
