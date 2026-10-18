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
//! against its program, its io-hash the run's. Its first four segments and
//! its last verify in their classes' leaves, which prove and verify; the
//! first four's leaves fold into a tree, two folds of two leaves and a fold
//! of the two folds, each proved and verified. The whole run's leaves fold
//! into one root, which the final wrap proves under format 28 and the final
//! verifier verifies.

mod common;

#[global_allocator]
static ALLOCATOR: common::Counting = common::Counting;

use std::sync::OnceLock;
use std::time::Instant;

use cipher_clerk::codec;
use cipher_clerk::conventions::PseudoAccount;
use cipher_clerk::ids::JournalId;
use cipher_clerk::kernel::Value;
use cipher_clerk::settlement::{Anchor, Reads, WindowError, window};
use cipher_clerk::types::{Account, Layer};
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::{KernelTrace, trace_kernel};
use vos_pvm_proof::program_id::KernelEntry;
use vos_pvm_proof::segment::{SegmentCursor, segment_bounds_budgeted};
use vos_pvm_proof::{Proof, ProvingError, program_commitment_of_proof, prove_kernel, prove_shaped};
use vos_pvm_proof_verifier::{verify_kernel_chain, verify_kernel_segment};
use vos_testkit::Testkit;
use vos_testkit::programs::{derivation, derived, method, package};
use vos_tree::{BatchProof, Blake2b, Decode, Leaf, MemStore, keys};
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

/// The kernel's statuses (`window`'s constants): a value that does not
/// decode, rows out of key order, rows the first or the second anchor's
/// proof refuses, and `WINDOW` plus the index of `window`'s error.
const MALFORMED: u8 = 1;
const UNORDERED: u8 = 2;
const REFUSED_I: u8 = 3;
const REFUSED_J: u8 = 4;
const WINDOW: u8 = 16;

/// `state`'s arguments, the proofs each a `BatchProof`'s encoding.
#[derive(Clone)]
struct Arguments {
    space: [u8; 32],
    window_i: u64,
    root_i: [u8; 32],
    window_j: u64,
    root_j: [u8; 32],
    rows: Vec<Row>,
    proof_i: Vec<u8>,
    proof_j: Vec<u8>,
}

impl Arguments {
    fn encode(&self) -> Vec<u8> {
        (
            (self.space, self.window_i, self.root_i),
            (self.window_j, self.root_j, self.rows.clone()),
            (self.proof_i.clone(), self.proof_j.clone()),
        )
            .encode()
    }
}

/// A window's arguments, and the output its kernel gives.
struct Instance {
    arguments: Arguments,
    expected: Vec<u8>,
}

/// The window over the eight journals' rows in a map of [`ROWS`] rows,
/// built once.
fn instance() -> &'static Instance {
    static INSTANCE: OnceLock<Instance> = OnceLock::new();
    INSTANCE.get_or_init(build)
}

/// A row's key: its account's id under the hashed transform.
fn key(account: &Account<Value>) -> Vec<u8> {
    keys::hashed(&Blake2b, &account.id.0)
}

fn build() -> Instance {
    let accounts: Vec<(Option<Account<Value>>, Account<Value>)> =
        (0..JOURNALS).flat_map(pair).collect();
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
    build_over(accounts, others, 1_000)
}

/// The window over `accounts`' rows in a map that also holds `others`, at
/// two versions: the first holds the accounts present at the first anchor;
/// at the second the accounts grew and the first `changed` others changed.
fn build_over(
    accounts: Vec<(Option<Account<Value>>, Account<Value>)>,
    others: Vec<(Vec<u8>, Vec<u8>)>,
    changed: usize,
) -> Instance {
    let (seed_i, seed_j) = ([1u8; 32], [2u8; 32]);
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

    let mut writes: Vec<(Vec<u8>, Vec<u8>)> = others
        .into_iter()
        .take(changed)
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
        arguments: Arguments {
            space: SPACE,
            window_i: WINDOW_I,
            root_i,
            window_j: WINDOW_J,
            root_j,
            rows,
            proof_i: proof_i.encode(),
            proof_j: proof_j.encode(),
        },
        expected,
    }
}

/// A key's bit at `level`, most significant first, a bit past its end
/// reading 0.
fn bit(key: &[u8], level: usize) -> u8 {
    key.get(level / 8)
        .map_or(0, |byte| (byte >> (7 - level % 8)) & 1)
}

/// Journal 0's window over a map of three rows, where the first anchor's
/// proof ends the paths of its two claims, one present and one absent, in
/// the opposite of their keys' order.
///
/// The outgoing account's key `p` is present at both anchors, the incoming
/// account's `a` only at the second; they first differ at bit `d`. The map
/// also holds `p` with a later bit `l` flipped, where `a`'s bit differs
/// from `p`'s and from its own at `d`: at the first anchor the tree is one
/// branch at `l`, and `a`, parting from both leaves at `d`, where no branch
/// splits, ends on the side of `l` opposite to the one its order puts it.
fn inversion() -> Instance {
    let accounts = pair(0);
    let present = key(&accounts[0].1);
    let absent = key(&accounts[1].1);
    let parted = (0..present.len() * 8)
        .find(|&level| bit(&present, level) != bit(&absent, level))
        .expect("distinct keys");
    let flipped = (parted + 1..128)
        .find(|&level| {
            bit(&absent, level) != bit(&present, level)
                && bit(&absent, level) != bit(&absent, parted)
        })
        .expect("a bit past the first difference");
    let mut other = present.clone();
    other[flipped / 8] ^= 0x80 >> (flipped % 8);
    assert_ne!(
        absent < present,
        bit(&absent, flipped) < bit(&present, flipped),
        "the keys' order is not the paths'"
    );
    let value = codec::to_bytes(&accounts[0].1);
    build_over(accounts.to_vec(), vec![(other, value)], 0)
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
    let mut arguments = instance.arguments.clone();
    arguments.rows[0].1.0[0] ^= 1;
    let refused = run(&arguments.encode());
    assert_eq!(refused.attest.output, vec![REFUSED_J].encode());
    traced(&refused);

    let mut arguments = instance.arguments.clone();
    let present = arguments
        .rows
        .iter()
        .position(|row| row.0.is_some())
        .unwrap();
    arguments.rows[present].0 = None;
    let refused = run(&arguments.encode());
    assert_eq!(refused.attest.output, vec![REFUSED_I].encode());
}

/// A proof tampered with or cut short is refused, and so are rows out of
/// key order, a value that does not decode, and rows `window` refuses.
#[test]
fn bad_proofs_and_rows_are_refused() {
    let instance = instance();
    let refused = |change: &dyn Fn(&mut Arguments)| {
        let mut arguments = instance.arguments.clone();
        change(&mut arguments);
        let kernel = run(&arguments.encode());
        traced(&kernel);
        kernel.attest.output
    };
    let status = |status: u8| vec![status].encode();
    // The last byte: of the last entry's hash or value commitment.
    let tampered = |proof: &mut Vec<u8>| {
        let last = proof.len() - 1;
        proof[last] ^= 1;
    };
    assert_eq!(refused(&|a| tampered(&mut a.proof_i)), status(REFUSED_I));
    assert_eq!(refused(&|a| tampered(&mut a.proof_j)), status(REFUSED_J));
    assert_eq!(
        refused(&|a| {
            a.proof_i.pop();
        }),
        status(REFUSED_I)
    );
    assert_eq!(
        refused(&|a| a.proof_j.truncate(a.proof_j.len() / 2)),
        status(REFUSED_J)
    );
    assert_eq!(refused(&|a| a.rows.swap(0, 1)), status(UNORDERED));
    assert_eq!(refused(&|a| a.rows[3].1.1.truncate(5)), status(MALFORMED));
    assert_eq!(
        refused(&|a| a.space = PEER),
        status(WINDOW + WindowError::SameSpace as u8)
    );
}

/// Claims whose paths end in the proof in the opposite of their keys'
/// order are accepted, as `vos_tree` accepts them: an absent key parting
/// from a subtree at a bit no branch splits on.
#[test]
fn claims_ending_out_of_key_order_are_accepted() {
    let instance = inversion();
    let arguments = &instance.arguments;
    let claims: Vec<(Vec<u8>, Option<[u8; 32]>)> = arguments
        .rows
        .iter()
        .map(|(at_i, at_j)| {
            let account: Account<Value> = codec::from_bytes(&at_j.1).expect("an account");
            let commitment = at_i
                .as_ref()
                .map(|(salt, value)| vos_tree::value_hash(&Blake2b, salt, value));
            (key(&account), commitment)
        })
        .collect();
    let proof = BatchProof::decode_exact(&arguments.proof_i).expect("a proof");
    proof
        .verify(&Blake2b, &arguments.root_i, &claims)
        .expect("vos_tree accepts");
    let kernel = run(&arguments.encode());
    assert_eq!(kernel.attest.output, instance.expected.encode());
    traced(&kernel);
}

/// The window's kernel re-runs from its attest to the window's statement,
/// proves over its shape cut at class 1's budgets, each segment at the
/// first class that holds it, and verifies as a chain against its program.
#[test]
fn the_window_proves_and_verifies_over_its_shape() {
    let started = Instant::now();
    let instance = instance();
    let kernel = run(&instance.arguments.encode());
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
    // No public arguments and no roots: the window's statement is bound
    // only through its output, the `NetFlow`'s fields.
    assert_eq!(
        io_hash,
        vos_pvm_precompiles::compute_io_hash(&[], &instance.expected.encode(), &[])
    );
}

/// Window `[a, b)` of the run proved at the first class of `program`'s
/// shape that holds it, as `prove_kernel` proves it, and the class.
fn prove_at_first_class(
    cursor: &mut SegmentCursor<'_>,
    (a, b): (usize, usize),
    program: &vos_pvm_proof::program_id::KernelProgram,
) -> (usize, Proof) {
    let steps = (b - a).next_power_of_two().trailing_zeros();
    for (class, sizes) in program.shape.classes.iter().enumerate() {
        if steps > u32::from(sizes.log_steps) {
            continue;
        }
        let shape = program.shape.segment(class).unwrap();
        match prove_shaped(&mut cursor.side_note(a, b), &shape, &SEGMENT) {
            Ok(proof) => return (class, proof),
            Err(ProvingError::Shape { .. }) => continue,
            Err(error) => panic!("{error}"),
        }
    }
    panic!("no class holds [{a}, {b})")
}

/// The window's kernel's leaves and folds: its program finalized with its
/// leaf circuits; its first four segments (the entry's, class 0, then
/// class-1 windows of the 32k cut) and its last (class 0, the halt), each
/// verified in its class's leaf as natively, the leaf within the padded
/// shape, proved and verified. The first states the entry, the last the
/// halt and the run's io-hash; the first's exit digest is the second's
/// entry digest. A class-1 leaf proves in at most 4 GiB of heap and in at
/// most the time of its segment's proving.
///
/// The first four leaves fold: two folds of two leaves, then a fold of the
/// two folds, the root of the run's first four segments, each within the
/// padded shape, proved and verified against the fold circuit's hash. The
/// root proves in at most 4 GiB of heap, as a leaf, and in at most the
/// time of a class-1 segment's proving.
#[test]
fn the_windows_leaves_and_folds_prove_and_verify() {
    let instance = instance();
    let kernel = run(&instance.arguments.encode());
    let trace = traced(&kernel);
    let ((program, entry), elapsed, peak) = common::measured(|| {
        vos_pvm_recair::leaf::kernel_program(
            &kernel.blob,
            &kernel.record,
            vos_pvm_compiler::TRANSPILER_VERSION,
            &SEGMENT,
        )
        .expect("the kernel's program")
    });
    eprintln!(
        "the program with its {} leaf circuits in {:.1}s, its peak heap {peak} MiB, id {:02x?}",
        program.shape.classes.len(),
        elapsed.as_secs_f64(),
        &program.id().to_bytes()[..8]
    );
    let cut = &program.shape.classes[CUT];
    let bounds =
        segment_bounds_budgeted(&trace.side_note, 1 << cut.log_steps, usize::from(cut.pages));
    let last = bounds.len() - 1;
    let fold = vos_pvm_recair::fold::FoldCircuit::new();
    let (word, elapsed, _) = common::measured(|| fold.hash());
    eprintln!("the fold circuit's hash in {:.1}s", elapsed.as_secs_f64());
    let mut cursor = SegmentCursor::new(&trace.side_note);
    let mut leaves = Vec::new();
    let mut slowest = std::time::Duration::ZERO;
    for position in [0, 1, 2, 3, last] {
        let ((class, proof), segment, segment_peak) =
            common::measured(|| prove_at_first_class(&mut cursor, bounds[position], &program));
        let leaf = common::prove_leaf(&program, &entry, class, &proof, position as u32, word);
        eprintln!(
            "segment {position} ({:?}, class {class}) proved in {:.2}s, its peak heap \
             {segment_peak} MiB; its leaf: {:?} rows ({:?} finalized), proved in {:.2}s ({:.2}× \
             the segment's), its peak heap {} MiB",
            bounds[position],
            segment.as_secs_f64(),
            leaf.rows,
            leaf.finalized,
            leaf.proving.as_secs_f64(),
            leaf.proving.as_secs_f64() / segment.as_secs_f64(),
            leaf.peak_mib,
        );
        if class == CUT {
            assert!(leaf.peak_mib <= 4 << 10, "{} MiB", leaf.peak_mib);
            assert!(
                leaf.proving <= segment,
                "{:?} against {segment:?}",
                leaf.proving
            );
            slowest = slowest.max(segment);
        }
        leaves.push((class, leaf));
    }
    let outputs: Vec<_> = leaves
        .iter()
        .map(|(class, leaf)| (*class, leaf.output))
        .collect();
    let [(_, first), (second_class, second), .., (_, end)] = outputs[..] else {
        unreachable!()
    };
    assert_eq!(second_class, CUT, "the second segment is a class-1 window");
    assert!(first.entry && !first.halt);
    assert!(!second.entry && !second.halt);
    assert!(!end.entry && end.halt);

    // The tree over the first four segments.
    let pairs = [
        common::prove_fold(&fold, &program, &leaves[0].1, &leaves[1].1, word),
        common::prove_fold(&fold, &program, &leaves[2].1, &leaves[3].1, word),
    ];
    let root = common::prove_fold(&fold, &program, &pairs[0], &pairs[1], word);
    for (name, run) in [
        ("the fold of leaves 0 and 1", &pairs[0]),
        ("the fold of leaves 2 and 3", &pairs[1]),
        ("the fold of the two folds", &root),
    ] {
        eprintln!(
            "{name}: {:?} rows ({:?} finalized), proved in {:.2}s, its peak heap {} MiB",
            run.rows,
            run.finalized,
            run.proving.as_secs_f64(),
            run.peak_mib,
        );
    }
    assert!(root.peak_mib <= 4 << 10, "{} MiB", root.peak_mib);
    assert!(
        root.proving <= slowest,
        "{:?} against {slowest:?}",
        root.proving
    );
    let root = root.output;
    assert_eq!((root.first, root.last), (0, 3));
    assert!(root.entry && !root.halt, "a prefix of the run");
    assert_eq!(root.entry_digest, first.entry_digest);
    assert_eq!(root.exit_digest, outputs[3].1.exit_digest);
    assert_eq!(root.program.0, program.id().0);
    assert_eq!(root.fold_word, word);
    assert_eq!(first.exit_digest, second.entry_digest);
    assert_eq!(end.io_hash, trace.io_hash);
}

/// The whole window, end to end: every segment proved in its class and
/// verified in its leaf, the leaves folded in adjacent pairs, an odd node
/// carried up, to one root stating the whole run (its entry, its halt, its
/// io-hash); the root wrapped under format 28 on the Blake2b-256 channel
/// within 2^17 rows and 8 GiB of heap, and verified by
/// `vos-pvm-final-verifier`, its statement the program's id and the run's
/// io-hash. The window's `vos_statement::Statement` (rootless, so of no
/// space: its space and anchors are in its output, which no venue checks;
/// its handler must) recomputes that io-hash, and a venue pinning the
/// program accepts it, natively and on the JAM-only host. The wrap's proof
/// (postcard), its public words (24 little-endian u32s) and the judgement's
/// input are written under the target's tmp directory,
/// `wrap/window.{proof,words,input}`, for the Wasm harness.
#[test]
fn the_window_wraps() {
    let instance = instance();
    let kernel = run(&instance.arguments.encode());
    let trace = traced(&kernel);
    let (program, entry) = vos_pvm_recair::leaf::kernel_program(
        &kernel.blob,
        &kernel.record,
        vos_pvm_compiler::TRANSPILER_VERSION,
        &SEGMENT,
    )
    .expect("the kernel's program");
    let cut = &program.shape.classes[CUT];
    let bounds =
        segment_bounds_budgeted(&trace.side_note, 1 << cut.log_steps, usize::from(cut.pages));
    let fold = vos_pvm_recair::fold::FoldCircuit::new();
    let word = vos_pvm_recair::fold::FoldCircuit::word();
    let started = Instant::now();
    let mut cursor = SegmentCursor::new(&trace.side_note);
    let mut nodes: Vec<common::NodeRun> = (0..bounds.len())
        .map(|position| {
            let (class, proof) = prove_at_first_class(&mut cursor, bounds[position], &program);
            common::prove_leaf(&program, &entry, class, &proof, position as u32, word)
        })
        .collect();
    eprintln!(
        "{} segments proved in their leaves in {:.0}s",
        nodes.len(),
        started.elapsed().as_secs_f64()
    );
    let started = Instant::now();
    let mut folds = 0;
    while nodes.len() > 1 {
        let mut level = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut pending = nodes.into_iter();
        while let Some(left) = pending.next() {
            match pending.next() {
                Some(right) => {
                    level.push(common::prove_fold(&fold, &program, &left, &right, word));
                    folds += 1;
                }
                None => level.push(left),
            }
        }
        nodes = level;
    }
    eprintln!("{folds} folds in {:.0}s", started.elapsed().as_secs_f64());
    let root = nodes.pop().expect("the root");
    let output = root.output;
    assert_eq!((output.first, output.last), (0, bounds.len() as u32 - 1));
    assert!(output.entry && output.halt, "the whole run");
    assert_eq!(output.io_hash, trace.io_hash);

    let (bytes, words) = common::wrap_root("the window", &program, &root);
    let input = common::judged_statement(
        vos_statement::Statement {
            format: vos_statement::FORMAT,
            program: vos_statement::ProgramId(program.id().0.map(|word| word.0)),
            // Rootless: of no space. The window's space and anchors are
            // in its output, for the handler to check.
            space: vos_statement::SpaceId::NONE,
            public_args: Vec::new(),
            output: instance.expected.encode(),
            roots: Vec::new(),
        },
        &trace.io_hash,
        &bytes,
    );
    common::write_wrap("window", &bytes, &words, &input);
}
