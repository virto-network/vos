//! A kernel leaf (`proving.md` §3.3, A.3) on a small kernel's run: a
//! standard program that sets its io-hash in φ9..12 and halts, traced from
//! the loader's layout and proved at its natural sizes under format 35, as
//! one segment and as two.
//!
//! - **The leaf states its segment:** no mismatch; its transcript the native
//!   recorder's permutation for permutation; its output digest the native
//!   [`NodeOutput`]'s, the entry and halt flags set, the io-hash φ9..12's;
//!   the wiring without values the filled one's; proved at the padded shape
//!   and verified; its own rows pinned, and its rows a derivation's count.
//! - **A cut run:** the first segment's leaf states the entry and not the
//!   halt, the second's the halt and not the entry, and the first's exit
//!   digest is the second's entry digest.
//! - **Each flag's conditions, negated, refused:** an entry flag over
//!   another entry pc, ts, register or image root, or over a segment that
//!   starts mid-run; a halt flag over a segment that does not end at the
//!   halt; a flag of two.
//! - **The boundary bytes:** a tampered byte is refused, and an io-hash byte
//!   of 256 is refused by its range check.

use std::sync::OnceLock;

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::{KernelTrace, trace_kernel};
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::{ENTRY_TIMESTAMP, HALT_PC};
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_proof::{Proof, RecursionData, extract_recursion_data, prove_canonical_format};
use vos_recair::leaf::{LeafCircuit, LeafValues, NodeOutput, PADDED_ROWS, State};
use vos_recair::verifier::SegmentShape;
use vos_recair::{Context, NoValue, Value};

/// The kernel's io-hash words, φ9..12; φ12's sign-extends, so its high
/// bytes are 0xff.
const IO: [u32; 4] = [0x4433_2211, 0x0807_0605, 0x7f00_00ff, 0x9abc_def0];

/// A standard program that sets φ8, the output's length, to 0 and φ9..12
/// to [`IO`], then returns to φ0, the halt address.
fn blob() -> Vec<u8> {
    let mut code = Vec::new();
    let mut bitmask = Vec::new();
    for (register, value) in [(8u8, 0u32)].into_iter().chain((9..13).zip(IO)) {
        code.extend_from_slice(&[51, register]);
        code.extend_from_slice(&value.to_le_bytes());
        bitmask.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
    }
    code.extend_from_slice(&[50, 0]);
    bitmask.extend_from_slice(&[1, 0]);
    vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 1,
        stack_size: 4096,
        code: vos_pvm_program::CodeBlob {
            jump_table: vec![],
            code,
            bitmask,
        },
    })
    .expect("a standard program")
}

/// The state the kernel's run starts at, from the loader's layout.
fn entry(blob: &[u8]) -> State {
    let program = vos_pvm_program::parse_standard_program(blob).expect("standard");
    State {
        registers: program.layout(&[]).expect("lays out").registers,
        pc: 0,
        timestamp: ENTRY_TIMESTAMP,
        memory_root: program.image_root().expect("an image root"),
    }
}

/// A segment's proof, its leaf circuit and the native verifier's record.
struct Segment {
    proof: Proof,
    leaf: LeafCircuit,
    data: RecursionData,
}

impl Segment {
    fn new(proof: Proof, entry: State) -> Self {
        let data = extract_recursion_data(&proof);
        let leaf = LeafCircuit::new(SegmentShape::of(&proof), entry);
        Self { proof, leaf, data }
    }

    /// Its values and output at position `position`, as an honest prover
    /// states them.
    fn values(&self, position: u32) -> (LeafValues<SecureField>, NodeOutput) {
        self.leaf
            .values(&self.proof, program_id(), fold_word(), position)
            .expect("the proof's values")
    }
}

fn program_id() -> P2Hash {
    P2Hash(core::array::from_fn(|i| BaseField::from(1_000 + i as u32)))
}

fn fold_word() -> P2Hash {
    P2Hash(core::array::from_fn(|i| BaseField::from(2_000 + i as u32)))
}

/// The run, whole and cut after its third step.
struct Run {
    trace: KernelTrace,
    whole: Segment,
    head: Segment,
    tail: Segment,
}

fn run() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| {
        let blob = blob();
        let trace = trace_kernel(&blob, &[], 1_000).expect("halts");
        let steps = trace.side_note.steps.len();
        assert_eq!(steps, 6);
        let entry = entry(&blob);
        let mut cursor = SegmentCursor::new(&trace.side_note);
        let [whole, head, tail] = [(0, steps), (0, 3), (3, steps)].map(|(a, b)| {
            let proof =
                prove_canonical_format(&mut cursor.side_note(a, b), &[], &SEGMENT).expect("proves");
            Segment::new(proof, entry)
        });
        Run {
            trace,
            whole,
            head,
            tail,
        }
    })
}

fn print_rows(name: &str, context: &Context<impl Value>) {
    eprintln!("{name}: {:?} rows (p2, qm31, h8)", context.rows());
    for (piece, rows) in context.piece_rows() {
        eprintln!("  {piece}: {rows:?}");
    }
}

/// The leaf's output digest over `values`, built strictly.
fn digest(leaf: &LeafCircuit, values: &LeafValues<SecureField>) -> [SecureField; 2] {
    let mut context = Context::<SecureField>::with_outputs(2);
    let wires = leaf.verify(&mut context, values);
    wires.digest.map(|wire| context.value(wire))
}

/// The leaf over `values`, lenient: the pieces of its mismatches, in order.
fn refusals(leaf: &LeafCircuit, values: &LeafValues<SecureField>) -> Vec<&'static str> {
    let mut context = Context::<SecureField>::with_outputs(2).lenient();
    let wires = leaf.verify(&mut context, values);
    context.set_outputs(&wires.digest);
    let mut pieces: Vec<&'static str> = context
        .mismatches()
        .iter()
        .map(|mismatch| mismatch.piece)
        .collect();
    pieces.dedup();
    pieces
}

fn m31(value: u32) -> SecureField {
    SecureField::from(BaseField::from(value))
}

/// The whole run's leaf verifies its segment as natively, states the
/// native output with both flags, proves at the padded shape and verifies.
#[test]
fn a_leaf_states_its_segment() {
    let run = run();
    let segment = &run.whole;
    let (values, output) = segment.values(7);
    assert!(output.entry && output.halt);
    assert_eq!(output.io_hash, run.trace.io_hash);
    assert_eq!(
        output.io_hash[..8],
        u64::from(IO[0]).to_le_bytes(),
        "φ9's bytes"
    );
    assert_eq!(
        output.io_hash[24..],
        (IO[3] as i32 as i64 as u64).to_le_bytes()
    );
    assert_eq!(
        output.entry_digest,
        State::from(&segment.proof.initial_state).digest()
    );
    assert_eq!(segment.proof.final_state.pc, HALT_PC);

    let mut context = Context::<SecureField>::with_outputs(2);
    let wires = segment.leaf.verify(&mut context, &values);
    context.set_outputs(&wires.digest);
    let digest = [
        context.value(wires.digest[0]),
        context.value(wires.digest[1]),
    ];
    assert_eq!(
        digest,
        vos_recair::verifier::witness::digest_wires(&output.digest())
    );
    assert_eq!(context.value(wires.entry.var()), SecureField::one());
    assert_eq!(context.value(wires.halt.var()), SecureField::one());
    print_rows("the small kernel's leaf", &context);

    // The transcript is the native recorder's, permutation for permutation.
    let mut transcript = Context::<SecureField>::new();
    let verified =
        vos_recair::verifier::verify_segment(&mut transcript, &segment.leaf.shape, &values.segment);
    let permutations = verified.channel.transcript().permutations();
    assert_eq!(permutations.len(), segment.data.transcript.records.len());
    for (i, (permutation, record)) in permutations
        .iter()
        .zip(&segment.data.transcript.records)
        .enumerate()
    {
        let words = record.output.map(|w| vos_pvm_poseidon2::M31::new(w.0));
        assert_eq!(
            *permutation,
            vos_recair::value::wires_of(words),
            "permutation {i}"
        );
    }

    // The leaf's own rows, past the segment's verification.
    let own = context.piece_rows();
    let rows = |piece: &str| own.get(piece).copied().unwrap_or_default();
    // The flags: 37 entry wires and pc out, two rows each; ts, four; the
    // scalars' wire, five.
    assert_eq!(rows("leaf: flags"), [0, 2 * 38 + 4 + 5, 0]);
    // 32 bytes of 13 rows (a limb, eight bits, four to recompose), and 16
    // limbs of two.
    assert_eq!(rows("leaf: io-hash"), [0, 32 * 13 + 16 * 2, 0]);
    // 19 permutations a digest.
    assert_eq!(rows("leaf: digests"), [38, 0, 0]);
    // Seven, and the outputs' two rows.
    assert_eq!(rows("leaf: output"), [7, 2, 0]);

    // A derivation's bound counts the rows exactly.
    let sizes: [u8; 25] = core::array::from_fn(|chip| {
        let mask = segment.proof.component_mask;
        let position = (mask & ((1 << chip) - 1)).count_ones() as usize;
        if mask & 1 << chip != 0 {
            segment.proof.log_sizes[position] as u8
        } else {
            0
        }
    });
    let terms = vos_pvm_compiler::leaf::leaf_terms(segment.proof.component_mask, &sizes);
    assert_eq!(terms.rows(), context.rows());

    let filled = context
        .finalize_to(Some(PADDED_ROWS))
        .expect("the wiring checks");
    let topology = segment.leaf.topology();
    assert_eq!(
        topology.circuit, filled.circuit,
        "the wiring without values"
    );
    let started = std::time::Instant::now();
    let proof = vos_recair::prove(&filled.circuit, &filled.witness).expect("proves");
    let proving = started.elapsed();
    let (_, hash) = vos_recair::circuit_commitment(&filled.circuit).unwrap();
    assert_eq!(
        segment.leaf.hash().0.map(|word| word.0),
        hash.map(|word| word.value()),
        "the leaf circuit's hash"
    );
    assert_eq!(
        proof.outputs,
        vos_recair::verifier::witness::digest_wires(&output.digest()).to_vec()
    );
    vos_recair::verify(proof, &hash).expect("verifies");
    eprintln!(
        "the small kernel's leaf, padded to 2^{:?}: proved in {:.2}s",
        filled.circuit.log_sizes(),
        proving.as_secs_f64()
    );
}

/// A run cut in two: the first segment's leaf states the entry, the
/// second's the halt and the io-hash, and they continue each other.
#[test]
fn a_cut_runs_leaves_continue_each_other() {
    let run = run();
    let (head_values, head) = run.head.values(0);
    let (tail_values, tail) = run.tail.values(1);
    assert!(head.entry && !head.halt);
    assert!(!tail.entry && tail.halt);
    assert_eq!(head.exit_digest, tail.entry_digest);
    assert_eq!(tail.io_hash, run.trace.io_hash);
    for (segment, values, output) in [
        (&run.head, &head_values, head),
        (&run.tail, &tail_values, tail),
    ] {
        assert!(refusals(&segment.leaf, values).is_empty());
        assert_eq!(
            digest(&segment.leaf, values),
            vos_recair::verifier::witness::digest_wires(&output.digest())
        );
    }
}

/// Each flag's conditions, negated, are refused by the leaf's checks.
#[test]
fn each_flags_conditions_negated_are_refused() {
    let run = run();
    let whole = &run.whole;
    let (values, _) = whole.values(0);
    assert!(refusals(&whole.leaf, &values).is_empty());
    let entry = whole.leaf.entry;
    type Change = fn(&mut State);
    let changes: [(&str, Change); 5] = [
        ("the entry pc", |state| state.pc += 1),
        ("the timestamp", |state| state.timestamp += 1),
        ("φ1, the stack's top", |state| state.registers[1] -= 8),
        ("φ8, the arguments' size", |state| state.registers[8] = 1),
        ("the image root", |state| state.memory_root[31] ^= 1),
    ];
    for (name, change) in changes {
        let mut other = entry;
        change(&mut other);
        let leaf = LeafCircuit::new(SegmentShape::of(&whole.proof), other);
        assert_eq!(refusals(&leaf, &values), ["leaf: flags"], "{name}");
        // Without the flag the segment states nothing about its entry.
        let mut unflagged = values.clone();
        unflagged.entry = m31(0);
        assert!(refusals(&leaf, &unflagged).is_empty(), "{name}");
    }

    // The tail starts mid-run; the head does not end at the halt.
    let (mut tail, _) = run.tail.values(1);
    tail.entry = m31(1);
    assert_eq!(refusals(&run.tail.leaf, &tail), ["leaf: flags"]);
    let (mut head, _) = run.head.values(0);
    head.halt = m31(1);
    assert_eq!(refusals(&run.head.leaf, &head), ["leaf: flags"]);

    // A flag of two.
    let mut two = values.clone();
    two.halt = m31(2);
    assert_eq!(refusals(&whole.leaf, &two), ["leaf: flags"]);
}

/// A tampered boundary byte is refused: the transcript moves, so the PoW
/// fails. An io-hash byte of 256 is refused by its range check as well.
#[test]
fn a_tampered_boundary_byte_is_refused() {
    let run = run();
    let whole = &run.whole;
    let (values, _) = whole.values(0);
    // φ9's first byte, wire 44's first lane: 0x11, then 0x12 and 0x111.
    for (delta, range_checked) in [(1, false), (256, true)] {
        let mut tampered = values.clone();
        tampered.segment.boundary[44] += m31(delta);
        let pieces = refusals(&whole.leaf, &tampered);
        assert_eq!(pieces.first(), Some(&"pow"), "{delta}: {pieces:?}");
        assert_eq!(
            pieces.contains(&"leaf: io-hash"),
            range_checked,
            "{delta}: {pieces:?}"
        );
    }
}

/// The leaf's topology, built without values, fits the padded shape.
#[test]
fn a_leaf_fits_the_padded_shape() {
    let leaf = &run().whole.leaf;
    let context = leaf.build(&LeafValues::<NoValue>::blank(&leaf.shape));
    let rows = context.rows();
    assert!(
        rows.iter()
            .zip(PADDED_ROWS)
            .all(|(&rows, padded)| rows <= padded)
    );
}
