//! A fold (`proving.md` §3.4, `recursion-air.md` §6) over a small kernel's
//! run, a standard program that sets its io-hash and halts, cut in four
//! segments proved at their natural sizes under format 35, each verified in
//! its leaf and the leaves proved at the padded shape.
//!
//! - **A fold of two leaves** verifies both children as natively (each
//!   child's transcript the native recorder's, permutation for
//!   permutation), states the native [`NodeOutput::fold`], proves at the
//!   padded shape and verifies against the fold circuit's hash.
//! - **A tree over the four segments:** two folds of two leaves, then a fold
//!   of the two folds, its children's circuit hash W; the root states the
//!   whole run, its entry, its halt and its io-hash. Its wiring without
//!   values is the filled one's, and its rows fit the padded shape.
//! - **Refusals, each by its intended check:** a wrong program and a leaf
//!   carrying a wrong program id (`fold: program`); a gap (`fold:
//!   adjacency`), and the same leaf as both children; broken continuity
//!   (`fold: continuity`), and one segment relabelled at two adjacent
//!   positions; a wrong child circuit and a child carrying a foreign W
//!   (`fold: circuit`); a tampered child preimage, and a prefix or a mid-run
//!   start claiming the flag its run lacks (`fold: preimage`). A prefix and a mid-run start state no
//!   halt and no entry, which the wrap refuses. A refused fold, proved, does
//!   not verify.
//! - **A tampered child proof** is refused by the check the native verifier
//!   refuses it with.
//! - **The fixed point:** the fold's rows, pinned by piece, fit under half
//!   of each of the padded shape's components.

use crate::common;

use std::sync::OnceLock;

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_proof::Proof;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::{IdPreimage, LeafCircuits};
use vos_pvm_proof::prove_canonical_format;
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_recair::fold::child::{self, verify_child};
use vos_pvm_recair::fold::{FoldCircuit, FoldValues};
use vos_pvm_recair::leaf::{LeafCircuit, NodeOutput, PADDED_ROWS, State, preimage};
use vos_pvm_recair::tree::{self, Node};
use vos_pvm_recair::verifier::SegmentShape;
use vos_pvm_recair::verifier::witness::digest_wires;
use vos_pvm_recair::{Context, NoValue};

use crate::common::{assert_transcript_is, print_rows};
use common::kernel::{blob, entry};

/// The run's segments, their leaves, the program and the fold circuit.
struct Run {
    entry: State,
    segments: Vec<Proof>,
    leaves: Vec<LeafCircuit>,
    program: IdPreimage,
    fold: FoldCircuit,
    /// The fold circuit's hash, every node's W.
    word: P2Hash,
}

/// The run and the tree over it.
struct Tree {
    run: Run,
    /// Each segment's leaf, proved at its position under the program.
    leaves: Vec<Node>,
    /// The folds of leaves 0 and 1, and of 2 and 3.
    folds: [Node; 2],
}

/// The run's cuts: four segments.
const CUTS: [(usize, usize); 4] = [(0, 1), (1, 3), (3, 5), (5, 6)];

fn id(program: &IdPreimage) -> P2Hash {
    P2Hash(program.id().0)
}

impl Run {
    fn new() -> Self {
        let blob = blob();
        let trace = trace_kernel(&blob, &[], 1_000).expect("halts");
        assert_eq!(trace.side_note.steps.len(), 6);
        let entry = entry(&blob);
        let mut cursor = SegmentCursor::new(&trace.side_note);
        let segments: Vec<Proof> = CUTS
            .iter()
            .map(|&(a, b)| {
                prove_canonical_format(&mut cursor.side_note(a, b), &[], &SEGMENT).expect("proves")
            })
            .collect();
        let leaves: Vec<LeafCircuit> = segments
            .iter()
            .map(|proof| LeafCircuit::new(SegmentShape::of(proof), entry))
            .collect();
        let mut hashes: Vec<P2Hash> = Vec::new();
        for leaf in &leaves {
            let hash = leaf.hash();
            if !hashes.contains(&hash) {
                hashes.push(hash);
            }
        }
        let program = IdPreimage {
            kernel: P2Hash(core::array::from_fn(|i| BaseField::from(3_000 + i as u32))),
            leaf_circuits: LeafCircuits::Hashes(hashes),
        };
        let fold = FoldCircuit::new();
        let word = fold.hash();
        Self {
            entry,
            segments,
            leaves,
            program,
            fold,
            word,
        }
    }

    /// Segment `segment`'s leaf at `position`, under the program id
    /// `program` and the fold word `word`, proved.
    fn leaf(&self, segment: usize, position: u32, program: P2Hash, word: P2Hash) -> Node {
        tree::leaf(
            &self.leaves[segment],
            &self.segments[segment],
            program,
            word,
            position,
        )
        .expect("proves")
    }

    /// Segment `segment`'s leaf at its position, under the program.
    fn honest_leaf(&self, segment: usize) -> Node {
        self.leaf(segment, segment as u32, id(&self.program), self.word)
    }

    /// The fold of `left` and `right` under `program`, the run's W: its
    /// values and output.
    fn values(
        &self,
        left: &Node,
        right: &Node,
        program: &IdPreimage,
    ) -> (FoldValues<SecureField>, NodeOutput) {
        self.fold
            .values(left.proved(), right.proved(), program, self.word)
            .expect("the children's values")
    }

    /// The fold of `left` and `right` under the run's program, proved.
    fn node(&self, left: &Node, right: &Node) -> Node {
        tree::fold(&self.fold, left, right, &self.program, self.word).expect("proves")
    }
}

fn tree() -> &'static Tree {
    static TREE: OnceLock<Tree> = OnceLock::new();
    TREE.get_or_init(|| {
        let run = Run::new();
        let leaves: Vec<Node> = (0..CUTS.len()).map(|s| run.honest_leaf(s)).collect();
        let folds = [
            run.node(&leaves[0], &leaves[1]),
            run.node(&leaves[2], &leaves[3]),
        ];
        Tree { run, leaves, folds }
    })
}

/// The fold over `values`, lenient: the pieces of its mismatches, in order.
fn refusals(fold: &FoldCircuit, values: &FoldValues<SecureField>) -> Vec<&'static str> {
    let mut context = Context::<SecureField>::with_outputs(2).lenient();
    let digest = fold.verify(&mut context, values);
    context.set_outputs(&digest);
    let mut pieces: Vec<&'static str> = context
        .mismatches()
        .iter()
        .map(|mismatch| mismatch.piece)
        .collect();
    pieces.dedup();
    pieces
}

fn digest_of(hash: &P2Hash) -> vos_pvm_poseidon2::Digest {
    (*hash).into()
}

/// The fold of the first two leaves verifies each child as natively,
/// states the native output, proves and verifies against W.
#[test]
fn a_fold_of_two_leaves_states_their_run() {
    let tree = tree();
    let run = &tree.run;
    let [left, right] = [&tree.leaves[0], &tree.leaves[1]];
    let (values, output) = run.values(left, right, &run.program);
    assert_eq!(output, NodeOutput::fold(&left.output, &right.output));
    assert_eq!((output.first, output.last), (0, 1));
    assert!(output.entry && !output.halt);
    assert_eq!(output.program, id(&run.program));
    assert_eq!(output.fold_word, run.word);

    // Each child's transcript is the native recorder's.
    for (child, node) in values.children.iter().zip([left, right]) {
        let data = child::recursion_data(run.fold.child, &node.proof).expect("a child");
        let mut context = Context::<SecureField>::new();
        let outputs = context.guess_pair(child.output);
        let verified = verify_child(&mut context, run.fold.child, &child.proof, outputs);
        assert_transcript_is(verified.channel.transcript(), &data.transcript);
    }

    let mut context = Context::<SecureField>::with_outputs(2);
    let digest = run.fold.verify(&mut context, &values);
    context.set_outputs(&digest);
    assert_eq!(
        digest.map(|wire| context.value(wire)),
        digest_wires(&output.digest())
    );
    print_rows("a fold of two leaves", &context);

    let fold = &tree.folds[0];
    assert_eq!(fold.output, output);
    assert_eq!(fold.proof.outputs, digest_wires(&output.digest()).to_vec());
    vos_pvm_recair::verify(fold.proof.clone(), &digest_of(&run.word)).expect("verifies");
}

/// A tree over the four segments: a fold of the two folds states the whole
/// run, fits the padded shape, is the fold circuit, and proves and
/// verifies.
#[test]
fn a_tree_over_four_segments_states_the_run() {
    let tree = tree();
    let run = &tree.run;
    let [left, right] = &tree.folds;
    let (values, output) = run.values(left, right, &run.program);
    let [first, .., last] = &tree.leaves[..] else {
        unreachable!()
    };
    assert_eq!((output.first, output.last), (0, 3));
    assert!(output.entry && output.halt);
    assert_eq!(output.entry_digest, first.output.entry_digest);
    assert_eq!(output.exit_digest, last.output.exit_digest);
    assert_eq!(output.io_hash, last.output.io_hash);
    assert_eq!(output.entry_digest, run.entry.digest());

    let context = run.fold.build(&values);
    print_rows("a fold of two folds", &context);
    let rows = context.finalized_rows();
    for (component, (rows, padded)) in ["p2", "qm31", "h8"]
        .iter()
        .zip(rows.iter().zip(PADDED_ROWS))
    {
        eprintln!(
            "  {component}: {rows} of {padded} finalized, {:.1}%",
            100.0 * *rows as f64 / padded as f64
        );
        assert!(*rows <= padded, "{component}");
    }
    let filled = context.finalize_to(Some(PADDED_ROWS)).expect("checks");
    assert_eq!(
        run.fold.topology().circuit,
        filled.circuit,
        "the wiring without values"
    );
    let (_, hash) = vos_pvm_recair::circuit_commitment(&filled.circuit).expect("checks");
    assert_eq!(hash, digest_of(&run.word), "the fold circuit's hash");
    let started = std::time::Instant::now();
    let proof = vos_pvm_recair::prove(&filled.circuit, &filled.witness).expect("proves");
    eprintln!(
        "a fold of two folds proved in {:.2}s",
        started.elapsed().as_secs_f64()
    );
    assert_eq!(proof.outputs, digest_wires(&output.digest()).to_vec());
    vos_pvm_recair::verify(proof, &hash).expect("verifies");
}

/// The program: a wrong one, a leaf carrying a wrong program id, and a
/// leaf whose circuit is not among the program's.
#[test]
fn a_wrong_program_or_circuit_is_refused() {
    let tree = tree();
    let run = &tree.run;
    let [left, right] = [&tree.leaves[0], &tree.leaves[1]];
    let (values, _) = run.values(left, right, &run.program);
    assert!(refusals(&run.fold, &values).is_empty());

    // Another kernel's digest, the same leaf circuits.
    let wrong = IdPreimage {
        kernel: P2Hash(core::array::from_fn(|i| BaseField::from(4_000 + i as u32))),
        ..run.program.clone()
    };
    let (values, _) = run.values(left, right, &wrong);
    assert_eq!(refusals(&run.fold, &values), ["fold: program"]);

    // A program without the first leaf's circuit.
    let hashes = run.program.leaf_circuits.hashes();
    let first = run.leaves[0].hash();
    let short = IdPreimage {
        kernel: run.program.kernel,
        leaf_circuits: LeafCircuits::Hashes(
            hashes
                .iter()
                .copied()
                .filter(|&hash| hash != first)
                .collect(),
        ),
    };
    let short_left = run.leaf(0, 0, id(&short), run.word);
    // A leaf carrying the short program's id, under the run's program.
    let (values, _) = run.values(&short_left, right, &run.program);
    assert_eq!(refusals(&run.fold, &values), ["fold: program"]);
    // Under the short program, the first leaf's circuit is none of its
    // (nor the second's, at the same sizes).
    let short_right = run.leaf(1, 1, id(&short), run.word);
    let (values, _) = run.values(&short_left, &short_right, &short);
    assert_eq!(refusals(&run.fold, &values), ["fold: circuit"]);
}

/// The fold word: a child carrying a foreign W, and a child claiming a
/// circuit its hash is not.
#[test]
fn a_foreign_fold_word_or_a_wrong_choice_is_refused() {
    let tree = tree();
    let run = &tree.run;
    let foreign = P2Hash(core::array::from_fn(|i| BaseField::from(5_000 + i as u32)));
    let left = run.leaf(0, 0, id(&run.program), foreign);
    let (values, _) = run.values(&left, &tree.leaves[1], &run.program);
    assert_eq!(refusals(&run.fold, &values), ["fold: circuit"]);

    // A fold child claiming to be the program's first leaf circuit, and a
    // leaf claiming to be W.
    let [fold_left, fold_right] = &tree.folds;
    let (values, _) = run.values(fold_left, fold_right, &run.program);
    assert!(refusals(&run.fold, &values).is_empty());
    let mut claimed = values.clone();
    claimed.children[0].circuit.rotate_left(1);
    assert_eq!(refusals(&run.fold, &claimed), ["fold: circuit"]);
    let (values, _) = run.values(&tree.leaves[0], &tree.leaves[1], &run.program);
    let mut claimed = values.clone();
    claimed.children[1].circuit.rotate_right(1);
    assert_eq!(refusals(&run.fold, &claimed), ["fold: circuit"]);
    // No circuit at all, and two.
    let mut none = values.clone();
    none.children[0].circuit = [SecureField::default(); vos_pvm_recair::fold::CIRCUITS];
    assert_eq!(refusals(&run.fold, &none), ["fold: circuit"]);
    let mut two = values.clone();
    two.children[0].circuit[vos_pvm_recair::fold::CIRCUITS - 1] =
        SecureField::from(BaseField::from(1));
    assert_eq!(refusals(&run.fold, &two), ["fold: circuit"]);
}

/// The run: a gap between the children's positions, children that do not
/// continue each other, the same leaf as both children, and the same
/// segment relabelled at two adjacent positions, refused in the circuit
/// and, proved, by the fold's verifier.
#[test]
fn a_gap_or_broken_continuity_is_refused() {
    let tree = tree();
    let run = &tree.run;
    let left = &tree.leaves[0];
    // The second segment at position 2.
    let gap = run.leaf(1, 2, id(&run.program), run.word);
    let (values, _) = run.values(left, &gap, &run.program);
    assert_eq!(refusals(&run.fold, &values), ["fold: adjacency"]);
    // The third segment at position 1.
    let skip = run.leaf(2, 1, id(&run.program), run.word);
    let (values, _) = run.values(left, &skip, &run.program);
    assert_eq!(refusals(&run.fold, &values), ["fold: continuity"]);

    // The same leaf as both children: its position does not follow itself.
    let (values, _) = run.values(left, left, &run.program);
    assert_eq!(
        refusals(&run.fold, &values),
        ["fold: adjacency", "fold: continuity"]
    );
    // The same segment relabelled at positions 1 and 2: adjacent, but its
    // exit is not its own entry.
    let relabelled = run.leaf(1, 2, id(&run.program), run.word);
    let (values, _) = run.values(&tree.leaves[1], &relabelled, &run.program);
    assert_eq!(refusals(&run.fold, &values), ["fold: continuity"]);

    // The third segment at position 1, again.
    let (values, _) = run.values(left, &skip, &run.program);
    // Proved, the refused witness does not verify as the fold circuit: its
    // `Gate` relation does not balance.
    let mut context = Context::<SecureField>::with_outputs(2).lenient();
    let digest = run.fold.verify(&mut context, &values);
    context.set_outputs(&digest);
    let finalized = context
        .finalize_to(Some(PADDED_ROWS))
        .expect("the wiring checks");
    let refused = match vos_pvm_recair::prove(&finalized.circuit, &finalized.witness) {
        Err(_) => true,
        Ok(proof) => vos_pvm_recair::verify(proof, &digest_of(&run.word)).is_err(),
    };
    assert!(refused, "a broken fold proves and verifies");
}

/// A prefix states no halt, and a run started mid-way no entry: the fold
/// takes each flag from its side alone, so the wrap, which refuses a root
/// without both, refuses them. A child's preimage claiming the flag is
/// refused by its re-hash, as is any tampered preimage word.
#[test]
fn a_prefix_or_a_mid_run_start_states_no_flag() {
    let tree = tree();
    let run = &tree.run;
    let leaves = &tree.leaves;
    let (prefix, output) = run.values(&leaves[0], &leaves[1], &run.program);
    assert!(refusals(&run.fold, &prefix).is_empty());
    assert!(output.entry && !output.halt, "a prefix");
    let (middle, output) = run.values(&leaves[1], &leaves[2], &run.program);
    assert!(refusals(&run.fold, &middle).is_empty());
    assert!(!output.entry && !output.halt, "a run started mid-way");
    let (suffix, output) = run.values(&leaves[2], &leaves[3], &run.program);
    assert!(refusals(&run.fold, &suffix).is_empty());
    assert!(!output.entry && output.halt, "a suffix");

    // The flags' lanes of `[first, last, entry, halt]`.
    let set = |values: &FoldValues<SecureField>, child: usize, lane: usize| {
        let mut values = values.clone();
        let mut limbs = [BaseField::from(0); 4];
        limbs[lane] = BaseField::from(1);
        values.children[child].preimage[preimage::SCALARS] += SecureField::from_m31_array(limbs);
        values
    };
    assert_eq!(refusals(&run.fold, &set(&prefix, 1, 3)), ["fold: preimage"]);
    assert_eq!(refusals(&run.fold, &set(&middle, 0, 2)), ["fold: preimage"]);

    // A tampered preimage word: an io-hash limb, the exit digest.
    for wire in [preimage::IO_HASH.start, preimage::EXIT_DIGEST.end - 1] {
        let mut tampered = suffix.clone();
        tampered.children[1].preimage[wire] += SecureField::from(BaseField::from(1));
        assert_eq!(refusals(&run.fold, &tampered), ["fold: preimage"]);
    }
}

/// The fixed point: a fold of two children of the padded shape fits the
/// padded shape, about half its `p2` rows, a third of its `qm31` rows and
/// a sixteenth of its `h8` rows. Its rows by piece are pinned, a child's
/// verification twice and the fold's own work, so a change that moves the
/// fold's cost is seen here.
#[test]
fn the_folds_rows_are_pinned() {
    let fold = FoldCircuit::new();
    let context = fold.build(&FoldValues::<NoValue>::blank(fold.child));
    let pieces: Vec<(&str, [usize; 3])> = context
        .piece_rows()
        .iter()
        .map(|(&piece, &rows)| (piece, rows))
        .collect();
    assert_eq!(
        pieces,
        [
            ("channel", [602, 0, 0]),
            ("circle", [0, 6_248, 0]),
            ("context", [0, 2, 0]),
            ("deep", [0, 14_432, 4_048]),
            ("deep once", [0, 2_216, 0]),
            ("fold: adjacency", [0, 2, 0]),
            ("fold: circuit", [10, 58, 0]),
            ("fold: continuity", [0, 2, 0]),
            ("fold: output", [7, 4, 0]),
            ("fold: preimage", [14, 4, 0]),
            ("fold: program", [6, 4, 0]),
            ("fri", [19_448, 8_800, 0]),
            ("logup", [0, 48, 0]),
            ("merkle", [12_056, 0, 0]),
            ("oods", [0, 4_908, 0]),
            ("pow", [12, 504, 0]),
            ("queries", [12, 5_632, 0]),
        ]
    );
    assert_eq!(context.rows(), [32_167, 42_864, 4_048]);
    let finalized = context.finalized_rows();
    assert_eq!(finalized, [32_167, 42_896, 4_048]);
    assert!(
        finalized
            .iter()
            .zip(PADDED_ROWS)
            .all(|(&rows, padded)| 2 * rows < padded),
        "under half of every component"
    );
}

/// A tampered child proof is refused by the check the native verifier
/// refuses it with: the fold's first mismatch.
#[test]
fn a_tampered_child_proof_is_refused() {
    let tree = tree();
    let run = &tree.run;
    let (values, _) = run.values(&tree.leaves[0], &tree.leaves[1], &run.program);
    let one = SecureField::from(BaseField::from(1));
    type Tamper = fn(&mut FoldValues<SecureField>, SecureField);
    let tampers: [(&str, &str, Tamper); 10] = [
        ("the preprocessed root", "pow", |v, d| {
            v.children[0].proof.preprocessed_root[1] += d
        }),
        ("the main root", "pow", |v, d| {
            v.children[0].proof.stark.roots[0][0] += d
        }),
        ("an output wire", "pow", |v, d| v.children[0].output[1] += d),
        ("the interaction nonce", "pow", |v, d| {
            v.children[0].proof.stark.interaction_nonce += d
        }),
        ("a claimed sum", "logup", |v, d| {
            v.children[0].proof.stark.claimed_sums[1] += d
        }),
        ("the composition root", "oods", |v, d| {
            v.children[0].proof.stark.roots[2][1] += d
        }),
        ("a sampled value", "oods", |v, d| {
            v.children[0].proof.stark.sampled[100] += d
        }),
        ("the PoW nonce", "pow", |v, d| {
            v.children[0].proof.stark.nonce += d
        }),
        ("a queried value", "merkle", |v, d| {
            v.children[0].proof.stark.queries[5].trees[1].leaf[7] += d
        }),
        ("a FRI sibling", "fri", |v, d| {
            v.children[0].proof.stark.queries[2].fri[4].sibling += d
        }),
    ];
    for (name, piece, tamper) in tampers {
        let mut tampered = values.clone();
        tamper(&mut tampered, one);
        let pieces = refusals(&run.fold, &tampered);
        assert_eq!(pieces.first(), Some(&piece), "{name}: {pieces:?}");
    }
}
