//! The final wrap (`proving.md` §3.5, `recursion-air.md` §7) over a small
//! kernel's run, a standard program that sets its io-hash and halts: as one
//! segment, whose leaf is the root, and cut in four segments, whose leaves
//! fold to the root. Each root is wrapped, proved under format 28 on the
//! Blake2b-256 channel and verified by `vos-pvm-final-verifier`.
//!
//! - **The circuit is pinned:** its log sizes and preprocessed root are the
//!   final verifier's constants, its rows by piece, within 2^17.
//! - **Refusals, each by its intended check:** a root without the entry flag
//!   or the halt flag, or with `first` other than 0 (`wrap: run`); a root
//!   carrying a foreign W, or whose circuit is none of the program's
//!   (`wrap: circuit`); a root carrying another program's id (`wrap:
//!   program`); a tampered root proof, by the check the native verifier
//!   refuses it with. A refused wrap, proved, does not verify.
//! - **The final verifier refuses** a tampered wrap proof, on FRI at fold
//!   step 3 and on the Blake2b-256 trees and channel, and every malformed
//!   shape cleanly, with an error.
//! - **On the JAM-only host** the final verifier, a refine program
//!   (`final-verify.elf`, built by `just check-no-std`), accepts the wrap
//!   within 150M gas, and refuses a tampered one or other words.

use crate::common;
use crate::jam;

use std::sync::OnceLock;
use std::time::Instant;

use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriVerificationError;
use stwo::core::poly::line::LinePoly;
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use stwo::core::vcs_lifted::verifier::MerkleVerificationError;
use stwo::core::verifier::VerificationError;
use vos_pvm_final_verifier::{Error, PUBLIC_WORDS, Statement, WrapProof, unmasked};
use vos_pvm_proof::Proof;
use vos_pvm_proof::format::{SEGMENT, WRAP};
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::{IdPreimage, LeafCircuits};
use vos_pvm_proof::prove_canonical_format;
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_recair::fold::FoldCircuit;
use vos_pvm_recair::leaf::{LeafCircuit, io_hash_of};
use vos_pvm_recair::tree::{self, Node};
use vos_pvm_recair::verifier::SegmentShape;
use vos_pvm_recair::wrap::{self, WrapCircuit, WrapValues};
use vos_pvm_recair::{Context, NoValue};

use common::kernel::{blob, entry};

/// The four segments' cuts, as the fold's test cuts them.
const CUTS: [(usize, usize); 4] = [(0, 1), (1, 3), (3, 5), (5, 6)];
/// The whole run, one segment.
const WHOLE: (usize, usize) = (0, 6);

/// A run's segments under a program of their leaves' circuits.
pub(crate) struct Run {
    segments: Vec<Proof>,
    leaves: Vec<LeafCircuit>,
    pub(crate) program: IdPreimage,
}

fn program_of(leaves: &[LeafCircuit], kernel: u32) -> IdPreimage {
    let mut hashes: Vec<P2Hash> = Vec::new();
    for leaf in leaves {
        let hash = leaf.hash();
        if !hashes.contains(&hash) {
            hashes.push(hash);
        }
    }
    IdPreimage {
        kernel: P2Hash(core::array::from_fn(|i| BaseField::from(kernel + i as u32))),
        leaf_circuits: LeafCircuits::Hashes(hashes),
    }
}

fn id(program: &IdPreimage) -> P2Hash {
    P2Hash(program.id().0)
}

impl Run {
    fn new(cuts: &[(usize, usize)], kernel: u32) -> Self {
        let blob = blob();
        let trace = trace_kernel(&blob, &[], 1_000).expect("halts");
        let entry = entry(&blob);
        let mut cursor = SegmentCursor::new(&trace.side_note);
        let segments: Vec<Proof> = cuts
            .iter()
            .map(|&(a, b)| {
                prove_canonical_format(&mut cursor.side_note(a, b), &[], &SEGMENT).expect("proves")
            })
            .collect();
        let leaves: Vec<LeafCircuit> = segments
            .iter()
            .map(|proof| LeafCircuit::new(SegmentShape::of(proof), entry))
            .collect();
        let program = program_of(&leaves, kernel);
        Self {
            segments,
            leaves,
            program,
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

    fn honest_leaf(&self, segment: usize, position: u32) -> Node {
        self.leaf(segment, position, id(&self.program), FoldCircuit::word())
    }

    fn fold(&self, left: &Node, right: &Node) -> Node {
        tree::fold(
            &FoldCircuit::new(),
            left,
            right,
            &self.program,
            FoldCircuit::word(),
        )
        .expect("proves")
    }
}

/// A wrap, proved: its proof, its public words and its statement.
pub(crate) struct Wrapped {
    pub(crate) proof: WrapProof,
    pub(crate) words: [u32; PUBLIC_WORDS],
    pub(crate) statement: Statement,
}

/// Wraps `root` under `program`, proves it and verifies it natively.
fn wrapped(root: &Node, program: &IdPreimage, name: &str) -> Wrapped {
    let started = Instant::now();
    let (proof, statement, words) =
        tree::wrap_with(root, program, wrap::prove_unmasked).expect("proves");
    assert_eq!(words, statement.words());
    let bytes = postcard::to_allocvec(&proof).expect("encodes");
    eprintln!(
        "{name}: the wrap proved in {:.2}s, {} bytes",
        started.elapsed().as_secs_f64(),
        bytes.len()
    );
    assert_eq!(
        unmasked::verify_bytes(&bytes, &words).expect("verifies"),
        statement
    );
    Wrapped {
        proof,
        words,
        statement,
    }
}

/// The whole run as one segment, its leaf at position 0, and its wrap.
pub(crate) struct OneSegment {
    pub(crate) run: Run,
    pub(crate) root: Node,
    pub(crate) wrapped: Wrapped,
}

pub(crate) fn one_segment() -> &'static OneSegment {
    static ONE: OnceLock<OneSegment> = OnceLock::new();
    ONE.get_or_init(|| {
        let run = Run::new(&[WHOLE], 6_000);
        let root = run.honest_leaf(0, 0);
        let wrapped = wrapped(&root, &run.program, "one segment");
        OneSegment { run, root, wrapped }
    })
}

/// The run cut in four segments, under a program of their leaves.
fn four_segments() -> &'static Run {
    static FOUR: OnceLock<Run> = OnceLock::new();
    FOUR.get_or_init(|| Run::new(&CUTS, 7_000))
}

/// The wrap over `values`, lenient: the pieces of its mismatches, in order.
fn refusals(values: &WrapValues<SecureField>) -> Vec<&'static str> {
    let wrap = WrapCircuit::get();
    let mut context = Context::<SecureField>::with_layout(wrap::LAYOUT).lenient();
    let lanes = wrap.verify(&mut context, values);
    context.set_output_lanes(&lanes);
    let mut pieces: Vec<&'static str> = context
        .mismatches()
        .iter()
        .map(|mismatch| mismatch.piece)
        .collect();
    pieces.dedup();
    pieces
}

/// The wrap's values over `root` under `program`.
pub(crate) fn values_of(root: &Node, program: &IdPreimage) -> WrapValues<SecureField> {
    WrapCircuit::get()
        .values(root.proved(), program)
        .expect("the root's values")
        .0
}

/// The circuit: its log sizes and preprocessed root the final verifier's,
/// its rows by piece, the tallest component 2^15, within 2^17; format 28's
/// entry the final verifier's constants.
#[test]
fn the_wrap_circuit_is_pinned() {
    let wrap = WrapCircuit::get();
    let context = wrap.build(&WrapValues::<NoValue>::blank(wrap.root));
    let pieces: Vec<(&str, [usize; 3])> = context
        .piece_rows()
        .iter()
        .map(|(&piece, &rows)| (piece, rows))
        .collect();
    assert_eq!(
        pieces,
        [
            ("channel", [301, 0, 0]),
            ("circle", [0, 3_124, 0]),
            ("context", [0, 2, 0]),
            ("deep", [0, 7_216, 2_024]),
            ("deep once", [0, 1_108, 0]),
            ("fri", [9_724, 4_400, 0]),
            ("logup", [0, 24, 0]),
            ("merkle", [6_028, 0, 0]),
            ("oods", [0, 2_454, 0]),
            ("pow", [6, 252, 0]),
            ("queries", [6, 2_816, 0]),
            ("wrap: circuit", [5, 29, 0]),
            ("wrap: preimage", [7, 2, 0]),
            ("wrap: program", [6, 2, 0]),
            ("wrap: public", [0, 24, 0]),
            ("wrap: run", [0, 3, 0]),
        ]
    );
    assert_eq!(context.finalized_rows(), [16_083, 21_489, 2_024]);
    let topology = wrap.topology();
    assert_eq!(
        topology.circuit.log_sizes(),
        vos_pvm_final_verifier::LOG_SIZES
    );
    assert!(topology.circuit.log_sizes().iter().all(|&log| log <= 17));
    assert_eq!(
        wrap.preprocessed_root(),
        Blake2bHash(vos_pvm_final_verifier::PREPROCESSED_ROOT)
    );

    assert_eq!(WRAP.number, unmasked::FORMAT);
    assert_eq!(WRAP.pcs_config(), unmasked::CONFIG);
    assert_eq!(WRAP.interaction_pow_bits(), unmasked::INTERACTION_POW_BITS);
    assert_eq!(wrap.fold_word, FoldCircuit::new().hash());
}

/// A run of one segment wraps through its leaf: the wrap states its
/// program id and io-hash, and the final verifier refuses other words.
#[test]
fn a_one_segment_run_wraps_through_its_leaf() {
    let one = one_segment();
    let output = &one.root.output;
    assert!(output.entry && output.halt && output.first == 0);
    let statement = one.wrapped.statement;
    assert_eq!(statement.program, id(&one.run.program).0.map(|word| word.0));
    let io = common::kernel::IO;
    let registers: [u64; 13] = core::array::from_fn(|i| match i {
        9..=11 => u64::from(io[i - 9]),
        12 => i64::from(io[3] as i32) as u64,
        _ => 0,
    });
    assert_eq!(statement.io_hash, io_hash_of(&registers));
    assert!(refusals(&values_of(&one.root, &one.run.program)).is_empty());

    for word in [0, 7, 8, 23] {
        let mut words = one.wrapped.words;
        words[word] ^= 1;
        let error = unmasked::verify(one.wrapped.proof.clone(), &words).unwrap_err();
        // The words are mixed before the interaction PoW, so another word
        // moves the transcript: the nonce falls short, or, past it, the
        // public terms do not balance.
        assert!(
            matches!(error, Error::InteractionPow | Error::Logup),
            "word {word}: {error}"
        );
    }
}

/// A tree over four segments wraps through its root fold.
#[test]
fn a_tree_root_wraps() {
    let run = four_segments();
    let leaves: Vec<Node> = (0..CUTS.len())
        .map(|s| run.honest_leaf(s, s as u32))
        .collect();
    let folds = [
        run.fold(&leaves[0], &leaves[1]),
        run.fold(&leaves[2], &leaves[3]),
    ];
    let root = run.fold(&folds[0], &folds[1]);
    assert!(root.output.entry && root.output.halt);
    assert_eq!((root.output.first, root.output.last), (0, 3));
    let wrapped = wrapped(&root, &run.program, "four segments");
    assert_eq!(wrapped.statement.program, id(&run.program).0.map(|w| w.0));
    assert_eq!(
        wrapped.statement.io_hash,
        one_segment().wrapped.statement.io_hash
    );
}

/// The run: a root without the entry flag, without the halt flag, or at a
/// first position other than 0.
#[test]
fn a_root_without_its_ends_is_refused() {
    let run = four_segments();
    // The first segment alone: its entry, no halt.
    let head = run.honest_leaf(0, 0);
    assert!(head.output.entry && !head.output.halt);
    assert_eq!(refusals(&values_of(&head, &run.program)), ["wrap: run"]);
    // The last segment alone, at position 0: its halt, no entry.
    let tail = run.honest_leaf(3, 0);
    assert!(!tail.output.entry && tail.output.halt);
    assert_eq!(refusals(&values_of(&tail, &run.program)), ["wrap: run"]);
    // The whole run at position 1.
    let one = one_segment();
    let late = one.run.honest_leaf(0, 1);
    assert!(late.output.entry && late.output.halt && late.output.first == 1);
    assert_eq!(refusals(&values_of(&late, &one.run.program)), ["wrap: run"]);

    // Proved, the refused witness does not verify.
    let wrap = WrapCircuit::get();
    let values = values_of(&head, &run.program);
    let mut context = Context::<SecureField>::with_layout(wrap::LAYOUT).lenient();
    let lanes = wrap.verify(&mut context, &values);
    context.set_output_lanes(&lanes);
    let finalized = context.finalize().expect("the wiring checks");
    let words = wrap::public_words(&finalized);
    let refused = match wrap::prove_unmasked(&finalized) {
        Err(_) => true,
        Ok(proof) => unmasked::verify(proof, &words).is_err(),
    };
    assert!(refused, "a root without its halt wraps and verifies");
}

/// The circuit and the program: a root carrying a foreign W, a root whose
/// circuit is none of the program's, and a root carrying another program's
/// id.
#[test]
fn a_root_of_another_circuit_or_program_is_refused() {
    let one = one_segment();
    let run = &one.run;
    let foreign = P2Hash(core::array::from_fn(|i| BaseField::from(5_000 + i as u32)));
    let carrying = run.leaf(0, 0, id(&run.program), foreign);
    assert_eq!(
        refusals(&values_of(&carrying, &run.program)),
        ["wrap: circuit"]
    );

    // A program whose leaf circuits are another run's: the root's id is
    // its, but its circuit is none of them.
    let other = IdPreimage {
        leaf_circuits: four_segments().program.leaf_circuits.clone(),
        ..run.program.clone()
    };
    assert!(!other.leaf_circuits.hashes().contains(&run.leaves[0].hash()));
    let outsider = run.leaf(0, 0, id(&other), FoldCircuit::word());
    assert_eq!(refusals(&values_of(&outsider, &other)), ["wrap: circuit"]);

    // The root carries another kernel's id, under the run's program.
    let wrong = IdPreimage {
        kernel: P2Hash(core::array::from_fn(|i| BaseField::from(9_000 + i as u32))),
        ..run.program.clone()
    };
    let stranger = run.leaf(0, 0, id(&wrong), FoldCircuit::word());
    assert_eq!(
        refusals(&values_of(&stranger, &run.program)),
        ["wrap: program"]
    );
}

/// A tampered root proof is refused by the check the native verifier
/// refuses it with: the wrap's first mismatch.
#[test]
fn a_tampered_root_proof_is_refused() {
    let one = one_segment();
    let values = values_of(&one.root, &one.run.program);
    let one_value = SecureField::from(BaseField::from(1));
    type Tamper = fn(&mut WrapValues<SecureField>, SecureField);
    let tampers: [(&str, &str, Tamper); 6] = [
        ("the preprocessed root", "pow", |v, d| {
            v.root.proof.preprocessed_root[0] += d
        }),
        ("an output wire", "pow", |v, d| v.root.output[0] += d),
        ("a claimed sum", "logup", |v, d| {
            v.root.proof.stark.claimed_sums[0] += d
        }),
        ("a sampled value", "oods", |v, d| {
            v.root.proof.stark.sampled[7] += d
        }),
        ("a queried value", "merkle", |v, d| {
            v.root.proof.stark.queries[3].trees[1].leaf[2] += d
        }),
        ("a FRI sibling", "fri", |v, d| {
            v.root.proof.stark.queries[1].fri[3].sibling += d
        }),
    ];
    for (name, piece, tamper) in tampers {
        let mut tampered = values.clone();
        tamper(&mut tampered, one_value);
        let pieces = refusals(&tampered);
        assert_eq!(pieces.first(), Some(&piece), "{name}: {pieces:?}");
    }
}

/// Tampers on the wrap proof, end to end: each refused by the final
/// verifier with an error. FRI at fold step 3 (the first layer's and an
/// inner layer's witness value, an inner layer's root and Merkle witness,
/// the last layer) and the Blake2b-256 trees and channel (a trace root, a
/// Merkle witness, a queried value, the PoW and interaction nonces, a
/// sampled value).
#[test]
fn the_final_verifier_refuses_a_tampered_wrap() {
    let one = one_segment();
    let words = one.wrapped.words;
    let flip = |hash: &mut Blake2bHash| hash.0[5] ^= 1;
    let one_value = SecureField::from(BaseField::from(1));
    type Tamper = Box<dyn Fn(&mut WrapProof)>;
    let tampers: Vec<(&str, Tamper)> = vec![
        (
            "a first-layer FRI value",
            Box::new(move |p| p.stark_proof.0.fri_proof.first_layer.fri_witness[0] += one_value),
        ),
        (
            "an inner-layer FRI value",
            Box::new(move |p| {
                p.stark_proof.0.fri_proof.inner_layers[1].fri_witness[2] += one_value
            }),
        ),
        (
            "an inner layer's root",
            Box::new(move |p| flip(&mut p.stark_proof.0.fri_proof.inner_layers[0].commitment)),
        ),
        (
            "an inner layer's Merkle witness",
            Box::new(move |p| {
                flip(
                    &mut p.stark_proof.0.fri_proof.inner_layers[0]
                        .decommitment
                        .hash_witness[0],
                )
            }),
        ),
        (
            "the last layer",
            Box::new(move |p| p.stark_proof.0.fri_proof.last_layer_poly[3] += one_value),
        ),
        (
            "the main trace's root",
            Box::new(move |p| flip(&mut p.stark_proof.0.commitments[1])),
        ),
        (
            "the composition root",
            Box::new(move |p| flip(&mut p.stark_proof.0.commitments[3])),
        ),
        (
            "a trace Merkle witness",
            Box::new(move |p| flip(&mut p.stark_proof.0.decommitments[1].hash_witness[4])),
        ),
        (
            "a queried value",
            Box::new(move |p| {
                let value = &mut p.stark_proof.0.queried_values[1][10][0];
                *value = BaseField::from((value.0 + 1) % P);
            }),
        ),
        (
            "a sampled value",
            Box::new(move |p| p.stark_proof.0.sampled_values[1][5][0] += one_value),
        ),
        (
            "the PoW nonce",
            Box::new(|p| p.stark_proof.0.proof_of_work ^= 1),
        ),
        (
            "the interaction nonce",
            Box::new(|p| p.interaction_pow ^= 1),
        ),
        (
            "a claimed sum",
            Box::new(move |p| p.claimed_sums[2] += one_value),
        ),
    ];
    for (name, tamper) in tampers {
        let mut proof = one.wrapped.proof.clone();
        tamper(&mut proof);
        let error = unmasked::verify(proof, &words).expect_err(name).to_string();
        eprintln!("{name}: {error}");
    }
    // The preprocessed root: another circuit.
    let mut proof = one.wrapped.proof.clone();
    flip(&mut proof.stark_proof.0.commitments[0]);
    assert!(matches!(
        unmasked::verify(proof, &words),
        Err(Error::Circuit)
    ));
}

/// Every malformed shape is refused with an error, each by the check meant
/// for it: the trees' counts, a column's samples and a tree's columns by the
/// shape's check, before Stwo indexes the proof; a noncanonical limb; the
/// format, configuration and log sizes; and by Stwo's own errors the
/// queried values' columns and values (the Merkle verifier's shape check),
/// FRI's layer count, a layer's witness and the last layer's degree.
#[test]
fn the_final_verifier_refuses_a_malformed_shape() {
    let one = one_segment();
    let words = one.wrapped.words;
    type Malform = Box<dyn Fn(&mut WrapProof)>;
    type Expect = fn(&Error) -> bool;
    let shape: Expect = |error| matches!(error, Error::Shape(_));
    let noncanonical: Expect = |error| matches!(error, Error::Noncanonical);
    let format: Expect = |error| matches!(error, Error::Format);
    let queried: Expect = |error| {
        matches!(
            error,
            Error::Stark(VerificationError::Merkle(
                MerkleVerificationError::QueriedValuesShapeMismatch
            ))
        )
    };
    let layers: Expect = |error| {
        matches!(
            error,
            Error::Stark(VerificationError::Fri(
                FriVerificationError::InvalidNumFriLayers
            ))
        )
    };
    let witness: Expect = |error| {
        matches!(
            error,
            Error::Stark(VerificationError::Fri(
                FriVerificationError::InnerLayerEvaluationsInvalid { inner_layer: 0 }
            ))
        )
    };
    let last: Expect = |error| {
        matches!(
            error,
            Error::Stark(VerificationError::Fri(
                FriVerificationError::LastLayerDegreeInvalid
            ))
        )
    };
    let shapes: Vec<(&str, Expect, Malform)> = vec![
        (
            "a commitment fewer",
            shape,
            Box::new(|p| {
                p.stark_proof.0.commitments.pop();
            }),
        ),
        (
            "a commitment more",
            shape,
            Box::new(|p| {
                let extra = p.stark_proof.0.commitments[0];
                p.stark_proof.0.commitments.push(extra);
            }),
        ),
        (
            "a tree of samples fewer",
            shape,
            Box::new(|p| {
                p.stark_proof.0.sampled_values.pop();
            }),
        ),
        (
            "a column's sample fewer",
            shape,
            Box::new(|p| {
                p.stark_proof.0.sampled_values[1][0].pop();
            }),
        ),
        (
            "a column's sample more",
            shape,
            Box::new(|p| p.stark_proof.0.sampled_values[2][3].push(SecureField::default())),
        ),
        (
            "a composition column's sample fewer",
            shape,
            Box::new(|p| {
                p.stark_proof.0.sampled_values[3][7].pop();
            }),
        ),
        (
            "a column of samples fewer",
            shape,
            Box::new(|p| {
                p.stark_proof.0.sampled_values[1].pop();
            }),
        ),
        (
            "a preprocessed column's samples empty",
            shape,
            Box::new(|p| p.stark_proof.0.sampled_values[0][0].clear()),
        ),
        (
            "a decommitment fewer",
            shape,
            Box::new(|p| {
                p.stark_proof.0.decommitments.pop();
            }),
        ),
        (
            "a tree of queried values fewer",
            shape,
            Box::new(|p| {
                p.stark_proof.0.queried_values.pop();
            }),
        ),
        (
            "a column of queried values fewer",
            queried,
            Box::new(|p| {
                p.stark_proof.0.queried_values[2].pop();
            }),
        ),
        (
            "a queried value fewer",
            queried,
            Box::new(|p| {
                p.stark_proof.0.queried_values[0][4].pop();
            }),
        ),
        (
            "an inner FRI layer fewer",
            layers,
            Box::new(|p| {
                p.stark_proof.0.fri_proof.inner_layers.pop();
            }),
        ),
        (
            "an inner FRI layer more",
            layers,
            Box::new(|p| {
                let extra = p.stark_proof.0.fri_proof.inner_layers[0].clone();
                p.stark_proof.0.fri_proof.inner_layers.push(extra);
            }),
        ),
        (
            "a FRI witness value fewer",
            witness,
            Box::new(|p| {
                p.stark_proof.0.fri_proof.inner_layers[0].fri_witness.pop();
            }),
        ),
        (
            "a last layer twice as long",
            last,
            Box::new(|p| {
                let mut coeffs = p.stark_proof.0.fri_proof.last_layer_poly.to_vec();
                coeffs.extend(coeffs.clone());
                p.stark_proof.0.fri_proof.last_layer_poly = LinePoly::new(coeffs);
            }),
        ),
        (
            "a noncanonical sampled value",
            noncanonical,
            Box::new(|p| {
                p.stark_proof.0.sampled_values[1][0][0] =
                    SecureField::from_m31_array([BaseField::from_u32_unchecked(P); 4])
            }),
        ),
        (
            "a noncanonical queried value",
            noncanonical,
            Box::new(|p| {
                p.stark_proof.0.queried_values[1][0][0] = BaseField::from_u32_unchecked(P)
            }),
        ),
        (
            "a noncanonical claimed sum",
            noncanonical,
            Box::new(|p| {
                p.claimed_sums[0] =
                    SecureField::from_m31_array([BaseField::from_u32_unchecked(P + 3); 4])
            }),
        ),
        (
            "another format",
            format,
            Box::new(|p| p.format_version = 32),
        ),
        ("other log sizes", format, Box::new(|p| p.log_sizes[2] += 1)),
        (
            "another configuration",
            format,
            Box::new(|p| p.stark_proof.0.config.fri_config.n_queries = 21),
        ),
    ];
    for (name, expect, malform) in shapes {
        let mut proof = one.wrapped.proof.clone();
        malform(&mut proof);
        let error = unmasked::verify(proof, &words).expect_err(name);
        eprintln!("{name}: {error}");
        assert!(expect(&error), "{name}: {error}");
    }
}

/// The bytes: undecodable bytes, a byte after the proof and bytes over
/// [`vos_pvm_final_verifier::MAX_PROOF_BYTES`] are refused. Postcard's varints
/// need not be minimal, so the proof re-encoded with a longer varint is
/// another byte string that verifies: a proof's bytes are no key for it.
#[test]
fn the_final_verifier_reads_one_bounded_encoding() {
    let one = one_segment();
    let words = one.wrapped.words;
    let bytes = postcard::to_allocvec(&one.wrapped.proof).expect("encodes");
    assert!(matches!(
        unmasked::verify_bytes(&[28, 1, 2], &words),
        Err(Error::Decode)
    ));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        unmasked::verify_bytes(&trailing, &words),
        Err(Error::Decode)
    ));
    let mut long = bytes.clone();
    long.resize(vos_pvm_final_verifier::MAX_PROOF_BYTES + 1, 0);
    assert!(matches!(
        unmasked::verify_bytes(&long, &words),
        Err(Error::Length)
    ));
    // The format version, 28, is the first varint: one byte, or two.
    assert_eq!(bytes[0], 28);
    let overlong = [&[28 | 0x80, 0][..], &bytes[1..]].concat();
    assert_eq!(
        unmasked::verify_bytes(&overlong, &words).expect("verifies"),
        one.wrapped.statement
    );
}

/// The final verifier on the JAM-only host: the wrap accepted within 150M
/// gas, its phases reported; a proof tampered at its middle byte, and
/// other words, refused without a panic.
#[test]
fn the_wrap_verifies_on_the_jam_only_host() {
    let (program, elf_len) = jam::program();
    let one = one_segment();
    let bytes = postcard::to_allocvec(&one.wrapped.proof).expect("encodes");
    let request = jam::words_request(unmasked::FORMAT, &one.wrapped.words);
    let (gas, report) = jam::run(&program, &request, &bytes);
    let [start, lookup, decode, end] = report.gas;
    eprintln!(
        "the wrap on the JAM-only host: {gas} gas ({:.1}M): lookup {}, decode {}, verify {}; \
         {} bytes, program {} bytes (ELF {elf_len}); heap peak {} KiB, high water {} KiB, {} \
         allocations",
        gas as f64 / 1e6,
        start - lookup,
        lookup - decode,
        decode - end,
        bytes.len(),
        program.len(),
        report.peak_live >> 10,
        report.high_water >> 10,
        report.allocs,
    );
    assert_eq!(report.verdict, jam::ACCEPT, "{}", report.error);
    assert!(gas <= 150_000_000, "{gas} gas");

    let mut tampered = bytes.clone();
    tampered[bytes.len() / 2] ^= 1;
    let (gas, report) = jam::run(&program, &request, &tampered);
    eprintln!(
        "a tampered byte: verdict {}, {gas} gas: {}",
        report.verdict, report.error
    );
    assert_ne!(report.verdict, jam::ACCEPT);
    let mut words = one.wrapped.words;
    words[3] ^= 1;
    let (gas, report) = jam::run(
        &program,
        &jam::words_request(unmasked::FORMAT, &words),
        &bytes,
    );
    eprintln!("other words: {gas} gas: {}", report.error);
    assert_eq!(report.verdict, jam::REJECT);
}
