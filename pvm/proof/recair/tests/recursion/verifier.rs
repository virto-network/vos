//! The in-AIR verifier's pieces (`recursion-air.md` §4) on real format-35
//! proofs: the fixture (18 chips) and a run proved over all 25.
//!
//! - **Composed:** the fixture verified in a circuit, its transcript
//!   permutation for permutation the native recorder's, every draw the
//!   native verifier's, every query's DEEP quotient its first-layer value;
//!   the wiring without values is the filled one's; the circuit proves and
//!   verifies.
//! - **Each piece on recorded data:** the channel, Merkle openings and
//!   `expand_decommitment`, FRI, DEEP, OODS and the logup sums, each fed the
//!   native verifier's values alone.
//! - **Each tamper refused, by the check that should refuse it:** a Merkle
//!   sibling, a queried value, a FRI layer value and path node, the last
//!   layer's coefficient, either PoW nonce, a claimed sum, an OODS sample, a
//!   boundary byte (the interaction PoW reground), a header word, each
//!   committed root; and a tampered witness, proved, is refused by the
//!   verifier. A nonce limb of 2^16, a wire no u64 encodes, is refused even
//!   when its work passes.
//! - **The shape:** a shape the native verifier refuses (a format not
//!   admitted, a log size past 2^24, counts below the format's floor) builds
//!   no circuit; a proof of another format, configuration, mask, log sizes or
//!   program is refused before its values reach a circuit, and values of
//!   another structure before they are guessed.
//! - **Repeats:** a position drawn twice is laid out twice, each opening
//!   accepted.
//! - **Rows:** each piece's, on the fixture (the window kernel's leaf
//!   topology is pinned term by term in `leaves.rs`).

use std::sync::OnceLock;

use crate::common::{
    self, WINDOW_LOG_SIZES, WINDOW_MASK, assert_transcript_is, bump, is_refused, position_of,
    print_rows,
};
use num_traits::{One, Zero};
use stwo::core::channel::{Channel as _, MerkleChannel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use vos_pvm_proof::format::{Format, LEAF_FOLD, SEGMENT, SecurityFloor};
use vos_pvm_proof::pcs::{FsChannel, StarkProofAny};
use vos_pvm_proof::poseidon2::{P2Hash, P2MerkleChannel, P2MerkleHasher, Poseidon2M31Channel};
use vos_pvm_proof::{Proof, RecursionData, chip_idx, extract_recursion_data};
use vos_pvm_recair::gadgets::TranscriptGadget;
use vos_pvm_recair::verifier::bits::{
    assert_trailing_zeros, assert_u16_limbs, check_word_bits, guess_bits,
};
use vos_pvm_recair::verifier::channel::{Channel, u64_wire};
use vos_pvm_recair::verifier::circle::{Point, domain_point};
use vos_pvm_recair::verifier::fri::{FriCommitment, verify_query};
use vos_pvm_recair::verifier::logup::{BoundaryRelations, Challenges};
use vos_pvm_recair::verifier::merkle::{ExpandError, expand_decommitment, verify_opening};
use vos_pvm_recair::verifier::stark::{CompiledInput, preprocessed_bits};
use vos_pvm_recair::verifier::witness::digest_wires;
use vos_pvm_recair::verifier::{
    SegmentShape, SegmentValues, ShapeMismatch, WitnessError, deep, logup, oods, verify_segment,
};
use vos_pvm_recair::{Bit, Context, NoValue, Var};

/// A real proof, its circuit's shape, its values and the native verifier's
/// record of it.
struct Real {
    proof: Proof,
    shape: SegmentShape,
    values: SegmentValues<SecureField>,
    data: RecursionData,
}

impl Real {
    fn new(proof: Proof) -> Self {
        let shape = SegmentShape::of(&proof);
        let values = SegmentValues::from_proof(&shape, &proof).expect("the proof's values");
        let data = extract_recursion_data(&proof);
        Self {
            proof,
            shape,
            values,
            data,
        }
    }

    /// Each query's position in draw order.
    fn drawn(&self) -> Vec<usize> {
        vos_pvm_recair::verifier::witness::drawn_positions(&self.shape.stark, &self.data)
    }

    /// The native first-layer value at `position`.
    fn first_layer(&self, position: usize) -> SecureField {
        let index = self.data.query_positions.binary_search(&position).unwrap();
        self.data.first_layer_evals[index]
    }

    /// Each relation's `z` and `α`, in draw order, as the native verifier
    /// drew them: `z` its challenges', `α` the rest of its squeeze (a
    /// one-limb relation never powers it).
    fn challenges(&self) -> Vec<[SecureField; 2]> {
        let native = self.data.lookup_elements.relation_challenges();
        let records = &self.data.transcript.records;
        self.shape
            .stark
            .relations
            .iter()
            .map(|name| {
                let relation = native.iter().find(|r| &r.name == name).unwrap();
                let squeeze = records
                    .iter()
                    .find(|record| {
                        SecureField::from_m31_array(core::array::from_fn(|i| record.output[i]))
                            == relation.z
                    })
                    .expect("the relation's squeeze");
                let alpha =
                    SecureField::from_m31_array(core::array::from_fn(|i| squeeze.output[4 + i]));
                if let Some(&power) = relation.alpha_powers.get(1) {
                    assert_eq!(power, alpha);
                }
                [relation.z, alpha]
            })
            .collect()
    }
}

fn fixture() -> &'static Real {
    static FIXTURE: OnceLock<Real> = OnceLock::new();
    FIXTURE.get_or_init(|| Real::new(common::segment_fixture()))
}

/// A run proved over all 25 chips, the ones it does not use padded.
fn full_shape() -> &'static Real {
    static FULL: OnceLock<Real> = OnceLock::new();
    FULL.get_or_init(|| Real::new(common::full_shape_proof().clone()))
}

fn value(context: &Context<SecureField>, var: Var) -> SecureField {
    context.value(var)
}

/// The composed circuit over `values`, lenient: its context and the first
/// mismatch's piece.
fn first_refusal(real: &Real, values: &SegmentValues<SecureField>) -> Option<&'static str> {
    let mut context = Context::<SecureField>::new().lenient();
    verify_segment(&mut context, &real.shape, values);
    context.mismatches().first().map(|mismatch| mismatch.piece)
}

/// The composed circuit on `real`: no mismatch, the transcript the native
/// recorder's permutation for permutation, every draw the native verifier's,
/// each query's DEEP quotient its first-layer value. Returns the context.
fn verifies_as_natively(real: &Real) -> Context<SecureField> {
    let mut context = Context::<SecureField>::new();
    let verified = verify_segment(&mut context, &real.shape, &real.values);
    let data = &real.data;

    assert_transcript_is(verified.channel.transcript(), &data.transcript);

    let draws = &verified.draws;
    for (drawn, native) in draws.relations.iter().zip(real.challenges()) {
        assert_eq!(drawn.map(|var| value(&context, var)), native);
    }
    assert_eq!(value(&context, draws.composition_coeff), data.random_coeff);
    assert_eq!(value(&context, draws.oods.x), data.oods_point.x);
    assert_eq!(value(&context, draws.oods.y), data.oods_point.y);
    assert_eq!(value(&context, draws.deep_coeff), data.deep_coeff);
    let alphas: Vec<SecureField> = draws
        .fri_alphas
        .iter()
        .map(|&var| value(&context, var))
        .collect();
    assert_eq!(alphas, data.fold_alphas);
    let drawn: Vec<usize> = draws
        .queries
        .iter()
        .map(|bits| position_of(&context, bits))
        .collect();
    assert_eq!(drawn, real.drawn());
    for (&position, &answer) in drawn.iter().zip(&verified.answers) {
        assert_eq!(value(&context, answer), real.first_layer(position));
    }
    context
}

/// The message `build` panics with, if it panics.
fn panic_message(build: impl FnOnce()) -> Option<String> {
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(build)).err()?;
    Some(
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default(),
    )
}

// ── Composed ───────────────────────────────────────────────────────────────

#[test]
fn the_fixture_verifies_in_a_circuit_as_natively() {
    let real = fixture();
    let context = verifies_as_natively(real);
    print_rows("the fixture's circuit", &context);
    let (blocks, singles, samples) = real.shape.stark.deep.counts();
    eprintln!(
        "DEEP: {samples} samples at {} points; a query's chains {blocks} h8 blocks and {singles} \
         single samples",
        real.shape.stark.deep.points.len()
    );

    // The wiring built without values is the filled one's.
    let mut wiring = Context::<NoValue>::new();
    verify_segment(
        &mut wiring,
        &real.shape,
        &SegmentValues::<NoValue>::blank(&real.shape),
    );
    assert_eq!(
        wiring.finalize().expect("the wiring checks").circuit,
        context.finalize().expect("the wiring checks").circuit
    );
}

#[test]
fn a_full_shape_proof_verifies_in_a_circuit_as_natively() {
    let context = verifies_as_natively(full_shape());
    print_rows("the full shape's circuit", &context);
}

#[test]
fn the_verifier_circuit_proves_and_verifies() {
    let real = fixture();
    let mut context = Context::<SecureField>::new();
    verify_segment(&mut context, &real.shape, &real.values);
    let finalized = context.finalize().expect("the wiring checks");
    let started = std::time::Instant::now();
    let proof = vos_pvm_recair::prove(&finalized.circuit, &finalized.witness).expect("proves");
    eprintln!(
        "the fixture's verifier circuit, {:?} rows, proved in {:.2}s",
        finalized.circuit.log_sizes(),
        started.elapsed().as_secs_f64()
    );
    let (_, hash) = vos_pvm_recair::circuit_commitment(&finalized.circuit).unwrap();
    vos_pvm_recair::verify(proof, &hash).expect("verifies");
}

// ── Tampers, composed ──────────────────────────────────────────────────────

#[test]
fn every_tamper_is_refused_by_its_check() {
    let real = fixture();
    let mut cases: Vec<(&str, &str, SegmentValues<SecureField>)> = Vec::new();
    let mut add = |name: &'static str,
                   piece: &'static str,
                   edit: &dyn Fn(&mut SegmentValues<SecureField>)| {
        let mut values = real.values.clone();
        edit(&mut values);
        cases.push((name, piece, values));
    };
    add("a Merkle sibling", "merkle", &|v| {
        bump(&mut v.stark.queries[3].trees[1].path[5][0])
    });
    add("a preprocessed sibling", "merkle", &|v| {
        bump(&mut v.stark.queries[9].trees[0].path[0][1])
    });
    add("a queried value", "merkle", &|v| {
        bump(&mut v.stark.queries[7].trees[2].leaf[10])
    });
    add("a composition value", "merkle", &|v| {
        bump(&mut v.stark.queries[1].trees[3].leaf[1])
    });
    add("a FRI layer value", "fri", &|v| {
        bump(&mut v.stark.queries[0].fri[3].sibling)
    });
    add("a FRI path node", "fri", &|v| {
        bump(&mut v.stark.queries[5].fri[2].path[1][1])
    });
    add("a FRI root", "pow", &|v| bump(&mut v.stark.fri_roots[4][0]));
    add("the last layer's coefficient", "pow", &|v| {
        bump(&mut v.stark.last_layer)
    });
    add("the PoW nonce", "pow", &|v| bump(&mut v.stark.nonce));
    add("the interaction PoW nonce", "pow", &|v| {
        bump(&mut v.stark.interaction_nonce)
    });
    add("a claimed sum", "logup", &|v| {
        bump(&mut v.stark.claimed_sums[2])
    });
    add("a header word", "shape", &|v| bump(&mut v.header[11]));
    let running_sum = {
        let component = &real.shape.stark.layout.components[0];
        let column = component.interaction_columns.end - 1;
        real.shape.stark.sample_index[2][column] + 1
    };
    add("an OODS sample", "oods", &move |v| {
        bump(&mut v.stark.sampled[running_sum])
    });
    let composition = real.shape.stark.sample_index[3][5];
    add("a composition sample", "oods", &move |v| {
        bump(&mut v.stark.sampled[composition])
    });
    // Each committed root: the main root precedes the interaction PoW; the
    // interaction root, the composition coefficient and the OODS point; the
    // composition root, the OODS point.
    add("the main root", "pow", &|v| bump(&mut v.stark.roots[0][0]));
    add("the interaction root", "oods", &|v| {
        bump(&mut v.stark.roots[1][1])
    });
    add("the composition root", "oods", &|v| {
        bump(&mut v.stark.roots[2][0])
    });

    // A boundary byte, its interaction PoW reground natively: the public
    // terms refuse it.
    let mut values = real.values.clone();
    let mut bytes = vos_pvm_proof::boundary_binding::boundary_state_bytes(
        &real.proof.initial_state,
        &real.proof.final_state,
    );
    bytes[3] ^= 1;
    values.boundary[0] = vos_pvm_recair::verifier::witness::pack(
        &bytes[..4]
            .iter()
            .map(|&b| BaseField::from(b as u32))
            .collect::<Vec<_>>(),
    )[0];
    values.stark.interaction_nonce = u64_wire(regrind_interaction(real, &bytes));
    cases.push(("a boundary byte", "logup", values));

    for (name, piece, values) in &cases {
        assert_eq!(
            first_refusal(real, values),
            Some(*piece),
            "{name} is refused by {piece}"
        );
    }

    // The interaction PoW alone, for a tampered byte not reground.
    let mut values = real.values.clone();
    bump(&mut values.boundary[30]);
    assert_eq!(first_refusal(real, &values), Some("pow"));
}

/// The interaction PoW nonce over the transcript with `bytes` as the
/// boundary states.
fn regrind_interaction(real: &Real, bytes: &[u8]) -> u64 {
    let StarkProofAny::Poseidon2M31(stark) = &real.proof.stark_proof else {
        unreachable!()
    };
    let mut channel = Poseidon2M31Channel::default();
    vos_pvm_proof::proof::mix_statement_header(
        &mut channel,
        real.shape.stark.format.number,
        &real.shape.config(),
        &real.shape.log_sizes,
    );
    P2MerkleChannel::mix_root(&mut channel, stark.commitments[0]);
    P2MerkleChannel::mix_root(&mut channel, stark.commitments[1]);
    channel.mix_bytes(bytes);
    let bits = real.shape.stark.format.interaction_pow_bits();
    (0..)
        .find(|&nonce| channel.verify_pow_nonce(bits, nonce))
        .unwrap()
}

/// A tampered witness, proved, is refused: its `Gate` relation does not
/// balance.
#[test]
fn a_tampered_witness_proved_is_refused() {
    let real = fixture();
    let mut values = real.values.clone();
    bump(&mut values.stark.queries[3].trees[1].path[5][0]);
    let mut context = Context::<SecureField>::new().lenient();
    verify_segment(&mut context, &real.shape, &values);
    assert!(!context.mismatches().is_empty());
    let finalized = context.finalize().expect("the wiring checks");
    assert!(
        is_refused(&finalized),
        "a tampered witness proves and verifies"
    );
}

// ── The shape ──────────────────────────────────────────────────────────────

#[test]
fn a_proof_of_another_shape_is_refused() {
    let real = fixture();
    let check = |edit: &dyn Fn(&mut Proof)| {
        let mut proof = real.proof.clone();
        edit(&mut proof);
        real.shape.check(&proof)
    };
    assert_eq!(check(&|_| {}), Ok(()));
    assert_eq!(
        check(&|p| p.format_version = 32),
        Err(ShapeMismatch::Format {
            circuit: 35,
            proof: 32
        })
    );
    assert_eq!(
        check(&|p| p.pcs_config.pow_bits = 20),
        Err(ShapeMismatch::Config)
    );
    assert!(matches!(
        check(&|p| p.component_mask ^= 1 << chip_idx::POPCOUNT),
        Err(ShapeMismatch::ComponentMask { .. })
    ));
    assert_eq!(
        check(&|p| p.log_sizes[3] += 1),
        Err(ShapeMismatch::LogSizes)
    );
    assert_eq!(
        check(&|p| {
            let StarkProofAny::Poseidon2M31(stark) = &mut p.stark_proof else {
                unreachable!()
            };
            stark.0.commitments[0].0[0] += BaseField::one();
        }),
        Err(ShapeMismatch::PreprocessedRoot)
    );
    let mut proof = real.proof.clone();
    proof.log_sizes[0] += 1;
    assert_eq!(
        SegmentValues::from_proof(&real.shape, &proof).unwrap_err(),
        WitnessError::Shape(ShapeMismatch::LogSizes)
    );
}

/// A shape the native verifier refuses builds no circuit: a format not
/// admitted, a log size past the native bound, counts below the format's
/// floor at this shape, counted as the standalone verifier counts them.
#[test]
fn a_shape_the_native_verifier_refuses_builds_no_circuit() {
    for real in [fixture(), full_shape()] {
        assert_eq!(
            vos_pvm_proof::proof::format_security_bits(
                real.shape.stark.format,
                &real.shape.config(),
                &real.shape.stark.layout.security_shape
            ),
            Ok(vos_pvm_proof_verifier::proof_security_bits(&real.proof).unwrap())
        );
    }
    let refusal = |format: &'static Format, log_sizes: &[u32]| {
        panic_message(|| {
            SegmentShape::new(format, WINDOW_MASK, log_sizes, P2Hash::default());
        })
    };
    let refused = |format, log_sizes: &[u32], reason: &str| {
        let message = refusal(format, log_sizes).expect("refused");
        assert!(message.contains(reason), "{message}");
    };
    refused(&LEAF_FOLD, &WINDOW_LOG_SIZES, "an admitted format");
    let mut oversize = WINDOW_LOG_SIZES;
    oversize[3] = vos_pvm_proof::DEFAULT_MAX_LOG_SIZE + 1;
    refused(&SEGMENT, &oversize, "log sizes the native verifier admits");
    // Format 35 with a proven floor of 63 bits: the window kernel's shape
    // counts 63, the same with its widest chip at 2^20 rows 62.
    let raised: &'static Format = Box::leak(Box::new(Format {
        floor: SecurityFloor {
            proven: 63,
            ..SEGMENT.floor
        },
        ..SEGMENT
    }));
    assert_eq!(refusal(raised, &WINDOW_LOG_SIZES), None);
    let mut taller = WINDOW_LOG_SIZES;
    taller[3] = 20;
    refused(raised, &taller, "a shape the format's floors admit");
}

/// Values whose lengths are not the shape's are refused before any is
/// guessed: the circuit's structure never follows them.
#[test]
fn values_of_another_structure_are_refused() {
    let real = fixture();
    type Edit = Box<dyn Fn(&mut SegmentValues<SecureField>)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "FRI layers",
            Box::new(|v| {
                v.stark.queries[4].fri.pop();
            }),
        ),
        (
            "FRI roots",
            Box::new(|v| {
                v.stark.fri_roots.pop();
                for query in &mut v.stark.queries {
                    query.fri.pop();
                }
            }),
        ),
        (
            "header words",
            Box::new(|v| {
                v.header.pop();
            }),
        ),
        (
            "claimed sums",
            Box::new(|v| {
                v.stark.claimed_sums.pop();
            }),
        ),
        (
            "sampled values",
            Box::new(|v| {
                v.stark.sampled.pop();
            }),
        ),
        (
            "queries",
            Box::new(|v| {
                v.stark.queries.pop();
            }),
        ),
        (
            "tree path nodes",
            Box::new(|v| {
                v.stark.queries[2].trees[1].path.pop();
            }),
        ),
    ];
    for (reason, edit) in cases {
        let mut values = real.values.clone();
        edit(&mut values);
        let message = panic_message(|| {
            verify_segment(
                &mut Context::<SecureField>::new().lenient(),
                &real.shape,
                &values,
            );
        })
        .expect("refused");
        assert!(message.contains(reason), "{reason}: {message}");
    }
}

// ── Repeats ────────────────────────────────────────────────────────────────

/// A position drawn twice, as some 0.15% of proofs draw one: the fixture's
/// openings laid out at its draws with one repeated, each draw's openings
/// its position's, every opening accepted by the Merkle and FRI checks.
#[test]
fn a_position_drawn_twice_is_opened_twice() {
    let real = fixture();
    let lifting = real.shape.stark.layout.lifting_log_size;
    let mut drawn = real.drawn();
    let (first, repeat) = (3, 11);
    drawn[repeat] = drawn[first];
    let values =
        SegmentValues::with_draws(&real.shape, &real.proof, &drawn).expect("the proof's values");
    assert_eq!(
        values.stark.queries[repeat],
        real.values.stark.queries[first]
    );
    for (q, query) in values.stark.queries.iter().enumerate() {
        if q != repeat {
            assert_eq!(*query, real.values.stark.queries[q], "query {q}");
        }
    }

    let StarkProofAny::Poseidon2M31(stark) = &real.proof.stark_proof else {
        unreachable!()
    };
    let mut context = Context::<SecureField>::new().lenient();
    let fri_roots = values
        .stark
        .fri_roots
        .iter()
        .map(|&root| context.guess_pair(root))
        .collect();
    let alphas = real
        .data
        .fold_alphas
        .iter()
        .map(|&alpha| context.guess(alpha))
        .collect();
    let commitment = FriCommitment {
        roots: fri_roots,
        alphas,
        last_layer: context.guess(values.stark.last_layer),
    };
    for (&position, query) in drawn.iter().zip(&values.stark.queries) {
        let bits = bits_of(&mut context, position, lifting);
        for (tree, opening) in query.trees.iter().enumerate() {
            let tree_bits = if tree == 0 {
                preprocessed_bits(&bits, real.shape.stark.heights[0])
            } else {
                bits.clone()
            };
            let wires: Vec<Var> = opening.leaf.iter().map(|&v| context.guess(v)).collect();
            let root = guess_digest(&mut context, &stark.commitments[tree]);
            verify_opening(
                &mut context,
                &wires,
                real.shape.stark.leaf_order[tree].len(),
                &tree_bits,
                &opening.path,
                root,
            );
        }
        let point = domain_point(&mut context, lifting, &bits);
        let value = context.guess(real.first_layer(position));
        verify_query(
            &mut context,
            lifting,
            &commitment,
            &bits,
            point,
            value,
            &query.fri,
        );
    }
    assert!(context.mismatches().is_empty());
}

// ── Each piece on recorded data ────────────────────────────────────────────

/// Bits guessed and constrained for `position`.
fn bits_of(context: &mut Context<SecureField>, position: usize, n: u32) -> Vec<Bit> {
    guess_bits(context, Some(position as u32), n)
}

fn guess_digest(context: &mut Context<SecureField>, hash: &P2Hash) -> [Var; 2] {
    context.guess_pair(digest_wires(hash))
}

#[test]
fn the_bits_refuse_a_noncanonical_word_and_a_short_pow() {
    // Zero's other decomposition, thirty-one ones, recomposes it but is
    // refused.
    let mut context = Context::<SecureField>::new().lenient();
    let word = context.guess(SecureField::zero());
    let ones = guess_bits(&mut context, Some(u32::MAX), 31);
    check_word_bits(&mut context, word, &ones);
    assert_eq!(context.mismatches().len(), 1, "only the canonical check");

    let mut context = Context::<SecureField>::new().lenient();
    let word = context.guess(SecureField::zero());
    let zeros = guess_bits(&mut context, Some(0), 31);
    check_word_bits(&mut context, word, &zeros);
    assert!(context.mismatches().is_empty());

    for (word, n_bits, passes) in [(0u32, 24, true), (5 << 24, 24, true), (3 << 23, 24, false)] {
        let mut context = Context::<SecureField>::new().lenient();
        let var = context.guess(SecureField::from(BaseField::from(word)));
        assert_trailing_zeros(&mut context, var, n_bits);
        assert_eq!(context.mismatches().is_empty(), passes, "{word:#x}");
    }
}

/// A nonce's limbs are each below 2^16, the wire a u64's: a limb of 2^16 is
/// refused, alone and in the channel, where a nonce whose work passes with
/// such a limb is refused for the limb alone.
#[test]
fn a_nonce_limb_of_2_16_is_refused() {
    let limbs = |limbs: [u32; 4]| SecureField::from_m31_array(limbs.map(BaseField::from));
    let refusals = |wire: SecureField| {
        let mut context = Context::<SecureField>::new().lenient();
        let var = context.guess(wire);
        assert_u16_limbs(&mut context, var);
        context.mismatches().len()
    };
    assert_eq!(refusals(u64_wire(u64::MAX)), 0);
    assert_eq!(refusals(u64_wire(0x0123_4567_89ab_cdef)), 0);
    for lane in 0..4 {
        let mut wide = [0xffff; 4];
        wide[lane] = 1 << 16;
        assert_eq!(refusals(limbs(wide)), 1, "lane {lane}");
    }

    // At 4 bits: the work alone (the hash and its trailing zeros), and the
    // channel's check.
    const BITS: u32 = 4;
    let work = |nonce: SecureField| {
        let mut context = Context::<SecureField>::new().lenient();
        let var = context.guess(nonce);
        let check = TranscriptGadget::new(&context).pow(&mut context, BITS, var);
        let word = context.limb(check.digest[0], 0);
        assert_trailing_zeros(&mut context, word, BITS);
        context.mismatches().is_empty()
    };
    let check_pow = |nonce: SecureField| {
        let mut context = Context::<SecureField>::new().lenient();
        let var = context.guess(nonce);
        let mut channel = Channel::new(&context);
        channel.check_pow(&mut context, BITS, var);
        context.mismatches().len()
    };
    let native = Poseidon2M31Channel::default();
    let nonce = (0..)
        .find(|&nonce| native.verify_pow_nonce(BITS, nonce))
        .unwrap();
    assert!(work(u64_wire(nonce)));
    assert_eq!(check_pow(u64_wire(nonce)), 0);
    let forged = (0..)
        .map(|k| limbs([(1 << 16) + k, 0, 0, 0]))
        .find(|&wire| work(wire))
        .unwrap();
    assert_eq!(check_pow(forged), 1);
}

#[test]
fn expand_decommitment_gives_each_query_its_path() {
    let real = fixture();
    let StarkProofAny::Poseidon2M31(stark) = &real.proof.stark_proof else {
        unreachable!()
    };
    let tree = 1;
    let height = real.shape.stark.heights[tree];
    let order = &real.shape.stark.leaf_order[tree];
    let leaf = |index: usize| {
        let row: Vec<BaseField> = order
            .iter()
            .map(|&c| stark.queried_values[tree][c][index])
            .collect();
        let mut hasher = P2MerkleHasher::default();
        hasher.update_leaf(&row);
        hasher.finalize()
    };
    let positions = &real.data.query_positions;
    let leaves: Vec<(usize, P2Hash)> = positions
        .iter()
        .enumerate()
        .map(|(i, &p)| (p, leaf(i)))
        .collect();
    let witness = &stark.decommitments[tree].hash_witness;
    let expanded = expand_decommitment::<P2MerkleHasher>(height, &leaves, witness).unwrap();
    assert_eq!(expanded.root, stark.commitments[tree]);
    for &(position, hash) in &leaves {
        let mut node = hash;
        for (level, sibling) in expanded.path(position).into_iter().enumerate() {
            node = if position >> level & 1 == 0 {
                P2MerkleHasher::hash_children((node, sibling))
            } else {
                P2MerkleHasher::hash_children((sibling, node))
            };
        }
        assert_eq!(node, stark.commitments[tree], "position {position}");
    }
    assert_eq!(
        expand_decommitment::<P2MerkleHasher>(height, &leaves, &witness[1..]).unwrap_err(),
        ExpandError::WitnessTooShort
    );
    let mut long = witness.clone();
    long.push(P2Hash::default());
    assert_eq!(
        expand_decommitment::<P2MerkleHasher>(height, &leaves, &long).unwrap_err(),
        ExpandError::WitnessTooLong
    );
}

/// Every tree's opening of every query, alone: accepted, and a sibling or a
/// value tampered refused.
#[test]
fn the_merkle_openings_accept_and_refuse() {
    let real = fixture();
    let StarkProofAny::Poseidon2M31(stark) = &real.proof.stark_proof else {
        unreachable!()
    };
    let lifting = real.shape.stark.layout.lifting_log_size;
    let open = |tamper: Option<(usize, bool)>| {
        let mut context = Context::<SecureField>::new().lenient();
        for (q, (&position, query)) in real
            .drawn()
            .iter()
            .zip(&real.values.stark.queries)
            .enumerate()
        {
            let bits = bits_of(&mut context, position, lifting);
            for (tree, opening) in query.trees.iter().enumerate() {
                let mut opening = opening.clone();
                if tamper == Some((q, true)) && tree == 2 {
                    bump(&mut opening.path[3][1]);
                }
                if tamper == Some((q, false)) && tree == 0 {
                    bump(&mut opening.leaf[0]);
                }
                let tree_bits = if tree == 0 {
                    preprocessed_bits(&bits, real.shape.stark.heights[0])
                } else {
                    bits.clone()
                };
                let wires: Vec<Var> = opening.leaf.iter().map(|&v| context.guess(v)).collect();
                let root = guess_digest(&mut context, &stark.commitments[tree]);
                verify_opening(
                    &mut context,
                    &wires,
                    real.shape.stark.leaf_order[tree].len(),
                    &tree_bits,
                    &opening.path,
                    root,
                );
            }
        }
        context.mismatches().len()
    };
    // A refused opening's root differs in both its wires.
    assert_eq!(open(None), 0);
    assert_eq!(open(Some((4, true))), 2);
    assert_eq!(open(Some((11, false))), 2);
}

/// FRI alone, on the native first-layer values, folding coefficients and
/// positions: accepted; a sibling, a first-layer value or the last layer's
/// coefficient tampered refused.
#[test]
fn fri_accepts_and_refuses() {
    let real = fixture();
    let lifting = real.shape.stark.layout.lifting_log_size;
    let run = |tamper: &str| {
        let mut context = Context::<SecureField>::new().lenient();
        let roots = real
            .values
            .stark
            .fri_roots
            .iter()
            .map(|&root| context.guess_pair(root))
            .collect();
        let alphas = real
            .data
            .fold_alphas
            .iter()
            .map(|&alpha| context.guess(alpha))
            .collect();
        let mut last = real.values.stark.last_layer;
        if tamper == "last" {
            bump(&mut last);
        }
        let commitment = FriCommitment {
            roots,
            alphas,
            last_layer: context.guess(last),
        };
        for (q, (&position, query)) in real
            .drawn()
            .iter()
            .zip(&real.values.stark.queries)
            .enumerate()
        {
            let bits = bits_of(&mut context, position, lifting);
            let point = domain_point(&mut context, lifting, &bits);
            let mut first = real.first_layer(position);
            if tamper == "value" && q == 6 {
                bump(&mut first);
            }
            let value = context.guess(first);
            let mut openings = query.fri.clone();
            if tamper == "sibling" && q == 2 {
                bump(&mut openings[7].sibling);
            }
            verify_query(
                &mut context,
                lifting,
                &commitment,
                &bits,
                point,
                value,
                &openings,
            );
        }
        context.mismatches().to_vec()
    };
    assert!(run("").is_empty());
    for tamper in ["last", "value", "sibling"] {
        assert!(!run(tamper).is_empty(), "{tamper}");
    }
    // The last layer: every query's last fold is refused.
    assert_eq!(run("last").len(), real.values.stark.queries.len());
}

/// DEEP alone, from the native sampled values, coefficient and OODS point:
/// each query's quotient is the native first-layer value; a queried value
/// or a sampled value tampered moves it.
#[test]
fn deep_is_the_native_quotient() {
    let real = fixture();
    let lifting = real.shape.stark.layout.lifting_log_size;
    let run = |tamper: &str| {
        let mut context = Context::<SecureField>::new();
        let mut sampled_values = real.values.stark.sampled.clone();
        if tamper == "sample" {
            bump(&mut sampled_values[100]);
        }
        let sampled: Vec<Var> = sampled_values.iter().map(|&v| context.guess(v)).collect();
        let oods = Point {
            x: context.guess(real.data.oods_point.x),
            y: context.guess(real.data.oods_point.y),
        };
        let alpha = context.guess(real.data.deep_coeff);
        let constants = deep::prepare(&mut context, &real.shape.stark.deep, oods, alpha, &sampled);
        let mut moved = 0;
        for (q, (&position, query)) in real
            .drawn()
            .iter()
            .zip(&real.values.stark.queries)
            .enumerate()
        {
            let bits = bits_of(&mut context, position, lifting);
            let point = domain_point(&mut context, lifting, &bits);
            let leaves: Vec<Vec<Var>> = query
                .trees
                .iter()
                .enumerate()
                .map(|(tree, opening)| {
                    let mut leaf = opening.leaf.clone();
                    if tamper == "queried" && q == 3 && tree == 1 {
                        bump(&mut leaf[17]);
                    }
                    leaf.iter().map(|&v| context.guess(v)).collect()
                })
                .collect();
            let answer = deep::answer(
                &mut context,
                &real.shape.stark.deep,
                &constants,
                point,
                [&leaves[0], &leaves[1], &leaves[2], &leaves[3]],
            );
            if value(&context, answer) != real.first_layer(position) {
                moved += 1;
            }
        }
        moved
    };
    assert_eq!(run(""), 0);
    assert_eq!(run("queried"), 1);
    assert_eq!(run("sample"), real.values.stark.queries.len());
}

/// The composition check alone, from the native values: accepted; an OODS
/// sample, a claimed sum or a challenge tampered refused.
#[test]
fn oods_accepts_and_refuses() {
    let real = fixture();
    let challenges = real.challenges();
    let inputs = real.shape.stark.compiled_inputs();
    let run = |tamper: Option<usize>| {
        let mut context = Context::<SecureField>::new().lenient();
        let wires: Vec<Var> = inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                let mut value = match *input {
                    CompiledInput::Sample(index) => real.values.stark.sampled[index],
                    CompiledInput::ClaimedSum(chip) => real.values.stark.claimed_sums[chip],
                    CompiledInput::Challenge(r, k) => challenges[r][k],
                };
                if tamper == Some(i) {
                    bump(&mut value);
                }
                context.guess(value)
            })
            .collect();
        let coeff = context.guess(real.data.random_coeff);
        let oods_point = Point {
            x: context.guess(real.data.oods_point.x),
            y: context.guess(real.data.oods_point.y),
        };
        let composition = core::array::from_fn(|c| {
            context.guess(real.values.stark.sampled[real.shape.stark.sample_index[3][c]])
        });
        oods::check(
            &mut context,
            &real.shape.stark.compiled,
            &wires,
            coeff,
            oods_point,
            real.shape.stark.layout.max_log_degree_bound,
            composition,
        );
        context.mismatches().len()
    };
    assert_eq!(run(None), 0);
    let last_of = |pick: &dyn Fn(&CompiledInput) -> bool| inputs.iter().rposition(pick).unwrap();
    let running_sum = last_of(&|input| matches!(input, CompiledInput::Sample(_)));
    let claimed = last_of(&|input| matches!(input, CompiledInput::ClaimedSum(_)));
    // The register-memory relation's `z`: a relation only chips idle on the
    // trace use samples to zero there whatever `z` is.
    let register = real.shape.boundary.unwrap().relations[0];
    let challenge = last_of(&|input| *input == CompiledInput::Challenge(register, 0));
    for tamper in [running_sum, claimed, challenge] {
        assert_eq!(run(Some(tamper)), 1, "{:?}", inputs[tamper]);
    }
}

/// The logup sums alone, from the native claimed sums, boundary bytes and
/// challenges: accepted; a claimed sum or a boundary byte tampered refused.
#[test]
fn the_logup_sums_accept_and_refuse() {
    let real = fixture();
    let challenges = real.challenges();
    let run = |sum: Option<usize>, byte: Option<usize>| {
        let mut context = Context::<SecureField>::new().lenient();
        let claimed: Vec<Var> = real
            .values
            .stark
            .claimed_sums
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let mut v = v;
                if sum == Some(i) {
                    bump(&mut v);
                }
                context.guess(v)
            })
            .collect();
        let boundary: Vec<Var> = real
            .values
            .boundary
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let mut v = v;
                if byte.is_some_and(|byte| byte / 4 == i) {
                    let mut limbs = v.to_m31_array();
                    limbs[byte.unwrap() % 4] += BaseField::one();
                    v = SecureField::from_m31_array(limbs);
                }
                context.guess(v)
            })
            .collect();
        let mut challenge = |r: usize| {
            let [z, alpha] = challenges[r];
            Challenges {
                z: context.guess(z),
                alpha: context.guess(alpha),
            }
        };
        let terms = real.shape.boundary.unwrap();
        let [register, program, merkle] = terms.relations;
        let relations = BoundaryRelations {
            register_memory: challenge(register),
            program_execution: challenge(program),
            merkle_node: challenge(merkle),
        };
        logup::check(
            &mut context,
            &claimed,
            &terms.positions,
            &boundary,
            &relations,
        );
        context.mismatches().len()
    };
    assert_eq!(run(None, None), 0);
    let positions = real.shape.boundary.unwrap().positions;
    // A boundary chip's sum: the total and its public term.
    assert_eq!(run(Some(positions.register_closing), None), 2);
    // Another chip's: the total.
    assert_eq!(run(Some(0), None), 1);
    // A byte of each boundary state: a register in and out, pc and ts in and
    // out, each memory root.
    // The closing timestamp enters the register closing's tuples and the
    // program boundary's consumed one.
    for (byte, refusals) in [
        (5, 1),
        (104 + 9, 1),
        (208, 1),
        (212, 1),
        (220, 1),
        (224, 2),
        (232 + 31, 1),
        (264, 1),
    ] {
        assert_eq!(run(None, Some(byte)), refusals, "byte {byte}");
    }
}
