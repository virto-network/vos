//! The masked prover (`vos_pvm_recair::masked`) on small circuits: the mask
//! keeps a column on its domain, R1 refuses a randomizer too small for what
//! the proof reveals, the FRI mask's DEEP coefficients span QM31, an invalid
//! witness is refused, the prover runs on another channel and component set,
//! every masked root and claimed sum is fresh, and the seeded seam
//! reproduces a proof byte for byte. Each proof is verified by the final
//! verifier's masked verifier (`vos_pvm_final_verifier::masked`), over the
//! set and channel it was proved on, under the format as the verifier pins
//! it (`vos_pvm_recair::masked::verifier_format`).

use crate::common::random_circuit;
use vos_pvm_final_verifier::Error;
use vos_pvm_final_verifier::masked::{Claim, replay, verify_masked};

use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::{DeepCoefficients, deep_values_of_column};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleChannel;
use stwo::prover::backend::Column;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleCoefficients;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::{ComponentProver, ProvingError};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
use vos_pvm_proof::format::{DeepBatching, Format, FormatParams, MASKED_WRAP, Masking};
use vos_pvm_recair::masked::{
    MaskLayout, MaskRng, MaskedProof, MaskedProvers, MaskedTrace, prove_masked, rank_m31,
    verifier_format,
};
use vos_pvm_recair::prove::prove_masked_on;
use vos_pvm_recair::trace::{self, FirstRowFraction};
use vos_pvm_recair::{Finalized, ProveError, RecairProof};
use vos_pvm_recair_air::gate::{GateRelation, Layout, public_logup_sum};
use vos_pvm_recair_air::masked::{BlindRelation, MaskedComponents, MaskedEval, WrapComponents};
use vos_pvm_recair_air::p2::{self, P2Eval};

/// Each component's rows in the small circuits.
const LOG_SIZE: u32 = 9;

/// A masked format for the small circuits, of no registered number: blowup
/// 4, `n_queries` queries, `h = 2^log_mask_rows` and an `R` of
/// `fri_mask_columns`.
fn small_format(log_mask_rows: u32, fri_mask_columns: usize, n_queries: usize) -> Format {
    Format {
        number: 0x7e57,
        params: FormatParams {
            log_blowup: 2,
            n_queries,
            pow_bits: 4,
            fold_step: 1,
            log_last_layer: 0,
            interaction_pow_bits: 4,
            batching: DeepBatching::Affine,
        },
        masking: Some(Masking {
            salt_columns: 8,
            fri_mask_columns,
            log_mask_rows,
        }),
        ..MASKED_WRAP
    }
}

/// The small format R1 passes: `h = 64` against `2(4·2 + 4·3) = 40`
/// revealed rows.
fn format() -> Format {
    small_format(6, 8, 4)
}

/// A random circuit over every gate, each component at `2^LOG_SIZE` rows.
fn circuit(seed: u64) -> Finalized<SecureField> {
    random_circuit::<SecureField>(seed, 300)
        .finalize_to(Some([1 << LOG_SIZE; 3]))
        .expect("the wiring checks")
}

fn prove(
    format: &Format,
    finalized: &Finalized<SecureField>,
    rng: MaskRng,
) -> Result<RecairProof<<Blake2bMerkleChannel as MerkleChannel>::H>, ProveError> {
    prove_masked_on::<Blake2bMerkleChannel>(
        format,
        &finalized.circuit,
        &finalized.witness,
        rng,
        |_| {},
    )
    .map(|(proof, _)| proof)
}

/// The recursion AIR's set at the proof's sizes, under any relations: its
/// trees' layout.
fn wrap_layout(log_sizes: &[u32; 3]) -> WrapComponents {
    WrapComponents::build(
        &GateRelation::dummy(),
        &BlindRelation::dummy(),
        log_sizes,
        &[SecureField::zero(); 3],
    )
}

/// Verifies a masked proof of a small circuit, its outputs at a node's
/// layout.
fn verify(
    format: &Format,
    proof: &RecairProof<<Blake2bMerkleChannel as MerkleChannel>::H>,
) -> Result<(), Error> {
    let public_sum = |relation: &GateRelation| {
        public_logup_sum(
            relation,
            Layout::node(proof.outputs.len() as u32).public_terms(proof.outputs.iter().copied()),
        )
    };
    let layout = wrap_layout(&proof.log_sizes);
    verify_masked::<Blake2bMerkleChannel, WrapComponents>(
        &verifier_format(format, &proof.log_sizes, &layout).expect("a masked format"),
        &Claim {
            log_sizes: &proof.log_sizes,
            circuit: None,
            public: &proof.outputs,
            public_sum: Some(&public_sum),
            interaction_pow: proof.interaction_pow,
            claimed_sums: &proof.claimed_sums,
        },
        &layout,
        proof.stark_proof.clone(),
    )
}

/// `f' = f + v_H·r`: `(f' − f)/v_H`, taken on `2N` points off the trace
/// domain, is a polynomial of exactly `h` coefficients, at every size from
/// `2^6` to `2^17` rows. Of degree below `N + h ≤ 2N`, `v_H` times it agrees
/// with `f' − f` everywhere, so `f'` equals `f` on the trace domain.
#[test]
fn the_mask_keeps_the_column_on_its_domain() {
    let mut rng =
        <rand_chacha::ChaCha20Rng as rand_chacha::rand_core::SeedableRng>::seed_from_u64(1);
    for log_size in 6..=17u32 {
        let log_mask_rows = (log_size - 2).min(8);
        let h = 1usize << log_mask_rows;
        let layout = MaskLayout::new(log_size, log_mask_rows).unwrap();
        let values: Vec<BaseField> = (0..1u32 << log_size)
            .map(|i| BaseField::from(i.wrapping_mul(2_654_435_761) % 1_000_003))
            .collect();
        let domain = CanonicCoset::new(log_size).circle_domain();
        let f = CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(
            domain,
            BaseColumn::from_cpu(&values),
        )
        .interpolate();
        let masked = layout.mask(&f, &mut rng).unwrap();
        assert_eq!(masked.log_size(), log_size + 1);
        let wide = CanonicCoset::new(log_size + 1).circle_domain();
        let difference = masked.evaluate(wide).values.to_cpu();
        let original = f.extend(log_size + 1).evaluate(wide).values.to_cpu();
        let trace_coset = CanonicCoset::new(log_size).coset;
        let quotient: Vec<BaseField> = (0..wide.size())
            .map(|i| {
                let point = wide.at(stwo::core::utils::bit_reverse_index(i, log_size + 1));
                let vanishing = stwo::core::constraints::coset_vanishing(trace_coset, point);
                (difference[i] - original[i]) / vanishing
            })
            .collect();
        let quotient = CircleEvaluation::<SimdBackend, BaseField, BitReversedOrder>::new(
            wide,
            BaseColumn::from_cpu(&quotient),
        )
        .interpolate();
        // The size-`h` basis at `2^(log_size + 1)`: where an `h`-coefficient
        // polynomial's coefficients land when extended.
        let probe: Vec<BaseField> = (1..=h as u32).map(BaseField::from).collect();
        let span: Vec<bool> = CircleCoefficients::<SimdBackend>::new(BaseColumn::from_cpu(&probe))
            .extend(log_size + 1)
            .coeffs
            .to_cpu()
            .iter()
            .map(|c| !c.is_zero())
            .collect();
        let quotient = quotient.coeffs.to_cpu();
        assert!(
            quotient
                .iter()
                .zip(&span)
                .all(|(c, &spanned)| spanned || c.is_zero()),
            "2^{log_size}: (f' − f)/v_H of degree below h"
        );
        let nonzero = quotient.iter().filter(|c| !c.is_zero()).count();
        assert_eq!(nonzero, h, "2^{log_size}");
    }
    assert!(matches!(MaskLayout::new(9, 8), Err(ProveError::Masking(_))));
}

/// R1 refuses `h = 64` against 24 queries, `2(4·2 + 24·3) = 160` revealed
/// rows, after every attempt; at 4 queries the same `h` passes.
#[test]
fn r1_refuses_too_small_a_randomizer() {
    let finalized = circuit(1);
    assert!(matches!(
        prove(&small_format(6, 8, 24), &finalized, MaskRng::default()),
        Err(ProveError::MaskRank)
    ));
    let (_, stats) = prove_masked_on::<Blake2bMerkleChannel>(
        &format(),
        &finalized.circuit,
        &finalized.witness,
        MaskRng::default(),
        |_| {},
    )
    .unwrap();
    assert_eq!(stats.attempts, 1);
    assert!(stats.revealed_rows <= 64, "{stats:?}");
}

/// Whether the FRI mask's DEEP coefficients span QM31 over M31: their
/// `n × 4` matrix of M31 coordinates has rank 4 (R3).
fn spans_qm31(coefficients: &[SecureField]) -> bool {
    rank_m31(
        coefficients
            .iter()
            .map(|c| c.to_m31_array().to_vec())
            .collect(),
    ) == 4
}

/// The coefficients `prove_values` draws for `R`'s columns, replayed: the
/// samples mixed, one coefficient a DEEP value, `R`'s after every earlier
/// tree's values and the composition's 4.
fn fri_mask_coefficients(
    format: &Format,
    proof: &RecairProof<<Blake2bMerkleChannel as MerkleChannel>::H>,
) -> Vec<SecureField> {
    let public_sum = |relation: &GateRelation| {
        public_logup_sum(
            relation,
            Layout::node(proof.outputs.len() as u32).public_terms(proof.outputs.iter().copied()),
        )
    };
    let claim = Claim {
        log_sizes: &proof.log_sizes,
        circuit: None,
        public: &proof.outputs,
        public_sum: Some(&public_sum),
        interaction_pow: proof.interaction_pow,
        claimed_sums: &proof.claimed_sums,
    };
    let layout = wrap_layout(&proof.log_sizes);
    let mut channel = replay::<Blake2bMerkleChannel, WrapComponents>(
        &verifier_format(format, &proof.log_sizes, &layout).expect("a masked format"),
        &claim,
        &layout,
        &proof.stark_proof,
    )
    .unwrap()
    .channel;
    let sampled = &proof.stark_proof.sampled_values;
    channel.mix_felts(&sampled.clone().flatten_cols());
    let values = |trees: &[Vec<Vec<SecureField>>]| -> usize {
        trees
            .iter()
            .flatten()
            .map(|column| deep_values_of_column(column.len()))
            .sum()
    };
    let coefficients =
        DeepCoefficients::draw(&mut channel, format.params.batching, values(&sampled.0));
    let before = values(&sampled.0[..3]) + 4;
    let r = format.masking.unwrap().fri_mask_columns;
    coefficients.iter().skip(before).take(r).collect()
}

/// R3 by construction: an 8-column `R`'s coefficients span QM31 on every
/// transcript, with no check; a 4-column `R`'s coefficients, a planted
/// dependent one among them, are caught.
#[test]
fn fri_mask_coefficients_independent() {
    let finalized = circuit(2);
    let eight = format();
    for _ in 0..4 {
        let proof = prove(&eight, &finalized, MaskRng::default()).unwrap();
        verify(&eight, &proof).unwrap();
        let coefficients = fri_mask_coefficients(&eight, &proof);
        assert_eq!(coefficients.len(), 8);
        assert!(spans_qm31(&coefficients));
    }
    let four = small_format(6, 4, 4);
    let proof = prove(&four, &finalized, MaskRng::default()).unwrap();
    verify(&four, &proof).unwrap();
    let mut coefficients = fri_mask_coefficients(&four, &proof);
    assert_eq!(coefficients.len(), 4);
    assert!(spans_qm31(&coefficients));
    coefficients[3] = coefficients[0] + coefficients[1] * BaseField::from(5) - coefficients[2];
    assert!(!spans_qm31(&coefficients));
}

/// A witness that breaks a constraint is refused by the prover's own
/// out-of-domain check, the qm31 limb a relation reads and the S-box no
/// relation reads alike.
#[test]
fn an_invalid_witness_is_refused() {
    let finalized = circuit(3);
    for (component, column) in [(1, 0), (0, 16)] {
        let refused = prove_masked_on::<Blake2bMerkleChannel>(
            &format(),
            &finalized.circuit,
            &finalized.witness,
            MaskRng::default(),
            |main| main.columns[component][column][3] += BaseField::one(),
        );
        assert!(
            matches!(
                refused,
                Err(ProveError::Stwo(ProvingError::ConstraintsNotSatisfied))
            ),
            "component {component}, column {column}: {:?}",
            refused.map(|_| ())
        );
    }
    assert!(matches!(
        prove(&vos_pvm_proof::format::WRAP, &finalized, MaskRng::default()),
        Err(ProveError::UnmaskedFormat)
    ));
}

/// The recursion AIR's `p2` alone: a component set of one, which the masked
/// prover takes as it takes the wrap's. A set of one is not blinded, its
/// claimed sum in the clear; this test's verifier checks no logup total
/// (`p2`'s relation does not balance alone), so it tests the transcript,
/// not zero knowledge.
struct P2Only {
    p2: FrameworkComponent<MaskedEval<P2Eval>>,
    log_sizes: [u32; 1],
}

impl MaskedComponents for P2Only {
    type Relations = GateRelation;

    fn draw_relations(channel: &mut impl Channel) -> GateRelation {
        GateRelation::draw(channel)
    }

    fn new(
        relation: &GateRelation,
        blind: &BlindRelation,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Option<Self> {
        let (&[log_size], &[claimed_sum]) = (log_sizes, claimed_sums) else {
            return None;
        };
        let ids: Vec<PreProcessedColumnId> = p2::PREPROCESSED
            .iter()
            .map(|&id| PreProcessedColumnId { id: id.into() })
            .collect();
        let p2 = FrameworkComponent::new(
            &mut TraceLocationAllocator::new_with_preprocessed_columns(&ids),
            MaskedEval::new(
                P2Eval {
                    log_size,
                    relation: relation.clone(),
                },
                blind,
            ),
            claimed_sum,
        );
        Some(Self {
            p2,
            log_sizes: [log_size],
        })
    }

    fn log_sizes(&self) -> &[u32] {
        &self.log_sizes
    }

    fn preprocessed_log_sizes(&self) -> Vec<u32> {
        vec![self.log_sizes[0]; p2::PREPROCESSED.len()]
    }

    fn components(&self) -> Vec<&dyn Component> {
        vec![&self.p2]
    }
}

impl MaskedProvers for P2Only {
    fn provers(&self) -> Vec<&dyn ComponentProver<SimdBackend>> {
        vec![&self.p2]
    }
}

/// Generic: the masked prover and the tests' verifier on the Blake2s
/// channel over the `p2`-only set; a tampered sample is refused.
#[test]
fn the_masked_prover_is_generic() {
    let finalized = circuit(4);
    let circuit = &finalized.circuit;
    circuit.check_wiring().unwrap();
    let log_sizes = [LOG_SIZE];
    let preprocessed = trace::evaluations(&trace::preprocessed_columns(circuit)[0], LOG_SIZE);
    let main = trace::main_trace(circuit, &finalized.witness);
    let interaction = |relation: &GateRelation, blinding: &[FirstRowFraction]| {
        let [p2, _, _] =
            main.interaction_with(circuit, relation, [blinding.first().copied(), None, None]);
        vec![p2]
    };
    let format = format();
    let prove = || {
        prove_masked::<Blake2sMerkleChannel, P2Only>(
            &format,
            MaskedTrace {
                log_sizes: &log_sizes,
                preprocessed: preprocessed.clone(),
                main: vec![trace::evaluations(&main.columns[0], LOG_SIZE)],
                public: &finalized.witness.outputs,
                interaction: &interaction,
            },
            MaskRng::default(),
        )
        .unwrap()
        .0
    };
    let proof: MaskedProof<_> = prove();
    let layout = P2Only::new(
        &GateRelation::dummy(),
        &BlindRelation::dummy(),
        &log_sizes,
        &[SecureField::zero()],
    )
    .unwrap();
    let pinned = verifier_format(&format, &log_sizes, &layout).expect("a masked format");
    let claim = |proof: &MaskedProof<_>| -> Result<(), Error> {
        verify_masked::<Blake2sMerkleChannel, P2Only>(
            &pinned,
            &Claim {
                log_sizes: &log_sizes,
                circuit: None,
                public: &finalized.witness.outputs,
                public_sum: None,
                interaction_pow: proof.interaction_pow,
                claimed_sums: &proof.claimed_sums,
            },
            &layout,
            proof.stark_proof.clone(),
        )
    };
    claim(&proof).unwrap();
    // The main tree: `p2`'s columns, its blinding's 4 and 8 salts.
    assert_eq!(
        proof.stark_proof.queried_values[1].len(),
        p2::N_MAIN + 4 + 8
    );
    let mut tampered = proof.clone();
    tampered.stark_proof.0.sampled_values[1][0][0] += SecureField::one();
    assert!(claim(&tampered).is_err());
    let mut tampered = proof.clone();
    tampered.stark_proof.0.queried_values[1][p2::N_MAIN + 4][0] += BaseField::one();
    assert!(claim(&tampered).is_err());
    let other = prove();
    assert_ne!(
        other.stark_proof.commitments[1],
        proof.stark_proof.commitments[1]
    );
}

/// Two proofs of one witness share only the preprocessed root: every masked
/// root and every blinded claimed sum is fresh. The seeded seam reproduces a
/// proof byte for byte, and another seed does not.
#[test]
fn every_masked_value_is_fresh_and_the_seam_reproduces_bytes() {
    let finalized = circuit(5);
    let format = format();
    let [first, second] = [(); 2].map(|_| prove(&format, &finalized, MaskRng::default()).unwrap());
    for proof in [&first, &second] {
        verify(&format, proof).unwrap();
    }
    let (a, b) = (
        &first.stark_proof.commitments,
        &second.stark_proof.commitments,
    );
    assert_eq!(a[0], b[0]);
    for tree in 1..4 {
        assert_ne!(a[tree], b[tree], "tree {tree}");
    }
    for (x, y) in first.claimed_sums.iter().zip(&second.claimed_sums) {
        assert_ne!(x, y);
    }

    let bytes =
        |rng: MaskRng| postcard::to_allocvec(&prove(&format, &finalized, rng).unwrap()).unwrap();
    let seeded = bytes(MaskRng::Seeded(7));
    assert_eq!(seeded, bytes(MaskRng::Seeded(7)));
    assert_ne!(seeded, bytes(MaskRng::Seeded(8)));
}
