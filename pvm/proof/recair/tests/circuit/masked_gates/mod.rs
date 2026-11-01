//! The masking's soundness and leakage gates (`docs/design/proving.md` §5)
//! on small circuits of the recursion AIR, each proof verified by the final
//! verifier's masked verifier over the set and channel it was proved on.
//! The gates other files hold are theirs: the degree audit (`masked.rs`),
//! the mask invariant and R1's refusal (`masked_prover.rs`), each masked
//! field tampered and both bit counts (`format::MASKED_WRAP`'s own tests).
//!
//! **Soundness:** masked proofs verify at every size, alone and mixed, on
//! both channels (Blake2b-256 and Poseidon2-M31); a broken constraint on
//! the first, the last and the wrap row is refused by the prover, and a
//! forced proof of it by the verifier; a verifier laying the preprocessed
//! columns at `n` refuses them at `n + 1`; an unbalanced relation is refused,
//! and the blinding cannot cancel it; a malformed proof is an error, never
//! a panic.
//!
//! **Leakage:** R1 checks every column class on every proof; every opening
//! is fresh, and a replayed seed draws other masks for another witness; a
//! right guess reproduces an unblinded claimed sum, never a blinded one; a
//! proof's shape is the format's and its coins'. Witness
//! indistinguishability and uniformity are `leakage.rs`'s; no hidden state
//! in a carrier, the real wrap's.

mod freshness;
mod malformed;
mod shape;
mod soundness;

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::common::leakage::published;
use crate::common::random_circuit;
use crate::leakage::{Witness as PrivateWitness, private_circuit};
use crate::masked_prover::{
    LOG_SIZE, Proof, circuit, format, prove, public_sum, verify, verify_as, wrap_layout,
};

use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::{CirclePolyDegreeBound, FriVerifier};
use stwo::core::pcs::quotients::{DeepCoefficients, deep_values_of_column};
use stwo::core::pcs::utils::prepare_preprocessed_query_positions;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::LinePoly;
use stwo::core::queries::Queries;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleChannel;
use stwo::prover::ProvingError;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::fri::FriProver;
use stwo::prover::poly::circle::{PolyOps, SecureEvaluation};
use stwo::prover::secure_column::SecureColumnByCoords;
use vos_pvm_final_verifier::Error;
use vos_pvm_final_verifier::masked::{Claim, replay, verify_masked};
use vos_pvm_poseidon2::{M31, N_STATE};
use vos_pvm_proof::format::Format;
use vos_pvm_proof::poseidon2::P2MerkleChannel;
use vos_pvm_proof::proof::mix_statement_header;
use vos_pvm_recair::circuit::Qm31Wiring;
use vos_pvm_recair::masked::{
    MaskRng, MaskedTrace, prove_masked, prove_masked_unchecked, verifier_format,
};
use vos_pvm_recair::prove::prove_on;
use vos_pvm_recair::trace::{self, FirstRowFraction, MainTrace};
use vos_pvm_recair::{Circuit, Finalized, ProveError, RecairProof, Witness};
use vos_pvm_recair_air::gate::GateRelation;
use vos_pvm_recair_air::masked::{
    BlindRelation, MaskedComponent, MaskedComponents, WrapComponents, composition_log_degree_bound,
    sample_points,
};
use vos_pvm_recair_air::{h8, p2, qm31};

/// A random circuit of every gate, each component at `2^log_sizes` rows.
fn sized(seed: u64, log_sizes: [u32; 3]) -> Finalized<SecureField> {
    random_circuit::<SecureField>(seed, 200)
        .finalize_to(Some(log_sizes.map(|log_size| 1 << log_size)))
        .expect("the wiring checks")
}

/// The recursion AIR's set proved masked over `circuit` and `witness`, as
/// `prove_masked_on` proves it but with the wiring unchecked: the main trace
/// through `tamper`, each component's blinding fraction through `blind`
/// once the relations are drawn, and the prover's own check of the
/// constraints made when `checked` (a forced proof otherwise).
fn prove_set<MC: MerkleChannel>(
    format: &Format,
    circuit: &Circuit,
    witness: &Witness<SecureField>,
    tamper: impl FnOnce(&mut MainTrace),
    blind: impl Fn(&GateRelation, &mut [FirstRowFraction]),
    checked: bool,
) -> Result<Proof<MC>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let log_sizes = circuit.log_sizes();
    let mut main = trace::main_trace(circuit, witness);
    tamper(&mut main);
    let preprocessed = trace::preprocessed_columns(circuit)
        .iter()
        .zip(log_sizes)
        .flat_map(|(columns, log_size)| trace::evaluations(columns, log_size))
        .collect();
    let main_columns: Vec<trace::Evaluations> = main
        .columns
        .iter()
        .zip(log_sizes)
        .map(|(columns, log_size)| trace::evaluations(columns, log_size))
        .collect();
    let interaction = |relation: &GateRelation, blinding: &[FirstRowFraction]| {
        let mut fractions = blinding.to_vec();
        blind(relation, &mut fractions);
        let extra = core::array::from_fn(|component| fractions.get(component).copied());
        Vec::from(main.interaction_with(circuit, relation, extra))
    };
    let trace = MaskedTrace {
        active: (),
        log_sizes: &log_sizes,
        preprocessed,
        main: &|component: usize| {
            main_columns[component]
                .iter()
                .map(|column| &column.values)
                .collect()
        },
        public: &witness.outputs,
        interaction: &interaction,
    };
    let rng = MaskRng::Seeded(6);
    let (proof, _) = if checked {
        prove_masked::<MC, WrapComponents>(format, trace, rng)
    } else {
        prove_masked_unchecked::<MC, WrapComponents>(format, trace, rng)
    }?;
    Ok(RecairProof {
        format_version: format.number,
        log_sizes,
        outputs: witness.outputs.clone(),
        interaction_pow: proof.interaction_pow,
        claimed_sums: proof.claimed_sums.try_into().expect("three components"),
        stark_proof: proof.stark_proof,
    })
}

/// The column classes R1 must check on a set: each masked column with
/// samples (the main and interaction trees'), by its level, its quotient's
/// lift and its offsets from the out-of-domain point, each class once.
/// It reads the points from `sample_points`, as R1 does: it holds R1's walk
/// over the classes, not the sample points themselves (those are
/// `masked.rs`' tests and the verifier's).
fn column_classes(set: &WrapComponents, format: &Format) -> usize {
    let pins = vos_pvm_recair::masked::mask_pins(&format.masking.expect("masked"));
    let z = CirclePoint::<SecureField>::get_point(98_765);
    let points = sample_points(set, z, &pins).expect("the sample points");
    let composition = composition_log_degree_bound(set).expect("the composition's bound");
    let mut classes = BTreeSet::new();
    let mut offsets = [0usize; 4];
    for inner in set.components() {
        let lifted = MaskedComponent { inner };
        let lift = composition - lifted.max_constraint_log_degree_bound();
        for (tree, levels) in lifted.trace_log_degree_bounds().iter().enumerate() {
            let start = offsets[tree];
            offsets[tree] += levels.len();
            if tree == 0 {
                continue;
            }
            for (column, &level) in levels.iter().enumerate() {
                let shifts: Vec<String> = points[tree][start + column]
                    .iter()
                    .map(|&point| format!("{:?}", point - z))
                    .collect();
                classes.insert((level, lift, shifts));
            }
        }
    }
    classes.len()
}

/// The sizes the acceptance runs at, `2^n` rows a component: each from the
/// smallest the small format's randomizer takes (`h = 64 ≤ N/4`) to `2^12`,
/// and sets of mixed sizes, lifted to their tallest.
const SIZES: [[u32; 3]; 8] = [
    [8, 8, 8],
    [9, 9, 9],
    [10, 10, 10],
    [11, 11, 11],
    [12, 12, 12],
    [10, 8, 9],
    [8, 12, 10],
    [12, 9, 8],
];

/// A masked proof at `log_sizes` on `MC`: it verifies, and R1 checked every
/// column class, its randomizer of full rank on the first attempt.
fn accepted_on<MC: MerkleChannel>(finalized: &Finalized<SecureField>, name: &str)
where
    SimdBackend: BackendForChannel<MC>,
{
    let format = format();
    let (proof, stats) = prove::<MC>(&format, finalized, MaskRng::Seeded(1)).expect("proves");
    verify::<MC>(&format, &proof).unwrap_or_else(|error| panic!("{name}: {error}"));
    let classes = column_classes(&wrap_layout(&proof.log_sizes), &format);
    eprintln!(
        "{name} at {:?}: verified; R1 over {} classes, {} rows at most of 64, {} attempt(s)",
        proof.log_sizes, stats.classes, stats.revealed_rows, stats.attempts
    );
    assert_eq!(stats.classes, classes, "{name}");
    assert!(stats.revealed_rows <= 64, "{name}: {stats:?}");
    assert_eq!(stats.attempts, 1, "{name}");
}

/// The relation a masked or unmasked proof of the recursion AIR draws: its
/// transcript replayed to the relation, after the main tree's root, the
/// outputs and the interaction PoW.
fn drawn_relation<MC: MerkleChannel>(format: &Format, proof: &Proof<MC>) -> GateRelation {
    let mut channel = MC::C::default();
    mix_statement_header(
        &mut channel,
        format.number,
        &format.pcs_config(),
        &proof.log_sizes,
    );
    MC::mix_root(&mut channel, proof.stark_proof.commitments[0]);
    MC::mix_root(&mut channel, proof.stark_proof.commitments[1]);
    channel.mix_felts(&proof.outputs);
    channel.mix_u64(proof.interaction_pow);
    GateRelation::draw(&mut channel)
}
