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

/// Masked acceptance, lifting and the rank: a masked proof verifies at
/// every size, each component alone at `2^8` to `2^12` rows and mixed in
/// one proof, on both channels; R1 checks every column class of each.
#[test]
fn masked_proofs_verify_at_every_size_on_both_channels() {
    for (seed, &log_sizes) in SIZES.iter().enumerate() {
        let finalized = sized(seed as u64, log_sizes);
        accepted_on::<Blake2bMerkleChannel>(&finalized, "Blake2b-256");
        accepted_on::<P2MerkleChannel>(&finalized, "Poseidon2-M31");
    }
}

/// Masked acceptance above the SIMD backend's `2^16`: `p2` at `2^17` rows, the
/// others below, on both channels.
#[cfg(feature = "heavy-gates")]
#[test]
fn heavy_masked_proofs_verify_above_2_16() {
    let finalized = sized(17, [17, 15, 12]);
    accepted_on::<Blake2bMerkleChannel>(&finalized, "Blake2b-256");
    accepted_on::<P2MerkleChannel>(&finalized, "Poseidon2-M31");
}

/// A tamper refused both ways: the prover's check refuses it, and the
/// verifier a forced proof of it.
fn refused_both_ways(
    name: &str,
    circuit: &Circuit,
    witness: &Witness<SecureField>,
    tamper: impl Fn(&mut MainTrace),
) {
    let format = format();
    let refused =
        prove_set::<Blake2bMerkleChannel>(&format, circuit, witness, &tamper, |_, _| {}, true);
    assert!(
        matches!(
            refused,
            Err(ProveError::Stwo(ProvingError::ConstraintsNotSatisfied))
        ),
        "{name}: the prover {:?}",
        refused.map(|_| ())
    );
    let forced =
        prove_set::<Blake2bMerkleChannel>(&format, circuit, witness, &tamper, |_, _| {}, false)
            .expect("a forced proof");
    let error = verify::<Blake2bMerkleChannel>(&format, &forced).expect_err(name);
    eprintln!("{name}: refused by the prover; forced, by the verifier: {error}");
    assert!(
        matches!(
            error,
            Error::Stark(stwo::core::verifier::VerificationError::OodsNotMatching)
        ),
        "{name}: {error}"
    );
}

/// `finalized` with one component's rows turned left by `by`: the same
/// constraints over the cyclic domain and the same relation (a `p2` row
/// chained to its predecessor stays after it, across the domain's end).
fn rotated(
    finalized: &Finalized<SecureField>,
    component: usize,
    by: usize,
) -> (Circuit, Witness<SecureField>) {
    let (mut circuit, mut witness) = (finalized.circuit.clone(), finalized.witness.clone());
    match component {
        0 => {
            circuit.p2.rotate_left(by);
            witness.p2.rotate_left(by);
        }
        1 => {
            circuit.qm31.rotate_left(by);
            witness.qm31.rotate_left(by);
        }
        _ => {
            circuit.h8.rotate_left(by);
            witness.h8.rotate_left(by);
        }
    }
    (circuit, witness)
}

/// `finalized`'s `p2` rows turned so that row 0 is a chained row whose
/// output no gate reads by the relation: row 0 reads the last row at
/// offset −1, a layout the wiring check refuses only because it never
/// chains row 0.
fn chained_row_first(finalized: &Finalized<SecureField>) -> (Circuit, Witness<SecureField>) {
    let chained = finalized
        .circuit
        .p2
        .iter()
        .position(|row| {
            row.mode.is_some_and(|mode| mode.is_chained()) && row.out_multiplicity == [0, 0]
        })
        .expect("a chained row of an unread output");
    rotated(finalized, 0, chained)
}

/// `finalized`'s `qm31` rows turned so that the first and the last rows are
/// padding (no coefficient, no relation entry): a broken `out` there breaks
/// the gate's constraint alone.
fn qm31_padding_at_both_ends(
    finalized: &Finalized<SecureField>,
) -> (Circuit, Witness<SecureField>) {
    let padding = Qm31Wiring::default();
    let rows = &finalized.circuit.qm31;
    let first = rows
        .iter()
        .position(|row| *row == padding)
        .expect("padding rows");
    assert!(rows.len() - first >= 2, "two padding rows");
    let (circuit, witness) = rotated(finalized, 1, first + 1);
    assert_eq!(circuit.qm31[0], padding);
    assert_eq!(circuit.qm31[rows.len() - 1], padding);
    (circuit, witness)
}

/// Row `row`'s `p2` permutation recomputed from its input with the first
/// word plus 1: every S-box of the row holds, and only what reads its
/// input (the chaining to the previous row) breaks.
fn input_plus_one(main: &mut MainTrace, row: usize) {
    let columns = &mut main.columns[0];
    let mut input: [M31; N_STATE] =
        core::array::from_fn(|word| M31::new(columns[p2::main::INPUT + word][row].0));
    input[0] = M31::new((input[0].value() + 1) % stwo::core::fields::m31::P);
    let mut permutation = vec![M31::ZERO; p2::main::M];
    p2::permutation_columns(input, &mut permutation);
    for (column, word) in permutation.iter().enumerate() {
        columns[column][row] = BaseField::from_u32_unchecked(word.value());
    }
}

/// A constraint tampered: one broken constraint on the first row, the last
/// row and the wrap row of each component is refused by the prover's own
/// check, and a proof forced past it by the verifier's out-of-domain check.
/// A `qm31` row is broken on padding rows turned to both ends, so that no
/// relation entry moves. The wrap row: the `p2` rows turned so that row 0
/// is chained and reads the last row across the domain's end, which an
/// honest proof keeps; then row 0's permutation recomputed from another
/// input, so that only its chaining to the last row breaks.
#[test]
fn a_broken_constraint_on_the_first_last_or_wrap_row_is_refused() {
    let finalized = circuit(11);
    let last = (1 << LOG_SIZE) - 1;
    let (qm31_circuit, qm31_witness) = qm31_padding_at_both_ends(&finalized);
    let constrained = [
        (
            "p2's first S-box",
            0,
            p2::main::SBOXES,
            &finalized.circuit,
            &finalized.witness,
        ),
        (
            "qm31's out on padding",
            1,
            qm31::N_MAIN - 4,
            &qm31_circuit,
            &qm31_witness,
        ),
        (
            "h8's first Horner step",
            2,
            h8::main::Q,
            &finalized.circuit,
            &finalized.witness,
        ),
    ];
    for (name, component, column, circuit, witness) in constrained {
        for (row_name, row) in [("first", 0), ("last", last)] {
            refused_both_ways(
                &format!("{name} on the {row_name} row"),
                circuit,
                witness,
                |main| main.columns[component][column][row] += BaseField::one(),
            );
        }
    }

    let (circuit, witness) = chained_row_first(&finalized);
    let format = format();
    let honest =
        prove_set::<Blake2bMerkleChannel>(&format, &circuit, &witness, |_| {}, |_, _| {}, true)
            .expect("row 0 chained to the last row proves");
    verify::<Blake2bMerkleChannel>(&format, &honest).expect("and verifies");
    refused_both_ways(
        "the wrap row's chaining (row 0's permutation of another input)",
        &circuit,
        &witness,
        |main| input_plus_one(main, 0),
    );
}

/// The wrap's set with its preprocessed columns laid at their rows' level
/// `n`, not the masked `n + 1`: a verifier that does not lift them.
struct Unlifted(WrapComponents);

impl MaskedComponents for Unlifted {
    type Relations = GateRelation;
    type Active = ();

    fn draw_relations((): (), channel: &mut impl Channel) -> GateRelation {
        WrapComponents::draw_relations((), channel)
    }

    fn new(
        (): (),
        relation: &GateRelation,
        blind: &BlindRelation,
        log_sizes: &[u32],
        claimed_sums: &[SecureField],
    ) -> Option<Self> {
        WrapComponents::new((), relation, blind, log_sizes, claimed_sums).map(Self)
    }

    fn layout((): (), log_sizes: &[u32]) -> Option<Self> {
        <WrapComponents as MaskedComponents>::layout((), log_sizes).map(Self)
    }

    fn active(&self) {}

    fn log_sizes(&self) -> &[u32] {
        self.0.log_sizes()
    }

    fn preprocessed_log_sizes(&self) -> Vec<u32> {
        self.0
            .preprocessed_log_sizes()
            .into_iter()
            .map(|log_size| log_size - 1)
            .collect()
    }

    fn components(&self) -> Vec<&dyn Component> {
        self.0.components()
    }

    fn bind<'a>(
        &'a self,
        relation: &GateRelation,
        blind: &BlindRelation,
        claimed_sums: &[SecureField],
    ) -> Option<Vec<Box<dyn Component + 'a>>> {
        self.0.bind(relation, blind, claimed_sums)
    }
}

/// Lifting: the preprocessed columns verify at `n + 1`, as the prover
/// commits them; a verifier laying them at `n` refuses the proof, with an
/// error.
#[test]
fn the_preprocessed_columns_verify_only_lifted() {
    let format = format();
    let (proof, _) =
        prove::<Blake2bMerkleChannel>(&format, &sized(12, [10, 8, 9]), MaskRng::Seeded(12))
            .expect("proves");
    verify::<Blake2bMerkleChannel>(&format, &proof).expect("verifies lifted");
    let layout = Unlifted(wrap_layout(&proof.log_sizes));
    let error = catch_unwind(AssertUnwindSafe(|| {
        verify_as::<Blake2bMerkleChannel, _>(&format, &proof, &layout)
    }))
    .expect("an error, never a panic")
    .expect_err("refused at n");
    eprintln!("the preprocessed columns at n: {error}");
}

/// A `qm31` row whose output is linear in `a` (no product): its row and
/// `k_a`, with `a` a use of the relation.
fn linear_row(circuit: &Circuit) -> (usize, BaseField) {
    circuit
        .qm31
        .iter()
        .enumerate()
        .find(|(_, row)| {
            row.op.k_m.is_zero()
                && row.op.k_p.is_zero()
                && !row.op.k_a.is_zero()
                && row.operands[0].multiplicity != 0
        })
        .map(|(at, row)| (at, row.op.k_a))
        .expect("a linear row")
}

/// The blinding's soundness (R2): a witness whose every row holds but whose
/// relation does not balance (one `qm31` row reads `a + 1` and yields its
/// output accordingly) proves, and the verifier refuses its logup total. A
/// prover that sets its blinding to cancel the imbalance at the drawn
/// challenges is refused by its own check, and a proof forced past it by
/// the verifier's out-of-domain check, its total balanced: the blinding
/// columns are committed before the challenges, so they cannot follow them.
#[test]
fn an_unbalanced_relation_cancelled_by_the_blinding_is_refused() {
    let finalized = circuit(13);
    let (circuit, witness) = (&finalized.circuit, &finalized.witness);
    let (row, k_a) = linear_row(circuit);
    let unbalance = |main: &mut MainTrace| {
        main.columns[1][0][row] += BaseField::one();
        main.columns[1][12][row] += k_a;
    };
    let format = format();

    let unbalanced =
        prove_set::<Blake2bMerkleChannel>(&format, circuit, witness, unbalance, |_, _| {}, true)
            .expect("every row holds");
    let error = verify::<Blake2bMerkleChannel>(&format, &unbalanced).expect_err("unbalanced");
    assert!(matches!(error, Error::Logup), "{error}");

    let cancel = |relation: &GateRelation, fractions: &mut [FirstRowFraction]| {
        let mut main = trace::main_trace(circuit, witness);
        unbalance(&mut main);
        let extra = core::array::from_fn(|component| fractions.get(component).copied());
        let total = main
            .interaction_with(circuit, relation, extra)
            .iter()
            .map(|(_, sum)| *sum)
            .sum::<SecureField>()
            + public_sum(&witness.outputs, relation);
        fractions[0].numerator -= total * fractions[0].denominator;
    };
    let refused =
        prove_set::<Blake2bMerkleChannel>(&format, circuit, witness, unbalance, cancel, true);
    assert!(
        matches!(
            refused,
            Err(ProveError::Stwo(ProvingError::ConstraintsNotSatisfied))
        ),
        "{:?}",
        refused.map(|_| ())
    );
    let forced =
        prove_set::<Blake2bMerkleChannel>(&format, circuit, witness, unbalance, cancel, false)
            .expect("a forced proof");
    let relation = drawn_relation::<Blake2bMerkleChannel>(&format, &forced);
    assert!(
        (forced.claimed_sums.iter().copied().sum::<SecureField>()
            + public_sum(&forced.outputs, &relation))
        .is_zero(),
        "the forced total balances"
    );
    let error = verify::<Blake2bMerkleChannel>(&format, &forced).expect_err("forced");
    assert!(
        matches!(
            error,
            Error::Stark(stwo::core::verifier::VerificationError::OodsNotMatching)
        ),
        "{error}"
    );
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

/// The structure: a proof malformed in any field of its structure is refused
/// with an error, never a panic: a tree, a column, a sample, a queried
/// value, a witness hash or a FRI layer more or fewer, another last layer,
/// claimed sums or log sizes of another count, another configuration.
#[test]
fn a_malformed_proof_is_an_error_never_a_panic() {
    let format = format();
    let finalized = circuit(14);
    let (proof, _) =
        prove::<Blake2bMerkleChannel>(&format, &finalized, MaskRng::Seeded(14)).expect("proves");
    verify::<Blake2bMerkleChannel>(&format, &proof).expect("verifies");
    type P = Proof<Blake2bMerkleChannel>;
    type Mutation = Box<dyn Fn(&mut P)>;
    let mut cases: Vec<(String, Mutation)> = Vec::new();
    let mut case = |name: String, mutation: Mutation| cases.push((name, mutation));
    case(
        "a commitment fewer".into(),
        Box::new(|p| {
            p.stark_proof.0.commitments.pop();
        }),
    );
    case(
        "a commitment more".into(),
        Box::new(|p| {
            let root = p.stark_proof.0.commitments[0];
            p.stark_proof.0.commitments.push(root);
        }),
    );
    for tree in 0..4 {
        case(
            format!("tree {tree}'s samples dropped"),
            Box::new(move |p| {
                p.stark_proof.0.sampled_values.remove(tree);
            }),
        );
        case(
            format!("tree {tree}'s queried values dropped"),
            Box::new(move |p| {
                p.stark_proof.0.queried_values.remove(tree);
            }),
        );
        case(
            format!("tree {tree}'s decommitment dropped"),
            Box::new(move |p| {
                p.stark_proof.0.decommitments.remove(tree);
            }),
        );
        case(
            format!("tree {tree}: a sampled column fewer"),
            Box::new(move |p| {
                p.stark_proof.0.sampled_values[tree].pop();
            }),
        );
        case(
            format!("tree {tree}: a sampled column more"),
            Box::new(move |p| p.stark_proof.0.sampled_values[tree].push(vec![SecureField::one()])),
        );
        case(
            format!("tree {tree}: a sample more on its first column"),
            Box::new(move |p| p.stark_proof.0.sampled_values[tree][0].push(SecureField::one())),
        );
        case(
            format!("tree {tree}: its first column's samples cleared"),
            Box::new(move |p| p.stark_proof.0.sampled_values[tree][0].clear()),
        );
        case(
            format!("tree {tree}: a queried column fewer"),
            Box::new(move |p| {
                p.stark_proof.0.queried_values[tree].pop();
            }),
        );
        case(
            format!("tree {tree}: a queried column more"),
            Box::new(move |p| {
                let column = p.stark_proof.0.queried_values[tree][0].clone();
                p.stark_proof.0.queried_values[tree].push(column)
            }),
        );
        case(
            format!("tree {tree}: a queried value fewer on its first column"),
            Box::new(move |p| {
                p.stark_proof.0.queried_values[tree][0].pop();
            }),
        );
        case(
            format!("tree {tree}: a queried value more on its first column"),
            Box::new(move |p| p.stark_proof.0.queried_values[tree][0].push(BaseField::one())),
        );
        case(
            format!("tree {tree}: a queried value fewer on every column"),
            Box::new(move |p| {
                for column in &mut p.stark_proof.0.queried_values[tree] {
                    column.pop();
                }
            }),
        );
        case(
            format!("tree {tree}: a queried value more on every column"),
            Box::new(move |p| {
                for column in &mut p.stark_proof.0.queried_values[tree] {
                    column.push(BaseField::one());
                }
            }),
        );
        case(
            format!("tree {tree}: a witness hash fewer"),
            Box::new(move |p| {
                p.stark_proof.0.decommitments[tree].hash_witness.pop();
            }),
        );
        case(
            format!("tree {tree}: a witness hash more"),
            Box::new(move |p| {
                let root = p.stark_proof.0.commitments[tree];
                p.stark_proof.0.decommitments[tree].hash_witness.push(root)
            }),
        );
    }
    case(
        "FRI's first layer: a witness value fewer".into(),
        Box::new(|p| {
            p.stark_proof.0.fri_proof.first_layer.fri_witness.pop();
        }),
    );
    case(
        "FRI's first layer: a witness value more".into(),
        Box::new(|p| {
            p.stark_proof
                .0
                .fri_proof
                .first_layer
                .fri_witness
                .push(SecureField::one())
        }),
    );
    case(
        "FRI's first layer: a witness hash fewer".into(),
        Box::new(|p| {
            p.stark_proof
                .0
                .fri_proof
                .first_layer
                .decommitment
                .hash_witness
                .pop();
        }),
    );
    case(
        "FRI: an inner layer fewer".into(),
        Box::new(|p| {
            p.stark_proof.0.fri_proof.inner_layers.pop();
        }),
    );
    case(
        "FRI: an inner layer more".into(),
        Box::new(|p| {
            let layer = p.stark_proof.0.fri_proof.first_layer.clone();
            p.stark_proof.0.fri_proof.inner_layers.push(layer)
        }),
    );
    case(
        "FRI: an inner layer's witness value fewer".into(),
        Box::new(|p| {
            if let Some(layer) = p.stark_proof.0.fri_proof.inner_layers.first_mut() {
                layer.fri_witness.pop();
            }
        }),
    );
    case(
        "FRI: a last layer of twice the coefficients".into(),
        Box::new(|p| {
            let coefficients = p.stark_proof.0.fri_proof.last_layer_poly.len();
            p.stark_proof.0.fri_proof.last_layer_poly =
                LinePoly::new(vec![SecureField::one(); 2 * coefficients]);
        }),
    );
    case(
        "another PoW nonce".into(),
        Box::new(|p| p.stark_proof.0.proof_of_work ^= 1),
    );
    case(
        "another blowup".into(),
        Box::new(|p| p.stark_proof.0.config.fri_config.log_blowup_factor += 1),
    );
    case(
        "other queries".into(),
        Box::new(|p| p.stark_proof.0.config.fri_config.n_queries += 1),
    );
    case(
        "another PoW".into(),
        Box::new(|p| p.stark_proof.0.config.pow_bits += 1),
    );
    case(
        "log sizes of another component".into(),
        Box::new(|p| p.log_sizes[2] += 1),
    );
    case(
        "log sizes at the field's bound".into(),
        Box::new(|p| p.log_sizes = [31; 3]),
    );

    let mut failures = Vec::new();
    // The verifier pins the format's log sizes and lays its set out at
    // them; a proof's own are its claim's.
    let layout = wrap_layout(&proof.log_sizes);
    let pinned = verifier_format(&format, &proof.log_sizes, &layout).expect("a masked format");
    let verified = |proof: &P, log_sizes: &[u32], claimed_sums: &[SecureField]| {
        let public_sum = |relation: &GateRelation| public_sum(&proof.outputs, relation);
        verify_masked::<Blake2bMerkleChannel, WrapComponents>(
            &pinned,
            &Claim {
                log_sizes,
                circuit: None,
                public: &proof.outputs,
                public_sum: Some(&public_sum),
                bound_sums: None,
                interaction_pow: proof.interaction_pow,
                claimed_sums,
            },
            &layout,
            proof.stark_proof.clone(),
        )
    };
    let mut outcome =
        |name: &str, run: &dyn Fn() -> Result<(), Error>| match catch_unwind(AssertUnwindSafe(run))
        {
            Ok(Err(error)) => eprintln!("{name}: {error}"),
            Ok(Ok(())) => failures.push(format!("{name}: accepted")),
            Err(_) => failures.push(format!("{name}: panicked")),
        };
    for (name, mutation) in &cases {
        let mut malformed = proof.clone();
        mutation(&mut malformed);
        let claimed = malformed.claimed_sums;
        outcome(name, &|| {
            verified(&malformed, &malformed.log_sizes, &claimed)
        });
    }
    let pinned = proof.log_sizes;
    let sums = proof.claimed_sums;
    outcome("claimed sums fewer", &|| {
        verified(&proof, &pinned, &sums[..2])
    });
    let more = [sums[0], sums[1], sums[2], SecureField::zero()];
    outcome("claimed sums more", &|| verified(&proof, &pinned, &more));
    outcome("log sizes fewer", &|| verified(&proof, &pinned[..2], &sums));
    let longer = [pinned[0], pinned[1], pinned[2], pinned[2]];
    outcome("log sizes more", &|| verified(&proof, &longer, &sums));
    outcome("log sizes zero", &|| verified(&proof, &[0; 3], &sums));
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Fresh randomness: two proofs of one witness differ in every opening; and a
/// replayed seed with two witnesses (amounts differing by 1) differs in
/// every opening, its masks drawn from the witness's digest too.
#[test]
fn every_opening_is_fresh() {
    let format = format();
    let differing = |a: &Proof<Blake2bMerkleChannel>, b: &Proof<Blake2bMerkleChannel>| {
        let a = published(&a.stark_proof, &a.claimed_sums);
        let b: std::collections::BTreeMap<_, _> = published(&b.stark_proof, &b.claimed_sums)
            .into_iter()
            .collect();
        let shared: Vec<_> = a
            .iter()
            .filter(|(key, value)| b.get(key) == Some(value))
            .collect();
        assert!(a.len() > 1_000, "{} openings", a.len());
        assert!(shared.is_empty(), "openings shared: {shared:?}");
        a.len()
    };
    let finalized = circuit(15);
    let [first, second] = [(); 2].map(|_| {
        prove::<Blake2bMerkleChannel>(&format, &finalized, MaskRng::default())
            .expect("proves")
            .0
    });
    let n = differing(&first, &second);
    let amount = private_circuit(&PrivateWitness::random(15));
    let other = private_circuit(&PrivateWitness::random(15).plus_one());
    let [a, b] = [&amount, &other].map(|finalized| {
        prove::<Blake2bMerkleChannel>(&format, finalized, MaskRng::Seeded(15))
            .expect("proves")
            .0
    });
    let m = differing(&a, &b);
    eprintln!("{n} openings of one witness, {m} of two from one seed: none shared");
}

/// The claimed sums' control. Unblinded (`format::WRAP`'s
/// parameters, unmasked), the sums a right guess of the witness computes
/// at the proof's relation are the proof's; blinded, none is, though their
/// total is (the blinding sums to zero).
#[test]
fn a_right_guess_reproduces_an_unblinded_sum_only() {
    let finalized = circuit(16);
    let (circuit, witness) = (&finalized.circuit, &finalized.witness);
    let guess = |relation: &GateRelation| -> [SecureField; 3] {
        trace::main_trace(circuit, witness)
            .interaction(circuit, relation)
            .map(|(_, sum)| sum)
    };
    let unmasked = Format {
        masked: false,
        masking: None,
        ..format()
    };
    let proof = prove_on::<Blake2bMerkleChannel>(&unmasked, circuit, witness, |_| {}).unwrap();
    let relation = drawn_relation::<Blake2bMerkleChannel>(&unmasked, &proof);
    assert_eq!(guess(&relation), proof.claimed_sums, "unblinded: the guess");

    let masked = format();
    let (proof, _) =
        prove::<Blake2bMerkleChannel>(&masked, &finalized, MaskRng::default()).expect("proves");
    verify::<Blake2bMerkleChannel>(&masked, &proof).unwrap();
    let relation = drawn_relation::<Blake2bMerkleChannel>(&masked, &proof);
    let guessed = guess(&relation);
    for (component, (guessed, claimed)) in guessed.iter().zip(&proof.claimed_sums).enumerate() {
        assert_ne!(guessed, claimed, "blinded: component {component}");
    }
    assert_eq!(
        guessed.iter().copied().sum::<SecureField>(),
        proof.claimed_sums.iter().copied().sum::<SecureField>(),
        "the blinded total"
    );
}

/// The witness hashes a lifted Merkle tree of `height` decommits at
/// `positions`: a node's sibling whenever the sibling is not itself
/// queried, at every level.
fn merkle_witness(positions: &[usize], height: u32) -> usize {
    let mut layer: Vec<usize> = positions.to_vec();
    layer.sort_unstable();
    layer.dedup();
    let mut witness = 0;
    for _ in 0..height {
        let mut parents = Vec::with_capacity(layer.len());
        for pair in layer.chunk_by(|a, b| a ^ 1 == *b) {
            witness += usize::from(pair.len() == 1);
            parents.push(pair[0] >> 1);
        }
        layer = parents;
    }
    witness
}

/// The lengths a proof's layout varies by: each tree's queried values a
/// column and witness hashes, and each FRI layer's witness values and
/// hashes, the last layer's coefficients.
#[derive(Debug, PartialEq, Eq)]
struct Lengths {
    queried: Vec<Vec<usize>>,
    witness_hashes: Vec<usize>,
    fri: Vec<(usize, usize)>,
    last_layer: usize,
}

fn lengths_of<MC: MerkleChannel>(stark: &stwo::core::proof::StarkProof<MC::H>) -> Lengths {
    let fri = &stark.fri_proof;
    Lengths {
        queried: stark
            .queried_values
            .iter()
            .map(|tree| tree.iter().map(Vec::len).collect())
            .collect(),
        witness_hashes: stark
            .decommitments
            .iter()
            .map(|decommitment| decommitment.hash_witness.len())
            .collect(),
        fri: std::iter::once(&fri.first_layer)
            .chain(&fri.inner_layers)
            .map(|layer| {
                (
                    layer.fri_witness.len(),
                    layer.decommitment.hash_witness.len(),
                )
            })
            .collect(),
        last_layer: fri.last_layer_poly.len(),
    }
}

/// The lengths a proof of `format` over the set laid out as `layout` has at
/// its own Fiat–Shamir coins: its query positions replayed from the
/// transcript, each tree's witness hashes counted at them, and FRI's
/// lengths those of a proof of the zero codeword decommitted at them.
fn lengths_at_coins<MC: MerkleChannel>(format: &Format, proof: &Proof<MC>) -> Lengths
where
    SimdBackend: BackendForChannel<MC>,
{
    let layout = wrap_layout(&proof.log_sizes);
    let public_sum = |relation: &GateRelation| public_sum(&proof.outputs, relation);
    let pinned = verifier_format(format, &proof.log_sizes, &layout).expect("a masked format");
    let claim = Claim {
        log_sizes: &proof.log_sizes,
        circuit: None,
        public: &proof.outputs,
        public_sum: Some(&public_sum),
        bound_sums: None,
        interaction_pow: proof.interaction_pow,
        claimed_sums: &proof.claimed_sums,
    };
    let stark = &proof.stark_proof;
    let replayed = replay::<MC, WrapComponents>(&pinned, &claim, &layout, stark).expect("replays");
    let mut channel = replayed.channel;
    let config = format.pcs_config();
    let sampled = &stark.sampled_values;
    channel.mix_felts(&sampled.clone().flatten_cols());
    let values = sampled
        .iter()
        .flatten()
        .map(|column| deep_values_of_column(column.len()))
        .sum();
    DeepCoefficients::draw(&mut channel, config.deep_batching, values);
    let heights: Vec<u32> = replayed
        .scheme
        .trees
        .iter()
        .map(|tree| tree.height)
        .collect();
    let lifting = *heights.last().expect("four trees");
    let bound = CirclePolyDegreeBound::new(lifting - config.fri_config.log_blowup_factor);
    let mut fri = FriVerifier::<MC>::commit(
        &mut channel,
        config.fri_config,
        stark.fri_proof.clone(),
        bound,
    )
    .expect("FRI's layers");
    assert!(channel.verify_pow_nonce(config.pow_bits, stark.proof_of_work));
    channel.mix_u64(stark.proof_of_work);
    let positions = fri.sample_query_positions(&mut channel);

    let preprocessed = prepare_preprocessed_query_positions(&positions, lifting, heights[0]);
    let domain = CanonicCoset::new(lifting).circle_domain();
    let twiddles = SimdBackend::precompute_twiddles(domain.half_coset);
    let zero =
        SecureEvaluation::<SimdBackend, _>::new(domain, SecureColumnByCoords::zeros(1 << lifting));
    let zero_fri = FriProver::<SimdBackend, MC>::commit(
        &mut MC::C::default(),
        config.fri_config,
        &zero,
        &twiddles,
    )
    .decommit_on_queries(&Queries {
        positions: positions.clone(),
        log_domain_size: lifting,
    })
    .proof;
    let fri_lengths = lengths_of::<MC>(&stwo::core::proof::StarkProof(
        stwo::core::pcs::quotients::CommitmentSchemeProof {
            fri_proof: zero_fri,
            ..stark.0.clone()
        },
    ));
    Lengths {
        queried: stark
            .queried_values
            .iter()
            .map(|tree| vec![positions.len(); tree.len()])
            .collect(),
        witness_hashes: heights
            .iter()
            .enumerate()
            .map(|(tree, &height)| {
                let at = if tree == 0 { &preprocessed } else { &positions };
                merkle_witness(at, height)
            })
            .collect(),
        fri: fri_lengths.fri,
        last_layer: fri_lengths.last_layer,
    }
}

/// The shape public: a proof's shape is public, the format's and its
/// Fiat–Shamir coins' alone: every length its layout varies by (each
/// column's queried values, each tree's and FRI layer's witness hashes,
/// FRI's witness values) is what its own query positions give, counted for
/// an all-zero witness, for proofs of a zero witness and of a random one
/// alike; every other count is the format's pin (`check_shape`,
/// `format::MASKED_WRAP`'s own tests).
#[test]
fn the_shape_is_the_format_and_the_coins() {
    let format = format();
    let mut distinct = BTreeSet::new();
    for witness in [PrivateWitness::zero(), PrivateWitness::random(17)] {
        let finalized = private_circuit(&witness);
        for seed in 0..6 {
            let (proof, _) =
                prove::<Blake2bMerkleChannel>(&format, &finalized, MaskRng::Seeded(seed))
                    .expect("proves");
            let lengths = lengths_of::<Blake2bMerkleChannel>(&proof.stark_proof);
            assert_eq!(
                lengths,
                lengths_at_coins::<Blake2bMerkleChannel>(&format, &proof),
                "seed {seed}"
            );
            distinct.insert(format!("{lengths:?}"));
        }
    }
    eprintln!(
        "12 proofs, {} distinct shapes, each its coins'",
        distinct.len()
    );
}
