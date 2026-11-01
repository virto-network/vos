//! Masked proofs verify at every size on both channels; a broken
//! constraint, unlifted preprocessed columns and an unbalanced relation are
//! refused.

use super::*;

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
