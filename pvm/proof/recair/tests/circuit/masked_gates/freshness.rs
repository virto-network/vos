//! Every opening is fresh, and a right guess reproduces an unblinded sum
//! only.

use super::*;

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
