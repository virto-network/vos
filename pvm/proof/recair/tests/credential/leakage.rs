//! The masking's leakage gates on credential proofs (`docs/design/proving.md`
//! §5; slice 6's 6.6, gates 2, 3 and 5, with 4 and 7) at N proofs a
//! witness: 16 in `just check`; under `heavy-gates`,
//! `LEAKAGE_CREDENTIAL_N`, [`MEDIUM`] unless it is set (`just test-proof`;
//! `just slice-gate` sets the full N).
//!
//! **The pair:** one member's leaf at two slots of one tree, so two auth
//! witnesses (their slots' bits and siblings) with **equal public words**
//! (the root, the scope, the nullifier and the binding are the secret's
//! and the call's, not the slot's).
//!
//! - **Witness indistinguishability (2):** N proofs of one witness against
//!   N of the other: per field a two-sample χ² on its top bits, one pooled
//!   KS. Every published value is a field: both claimed sums are blinded.
//! - **Uniformity (3):** each field of the first witness's N proofs against
//!   uniform M31.
//! - **Hidden state (4):** the secret, the nullifier's key, the member
//!   digest, its leaf and every sibling not an empty subtree (those are
//!   public constants) are not among a proof's published values, which a
//!   planted control finds.
//! - **Fresh randomness (5):** two proofs of one witness share no opening,
//!   nor two witnesses' proofs from one seed.
//! - **The shape (7):** the two witnesses' proofs have one shape.

use std::collections::BTreeMap;

#[cfg(feature = "heavy-gates")]
use std::sync::OnceLock;
use stwo::core::fields::m31::BaseField;

use vos_pvm_final_verifier::credential::CredentialProof;
use vos_pvm_recair::credential::{self, Statement, Words};
use vos_pvm_recair::masked::MaskRng;
use vos_wire::credentials::{EMPTY, Tag, compress, leaf};

use crate::common::Rng;
use crate::common::leakage::{self, Fields, Key, Verdicts, indistinguishable, published, uniform};
use crate::prove::verify;
use crate::support::{self, member};

/// The proofs a witness under `heavy-gates` unless `LEAKAGE_CREDENTIAL_N`
/// is set: the plan's 500 at `test-proof`.
#[cfg(feature = "heavy-gates")]
const MEDIUM: usize = 500;

/// The proofs a witness.
fn n() -> usize {
    #[cfg(feature = "heavy-gates")]
    {
        static N: OnceLock<usize> = OnceLock::new();
        *N.get_or_init(|| crate::common::leakage::heavy_n("LEAKAGE_CREDENTIAL_N", MEDIUM))
    }
    #[cfg(not(feature = "heavy-gates"))]
    {
        16
    }
}

/// The two slots the member's leaf holds.
const SLOTS: [u32; 2] = [0x0000_0005, 0xc0de_0a11];

/// Two auth statements of one member at [`SLOTS`]: one public statement,
/// two witnesses.
fn the_pair() -> [Statement; 2] {
    let mut rng = Rng::new(41);
    let enrolled = support::enrolled(&mut rng, &SLOTS, 6);
    let scope = support::digest(&mut rng);
    let binding = support::digest(&mut rng);
    let pair = SLOTS.map(|slot| support::auth_in(&enrolled, slot, scope, binding));
    assert_eq!(pair[0].words(), pair[1].words(), "equal public words");
    assert_ne!(pair[0], pair[1], "two witnesses");
    pair
}

fn proof(statement: &Statement, rng: MaskRng) -> CredentialProof {
    credential::prove(statement, rng).expect("proves").0
}

fn fields(proof: &CredentialProof) -> Vec<(Key, u32)> {
    published(&proof.stark_proof, &proof.claimed_sums)
}

/// Witness indistinguishability and uniformity at equal public words.
#[test]
fn the_published_values_do_not_depend_on_the_witness() {
    let n = n();
    let [a, b] = the_pair().map(|statement| {
        let mut gathered = Fields::default();
        for mask in 0..n as u64 {
            gathered.add(&fields(&proof(&statement, MaskRng::Seeded(mask))));
        }
        gathered
    });
    let mut verdicts = Verdicts::new("credential proofs' witness indistinguishability");
    indistinguishable(&mut verdicts, "two slots", &a, &b, n);
    verdicts.report();
    assert!(verdicts.refused().is_empty(), "{:?}", verdicts.refused());

    let mut verdicts = Verdicts::new("credential proofs' uniformity");
    uniform(&mut verdicts, &a, n);
    verdicts.report();
    assert!(verdicts.refused().is_empty(), "{:?}", verdicts.refused());
}

/// The hidden digests among `hidden` a proof's published values hold
/// ([`leakage::leaked`]).
fn leaked(proof: &CredentialProof, hidden: &[Words]) -> Vec<Words> {
    leakage::leaked(&fields(proof), hidden)
}

/// No hidden state among a proof's published values: the secret, the
/// nullifier's key `C(T(nf), s)`, the member digest, its leaf and every
/// sibling not an empty subtree (those are public constants), none with two
/// of its words among them. The control: the secret's words planted among a
/// proof's queried values are found.
#[test]
fn no_hidden_state_is_in_a_proof() {
    let [statement, _] = the_pair();
    let proof = proof(&statement, MaskRng::default());
    verify(&statement, proof.clone()).unwrap();
    let Statement::Auth(_, witness) = statement else {
        unreachable!()
    };
    let s = witness.secret;
    let m = member(&s);
    let occupied = witness
        .siblings
        .iter()
        .enumerate()
        .filter(|&(level, sibling)| *sibling != EMPTY[level])
        .map(|(_, sibling)| *sibling);
    let hidden: Vec<Words> = [s, compress(&Tag::Nf.block(), &s), m, leaf(&m)]
        .into_iter()
        .chain(occupied)
        .collect();
    assert!(hidden.len() > 4, "siblings of other members");
    assert_eq!(leaked(&proof, &hidden), Vec::<Words>::new());

    let mut planted = proof;
    for (value, &word) in planted.stark_proof.0.queried_values[1][0]
        .iter_mut()
        .zip(&s)
    {
        *value = BaseField::from(word);
    }
    assert_eq!(leaked(&planted, &hidden), vec![s], "the control");
}

/// Fresh randomness: two proofs of one witness share no opening, and a
/// replayed seed with the two witnesses shares none.
#[test]
fn every_opening_is_fresh() {
    let differing = |a: &CredentialProof, b: &CredentialProof| {
        let a = fields(a);
        let b: BTreeMap<_, _> = fields(b).into_iter().collect();
        let shared: Vec<_> = a
            .iter()
            .filter(|(key, value)| b.get(key) == Some(value))
            .collect();
        assert!(a.len() > 1_000, "{} openings", a.len());
        assert!(shared.is_empty(), "openings shared: {shared:?}");
        a.len()
    };
    let [first, second] = the_pair();
    let [x, y] = [(); 2].map(|_| proof(&first, MaskRng::default()));
    let n = differing(&x, &y);
    let [a, b] = [&first, &second].map(|statement| proof(statement, MaskRng::Seeded(15)));
    let m = differing(&a, &b);
    eprintln!("{n} openings of one witness, {m} of two from one seed: none shared");
}

/// The shape public: the two witnesses' proofs have one layout. Their
/// Merkle witnesses' lengths follow the query positions, the coins'.
#[test]
fn the_shape_is_the_programs_and_the_coins() {
    let shape = |proof: &CredentialProof| {
        let stark = &proof.stark_proof;
        let samples: Vec<Vec<usize>> = stark
            .sampled_values
            .iter()
            .map(|tree| tree.iter().map(Vec::len).collect())
            .collect();
        let queried: Vec<Vec<usize>> = stark
            .queried_values
            .iter()
            .map(|tree| tree.iter().map(Vec::len).collect())
            .collect();
        (
            samples,
            queried,
            stark.fri_proof.inner_layers.len(),
            stark.fri_proof.last_layer_poly.len(),
        )
    };
    let [a, b] = the_pair().map(|statement| proof(&statement, MaskRng::Seeded(21)));
    assert_eq!(shape(&a), shape(&b));
}
