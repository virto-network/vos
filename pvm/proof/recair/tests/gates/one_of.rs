//! `assert_one_of` (`recursion-air.md` §6): a hash is the candidate its one
//! set bit picks, `Σ bits = 1` and `bit·(hash − candidate) = 0` for each.
//! The fold and the wrap check a child's circuit hash so against the
//! program's leaf circuits and W.
//!
//! The forger states a hash outside the set and a choice of its liking: the
//! circuit's gates do not hold (a lenient context names the piece), and the
//! malicious prover proves the witness either as built, a relation that
//! does not balance, or balanced, so the gates that check the choice break
//! their constraints:
//! - **in a small circuit,** its hash and candidates its outputs: a bit on
//!   each candidate in turn, the empty slot of a short program among them;
//!   no bit; two bits; one half on two candidates;
//! - **in the fold,** a child whose circuit is not among the program's
//!   claiming the program's first slot;
//! - **in the wrap,** a root whose circuit is neither the program's nor
//!   the fold's claiming the program's first slot: refused by the wrap's
//!   circuit check alone (the wrap proves on the Blake2b channel, which the
//!   forger does not, so its proof is not forged here).

use num_traits::{One, Zero};
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::program_id::{IdPreimage, LeafCircuits};
use vos_pvm_proof::prove_canonical_format;
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_recair::fold::{CIRCUITS, FoldCircuit};
use vos_pvm_recair::gadgets::assert_one_of;
use vos_pvm_recair::leaf::{LeafCircuit, PADDED_ROWS};
use vos_pvm_recair::tree;
use vos_pvm_recair::verifier::SegmentShape;
use vos_pvm_recair::wrap::{LAYOUT, WrapCircuit};
use vos_pvm_recair::{Context, Finalized};

use crate::common::Rng;
use crate::common::kernel::{blob, entry, whole_run};
use crate::forge::{DEEP_ALI, Forgery, LOGUP, assert_accepted, assert_refused, hash_of};

/// The candidates: three hashes and an empty slot, as a short program's
/// unused leaf-circuit slots are.
fn candidates() -> Vec<[SecureField; 2]> {
    let mut rng = Rng::new(61);
    let mut candidates: Vec<[SecureField; 2]> = (0..3).map(|_| [rng.qm31(), rng.qm31()]).collect();
    candidates.push([SecureField::zero(); 2]);
    candidates
}

/// The circuit over `hash`, the candidates and the choice `bits`, built
/// leniently: its outputs the hash and the candidates; the pieces of its
/// mismatches.
fn one_of(
    hash: [SecureField; 2],
    bits: &[SecureField],
) -> (Finalized<SecureField>, Vec<&'static str>) {
    let candidates = candidates();
    let mut context =
        Context::<SecureField>::with_outputs(2 + 2 * candidates.len() as u32).lenient();
    context.piece("one of");
    let hash = context.guess_pair(hash);
    let wires: Vec<_> = candidates
        .iter()
        .map(|&pair| context.guess_pair(pair))
        .collect();
    let bits: Vec<_> = bits
        .iter()
        .map(|&bit| {
            let bit = context.guess(bit);
            context.assert_bit(bit)
        })
        .collect();
    assert_one_of(&mut context, hash, &wires, &bits);
    let outputs: Vec<_> = hash
        .into_iter()
        .chain(wires.into_iter().flatten())
        .collect();
    context.set_outputs(&outputs);
    let pieces = context
        .mismatches()
        .iter()
        .map(|mismatch| mismatch.piece)
        .collect();
    (context.finalize().expect("the wiring checks"), pieces)
}

fn choice(set: &[usize]) -> Vec<SecureField> {
    (0..candidates().len())
        .map(|k| SecureField::from(BaseField::from(u32::from(set.contains(&k)))))
        .collect()
}

/// The forgery `finalized` proved as built and balanced: refused by the
/// relation, then by the constraints.
fn assert_both_refused(
    finalized: &Finalized<SecureField>,
    hash: &vos_pvm_poseidon2::Digest,
    what: &str,
) {
    let forgery = Forgery::honest(finalized);
    assert_refused(forgery.prove(), hash, LOGUP, what);
    let mut balanced = Forgery::honest(finalized);
    balanced.balance();
    assert_refused(
        balanced.prove(),
        hash,
        DEEP_ALI,
        &format!("{what}, balanced"),
    );
}

/// A hash among the candidates, its bit set, proves and verifies.
#[test]
fn a_choice_in_the_set_is_accepted() {
    let (finalized, pieces) = one_of(candidates()[2], &choice(&[2]));
    assert!(pieces.is_empty(), "{pieces:?}");
    assert_accepted(
        Forgery::honest(&finalized).prove(),
        &hash_of(&finalized.circuit),
        "a choice in the set",
    );
}

/// A hash outside the set, whatever the choice, is refused.
#[test]
fn a_choice_outside_the_set_is_refused() {
    let outside = [SecureField::one(), SecureField::from(BaseField::from(2))];
    let half = SecureField::from(BaseField::from(2)).inverse();
    let mut choices: Vec<(String, Vec<SecureField>)> = (0..candidates().len())
        .map(|k| (format!("a bit on candidate {k}"), choice(&[k])))
        .collect();
    choices.push(("no bit".into(), choice(&[])));
    choices.push(("two bits".into(), choice(&[0, 3])));
    let mut halves = choice(&[]);
    halves[0] = half;
    halves[1] = half;
    choices.push(("one half on two candidates".into(), halves));
    // The pinned circuit is the honest one's: the wiring does not depend on
    // the values.
    let hash = hash_of(&one_of(candidates()[0], &choice(&[0])).0.circuit);
    for (what, bits) in choices {
        let (finalized, pieces) = one_of(outside, &bits);
        assert_eq!(
            hash_of(&finalized.circuit),
            hash,
            "{what}: the same circuit"
        );
        assert!(
            !pieces.is_empty() && pieces.iter().all(|&piece| piece == "one of"),
            "{what}: {pieces:?}"
        );
        assert_both_refused(&finalized, &hash, &what);
    }
}

fn id(program: &IdPreimage) -> P2Hash {
    P2Hash(program.id().0)
}

/// In the fold: a run's two leaves under a program without the first
/// leaf's circuit, the first child claiming the program's first slot. The
/// fold's circuit check refuses it, and its proof, as built or balanced,
/// does not verify as the fold circuit.
#[test]
fn a_fold_child_of_a_circuit_outside_the_program_is_refused() {
    let blob = blob();
    let trace = trace_kernel(&blob, &[], 1_000).expect("halts");
    let entry = entry(&blob);
    let mut cursor = SegmentCursor::new(&trace.side_note);
    let segments: Vec<_> = [(0, 3), (3, 6)]
        .map(|(a, b)| {
            prove_canonical_format(&mut cursor.side_note(a, b), &[], &SEGMENT).expect("proves")
        })
        .into();
    let leaves: Vec<LeafCircuit> = segments
        .iter()
        .map(|proof| LeafCircuit::new(SegmentShape::of(proof), entry))
        .collect();
    let first = leaves[0].hash();
    let others: Vec<P2Hash> = leaves[1..]
        .iter()
        .map(LeafCircuit::hash)
        .filter(|&hash| hash != first)
        .collect();
    let short = IdPreimage {
        kernel: P2Hash(core::array::from_fn(|i| BaseField::from(3_000 + i as u32))),
        leaf_circuits: LeafCircuits::Hashes(others),
    };
    let fold = FoldCircuit::new();
    let word = fold.hash();
    let nodes: Vec<_> = (0..2)
        .map(|s| tree::leaf(&leaves[s], &segments[s], id(&short), word, s as u32).expect("proves"))
        .collect();
    let (mut values, _) = fold
        .values(nodes[0].proved(), nodes[1].proved(), &short, word)
        .expect("the children's values");
    assert!(
        values.children[0].circuit.iter().all(|bit| bit.is_zero()),
        "the first leaf's circuit is not the program's"
    );
    values.children[0].circuit =
        core::array::from_fn(|k| SecureField::from(BaseField::from(u32::from(k == 0))));
    assert_eq!(CIRCUITS, values.children[0].circuit.len());

    let mut context = Context::<SecureField>::with_outputs(2).lenient();
    let digest = fold.verify(&mut context, &values);
    context.set_outputs(&digest);
    let mut pieces: Vec<_> = context
        .mismatches()
        .iter()
        .map(|mismatch| mismatch.piece)
        .collect();
    pieces.dedup();
    assert_eq!(pieces, ["fold: circuit"]);
    let finalized = context
        .finalize_to(Some(PADDED_ROWS))
        .expect("the wiring checks");
    let word = word.0.map(|limb| vos_pvm_poseidon2::M31::new(limb.0));
    assert_both_refused(&finalized, &word, "a fold child outside the program");
}

/// In the wrap: the whole run's leaf as the root, under a program whose one
/// leaf circuit is not the leaf's, claiming the program's first slot. The
/// wrap's circuit check refuses it, and no other; under a program whose
/// slot is the leaf's circuit, nothing is refused.
#[test]
fn a_wrap_root_of_a_circuit_outside_the_program_is_refused() {
    let proof = whole_run();
    let leaf = LeafCircuit::new(SegmentShape::of(proof), entry(&blob()));
    let wrap = WrapCircuit::get();
    let program = |hash: P2Hash| IdPreimage {
        kernel: P2Hash(core::array::from_fn(|i| BaseField::from(3_000 + i as u32))),
        leaf_circuits: LeafCircuits::Hashes(vec![hash]),
    };
    let pieces = |values: &vos_pvm_recair::wrap::WrapValues<SecureField>| {
        let mut context = Context::<SecureField>::with_layout(LAYOUT).lenient();
        let lanes = wrap.verify(&mut context, values);
        context.set_output_lanes(&lanes);
        let mut pieces: Vec<_> = context
            .mismatches()
            .iter()
            .map(|mismatch| mismatch.piece)
            .collect();
        pieces.dedup();
        pieces
    };

    let own = program(leaf.hash());
    let node = tree::leaf(&leaf, proof, id(&own), wrap.fold_word, 0).expect("proves");
    let (values, _) = wrap.values(node.proved(), &own).expect("the root's values");
    assert!(pieces(&values).is_empty(), "the root's own program");

    let other = program(P2Hash(core::array::from_fn(|i| {
        BaseField::from(7_000 + i as u32)
    })));
    let node = tree::leaf(&leaf, proof, id(&other), wrap.fold_word, 0).expect("proves");
    let (mut values, _) = wrap
        .values(node.proved(), &other)
        .expect("the root's values");
    assert!(values.root.circuit.iter().all(|bit| bit.is_zero()));
    values.root.circuit[0] = SecureField::one();
    assert_eq!(pieces(&values), ["wrap: circuit"]);
}
