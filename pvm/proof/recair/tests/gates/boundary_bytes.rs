//! The leaf's boundary bytes (`proving.md` A.3): the leaf range-checks only
//! φ9..12's 32 bytes, which it combines into the io-hash; every other byte
//! it uses exactly, as an M31, in the transcript, the boundary chips'
//! public terms, the state digests and the flags. A value of 256 or more
//! there aliases no other state, and is refused.
//!
//! The forger states the segment's boundary with one such value, on the
//! whole run's leaf, at a byte of each field outside φ9..12: `b + 256`, and
//! where a field's next byte allows it, `(b + 256, b' − 1)`, the same
//! integer in another encoding. It skips the leaf's checks and goes as far
//! as a prover can:
//! - **the interaction PoW,** ground anew over the moved transcript, so the
//!   PoW does not refuse it; the boundary chips' public terms then do not
//!   match the segment's claimed sums (`logup`);
//! - **the claimed sums,** forged to match those terms and to add to zero:
//!   the composition at the OODS point refuses them (`oods`);
//! - **proved,** as built, the leaf's `Gate` relation does not balance, and
//!   the verifier refuses it; balanced, the gates whose wires moved break
//!   their constraints, and the verifier refuses that.
//!
//! The `logup` refusal is the Fiat–Shamir binding as much as the byte
//! tuple: the moved transcript moves every challenge after the boundary,
//! so the public terms differ from the claimed sums for both reasons. The
//! tuple alone is checked natively too: under the proof's own challenges,
//! an alias's public terms do not match the claimed sums.

use std::sync::OnceLock;

use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_poseidon2::{M31, N_STATE, PermKind, permute, pow_passes};
use vos_pvm_proof::boundary_binding::BOUNDARY_STATE_BYTES;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_proof::{RecursionData, extract_recursion_data};
use vos_pvm_recair::leaf::{LeafCircuit, LeafValues, PADDED_ROWS};
use vos_pvm_recair::verifier::channel::u64_wire;
use vos_pvm_recair::verifier::logup::{self, BoundaryRelations, Challenges};
use vos_pvm_recair::verifier::witness::pack;
use vos_pvm_recair::verifier::{SegmentShape, verify_segment};
use vos_pvm_recair::{Context, Mismatch};

use crate::common::kernel::{blob, entry, whole_run};
use crate::forge::{DEEP_ALI, Forgery, LOGUP, assert_refused};

/// The whole run's segment, its leaf, the native verifier's record and the
/// honest leaf's values.
struct Whole {
    leaf: LeafCircuit,
    data: RecursionData,
    values: LeafValues<SecureField>,
}

fn whole() -> &'static Whole {
    static WHOLE: OnceLock<Whole> = OnceLock::new();
    WHOLE.get_or_init(|| {
        let proof = whole_run();
        let leaf = LeafCircuit::new(SegmentShape::of(proof), entry(&blob()));
        let word = |base: u32| P2Hash(core::array::from_fn(|i| BaseField::from(base + i as u32)));
        let (values, output) = leaf
            .values(proof, word(1_000), word(2_000), 0)
            .expect("the proof's values");
        assert!(output.entry && output.halt);
        Whole {
            data: extract_recursion_data(proof),
            leaf,
            values,
        }
    })
}

/// The boundary's bytes, one M31 each, from its wires.
fn bytes_of(values: &LeafValues<SecureField>) -> Vec<BaseField> {
    values
        .segment
        .boundary
        .iter()
        .flat_map(|wire| wire.to_m31_array())
        .collect()
}

/// The leaf's mismatches over `values`, built leniently, in order.
fn mismatches(values: &LeafValues<SecureField>) -> Vec<Mismatch> {
    let mut context = Context::<SecureField>::with_outputs(2).lenient();
    let wires = whole().leaf.verify(&mut context, values);
    context.set_outputs(&wires.digest);
    context.mismatches().to_vec()
}

/// Their pieces, each once in the order first met.
fn pieces(mismatches: &[Mismatch]) -> Vec<&'static str> {
    let mut pieces: Vec<&'static str> = mismatches.iter().map(|mismatch| mismatch.piece).collect();
    pieces.dedup();
    pieces
}

/// The interaction PoW's prefix over `bytes` absorbed where the native
/// verifier absorbed the boundary: the digest before that absorption is the
/// recorded transcript's.
fn pow_prefix(data: &RecursionData, bytes: &[BaseField], n_bits: u32) -> [M31; 8] {
    let records = &data.transcript.records;
    let pow = records
        .iter()
        .position(|record| record.kind == PermKind::Pow)
        .expect("the interaction PoW");
    let chunks = BOUNDARY_STATE_BYTES.div_ceil(8);
    let first = &records[pow - chunks];
    assert!(
        first.first_chunk
            && records[pow - chunks + 1..pow]
                .iter()
                .all(|r| !r.first_chunk)
    );
    let honest = bytes_of(&whole().values);
    assert_eq!(&first.input[8..], &honest[..8], "the boundary's absorption");
    let mut state = [M31::ZERO; N_STATE];
    for (word, limb) in state.iter_mut().zip(&first.input[..8]) {
        *word = M31::new(limb.0);
    }
    for chunk in bytes.chunks(8) {
        for (word, byte) in state[8..].iter_mut().zip(chunk) {
            *word += M31::new(byte.0);
        }
        permute(&mut state);
    }
    let mut prefix = [M31::ZERO; N_STATE];
    prefix[..8].copy_from_slice(&state[..8]);
    prefix[8] = M31::new(n_bits);
    permute(&mut prefix);
    core::array::from_fn(|i| prefix[i])
}

/// The forger's values: the boundary's bytes `bytes`, and an interaction
/// nonce ground over the transcript they move.
fn forged(bytes: &[BaseField]) -> LeafValues<SecureField> {
    let whole = whole();
    let n_bits = SEGMENT.interaction_pow_bits();
    let prefix = pow_prefix(&whole.data, bytes, n_bits);
    let nonce = (0u64..)
        .find(|&nonce| pow_passes(&prefix, n_bits, nonce, &mut ()))
        .expect("a nonce");
    let mut values = whole.values.clone();
    values.segment.boundary = pack(bytes);
    values.segment.stark.interaction_nonce = u64_wire(nonce);
    values
}

/// The forger's claimed sums: each boundary chip's the public term the leaf
/// computes, then one other chip's moved so that they add to zero, until
/// the logup check holds.
fn forge_claimed_sums(values: &mut LeafValues<SecureField>) {
    let mut forged: Vec<usize> = Vec::new();
    for _ in 0..3 {
        let logup: Vec<Mismatch> = mismatches(values)
            .into_iter()
            .filter(|mismatch| mismatch.piece == "logup")
            .collect();
        if logup.is_empty() {
            return;
        }
        let sums = &mut values.segment.stark.claimed_sums;
        for mismatch in logup {
            if mismatch.address == 0 {
                // The total: one chip's sum takes the difference.
                let other = (0..sums.len())
                    .find(|k| !forged.contains(k))
                    .expect("a chip other than the boundary's");
                sums[other] -= mismatch.computed;
            } else {
                let k = sums
                    .iter()
                    .position(|&sum| sum == mismatch.expected)
                    .expect("a boundary chip's claimed sum");
                sums[k] = mismatch.computed;
                forged.push(k);
            }
        }
    }
    panic!("the logup check still refuses the forged sums");
}

/// The fields' byte ranges outside φ9..12, by name, in the boundary's
/// order, and whether a field is an integer (an alias is the same one).
fn fields() -> Vec<(&'static str, core::ops::Range<usize>, bool)> {
    let fields = vec![
        ("φ1 in", 8..16, true),
        ("φ0 out", 104..112, true),
        ("φ8 out", 104 + 64..104 + 72, true),
        ("pc in", 208..212, true),
        ("ts in", 212..220, true),
        ("pc out", 220..224, true),
        ("ts out", 224..232, true),
        ("the memory root in", 232..264, false),
        ("the memory root out", 264..296, false),
    ];
    assert_eq!(fields.last().expect("a field").1.end, BOUNDARY_STATE_BYTES);
    fields
}

/// The forgeries: a field's first byte plus 256, and an integer field's
/// first byte that can borrow from the next as `(b + 256, b' − 1)`.
fn forgeries() -> Vec<(String, Vec<BaseField>)> {
    let honest = bytes_of(&whole().values);
    let mut forgeries = Vec::new();
    for (name, range, integer) in fields() {
        let mut bytes = honest.clone();
        bytes[range.start] += BaseField::from(256);
        forgeries.push((format!("{name}: a byte plus 256"), bytes));
        let borrow = (range.start..range.end - 1).find(|&i| !honest[i + 1].is_zero());
        if let (true, Some(i)) = (integer, borrow) {
            let mut bytes = honest.clone();
            bytes[i] += BaseField::from(256);
            bytes[i + 1] -= BaseField::from(1);
            forgeries.push((
                format!(
                    "{name}: byte {} as 256 more, one less above",
                    i - range.start
                ),
                bytes,
            ));
        }
    }
    forgeries
}

/// The honest leaf has no mismatch, and the forger's PoW model is the
/// native transcript's: over the honest bytes the proof's own nonce
/// passes.
#[test]
fn the_forgers_transcript_is_the_native_one() {
    let whole = whole();
    assert!(mismatches(&whole.values).is_empty());
    let n_bits = SEGMENT.interaction_pow_bits();
    let prefix = pow_prefix(&whole.data, &bytes_of(&whole.values), n_bits);
    let limbs = whole.values.segment.stark.interaction_nonce.to_m31_array();
    let nonce = (0..4).fold(0u64, |nonce, i| nonce | (u64::from(limbs[i].0) << (16 * i)));
    assert!(pow_passes(&prefix, n_bits, nonce, &mut ()));
    let forged = forged(&bytes_of(&whole.values));
    assert!(
        mismatches(&forged).is_empty(),
        "a nonce ground over the honest bytes"
    );
}

/// Every forged byte, its PoW ground anew, is refused by the boundary
/// chips' public terms; an alias, or a root's byte, with the claimed sums
/// forged to match them, by the composition at the OODS point.
#[test]
fn a_boundary_byte_of_256_or_more_is_refused() {
    let forgeries = forgeries();
    assert!(
        forgeries.len() >= fields().len() + 3,
        "{} forgeries",
        forgeries.len()
    );
    for (what, bytes) in &forgeries {
        let mut values = forged(bytes);
        let refused = pieces(&mismatches(&values));
        assert_eq!(refused.first(), Some(&"logup"), "{what}: {refused:?}");
        // The deeper forger, on the aliases and the roots.
        if what.contains("one less above") || what.contains("root") {
            forge_claimed_sums(&mut values);
            let refused = pieces(&mismatches(&values));
            assert_eq!(
                refused.first(),
                Some(&"oods"),
                "{what}, its sums forged: {refused:?}"
            );
        }
    }
}

/// The leaf over `values`, built leniently and finalized at the padded
/// shape.
fn finalized(values: &LeafValues<SecureField>) -> vos_pvm_recair::Finalized<SecureField> {
    let mut context = Context::<SecureField>::with_outputs(2).lenient();
    let wires = whole().leaf.verify(&mut context, values);
    context.set_outputs(&wires.digest);
    context
        .finalize_to(Some(PADDED_ROWS))
        .expect("the wiring checks")
}

/// Forgeries proved: an alias of φ0 out and a root's byte, its sums forged,
/// as built (the leaf's relation does not balance); the alias balanced (its
/// gates break).
#[test]
fn a_forged_boundary_byte_proved_is_refused() {
    let whole = whole();
    let hash = whole.leaf.hash().0.map(|limb| M31::new(limb.0));
    let forgeries = forgeries();
    let alias = forgeries
        .iter()
        .find(|(what, _)| what.starts_with("φ0 out: byte"))
        .expect("an alias of φ0 out");
    let root = forgeries
        .iter()
        .find(|(what, _)| what.starts_with("the memory root out"))
        .expect("the memory root out");

    let alias_values = forged(&alias.1);
    let mut root_values = forged(&root.1);
    forge_claimed_sums(&mut root_values);
    for ((what, _), values) in [(alias, &alias_values), (root, &root_values)] {
        let forgery = Forgery::honest(&finalized(values));
        assert_refused(forgery.prove(), &hash, LOGUP, what);
    }
    let mut balanced = Forgery::honest(&finalized(&alias_values));
    balanced.balance();
    let unbalanced = balanced.unbalanced();
    assert!(
        unbalanced.is_empty(),
        "{:?}",
        &unbalanced[..unbalanced.len().min(12)]
    );
    assert_refused(
        balanced.prove(),
        &hash,
        DEEP_ALI,
        &format!("{}, balanced", alias.0),
    );
}

/// The byte tuple alone: under the proof's own relation challenges, the
/// boundary chips' public terms over an alias do not match the claimed
/// sums, which they match over the honest bytes.
#[test]
fn an_alias_misses_the_claimed_sums_under_the_proofs_challenges() {
    let whole = whole();
    let shape = &whole.leaf.shape;
    let terms = shape.boundary.as_ref().expect("a segment's boundary chips");
    let mut context = Context::<SecureField>::new();
    let verified = verify_segment(&mut context, shape, &whole.values.segment);
    let challenges: Vec<[SecureField; 2]> = verified
        .draws
        .relations
        .iter()
        .map(|relation| relation.map(|wire| context.value(wire)))
        .collect();
    let check = |bytes: &[BaseField]| {
        let mut context = Context::<SecureField>::new().lenient();
        let sums: Vec<_> = whole
            .values
            .segment
            .stark
            .claimed_sums
            .iter()
            .map(|&sum| context.guess(sum))
            .collect();
        let boundary: Vec<_> = pack(bytes)
            .into_iter()
            .map(|wire| context.guess(wire))
            .collect();
        let [register, program, merkle] = terms.relations.map(|r| {
            let [z, alpha] = challenges[r].map(|value| context.guess(value));
            Challenges { z, alpha }
        });
        logup::check(
            &mut context,
            &sums,
            &terms.positions,
            &boundary,
            &BoundaryRelations {
                register_memory: register,
                program_execution: program,
                merkle_node: merkle,
            },
        );
        context.mismatches().len()
    };
    assert_eq!(check(&bytes_of(&whole.values)), 0, "the honest bytes");
    let aliases: Vec<_> = forgeries()
        .into_iter()
        .filter(|(what, _)| what.contains("one less above"))
        .collect();
    assert!(!aliases.is_empty());
    for (what, bytes) in aliases {
        assert!(check(&bytes) > 0, "{what}");
    }
}
