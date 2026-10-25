//! The masking's soundness gates on the masked segment
//! (`docs/design/proving.md` §5; slice 6's 6.6): masked acceptance at every
//! size on both channels, R1 over every column class; a broken constraint
//! on the first, the last and the wrap row refused by the prover and, forced,
//! by the verifier; an unbalanced relation refused, and the blinding unable
//! to cancel it; each masked field and each public value tampered, refused;
//! a malformed proof an error, never a panic. The degree audit is
//! `circuit`'s (`masked::the_masked_segment_chips_pass_the_degree_audit`),
//! the mask invariant and R1's refusal the generic prover's.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::MerkleChannel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::verifier::VerificationError;
use stwo::prover::ProvingError;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_final_verifier::Error;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::chip_idx;
use vos_pvm_proof::chips::{range_multiplicity, register_memory};
use vos_pvm_proof::format::{ChannelKind, Format};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::masked::{MaskedSegmentTrace, SegmentComponents};
use vos_pvm_proof::poseidon2::P2MerkleChannel;
use vos_pvm_recair::ProveError;
use vos_pvm_recair::masked::segment::prove_segment_forced;
use vos_pvm_recair::masked::{MaskRng, mask_pins, mask_rows};
use vos_pvm_recair::trace::FirstRowFraction;
use vos_pvm_recair_air::masked::{
    MaskedComponent, MaskedComponents, composition_log_degree_bound, sample_points,
};

use crate::support::{IO, Proof, active, format, prove, run, small_format, verify};

/// The column classes R1 must check on the segment's set: each masked
/// column with samples, by its level, its quotient's lift, its offsets from
/// the out-of-domain point and its component's `h`, each class once.
pub fn column_classes(format: &Format, active: u32, log_sizes: &[u32]) -> usize {
    let set = SegmentComponents::layout(active, log_sizes).expect("the layout");
    let rows = mask_rows(format, &set).expect("the masks' sizes");
    let pins = mask_pins(&format.masking.expect("masked"));
    let z = CirclePoint::<SecureField>::get_point(98_765);
    let points = sample_points(&set, z, &pins).expect("the sample points");
    let composition = composition_log_degree_bound(&set).expect("the composition's bound");
    let mut classes = BTreeSet::new();
    let mut offsets = [0usize; 4];
    for (inner, h) in set.components().into_iter().zip(rows) {
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
                if !shifts.is_empty() {
                    classes.insert((level, lift, shifts, h));
                }
            }
        }
    }
    classes.len()
}

/// The kernel's run proved masked under `format` on `MC`, its main columns
/// through `tamper`, its blinding fractions through `blind`, the prover's
/// own check of the constraints made only when `checked`.
pub fn forced<MC: MerkleChannel>(
    format: &Format,
    seed: u64,
    tamper: impl FnOnce(&mut MaskedSegmentTrace),
    blind: impl Fn(&AllLookupElements, &mut [FirstRowFraction]),
    checked: bool,
) -> Result<Proof<MC>, ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let mut side_note = run(IO);
    let active = active(&side_note);
    prove_segment_forced::<MC>(
        format,
        &mut side_note,
        active,
        MaskRng::Seeded(seed),
        tamper,
        blind,
        checked,
    )
    .map(|(proof, _)| proof)
}

/// The position of chip `chip` among the kernel's chips.
fn position(chip: usize) -> usize {
    let active = active(&run(IO));
    (active & ((1 << chip) - 1)).count_ones() as usize
}

/// Coset row `row` of a column of `2^log_size` rows, where the evaluation
/// stores it.
fn stored(row: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(row, log_size), log_size)
}

/// The trace's chip at `position`, its main column `column` at coset row
/// `row` (from the end when negative), moved by `by`.
fn bump(trace: &mut MaskedSegmentTrace, position: usize, column: usize, row: isize, by: u32) {
    let log_size = trace.log_sizes[position];
    let rows = 1isize << log_size;
    let row = row.rem_euclid(rows) as usize;
    let columns = trace.main_columns_mut().nth(position).expect("the chip");
    columns[column].as_mut_slice()[stored(row, log_size)] += BaseField::from(by);
}

/// Masked acceptance at every size, on both channels: the kernel's chips
/// padded to `2^8`, `2^9` and `2^10` rows at least (`h` 64, 128 and 256 at
/// 4, 12 and 24 queries), the CPU, the ledgers and the tables at sizes of
/// their own; R1 checked every column class, the first attempt of full
/// rank; a seeded proof reproduced.
#[test]
fn masked_segments_verify_at_every_size_on_both_channels() {
    fn accepted<MC: MerkleChannel>(format: &Format, floor: u32)
    where
        SimdBackend: BackendForChannel<MC>,
    {
        let (proof, stats) = prove::<MC>(format, IO, MaskRng::Seeded(1)).expect("proves");
        verify::<MC>(format, &proof).expect("verifies");
        assert!(proof.log_sizes.iter().all(|&log_size| log_size >= floor));
        assert!(proof.log_sizes.iter().any(|&log_size| log_size > floor));
        assert_eq!(stats.attempts, 1);
        assert_eq!(
            stats.classes,
            column_classes(format, proof.active, &proof.log_sizes)
        );
        assert!(stats.revealed_rows <= 1 << (floor - 2), "{stats:?}");
        eprintln!(
            "floor 2^{floor}: {} chips at {:?}; R1 over {} classes, {} rows at most",
            proof.log_sizes.len(),
            proof.log_sizes,
            stats.classes,
            stats.revealed_rows
        );
    }
    for (queries, floor) in [(4, 8), (12, 9), (24, 10)] {
        let poseidon = small_format(ChannelKind::Poseidon2M31, 8, queries);
        accepted::<P2MerkleChannel>(&poseidon, floor);
        let blake = small_format(ChannelKind::Blake2s, 8, queries);
        accepted::<Blake2sMerkleChannel>(&blake, floor);
    }
    let format = format();
    let [first, again] = [(); 2].map(|_| {
        prove::<P2MerkleChannel>(&format, IO, MaskRng::Seeded(3))
            .unwrap()
            .0
    });
    assert_eq!(
        first.proof.stark_proof.commitments.0,
        again.proof.stark_proof.commitments.0
    );
    assert_eq!(first.proof.claimed_sums, again.proof.claimed_sums);
}

/// Masked acceptance at the device candidates' floors (`device-params.md`):
/// blowup 4 with 43 queries (`h = 512`, every chip at `2^11` rows at
/// least) and blowup 2 with 86 (`h = 1,024`, `2^12`), on Blake2s; R1 in one
/// attempt over every class, 137 and 266 rows revealed.
#[cfg(feature = "heavy-gates")]
#[test]
fn heavy_masked_segments_verify_at_the_device_floors() {
    for (log_blowup, queries, log_mask_rows, floor) in [(2, 43, 9, 11), (1, 86, 10, 12)] {
        let format = Format {
            params: vos_pvm_proof::format::FormatParams {
                log_blowup,
                ..small_format(ChannelKind::Blake2s, log_mask_rows, queries).params
            },
            ..small_format(ChannelKind::Blake2s, log_mask_rows, queries)
        };
        let (proof, stats) =
            prove::<Blake2sMerkleChannel>(&format, IO, MaskRng::Seeded(9)).expect("proves");
        verify::<Blake2sMerkleChannel>(&format, &proof).expect("verifies");
        assert!(proof.log_sizes.iter().all(|&log_size| log_size >= floor));
        assert_eq!(stats.attempts, 1);
        assert_eq!(
            stats.classes,
            column_classes(&format, proof.active, &proof.log_sizes)
        );
        assert!(2 * stats.revealed_rows <= 1 << log_mask_rows, "{stats:?}");
        eprintln!(
            "blowup 2^{log_blowup}, {queries} queries: chips at {:?}; R1 over {} classes, {} rows",
            proof.log_sizes, stats.classes, stats.revealed_rows
        );
    }
}

/// A broken constraint is refused on the first row, the last and the wrap
/// row: the register ledger's `BothRealH` (in no relation's tuple) moved at
/// row 0, at the last row (whose constraint reads row 0 across the wrap)
/// and mid-way. The prover refuses each; forced, the verifier refuses it at
/// the out-of-domain point, the logup still balanced.
#[test]
fn a_broken_constraint_on_the_first_last_or_wrap_row_is_refused() {
    let format = format();
    let at = position(chip_idx::REGISTER_MEMORY);
    let column = register_memory::Column::BothRealH.offset();
    for row in [0, -1, 37] {
        let tamper = |trace: &mut MaskedSegmentTrace| bump(trace, at, column, row, 1);
        let refused = forced::<P2MerkleChannel>(&format, 4, tamper, |_, _| {}, true);
        assert!(
            matches!(
                refused,
                Err(ProveError::Stwo(ProvingError::ConstraintsNotSatisfied))
            ),
            "row {row}: {refused:?}"
        );
        let proof = forced::<P2MerkleChannel>(&format, 4, tamper, |_, _| {}, false)
            .expect("a forced proof");
        assert!(
            matches!(
                verify::<P2MerkleChannel>(&format, &proof),
                Err(Error::Stark(VerificationError::OodsNotMatching))
            ),
            "row {row}"
        );
    }
}

/// The blinding's soundness: a relation unbalanced (a byte's multiplicity
/// in the range table one more) is refused by its logup total; with the
/// CPU's blinding fraction moved to cancel it once the relations are drawn,
/// the total is zero, but the prover refuses the proof, and forced, the
/// verifier refuses it at the out-of-domain point: the blinding is
/// committed before the relations are drawn.
#[test]
fn an_unbalanced_relation_cancelled_by_the_blinding_is_refused() {
    let format = format();
    let at = position(chip_idx::RANGE_MULTIPLICITY_256);
    let column = range_multiplicity::Column::Multiplicity.offset();
    let tamper = |trace: &mut MaskedSegmentTrace| bump(trace, at, column, 5, 1);
    let unbalanced =
        forced::<P2MerkleChannel>(&format, 5, tamper, |_, _| {}, true).expect("it proves");
    assert!(matches!(
        verify::<P2MerkleChannel>(&format, &unbalanced),
        Err(Error::Logup)
    ));
    let imbalance: SecureField = unbalanced.proof.claimed_sums.iter().copied().sum();
    assert!(!imbalance.is_zero());
    let cancel = |_: &AllLookupElements, fractions: &mut [FirstRowFraction]| {
        let cpu = &mut fractions[position(chip_idx::CPU)];
        cpu.numerator -= imbalance * cpu.denominator;
    };
    let refused = forced::<P2MerkleChannel>(&format, 5, tamper, cancel, true);
    assert!(
        matches!(
            refused,
            Err(ProveError::Stwo(ProvingError::ConstraintsNotSatisfied))
        ),
        "{refused:?}"
    );
    let cancelled =
        forced::<P2MerkleChannel>(&format, 5, tamper, cancel, false).expect("a forced proof");
    assert!(
        cancelled
            .proof
            .claimed_sums
            .iter()
            .copied()
            .sum::<SecureField>()
            .is_zero()
    );
    assert!(matches!(
        verify::<P2MerkleChannel>(&format, &cancelled),
        Err(Error::Stark(VerificationError::OodsNotMatching))
    ));
}

/// `proof` verified under `format`, a panic caught as one.
fn outcome<MC: MerkleChannel>(format: &Format, proof: &Proof<MC>) -> Result<(), String> {
    match catch_unwind(AssertUnwindSafe(|| verify::<MC>(format, proof))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("{error:?}")),
        Err(_) => Err("panicked".into()),
    }
}

/// Each masked field and each public value tampered is refused: a sample of
/// each tree (a main, an interaction, a composition column, an `R` column),
/// a queried value of each, a salt's queried value, a blinded and a public
/// claimed sum, the interaction PoW, a boundary state's register, pc and
/// memory root, the preprocessed root against the circuit's; and malformed,
/// in any part of its structure, the proof is an error, never a panic.
#[test]
fn a_tampered_or_malformed_proof_is_refused_never_a_panic() {
    type P = Proof<P2MerkleChannel>;
    let format = format();
    let (honest, _) = prove::<P2MerkleChannel>(&format, IO, MaskRng::Seeded(6)).unwrap();
    verify::<P2MerkleChannel>(&format, &honest).expect("verifies");
    let one = SecureField::one();
    let salts = format.masking.expect("masked").salt_columns;
    let cases: Vec<(&str, Box<dyn Fn(&mut P)>)> = vec![
        (
            "a main sample",
            Box::new(|p| p.proof.stark_proof.0.sampled_values[1][3][0] += one),
        ),
        (
            "an interaction sample",
            Box::new(|p| p.proof.stark_proof.0.sampled_values[2][0][0] += one),
        ),
        (
            "a composition sample",
            Box::new(|p| p.proof.stark_proof.0.sampled_values[3][0][0] += one),
        ),
        (
            "an R sample",
            Box::new(|p| p.proof.stark_proof.0.sampled_values[3][5][0] += one),
        ),
        (
            "a main queried value",
            Box::new(|p| p.proof.stark_proof.0.queried_values[1][2][0] += BaseField::one()),
        ),
        (
            "an interaction queried value",
            Box::new(|p| p.proof.stark_proof.0.queried_values[2][1][0] += BaseField::one()),
        ),
        (
            "a composition queried value",
            Box::new(|p| p.proof.stark_proof.0.queried_values[3][0][0] += BaseField::one()),
        ),
        (
            "a salt's queried value",
            Box::new(move |p| {
                let tree = &mut p.proof.stark_proof.0.queried_values[1];
                let last = tree.len() - salts;
                tree[last][0] += BaseField::one();
            }),
        ),
        (
            "the CPU's claimed sum",
            Box::new(|p| p.proof.claimed_sums[0] += one),
        ),
        (
            "a boundary chip's claimed sum",
            Box::new(|p| {
                let at = position(chip_idx::PROGRAM_BOUNDARY);
                p.proof.claimed_sums[at] += one;
            }),
        ),
        (
            "the interaction PoW",
            Box::new(|p| p.proof.interaction_pow ^= 1),
        ),
        (
            "an initial register",
            Box::new(|p| p.initial_state.registers[3] ^= 1),
        ),
        (
            "a final register",
            Box::new(|p| p.final_state.registers[10] ^= 1),
        ),
        ("the final pc", Box::new(|p| p.final_state.pc ^= 2)),
        (
            "the final timestamp",
            Box::new(|p| p.final_state.timestamp += 1),
        ),
        (
            "the initial memory root",
            Box::new(|p| p.initial_state.memory_root[0] ^= 1),
        ),
        (
            "a commitment fewer",
            Box::new(|p| {
                p.proof.stark_proof.0.commitments.pop();
            }),
        ),
        (
            "a tree's samples fewer",
            Box::new(|p| {
                p.proof.stark_proof.0.sampled_values[1].pop();
            }),
        ),
        (
            "a sample more",
            Box::new(|p| p.proof.stark_proof.0.sampled_values[2][4].push(SecureField::zero())),
        ),
        (
            "a queried column fewer",
            Box::new(|p| {
                p.proof.stark_proof.0.queried_values[2].pop();
            }),
        ),
        (
            "a queried value fewer",
            Box::new(|p| {
                p.proof.stark_proof.0.queried_values[1][0].pop();
            }),
        ),
        (
            "a decommitment's witness fewer",
            Box::new(|p| {
                p.proof.stark_proof.0.decommitments[1].hash_witness.pop();
            }),
        ),
        (
            "a FRI layer fewer",
            Box::new(|p| {
                p.proof.stark_proof.0.fri_proof.inner_layers.pop();
            }),
        ),
        (
            "a claimed sum fewer",
            Box::new(|p| {
                p.proof.claimed_sums.pop();
            }),
        ),
        (
            "a claimed sum more",
            Box::new(|p| p.proof.claimed_sums.push(SecureField::zero())),
        ),
        (
            "a log size fewer",
            Box::new(|p| {
                p.log_sizes.pop();
            }),
        ),
        ("a log size more", Box::new(|p| p.log_sizes.push(8))),
        ("a log size larger", Box::new(|p| p.log_sizes[0] += 1)),
        ("a log size zero", Box::new(|p| p.log_sizes[2] = 0)),
        (
            "a chip more",
            Box::new(|p| {
                let missing = (0..chip_idx::COUNT)
                    .find(|chip| p.active & 1 << chip == 0)
                    .unwrap();
                p.active |= 1 << missing;
            }),
        ),
        (
            "a chip fewer",
            Box::new(|p| p.active &= !(1 << chip_idx::CPU)),
        ),
        (
            "another chip",
            Box::new(|p| {
                let missing = (0..chip_idx::COUNT)
                    .find(|chip| p.active & 1 << chip == 0)
                    .unwrap();
                p.active = (p.active & !(1 << chip_idx::BITWISE_LOOKUP)) | 1 << missing;
            }),
        ),
        ("every bit of the mask", Box::new(|p| p.active = u32::MAX)),
        (
            "another configuration",
            Box::new(|p| p.proof.stark_proof.0.config.fri_config.n_queries += 1),
        ),
    ];
    let mut failures = Vec::new();
    for (name, tamper) in &cases {
        let mut proof = honest.clone();
        tamper(&mut proof);
        match outcome::<P2MerkleChannel>(&format, &proof) {
            Ok(()) => failures.push(format!("{name}: accepted")),
            Err(error) if error == "panicked" => failures.push(format!("{name}: panicked")),
            Err(error) => eprintln!("{name}: {error}"),
        }
    }
    let other_circuit = honest.proof.stark_proof.commitments[1];
    if !vos_pvm_recair::masked::segment::verify_segment::<P2MerkleChannel>(
        &format,
        &honest,
        Some(other_circuit),
    )
    .is_err_and(|error| matches!(error, Error::Circuit))
    {
        failures.push("another circuit's root: not refused as such".into());
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
