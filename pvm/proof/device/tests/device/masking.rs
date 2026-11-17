//! The masking's soundness gates on the device shape
//! (`docs/design/proving.md` §5), over the chip-set path the wrap's gates
//! do not take (`MaskedChipEval`, `ChipTraces::interaction`): R1 over every
//! column class; a broken constraint on the first, the last and the wrap
//! row refused by the prover and, forced, by the verifier; an unbalanced
//! relation refused, and the blinding unable to cancel it; a prover-chosen
//! table refused against the program's root.

use std::collections::BTreeSet;

use num_traits::Zero;
use stwo::core::air::Component;
use stwo::core::channel::MerkleChannel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::verifier::VerificationError;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_device::masked::{prove_device_forced, verify_device};
use vos_pvm_final_verifier::Error;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::chips::{range_multiplicity, register_memory};
use vos_pvm_proof::device::{DeviceShape, device_chip, device_chips_of_mask};
use vos_pvm_proof::format::{ChannelKind, Format};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::masked::{DeviceComponents, MaskedDeviceTrace};
use vos_pvm_proof::poseidon2::P2MerkleChannel;
use vos_pvm_recair::masked::{Checks, MaskRng, mask_rows};
use vos_pvm_recair::trace::FirstRowFraction;
use vos_pvm_recair_air::masking::{
    MaskedComponent, MaskedComponents, composition_log_degree_bound, sample_points,
};

use crate::support::{
    Proof, blob, format, program, prove, run, small_format, the_program, witness,
};

type P2 = P2MerkleChannel;

/// The column classes R1 must check on a device program's set: each masked
/// column with samples, by its level, its quotient's lift, its offsets from
/// the out-of-domain point and its component's `h`, each class once.
fn column_classes(format: &Format, shape: DeviceShape, log_sizes: &[u32]) -> usize {
    let set = DeviceComponents::layout(shape, log_sizes).expect("the layout");
    let rows = mask_rows(format, &set).expect("the masks' sizes");
    let pins = format.masking.expect("masked");
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

/// R1 checks every column class of the device set, on both channels, its
/// randomizer of full rank on the first attempt, within `h/4` rows a class.
#[test]
fn r1_checks_every_column_class() {
    fn checked<MC: MerkleChannel>(format: &Format)
    where
        SimdBackend: BackendForChannel<MC>,
    {
        let program = program::<MC>(format, &blob());
        let (proof, stats) =
            prove::<MC>(format, &program, &blob(), &witness(1), MaskRng::Seeded(1))
                .expect("proves");
        verify_device::<MC>(format, &program, &proof).expect("verifies");
        assert_eq!(stats.attempts, 1);
        assert_eq!(
            stats.classes,
            column_classes(format, program.shape(), &program.log_sizes)
        );
        let h = 1usize << format.masking.expect("masked").log_mask_rows;
        assert!(stats.revealed_rows <= h, "{stats:?}");
    }
    checked::<P2>(&format());
    checked::<Blake2sM31MerkleChannel>(&small_format(ChannelKind::Blake2sM31, 6, 4));
}

/// The position of chip `chip` among the program's chips.
fn position(chip: usize) -> usize {
    device_chips_of_mask(the_program().active)
        .position(|at| at == chip)
        .expect("the chip")
}

/// Coset row `row` of a column of `2^log_size` rows, where the evaluation
/// stores it.
fn stored(row: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(row, log_size), log_size)
}

/// The trace's chip at `position`, its main column `column` at coset row
/// `row` (from the end when negative), moved by `by`.
fn bump(trace: &mut MaskedDeviceTrace, position: usize, column: usize, row: isize, by: u32) {
    let log_size = trace.log_sizes[position];
    let row = row.rem_euclid(1isize << log_size) as usize;
    let columns = trace.main_columns_mut().nth(position).expect("the chip");
    columns[column].as_mut_slice()[stored(row, log_size)] += BaseField::from(by);
}

/// The kernel's run proved under its program, the trace through `tamper`,
/// the blinding fractions through `blind`, the prover's own check of the
/// constraints made only when `checked`.
fn forced(
    seed: u64,
    tamper: impl FnOnce(&mut MaskedDeviceTrace),
    blind: impl Fn(&AllLookupElements, &mut [FirstRowFraction]),
    checked: bool,
) -> Result<Proof<P2>, vos_pvm_device::Error> {
    let checks = Checks {
        constraints: checked,
        ..Checks::ALL
    };
    prove_device_forced::<P2>(
        &format(),
        the_program(),
        &mut run(&blob(), &witness(1)),
        MaskRng::Seeded(seed),
        tamper,
        blind,
        checks,
    )
    .map(|(proof, _)| proof)
}

/// A broken constraint is refused on the first row, the last and the wrap
/// row: the register ledger's `BothRealH` (in no relation's tuple) moved at
/// row 0, at the last row (whose constraint reads row 0 across the wrap)
/// and mid-way. The prover refuses each; forced, the verifier refuses it at
/// the out-of-domain point, the logup still balanced.
#[test]
fn a_broken_constraint_on_the_first_last_or_wrap_row_is_refused() {
    let at = position(device_chip::REGISTER_MEMORY);
    let column = register_memory::Column::BothRealH.offset();
    for row in [0, -1, 37] {
        let tamper = |trace: &mut MaskedDeviceTrace| bump(trace, at, column, row, 1);
        let refused = forced(4, tamper, |_, _| {}, true);
        assert!(
            matches!(refused, Err(vos_pvm_device::Error::Unsatisfied)),
            "row {row}: {refused:?}"
        );
        let proof = forced(4, tamper, |_, _| {}, false).expect("a forced proof");
        let outcome = verify_device::<P2>(&format(), the_program(), &proof);
        assert!(
            matches!(
                outcome,
                Err(Error::Stark(VerificationError::OodsNotMatching))
            ),
            "row {row}: {outcome:?}"
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
    let at = position(device_chip::RANGE_MULTIPLICITY_256);
    let column = range_multiplicity::Column::Multiplicity.offset();
    let tamper = |trace: &mut MaskedDeviceTrace| bump(trace, at, column, 5, 1);
    let unbalanced = forced(5, tamper, |_, _| {}, true).expect("it proves");
    assert!(matches!(
        verify_device::<P2>(&format(), the_program(), &unbalanced),
        Err(Error::Logup)
    ));
    let imbalance: SecureField = unbalanced.proof.claimed_sums.iter().copied().sum();
    assert!(!imbalance.is_zero());
    let cpu = position(device_chip::CPU);
    let cancel = |_: &AllLookupElements, fractions: &mut [FirstRowFraction]| {
        let cpu = &mut fractions[cpu];
        cpu.numerator -= imbalance * cpu.denominator;
    };
    let refused = forced(5, tamper, cancel, true);
    assert!(
        matches!(refused, Err(vos_pvm_device::Error::Unsatisfied)),
        "{refused:?}"
    );
    let cancelled = forced(5, tamper, cancel, false).expect("a forced proof");
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
        verify_device::<P2>(&format(), the_program(), &cancelled),
        Err(Error::Stark(VerificationError::OodsNotMatching))
    ));
}

/// The program's root pins the tables: a prover-chosen table, the
/// power-of-two table's entry at a padding row of no multiplicity made one
/// no honest table holds (the logup still balanced, every constraint held),
/// verifies against the root it commits, and is refused against the
/// program's.
#[test]
fn the_programs_root_pins_the_tables() {
    let at = position(device_chip::POWER_OF_TWO);
    let choose = |trace: &mut MaskedDeviceTrace| {
        let log_size = trace.log_sizes[at];
        // Row 100 is past the table's 64 entries, a repeat of no multiplicity:
        // its shift amount made 70, an entry no honest table holds.
        let table = trace.preprocessed_columns_mut().nth(at).unwrap();
        table[0].as_mut_slice()[stored(100, log_size)] = BaseField::from(70);
    };
    let chosen = forced(9, choose, |_, _| {}, true).expect("a chosen table proves");
    let program = the_program();
    let its_own = chosen.proof.stark_proof.commitments[0];
    assert_ne!(its_own, program.circuit);
    let mut chosen_program = program.clone();
    chosen_program.circuit = its_own;
    verify_device::<P2>(&format(), &chosen_program, &chosen)
        .expect("verifies against the root it commits");
    assert!(matches!(
        verify_device::<P2>(&format(), program, &chosen),
        Err(Error::Circuit)
    ));
}
