//! The device format, 47, counted on the device shape's masked reference,
//! its built set with every chip a device program may hold, the full CPU
//! among them, at the most rows a device program takes.

use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::deep_values_of_column;
use stwo_constraint_framework::InfoEvaluator;
use vos_pvm_device::masked::{device_floors, device_reveals};
use vos_pvm_proof::device::{DEVICE_ALL, DEVICE_MAX_LOG_SIZE, DeviceShape, device_chips_of_mask};
use vos_pvm_proof::format::{DEVICE_PROOF, DEVICE_REFERENCE, FormatParams, lookup};
use vos_pvm_proof::framework_access::MAX_RELATION_WIDTH;
use vos_pvm_proof::masked::{DeviceComponents, drive_masked_device_chip};
use vos_pvm_proof::security::{SecurityShape, proven_count, security_bits};
use vos_pvm_recair_air::masking::{
    BlindRelation, MaskedComponent, MaskedComponents, air_log_size, committed_log_sizes,
    composition_log_degree_bound, sample_points,
};

/// The device set's masked shape with every chip at `2^log_size` rows, as
/// its reference counts it: its trees' levels, its sample points' DEEP
/// values, its constraints, every fraction a masked row evaluates (the
/// blinding's among them) and the widest relation.
fn device_shape(log_size: u32) -> SecurityShape {
    shape_of(DEVICE_ALL.into(), log_size)
}

/// The masked shape of the device set `set_shape`: every chip it may hold
/// and its CPU.
fn shape_of(set_shape: DeviceShape, log_size: u32) -> SecurityShape {
    let pins = DEVICE_PROOF.masking.unwrap();
    let chips: Vec<usize> = device_chips_of_mask(DEVICE_ALL).collect();
    let set = DeviceComponents::layout(set_shape, &vec![log_size; chips.len()]).unwrap();
    let trees = committed_log_sizes(&set, &pins).unwrap();
    let points = sample_points(&set, CirclePoint::<SecureField>::get_point(1), &pins).unwrap();
    let columns = points.iter().flatten();
    let composition = composition_log_degree_bound(&set).unwrap();
    let components = set.components();
    let masked_level = components
        .iter()
        .flat_map(|&inner| {
            MaskedComponent { inner }
                .trace_log_degree_bounds()
                .0
                .into_iter()
                .flatten()
        })
        .max()
        .unwrap();
    let channel = &mut Blake2sM31Channel::default();
    let relations = DeviceComponents::draw_relations(set_shape, channel);
    let blind = BlindRelation::draw(channel);
    let fractions: u64 = chips
        .iter()
        .map(|&chip| {
            let info = drive_masked_device_chip(
                set_shape,
                chip,
                log_size,
                &relations,
                &blind,
                InfoEvaluator::empty(),
            );
            (info.logup.fracs.len() as u64) << log_size
        })
        .sum();
    SecurityShape {
        log_degree_bound: trees.iter().flatten().copied().max().unwrap(),
        log_trace_length: masked_level,
        log_composition_degree_bound: composition,
        sampled_values: columns
            .clone()
            .map(|column| deep_values_of_column(column.len()) as u64)
            .sum(),
        max_samples_per_column: columns
            .map(|column| deep_values_of_column(column.len()))
            .max()
            .unwrap() as u64,
        constraints: components.iter().map(|c| c.n_constraints() as u64).sum(),
        logup_fractions: fractions,
        relation_width: MAX_RELATION_WIDTH as u64,
        composition_point_doublings: composition - air_log_size(&set).unwrap(),
    }
}

/// The lifted tree binds a column to its size only by the periodicity
/// value of a column sampled at two points (`SECURITY.md`, "Masking"):
/// every committed column of the device set, every chip a device program
/// may hold, is sampled at one or two points, but the preprocessed columns
/// no chip reads and the salts, at none.
#[test]
fn every_device_column_is_sampled_at_one_or_two_points() {
    let pins = DEVICE_PROOF.masking.unwrap();
    let chips = device_chips_of_mask(DEVICE_ALL).count();
    let set = DeviceComponents::layout(DEVICE_ALL.into(), &vec![10; chips]).unwrap();
    let points = sample_points(&set, CirclePoint::<SecureField>::get_point(1), &pins).unwrap();
    assert!(points[0].iter().all(|column| column.len() <= 1));
    for tree in 1..4 {
        let salts = pins.salt_columns;
        let (columns, salted) = points[tree].split_at(points[tree].len() - salts);
        assert!(
            columns.iter().all(|c| (1..=2).contains(&c.len())),
            "tree {tree}"
        );
        assert!(salted.iter().all(Vec::is_empty), "tree {tree}");
    }
    assert!(points.iter().flatten().any(|column| column.len() == 2));
}

/// The registry's reference for the device format is its built set's
/// masked shape at `DEVICE_MAX_LOG_SIZE`, field for field; it counts its
/// pinned bits on it, and one query fewer falls under 62.
#[test]
fn the_device_reference_shape_is_the_built_sets() {
    let format = DEVICE_PROOF;
    let built = device_shape(DEVICE_MAX_LOG_SIZE);
    assert_eq!(built, DEVICE_REFERENCE);
    let counted = vos_pvm_proof::format::count(&format).unwrap();
    assert_eq!(counted.reference, DEVICE_REFERENCE);
    let bits = security_bits(&format.params, &built).unwrap();
    assert_eq!(bits, counted.bits);
    assert!(counted.meets(&format.floor));
    let count = proven_count(&format.params, &built).unwrap();
    assert!(count >= 62.0, "{count}");
    let fewer = FormatParams {
        n_queries: format.params.n_queries - 1,
        ..format.params
    };
    assert!(proven_count(&fewer, &built).unwrap() < 62.0);
    assert_eq!(lookup(format.number), Some(&format));
}

/// The per-program CPU's cut only raises the count: the test kernel's
/// cut CPU, every other chip at the reference's size, counts no fewer bits
/// than the full CPU there.
#[test]
fn the_reference_bounds_the_per_program_cpu() {
    let reference = proven_count(&DEVICE_PROOF.params, &DEVICE_REFERENCE).unwrap();
    let blob = crate::support::blob();
    let code = vos_pvm_proof::kernel::trace_kernel(&blob, &crate::support::witness(1), 10_000)
        .unwrap()
        .side_note;
    let cut = DeviceShape {
        cpu: vos_pvm_proof::chips::CpuColumns::of_code(&code.code, &code.bitmask),
        ..DEVICE_ALL.into()
    };
    assert_ne!(cut.cpu, vos_pvm_proof::chips::CpuColumns::ALL);
    let count = proven_count(&DEVICE_PROOF.params, &shape_of(cut, DEVICE_MAX_LOG_SIZE)).unwrap();
    assert!(count >= reference, "{count} against {reference}");
}

/// The masking's condition (`proving.md` §5, how large `h` must be) on
/// every chip of the device set, at its floor and at the most rows a
/// program takes: each reads two offsets at most, so a masked column
/// reveals at most `4·2 + 47·3 = 149` rows, within `h = 256` (107 spare),
/// though not twice within it; and the floor, 2^10 rows, is `4h`.
#[test]
fn every_device_chip_reveals_at_most_its_h() {
    let format = DEVICE_PROOF;
    let h = 1usize << format.masking.unwrap().log_mask_rows;
    assert_eq!(h, 256);
    let chips = device_chips_of_mask(DEVICE_ALL).count();
    for log_size in [10, DEVICE_MAX_LOG_SIZE] {
        let reveals = device_reveals(&format, DEVICE_ALL.into(), &vec![log_size; chips]).unwrap();
        assert_eq!(reveals.len(), chips);
        for (reveal, log_mask_rows) in reveals {
            assert_eq!((reveal.offsets, reveal.rows), (2, 149), "2^{log_size}");
            assert_eq!(1usize << log_mask_rows, h);
            assert!(reveal.rows <= h && 2 * reveal.rows > h);
        }
    }
    let floors = device_floors(&format, DEVICE_ALL.into()).unwrap();
    assert!(floors.iter().all(|&floor| floor == 10), "{floors:?}");
}

/// A format whose `h` is below the rows a chip reveals has no floors, so
/// the install refuses it before any proof, where R1 would refuse every
/// transcript: `h = 128` against 149 rows at 47 queries, and `h = 256`
/// against `8 + 3·83 = 257` at 83 queries; 82 queries (254 rows) fit.
#[test]
fn an_h_under_the_rows_revealed_is_refused_before_any_proof() {
    let with = |log_mask_rows, n_queries| vos_pvm_proof::format::Format {
        params: FormatParams {
            n_queries,
            ..DEVICE_PROOF.params
        },
        masking: Some(vos_pvm_proof::format::Masking {
            log_mask_rows,
            ..DEVICE_PROOF.masking.unwrap()
        }),
        ..DEVICE_PROOF
    };
    assert!(device_floors(&with(7, 47), DEVICE_ALL.into()).is_none());
    assert!(device_floors(&with(8, 83), DEVICE_ALL.into()).is_none());
    assert!(device_floors(&with(8, 82), DEVICE_ALL.into()).is_some());
}

/// A smaller device program counts more bits than the reference: the
/// reference bounds every program the format admits.
#[test]
fn the_reference_bounds_smaller_programs() {
    let reference = proven_count(&DEVICE_PROOF.params, &DEVICE_REFERENCE).unwrap();
    for log_size in 10..DEVICE_MAX_LOG_SIZE {
        let count = proven_count(&DEVICE_PROOF.params, &device_shape(log_size)).unwrap();
        assert!(
            count >= reference,
            "2^{log_size}: {count} against {reference}"
        );
    }
}
