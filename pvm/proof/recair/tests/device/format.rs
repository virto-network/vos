//! The device formats, 47 and 46, counted on the device shape's masked
//! reference, each its built set (the word ledger's and the byte ledger's)
//! with every chip a device program may hold, the full CPU among them, at
//! the most rows a device program takes.

use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::deep_values_of_column;
use stwo_constraint_framework::InfoEvaluator;
use vos_pvm_proof::device::{DEVICE_ALL, DEVICE_MAX_LOG_SIZE, DeviceShape, device_chips_of_mask};
use vos_pvm_proof::format::{
    BYTE_DEVICE_PROOF, BYTE_DEVICE_REFERENCE, DEVICE_PROOF, DEVICE_REFERENCE, Format, FormatParams,
    lookup,
};
use vos_pvm_proof::framework_access::MAX_RELATION_WIDTH;
use vos_pvm_proof::masked::{DeviceComponents, drive_masked_device_chip};
use vos_pvm_proof::security::{SecurityShape, proven_count, security_bits};
use vos_pvm_recair::masked::device::{device_floors, device_reveals};
use vos_pvm_recair::masked::mask_pins;
use vos_pvm_recair_air::masked::{
    BlindRelation, MaskedComponent, MaskedComponents, air_log_size, committed_log_sizes,
    composition_log_degree_bound, sample_points,
};

/// Device format `format`'s set: every chip a device program may hold, the
/// full CPU, its memory ledger.
fn set_of(format: &Format) -> DeviceShape {
    DeviceShape {
        memory: format.memory,
        ..DEVICE_ALL.into()
    }
}

/// Device format `format`'s set's masked shape with every chip at
/// `2^log_size` rows, as its reference counts it: its trees' levels, its
/// sample points' DEEP values, its constraints, every fraction a masked
/// row evaluates (the blinding's among them) and the widest relation.
fn device_shape(format: &Format, log_size: u32) -> SecurityShape {
    shape_of(set_of(format), log_size)
}

/// The masked shape of the device set `set_shape`: every chip it may hold,
/// its CPU and its memory ledger.
fn shape_of(set_shape: DeviceShape, log_size: u32) -> SecurityShape {
    let pins = mask_pins(&DEVICE_PROOF.masking.unwrap());
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

/// The registry's reference for each device format is its built set's
/// masked shape at `DEVICE_MAX_LOG_SIZE`, field for field; each counts its
/// pinned bits on it, and one query fewer falls under 62.
#[test]
fn the_device_reference_shape_is_the_built_sets() {
    for (format, reference) in [
        (DEVICE_PROOF, DEVICE_REFERENCE),
        (BYTE_DEVICE_PROOF, BYTE_DEVICE_REFERENCE),
    ] {
        let built = device_shape(&format, DEVICE_MAX_LOG_SIZE);
        assert_eq!(built, reference, "format {}", format.number);
        assert_eq!(format.reference, reference);
        let bits = security_bits(&format.params, &built).unwrap();
        assert_eq!(bits, format.bits);
        assert!(format.meets_floors());
        let count = proven_count(&format.params, &built).unwrap();
        assert!(count >= 62.0, "{count}");
        let fewer = FormatParams {
            n_queries: format.params.n_queries - 1,
            ..format.params
        };
        assert!(proven_count(&fewer, &built).unwrap() < 62.0);
        assert_eq!(lookup(format.number), Some(&format));
    }
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
        ..set_of(&DEVICE_PROOF)
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
    for format in [DEVICE_PROOF, BYTE_DEVICE_PROOF] {
        let h = 1usize << format.masking.unwrap().log_mask_rows;
        assert_eq!(h, 256);
        let chips = device_chips_of_mask(DEVICE_ALL).count();
        for log_size in [10, DEVICE_MAX_LOG_SIZE] {
            let reveals = device_reveals(&format, set_of(&format), &vec![log_size; chips]).unwrap();
            assert_eq!(reveals.len(), chips);
            for (reveal, log_mask_rows) in reveals {
                assert_eq!((reveal.offsets, reveal.rows), (2, 149), "2^{log_size}");
                assert_eq!(1usize << log_mask_rows, h);
                assert!(reveal.rows <= h && 2 * reveal.rows > h);
            }
        }
        let floors = device_floors(&format, set_of(&format)).unwrap();
        assert!(floors.iter().all(|&floor| floor == 10), "{floors:?}");
    }
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
    for format in [DEVICE_PROOF, BYTE_DEVICE_PROOF] {
        let reference = proven_count(&format.params, &format.reference).unwrap();
        for log_size in 10..DEVICE_MAX_LOG_SIZE {
            let count = proven_count(&format.params, &device_shape(&format, log_size)).unwrap();
            assert!(
                count >= reference,
                "format {}, 2^{log_size}: {count} against {reference}",
                format.number
            );
        }
    }
}
