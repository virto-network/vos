//! Format 45 counted on the device shape's masked reference, the built set
//! with every chip a device program may hold at the most rows a device
//! program takes; the candidates measured beside it counted on the same
//! shape.

use stwo::core::air::Component;
use stwo::core::channel::Blake2sChannel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::DeepBatching;
use stwo::core::pcs::quotients::deep_values_of_column;
use stwo_constraint_framework::InfoEvaluator;
use vos_pvm_proof::device::{DEVICE_ALL, DEVICE_MAX_LOG_SIZE, device_chips_of_mask};
use vos_pvm_proof::format::{DEVICE_PROOF, DEVICE_REFERENCE, FormatParams, RETIRED, lookup};
use vos_pvm_proof::framework_access::MAX_RELATION_WIDTH;
use vos_pvm_proof::masked::{DeviceComponents, drive_masked_device_chip};
use vos_pvm_proof::security::{SecurityBits, SecurityShape, proven_count, security_bits};
use vos_pvm_recair::masked::device::{device_floors, device_reveals};
use vos_pvm_recair::masked::mask_pins;
use vos_pvm_recair_air::masked::{
    BlindRelation, MaskedComponent, MaskedComponents, air_log_size, committed_log_sizes,
    composition_log_degree_bound, sample_points,
};

/// The device set's masked shape with every chip at `2^log_size` rows, as
/// `format::DEVICE_REFERENCE` counts it: its trees' levels, its sample
/// points' DEEP values, its constraints, every fraction a masked row
/// evaluates (the blinding's among them) and the widest relation.
fn device_shape(log_size: u32) -> SecurityShape {
    let pins = mask_pins(&DEVICE_PROOF.masking.unwrap());
    let chips: Vec<usize> = device_chips_of_mask(DEVICE_ALL).collect();
    let set = DeviceComponents::layout(DEVICE_ALL, &vec![log_size; chips.len()]).unwrap();
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
    let channel = &mut Blake2sChannel::default();
    let relations = DeviceComponents::draw_relations(DEVICE_ALL, channel);
    let blind = BlindRelation::draw(channel);
    let fractions: u64 = chips
        .iter()
        .map(|&chip| {
            let info = drive_masked_device_chip(
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

/// Format 43's parameters at another blowup, query count, PoW and batching.
fn candidate(
    log_blowup: u32,
    n_queries: usize,
    pow_bits: u32,
    batching: DeepBatching,
) -> FormatParams {
    FormatParams {
        log_blowup,
        n_queries,
        pow_bits,
        batching,
        ..DEVICE_PROOF.params
    }
}

/// The registry's reference for format 45 is the built device set's
/// masked shape at `DEVICE_MAX_LOG_SIZE`, field for field; 45 counts its
/// pinned bits on it (62.82), and one query fewer falls under 62.
#[test]
fn the_device_reference_shape_is_the_built_sets() {
    let built = device_shape(DEVICE_MAX_LOG_SIZE);
    assert_eq!(built, DEVICE_REFERENCE);
    let bits = security_bits(&DEVICE_PROOF.params, &built).unwrap();
    assert_eq!(bits, DEVICE_PROOF.bits);
    assert!(DEVICE_PROOF.meets_floors());
    let count = proven_count(&DEVICE_PROOF.params, &built).unwrap();
    assert!(count >= 62.0, "{count}");
    let fewer = FormatParams {
        n_queries: DEVICE_PROOF.params.n_queries - 1,
        ..DEVICE_PROOF.params
    };
    assert!(proven_count(&fewer, &built).unwrap() < 62.0);
    assert_eq!(lookup(45), Some(&DEVICE_PROOF));
    for retired in [37, 43] {
        assert!(RETIRED.contains(&retired) && lookup(retired).is_none());
    }
}

/// The masking's condition (`proving.md` §5, how large `h` must be) on
/// every chip of the device set, at its floor and at the most rows a
/// program takes: each reads two offsets at most, so a masked column
/// reveals at most `4·2 + 47·3 = 149` rows, within `h = 256` (107 spare),
/// though not twice within it; and the floor, 2^10 rows, is `4h`.
#[test]
fn every_device_chip_reveals_at_most_its_h() {
    let h = 1usize << DEVICE_PROOF.masking.unwrap().log_mask_rows;
    assert_eq!(h, 256);
    let chips = device_chips_of_mask(DEVICE_ALL).count();
    for log_size in [10, DEVICE_MAX_LOG_SIZE] {
        let reveals = device_reveals(&DEVICE_PROOF, DEVICE_ALL, &vec![log_size; chips]).unwrap();
        assert_eq!(reveals.len(), chips);
        for (reveal, log_mask_rows) in reveals {
            assert_eq!((reveal.offsets, reveal.rows), (2, 149), "2^{log_size}");
            assert_eq!(1usize << log_mask_rows, h);
            assert!(reveal.rows <= h && 2 * reveal.rows > h);
        }
    }
    let floors = device_floors(&DEVICE_PROOF, DEVICE_ALL).unwrap();
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
    assert!(device_floors(&with(7, 47), DEVICE_ALL).is_none());
    assert!(device_floors(&with(8, 83), DEVICE_ALL).is_none());
    assert!(device_floors(&with(8, 82), DEVICE_ALL).is_some());
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

/// The least queries clearing 62 proven bits on the reference, by blowup,
/// PoW and batching: blowup 2 at PoW 20 87 by powers and 85 affine; blowup
/// 4 43 at PoW 20 and 47 at PoW 16; blowup 8 29 at PoW 20; either batching
/// where one count is given.
#[test]
fn the_least_queries_that_clear_62_bits() {
    let least = |log_blowup, pow_bits, batching| {
        (1..=256).find(|&n_queries| {
            let params = candidate(log_blowup, n_queries, pow_bits, batching);
            proven_count(&params, &DEVICE_REFERENCE).unwrap() >= 62.0
        })
    };
    for (log_blowup, pow_bits, powers, affine) in [
        (1, 20, 87, 85),
        (2, 20, 43, 43),
        (2, 16, 47, 47),
        (3, 20, 29, 29),
    ] {
        assert_eq!(
            least(log_blowup, pow_bits, DeepBatching::Powers),
            Some(powers)
        );
        assert_eq!(
            least(log_blowup, pow_bits, DeepBatching::Affine),
            Some(affine)
        );
    }
}

/// A candidate's log blowup, queries and PoW.
type Candidate = (u32, usize, u32);
/// Conjectured and proven bits.
type Bits = (u32, u32);

/// The candidates measured (`device-params.md`), each counted on the
/// reference: `(log blowup, queries, PoW)`, its bits by powers and by
/// affine batching.
#[test]
fn the_candidates_count_on_the_reference() {
    let candidates: [(Candidate, Bits, Bits); 5] = [
        ((1, 86, 20), (106, 61), (106, 62)),
        ((1, 87, 20), (107, 62), (107, 63)),
        ((2, 43, 20), (106, 62), (106, 62)),
        ((2, 47, 16), (110, 62), (110, 62)),
        ((3, 29, 20), (107, 62), (107, 63)),
    ];
    for ((log_blowup, n_queries, pow_bits), powers, affine) in candidates {
        for (batching, (conjectured, proven)) in [
            (DeepBatching::Powers, powers),
            (DeepBatching::Affine, affine),
        ] {
            let params = candidate(log_blowup, n_queries, pow_bits, batching);
            assert_eq!(
                security_bits(&params, &DEVICE_REFERENCE),
                Some(SecurityBits {
                    conjectured,
                    proven
                }),
                "{log_blowup}:{n_queries}:{pow_bits} {batching:?}"
            );
        }
    }
}
