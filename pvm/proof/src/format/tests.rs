use super::reference::SEGMENT_RELATION_WIDTH;
use super::*;
use crate::framework_access::{
    AllLookupElements, air_layout, create_verifier_components, draw_all_lookup_elements,
};
use alloc::vec::Vec;
use num_traits::Zero;
use stwo::core::air::Component;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{PcsConfig, TreeVec};
use stwo_constraint_framework::TraceLocationAllocator;

/// `f` of the segment AIR's layout and components with every chip at
/// `2^log_size` rows.
fn with_segment_air<R>(
    log_size: u32,
    format: &Format,
    f: impl FnOnce(&crate::framework_access::AirLayout, &[&dyn Component]) -> R,
) -> R {
    let count = crate::chip_idx::COUNT;
    let mask = ((1u64 << count) - 1) as u32;
    let log_sizes = alloc::vec![log_size; count];
    let (trace_sizes, preprocessed) =
        create_verifier_components::trace_and_preprocessed_sizes(&log_sizes, mask);
    let mut trees = TreeVec::concat_cols(trace_sizes.into_iter());
    trees[0] = preprocessed;
    let mut lookups = AllLookupElements::default();
    draw_all_lookup_elements(
        &mut lookups,
        &mut stwo::core::channel::Blake2sM31Channel::default(),
        mask,
    );
    let components = create_verifier_components::components(
        &mut TraceLocationAllocator::default(),
        &lookups,
        &log_sizes,
        &alloc::vec![SecureField::zero(); count],
        mask,
    );
    let refs: Vec<&dyn Component> = components.iter().map(|c| &**c).collect();
    f(
        &air_layout(&format.pcs_config(), &refs, &trees).unwrap(),
        &refs,
    )
}

/// The segment AIR's shape with every chip at `2^log_size` rows.
fn segment_air_shape(log_size: u32, format: &Format) -> SecurityShape {
    with_segment_air(log_size, format, |layout, refs| layout.security_shape(refs))
}

/// The lifted tree binds a column to its size only by the periodicity
/// value of a column sampled at two points (`SECURITY.md`, "Masking"):
/// every main and interaction column of the segment AIR is sampled at one
/// or two points, a preprocessed column at most one.
#[test]
fn every_segment_column_is_sampled_at_one_or_two_points() {
    let samples = with_segment_air(10, &SEGMENT, |layout, _| layout.samples.clone());
    assert!(samples[0].iter().all(|&n| n <= 1), "{:?}", samples[0]);
    for tree in &samples[1..3] {
        assert!(!tree.is_empty());
        assert!(tree.iter().all(|n| (1..=2).contains(n)), "{tree:?}");
    }
    assert!(samples[1..3].iter().flatten().any(|&n| n == 2));
}

/// The registry's segment reference shape is the segment AIR's, every
/// chip at 2^20 rows (the device's, the masked device set's, is
/// `vos-pvm-device`'s tests').
#[test]
fn the_reference_shapes_are_the_segment_airs() {
    assert_eq!(segment_air_shape(20, &SEGMENT), SEGMENT_REFERENCE);
    assert_eq!(
        crate::lookups::MAX_RELATION_WIDTH as u64,
        SEGMENT_RELATION_WIDTH
    );
}

/// Logup forces integer cancellation only below `p` fractions: the full set
/// at 2^20 (0.855·p) is counted, at 2^21 refused as outside the analysis.
#[test]
fn a_shape_whose_fractions_reach_p_is_outside_the_analysis() {
    let config = SEGMENT.pcs_config();
    let check =
        |shape: &SecurityShape| crate::proof::check_format_security(&SEGMENT, &config, shape);
    assert!(check(&segment_air_shape(20, &SEGMENT)).is_ok());
    let wide = segment_air_shape(21, &SEGMENT);
    assert!(
        wide.logup_fractions >= (1 << 31) - 1,
        "{}",
        wide.logup_fractions
    );
    assert_eq!(check(&wide), Err(crate::proof::SecurityError::Outside));
    let at_p = SecurityShape {
        logup_fractions: (1 << 31) - 1,
        ..SEGMENT_REFERENCE
    };
    assert_eq!(check(&at_p), Err(crate::proof::SecurityError::Outside));
    let below = SecurityShape {
        logup_fractions: (1 << 31) - 2,
        ..SEGMENT_REFERENCE
    };
    assert!(check(&below).is_ok());
}

/// The tool's two counts, pinned per format at its reference shape:
/// every format clears its floors, the wrap with affine batching.
#[test]
fn the_bit_counts_are_pinned_per_format() {
    let pinned: Vec<(u32, u32, u32)> = REGISTRY
        .iter()
        .map(|format| {
            let counted = count(format).expect("a count for every registered format");
            let bits = crate::security::security_bits(&format.params, &counted.reference).unwrap();
            assert_eq!(bits, counted.bits, "format {}", format.number);
            assert!(counted.meets(&format.floor), "format {}", format.number);
            (format.number, bits.conjectured, bits.proven)
        })
        .collect();
    assert_eq!(
        pinned,
        [(32, 108, 63), (39, 106, 65), (41, 104, 62), (47, 110, 62),]
    );
    assert!(
        REGISTRY
            .iter()
            .zip(COUNTS)
            .all(|(format, count)| format.number == count.number)
    );
    // Every format grinds an interaction PoW: the prover always grinds
    // and the verifier always checks one.
    assert!(
        REGISTRY
            .iter()
            .all(|format| format.interaction_pow_bits() > 0)
    );
}

/// The unrounded counts the parameters were chosen by: the segments'
/// 62.81 at 40 queries and PoW 24, no less than 44 queries at PoW 20
/// give the same shape, and the device format's least query count whose
/// count clears 62.
#[test]
fn the_parameters_are_the_least_that_clear_their_margins() {
    let proven = |params: &FormatParams, shape: &SecurityShape| {
        crate::security::proven_count(params, shape).unwrap()
    };
    let device = count(&DEVICE_PROOF).unwrap().reference;
    let segment = proven(&SEGMENT.params, &SEGMENT_REFERENCE);
    assert!((62.81..62.82).contains(&segment), "{segment}");
    let at_44 = proven(&LEAF_FOLD.params, &SEGMENT_REFERENCE);
    assert!((62.74..62.75).contains(&at_44), "{at_44}");
    let fewer = FormatParams {
        n_queries: DEVICE_PROOF.params.n_queries - 1,
        ..DEVICE_PROOF.params
    };
    assert!(proven(&DEVICE_PROOF.params, &device) >= 62.0);
    assert!(proven(&fewer, &device) < 62.0);
}

/// A proof's config does not carry its batching: deserialized, it reads
/// powers, and the verifier takes the format's.
#[test]
fn the_verifier_takes_the_batching_from_the_format() {
    let carried = PcsConfig {
        deep_batching: DeepBatching::Powers,
        ..MASKED_WRAP.pcs_config()
    };
    assert_eq!(
        MASKED_WRAP.verifier_config(&carried),
        MASKED_WRAP.pcs_config()
    );
    assert_eq!(MASKED_WRAP.pcs_config().deep_batching, DeepBatching::Affine);
    assert!(
        crate::proof::check_format_security(&MASKED_WRAP, &carried, &MASKED_WRAP_REFERENCE).is_ok()
    );
    for format in [SEGMENT, LEAF_FOLD] {
        assert_eq!(format.pcs_config().deep_batching, DeepBatching::Powers);
    }
}

/// Every number names one entry; only 39, 41 and 47 are admitted, and a
/// segment verifier takes 41 alone; every other number is refused, as
/// retired when an earlier format took it, else as unregistered.
#[test]
fn the_registry_numbers_round_trip() {
    for format in REGISTRY {
        assert_eq!(lookup(format.number), Some(&format));
        assert_eq!(
            admitted(format.number).is_ok(),
            [SEGMENT.number, MASKED_WRAP.number, DEVICE_PROOF.number,].contains(&format.number)
        );
        assert_eq!(
            admitted_segment(format.number).is_ok(),
            format.number == SEGMENT.number
        );
    }
    assert!(REGISTRY.windows(2).all(|w| w[0].number < w[1].number));
    for number in (0..64).chain([u32::MAX]) {
        if REGISTRY.iter().any(|format| format.number == number) {
            continue;
        }
        assert!(lookup(number).is_none());
        let refused = match RETIRED.contains(&number) {
            true => Refused::Retired,
            false => Refused::Unregistered,
        };
        assert_eq!(admitted(number), Err(refused));
    }
}

/// A proof below either floor is refused: fewer queries than the
/// conjectured floor allows, less PoW than the proven floor allows, a
/// shape whose proven count falls short, and parameters other than the
/// format's.
#[test]
fn a_proof_below_a_floor_is_refused() {
    let check = crate::proof::check_format_security;
    let config = SEGMENT.pcs_config();
    assert_eq!(
        check(&SEGMENT, &config, &SEGMENT_REFERENCE).unwrap(),
        count(&SEGMENT).unwrap().bits
    );

    let mut fewer = config;
    fewer.fri_config.n_queries = 37;
    let error = check(&SEGMENT, &fewer, &SEGMENT_REFERENCE).unwrap_err();
    assert_eq!(
        error,
        crate::proof::SecurityError::Conjectured {
            format: 41,
            bits: 98,
            floor: 100
        }
    );

    // 20 + 40 · 2 = 100 conjectured, but the query term tends to
    // 20 + 40 = 60 proven bits, and falls short of it.
    let mut less_pow = config;
    less_pow.pow_bits = 20;
    let error = check(&SEGMENT, &less_pow, &SEGMENT_REFERENCE).unwrap_err();
    assert_eq!(
        error,
        crate::proof::SecurityError::Proven {
            format: 41,
            bits: 59,
            floor: 60
        }
    );

    // 2^30 sampled values over a 2^28-row trace: the batching term binds.
    let wide = SecurityShape {
        log_degree_bound: 28,
        log_trace_length: 28,
        log_composition_degree_bound: 29,
        sampled_values: 1 << 30,
        ..SEGMENT_REFERENCE
    };
    let error = check(&SEGMENT, &config, &wide).unwrap_err();
    assert!(
        matches!(error, crate::proof::SecurityError::Proven { .. }),
        "{error}"
    );

    let mut stronger = config;
    stronger.fri_config.n_queries = 41;
    let error = check(&SEGMENT, &stronger, &SEGMENT_REFERENCE).unwrap_err();
    assert_eq!(
        error,
        crate::proof::SecurityError::Parameters { format: 41 }
    );
}
