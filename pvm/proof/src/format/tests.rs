use super::reference::SEGMENT_RELATION_WIDTH;
use super::*;
use crate::framework_access::{
    AllLookupElements, air_layout, create_verifier_components, draw_all_lookup_elements,
};
use alloc::vec::Vec;
use num_traits::Zero;
use stwo::core::air::Component;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo_constraint_framework::TraceLocationAllocator;

/// The segment AIR's shape with every chip at `2^log_size` rows.
fn segment_air_shape(log_size: u32, format: &Format) -> SecurityShape {
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
        &mut stwo::core::channel::Blake2sChannel::default(),
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
    air_layout(&format.pcs_config(), &refs, &trees)
        .unwrap()
        .security_shape(&refs)
}

/// The registry's segment reference shape is the segment AIR's, every
/// chip at 2^20 rows (the device's, the masked device set's, is
/// `vos-pvm-recair`'s device tests').
#[test]
fn the_reference_shapes_are_the_segment_airs() {
    assert_eq!(segment_air_shape(20, &SEGMENT), SEGMENT_REFERENCE);
    assert_eq!(
        crate::lookups::MAX_RELATION_WIDTH as u64,
        SEGMENT_RELATION_WIDTH
    );
}

/// The tool's two counts, pinned per format at its reference shape:
/// every format clears its floors, the wrap with affine batching.
#[test]
fn the_bit_counts_are_pinned_per_format() {
    let pinned: Vec<(u32, u32, u32)> = REGISTRY
        .iter()
        .map(|format| {
            let bits = crate::security::security_bits(&format.params, &format.reference).unwrap();
            assert_eq!(bits, format.bits, "format {}", format.number);
            (format.number, bits.conjectured, bits.proven)
        })
        .collect();
    assert_eq!(
        pinned,
        [
            (28, 146, 82),
            (32, 108, 63),
            (39, 146, 82),
            (41, 104, 62),
            (44, 110, 62),
            (46, 110, 62),
        ]
    );
    assert!(REGISTRY.iter().all(Format::meets_floors));
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
/// give the same shape, and the device and credential formats' least
/// query count whose count clears 62.
#[test]
fn the_parameters_are_the_least_that_clear_their_margins() {
    let count = |params: &FormatParams, shape: &SecurityShape| {
        crate::security::proven_count(params, shape).unwrap()
    };
    let segment = count(&SEGMENT.params, &SEGMENT_REFERENCE);
    assert!((62.81..62.82).contains(&segment), "{segment}");
    let at_44 = count(&LEAF_FOLD.params, &SEGMENT_REFERENCE);
    assert!((62.74..62.75).contains(&at_44), "{at_44}");
    for format in [DEVICE_PROOF, CREDENTIAL_PROOF] {
        let fewer = FormatParams {
            n_queries: format.params.n_queries - 1,
            ..format.params
        };
        assert!(count(&format.params, &format.reference) >= 62.0);
        assert!(
            count(&fewer, &format.reference) < 62.0,
            "format {}",
            format.number
        );
    }
}

/// The wrap counts 82.6 proven bits under affine batching, and needs 19
/// queries for its floor of 80. Batched by powers of one coefficient it
/// counts 74.7 at blowup 64 with 18 queries or 20, and as many queries
/// as the analysis takes: that batching term binds, and it grows with
/// the blowup; at blowup 8 it reaches 80 with 41 queries. The verifier's
/// check says so.
#[test]
fn the_wrap_needs_affine_batching() {
    let count = |batching, log_blowup, n_queries| {
        let params = FormatParams {
            log_blowup,
            n_queries,
            batching,
            ..WRAP.params
        };
        crate::security::proven_count(&params, &WRAP_REFERENCE).unwrap()
    };
    assert_eq!(WRAP.params.batching, DeepBatching::Affine);
    let affine = count(DeepBatching::Affine, 6, 20);
    assert!((82.60..82.61).contains(&affine), "{affine}");
    let least = |batching, log_blowup| (1..=256).find(|&q| count(batching, log_blowup, q) >= 80.0);
    assert_eq!(least(DeepBatching::Affine, 6), Some(19));

    for queries in [18, 20, 256] {
        let bits = count(DeepBatching::Powers, 6, queries);
        assert!((74.71..74.72).contains(&bits), "{queries} queries: {bits}");
    }
    assert_eq!(
        [6, 4, 3].map(|log_blowup| least(DeepBatching::Powers, log_blowup)),
        [None, None, Some(41)]
    );
    let powers = Format {
        params: FormatParams {
            batching: DeepBatching::Powers,
            ..WRAP.params
        },
        ..WRAP
    };
    let error = crate::proof::check_format_security(&powers, &powers.pcs_config(), &WRAP_REFERENCE)
        .unwrap_err();
    assert!(
        error.contains("74 proven bits, below format 28's floor of 80"),
        "{error}"
    );
    assert_eq!(
        crate::proof::check_format_security(&WRAP, &WRAP.pcs_config(), &WRAP_REFERENCE),
        Ok(WRAP.bits)
    );
}

/// A proof's config does not carry its batching: deserialized, it reads
/// powers, and the verifier takes the format's.
#[test]
fn the_verifier_takes_the_batching_from_the_format() {
    let carried = PcsConfig {
        deep_batching: DeepBatching::Powers,
        ..WRAP.pcs_config()
    };
    assert_eq!(WRAP.verifier_config(&carried), WRAP.pcs_config());
    assert_eq!(WRAP.pcs_config().deep_batching, DeepBatching::Affine);
    assert!(crate::proof::check_format_security(&WRAP, &carried, &WRAP_REFERENCE).is_ok());
    for format in [SEGMENT, LEAF_FOLD] {
        assert_eq!(format.pcs_config().deep_batching, DeepBatching::Powers);
    }
}

/// Every number names one entry; only 28, 39, 41, 44 and 46 are
/// admitted, and a segment verifier takes 41 alone; every other number,
/// one an earlier format took among them, is refused as unregistered.
#[test]
fn the_registry_numbers_round_trip() {
    for format in REGISTRY {
        assert_eq!(lookup(format.number), Some(&format));
        assert_eq!(
            admitted(format.number).is_ok(),
            [
                WRAP.number,
                SEGMENT.number,
                MASKED_WRAP.number,
                DEVICE_PROOF.number,
                CREDENTIAL_PROOF.number
            ]
            .contains(&format.number)
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
        let error = admitted(number).unwrap_err();
        assert!(error.contains("not registered"), "{error}");
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
        SEGMENT.bits
    );

    let mut fewer = config;
    fewer.fri_config.n_queries = 37;
    let error = check(&SEGMENT, &fewer, &SEGMENT_REFERENCE).unwrap_err();
    assert!(error.contains("98 conjectured bits"), "{error}");

    // 20 + 40 · 2 = 100 conjectured, but the query term tends to
    // 20 + 40 = 60 proven bits, and falls short of it.
    let mut less_pow = config;
    less_pow.pow_bits = 20;
    let error = check(&SEGMENT, &less_pow, &SEGMENT_REFERENCE).unwrap_err();
    assert!(
        error.contains("59 proven bits, below format 41's floor of 60"),
        "{error}"
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
    assert!(error.contains("proven bits"), "{error}");

    let mut stronger = config;
    stronger.fri_config.n_queries = 41;
    let error = check(&SEGMENT, &stronger, &SEGMENT_REFERENCE).unwrap_err();
    assert!(error.contains("differ from format 41"), "{error}");
}
