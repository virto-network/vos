//! Format 39's counts under masking variant (c): the unmasked formats'
//! counts unmoved, the masked wrap's terms, the least queries that clear its
//! floors, and its need for affine batching.

use super::reference::WRAP_REFERENCE;
use super::*;
use crate::security::{proven_count, security_bits, summed_bits_at, summed_count, term_bits};

fn count(params: &FormatParams, shape: &SecurityShape) -> f64 {
    proven_count(params, shape).unwrap()
}

/// Format 39's parameters at another blowup, query count, PoW, fold step
/// and last layer.
fn masked(
    log_blowup: u32,
    n_queries: usize,
    pow_bits: u32,
    fold_step: u32,
    log_last_layer: u32,
) -> FormatParams {
    FormatParams {
        log_blowup,
        n_queries,
        pow_bits,
        fold_step,
        log_last_layer,
        ..MASKED_WRAP.params
    }
}

/// The least queries whose masked counts clear format 39's floors.
fn least_queries(base: FormatParams) -> Option<usize> {
    (1..=128).find(|&n_queries| {
        let bits =
            security_bits(&FormatParams { n_queries, ..base }, &MASKED_WRAP_REFERENCE).unwrap();
        bits.conjectured >= MASKED_WRAP.floor.conjectured && bits.proven >= MASKED_WRAP.floor.proven
    })
}

/// Variant (c) moves no unmasked count: every format but the masked ones
/// counted on their masked shapes (39, 47) samples its composition at the
/// out-of-domain point itself and counts what it pins; format 39's
/// reference is the unmasked wrap AIR's at (c)'s levels.
#[test]
fn the_unmasked_counts_do_not_move() {
    let counted_masked = [MASKED_WRAP.number, DEVICE_PROOF.number];
    for format in REGISTRY {
        let counted = super::count(&format).unwrap();
        let doublings = u32::from(counted_masked.contains(&format.number));
        assert_eq!(
            counted.reference.composition_point_doublings, doublings,
            "format {}",
            format.number
        );
        assert_eq!(
            format.masking.is_some(),
            counted_masked.contains(&format.number),
            "format {}",
            format.number
        );
        if format.number != MASKED_WRAP.number {
            assert_eq!(
                security_bits(&format.params, &counted.reference).unwrap(),
                counted.bits,
                "format {}",
                format.number
            );
        }
    }
    let levels = WRAP_REFERENCE.variant_c();
    assert_eq!(
        (
            levels.log_degree_bound,
            levels.log_trace_length,
            levels.log_composition_degree_bound,
            levels.composition_point_doublings,
        ),
        (17, 16, 17, 1)
    );
    assert_eq!(
        MASKED_WRAP_REFERENCE,
        SecurityShape {
            sampled_values: 538,
            constraints: 313 + 2,
            logup_fractions: (6 << 14) + (5 << 15) + (7 << 11),
            ..levels
        }
    );
}

/// Format 39 counts 106 / 65 (65.79), the query term binding at `m = 57`:
/// the DEEP batching about 0.06 bits above it, the worst FRI fold, the
/// first round's, about 0.2 above that, and ALI, DEEP and logup far above; its terms
/// summed, 64.25 at that `m` and 65.52 at the sum's best, `m = 29`. 16
/// queries is the least that clears its floor, 104 / 63: 15 count 101 / 63
/// (63.36), below the segments' 104 conjectured.
#[test]
fn format_39_counts_106_and_65() {
    let params = MASKED_WRAP.params;
    assert_eq!(
        (
            params.log_blowup,
            params.n_queries,
            params.pow_bits,
            params.fold_step,
            params.log_last_layer,
            params.interaction_pow_bits,
            params.batching,
        ),
        (5, 16, 26, 3, 6, 8, DeepBatching::Affine)
    );
    assert_eq!(
        security_bits(&params, &MASKED_WRAP_REFERENCE),
        Some(SecurityBits {
            conjectured: 106,
            proven: 65
        })
    );
    assert!(
        super::count(&MASKED_WRAP)
            .unwrap()
            .meets(&MASKED_WRAP.floor)
    );
    assert_eq!(
        crate::proof::check_format_security(
            &MASKED_WRAP,
            &MASKED_WRAP.pcs_config(),
            &MASKED_WRAP_REFERENCE
        ),
        Ok(super::count(&MASKED_WRAP).unwrap().bits)
    );

    let terms = term_bits(&params, &MASKED_WRAP_REFERENCE).unwrap();
    assert_eq!(terms.m, 57);
    assert_eq!(terms.query, count(&params, &MASKED_WRAP_REFERENCE));
    let within = |bits: f64, low: f64, high: f64| (low..high).contains(&bits);
    assert!(within(terms.query, 65.79, 65.80), "{terms:?}");
    assert!(within(terms.other.batching, 65.85, 65.86), "{terms:?}");
    assert!(within(terms.other.folds, 66.05, 66.06), "{terms:?}");
    assert!(within(terms.other.ali, 104.86, 104.87), "{terms:?}");
    assert!(within(terms.other.deep, 94.16, 94.17), "{terms:?}");
    assert!(within(terms.other.logup, 111.60, 111.61), "{terms:?}");
    // Summed rather than least, at the same m: the query term, the
    // batching, each of the four folds, ALI, DEEP and logup together.
    let summed = summed_bits_at(&params, &MASKED_WRAP_REFERENCE, terms.m).unwrap();
    assert!(within(summed, 64.25, 64.26), "{summed}");
    // The sum's own best m is another.
    let (m, summed) = summed_count(&params, &MASKED_WRAP_REFERENCE).unwrap();
    assert_eq!(m, 29);
    assert!(within(summed, 65.52, 65.53), "{summed}");

    assert_eq!(least_queries(params), Some(16));
    let fewer = masked(5, 15, 26, 3, 6);
    assert_eq!(
        security_bits(&fewer, &MASKED_WRAP_REFERENCE),
        Some(SecurityBits {
            conjectured: 101,
            proven: 63
        })
    );
    let fewer = count(&fewer, &MASKED_WRAP_REFERENCE);
    assert!((63.36..63.37).contains(&fewer), "{fewer}");
}

/// The least query count that clears 104 / 63 masked, by blowup, fold step,
/// last layer and PoW: format 39's shape (A: blowup 32, PoW 26, 16) and the
/// blowup-64 alternative (B: 13, 104 / 64, at twice the prover's memory).
/// Fold step 2 and a larger last layer save no query; below PoW 24 the
/// proven floor binds and costs queries, above it the conjectured one.
#[test]
fn the_least_queries_that_clear_the_floors() {
    let grid: [((u32, u32, u32, u32), usize); 10] = [
        ((4, 3, 6, 26), 20),
        ((5, 3, 6, 20), 18),
        ((5, 3, 6, 24), 16),
        ((5, 3, 6, 26), 16),
        ((5, 3, 6, 28), 16),
        ((5, 2, 6, 26), 16),
        ((5, 3, 8, 26), 16),
        ((6, 3, 6, 26), 13),
        ((6, 3, 6, 28), 13),
        ((6, 2, 6, 26), 13),
    ];
    for ((log_blowup, fold_step, log_last_layer, pow_bits), least) in grid {
        assert_eq!(
            least_queries(masked(log_blowup, 1, pow_bits, fold_step, log_last_layer)),
            Some(least),
            "log blowup {log_blowup}, fold step {fold_step}, last layer \
             2^{log_last_layer}, PoW {pow_bits}"
        );
    }
    let b = masked(6, 13, 26, 3, 6);
    assert_eq!(
        security_bits(&b, &MASKED_WRAP_REFERENCE),
        Some(SecurityBits {
            conjectured: 104,
            proven: 64
        })
    );
    let b_count = count(&b, &MASKED_WRAP_REFERENCE);
    assert!((64.79..64.80).contains(&b_count), "{b_count}");
}

/// The interaction PoW does not bind format 39: its logup term clears 100
/// bits without it, and the count is the same.
#[test]
fn the_interaction_pow_does_not_bind() {
    let without = FormatParams {
        interaction_pow_bits: 0,
        ..MASKED_WRAP.params
    };
    assert_eq!(
        count(&MASKED_WRAP.params, &MASKED_WRAP_REFERENCE),
        count(&without, &MASKED_WRAP_REFERENCE)
    );
    let terms = term_bits(&without, &MASKED_WRAP_REFERENCE).unwrap();
    assert!(terms.other.logup > 100.0, "{terms:?}");
}

/// Format 39 batches affinely (`DIVERGENCE-012`), as the device format
/// does; its floor does not need it. Batched by powers, the batching term
/// caps a count at 76.97 at blowup 32 and 74.47 at blowup 64, however many
/// queries are taken, above the floor: by powers the wrap counts 65.33 at
/// its 16 queries, the least that clears 104 / 63 by powers too.
#[test]
fn the_masked_wraps_batching() {
    let powers = |log_blowup, n_queries| FormatParams {
        batching: DeepBatching::Powers,
        ..masked(log_blowup, n_queries, 26, 3, 6)
    };
    for (log_blowup, low, high) in [(5, 76.97, 76.98), (6, 74.47, 74.48)] {
        let cap = count(&powers(log_blowup, 256), &MASKED_WRAP_REFERENCE);
        assert!((low..high).contains(&cap), "log blowup {log_blowup}: {cap}");
    }
    let by_powers = count(&powers(5, 16), &MASKED_WRAP_REFERENCE);
    assert!((65.33..65.34).contains(&by_powers), "{by_powers}");
    let least = |log_blowup| {
        (1..=256).find(|&n_queries| {
            let bits =
                security_bits(&powers(log_blowup, n_queries), &MASKED_WRAP_REFERENCE).unwrap();
            bits.conjectured >= MASKED_WRAP.floor.conjectured
                && bits.proven >= MASKED_WRAP.floor.proven
        })
    };
    assert_eq!(
        [6, 5, 4, 3].map(least),
        [Some(13), Some(16), Some(20), Some(26)]
    );
}

/// Format 39's masking (R6): 8 salt columns a tree, an 8-column `R`,
/// and `h = 256` within its static bounds: at least `2(4|O| + q(|O| + 1))`,
/// the randomizer's revealed functionals at `q` queries and `|O| = 2`
/// offsets (112), and at most `N/4` and `2N/3` for every component, the
/// smallest `h8`'s `N = 2^11`.
#[test]
fn the_masked_wraps_masking_meets_its_bounds() {
    let masking = MASKED_WRAP.masking.unwrap();
    assert_eq!(masking, MASKED_WRAP_MASKING);
    assert_eq!(
        (
            masking.salt_columns,
            masking.fri_mask_columns,
            masking.log_mask_rows
        ),
        (8, 8, 8)
    );
    let h = 1usize << masking.log_mask_rows;
    let offsets = 2;
    let revealed = 2 * (4 * offsets + MASKED_WRAP.params.n_queries * (offsets + 1));
    assert_eq!(revealed, 112);
    assert!(h >= revealed);
    let smallest = 1usize << 11;
    assert!(4 * h <= smallest && 3 * h <= 2 * smallest);
    assert!(31 * masking.salt_columns >= 248);
}
