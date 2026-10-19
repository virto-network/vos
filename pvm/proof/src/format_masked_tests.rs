//! Format 39's counts under masking variant (c): the unmasked formats'
//! counts unmoved, the masked wrap's terms, the least queries that clear its
//! floors, and its need for affine batching.

use super::*;
use crate::security::{proven_count, security_bits, term_bits};

/// Format 28 as Stwo builds it: its composition of bound 2^16 split once,
/// so FRI tests 2^15. [`WRAP_REFERENCE`] counts it one level up.
const WRAP_BUILT: SecurityShape = SecurityShape {
    log_degree_bound: 15,
    log_trace_length: 15,
    log_composition_degree_bound: 16,
    ..WRAP_REFERENCE
};

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

/// Variant (c) moves no unmasked count: every other format samples its
/// composition at the out-of-domain point itself and counts what it pins,
/// format 28 82.60; format 39's reference is 28's at (c)'s levels.
#[test]
fn the_unmasked_counts_do_not_move() {
    for format in REGISTRY {
        let doublings = u32::from(format.number == MASKED_WRAP.number);
        assert_eq!(
            format.reference.composition_point_doublings, doublings,
            "format {}",
            format.number
        );
        assert_eq!(format.masked, [30, 37, 39].contains(&format.number));
        if format.number != MASKED_WRAP.number {
            assert_eq!(
                security_bits(&format.params, &format.reference).unwrap(),
                format.bits,
                "format {}",
                format.number
            );
        }
    }
    let wrap = count(&WRAP.params, &WRAP_REFERENCE);
    assert!((82.60..82.61).contains(&wrap), "{wrap}");

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
            sampled_values: 2 * (458 + 24),
            constraints: 313 + 2,
            logup_fractions: (6 << 14) + (5 << 15) + (7 << 11),
            ..levels
        }
    );
}

/// Format 39 counts 146 / 82 (82.70), the query term binding at `m = 5`:
/// the DEEP batching 0.09 bits above it, the worst FRI fold, the first
/// round's, 0.19 above that, and ALI, DEEP and logup far above. 23 queries
/// is the least that clears 80 (80.84).
#[test]
fn format_39_counts_146_and_82() {
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
        (5, 24, 26, 3, 6, 8, DeepBatching::Affine)
    );
    assert_eq!(
        security_bits(&params, &MASKED_WRAP_REFERENCE),
        Some(SecurityBits {
            conjectured: 146,
            proven: 82
        })
    );
    assert!(MASKED_WRAP.meets_floors());
    assert_eq!(
        crate::proof::check_format_security(
            &MASKED_WRAP,
            &MASKED_WRAP.pcs_config(),
            &MASKED_WRAP_REFERENCE
        ),
        Ok(MASKED_WRAP.bits)
    );

    let terms = term_bits(&params, &MASKED_WRAP_REFERENCE).unwrap();
    assert_eq!(terms.m, 5);
    assert_eq!(terms.query, count(&params, &MASKED_WRAP_REFERENCE));
    let within = |bits: f64, low: f64, high: f64| (low..high).contains(&bits);
    assert!(within(terms.query, 82.69, 82.70), "{terms:?}");
    assert!(within(terms.other.batching, 82.78, 82.79), "{terms:?}");
    assert!(within(terms.other.folds, 82.98, 82.99), "{terms:?}");
    assert!(within(terms.other.ali, 108.37, 108.38), "{terms:?}");
    assert!(within(terms.other.deep, 97.67, 97.68), "{terms:?}");
    assert!(within(terms.other.logup, 111.60, 111.61), "{terms:?}");

    assert_eq!(least_queries(params), Some(23));
    let fewer = count(&masked(5, 23, 26, 3, 6), &MASKED_WRAP_REFERENCE);
    assert!((80.84..80.85).contains(&fewer), "{fewer}");
}

/// At format 28's own parameters (blowup 64, 20 queries), (c) counts 81.74:
/// FRI's dimension and domain both grow fourfold, which costs the DEEP
/// batching term 2 bits, and that term binds. Counting `π(z)` moves nothing,
/// as the DEEP term is 15 bits clear. Format 28 counts the same at its
/// reference and as built.
#[test]
fn variant_c_at_format_28s_parameters_binds_the_batching_term() {
    assert_eq!(
        count(&WRAP.params, &WRAP_BUILT),
        count(&WRAP.params, &WRAP_REFERENCE)
    );
    let at_28 = count(&WRAP.params, &MASKED_WRAP_REFERENCE);
    assert!((81.73..81.74).contains(&at_28), "{at_28}");
    let terms = term_bits(&WRAP.params, &MASKED_WRAP_REFERENCE).unwrap();
    assert_eq!(terms.other.batching, at_28);
    assert!(terms.other.deep > at_28 + 15.0, "{terms:?}");
    let without_doubling = SecurityShape {
        composition_point_doublings: 0,
        ..MASKED_WRAP_REFERENCE
    };
    assert_eq!(count(&WRAP.params, &without_doubling), at_28);
}

/// The least query count that clears 100 / 80 masked, by blowup, fold step,
/// last layer and PoW: format 39's shape (A: blowup 32, PoW 26, 23) and the
/// blowup-64 alternative (B: 19, 146 / 81 at 20 queries). Fold step 2 and a
/// larger last layer save no query; 2 bits of PoW save about one.
#[test]
fn the_least_queries_that_clear_the_floors() {
    let grid: [((u32, u32, u32, u32), usize); 10] = [
        ((4, 3, 6, 26), 28),
        ((5, 3, 6, 20), 25),
        ((5, 3, 6, 24), 24),
        ((5, 3, 6, 26), 23),
        ((5, 3, 6, 28), 22),
        ((5, 2, 6, 26), 23),
        ((5, 3, 8, 26), 23),
        ((6, 3, 6, 26), 19),
        ((6, 3, 6, 28), 19),
        ((6, 2, 6, 26), 19),
    ];
    for ((log_blowup, fold_step, log_last_layer, pow_bits), least) in grid {
        assert_eq!(
            least_queries(masked(log_blowup, 1, pow_bits, fold_step, log_last_layer)),
            Some(least),
            "log blowup {log_blowup}, fold step {fold_step}, last layer \
             2^{log_last_layer}, PoW {pow_bits}"
        );
    }
    let b = masked(6, 20, 26, 3, 6);
    assert_eq!(
        security_bits(&b, &MASKED_WRAP_REFERENCE),
        Some(SecurityBits {
            conjectured: 146,
            proven: 81
        })
    );
    let b_count = count(&b, &MASKED_WRAP_REFERENCE);
    assert!((81.73..81.74).contains(&b_count), "{b_count}");
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

/// Format 39 rests on affine batching (`DIVERGENCE-012`), as 28 does.
/// Batched by powers, the batching term caps it at 76.14 at blowup 32 and
/// 73.64 at blowup 64, however many queries are taken; only blowup 8, with
/// 43 queries, reaches 80. The verifier's check says so.
#[test]
fn the_masked_wrap_needs_affine_batching() {
    let powers = |log_blowup, n_queries| FormatParams {
        batching: DeepBatching::Powers,
        ..masked(log_blowup, n_queries, 26, 3, 6)
    };
    for (log_blowup, low, high) in [(5, 76.13, 76.14), (6, 73.63, 73.64)] {
        for n_queries in [24, 256] {
            let cap = count(&powers(log_blowup, n_queries), &MASKED_WRAP_REFERENCE);
            assert!(
                (low..high).contains(&cap),
                "log blowup {log_blowup}, {n_queries} queries: {cap}"
            );
        }
    }
    let least = |log_blowup| {
        (1..=256).find(|&n_queries| {
            count(&powers(log_blowup, n_queries), &MASKED_WRAP_REFERENCE) >= 80.0
        })
    };
    assert_eq!([6, 5, 4, 3].map(least), [None, None, None, Some(43)]);

    let by_powers = Format {
        params: powers(5, 24),
        ..MASKED_WRAP
    };
    let error = crate::proof::check_format_security(
        &by_powers,
        &by_powers.pcs_config(),
        &MASKED_WRAP_REFERENCE,
    )
    .unwrap_err();
    assert!(
        error.contains("76 proven bits, below format 39's floor of 80"),
        "{error}"
    );
}
