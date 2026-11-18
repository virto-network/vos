//! `SECURITY.md`'s format table, rendered from the registry and the
//! reference shapes: a figure changes there only when the code that counts
//! it changes.

use alloc::format;
use alloc::string::String;

use super::*;
use crate::security::{fold_term_bits, summed_bits_at, summed_count, term_bits};

const SECURITY: &str = include_str!("../../SECURITY.md");
const BEGIN: &str = "<!-- the format table: rendered by `src/format/table_tests.rs` -->\n";
const END: &str = "<!-- end of the format table -->\n";

/// `bits` to two decimals, rounded down: a figure never states more than
/// the count.
fn two(bits: f64) -> String {
    format!("{:.2}", (bits * 100.0).floor() / 100.0)
}

fn reference_name(shape: &SecurityShape) -> &'static str {
    [
        (SEGMENT_REFERENCE, "`SEGMENT_REFERENCE`"),
        (LEAF_FOLD_REFERENCE, "`LEAF_FOLD_REFERENCE`"),
        (MASKED_WRAP_REFERENCE, "`MASKED_WRAP_REFERENCE`"),
        (DEVICE_REFERENCE, "`DEVICE_REFERENCE`"),
    ]
    .into_iter()
    .find(|(reference, _)| reference == shape)
    .map(|(_, name)| name)
    .expect("every count's shape is a reference shape")
}

fn render() -> String {
    let mut table = String::from(
        "| format | each figure bounds | log blowup, queries, PoW, fold step, last layer, \
         interaction PoW, DEEP batching | reference shape | conjectured | proven, least term \
         (counted) | proven, summed terms: at their best m; at the least term's m | floors | \
         status |\n\
         |---|---|---|---|---|---|---|---|---|\n",
    );
    for format in REGISTRY {
        let counted = count(&format).expect("a count for every registered format");
        let params = format.params;
        let shape = counted.reference;
        let terms = term_bits(&params, &shape).expect("a reference shape inside the analysis");
        let (summed_m, summed) = summed_count(&params, &shape).expect("inside the analysis");
        let at_least_m = summed_bits_at(&params, &shape, terms.m).unwrap();
        let scope = match format.kind {
            ProofKind::Segment => "one segment proof",
            ProofKind::LeafFold => "one leaf or fold proof",
            ProofKind::Wrap => "one wrap",
            ProofKind::Device => "one device proof",
        };
        let batching = match params.batching {
            DeepBatching::Powers => "powers",
            DeepBatching::Affine => "affine",
        };
        let status = match format.status {
            Status::Admitted => "admitted",
            Status::Internal => "internal",
        };
        table += &format!(
            "| {} | {scope} | {}, {}, {}, {}, {}, {}, {batching} | {} | {} | {} (m = {}) | {} \
             (m = {summed_m}); {} | {} / {} | {status} |\n",
            format.number,
            params.log_blowup,
            params.n_queries,
            params.pow_bits,
            params.fold_step,
            params.log_last_layer,
            params.interaction_pow_bits,
            reference_name(&shape),
            counted.bits.conjectured,
            two(crate::security::proven_count(&params, &shape).unwrap()),
            terms.m,
            two(summed),
            two(at_least_m),
            format.floor.conjectured,
            format.floor.proven,
        );
        assert!(at_least_m <= summed, "format {}", format.number);
        assert!(
            at_least_m >= f64::from(format.floor.proven),
            "format {}: the summed terms under the proven floor",
            format.number
        );
    }
    table
}

/// The table between `SECURITY.md`'s markers is the one the registry and
/// the reference shapes give. On a mismatch the rendered table is printed:
/// paste it between the markers.
#[test]
fn the_security_notes_hold_the_rendered_format_table() {
    let rendered = render();
    let held = SECURITY
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(table, _)| table)
        .expect("SECURITY.md holds the format table's markers");
    assert!(
        held == rendered,
        "SECURITY.md's format table is not the rendered one; the rendered table:\n{rendered}"
    );
}

/// The summed rule's fold terms are the ones the least term takes the
/// worst of, and the summed count is below the least term: a sum of errors
/// is at least its largest.
#[test]
fn the_summed_rule_takes_the_counted_terms() {
    for format in REGISTRY {
        let shape = count(&format).unwrap().reference;
        let terms = term_bits(&format.params, &shape).unwrap();
        let folds = fold_term_bits(&format.params, &shape, terms.m).unwrap();
        let worst = folds.iter().copied().fold(f64::INFINITY, f64::min);
        assert_eq!(worst, terms.other.folds, "format {}", format.number);
        let summed = summed_bits_at(&format.params, &shape, terms.m).unwrap();
        assert!(
            summed < terms.query.min(terms.other.folds),
            "format {}",
            format.number
        );
    }
}
