//! The masked wrap's AIR (`format::MASKED_WRAP`, masking variant (c)): its degree audit,
//! the segment chips' under (c), its security shape from the built
//! components against the registry's reference, and where the masking may
//! be named.

use std::path::{Path, PathBuf};

use stwo::core::air::Component;
use stwo::core::channel::Blake2sChannel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::deep_values_of_column;
use stwo_constraint_framework::expr::ExprEvaluator;
use stwo_constraint_framework::{FrameworkEval, InfoEvaluator, Relation};
use vos_pvm_proof::format::{MASKED_WRAP, MASKED_WRAP_REFERENCE, SEGMENT_REFERENCE};
use vos_pvm_proof::framework_access::{
    AllLookupElements, draw_all_lookup_elements, drive_chip_oods,
};
use vos_pvm_proof::security::{SecurityShape, proven_count};
use vos_pvm_recair::masked::MASKED_WRAP_PINS;
use vos_pvm_recair_air::gate::{GATE_WIDTH, GateRelation};
use vos_pvm_recair_air::h8::H8Eval;
use vos_pvm_recair_air::masked::{
    BlindRelation, MaskedComponent, MaskedComponents, MaskedEval, WrapComponents, air_log_size,
    committed_log_sizes, composition_log_degree_bound, composition_point, sample_points,
};
use vos_pvm_recair_air::p2::P2Eval;
use vos_pvm_recair_air::qm31::Qm31Eval;
use vos_pvm_recair_air::{LogSizes, h8, p2, qm31};

use crate::gates::{degrees, preprocessed_of};

/// The wrap's log sizes, `format::WRAP`'s and 39's.
const LOG_SIZES: LogSizes = [14, 15, 11];

/// Each constraint's degree is at most 3, so a constraint over columns
/// masked to `2N` stays under the composition's `4N`:
/// `3(N + h) − N ≤ 4N − 1` for `h ≤ 2N/3`, which the format's `h = 256`
/// meets on every component.
fn audit(name: &str, recorded: &ExprEvaluator, preprocessed: &[&str]) -> Vec<usize> {
    let counted = degrees(recorded, preprocessed);
    assert!(
        counted.iter().all(|&degree| degree <= 3),
        "{name}: {counted:?}"
    );
    counted
}

/// The constraints of each degree, 0 to 3.
fn histogram(degrees: &[usize]) -> [usize; 4] {
    let mut histogram = [0; 4];
    for &degree in degrees {
        histogram[degree] += 1;
    }
    histogram
}

/// The masked components (body, blinding fraction, pairs) are of degree at
/// most 3, at 303, 4 and 8 constraints: the blinding takes `p2`'s lone
/// fraction's pair, and a new pair on `qm31` and `h8`, where it is the pair's
/// second fraction.
#[test]
fn the_masked_degree_audit_passes() {
    fn record<B: vos_pvm_recair_air::Body>(
        inner: B,
        blind: &BlindRelation,
        listed: &[&str],
    ) -> (ExprEvaluator, Vec<String>) {
        let masked = MaskedEval::new(inner, blind);
        let preprocessed = preprocessed_of(&masked.evaluate(InfoEvaluator::empty()));
        assert_eq!(preprocessed, listed);
        (masked.evaluate(ExprEvaluator::new()), preprocessed)
    }
    let relation = GateRelation::dummy();
    let blind = BlindRelation::dummy();
    let recorded = [
        (
            "p2",
            record(
                P2Eval {
                    log_size: 4,
                    relation: relation.clone(),
                },
                &blind,
                &p2::PREPROCESSED,
            ),
        ),
        (
            "qm31",
            record(
                Qm31Eval {
                    log_size: 4,
                    relation: relation.clone(),
                },
                &blind,
                &qm31::PREPROCESSED,
            ),
        ),
        (
            "h8",
            record(
                H8Eval {
                    log_size: 4,
                    relation,
                },
                &blind,
                &h8::PREPROCESSED,
            ),
        ),
    ];
    let counts: Vec<(usize, [usize; 4])> = recorded
        .iter()
        .map(|(name, (recorded, preprocessed))| {
            let preprocessed: Vec<&str> = preprocessed.iter().map(String::as_str).collect();
            let counted = audit(name, recorded, &preprocessed);
            (counted.len(), histogram(&counted))
        })
        .collect();
    assert_eq!(
        counts,
        [
            (303, [0, 0, 143, 160]),
            (4, [0, 1, 0, 3]),
            (8, [0, 1, 1, 6])
        ]
    );
}

/// R5: every constraint of the segment AIR's chips is of degree at most 3,
/// so masking variant (c) takes them as it takes the recursion AIR. Each
/// chip's preprocessed columns, read through an [`InfoEvaluator`], count as
/// columns.
#[test]
fn the_segment_chips_pass_the_degree_audit_under_c() {
    let count = vos_pvm_proof::chip_idx::COUNT;
    assert_eq!(count, 25);
    let mask = ((1u64 << count) - 1) as u32;
    let mut lookups = AllLookupElements::default();
    draw_all_lookup_elements(&mut lookups, &mut Blake2sChannel::default(), mask);
    let mut degrees = Vec::new();
    for chip in 0..count {
        let name = vos_pvm_proof::chip_idx::NAMES[chip];
        let info = drive_chip_oods(chip, 10, &lookups, InfoEvaluator::empty());
        let preprocessed = preprocessed_of(&info);
        let preprocessed: Vec<&str> = preprocessed.iter().map(String::as_str).collect();
        let recorded = drive_chip_oods(chip, 10, &lookups, ExprEvaluator::new());
        let counted = audit(name, &recorded, &preprocessed);
        assert_eq!(counted.len(), info.n_constraints, "{name}");
        degrees.extend(counted);
    }
    assert_eq!(degrees.len(), SEGMENT_REFERENCE.constraints as usize);
    assert_eq!(histogram(&degrees), [0, 23, 4395, 759]);
}

/// The masked wrap's shape, read from the built components' own layout:
/// FRI's `k` the composition's whole bound (`4N`, never split), the masked
/// columns' level, every value the DEEP quotient batches at the
/// transcript's sample points (a column sampled twice batches a third, its
/// periodicity value) and the most of one column, the constraints and
/// fractions the components declare, the widest relation, and the doublings
/// from `z` to the composition's point.
fn masked_wrap_shape() -> SecurityShape {
    let relation = GateRelation::dummy();
    let blind = BlindRelation::dummy();
    let wrap = WrapComponents::build(&relation, &blind, &LOG_SIZES, &[SecureField::default(); 3]);
    let trees = committed_log_sizes(&wrap, &MASKED_WRAP_PINS).unwrap();
    let z = CirclePoint::<SecureField>::get_point(1);
    let points = sample_points(&wrap, z, &MASKED_WRAP_PINS).unwrap();
    let components = wrap.components();
    let columns = points.iter().flatten();

    let composition = composition_log_degree_bound(&wrap).unwrap();
    let doublings = composition - air_log_size(&wrap).unwrap();
    assert_eq!(
        composition_point(&wrap, z),
        Some(z.repeated_double(doublings))
    );
    let masked_level = components
        .iter()
        .flat_map(|&inner| {
            let bounds = MaskedComponent { inner }.trace_log_degree_bounds();
            bounds.0.into_iter().flatten()
        })
        .max()
        .unwrap();
    let fractions: u64 = [
        wrap.p2.logup_counts(),
        wrap.qm31.logup_counts(),
        wrap.h8.logup_counts(),
    ]
    .iter()
    .flat_map(|counts| counts.values())
    .map(|&n| n as u64)
    .sum();
    let widths = [
        <GateRelation as Relation<BaseField, SecureField>>::get_size(&relation),
        <BlindRelation as Relation<BaseField, SecureField>>::get_size(&blind),
    ];
    assert_eq!(widths, [GATE_WIDTH, 1]);
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
        relation_width: widths.into_iter().max().unwrap() as u64,
        composition_point_doublings: doublings,
    }
}

/// The registry's reference for `format::MASKED_WRAP` is the built masked wrap's shape,
/// field for field: 538 batched values, 3 at most a column; it counts
/// 82.69 to 82.70 proven bits.
#[test]
fn the_masked_reference_shape_is_the_built_wraps() {
    let built = masked_wrap_shape();
    assert_eq!(built, MASKED_WRAP_REFERENCE);
    assert_eq!(
        (built.sampled_values, built.max_samples_per_column),
        (538, 3)
    );
    let count = proven_count(&MASKED_WRAP.params, &built).unwrap();
    assert!((82.69..82.70).contains(&count), "{count}");
}

/// The Rust sources under `dir`, every level.
fn sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}

/// The paths among `paths` whose source names any of `needles`.
fn naming(paths: Vec<PathBuf>, needles: &[String]) -> Vec<PathBuf> {
    paths
        .into_iter()
        .filter(|path| {
            let source = std::fs::read_to_string(path).unwrap();
            needles
                .iter()
                .any(|needle| source.contains(needle.as_str()))
        })
        .collect()
}

/// The blinding relation (spelled in pieces, so this file does not name it).
fn blinding() -> String {
    ["Blind", "Relation"].concat()
}

/// The masking is the wrap's alone: no source of the leaves, the folds or
/// the in-circuit verifiers they run names it.
#[test]
fn leaves_and_folds_never_reference_the_masking() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let found: Vec<PathBuf> = ["leaf", "fold", "verifier"]
        .iter()
        .flat_map(|dir| sources(&root.join(dir)))
        .collect();
    assert!(found.len() > 3);
    let needles = [["mask", "ed::"].concat(), blinding()];
    assert_eq!(naming(found, &needles), Vec::<PathBuf>::new());
}

/// The blinding relation is the masked evaluation's alone: no module of the
/// recursion AIR but `masked.rs` names it.
#[test]
fn only_the_masked_module_names_the_blinding_relation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../recair-air/src");
    let found = sources(&root);
    assert!(found.iter().any(|path| path.ends_with("masked.rs")));
    let others: Vec<PathBuf> = found
        .into_iter()
        .filter(|path| !path.ends_with("masked.rs"))
        .collect();
    assert!(others.len() >= 5);
    assert_eq!(naming(others, &[blinding()]), Vec::<PathBuf>::new());
}
