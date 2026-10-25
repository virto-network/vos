//! The masked wrap's AIR (`format::MASKED_WRAP`, masking variant (c)): its
//! degree audit, the segment chips' under (c), its security shape from the
//! built components against the registry's reference, and where the masking
//! may be named.

use std::path::{Path, PathBuf};

use stwo::core::air::Component;
use stwo::core::channel::Blake2sChannel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::deep_values_of_column;
use stwo_constraint_framework::expr::ExprEvaluator;
use stwo_constraint_framework::{FrameworkEval, InfoEvaluator, Relation};
use vos_pvm_final_verifier::masked::PINS;
use vos_pvm_proof::format::{MASKED_WRAP, MASKED_WRAP_REFERENCE, SEGMENT_REFERENCE};
use vos_pvm_proof::framework_access::{
    AllLookupElements, draw_all_lookup_elements, drive_chip_oods,
};
use vos_pvm_proof::masked::{SegmentComponents, drive_masked_chip};
use vos_pvm_proof::security::{SecurityShape, proven_count};
use vos_pvm_recair_air::gate::{GATE_WIDTH, GateRelation};
use vos_pvm_recair_air::h8::H8Eval;
use vos_pvm_recair_air::masked::{
    BlindRelation, MaskedComponent, MaskedComponents, MaskedEval, WrapComponents, air_log_size,
    committed_log_sizes, composition_log_degree_bound, composition_point, sample_points,
};
use vos_pvm_recair_air::p2::P2Eval;
use vos_pvm_recair_air::qm31::Qm31Eval;
use vos_pvm_recair_air::{LogSizes, h8, p2, qm31};

use crate::common::sources;
use crate::gates::{degrees, fraction_degrees, preprocessed_of};

/// The wrap's log sizes, `format::WRAP`'s and `format::MASKED_WRAP`'s.
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

/// R5 on the masked segment: each chip's masked evaluation (its constraints,
/// its blinding fraction joined to its last batch) keeps every constraint of
/// the chip at its degree, so the masked set holds the segment AIR's 5,177
/// constraints, none above 3; and the set built at its layout declares them.
#[test]
fn the_masked_segment_chips_pass_the_degree_audit() {
    let count = vos_pvm_proof::chip_idx::COUNT;
    let mask = vos_pvm_proof::chip_idx::ALL;
    let channel = &mut Blake2sChannel::default();
    let lookups = SegmentComponents::draw_relations(mask, channel);
    let blind = BlindRelation::draw(channel);
    let mut degrees = Vec::new();
    for chip in 0..count {
        let name = vos_pvm_proof::chip_idx::NAMES[chip];
        let info = drive_masked_chip(chip, 10, &lookups, &blind, InfoEvaluator::empty());
        let preprocessed = preprocessed_of(&info);
        let preprocessed: Vec<&str> = preprocessed.iter().map(String::as_str).collect();
        let recorded = drive_masked_chip(chip, 10, &lookups, &blind, ExprEvaluator::new());
        let counted = audit(name, &recorded, &preprocessed);
        assert_eq!(counted.len(), info.n_constraints, "{name}");
        let plain = drive_chip_oods(chip, 10, &lookups, InfoEvaluator::empty());
        assert_eq!(counted.len(), plain.n_constraints, "{name}");
        degrees.extend(counted);
    }
    assert_eq!(degrees.len(), SEGMENT_REFERENCE.constraints as usize);
    assert_eq!(histogram(&degrees), [0, 23, 4395, 759]);
    let built = SegmentComponents::layout(mask, &[10; 25]).unwrap();
    assert_eq!(
        built
            .components()
            .iter()
            .map(|component| component.n_constraints())
            .sum::<usize>(),
        degrees.len()
    );
    assert!(
        built
            .components()
            .iter()
            .all(|component| component.max_constraint_log_degree_bound() == 12)
    );
}

/// The cubic census (the review's option 4), a measurement: which of the
/// masked segment's 759 cubic constraints are logup batches (the pairs'
/// `Δ·d_1·d_2 − (n_1·d_2 + n_2·d_1)`, the blinding's constant denominator
/// adding no degree) and which are gates; and the degree the masked AIR
/// would have with every chip's fractions batched alone (`Logup::Single`,
/// `Δ·d − n`), with the interaction columns that costs. Measured: 723
/// batches and 36 gates (the CPU's 34, the memory ledger's 2); so batching
/// alone leaves the AIR cubic.
#[test]
fn the_masked_segments_cubic_census() {
    let mask = vos_pvm_proof::chip_idx::ALL;
    let channel = &mut Blake2sChannel::default();
    let lookups = SegmentComponents::draw_relations(mask, channel);
    let blind = BlindRelation::draw(channel);
    let (mut gates, mut batches) = ([0usize; 4], [0usize; 4]);
    let (mut single_max, mut paired_columns, mut single_columns) = (0, 0, 0);
    for chip in 0..vos_pvm_proof::chip_idx::COUNT {
        let name = vos_pvm_proof::chip_idx::NAMES[chip];
        let info = drive_masked_chip(chip, 10, &lookups, &blind, InfoEvaluator::empty());
        let preprocessed = preprocessed_of(&info);
        let preprocessed: Vec<&str> = preprocessed.iter().map(String::as_str).collect();
        let recorded = drive_masked_chip(chip, 10, &lookups, &blind, ExprEvaluator::new());
        let counted = audit(name, &recorded, &preprocessed);
        let fractions = fraction_degrees(&recorded, &preprocessed);
        // The chip's batches: its interaction columns a QM31 each, the
        // running sum's among them; the last constraints are theirs.
        let columns = info.mask_offsets[2].len() / 4;
        let (gate, batch) = counted.split_at(counted.len() - columns);
        for &degree in gate {
            gates[degree] += 1;
        }
        for &degree in batch {
            batches[degree] += 1;
        }
        // Alone, a fraction's constraint is `Δ·d − n`; the blinding joins
        // the last, its denominator constant.
        let alone = fractions
            .iter()
            .map(|&(numerator, denominator)| (1 + denominator).max(numerator))
            .max()
            .unwrap_or(0);
        single_max = single_max.max(alone);
        paired_columns += columns;
        single_columns += fractions.len() - 1;
        eprintln!(
            "{name}: {} gates {:?}, {columns} batches {:?}; {} fractions alone at degree {alone}",
            gate.len(),
            histogram(gate),
            histogram(batch),
            fractions.len() - 1
        );
    }
    eprintln!(
        "gates {gates:?}, batches {batches:?}; batched alone: degree {single_max} at most, \
         {single_columns} interaction QM31 columns against {paired_columns}"
    );
    assert_eq!(
        gates.iter().sum::<usize>() + batches.iter().sum::<usize>(),
        SEGMENT_REFERENCE.constraints as usize
    );
    // 723 of the 759 cubic constraints are the pairs' batches; 36 are gates
    // (the CPU's 34, the memory ledger's 2), which batching alone leaves
    // cubic. Alone, every fraction is quadratic, at 1,464 interaction QM31
    // columns against 741.
    assert_eq!(gates, [0, 23, 4377, 36]);
    assert_eq!(batches, [0, 0, 18, 723]);
    assert_eq!(single_max, 2);
    assert_eq!((single_columns, paired_columns), (1464, 741));
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
    let trees = committed_log_sizes(&wrap, &PINS).unwrap();
    let z = CirclePoint::<SecureField>::get_point(1);
    let points = sample_points(&wrap, z, &PINS).unwrap();
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

/// The registry's reference for `format::MASKED_WRAP` is the built masked
/// wrap's shape, field for field: 538 batched values, 3 at most a column;
/// it counts 82.69 to 82.70 proven bits.
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
/// recursion AIR but `masked`'s (`masked/`) names it.
#[test]
fn only_the_masked_module_names_the_blinding_relation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../recair-air/src");
    let masked = root.join("masked");
    let found = sources(&root);
    assert!(found.iter().any(|path| path.ends_with("masked/mod.rs")));
    let others: Vec<PathBuf> = found
        .into_iter()
        .filter(|path| !path.starts_with(&masked))
        .collect();
    assert!(others.len() >= 5);
    assert_eq!(naming(others, &[blinding()]), Vec::<PathBuf>::new());
}
