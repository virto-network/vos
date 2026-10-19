//! The masked wrap's AIR (format 39, masking variant (c)): its degree audit,
//! the segment chips' under (c), and its security shape from the built
//! components against the registry's reference.

use stwo::core::air::Component;
use stwo::core::channel::Blake2sChannel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::quotients::deep_values_of_column;
use stwo_constraint_framework::expr::ExprEvaluator;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{FrameworkEval, InfoEvaluator, Relation};
use vos_pvm_proof::format::{MASKED_WRAP, MASKED_WRAP_REFERENCE, SEGMENT_REFERENCE};
use vos_pvm_proof::framework_access::{
    AllLookupElements, draw_all_lookup_elements, drive_chip_oods,
};
use vos_pvm_proof::security::{SecurityShape, proven_count};
use vos_pvm_recair_air::gate::{GATE_WIDTH, GateRelation};
use vos_pvm_recair_air::h8::H8Eval;
use vos_pvm_recair_air::masked::{
    BlindRelation, MASKED_WRAP_PINS, MaskedComponent, MaskedComponents, MaskedEval, WrapComponents,
    air_log_size, committed_log_sizes, composition_log_degree_bound, composition_point,
    sample_points,
};
use vos_pvm_recair_air::p2::P2Eval;
use vos_pvm_recair_air::qm31::Qm31Eval;
use vos_pvm_recair_air::{LogSizes, h8, p2, qm31};

use crate::gates::degrees;

/// The wrap's log sizes, format 28's and 39's.
const LOG_SIZES: LogSizes = [14, 15, 11];

/// Each constraint's degree is at most 3, so a constraint over columns
/// masked to `2N` stays under the composition's `4N`:
/// `3(N + h) − N ≤ 4N − 1` for `h ≤ 2N/3`, which pin A's `h = 256` meets on
/// every component.
fn audit(name: &str, recorded: &ExprEvaluator, preprocessed: &[&str]) -> Vec<usize> {
    let counted = degrees(recorded, preprocessed);
    assert!(
        counted.iter().all(|&degree| degree <= 3),
        "{name}: {counted:?}"
    );
    counted
}

/// The masked components (body, blinding fraction, pairs) are of degree at
/// most 3, at 303, 4 and 8 constraints: the blinding takes `p2`'s lone
/// fraction's pair, and a new pair on `qm31` and `h8`, where it is the pair's
/// second fraction.
#[test]
fn the_masked_degree_audit_passes() {
    let relation = GateRelation::dummy();
    let blind = BlindRelation::dummy();
    let recorded = [
        (
            "p2",
            MaskedEval::new(
                P2Eval {
                    log_size: 4,
                    relation: relation.clone(),
                },
                &blind,
            )
            .evaluate(ExprEvaluator::new()),
            &p2::PREPROCESSED[..],
        ),
        (
            "qm31",
            MaskedEval::new(
                Qm31Eval {
                    log_size: 4,
                    relation: relation.clone(),
                },
                &blind,
            )
            .evaluate(ExprEvaluator::new()),
            &qm31::PREPROCESSED[..],
        ),
        (
            "h8",
            MaskedEval::new(
                H8Eval {
                    log_size: 4,
                    relation,
                },
                &blind,
            )
            .evaluate(ExprEvaluator::new()),
            &h8::PREPROCESSED[..],
        ),
    ];
    let counts: Vec<(usize, Vec<usize>)> = recorded
        .iter()
        .map(|(name, recorded, preprocessed)| {
            let counted = audit(name, recorded, preprocessed);
            let histogram = (0..=3)
                .map(|d| counted.iter().filter(|&&c| c == d).count())
                .collect();
            (counted.len(), histogram)
        })
        .collect();
    assert_eq!(
        counts,
        [
            (303, vec![0, 0, 143, 160]),
            (4, vec![0, 1, 0, 3]),
            (8, vec![0, 1, 1, 6]),
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
    let mut histogram = [0usize; 4];
    for chip in 0..count {
        let name = vos_pvm_proof::chip_idx::NAMES[chip];
        let info = drive_chip_oods(chip, 10, &lookups, InfoEvaluator::empty());
        let preprocessed: Vec<String> = info
            .preprocessed_columns
            .iter()
            .map(|PreProcessedColumnId { id }| id.clone())
            .collect();
        let preprocessed: Vec<&str> = preprocessed.iter().map(String::as_str).collect();
        let recorded = drive_chip_oods(chip, 10, &lookups, ExprEvaluator::new());
        let counted = audit(name, &recorded, &preprocessed);
        assert_eq!(counted.len(), info.n_constraints, "{name}");
        for degree in counted {
            histogram[degree] += 1;
        }
    }
    eprintln!("the segment chips' constraints by degree: {histogram:?}");
    assert_eq!(
        histogram.iter().sum::<usize>(),
        SEGMENT_REFERENCE.constraints as usize
    );
}

/// The masked wrap's shape, read from the built components' own layout:
/// FRI's `k` the composition's whole bound (`4N`, never split), the masked
/// columns' level, every value the DEEP quotient batches at pin B's sample
/// points (a column sampled twice batches a third, its periodicity value),
/// the constraints and fractions the components declare, the widest
/// relation, and the doublings from `z` to the composition's point.
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
        max_samples_per_column: columns.map(Vec::len).max().unwrap() as u64,
        constraints: components.iter().map(|c| c.n_constraints() as u64).sum(),
        logup_fractions: fractions,
        relation_width: widths.into_iter().max().unwrap() as u64,
        composition_point_doublings: doublings,
    }
}

/// The registry's reference for format 39 is the built masked wrap's shape
/// in every field but the sampled values, which it bounds from above (it
/// counts every column at two samples, the composition's and `R`'s among
/// them, where pin B samples those once); and the built shape counts what
/// the reference does, 82.69 to 82.70 proven bits.
#[test]
fn the_masked_reference_shape_is_the_built_wraps() {
    let built = masked_wrap_shape();
    assert_eq!(
        SecurityShape {
            sampled_values: MASKED_WRAP_REFERENCE.sampled_values,
            ..built
        },
        MASKED_WRAP_REFERENCE
    );
    assert!(built.sampled_values <= MASKED_WRAP_REFERENCE.sampled_values);
    assert_eq!(
        (built.sampled_values, MASKED_WRAP_REFERENCE.sampled_values),
        (538, 964)
    );
    let count = proven_count(&MASKED_WRAP.params, &built).unwrap();
    assert!((82.69..82.70).contains(&count), "{count}");
    assert_eq!(
        count,
        proven_count(&MASKED_WRAP.params, &MASKED_WRAP_REFERENCE).unwrap()
    );
}

/// The masking is the wrap's alone: no source of the leaves, the folds or
/// the in-circuit verifiers they run names it.
#[test]
fn leaves_and_folds_never_reference_the_masking() {
    fn sources(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for dir in ["leaf", "fold", "verifier"] {
        sources(&root.join(dir), &mut found);
    }
    assert!(found.len() > 3);
    let needles = [["mask", "ed::"].concat(), ["Blind", "Relation"].concat()];
    for path in found {
        let source = std::fs::read_to_string(&path).unwrap();
        for needle in &needles {
            assert!(!source.contains(needle.as_str()), "{}", path.display());
        }
    }
}
