//! The gate compiler (`recursion-air.md` §3) on every chip of the segment
//! AIR, its four equivalence tests:
//! 1. **constraint ≡ gate:** at random points, each compiled constraint
//!    equals the recording's, over M31 values (`ExtExpr::assign`) and over
//!    QM31 values, as the OODS point gives them;
//! 2. **gate ≡ verifier:** each chip's random linear combination equals the
//!    one Stwo's `PointEvaluator` accumulates from the chip's own
//!    `add_constraints`, at random points and on real proofs, where the
//!    compiled composition equals the proof's;
//! 3. **tamper:** every sample a chip reads moves its combination, and so
//!    the composition check (the samples no constraint reads are pinned);
//! 4. **counts:** each chip's rows are pinned, within 1% of the re-baselined
//!    count (`docs/design/research/slice-5/count-hardened.log`).
//!
//! A mis-compiled gate, a coefficient flipped or a term dropped, fails
//! tests 1 and 2 on every chip. A synthetic component covers what the chips
//! do not: an inverse of a trace expression.

use crate::common::{self, prove_and_verify};

use std::collections::HashMap;
use std::sync::OnceLock;

use num_traits::{One, Zero};
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::channel::Channel;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo_constraint_framework::expr::ExprEvaluator;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkEval, InfoEvaluator, ORIGINAL_TRACE_IDX, PointEvaluator, RelationEntry,
};
use vos_pvm_proof::chip_idx;
use vos_pvm_proof::framework_access::{
    AllLookupElements, RelationChallenges, draw_all_lookup_elements, drive_chip_oods,
};
use vos_pvm_proof::poseidon2::Poseidon2M31Channel;
use vos_pvm_proof::{Proof, reconstruct_oods_for_recursion};
use vos_pvm_recair::compile::{
    self, Compiled, OodsValues, Operand, Recording, Row, compose, compose_values,
};
use vos_pvm_recair::{Context, NoValue, Value, Var};

use common::Rng;

/// Each chip's log size at the window kernel's class 1, as the baseline
/// counted them.
const LOG_SIZES: [u32; chip_idx::COUNT] = [
    15, 14, 16, 18, 9, 8, 4, 17, 4, 4, 4, 16, 8, 16, 8, 8, 6, 8, 8, 8, 15, 15, 15, 15, 16,
];

/// Each chip's fused gate rows in the re-baselined count
/// (`count-hardened.log`, the full shape).
const BASELINE: [usize; chip_idx::COUNT] = [
    2850, 12307, 5341, 202, 4876, 709, 76, 191, 19, 26, 37, 48, 19, 126, 10, 12, 18, 11, 12, 18,
    830, 353, 141, 1199, 12,
];

/// Each chip's compiled rows, pinned: a change of a chip that changes its
/// recursion cost is seen here.
const PINNED: [usize; chip_idx::COUNT] = BASELINE;

/// The full shape's rows: the chips' rows with what they share counted
/// once, then the relations' `α` powers.
const PINNED_SHAPE: (usize, usize) = (29443, 573);

fn lookup(seed: u64) -> AllLookupElements {
    let mut channel = Poseidon2M31Channel::default();
    channel.mix_u64(seed);
    let mut lookup = AllLookupElements::default();
    draw_all_lookup_elements(&mut lookup, &mut channel, chip_idx::ALL);
    lookup
}

/// Every chip recorded, and compiled alone.
struct Chips {
    lookup: AllLookupElements,
    relations: Vec<RelationChallenges>,
    chips: Vec<(Recording, Compiled)>,
}

fn chips() -> &'static Chips {
    static CHIPS: OnceLock<Chips> = OnceLock::new();
    CHIPS.get_or_init(|| {
        let lookup = lookup(1);
        let relations = lookup.relation_challenges();
        let shape = compile::relations_of(&relations);
        let chips = (0..chip_idx::COUNT)
            .map(|chip| {
                let recording = Recording::chip(chip, LOG_SIZES[chip], &lookup);
                let compiled = compile::compile(std::slice::from_ref(&recording), &shape);
                (recording, compiled)
            })
            .collect();
        Chips {
            lookup,
            relations,
            chips,
        }
    })
}

/// A component's values at a point: its samples `[tree][column][offset]`,
/// its preprocessed samples in the order it reads them, its claimed sum.
#[derive(Clone)]
struct Point {
    samples: [Vec<Vec<SecureField>>; 2],
    preprocessed: Vec<SecureField>,
    claimed_sum: SecureField,
}

fn random_point(recording: &Recording, rng: &mut Rng, m31: bool) -> Point {
    let value = |rng: &mut Rng| {
        if m31 {
            SecureField::from(rng.m31())
        } else {
            rng.qm31()
        }
    };
    let samples = [0, 1].map(|tree| {
        recording.offsets[tree]
            .iter()
            .map(|offsets| offsets.iter().map(|_| value(rng)).collect())
            .collect()
    });
    let mut by_id: HashMap<String, SecureField> = HashMap::new();
    let preprocessed = recording
        .preprocessed
        .iter()
        .map(|id| *by_id.entry(id.id.clone()).or_insert_with(|| value(rng)))
        .collect();
    Point {
        samples,
        preprocessed,
        claimed_sum: rng.qm31(),
    }
}

/// The recording's intermediates in the order they were made.
fn intermediates(recording: &Recording) -> Vec<String> {
    let expr = recording.expr();
    let mut names: Vec<&String> = expr
        .intermediates
        .keys()
        .chain(expr.ext_intermediates.keys())
        .collect();
    names.sort_by_key(|name| {
        name.trim_start_matches("intermediate")
            .parse::<usize>()
            .unwrap()
    });
    names.into_iter().cloned().collect()
}

/// Every relation challenge as the recording names it.
fn challenge_names(relations: &[RelationChallenges]) -> HashMap<String, SecureField> {
    let mut names = HashMap::new();
    for relation in relations {
        names.insert(format!("{}_z", relation.name), relation.z);
        for (i, &power) in relation.alpha_powers.iter().enumerate() {
            names.insert(format!("{}_alpha{i}", relation.name), power);
        }
    }
    names
}

/// The recorded constraints over QM31 values: evaluated as
/// `PointEvaluator` evaluates, its `combine_ef` the verifier's.
fn recorded(
    recording: &Recording,
    point: &Point,
    relations: &[RelationChallenges],
) -> Vec<SecureField> {
    type E = PointEvaluator<'static>;
    let expr = recording.expr();
    let mut columns = HashMap::new();
    for tree in 0..2 {
        for (column, offsets) in recording.offsets[tree].iter().enumerate() {
            for (k, &offset) in offsets.iter().enumerate() {
                columns.insert(
                    recording.column_key(tree, column, offset),
                    point.samples[tree][column][k],
                );
            }
        }
    }
    let mut base: HashMap<String, SecureField> = recording
        .preprocessed
        .iter()
        .zip(&point.preprocessed)
        .map(|(id, &value)| (id.id.clone(), value))
        .collect();
    base.insert(
        "column_size".into(),
        BaseField::from(1u32 << recording.log_size).into(),
    );
    let mut ext = challenge_names(relations);
    ext.insert("claimed_sum".into(), point.claimed_sum);
    for name in intermediates(recording) {
        if let Some(e) = expr.intermediates.get(&name) {
            let value = e.eval_expr::<E, _, _>(&columns, &base);
            base.insert(name, value);
        } else {
            let value =
                expr.ext_intermediates[&name].eval_expr::<E, _, _, _>(&columns, &base, &ext);
            ext.insert(name, value);
        }
    }
    expr.constraints
        .iter()
        .map(|c| c.eval_expr::<E, _, _, _>(&columns, &base, &ext))
        .collect()
}

/// The recorded constraints over M31 values, through `ExtExpr::assign`.
fn recorded_m31(
    recording: &Recording,
    point: &Point,
    relations: &[RelationChallenges],
) -> Vec<SecureField> {
    let m31 = |value: SecureField| {
        let [limb, rest @ ..] = value.to_m31_array();
        assert_eq!(rest, [BaseField::zero(); 3], "an M31 point");
        limb
    };
    let expr = recording.expr();
    let mut assignment: stwo_constraint_framework::expr::assignment::ExprVarAssignment =
        Default::default();
    for tree in 0..2 {
        for (column, offsets) in recording.offsets[tree].iter().enumerate() {
            for (k, &offset) in offsets.iter().enumerate() {
                assignment.0.insert(
                    recording.column_key(tree, column, offset),
                    m31(point.samples[tree][column][k]),
                );
            }
        }
    }
    for (id, &value) in recording.preprocessed.iter().zip(&point.preprocessed) {
        assignment.1.insert(id.id.clone(), m31(value));
    }
    assignment.1.insert(
        "column_size".into(),
        BaseField::from(1u32 << recording.log_size),
    );
    assignment.2 = challenge_names(relations);
    assignment.2.insert("claimed_sum".into(), point.claimed_sum);
    for name in intermediates(recording) {
        if let Some(e) = expr.intermediates.get(&name) {
            let value = e.assign(&assignment);
            assignment.1.insert(name, value);
        } else {
            let value = expr.ext_intermediates[&name].assign(&assignment);
            assignment.2.insert(name, value);
        }
    }
    expr.constraints
        .iter()
        .map(|c| c.assign(&assignment))
        .collect()
}

/// The compiled circuit's input values for `points`, one a component.
fn input_values(
    compiled: &Compiled,
    points: &[Point],
    relations: &[RelationChallenges],
) -> Vec<SecureField> {
    let mut preprocessed = vec![SecureField::zero(); compiled.preprocessed.len()];
    for (component, point) in compiled.components.iter().zip(points) {
        for (k, &index) in component.preprocessed.iter().enumerate() {
            preprocessed[index] = point.preprocessed[k];
        }
    }
    compiled.input_values(&OodsValues {
        samples: points
            .iter()
            .map(|point| [&point.samples[0][..], &point.samples[1][..]])
            .collect(),
        preprocessed,
        claimed_sums: points.iter().map(|point| point.claimed_sum).collect(),
        relations,
    })
}

/// The random linear combination under `coeff` that Stwo's
/// `PointEvaluator` accumulates from the component's own constraints, the
/// vanishing polynomial's inverse taken as one.
fn native(
    recording: &Recording,
    point: &Point,
    coeff: SecureField,
    drive: &dyn Fn(PointEvaluator<'_>) -> PointEvaluator<'_>,
) -> SecureField {
    let preprocessed: Vec<Vec<SecureField>> = point
        .preprocessed
        .iter()
        .map(|&value| vec![value])
        .collect();
    let mask = TreeVec::new(vec![
        preprocessed.iter().collect(),
        point.samples[0].iter().collect(),
        point.samples[1].iter().collect(),
    ]);
    let mut accumulator = PointEvaluationAccumulator::new(coeff);
    drive(PointEvaluator::new(
        mask,
        &mut accumulator,
        SecureField::one(),
        recording.log_size,
        point.claimed_sum,
    ));
    accumulator.finalize()
}

fn drive_chip(
    chip: usize,
    lookup: &AllLookupElements,
) -> impl Fn(PointEvaluator<'_>) -> PointEvaluator<'_> + '_ {
    drive_at(chip, LOG_SIZES[chip], lookup)
}

fn drive_at(
    chip: usize,
    log_size: u32,
    lookup: &AllLookupElements,
) -> impl Fn(PointEvaluator<'_>) -> PointEvaluator<'_> + '_ {
    move |eval| drive_chip_oods(chip, log_size, lookup, eval)
}

/// The compiled circuit built in a `Context`, its inputs guessed: each
/// component's constraint values.
fn emitted(compiled: &Compiled, inputs: &[SecureField]) -> Vec<Vec<SecureField>> {
    let mut context = Context::<SecureField>::new();
    let wires: Vec<Var> = inputs.iter().map(|&value| context.guess(value)).collect();
    compiled
        .emit(&mut context, &wires)
        .iter()
        .map(|values| values.iter().map(|&var| context.value(var)).collect())
        .collect()
}

/// The constraint values with input `changed` of `inputs` changed, given
/// the rows' values `honest` before the change: only the rows it reaches
/// are evaluated again.
fn retampered(
    compiled: &Compiled,
    inputs: &[SecureField],
    honest: &[SecureField],
    changed: usize,
) -> Vec<Vec<SecureField>> {
    let mut rows = honest.to_vec();
    let mut dirty = vec![false; rows.len()];
    for (r, row) in compiled.rows.iter().enumerate() {
        let reads = |operand: &Operand| match *operand {
            Operand::Input(i) => i == changed,
            Operand::Row(j) => dirty[j],
            Operand::One | Operand::Constant(_) => false,
        };
        let reached = match row {
            Row::Inverse(a) => reads(a),
            Row::Gate { operands, .. } => operands.iter().flatten().any(reads),
        };
        if reached {
            rows[r] = row.evaluate(inputs, &rows[..r]);
            dirty[r] = true;
        }
    }
    compiled.values(inputs, &rows)
}

#[test]
fn each_constraint_is_its_recordings_on_every_chip() {
    let chips = chips();
    let mut rng = Rng::new(11);
    for (recording, compiled) in &chips.chips {
        for m31 in [true, false] {
            for _ in 0..2 {
                let point = random_point(recording, &mut rng, m31);
                let expected = if m31 {
                    recorded_m31(recording, &point, &chips.relations)
                } else {
                    recorded(recording, &point, &chips.relations)
                };
                let inputs = input_values(compiled, std::slice::from_ref(&point), &chips.relations);
                assert_eq!(
                    compiled.evaluate(&inputs)[0],
                    expected,
                    "{}: compiled ≠ recorded (M31 point: {m31})",
                    recording.name
                );
                assert_eq!(
                    emitted(compiled, &inputs)[0],
                    expected,
                    "{}: emitted ≠ recorded",
                    recording.name
                );
            }
        }
    }
}

#[test]
fn each_chips_combination_is_the_verifiers_at_random_points() {
    let chips = chips();
    let mut rng = Rng::new(12);
    for (chip, (recording, compiled)) in chips.chips.iter().enumerate() {
        for _ in 0..2 {
            let point = random_point(recording, &mut rng, false);
            let coeff = rng.qm31();
            let inputs = input_values(compiled, std::slice::from_ref(&point), &chips.relations);
            let combination = compose_values(None, coeff, &compiled.evaluate(&inputs)[0]);
            assert_eq!(
                combination.unwrap(),
                native(recording, &point, coeff, &drive_chip(chip, &chips.lookup)),
                "{}",
                recording.name
            );
        }
    }
}

/// At random points, every input a chip reads moves its combination: no
/// read column is lost in compiling. Every sample a chip's mask holds is
/// read: the AIR carries no column, and no next-row mask, that no
/// constraint reads, each of which would cost every leaf its samples.
#[test]
fn every_sample_a_chip_reads_moves_its_combination() {
    let chips = chips();
    let mut rng = Rng::new(17);
    let mut never_read = Vec::new();
    for (chip, (recording, compiled)) in chips.chips.iter().enumerate() {
        let point = random_point(recording, &mut rng, false);
        let coeff = rng.qm31();
        let inputs = input_values(compiled, std::slice::from_ref(&point), &chips.relations);
        let rows = compiled.evaluate_rows(&inputs);
        let honest = compose_values(None, coeff, &compiled.values(&inputs, &rows)[0]);
        for (i, input) in compiled.inputs.iter().enumerate() {
            let mut tampered = inputs.clone();
            tampered[i] += SecureField::one();
            let moved = compose_values(None, coeff, &retampered(compiled, &tampered, &rows, i)[0]);
            assert_ne!(
                moved, honest,
                "{}: {input:?} tampered, the combination stands",
                recording.name
            );
        }
        for tree in 0..2 {
            for (column, offsets) in recording.offsets[tree].iter().enumerate() {
                for &offset in offsets {
                    let sample = compile::Input::Sample {
                        chip: 0,
                        tree,
                        column,
                        offset,
                    };
                    if !compiled.inputs.contains(&sample) {
                        assert_eq!(tree, 0, "{}: an interaction column unread", recording.name);
                        never_read.push((chip, column, offset));
                    }
                }
            }
        }
    }
    assert!(
        never_read.is_empty(),
        "samples no constraint reads, (chip, column, offset): {never_read:?}"
    );
}

/// The recursion AIR's three components, a fold's child's AIR
/// (`vos_pvm_recair::fold::child`), at the padded shape's log sizes: tests 1
/// and 2, each compiled constraint its recording's at random points over
/// M31 and QM31 values, emitted and evaluated, and each component's
/// combination the verifier's; and test 3, every input moving it.
#[test]
fn the_recursion_airs_components_compile_to_their_recordings() {
    use vos_pvm_recair_air::{GateRelation, h8, p2, qm31};
    let mut channel = Poseidon2M31Channel::default();
    channel.mix_u64(13);
    let gate = GateRelation::draw(&mut channel);
    let relations = vec![RelationChallenges {
        name: "Gate".into(),
        z: gate.0.z,
        alpha_powers: gate.0.alpha_powers.to_vec(),
    }];
    let shape = compile::relations_of(&relations);
    let [p2_log, qm31_log, h8_log] = vos_pvm_proof::format::LEAF_FOLD_LOG_SIZES;
    let p2 = p2::P2Eval {
        log_size: p2_log,
        relation: gate.clone(),
    };
    let qm31 = qm31::Qm31Eval {
        log_size: qm31_log,
        relation: gate.clone(),
    };
    let h8 = h8::H8Eval {
        log_size: h8_log,
        relation: gate.clone(),
    };
    type Drive<'a> = Box<dyn Fn(PointEvaluator<'_>) -> PointEvaluator<'_> + 'a>;
    let components: [(Recording, Drive<'_>); 3] = [
        (Recording::of("p2", &p2), Box::new(|eval| p2.evaluate(eval))),
        (
            Recording::of("qm31", &qm31),
            Box::new(|eval| qm31.evaluate(eval)),
        ),
        (Recording::of("h8", &h8), Box::new(|eval| h8.evaluate(eval))),
    ];
    let mut rng = Rng::new(19);
    for (recording, drive) in &components {
        let compiled = compile::compile(std::slice::from_ref(recording), &shape);
        for m31 in [true, false] {
            let point = random_point(recording, &mut rng, m31);
            let expected = if m31 {
                recorded_m31(recording, &point, &relations)
            } else {
                recorded(recording, &point, &relations)
            };
            let inputs = input_values(&compiled, std::slice::from_ref(&point), &relations);
            assert_eq!(
                compiled.evaluate(&inputs)[0],
                expected,
                "{}",
                recording.name
            );
            assert_eq!(
                emitted(&compiled, &inputs)[0],
                expected,
                "{}",
                recording.name
            );
        }
        let point = random_point(recording, &mut rng, false);
        let coeff = rng.qm31();
        let inputs = input_values(&compiled, std::slice::from_ref(&point), &relations);
        let rows = compiled.evaluate_rows(&inputs);
        let honest = compose_values(None, coeff, &compiled.values(&inputs, &rows)[0]);
        assert_eq!(
            honest.unwrap(),
            native(recording, &point, coeff, drive),
            "{}: the verifier's combination",
            recording.name
        );
        for (i, input) in compiled.inputs.iter().enumerate() {
            let mut tampered = inputs.clone();
            tampered[i] += SecureField::one();
            let moved = compose_values(None, coeff, &retampered(&compiled, &tampered, &rows, i)[0]);
            assert_ne!(moved, honest, "{}: {input:?} tampered", recording.name);
        }
        eprintln!(
            "{}: {} constraints, {} rows",
            recording.name,
            compiled.components[0].constraints.len(),
            compiled.rows.len()
        );
    }
}

/// Mis-compiled gates, in rows across every chip: a flipped coefficient, a
/// dropped term, `a` and `b` swapped where their coefficients differ, an
/// operand re-pointed to its neighbouring input, and a relation's `z` and
/// `α` swapped throughout. Tests 1 and 2 refuse every one, the first
/// mutation of each kind on a chip through a `Context`.
#[test]
fn a_miscompiled_gate_fails_both_equivalence_tests_on_every_chip() {
    let chips = chips();
    let mut rng = Rng::new(13);
    let mut kinds = [0usize; 5];
    for (chip, (recording, compiled)) in chips.chips.iter().enumerate() {
        let point = random_point(recording, &mut rng, false);
        let coeff = rng.qm31();
        let recorded = recorded(recording, &point, &chips.relations);
        let native = native(recording, &point, coeff, &drive_chip(chip, &chips.lookup));
        let inputs = input_values(compiled, std::slice::from_ref(&point), &chips.relations);
        let refused = |wrong: &Compiled, through_context: bool, what: &str| {
            let values = if through_context {
                emitted(wrong, &inputs).remove(0)
            } else {
                wrong.evaluate(&inputs).remove(0)
            };
            assert_ne!(values, recorded, "{}: {what} passes test 1", recording.name);
            assert_ne!(
                compose_values(None, coeff, &values).unwrap(),
                native,
                "{}: {what} passes test 2",
                recording.name
            );
        };
        // Up to six of the rows `admits`, every one if there are no more.
        let mut picks = |admits: &dyn Fn(&Row) -> bool| -> Vec<usize> {
            let rows: Vec<usize> = (0..compiled.rows.len())
                .filter(|&r| admits(&compiled.rows[r]))
                .collect();
            if rows.len() <= 6 {
                rows
            } else {
                (0..6).map(|_| rows[rng.below(rows.len())]).collect()
            }
        };

        let gates = picks(&|row| matches!(row, Row::Gate { .. }));
        for (pick, &r) in gates.iter().enumerate() {
            for flip in [true, false] {
                let mut wrong = compiled.clone();
                let Row::Gate { op, .. } = &mut wrong.rows[r] else {
                    unreachable!()
                };
                let coefficient = [&mut op.k_m, &mut op.k_a, &mut op.k_b, &mut op.k_c]
                    .into_iter()
                    .find(|k| **k != BaseField::zero())
                    .expect("a row reads a term");
                *coefficient = if flip {
                    -*coefficient
                } else {
                    BaseField::zero()
                };
                refused(&wrong, pick == 0, &format!("row {r} (flip {flip})"));
                kinds[usize::from(!flip)] += 1;
            }
        }

        let swappable = picks(&|row| {
            matches!(row, Row::Gate { op, operands: [Some(a), Some(b), _] }
                if op.k_a != op.k_b && a != b)
        });
        for (pick, &r) in swappable.iter().enumerate() {
            let mut wrong = compiled.clone();
            let Row::Gate { operands, .. } = &mut wrong.rows[r] else {
                unreachable!()
            };
            operands.swap(0, 1);
            refused(&wrong, pick == 0, &format!("row {r} with a and b swapped"));
            kinds[2] += 1;
        }

        let reading = picks(&|row| {
            matches!(row, Row::Gate { operands, .. }
                if operands.iter().any(|o| matches!(o, Some(Operand::Input(_)))))
        });
        for (pick, &r) in reading.iter().enumerate() {
            let mut wrong = compiled.clone();
            let Row::Gate { operands, .. } = &mut wrong.rows[r] else {
                unreachable!()
            };
            let operand = operands
                .iter_mut()
                .find_map(|o| match o {
                    Some(Operand::Input(i)) => Some(i),
                    _ => None,
                })
                .unwrap();
            *operand = if *operand + 1 < compiled.inputs.len() {
                *operand + 1
            } else {
                *operand - 1
            };
            refused(&wrong, pick == 0, &format!("row {r} re-pointed"));
            kinds[3] += 1;
        }

        let index = |input: compile::Input| compiled.inputs.iter().position(|&i| i == input);
        let pair = (0..compiled.relations.len()).find_map(|relation| {
            Some((
                index(compile::Input::Z(relation))?,
                index(compile::Input::Alpha(relation))?,
            ))
        });
        if let Some((z, alpha)) = pair {
            let swap = |operand: &mut Operand| match operand {
                Operand::Input(i) if *i == z => *i = alpha,
                Operand::Input(i) if *i == alpha => *i = z,
                _ => {}
            };
            let mut wrong = compiled.clone();
            for row in &mut wrong.rows {
                match row {
                    Row::Gate { operands, .. } => operands.iter_mut().flatten().for_each(swap),
                    Row::Inverse(operand) => swap(operand),
                }
            }
            refused(&wrong, true, "z and α swapped");
            kinds[4] += 1;
        }
    }
    eprintln!("mutations: flipped, dropped, swapped, re-pointed, z and α: {kinds:?}");
    assert!(kinds.iter().all(|&n| n > 0), "{kinds:?}");
}

#[test]
fn each_chips_rows_are_pinned_within_one_percent_of_the_baseline() {
    let chips = chips();
    let mut report = Vec::new();
    for (chip, (recording, compiled)) in chips.chips.iter().enumerate() {
        let rows = compiled.gate_rows();
        report.push(format!(
            "{}: {rows} rows ({} baseline), {} constraints, {} inputs",
            recording.name,
            BASELINE[chip],
            compiled.components[0].constraints.len(),
            compiled.inputs.len()
        ));
        assert!(
            rows.abs_diff(BASELINE[chip]) * 100 <= BASELINE[chip],
            "{}: {rows} rows against the baseline's {}",
            recording.name,
            BASELINE[chip]
        );
        assert_eq!(rows, PINNED[chip], "{}: the pinned rows", recording.name);
    }
    let recordings: Vec<Recording> = (0..chip_idx::COUNT)
        .map(|chip| Recording::chip(chip, LOG_SIZES[chip], &chips.lookup))
        .collect();
    let shape = compile::compile(&recordings, &compile::relations_of(&chips.relations));
    eprintln!(
        "{}\nthe full shape: {} rows, {} α powers, {} inputs, {} preprocessed columns",
        report.join("\n"),
        shape.gate_rows(),
        shape.power_rows,
        shape.inputs.len(),
        shape.preprocessed.len()
    );
    assert_eq!((shape.gate_rows(), shape.power_rows), PINNED_SHAPE);
    for (chip, compiled) in chips.chips.iter().map(|(_, c)| c).enumerate() {
        assert_eq!(shape.component_rows(chip), compiled.gate_rows());
    }
}

/// The full shape compiled into one circuit at a random point, with the
/// composition and the logup sum: its wiring built without values is the
/// filled one's, and it proves and verifies.
#[test]
fn the_compiled_shape_proves_and_verifies() {
    let chips = chips();
    let recordings: Vec<Recording> = (0..chip_idx::COUNT)
        .map(|chip| Recording::chip(chip, LOG_SIZES[chip], &chips.lookup))
        .collect();
    let compiled = compile::compile(&recordings, &compile::relations_of(&chips.relations));
    let mut rng = Rng::new(14);
    let points: Vec<Point> = recordings
        .iter()
        .map(|recording| random_point(recording, &mut rng, false))
        .collect();
    let inputs = input_values(&compiled, &points, &chips.relations);
    let (coeff, denom_inverse) = (rng.qm31(), rng.qm31());

    fn build<V: Value>(
        compiled: &Compiled,
        inputs: &[V],
        coeff: V,
        denom_inverse: V,
    ) -> (Context<V>, Var, Var) {
        let mut context = Context::<V>::new();
        let wires: Vec<Var> = inputs.iter().map(|&value| context.guess(value)).collect();
        let constraints = compiled.emit(&mut context, &wires);
        let coeff = context.guess(coeff);
        let acc = constraints
            .iter()
            .fold(None, |acc, values| {
                compose(&mut context, acc, coeff, values)
            })
            .unwrap();
        let denom_inverse = context.guess(denom_inverse);
        let composition = context.mul(acc, denom_inverse);
        let sums: Vec<Var> = compiled
            .inputs
            .iter()
            .zip(&wires)
            .filter(|(input, _)| matches!(input, compile::Input::ClaimedSum(_)))
            .map(|(_, &wire)| wire)
            .collect();
        let logup = sums[1..]
            .iter()
            .fold(sums[0], |sum, &wire| context.add(sum, wire));
        (context, composition, logup)
    }
    let (context, composition, logup) = build(&compiled, &inputs, coeff, denom_inverse);
    let values = compiled.evaluate(&inputs);
    assert_eq!(
        context.value(composition),
        Compiled::composition_value(&values, coeff, denom_inverse)
    );
    assert_eq!(
        context.value(logup),
        points
            .iter()
            .map(|point| point.claimed_sum)
            .sum::<SecureField>()
    );
    let rows = context.rows();
    eprintln!("the full shape's circuit: {rows:?} rows (p2, qm31, h8) before finalizing");
    let no_value = vec![NoValue; inputs.len()];
    let (wiring, ..) = build(&compiled, &no_value, NoValue, NoValue);
    let filled = context.finalize().expect("the wiring checks");
    assert_eq!(
        wiring.finalize().expect("the wiring checks").circuit,
        filled.circuit
    );
    prove_and_verify(&filled);
}

/// A segment proof's OODS data, as the in-AIR verifier receives it.
struct Real {
    recordings: Vec<Recording>,
    compiled: Compiled,
    points: Vec<Point>,
    relations: Vec<RelationChallenges>,
    oods: vos_pvm_proof::OodsReconstruction,
}

fn real(proof: &Proof) -> Real {
    let oods = reconstruct_oods_for_recursion(proof);
    let relations = oods.lookup_elements.relation_challenges();
    let recordings: Vec<Recording> = oods
        .comps
        .iter()
        .map(|&(chip, log_size, _)| Recording::chip(chip, log_size, &oods.lookup_elements))
        .collect();
    let compiled = compile::compile(&recordings, &compile::relations_of(&relations));
    let points = oods
        .comps
        .iter()
        .zip(&oods.component_masks)
        .map(|(&(_, _, claimed_sum), mask)| Point {
            samples: [mask.mask[1].clone(), mask.mask[2].clone()],
            preprocessed: mask
                .preproc_indices
                .iter()
                .map(|&index| mask.mask[0][index][0])
                .collect(),
            claimed_sum,
        })
        .collect();
    Real {
        recordings,
        compiled,
        points,
        relations,
        oods,
    }
}

/// Tests 2 and 3 on a real proof: the compiled composition is the proof's,
/// in values and in a `Context`; each chip's combination is the
/// verifier's; the claimed sums add to zero; every sample a chip reads moves
/// its combination, and one sample a chip, tampered, fails the composition
/// check.
fn check_real(proof: &Proof) {
    let real = real(proof);
    let Real {
        recordings,
        compiled,
        points,
        relations,
        oods,
    } = &real;
    let inputs = input_values(compiled, points, relations);
    let values = compiled.evaluate(&inputs);
    let composition = |values: &[Vec<SecureField>]| {
        Compiled::composition_value(values, oods.random_coeff, oods.denom_inverse)
    };
    assert_eq!(composition(&values), oods.composition_value);
    assert_eq!(emitted(compiled, &inputs), values);
    assert_eq!(
        points
            .iter()
            .map(|point| point.claimed_sum)
            .sum::<SecureField>(),
        SecureField::zero()
    );

    for (c, (recording, point)) in recordings.iter().zip(points).enumerate() {
        let (chip, ..) = oods.comps[c];
        let drive = drive_at(chip, recording.log_size, &oods.lookup_elements);
        let alone = compile::compile(
            std::slice::from_ref(recording),
            &compile::relations_of(relations),
        );
        let alone_inputs = input_values(&alone, std::slice::from_ref(point), relations);
        let honest = compose_values(None, oods.random_coeff, &alone.evaluate(&alone_inputs)[0]);
        assert_eq!(
            honest.unwrap(),
            native(recording, point, oods.random_coeff, &drive),
            "{}: compiled ≠ the verifier's on the proof",
            recording.name
        );
        assert_eq!(alone.evaluate(&alone_inputs)[0], values[c]);

        // Every sample, preprocessed sample and the claimed sum, tampered,
        // one at a time: the compiled combination is still the verifier's
        // (checked natively on up to 64 of them), so it moves where the
        // verifier's does. A sample read only under selectors that are zero
        // on the whole trace moves neither.
        let rows = alone.evaluate_rows(&alone_inputs);
        let mut rng = Rng::new(c as u64);
        let n = alone.inputs.len();
        let natively: Vec<usize> = if n <= 64 {
            (0..n).collect()
        } else {
            (0..64).map(|_| rng.below(n)).collect()
        };
        let (mut moved, mut inert) = (0, 0);
        for (i, input) in alone.inputs.iter().enumerate() {
            if matches!(input, compile::Input::Z(_) | compile::Input::Alpha(_)) {
                continue;
            }
            let mut tampered = alone_inputs.clone();
            tampered[i] += SecureField::one();
            let compiled = compose_values(
                None,
                oods.random_coeff,
                &retampered(&alone, &tampered, &rows, i)[0],
            )
            .unwrap();
            if Some(compiled) == honest {
                inert += 1;
            } else {
                moved += 1;
            }
            if !natively.contains(&i) {
                continue;
            }
            let mut tampered_point = point.clone();
            match *input {
                compile::Input::Sample {
                    tree,
                    column,
                    offset,
                    ..
                } => {
                    let k = recording.offsets[tree][column]
                        .iter()
                        .position(|&o| o == offset)
                        .unwrap();
                    tampered_point.samples[tree][column][k] += SecureField::one();
                }
                compile::Input::Preprocessed(index) => {
                    for (k, &read) in alone.components[0].preprocessed.iter().enumerate() {
                        if read == index {
                            tampered_point.preprocessed[k] += SecureField::one();
                        }
                    }
                }
                compile::Input::ClaimedSum(_) => tampered_point.claimed_sum += SecureField::one(),
                compile::Input::Z(_) | compile::Input::Alpha(_) => unreachable!(),
            }
            assert_eq!(
                compiled,
                native(recording, &tampered_point, oods.random_coeff, &drive),
                "{}: {input:?} tampered, compiled ≠ the verifier's",
                recording.name
            );
        }
        eprintln!(
            "{}: of its {} sampled inputs tampered, {moved} move the combination, {inert} \
             are read only under selectors zero on this trace",
            recording.name,
            moved + inert
        );

        // The chip's last interaction sample, its logup's running sum,
        // tampered in the shape's circuit.
        let sample = compiled
            .inputs
            .iter()
            .rposition(
                |input| matches!(input, compile::Input::Sample { chip, tree: 1, .. } if *chip == c),
            )
            .expect("the chip's logup reads its running sum");
        let mut tampered = inputs.clone();
        tampered[sample] += SecureField::one();
        assert_ne!(
            composition(&emitted(compiled, &tampered)),
            oods.composition_value,
            "{}: a tampered sample passes the composition check",
            recording.name
        );
    }
}

#[test]
fn the_fixtures_composition_is_compiled() {
    check_real(&common::segment_fixture());
}

/// A run proved over all 25 chips, the ones it does not use padded.
#[test]
fn a_full_shape_proofs_composition_is_compiled() {
    check_real(common::full_shape_proof());
}

// ── A synthetic component: what the chips do not exercise ──────────────────

stwo_constraint_framework::relation!(Synthetic, 3);

/// One relation of three limbs, a next-row mask, a preprocessed column, an
/// intermediate, an inverse of a trace expression, and three fractions
/// finalized in pairs or one a column. Stwo's `InfoEvaluator` cannot invert
/// (its counter's `inverse` is unimplemented), so what the component reads
/// is taken from its twin without the inverse: the same reads.
struct SyntheticEval {
    relation: Synthetic,
    paired: bool,
    inverse: bool,
}

impl FrameworkEval for SyntheticEval {
    fn log_size(&self) -> u32 {
        5
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        7
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let selector = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "synthetic_selector".into(),
        });
        let [x, x_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
        let y = eval.next_trace_mask();
        let z = eval.next_trace_mask();
        let w = eval.add_intermediate(x.clone() * y.clone() + selector.clone());
        let shifted = y.clone() + E::F::from(BaseField::from(7));
        let shifted = if self.inverse {
            shifted.inverse()
        } else {
            shifted
        };
        eval.add_constraint(z.clone() * shifted - x_next.clone());
        eval.add_constraint(E::EF::from(w.clone() - x.clone()) * E::EF::from(selector.clone()));
        eval.add_to_relation(RelationEntry::new(
            &self.relation,
            E::EF::one(),
            &[x.clone(), y.clone()],
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.relation,
            -E::EF::from(selector),
            &[z.clone(), w, x_next],
        ));
        eval.add_to_relation(RelationEntry::new(&self.relation, E::EF::one(), &[y]));
        if self.paired {
            eval.finalize_logup_in_pairs();
        } else {
            eval.finalize_logup();
        }
        eval
    }
}

#[test]
fn a_synthetic_component_compiles_paired_or_not() {
    let mut channel = Poseidon2M31Channel::default();
    channel.mix_u64(15);
    let relation = Synthetic::draw(&mut channel);
    let challenges = vec![RelationChallenges::of(&relation)];
    let mut rng = Rng::new(16);
    for paired in [true, false] {
        let component = SyntheticEval {
            relation: relation.clone(),
            paired,
            inverse: true,
        };
        let twin = SyntheticEval {
            relation: relation.clone(),
            paired,
            inverse: false,
        };
        let recording = Recording::new(
            "synthetic",
            component.log_size(),
            twin.evaluate(InfoEvaluator::empty()),
            component.evaluate(ExprEvaluator::new()),
        );
        assert!(
            recording.offsets[0][0] == [0, 1],
            "a next-row mask on the first column"
        );
        let compiled = compile::compile(
            std::slice::from_ref(&recording),
            &compile::relations_of(&challenges),
        );
        assert!(
            compiled
                .rows
                .iter()
                .any(|row| matches!(row, Row::Inverse(_))),
            "the inverse of a trace expression is a row"
        );
        assert_eq!(compiled.power_rows, 1, "α² from α");
        for m31 in [true, false] {
            let point = random_point(&recording, &mut rng, m31);
            let coeff = rng.qm31();
            let inputs = input_values(&compiled, std::slice::from_ref(&point), &challenges);
            let expected = if m31 {
                recorded_m31(&recording, &point, &challenges)
            } else {
                recorded(&recording, &point, &challenges)
            };
            assert_eq!(compiled.evaluate(&inputs)[0], expected);
            assert_eq!(emitted(&compiled, &inputs)[0], expected);
            assert_eq!(
                compose_values(None, coeff, &expected).unwrap(),
                native(&recording, &point, coeff, &|eval| component.evaluate(eval))
            );
        }
        let constant = compiled.components[0]
            .constraints
            .iter()
            .any(|operand| matches!(operand, Operand::Constant(_)));
        assert!(!constant, "no constraint folds to a constant");
    }
}
