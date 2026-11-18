//! A degenerate DEEP sample point (`deep::prepare`): a point `z` whose `y`
//! lies in CM31 has no line through `z` and its conjugate, so Stwo's
//! verifier refuses it, and the quotient there is a constant that ties no
//! sample at `z` to a committed column. The circuit constrains `c_z =
//! z̄.y − z.y` to have an inverse at every point of the plan: the OODS
//! point, each mask offset's and each periodicity point.
//!
//! The forger chooses the OODS point so that one point of the plan at a
//! time lands on a degenerate `z`, over the plans of the window kernel's
//! leaf (format 41) and of the fold's and the wrap's child (format 32):
//! - **the algebra:** at such a point, the quotient a query computes does
//!   not move with a value sampled at that point alone, which it does at an
//!   honest point; that is what the constraint closes;
//! - **refused:** a lenient context names the `deep once` piece, the
//!   inverse's row alone, at every point of each plan, and none at an
//!   honest OODS point;
//! - **proved:** the malicious prover proves the leaf plan's witness at a
//!   degenerate point, as built (its relation does not balance) and
//!   balanced (the inverse's row breaks its constraint); the same circuit
//!   at an honest point verifies;
//! - **the native verifier's:** over random OODS points, coefficients,
//!   sampled and queried values, the plan's quotient is Stwo's
//!   `fri_answers` at the pin, value for value, and at every degenerate
//!   point Stwo refuses (`InvalidStructure`) exactly where the circuit does.

use std::sync::OnceLock;

use num_traits::{One, Zero};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo::core::pcs::quotients::{DeepCoefficients, PointSample, fri_answers};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::core::verifier::VerificationError;
use vos_pvm_proof::format::SEGMENT;
use vos_pvm_proof::poseidon2::P2Hash;
use vos_pvm_recair::fold::child::ChildShape;
use vos_pvm_recair::verifier::circle::Point;
use vos_pvm_recair::verifier::deep::{self, DeepPlan, Item};
use vos_pvm_recair::verifier::witness::pack;
use vos_pvm_recair::verifier::{SegmentShape, StarkShape};
use vos_pvm_recair::{Context, Finalized};

use crate::common::{Rng, WINDOW_LOG_SIZES, WINDOW_MASK};
use crate::forge::{DEEP_ALI, Forgery, LOGUP, assert_accepted, assert_refused, hash_of};

/// The plans, by name: the window kernel's leaf and the fold's and the
/// wrap's child.
fn plans() -> Vec<(&'static str, DeepPlan, Vec<usize>)> {
    starks()
        .into_iter()
        .map(|(name, stark)| {
            let wires = stark
                .leaf_order
                .iter()
                .map(|order| order.len().div_ceil(4))
                .collect();
            (name, stark.deep.clone(), wires)
        })
        .collect()
}

/// The shapes the plans are of.
fn starks() -> Vec<(&'static str, &'static StarkShape)> {
    static LEAF: OnceLock<SegmentShape> = OnceLock::new();
    let leaf = LEAF.get_or_init(|| {
        SegmentShape::new(&SEGMENT, WINDOW_MASK, &WINDOW_LOG_SIZES, P2Hash::default())
    });
    vec![
        ("the leaf", &leaf.stark),
        (
            "the fold's and the wrap's child",
            &ChildShape::padded().stark,
        ),
    ]
}

/// `p + q` on the circle's group law, over QM31.
fn add(p: CirclePoint<SecureField>, q: CirclePoint<BaseField>) -> CirclePoint<SecureField> {
    let (qx, qy) = (SecureField::from(q.x), SecureField::from(q.y));
    CirclePoint {
        x: p.x * qx - p.y * qy,
        y: p.x * qy + p.y * qx,
    }
}

/// The OODS point that puts plan point `k` at a `z` whose `y` lies in
/// CM31 and whose `x` does not.
fn degenerate_at(plan: &DeepPlan, k: usize, rng: &mut Rng) -> CirclePoint<SecureField> {
    let cm31 = |rng: &mut Rng| {
        SecureField::from_m31_array([rng.m31(), rng.m31(), BaseField::zero(), BaseField::zero()])
    };
    let z = CirclePoint {
        x: rng.qm31(),
        y: cm31(rng),
    };
    let offset = plan.points[k].offset;
    let oods = add(
        z,
        CirclePoint {
            x: offset.x,
            y: -offset.y,
        },
    );
    let shifted = add(oods, offset);
    assert_eq!(shifted.y.to_m31_array()[2..], [BaseField::zero(); 2]);
    oods
}

/// The plan's points at a `z` whose `y` lies in CM31 when the OODS point
/// is `oods`: two points the circle's point of order two apart (a
/// column's period at half the lifting height) are degenerate together.
fn degenerate_points(plan: &DeepPlan, oods: CirclePoint<SecureField>) -> Vec<usize> {
    (0..plan.points.len())
        .filter(|&j| {
            add(oods, plan.points[j].offset).y.to_m31_array()[2..] == [BaseField::zero(); 2]
        })
        .collect()
}

/// What the forger states: the OODS point, `α`, the sampled values and one
/// query's point and leaves.
struct Witness {
    oods: CirclePoint<SecureField>,
    alpha: SecureField,
    sampled: Vec<SecureField>,
    q: CirclePoint<SecureField>,
    leaves: [Vec<SecureField>; 4],
}

impl Witness {
    fn random(plan: &DeepPlan, wires: &[usize], rng: &mut Rng) -> Self {
        let n_sampled = plan
            .points
            .iter()
            .flat_map(|point| &point.samples)
            .map(|&(_, index)| index + 1)
            .max()
            .expect("a sample");
        Self {
            oods: CirclePoint {
                x: rng.qm31(),
                y: rng.qm31(),
            },
            alpha: rng.qm31(),
            sampled: (0..n_sampled).map(|_| rng.qm31()).collect(),
            q: CirclePoint {
                x: SecureField::from(rng.m31()),
                y: SecureField::from(rng.m31()),
            },
            leaves: core::array::from_fn(|tree| {
                (0..wires.get(tree).copied().unwrap_or(0))
                    .map(|_| rng.qm31())
                    .collect()
            }),
        }
    }
}

/// DEEP's constants over `witness`, and one query's quotient, built
/// leniently: the quotient's value, the context, the pieces of its
/// mismatches.
fn build(
    plan: &DeepPlan,
    witness: &Witness,
) -> (SecureField, Context<SecureField>, Vec<&'static str>) {
    let mut context = Context::<SecureField>::with_outputs(2).lenient();
    context.piece("deep once");
    let oods = Point {
        x: context.guess(witness.oods.x),
        y: context.guess(witness.oods.y),
    };
    let alpha = context.guess(witness.alpha);
    let sampled: Vec<_> = witness
        .sampled
        .iter()
        .map(|&value| context.guess(value))
        .collect();
    let constants = deep::prepare(&mut context, plan, oods, alpha, &sampled);
    context.piece("deep");
    let q = Point {
        x: context.guess(witness.q.x),
        y: context.guess(witness.q.y),
    };
    let leaves: Vec<Vec<_>> = witness
        .leaves
        .iter()
        .map(|tree| tree.iter().map(|&value| context.guess(value)).collect())
        .collect();
    let answer = deep::answer(
        &mut context,
        plan,
        &constants,
        q,
        core::array::from_fn(|tree| leaves[tree].as_slice()),
    );
    context.set_outputs(&[answer, oods.y]);
    let pieces = context
        .mismatches()
        .iter()
        .map(|mismatch| mismatch.piece)
        .collect();
    (context.value(answer), context, pieces)
}

/// A leaf lane sampled at point `k` alone: one of its single items whose
/// lane no other point reads, as a single or in a block.
fn lane_of_point_alone(plan: &DeepPlan, k: usize) -> Option<(usize, usize)> {
    let reads = |point: &deep::DeepPoint, tree: usize, lane: usize| {
        point.items.iter().any(|item| match *item {
            Item::Single {
                tree: t, lane: l, ..
            } => (t, l) == (tree, lane),
            Item::Block { tree: t, block, .. } => t == tree && lane / 8 == block,
        })
    };
    plan.points[k].items.iter().find_map(|item| match *item {
        Item::Single { tree, lane, .. }
            if plan
                .points
                .iter()
                .enumerate()
                .all(|(j, point)| j == k || !reads(point, tree, lane)) =>
        {
            Some((tree, lane))
        }
        _ => None,
    })
}

/// At a degenerate point the quotient does not move with a value sampled
/// there alone; at an honest point it does.
#[test]
fn a_degenerate_point_frees_its_samples() {
    let mut rng = Rng::new(71);
    let mut shown = 0;
    for (name, plan, wires) in plans() {
        for k in 0..plan.points.len() {
            let Some((tree, lane)) = lane_of_point_alone(&plan, k) else {
                continue;
            };
            let mut witness = Witness::random(&plan, &wires, &mut rng);
            let moved = |witness: &Witness| {
                let (before, _, _) = build(&plan, witness);
                let mut other = Witness {
                    leaves: witness.leaves.clone(),
                    sampled: witness.sampled.clone(),
                    ..*witness
                };
                let wire = &mut other.leaves[tree][lane / 4];
                let mut limbs = wire.to_m31_array();
                limbs[lane % 4] += BaseField::one();
                *wire = SecureField::from_m31_array(limbs);
                let (after, _, _) = build(&plan, &other);
                before != after
            };
            assert!(moved(&witness), "{name}, point {k}: an honest point");
            witness.oods = degenerate_at(&plan, k, &mut rng);
            assert!(!moved(&witness), "{name}, point {k}: a degenerate point");
            shown += 1;
        }
    }
    assert!(shown > 0, "a point with a lane of its own");
}

/// Every point of each plan, put on a degenerate `z`, is refused by the
/// inverse's row alone; an honest OODS point by nothing.
#[test]
fn a_degenerate_point_is_refused_at_every_point_of_the_plan() {
    let mut rng = Rng::new(72);
    for (name, plan, wires) in plans() {
        assert!(
            plan.points.len() >= 3,
            "{name}: the OODS, mask and periodicity points"
        );
        assert!(
            plan.points
                .iter()
                .any(|point| point.offset == CirclePoint::zero()),
            "{name}: the OODS point itself"
        );
        let mut witness = Witness::random(&plan, &wires, &mut rng);
        let (_, _, pieces) = build(&plan, &witness);
        assert!(pieces.is_empty(), "{name}: an honest point: {pieces:?}");
        for k in 0..plan.points.len() {
            witness.oods = degenerate_at(&plan, k, &mut rng);
            let (_, context, pieces) = build(&plan, &witness);
            let degenerate = degenerate_points(&plan, witness.oods);
            assert!(degenerate.contains(&k), "{name}, point {k}");
            assert!(
                pieces.iter().all(|&piece| piece == "deep once"),
                "{name}, point {k}: {pieces:?}"
            );
            assert_eq!(
                context.mismatches().len(),
                degenerate.len(),
                "{name}, point {k}: one refusal a degenerate point {degenerate:?}"
            );
        }
    }
}

fn finalized(context: Context<SecureField>) -> Finalized<SecureField> {
    context.finalize().expect("the wiring checks")
}

/// The leaf plan's quotient at a degenerate point, proved: refused as built
/// and balanced; at an honest point, accepted.
#[test]
fn a_degenerate_point_proved_is_refused() {
    let mut rng = Rng::new(73);
    let (_, plan, wires) = plans().swap_remove(0);
    let mut witness = Witness::random(&plan, &wires, &mut rng);
    let honest = finalized(build(&plan, &witness).1);
    let hash = hash_of(&honest.circuit);
    assert_accepted(Forgery::honest(&honest).prove(), &hash, "an honest point");

    witness.oods = degenerate_at(&plan, 0, &mut rng);
    let forged = finalized(build(&plan, &witness).1);
    assert_eq!(hash_of(&forged.circuit), hash, "the same circuit");
    assert_refused(
        Forgery::honest(&forged).prove(),
        &hash,
        LOGUP,
        "a degenerate point",
    );
    let mut balanced = Forgery::honest(&forged);
    balanced.balance();
    assert_refused(
        balanced.prove(),
        &hash,
        DEEP_ALI,
        "a degenerate point, balanced",
    );
}

/// Stwo's quotient at the pin over `witness`'s OODS point, coefficient and
/// sampled values, at the query `position` with `columns`' values; and
/// `witness` set to the same query's point and leaves.
fn native(
    stark: &StarkShape,
    witness: &mut Witness,
    position: usize,
    columns: &[Vec<BaseField>],
) -> Result<SecureField, VerificationError> {
    let layout = &stark.layout;
    let lifting = layout.lifting_log_size;
    let mut sampled = witness.sampled.iter();
    let samples = TreeVec(
        layout
            .sample_offsets
            .iter()
            .map(|tree| {
                tree.iter()
                    .map(|column| {
                        column
                            .iter()
                            .map(|&offset| PointSample {
                                point: add(witness.oods, offset),
                                value: *sampled.next().expect("a sampled value"),
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect(),
    );
    let domain_point = CanonicCoset::new(lifting)
        .circle_domain()
        .at(bit_reverse_index(position, lifting));
    witness.q = CirclePoint {
        x: SecureField::from(domain_point.x),
        y: SecureField::from(domain_point.y),
    };
    witness.leaves = core::array::from_fn(|tree| {
        let row: Vec<BaseField> = stark
            .leaf_order
            .get(tree)
            .map(|order| order.iter().map(|&column| columns[tree][column]).collect())
            .unwrap_or_default();
        pack(&row)
    });
    let queried = TreeVec(
        columns
            .iter()
            .map(|tree| tree.iter().map(|&value| vec![value]).collect())
            .collect(),
    );
    fri_answers(
        TreeVec(layout.column_log_sizes.clone()),
        samples,
        DeepCoefficients::Powers(witness.alpha),
        &[position],
        queried,
        lifting,
    )
    .map(|answers| answers[0])
}

/// The plan's quotient is Stwo's over random inputs, and the two refuse the
/// same degenerate points.
#[test]
fn the_plans_quotient_and_refusals_are_the_native_verifiers() {
    let mut rng = Rng::new(74);
    for (name, stark) in starks() {
        let layout = &stark.layout;
        let n_sampled: usize = layout.sample_offsets.iter().flatten().map(Vec::len).sum();
        let wires: Vec<usize> = stark
            .leaf_order
            .iter()
            .map(|order| order.len().div_ceil(4))
            .collect();
        let random = |rng: &mut Rng| {
            let witness = Witness::random(&stark.deep, &wires, rng);
            assert_eq!(
                witness.sampled.len(),
                n_sampled,
                "{name}: the sampled values"
            );
            let position = rng.below(1 << layout.lifting_log_size);
            let columns: Vec<Vec<BaseField>> = layout
                .column_log_sizes
                .iter()
                .map(|tree| tree.iter().map(|_| rng.m31()).collect())
                .collect();
            (witness, position, columns)
        };
        for trial in 0..3 {
            let (mut witness, position, columns) = random(&mut rng);
            let expected =
                native(stark, &mut witness, position, &columns).expect("an honest point");
            let (answer, _, pieces) = build(&stark.deep, &witness);
            assert!(pieces.is_empty(), "{name}, trial {trial}: {pieces:?}");
            assert_eq!(answer, expected, "{name}, trial {trial}");
        }
        for k in 0..stark.deep.points.len() {
            let (mut witness, position, columns) = random(&mut rng);
            witness.oods = degenerate_at(&stark.deep, k, &mut rng);
            let refused = native(stark, &mut witness, position, &columns);
            assert!(
                matches!(refused, Err(VerificationError::InvalidStructure(_))),
                "{name}, point {k}: Stwo refuses it"
            );
            let (_, context, pieces) = build(&stark.deep, &witness);
            assert!(
                pieces.iter().all(|&piece| piece == "deep once"),
                "{name}, point {k}: {pieces:?}"
            );
            assert_eq!(
                context.mismatches().len(),
                degenerate_points(&stark.deep, witness.oods).len(),
                "{name}, point {k}"
            );
        }
    }
}
