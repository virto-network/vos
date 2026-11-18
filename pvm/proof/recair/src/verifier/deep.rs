//! DEEP (`recursion-air.md` §4.6): each query's first-layer FRI value, the
//! quotients Stwo's `fri_answers` sums, with the samples, points and `α`
//! powers of `build_samples_with_randomness_and_periodicity` at the pin.
//!
//! At a query's domain point `q`, for each sample point `z`:
//! `[c_z·S_z(q) − A_z·q.y − B_z] / D_z(q)`, with
//! - `S_z(q) = Σ α^k·v_k(q)` over the columns sampled at `z`, their queried
//!   values: the only part a query computes per sample;
//! - `c_z = z̄.y − z.y`, `A_z = Σ α^k·(v̄_k − v_k)`, `B_z = c_z·V_z − z.y·A_z`
//!   with `V_z = Σ α^k·v_k` over the sampled values: once, two rows a sample
//!   (`V_z`, and `W_z = conj(Σ ᾱ^k·v_k) = Σ α^k·v̄_k`);
//! - `D_z(q) = (Re z.x − q.x)·Im z.y − (Re z.y − q.y)·Im z.x`, a CM31.
//!
//! `S_z(q)` is a Horner chain from the highest exponent down: an `h8` row
//! takes a clean block (eight lanes of one leaf row, each a sample at `z`,
//! exponents in a step, no other sample of `z` between them), and a fused
//! `qm31` row any other sample, `acc·α^Δ + lane`. The chain's lowest power
//! is folded into `c_z`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use num_traits::{One, Zero};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use vos_pvm_proof::SampleLayout;

use crate::circuit::Qm31Op;
use crate::context::{Context, Var};
use crate::value::Value;

use super::circle::{Point, add_constant};

/// One sample point's share of the quotient.
#[derive(Clone, Debug)]
pub struct DeepPoint {
    /// The point, the OODS point plus this offset.
    pub offset: CirclePoint<BaseField>,
    /// Its samples, `(exponent, index in the sampled values)`, the highest
    /// exponent first.
    pub samples: Vec<(usize, usize)>,
    /// Its Horner chain over a query's leaves, the highest exponent first.
    pub items: Vec<Item>,
}

/// A link of a point's chain over a query's leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    /// One lane of tree `tree`'s sorted leaf row.
    Single {
        tree: usize,
        lane: usize,
        exponent: usize,
    },
    /// The eight lanes of block `block` (wires `2·block`, `2·block + 1`),
    /// lane `j` at exponent `low + j·step`.
    Block {
        tree: usize,
        block: usize,
        low: usize,
        step: usize,
    },
}

impl Item {
    fn low(&self) -> usize {
        match *self {
            Item::Single { exponent, .. } => exponent,
            Item::Block { low, .. } => low,
        }
    }

    fn high(&self) -> usize {
        match *self {
            Item::Single { exponent, .. } => exponent,
            Item::Block { low, step, .. } => low + 7 * step,
        }
    }
}

/// DEEP's structure over a shape.
#[derive(Clone, Debug)]
pub struct DeepPlan {
    pub points: Vec<DeepPoint>,
}

/// A column's sample: its point, exponent and value.
#[derive(Clone, Copy, Debug)]
struct ColumnSample {
    point: usize,
    exponent: usize,
    value: usize,
}

impl DeepPlan {
    /// The plan over `layout`, the trees' leaf rows sorted by `leaf_order`
    /// (each tree's columns, in the order its leaf hashes them).
    pub fn new(layout: &SampleLayout, leaf_order: &[Vec<usize>]) -> Self {
        let (offsets, columns) = Self::column_samples(layout);
        let mut points: Vec<DeepPoint> = offsets
            .iter()
            .map(|&offset| DeepPoint {
                offset,
                samples: Vec::new(),
                items: Vec::new(),
            })
            .collect();
        for sample in columns.iter().flatten().flatten() {
            points[sample.point]
                .samples
                .push((sample.exponent, sample.value));
        }
        for point in &mut points {
            point
                .samples
                .sort_unstable_by_key(|sample| core::cmp::Reverse(sample.0));
        }

        // Clean blocks, then every other sample a single.
        let taken = Self::clean_blocks(&mut points, &columns, leaf_order);
        for (tree, order) in leaf_order.iter().enumerate() {
            for (lane, &column) in order.iter().enumerate() {
                for sample in &columns[tree][column] {
                    if !taken.contains(&(tree, column, sample.point)) {
                        points[sample.point].items.push(Item::Single {
                            tree,
                            lane,
                            exponent: sample.exponent,
                        });
                    }
                }
            }
        }
        for point in &mut points {
            point
                .items
                .sort_unstable_by_key(|item| core::cmp::Reverse(item.high()));
            debug_assert!(
                point
                    .items
                    .windows(2)
                    .all(|pair| pair[0].low() > pair[1].high())
            );
        }
        Self { points }
    }

    /// Each tree's columns' samples, as the native verifier numbers them,
    /// and the distinct points they are at: a column of two samples first
    /// gets the periodicity sample, at its second point plus its log
    /// size's period, with the second value.
    fn column_samples(
        layout: &SampleLayout,
    ) -> (Vec<CirclePoint<BaseField>>, Vec<Vec<Vec<ColumnSample>>>) {
        let lifting_step = CanonicCoset::new(layout.lifting_log_size).step();
        let mut offsets: Vec<CirclePoint<BaseField>> = Vec::new();
        let mut point_of = |offset: CirclePoint<BaseField>| match offsets
            .iter()
            .position(|&known| known == offset)
        {
            Some(index) => index,
            None => {
                offsets.push(offset);
                offsets.len() - 1
            }
        };
        let (mut exponent, mut value) = (0, 0);
        let mut columns: Vec<Vec<Vec<ColumnSample>>> = Vec::new();
        for (tree, tree_offsets) in layout.sample_offsets.iter().enumerate() {
            let mut tree_samples = Vec::new();
            for (column, column_offsets) in tree_offsets.iter().enumerate() {
                let mut samples = Vec::new();
                if let [_, second] = column_offsets[..] {
                    let log_size = layout.column_log_sizes[tree][column];
                    let period = lifting_step.repeated_double(log_size);
                    samples.push(ColumnSample {
                        point: point_of(second + period),
                        exponent,
                        value: value + 1,
                    });
                    exponent += 1;
                }
                for (k, &offset) in column_offsets.iter().enumerate() {
                    samples.push(ColumnSample {
                        point: point_of(offset),
                        exponent,
                        value: value + k,
                    });
                    exponent += 1;
                }
                value += column_offsets.len();
                tree_samples.push(samples);
            }
            columns.push(tree_samples);
        }
        (offsets, columns)
    }

    /// The clean blocks of eight leaf lanes, each pushed to its point's
    /// items: at a point, each lane's one sample there, their exponents a
    /// step apart and no other sample of the point between them. The
    /// `(tree, column, point)`s they take.
    fn clean_blocks(
        points: &mut [DeepPoint],
        columns: &[Vec<Vec<ColumnSample>>],
        leaf_order: &[Vec<usize>],
    ) -> BTreeSet<(usize, usize, usize)> {
        let mut taken: BTreeSet<(usize, usize, usize)> = BTreeSet::new();
        for (tree, order) in leaf_order.iter().enumerate() {
            for block in 0..order.len() / 8 {
                let lanes = &order[8 * block..8 * block + 8];
                for (index, point) in points.iter_mut().enumerate() {
                    let exponents: Option<Vec<usize>> = lanes
                        .iter()
                        .map(|&column| {
                            let mut at = columns[tree][column]
                                .iter()
                                .filter(|sample| sample.point == index);
                            match (at.next(), at.next()) {
                                (Some(sample), None) => Some(sample.exponent),
                                _ => None,
                            }
                        })
                        .collect();
                    let Some(exponents) = exponents else {
                        continue;
                    };
                    let (low, high) = (exponents[0], exponents[7]);
                    let Some(step) = exponents[1].checked_sub(low).filter(|&step| step > 0) else {
                        continue;
                    };
                    let stepped = exponents
                        .iter()
                        .enumerate()
                        .all(|(j, &exponent)| exponent == low + j * step);
                    let alone = point
                        .samples
                        .iter()
                        .filter(|&&(exponent, _)| (low..=high).contains(&exponent))
                        .count()
                        == 8;
                    if stepped && alone {
                        point.items.push(Item::Block {
                            tree,
                            block,
                            low,
                            step,
                        });
                        for &column in lanes {
                            taken.insert((tree, column, index));
                        }
                    }
                }
            }
        }
        taken
    }

    /// Each point's lowest exponent.
    fn lowest(point: &DeepPoint) -> usize {
        point.samples.last().expect("a point has a sample").0
    }

    /// The powers of `α` the chains and the constants read.
    fn exponents(&self) -> (BTreeSet<usize>, BTreeSet<usize>) {
        let (mut powers, mut conjugates) = (BTreeSet::new(), BTreeSet::new());
        for point in &self.points {
            for pair in point.samples.windows(2) {
                powers.insert(pair[0].0 - pair[1].0);
                conjugates.insert(pair[0].0 - pair[1].0);
            }
            let lowest = Self::lowest(point);
            powers.insert(lowest);
            conjugates.insert(lowest);
            for pair in point.items.windows(2) {
                powers.insert(pair[0].low() - pair[1].low());
            }
            for item in &point.items {
                if let Item::Block { step, .. } = *item {
                    powers.insert(step);
                }
            }
        }
        powers.remove(&0);
        conjugates.remove(&0);
        (powers, conjugates)
    }

    /// `h8` rows and other rows a query, and samples, as counted for the
    /// record.
    pub fn counts(&self) -> (usize, usize, usize) {
        let blocks = self
            .points
            .iter()
            .flat_map(|point| &point.items)
            .filter(|item| matches!(item, Item::Block { .. }))
            .count();
        let items: usize = self.points.iter().map(|point| point.items.len()).sum();
        let samples = self.points.iter().map(|point| point.samples.len()).sum();
        (blocks, items - blocks, samples)
    }
}

/// A point's constants, computed once.
#[derive(Clone, Copy, Debug)]
struct PointConstants {
    im_x: Var,
    im_y: Var,
    k: Var,
    coeff: Var,
    a: Var,
    neg_b: Var,
}

/// What every query's quotient reads, computed once.
#[derive(Clone, Debug)]
pub struct DeepConstants {
    powers: HashMap<usize, Var>,
    points: Vec<PointConstants>,
}

fn pointwise<V: Value>(context: &mut Context<V>, a: Var, limbs: [i32; 4]) -> Var {
    let constant = context.constant(SecureField::from_m31_array(
        limbs.map(|limb| BaseField::from(limb.unsigned_abs()) * sign(limb)),
    ));
    context.pointwise_mul(a, constant)
}

fn sign(limb: i32) -> BaseField {
    if limb < 0 {
        -BaseField::one()
    } else {
        BaseField::one()
    }
}

/// `α^e` for each `e` of `exponents`: squarings, then a product a set bit.
fn powers_of<V: Value>(
    context: &mut Context<V>,
    alpha: Var,
    exponents: &BTreeSet<usize>,
) -> HashMap<usize, Var> {
    let Some(&max) = exponents.last() else {
        return HashMap::new();
    };
    let mut squares = vec![alpha];
    while 1 << squares.len() <= max {
        let last = *squares.last().unwrap();
        squares.push(context.mul(last, last));
    }
    exponents
        .iter()
        .map(|&e| {
            let mut acc: Option<Var> = None;
            for (bit, &square) in squares.iter().enumerate() {
                if e >> bit & 1 == 1 {
                    acc = Some(match acc {
                        None => square,
                        Some(acc) => context.mul(acc, square),
                    });
                }
            }
            (e, acc.expect("a positive exponent"))
        })
        .collect()
}

/// The constants of every point: from the OODS point, the DEEP
/// coefficient `alpha` and the sampled values' wires.
pub fn prepare<V: Value>(
    context: &mut Context<V>,
    plan: &DeepPlan,
    oods: Point,
    alpha: Var,
    sampled: &[Var],
) -> DeepConstants {
    let (exponents, conjugate_exponents) = plan.exponents();
    let powers = powers_of(context, alpha, &exponents);
    let conjugates: BTreeMap<usize, Var> = conjugate_exponents
        .iter()
        .map(|&e| (e, pointwise(context, powers[&e], [1, 1, -1, -1])))
        .collect();
    let u_inverse = context.constant(FieldExpOps::inverse(&SecureField::from_m31_array(
        [0, 0, 1, 0].map(BaseField::from),
    )));
    let points = plan
        .points
        .iter()
        .map(|point| {
            let z = add_constant(context, oods, point.offset);
            let re_x = pointwise(context, z.x, [1, 1, 0, 0]);
            let re_y = pointwise(context, z.y, [1, 1, 0, 0]);
            let im_x = pointwise(context, z.x, [0, 0, 1, 1]);
            let im_x = context.mul(im_x, u_inverse);
            let im_y = pointwise(context, z.y, [0, 0, 1, 1]);
            let im_y = context.mul(im_y, u_inverse);
            let re_x_im_y = context.mul(re_x, im_y);
            let k = context.qm31(
                Qm31Op {
                    k_m: -BaseField::one(),
                    k_c: BaseField::one(),
                    ..Default::default()
                },
                Some(re_y),
                Some(im_x),
                Some(re_x_im_y),
            );
            let c = pointwise(context, z.y, [0, 0, -2, -2]);

            // V and W' = Σ ᾱ^k·v_k, Horner from the highest exponent.
            let chain = |context: &mut Context<V>, powers: &dyn Fn(usize) -> Var| {
                let mut acc = sampled[point.samples[0].1];
                for pair in point.samples.windows(2) {
                    let step = powers(pair[0].0 - pair[1].0);
                    acc = context.mul_add(acc, step, sampled[pair[1].1]);
                }
                let lowest = DeepPlan::lowest(point);
                if lowest > 0 {
                    acc = context.mul(acc, powers(lowest));
                }
                acc
            };
            let v = chain(context, &|e| powers[&e]);
            let w = chain(context, &|e| conjugates[&e]);
            let w = pointwise(context, w, [1, 1, -1, -1]);
            let a = context.sub(w, v);
            let cv = context.mul(c, v);
            let neg_b = context.qm31(
                Qm31Op {
                    k_m: BaseField::one(),
                    k_c: -BaseField::one(),
                    ..Default::default()
                },
                Some(z.y),
                Some(a),
                Some(cv),
            );
            let lowest = DeepPlan::lowest(point);
            let coeff = if lowest > 0 {
                context.mul(c, powers[&lowest])
            } else {
                c
            };
            PointConstants {
                im_x,
                im_y,
                k,
                coeff,
                a,
                neg_b,
            }
        })
        .collect();
    DeepConstants { powers, points }
}

/// A query's first-layer value at its domain point `q`, from its leaves:
/// each tree's sorted row, packed four values a wire.
pub fn answer<V: Value>(
    context: &mut Context<V>,
    plan: &DeepPlan,
    constants: &DeepConstants,
    q: Point,
    leaves: [&[Var]; 4],
) -> Var {
    let one = context.one();
    let zero = context.zero();
    let mut total: Option<Var> = None;
    for (point, consts) in plan.points.iter().zip(&constants.points) {
        let mut s: Option<Var> = None;
        let mut current = 0;
        for item in &point.items {
            let mu = s.map(|_| constants.powers[&(current - item.low())]);
            s = Some(match *item {
                Item::Single { tree, lane, .. } => {
                    let mut lanes = [BaseField::zero(); 4];
                    lanes[lane % 4] = BaseField::one();
                    let wire = leaves[tree][lane / 4];
                    match (s, mu) {
                        (Some(acc), Some(mu)) => context.qm31(
                            Qm31Op {
                                k_m: BaseField::one(),
                                lanes,
                                ..Default::default()
                            },
                            Some(acc),
                            Some(mu),
                            Some(wire),
                        ),
                        _ => context.limb(wire, lane % 4),
                    }
                }
                Item::Block {
                    tree, block, step, ..
                } => {
                    let v = [leaves[tree][2 * block], leaves[tree][2 * block + 1]];
                    let sigma = constants.powers[&step];
                    match (s, mu) {
                        (Some(acc), Some(mu)) => context.h8(acc, sigma, mu, v),
                        _ => context.h8(zero, sigma, one, v),
                    }
                }
            });
            current = item.low();
        }
        let s = s.expect("a point has a sample");
        let t = context.mul_add(q.y, consts.im_x, consts.k);
        let denominator = context.qm31(
            Qm31Op {
                k_m: -BaseField::one(),
                k_c: BaseField::one(),
                ..Default::default()
            },
            Some(q.x),
            Some(consts.im_y),
            Some(t),
        );
        let inverse = context.inverse(denominator);
        let partial = context.mul_add(consts.coeff, s, consts.neg_b);
        let numerator = context.qm31(
            Qm31Op {
                k_m: -BaseField::one(),
                k_c: BaseField::one(),
                ..Default::default()
            },
            Some(consts.a),
            Some(q.y),
            Some(partial),
        );
        total = Some(match total {
            None => context.mul(numerator, inverse),
            Some(acc) => context.mul_add(numerator, inverse, acc),
        });
    }
    total.expect("a sample point")
}
