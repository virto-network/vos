//! Circle points over the verifier's wires: a domain point from its
//! position's bits, a point plus a constant, `x` doubled, and the OODS point
//! from its draw.

use num_traits::One;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;

use crate::circuit::Qm31Op;
use crate::context::{Bit, Context, Var};
use crate::value::Value;

/// A circle point's two coordinates as wires.
#[derive(Clone, Copy, Debug)]
pub struct Point {
    pub x: Var,
    pub y: Var,
}

/// `p + c`, `c` a constant: `(x·cx − y·cy, x·cy + y·cx)`, two rows.
pub fn add_constant<V: Value>(
    context: &mut Context<V>,
    p: Point,
    c: CirclePoint<BaseField>,
) -> Point {
    let x = context.qm31(
        Qm31Op {
            k_a: c.x,
            k_b: -c.y,
            ..Default::default()
        },
        Some(p.x),
        Some(p.y),
        None,
    );
    let y = context.qm31(
        Qm31Op {
            k_a: c.y,
            k_b: c.x,
            ..Default::default()
        },
        Some(p.x),
        Some(p.y),
        None,
    );
    Point { x, y }
}

/// The `x` of a point doubled: `2x² − 1`, one row.
pub(crate) fn double_x<V: Value>(context: &mut Context<V>, x: Var) -> Var {
    let one = context.one();
    context.qm31(
        Qm31Op {
            k_m: BaseField::from(2),
            k_c: -BaseField::one(),
            ..Default::default()
        },
        Some(x),
        Some(x),
        Some(one),
    )
}

/// `CirclePoint::get_random_point` of the draw `t`: `x = 2/(1 + t²) − 1`,
/// `y = 2t/(1 + t²)`, four rows.
pub fn random_point<V: Value>(context: &mut Context<V>, t: Var) -> Point {
    let one = context.one();
    let denominator = context.qm31(
        Qm31Op {
            k_m: BaseField::one(),
            k_c: BaseField::one(),
            ..Default::default()
        },
        Some(t),
        Some(t),
        Some(one),
    );
    let inverse = context.inverse(denominator);
    let x = context.qm31(
        Qm31Op {
            k_a: BaseField::from(2),
            k_c: -BaseField::one(),
            ..Default::default()
        },
        Some(inverse),
        None,
        Some(one),
    );
    let y = context.qm31(
        Qm31Op {
            k_m: BaseField::from(2),
            ..Default::default()
        },
        Some(t),
        Some(inverse),
        None,
    );
    Point { x, y }
}

/// The point of `CanonicCoset(log_size)`'s circle domain at
/// `bit_reverse_index(position, log_size)`, from the position's
/// `log_size` bits, least significant first: the half coset's point at the
/// bits above the first, read reversed, conjugated when the first is one.
/// Four rows a bit.
pub fn domain_point<V: Value>(context: &mut Context<V>, log_size: u32, bits: &[Bit]) -> Point {
    assert_eq!(bits.len(), log_size as usize, "one bit a level");
    assert!(log_size >= 2, "a circle domain of at least four points");
    let half = CanonicCoset::new(log_size).half_coset();
    let initial = half.initial;
    let one = context.one();
    let mut point: Option<Point> = None;
    for (k, bit) in bits.iter().enumerate().skip(1) {
        let g = (half.step_size * (1 << (log_size as usize - 1 - k))).to_point();
        let b = bit.var();
        point = Some(match point {
            // The first step from the constant initial point:
            // `initial + b·(initial·g − initial)`.
            None => {
                let moved = initial + g;
                let x = context.qm31(
                    Qm31Op {
                        k_a: moved.x - initial.x,
                        k_c: initial.x,
                        ..Default::default()
                    },
                    Some(b),
                    None,
                    Some(one),
                );
                let y = context.qm31(
                    Qm31Op {
                        k_a: moved.y - initial.y,
                        k_c: initial.y,
                        ..Default::default()
                    },
                    Some(b),
                    None,
                    Some(one),
                );
                Point { x, y }
            }
            // `p + b·(p·g − p)`, coordinate by coordinate.
            Some(p) => {
                let dx = context.qm31(
                    Qm31Op {
                        k_a: g.x - BaseField::one(),
                        k_b: -g.y,
                        ..Default::default()
                    },
                    Some(p.x),
                    Some(p.y),
                    None,
                );
                let dy = context.qm31(
                    Qm31Op {
                        k_a: g.y,
                        k_b: g.x - BaseField::one(),
                        ..Default::default()
                    },
                    Some(p.x),
                    Some(p.y),
                    None,
                );
                let x = context.qm31(
                    Qm31Op {
                        k_m: BaseField::one(),
                        k_c: BaseField::one(),
                        ..Default::default()
                    },
                    Some(b),
                    Some(dx),
                    Some(p.x),
                );
                let y = context.qm31(
                    Qm31Op {
                        k_m: BaseField::one(),
                        k_c: BaseField::one(),
                        ..Default::default()
                    },
                    Some(b),
                    Some(dy),
                    Some(p.y),
                );
                Point { x, y }
            }
        });
    }
    let p = point.expect("a bit above the first");
    // Conjugated on the first bit: `y − 2·b·y`.
    let y = context.qm31(
        Qm31Op {
            k_m: -BaseField::from(2),
            k_b: BaseField::one(),
            ..Default::default()
        },
        Some(bits[0].var()),
        Some(p.y),
        None,
    );
    Point { x: p.x, y }
}
