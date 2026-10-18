//! OODS (`recursion-air.md` §4.5): the composition check through the
//! compiled gates (slice 5's 5.9), as Stwo's verifier makes it.
//!
//! - The compiled constraints at the sampled values, folded under the
//!   composition coefficient as `PointEvaluationAccumulator` folds them,
//!   times one vanishing inverse at the OODS point:
//!   `coset_vanishing(CanonicCoset(B).coset, z)`, `B` the max log degree
//!   bound, the point shifted onto the canonic coset's doubling chain and
//!   its `x` doubled `B − 1` times.
//! - The sampled composition: its eight coordinate columns as
//!   `left + x·right`, each half `Σ e_k·basis_k` over `1, i, u, iu`, `x`
//!   the OODS point's `x` doubled `B − 1` times
//!   (`extract_composition_oods_eval`).
//! - The two are one: the product's output is the sampled composition's
//!   wire.

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;

use crate::circuit::Qm31Op;
use crate::compile::{Compiled, compose};
use crate::context::{Context, Var};
use crate::value::Value;

use super::circle::{Point, add_constant, double_x};

/// `Σ e_k·basis_k` over `1, i, u, iu`: three rows.
fn from_partial_evals<V: Value>(context: &mut Context<V>, evals: [Var; 4]) -> Var {
    let mut acc = evals[0];
    for (k, &eval) in evals.iter().enumerate().skip(1) {
        let mut limbs = [BaseField::from(0); 4];
        limbs[k] = BaseField::one();
        let basis = context.constant(SecureField::from_m31_array(limbs));
        acc = context.mul_add(eval, basis, acc);
    }
    acc
}

/// The composition check: the compiled constraints over `inputs` (the
/// wires of [`Compiled::inputs`]), under `coeff`, at `oods`, against the
/// sampled composition's eight columns.
pub fn check<V: Value>(
    context: &mut Context<V>,
    compiled: &Compiled,
    inputs: &[Var],
    coeff: Var,
    oods: Point,
    max_log_degree_bound: u32,
    composition: [Var; 8],
) {
    let constraints = compiled.emit(context, inputs);
    let acc = constraints
        .iter()
        .fold(None, |acc, values| compose(context, acc, coeff, values))
        .expect("a constraint");

    let coset = CanonicCoset::new(max_log_degree_bound).coset();
    let shift = (-coset.initial_index + coset.step_size.half()).to_point();
    let mut x = add_constant(context, oods, shift).x;
    for _ in 1..max_log_degree_bound {
        x = double_x(context, x);
    }
    let vanishing_inverse = context.inverse(x);

    let mut doubled = oods.x;
    for _ in 1..max_log_degree_bound {
        doubled = double_x(context, doubled);
    }
    let left = from_partial_evals(
        context,
        [
            composition[0],
            composition[1],
            composition[2],
            composition[3],
        ],
    );
    let right = from_partial_evals(
        context,
        [
            composition[4],
            composition[5],
            composition[6],
            composition[7],
        ],
    );
    let sampled = context.mul_add(doubled, right, left);
    context.qm31_into(
        Qm31Op {
            k_m: BaseField::one(),
            ..Default::default()
        },
        Some(acc),
        Some(vanishing_inverse),
        None,
        sampled,
    );
}
