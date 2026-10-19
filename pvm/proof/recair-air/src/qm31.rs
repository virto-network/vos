//! `qm31`: the arithmetic gate (`recursion-air.md` §1.4).
//!
//! `out = k_m·a·b + k_p·(a⊙b) + k_a·a + k_b·b + k_c·c + Σ_j λ_j·c_j`, one QM31
//! constraint of degree 3 with M31 coefficients from preprocessed columns.
//! `a⊙b` multiplies limb by limb; the lane terms read the M31 limbs of `c`.
//! One row is an add, a sub, a product, a pointwise product, a fused
//! multiply-add, a scaling, a three-term sum, a limb of a packed wire, an
//! inverse (`a·b = 1`, with `b` yielded and the output using `one`), a bit
//! (`b·b = b`), or a constant from `one`, `u` and the basis they make.
//!
//! Each of the four operands is a `Gate` entry with a preprocessed address and
//! multiplicity: four fractions in two pairs.

use core::array::from_fn;

use alloc::string::ToString;
use num_traits::Zero;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, RelationEntry};

use crate::gate::GateRelation;
use crate::{Body, LOG_CONSTRAINT_EXPANSION};

/// The preprocessed columns, in commitment order: the five coefficients, the
/// four lane coefficients, the operands' addresses and multiplicities, each
/// in the order `a`, `b`, `c`, `out`.
pub const PREPROCESSED: [&str; 17] = [
    "recair_qm31_k_m",
    "recair_qm31_k_p",
    "recair_qm31_k_a",
    "recair_qm31_k_b",
    "recair_qm31_k_c",
    "recair_qm31_lane_0",
    "recair_qm31_lane_1",
    "recair_qm31_lane_2",
    "recair_qm31_lane_3",
    "recair_qm31_addr_a",
    "recair_qm31_addr_b",
    "recair_qm31_addr_c",
    "recair_qm31_addr_out",
    "recair_qm31_mult_a",
    "recair_qm31_mult_b",
    "recair_qm31_mult_c",
    "recair_qm31_mult_out",
];

/// Positions in [`PREPROCESSED`].
pub mod pre {
    pub const K_M: usize = 0;
    pub const K_P: usize = 1;
    pub const K_A: usize = 2;
    pub const K_B: usize = 3;
    pub const K_C: usize = 4;
    pub const LANES: usize = 5;
    pub const ADDR: usize = 9;
    pub const MULT: usize = 13;
}

/// The main trace: `a`, `b`, `c` and `out`, four limbs each.
pub const N_MAIN: usize = 16;
/// The interaction trace's columns: two pairs of fractions.
pub const N_INTERACTION: usize = 8;
/// The gate and the two fraction pairs.
pub const N_CONSTRAINTS: usize = 3;

/// The component, at `log_size` rows.
#[derive(Clone)]
pub struct Qm31Eval {
    pub log_size: u32,
    pub relation: GateRelation,
}

impl FrameworkEval for Qm31Eval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + LOG_CONSTRAINT_EXPANSION
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        self.body(&mut eval);
        eval.finalize_logup_in_pairs();
        eval
    }
}

impl Body for Qm31Eval {
    fn body<E: EvalAtRow>(&self, eval: &mut E) {
        let pre: [E::F; 17] = from_fn(|i| {
            eval.get_preprocessed_column(PreProcessedColumnId {
                id: PREPROCESSED[i].to_string(),
            })
        });
        let operands: [[E::F; 4]; 4] = from_fn(|_| from_fn(|_| eval.next_trace_mask()));
        let [a, b, c, out] = operands.clone();
        let (ea, eb, ec) = (
            E::combine_ef(a.clone()),
            E::combine_ef(b.clone()),
            E::combine_ef(c.clone()),
        );
        let pointwise = E::combine_ef(from_fn(|i| a[i].clone() * b[i].clone()));
        let lanes = (0..4).fold(E::F::zero(), |sum, j| {
            sum + pre[pre::LANES + j].clone() * c[j].clone()
        });
        let k = |i: usize| E::EF::from(pre[i].clone());
        eval.add_constraint(
            E::combine_ef(out)
                - (ea.clone() * eb.clone() * k(pre::K_M)
                    + pointwise * k(pre::K_P)
                    + ea * k(pre::K_A)
                    + eb * k(pre::K_B)
                    + ec * k(pre::K_C)
                    + E::EF::from(lanes)),
        );
        for (i, [l0, l1, l2, l3]) in operands.into_iter().enumerate() {
            eval.add_to_relation(RelationEntry::new(
                &self.relation,
                E::EF::from(pre[pre::MULT + i].clone()),
                &[pre[pre::ADDR + i].clone(), l0, l1, l2, l3],
            ));
        }
    }
}
