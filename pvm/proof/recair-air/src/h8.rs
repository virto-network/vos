//! `h8`: the DEEP accumulator (`recursion-air.md` §1.5).
//!
//! `out = acc·μ + Σ_j σ^j·v_j` over eight M31 samples `v` (two packed wires),
//! for one block of a leaf's row at one sample point, with `σ` the step of
//! its exponents and `μ` the step between blocks. Horner from `v7` down, two
//! steps an intermediate column, so each constraint is of degree 3:
//! - `q0 = (v7·σ + v6)·σ + v5`;
//! - `q1 = (q0·σ + v4)·σ + v3`;
//! - `q2 = (q1·σ + v2)·σ + v1`;
//! - `out = acc·μ + q2·σ + v0`.
//!
//! The inputs `acc`, `σ`, `μ` and the two sample wires are uses, `+1` each;
//! the output's multiplicity is preprocessed. A padding row reads the zero
//! wire five times. Six fractions in three pairs.

use core::array::from_fn;

use alloc::string::ToString;
use num_traits::One;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, RelationEntry};

use crate::gate::GateRelation;
use crate::{Body, LOG_CONSTRAINT_EXPANSION};

/// The preprocessed columns, in commitment order: the addresses of `acc`,
/// `σ`, `μ`, the two sample wires and the output, and the output's
/// multiplicity.
pub const PREPROCESSED: [&str; 7] = [
    "recair_h8_addr_acc",
    "recair_h8_addr_step",
    "recair_h8_addr_mu",
    "recair_h8_addr_v0",
    "recair_h8_addr_v1",
    "recair_h8_addr_out",
    "recair_h8_mult_out",
];

/// Positions in [`PREPROCESSED`].
pub mod pre {
    pub const ADDR_ACC: usize = 0;
    pub const ADDR_STEP: usize = 1;
    pub const ADDR_MU: usize = 2;
    pub const ADDR_V: [usize; 2] = [3, 4];
    pub const ADDR_OUT: usize = 5;
    pub const MULT_OUT: usize = 6;
}

/// Positions in the main trace.
pub mod main {
    pub const ACC: usize = 0;
    pub const STEP: usize = 4;
    pub const MU: usize = 8;
    pub const V: usize = 12;
    pub const Q: usize = 20;
    pub const OUT: usize = 32;
}

/// The main trace: `acc`, `σ`, `μ` (four limbs each), the eight samples, the
/// three Horner intermediates and the output.
pub const N_MAIN: usize = 36;
/// The interaction trace's columns: three pairs of fractions.
pub const N_INTERACTION: usize = 12;
/// The four Horner steps and the three fraction pairs.
pub const N_CONSTRAINTS: usize = 7;

/// The component, at `log_size` rows.
#[derive(Clone)]
pub struct H8Eval {
    pub log_size: u32,
    pub relation: GateRelation,
}

impl FrameworkEval for H8Eval {
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

impl Body for H8Eval {
    fn body<E: EvalAtRow>(&self, eval: &mut E) {
        let pre: [E::F; 7] = from_fn(|i| {
            eval.get_preprocessed_column(PreProcessedColumnId {
                id: PREPROCESSED[i].to_string(),
            })
        });
        let acc: [E::F; 4] = from_fn(|_| eval.next_trace_mask());
        let step: [E::F; 4] = from_fn(|_| eval.next_trace_mask());
        let mu: [E::F; 4] = from_fn(|_| eval.next_trace_mask());
        let v: [E::F; 8] = from_fn(|_| eval.next_trace_mask());
        let q: [[E::F; 4]; 3] = from_fn(|_| from_fn(|_| eval.next_trace_mask()));
        let out: [E::F; 4] = from_fn(|_| eval.next_trace_mask());

        let s = E::combine_ef(step.clone());
        let eq: [E::EF; 3] = from_fn(|i| E::combine_ef(q[i].clone()));
        let horner =
            |h: E::EF, x: &E::F, y: &E::F| (h * s.clone() + x.clone()) * s.clone() + y.clone();
        eval.add_constraint(eq[0].clone() - horner(E::EF::from(v[7].clone()), &v[6], &v[5]));
        eval.add_constraint(eq[1].clone() - horner(eq[0].clone(), &v[4], &v[3]));
        eval.add_constraint(eq[2].clone() - horner(eq[1].clone(), &v[2], &v[1]));
        eval.add_constraint(
            E::combine_ef(out.clone())
                - (E::combine_ef(acc.clone()) * E::combine_ef(mu.clone())
                    + eq[2].clone() * s.clone()
                    + v[0].clone()),
        );

        let use_ = || E::EF::one();
        let [v0, v1, v2, v3, v4, v5, v6, v7] = v;
        let entries: [(E::EF, usize, [E::F; 4]); 6] = [
            (use_(), pre::ADDR_ACC, acc),
            (use_(), pre::ADDR_STEP, step),
            (use_(), pre::ADDR_MU, mu),
            (use_(), pre::ADDR_V[0], [v0, v1, v2, v3]),
            (use_(), pre::ADDR_V[1], [v4, v5, v6, v7]),
            (E::EF::from(pre[pre::MULT_OUT].clone()), pre::ADDR_OUT, out),
        ];
        for (multiplicity, address, [l0, l1, l2, l3]) in entries {
            eval.add_to_relation(RelationEntry::new(
                &self.relation,
                multiplicity,
                &[pre[address].clone(), l0, l1, l2, l3],
            ));
        }
    }
}
