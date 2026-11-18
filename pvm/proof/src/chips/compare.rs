//! `CompareChip`: per-compare-or-branch-row chip.
//!
//! CpuChip emits one CompareLookup producer per `is_compare + is_branch`
//! row; CompareChip consumes once per real row.  CompareChip witnesses
//! the byte-wise subtraction carry chain (val_b + ~val_d + 1) and pins
//! cmp_lt_flag = 1 - cmp_carry\[7\].  Per-byte Range256 lookups on
//! cmp_sub_result emit from here too.
//!
//! Lookup tuple (17 limbs): val_b\[8\] + val_d\[8\] + cmp_lt_flag.
//!
//! The operands are not range-checked here: each is a register's value
//! (bytes, as every register write is: `cpu::constraints::memory::result_bytes`,
//! `tests/gates/register_writes_gate.rs`), an immediate of the program's
//! preprocessed code, a table's entry, or the CPU's bytes over these (a
//! low word and its sign's extension).

use crate::prelude::*;
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::WORD_SIZE;
use crate::trace::eval::TraceEval;

use crate::{
    framework::BuiltInComponent,
    lookups::{CompareLookupElements, Range256LookupElements},
};

#[derive(Clone, Copy)]
pub struct CompareChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    #[size = 8]
    ValB,
    #[size = 8]
    ValD,
    /// 1 iff val_b < val_d (unsigned).  Pinned to `1 - cmp_carry[7]`.
    #[size = 1]
    CmpLtFlag,
    /// Per-byte witness: `val_b[i] + 255 - val_d[i] + carry_in mod 256`.
    /// Range-checked via Range256.
    #[size = 8]
    CmpSubResult,
    /// Per-byte carry of the chain (each byte ∈ {0, 1}).
    #[size = 8]
    CmpCarry,
    #[size = 1]
    IsPadding,
    // No boolean-helper columns: the cmp_lt_flag and cmp_carry booleans
    // are enforced unconditionally as `X·(1-X)=0`.
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "compare"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for CompareChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (CompareLookupElements, Range256LookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(CompareLookupElements, Range256LookupElements),
    ) {
        let (compare_lookup, range256_lookup) = lookup_elements;
        let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let cmp_lt_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtFlag);
        let cmp_sub_result = crate::trace::trace_eval!(trace_eval, Column::CmpSubResult);
        let cmp_carry = crate::trace::trace_eval!(trace_eval, Column::CmpCarry);
        let is_padding = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

        // Boolean constraint on padding.
        eval.add_constraint(is_padding[0].clone() * (E::F::one() - is_padding[0].clone()));
        // cmp_lt_flag + cmp_carry[i] booleans enforced unconditionally —
        // trace fill defaults both to 0 on padding.
        let is_real = E::F::one() - is_padding[0].clone();
        eval.add_constraint(cmp_lt_flag[0].clone() * (E::F::one() - cmp_lt_flag[0].clone()));
        for i in 0..WORD_SIZE {
            eval.add_constraint(cmp_carry[i].clone() * (E::F::one() - cmp_carry[i].clone()));
        }

        // ── Subtraction carry chain ──
        //   sub_result[i] + carry[i]·256 = val_b[i] + 255 - val_d[i] + carry_in
        // (carry_in[0] = 1, carry_in[i] = carry[i-1])
        let f256: E::F = E::F::from(BaseField::from(256));
        let f255: E::F = E::F::from(BaseField::from(255));
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 {
                E::F::one()
            } else {
                cmp_carry[i - 1].clone()
            };
            eval.add_constraint(
                is_real.clone()
                    * (cmp_sub_result[i].clone() + cmp_carry[i].clone() * f256.clone()
                        - val_b[i].clone()
                        - f255.clone()
                        + val_d[i].clone()
                        - carry_in),
            );
        }
        // cmp_lt_flag = 1 - cmp_carry[7]
        eval.add_constraint(
            is_real.clone()
                * (cmp_lt_flag[0].clone() + cmp_carry[WORD_SIZE - 1].clone() - E::F::one()),
        );

        // ── Range256 emissions on cmp_sub_result bytes ──
        // 8 emissions per real row, gated on is_real.
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                &[cmp_sub_result[i].clone()],
            ));
        }

        // ── CompareLookup consumer ──
        // Tuple (17 limbs): val_b[8] + val_d[8] + cmp_lt_flag.
        let mut tuple: Vec<E::F> = Vec::with_capacity(17);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.push(cmp_lt_flag[0].clone());

        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                compare_lookup,
                (-is_real.clone()).into(),
                &tuple,
            ));
        }
    }
}

#[cfg(feature = "prover")]
mod fill;
