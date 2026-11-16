//! `BitwiseChip`: per-bitwise-row chip.
//!
//! CpuChip emits one BitwiseLookup producer per `is_bitwise=1` row;
//! BitwiseChip consumes once per real row.  BitwiseChip witnesses the
//! AND result + nibble decompositions, runs the per-op result-binding
//! identities, and emits the 16 nibble-AND lookups against
//! BitwiseLookupChip's table — all on BitwiseChip's narrower trace
//! rather than CpuChip's wide one.
//!
//! Lookup tuple (30 limbs): val_b\[8\] + val_d\[8\] + result\[8\] +
//! is_and + is_or + is_xor + is_and_inv + is_or_inv + is_xnor.

use crate::prelude::*;
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::WORD_SIZE;
use crate::trace::eval::TraceEval;

use crate::{
    framework::BuiltInComponent,
    lookups::{BitwiseAndLookupElements, BitwiseLookupElements},
};

#[derive(Clone, Copy)]
pub struct BitwiseChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    #[size = 8]
    ValB,
    #[size = 8]
    ValD,
    #[size = 8]
    Result,
    /// `and_result[i] = val_b[i] & val_d[i]` — pinned by 16 nibble-AND
    /// lookups against BitwiseLookupChip's 16×16 table.
    #[size = 8]
    AndResult,
    #[size = 8]
    ValBHiNib,
    #[size = 8]
    ValDHiNib,
    #[size = 8]
    AndResultHiNib,
    /// Per-op flag columns; exactly one is 1 on a real row.
    #[size = 1]
    IsAnd,
    #[size = 1]
    IsOr,
    #[size = 1]
    IsXor,
    #[size = 1]
    IsAndInv,
    #[size = 1]
    IsOrInv,
    #[size = 1]
    IsXnor,
    #[size = 1]
    IsPadding,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "bitwise"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for BitwiseChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    /// Depends on both BitwiseLookup (for the row-level
    /// consumer) and BitwiseAndLookup (for the 16 nibble emissions).
    type LookupElements = (BitwiseLookupElements, BitwiseAndLookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(BitwiseLookupElements, BitwiseAndLookupElements),
    ) {
        let (bitwise_lookup, bitwise_and_lookup) = lookup_elements;
        let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let result = crate::trace::trace_eval!(trace_eval, Column::Result);
        let and_result = crate::trace::trace_eval!(trace_eval, Column::AndResult);
        let val_b_hi_nib = crate::trace::trace_eval!(trace_eval, Column::ValBHiNib);
        let val_d_hi_nib = crate::trace::trace_eval!(trace_eval, Column::ValDHiNib);
        let and_result_hi_nib = crate::trace::trace_eval!(trace_eval, Column::AndResultHiNib);
        let is_and = crate::trace::trace_eval!(trace_eval, Column::IsAnd);
        let is_or = crate::trace::trace_eval!(trace_eval, Column::IsOr);
        let is_xor = crate::trace::trace_eval!(trace_eval, Column::IsXor);
        let is_and_inv = crate::trace::trace_eval!(trace_eval, Column::IsAndInv);
        let is_or_inv = crate::trace::trace_eval!(trace_eval, Column::IsOrInv);
        let is_xnor = crate::trace::trace_eval!(trace_eval, Column::IsXnor);
        let is_padding = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

        // Boolean constraints on flag columns.
        for flag in [
            &is_and,
            &is_or,
            &is_xor,
            &is_and_inv,
            &is_or_inv,
            &is_xnor,
            &is_padding,
        ] {
            eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
        }
        let is_real = E::F::one() - is_padding[0].clone();
        let variant_sum = is_and[0].clone()
            + is_or[0].clone()
            + is_xor[0].clone()
            + is_and_inv[0].clone()
            + is_or_inv[0].clone()
            + is_xnor[0].clone();
        eval.add_constraint(is_real.clone() * (variant_sum.clone() - E::F::one()));
        eval.add_constraint(is_padding[0].clone() * variant_sum);

        // ── Per-op result-binding identities (mirroring the block
        //    CpuChip would otherwise carry) ──
        let f255 = E::F::from(BaseField::from(255));
        let f2 = E::F::from(BaseField::from(2u32));
        for i in 0..WORD_SIZE {
            let a = &val_b[i];
            let b = &val_d[i];
            let ar = &and_result[i];
            let r = &result[i];
            // op=0 (AND):     r = ar
            eval.add_constraint(is_and[0].clone() * (r.clone() - ar.clone()));
            // op=1 (OR):      r = a + b - ar
            eval.add_constraint(
                is_or[0].clone() * (r.clone() - a.clone() - b.clone() + ar.clone()),
            );
            // op=2 (XOR):     r = a + b - 2*ar
            eval.add_constraint(
                is_xor[0].clone() * (r.clone() - a.clone() - b.clone() + f2.clone() * ar.clone()),
            );
            // op=3 (AndInv):  r = a - ar
            eval.add_constraint(is_and_inv[0].clone() * (r.clone() - a.clone() + ar.clone()));
            // op=4 (OrInv):   r = 255 - b + ar
            eval.add_constraint(
                is_or_inv[0].clone() * (r.clone() - f255.clone() + b.clone() - ar.clone()),
            );
            // op=5 (Xnor):    r = 255 - a - b + 2*ar
            eval.add_constraint(
                is_xnor[0].clone()
                    * (r.clone() - f255.clone() + a.clone() + b.clone() - f2.clone() * ar.clone()),
            );
        }

        // ── Bitwise AND nibble-level lookups (16 per real row) ──
        let sixteen: E::F = E::F::from(BaseField::from(16));
        for i in 0..WORD_SIZE {
            // High nibble: (val_b_hi[i], val_d_hi[i], and_result_hi[i])
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[
                    val_b_hi_nib[i].clone(),
                    val_d_hi_nib[i].clone(),
                    and_result_hi_nib[i].clone(),
                ],
            ));
            // Low nibble: lo = byte - hi*16
            let b_lo = val_b[i].clone() - val_b_hi_nib[i].clone() * sixteen.clone();
            let d_lo = val_d[i].clone() - val_d_hi_nib[i].clone() * sixteen.clone();
            let and_lo = and_result[i].clone() - and_result_hi_nib[i].clone() * sixteen.clone();
            eval.add_to_relation(RelationEntry::new(
                bitwise_and_lookup,
                is_real.clone().into(),
                &[b_lo, d_lo, and_lo],
            ));
        }

        // ── BitwiseLookup consumer ──
        // Tuple (30 limbs): val_b[8] + val_d[8] + result[8] + 6 sub-flags.
        let mut tuple: Vec<E::F> = Vec::with_capacity(30);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.push(is_and[0].clone());
        tuple.push(is_or[0].clone());
        tuple.push(is_xor[0].clone());
        tuple.push(is_and_inv[0].clone());
        tuple.push(is_or_inv[0].clone());
        tuple.push(is_xnor[0].clone());

        // Two paired emissions to mirror CpuChip's producer side.
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                (-is_real.clone()).into(),
                &tuple,
            ));
        }
    }
}

#[cfg(feature = "prover")]
mod fill;
