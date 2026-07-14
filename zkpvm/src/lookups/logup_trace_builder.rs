use num_traits::{One, Zero};
use stwo::{
    core::fields::{m31::BaseField, qm31::SecureField},
    prover::{
        backend::simd::{
            SimdBackend,
            m31::{LOG_N_LANES, PackedBaseField},
            qm31::PackedSecureField,
        },
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{LogupTraceGenerator, Relation};

use super::RegisteredLookupBound;
use crate::trace::component::FinalizedColumn;

type LogUpFrac = (PackedSecureField, PackedSecureField);

pub struct LogupTraceBuilder {
    pub log_size: u32,
    pub logup_trace_gen: LogupTraceGenerator,
    pub pending_logup: Vec<LogUpFrac>,
    /// When set (production default), rows whose batched numerator is entirely
    /// zero skip the `relation.combine()` and store the neutral denominator
    /// `1` instead.  A dead emission's denominator cancels in the finalized
    /// fraction value (`finalize_col` stores `numerator / denominator`), so the
    /// interaction columns are BIT-IDENTICAL to the always-combine path — the
    /// gated blake2b lookups (~1-in-96 live rows) skip the wide combine on the
    /// dead majority.  The reference (always-combine) path is kept for the
    /// bit-identity test.
    skip_dead_rows: bool,
}

impl LogupTraceBuilder {
    pub fn new(log_size: u32) -> Self {
        Self::with_dead_row_skip(log_size, true)
    }

    fn with_dead_row_skip(log_size: u32, skip_dead_rows: bool) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            log_size,
            logup_trace_gen: LogupTraceGenerator::new(log_size),
            pending_logup: Vec::with_capacity(1 << (log_size - LOG_N_LANES)),
            skip_dead_rows,
        }
    }
}

impl LogupTraceBuilder {
    fn iter_logup_fractions<'a, const N: usize, R, F>(
        log_size: u32,
        skip_dead_rows: bool,
        relation: &'a R,
        mult_columns: &'a [FinalizedColumn<'a>; N],
        mult_expr: F,
        tuple: &'a [FinalizedColumn<'a>],
    ) -> impl Iterator<Item = LogUpFrac> + 'a
    where
        R: RegisteredLookupBound,
        F: Fn([PackedBaseField; N]) -> PackedSecureField + 'a,
    {
        (0..1 << (log_size - LOG_N_LANES)).map(move |vec_idx| {
            let mult_vals = mult_columns.clone().map(|col| col.at(vec_idx));
            let p0 = mult_expr(mult_vals);

            // Dead row: every batched numerator lane is zero, so this fraction
            // contributes `0/denominator = 0` no matter the denominator.  Skip
            // the combine and store the neutral `1` — bit-identical after
            // `finalize_col` divides.
            if skip_dead_rows && p0.is_zero() {
                return (p0, PackedSecureField::one());
            }

            let tuple: Vec<PackedBaseField> = tuple.iter().map(|col| col.at(vec_idx)).collect();
            let p1: PackedSecureField = relation.as_relation_ref().combine(&tuple);

            (p0, p1)
        })
    }

    #[allow(dead_code)]
    pub fn add_to_relation<'a, T, R>(
        &mut self,
        relation: &'a R,
        mult: T,
        tuple: &'a [FinalizedColumn<'a>],
    ) where
        T: Into<FinalizedColumn<'a>>,
        R: RegisteredLookupBound,
    {
        let mult = mult.into();
        self.add_to_relation_with(relation, [mult], |[col]| col.into(), tuple);
    }

    pub fn add_to_relation_with<'a, const N: usize, R, F>(
        &mut self,
        relation: &R,
        mult_columns: [FinalizedColumn<'a>; N],
        mult_expr: F,
        tuple: &'a [FinalizedColumn<'a>],
    ) where
        R: RegisteredLookupBound,
        F: Fn([PackedBaseField; N]) -> PackedSecureField,
    {
        let frac_iter = Self::iter_logup_fractions(
            self.log_size,
            self.skip_dead_rows,
            relation,
            &mult_columns,
            mult_expr,
            tuple,
        );

        if self.pending_logup.is_empty() {
            self.pending_logup.extend(frac_iter);
        } else {
            let mut logup_col_gen = self.logup_trace_gen.new_col();

            for (vec_row, (a, b)) in frac_iter.enumerate() {
                let (c, d) = self.pending_logup[vec_row];
                logup_col_gen.write_frac(vec_row, a * d + b * c, b * d);
            }

            logup_col_gen.finalize_col();
            self.pending_logup.clear();
        }
    }

    /// Like `add_to_relation_with`, but the tuple values are computed per-row
    /// from a closure instead of read directly from columns.
    pub fn add_to_relation_computed<const N: usize, R, F, G>(
        &mut self,
        relation: &R,
        mult_columns: [FinalizedColumn<'_>; N],
        mult_expr: F,
        tuple_len: usize,
        tuple_expr: G,
    ) where
        R: RegisteredLookupBound,
        F: Fn([PackedBaseField; N]) -> PackedSecureField,
        G: Fn(usize) -> Vec<PackedBaseField>,
    {
        let num_vecs = 1 << (self.log_size - LOG_N_LANES);
        let skip_dead_rows = self.skip_dead_rows;
        let frac_iter = (0..num_vecs).map(|vec_idx| {
            let mult_vals = mult_columns.clone().map(|col| col.at(vec_idx));
            let p0 = mult_expr(mult_vals);
            // Dead row: skip both the tuple build and the combine (see
            // `iter_logup_fractions`).
            if skip_dead_rows && p0.is_zero() {
                return (p0, PackedSecureField::one());
            }
            let tuple = tuple_expr(vec_idx);
            debug_assert_eq!(tuple.len(), tuple_len);
            let p1: PackedSecureField = relation.as_relation_ref().combine(&tuple);
            (p0, p1)
        });

        if self.pending_logup.is_empty() {
            self.pending_logup.extend(frac_iter);
        } else {
            let mut logup_col_gen = self.logup_trace_gen.new_col();

            for (vec_row, (a, b)) in frac_iter.enumerate() {
                let (c, d) = self.pending_logup[vec_row];
                logup_col_gen.write_frac(vec_row, a * d + b * c, b * d);
            }

            logup_col_gen.finalize_col();
            self.pending_logup.clear();
        }
    }

    pub fn finalize(
        mut self,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        if !self.pending_logup.is_empty() {
            let mut logup_col_gen = self.logup_trace_gen.new_col();
            for (vec_row, (a, b)) in self.pending_logup.into_iter().enumerate() {
                logup_col_gen.write_frac(vec_row, a, b);
            }
            logup_col_gen.finalize_col();
        }

        self.logup_trace_gen.finalize_last()
    }
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::chips::blake2b::{Blake2bBoundaryChip, BoundaryColumn};
    use crate::framework::{MachineComponent, MachineProverComponent};
    use crate::lookups::{
        AllLookupElements, BitwiseAndLookupElements, Blake2bCompressionLookupElements,
        Range256LookupElements,
    };
    use crate::side_note::SideNote;
    use crate::trace::component::ComponentTrace;
    use stwo::core::channel::Blake2sChannel;
    use stwo::prover::backend::Column as _;

    /// A real `Blake2bBoundaryChip` component trace over a handful of
    /// synthetic compressions — the columns carry a dense (`IsReal`) selector
    /// alongside the 1-in-96 sparse `EmitMult` producer, i.e. exactly the
    /// gated-emission sparsity the dead-row skip targets.
    fn boundary_component_trace() -> ComponentTrace {
        use crate::chips::blake2b::Blake2bCall;
        let mut sn = SideNote::new(Vec::new(), Vec::new(), Vec::new());
        for k in 0..5u64 {
            let h = core::array::from_fn(|i| (i as u64).wrapping_mul(k + 1).wrapping_add(0x11));
            let m = core::array::from_fn(|i| (i as u64).wrapping_mul(3).wrapping_add(k * 7 + 1));
            sn.merkle_blake2b_calls.push(Blake2bCall {
                h,
                m,
                t: (k as u128) * 128,
                f: k % 2 == 0,
            });
            sn.merkle_blake2b_mults.push((k as u32) + 1);
        }
        Blake2bBoundaryChip.generate_component_trace(&mut sn)
    }

    /// Replay a representative emission sequence — dense (`IsReal`-gated
    /// nibble AND) and sparse (`EmitMult`-gated 265-wide producer) fractions,
    /// interleaved so every builder path is hit: stash of a dense and of a
    /// sparse emission, `combine` of dense+sparse, sparse+dense and dense+dense
    /// pairs, and an unpaired sparse tail at `finalize`.  Both builders see
    /// identical inputs; only the dead-row skip differs.  Returns the
    /// finalized interaction columns and claimed sum for a bit-for-bit
    /// comparison.
    fn replay_cols(
        trace: &ComponentTrace,
        lookups: &AllLookupElements,
        skip: bool,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let range256: &Range256LookupElements = lookups.as_ref();
        let bitwise: &BitwiseAndLookupElements = lookups.as_ref();
        let is_real = crate::trace::original_base_column!(trace, BoundaryColumn::IsReal);
        let a_hi = crate::trace::original_base_column!(trace, BoundaryColumn::And1AHi);
        let b_hi = crate::trace::original_base_column!(trace, BoundaryColumn::And1BHi);
        let r_hi = crate::trace::original_base_column!(trace, BoundaryColumn::And1ResHi);
        let a_in = crate::trace::original_base_column!(trace, BoundaryColumn::AIn);
        let emit_mult = crate::trace::original_base_column!(trace, BoundaryColumn::EmitMult);
        let output_cols = crate::trace::original_base_column!(trace, BoundaryColumn::Output);
        let compression: &Blake2bCompressionLookupElements = lookups.as_ref();

        let producer = |logup: &mut LogupTraceBuilder| {
            let output_cols = output_cols.clone();
            logup.add_to_relation_computed(
                compression,
                [emit_mult[0].clone()],
                |[m]| m.into(),
                265,
                move |v| (0..265).map(|k| output_cols[k % 64].at(v)).collect(),
            );
        };
        let dense_and = |logup: &mut LogupTraceBuilder, i: usize| {
            logup.add_to_relation_with(
                bitwise,
                [is_real[0].clone()],
                |[r]| r.into(),
                &[a_hi[i].clone(), b_hi[i].clone(), r_hi[i].clone()],
            );
        };
        let dense_range = |logup: &mut LogupTraceBuilder, i: usize| {
            logup.add_to_relation_with(
                range256,
                [is_real[0].clone()],
                |[r]| r.into(),
                &[a_in[i].clone()],
            );
        };

        let mut logup = LogupTraceBuilder::with_dead_row_skip(trace.log_size(), skip);
        producer(&mut logup);
        dense_and(&mut logup, 0);
        dense_and(&mut logup, 1);
        producer(&mut logup);
        dense_range(&mut logup, 0);
        dense_range(&mut logup, 1);
        producer(&mut logup);
        logup.finalize()
    }

    /// The dead-row skip must produce BIT-IDENTICAL interaction columns (and
    /// the same claimed sum) as the always-combine reference on a real chip
    /// trace, across every builder path.
    #[test]
    fn dead_row_skip_is_bit_identical() {
        let trace = boundary_component_trace();
        let mut lookups = AllLookupElements::default();
        Blake2bBoundaryChip.draw_lookup_elements(&mut lookups, &mut Blake2sChannel::default());

        let (cols_skip, sum_skip) = replay_cols(&trace, &lookups, true);
        let (cols_ref, sum_ref) = replay_cols(&trace, &lookups, false);
        assert_eq!(sum_skip, sum_ref, "claimed sums differ");
        assert_eq!(cols_skip.len(), cols_ref.len(), "column count differs");
        for (i, (a, b)) in cols_skip.iter().zip(cols_ref.iter()).enumerate() {
            assert_eq!(
                a.values.to_cpu(),
                b.values.to_cpu(),
                "interaction column {i} differs bit-for-bit"
            );
        }
    }
}
