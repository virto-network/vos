//! Phase 54a/b — `MulChip`: per-multiplication-row chip.
//!
//! Phase 54a established the lookup wiring (CpuChip ↔ MulChip producer/
//! consumer balance over a 53-limb tuple).  Phase 54b moves the
//! schoolbook byte-level carry-chain constraint here, dropping
//! MulCarry[16] + MulCarryHi[16] from CpuChip.  CpuChip's
//! UnsignedProductLow/Hi/MulHigh witnesses are bound to MulChip's
//! pinned values via the lookup tuple.
//!
//! The schoolbook AIR has two arms:
//!   - 64-bit (16 positions): val_b[0..8] * val_d[0..8] = low[0..8]
//!     + mul_high[0..8] · 2^64 + (for is_mul_upper) unsigned_product_hi[0..8] · 2^128.
//!   - 32-bit (8 positions, low 4 input limbs):
//!     val_b[0..4] * val_d[0..4] = low[0..4] + mul_high[0..4] · 2^32.
//! Both share the same MulCarry / MulCarryHi 16-position carry chain
//! (each position can carry up to ~16 bits at busy middle positions).
//!
//! Phase 54c will move sign correction (Phase 12c) + result-variant
//! dispatch and finally drop UnsignedProductLow/Hi/MulHigh from CpuChip.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::qm31::SecureField,
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::WORD_SIZE;
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::BuiltInComponent,
    lookups::MultiplicationLookupElements,
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct MulChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Operand b (8 bytes, low-endian).
    #[size = 8]
    ValB,
    /// Operand d (8 bytes, low-endian).
    #[size = 8]
    ValD,
    /// Per-row result column (post-variant-dispatch).  Bound on CpuChip
    /// side; mirrored here through the lookup tuple.
    #[size = 8]
    Result,
    /// High 64 bits of the mul output (post-variant-dispatch).
    #[size = 8]
    MulHigh,
    /// Phase 54b: low 64 bits of the unsigned schoolbook product.
    #[size = 8]
    UnsignedProductLow,
    /// Phase 54b: high 64 bits of the unsigned schoolbook product
    /// (positions 8..15 from the 16-position chain).  Used by
    /// MulUpper variants.
    #[size = 8]
    UnsignedProductHi,
    /// Phase 54b: per-position low byte of the schoolbook carry.  16
    /// positions; reconstructed full carry = MulCarry + 256·MulCarryHi.
    #[size = 16]
    MulCarry,
    /// Phase 54b: per-position high byte of the schoolbook carry.
    #[size = 16]
    MulCarryHi,
    /// 1 iff this row is a low-output mul variant (Mul / ShloL / RotL/R).
    /// `IsMulLo + IsMulUpperUU + IsMulUpperSU + IsMulUpperSS` partitions
    /// the multiplication-row population.
    #[size = 1]
    IsMulLo,
    #[size = 1]
    IsMulUpperUU,
    #[size = 1]
    IsMulUpperSU,
    #[size = 1]
    IsMulUpperSS,
    /// 1 iff the operation operates on the low 32 bits.
    #[size = 1]
    Is32Bit,
    /// 1 iff this is a padding row (no real multiplication entry).
    #[size = 1]
    IsPadding,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "mul"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for MulChip {
    // Schoolbook constraint is degree 4 (`is_real * is_64bit *
    // is_mul_low * (val_b*val_d - ... )`), so eval domain needs
    // log_size + 2.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 2;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = MultiplicationLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &MultiplicationLookupElements,
    ) {
        let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let result = crate::trace::trace_eval!(trace_eval, Column::Result);
        let mul_high = crate::trace::trace_eval!(trace_eval, Column::MulHigh);
        let upl = crate::trace::trace_eval!(trace_eval, Column::UnsignedProductLow);
        let uph = crate::trace::trace_eval!(trace_eval, Column::UnsignedProductHi);
        let mul_carry = crate::trace::trace_eval!(trace_eval, Column::MulCarry);
        let mul_carry_hi = crate::trace::trace_eval!(trace_eval, Column::MulCarryHi);
        let is_mul_lo = crate::trace::trace_eval!(trace_eval, Column::IsMulLo);
        let is_mu_uu = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperUU);
        let is_mu_su = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSU);
        let is_mu_ss = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSS);
        let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
        let is_padding = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

        // Boolean constraints on flag columns.
        for flag in [&is_mul_lo, &is_mu_uu, &is_mu_su, &is_mu_ss, &is_32bit, &is_padding] {
            eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
        }

        let is_real = E::F::one() - is_padding[0].clone();
        let is_mul_upper_e = is_mu_uu[0].clone() + is_mu_su[0].clone() + is_mu_ss[0].clone();
        let is_64bit = E::F::one() - is_32bit[0].clone();

        // Partition: on a real (non-padding) row, exactly one variant flag is 1.
        let variant_sum = is_mul_lo[0].clone()
            + is_mu_uu[0].clone()
            + is_mu_su[0].clone()
            + is_mu_ss[0].clone();
        eval.add_constraint(is_real.clone() * (variant_sum.clone() - E::F::one()));
        // On padding rows all variant flags are 0 (lookup multiplicity = 0).
        eval.add_constraint(is_padding[0].clone() * variant_sum);

        // ── Phase 54b: schoolbook byte-level carry chain ──
        // 64-bit: val_b[0..8] * val_d[0..8] = upl[0..8] + ... · 2^64.
        // 32-bit: val_b[0..4] * val_d[0..4] = upl[0..4] + mul_high[0..4] · 2^32.
        let f256: E::F = E::F::from(BaseField::from(256));
        let full_carry = |k: usize| -> E::F {
            mul_carry[k].clone() + mul_carry_hi[k].clone() * f256.clone()
        };
        // 64-bit chain (16 positions).  Output mapping:
        //   Mul-lo (non-rotate): k<8 → upl[k], k≥8 → mul_high[k-8].
        //   MulUpper:            k<8 → mul_high[k] (= unsigned-low),
        //                        k≥8 → uph[k-8] (= unsigned-high).
        for k in 0..16usize {
            let mut partial_sum = E::F::zero();
            for i in 0..WORD_SIZE {
                let j = k.wrapping_sub(i);
                if j < WORD_SIZE {
                    partial_sum += val_b[i].clone() * val_d[j].clone();
                }
            }
            let carry_in = if k == 0 { E::F::zero() } else { full_carry(k - 1) };
            let out_normal = if k < 8 { upl[k].clone() } else { mul_high[k - 8].clone() };
            let out_upper = if k < 8 { mul_high[k].clone() } else { uph[k - 8].clone() };
            let c_normal = out_normal + full_carry(k) * f256.clone() - partial_sum.clone() - carry_in.clone();
            let c_upper = out_upper + full_carry(k) * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(is_real.clone() * is_64bit.clone() * is_mul_lo[0].clone() * c_normal);
            eval.add_constraint(is_real.clone() * is_64bit.clone() * is_mul_upper_e.clone() * c_upper);
        }
        // 32-bit chain (8 positions, low 4 input limbs).  Same output
        // mapping: k<4 → upl[k], k≥4 → mul_high[k-4].
        for k in 0..8usize {
            let mut partial_sum = E::F::zero();
            for i in 0..4usize {
                let j = k.wrapping_sub(i);
                if j < 4 {
                    partial_sum += val_b[i].clone() * val_d[j].clone();
                }
            }
            let carry_in = if k == 0 { E::F::zero() } else { full_carry(k - 1) };
            let out_byte = if k < 4 { upl[k].clone() } else { mul_high[k - 4].clone() };
            let c = out_byte + full_carry(k) * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(is_real.clone() * is_32bit[0].clone() * c);
        }

        // ── Lookup consumer ──
        // Tuple (53 limbs): val_b[8] + val_d[8] + result[8] + mul_high[8]
        //   + upl[8] + uph[8] + 5 flags.
        let mut tuple: Vec<E::F> = Vec::with_capacity(53);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.extend_from_slice(&mul_high);
        tuple.extend_from_slice(&upl);
        tuple.extend_from_slice(&uph);
        tuple.push(is_mul_lo[0].clone());
        tuple.push(is_mu_uu[0].clone());
        tuple.push(is_mu_su[0].clone());
        tuple.push(is_mu_ss[0].clone());
        tuple.push(is_32bit[0].clone());

        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
                (-is_real.clone()).into(),
                &tuple,
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for MulChip {
    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let entries = &side_note.mul_entries;
        // stwo's FFT path needs domain >= MIN_FFT_LOG_SIZE (5).  Eval
        // domain = log_size + LOG_CONSTRAINT_DEGREE_BOUND (= 2 here),
        // so log_size ≥ 4 would suffice, but the LogupTraceBuilder
        // requires `log_size >= LOG_N_LANES` (= 4) and we add a small
        // safety floor at 5 to keep the FFT path warm.
        const MIN_LOG_SIZE: u32 = 5;

        if entries.is_empty() {
            let log_size = LOG_N_LANES.max(MIN_LOG_SIZE);
            let mut trace = TraceBuilder::<Column>::new(log_size);
            for row in 0..trace.num_rows() {
                trace.fill_columns(row, true, Column::IsPadding);
            }
            return trace.finalize_bit_reversed();
        }

        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(entries.len()).max(MIN_LOG_SIZE);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for (row, e) in entries.iter().enumerate() {
            trace.fill_columns_bytes(row, &e.val_b.to_le_bytes(), Column::ValB);
            trace.fill_columns_bytes(row, &e.val_d.to_le_bytes(), Column::ValD);
            trace.fill_columns_bytes(row, &e.result.to_le_bytes(), Column::Result);
            trace.fill_columns_bytes(row, &e.mul_high.to_le_bytes(), Column::MulHigh);
            trace.fill_columns_bytes(row, &e.unsigned_product_low.to_le_bytes(), Column::UnsignedProductLow);
            trace.fill_columns_bytes(row, &e.unsigned_product_hi.to_le_bytes(), Column::UnsignedProductHi);
            trace.fill_columns_bytes(row, &e.mul_carry, Column::MulCarry);
            trace.fill_columns_bytes(row, &e.mul_carry_hi, Column::MulCarryHi);
            trace.fill_columns(row, e.is_mul_lo, Column::IsMulLo);
            trace.fill_columns(row, e.is_mul_upper_uu, Column::IsMulUpperUU);
            trace.fill_columns(row, e.is_mul_upper_su, Column::IsMulUpperSU);
            trace.fill_columns(row, e.is_mul_upper_ss, Column::IsMulUpperSS);
            trace.fill_columns(row, e.is_32bit, Column::Is32Bit);
            trace.fill_columns(row, false, Column::IsPadding);
        }

        for row in entries.len()..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let mul: &MultiplicationLookupElements = lookup_elements.as_ref();
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let result = crate::trace::original_base_column!(component_trace, Column::Result);
        let mul_high = crate::trace::original_base_column!(component_trace, Column::MulHigh);
        let upl = crate::trace::original_base_column!(component_trace, Column::UnsignedProductLow);
        let uph = crate::trace::original_base_column!(component_trace, Column::UnsignedProductHi);
        let is_mul_lo = crate::trace::original_base_column!(component_trace, Column::IsMulLo);
        let is_mu_uu = crate::trace::original_base_column!(component_trace, Column::IsMulUpperUU);
        let is_mu_su = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSU);
        let is_mu_ss = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSS);
        let is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.extend_from_slice(&mul_high);
        tuple.extend_from_slice(&upl);
        tuple.extend_from_slice(&uph);
        tuple.push(is_mul_lo[0].clone());
        tuple.push(is_mu_uu[0].clone());
        tuple.push(is_mu_su[0].clone());
        tuple.push(is_mu_ss[0].clone());
        tuple.push(is_32bit[0].clone());

        for _ in 0..2 {
            logup.add_to_relation_with(
                mul,
                [is_padding[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (-(PackedBaseField::one() - pad)).into()
                },
                &tuple,
            );
        }

        logup.finalize()
    }
}
