//! Phase 54a/b/c — `MulChip`: per-multiplication-row chip.
//!
//! Phase 54a established the lookup wiring (CpuChip ↔ MulChip producer/
//! consumer balance).  Phase 54b moved the schoolbook byte-level
//! carry-chain constraint here, dropping MulCarry/MulCarryHi from
//! CpuChip.  Phase 54c moves the Phase 12c MulUpper SS/SU sign-
//! correction here, dropping UnsignedProductHi/MulCorrTermA/B/Carry
//! from CpuChip.
//!
//! Lookup tuple (47 limbs): val_b[8] + val_d[8] + result[8] +
//! mul_high[8] + unsigned_product_low[8] + sign_bit_b + sign_bit_d +
//! 5 flags.  CpuChip witnesses val_b/val_d/result/mul_high/
//! unsigned_product_low + sign_bit_b/d (the latter two pinned by
//! CpuChip's existing nibble-AND lookups); MulChip's AIR pins them all
//! via the schoolbook + sign-correction chain.

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
    /// Per-row result column (post-variant-dispatch).
    #[size = 8]
    Result,
    /// High 64 bits of the mul output (post-variant-dispatch).
    #[size = 8]
    MulHigh,
    /// Phase 54b: low 64 bits of the unsigned schoolbook product.
    #[size = 8]
    UnsignedProductLow,
    /// Phase 54b: high 64 bits of the unsigned schoolbook product
    /// (positions 8..15 from the 16-position chain).
    #[size = 8]
    UnsignedProductHi,
    /// Phase 54b: per-position low byte of the schoolbook carry.  16
    /// positions; full carry = MulCarry + 256·MulCarryHi.
    #[size = 16]
    MulCarry,
    /// Phase 54b: per-position high byte of the schoolbook carry.
    #[size = 16]
    MulCarryHi,
    /// Phase 54c: sign-correction term `sa·val_d` (low 64 bits).
    /// `sa·val_d` for SU/SS rows; 0 for UU.
    #[size = 8]
    MulCorrTermA,
    /// Phase 54c: sign-correction term `sb·val_b` (low 64 bits).
    /// `sb·val_b` for SS rows; 0 for UU/SU.
    #[size = 8]
    MulCorrTermB,
    /// Phase 54c: per-byte carry chain for `result + term_a + term_b ≡
    /// unsigned_product_hi (mod 2^64)` on is_mul_upper rows.
    #[size = 8]
    MulCorrCarry,
    /// Phase 54c: bit 7 of val_b's MSB (sa).  Pinned by CpuChip's
    /// nibble-AND lookups; flowed in via the lookup tuple.
    #[size = 1]
    SignBitB,
    /// Phase 54c: bit 7 of val_d's MSB (sb).
    #[size = 1]
    SignBitD,
    /// Phase 54d: rotate-class flags driving result-variant dispatch.
    /// Pinned via the lookup tuple to CpuChip's IsRotate{L,R}{64,32}.
    #[size = 1]
    IsRotateL64,
    #[size = 1]
    IsRotateR64,
    #[size = 1]
    IsRotateL32,
    #[size = 1]
    IsRotateR32,
    /// 1 iff this row is a low-output mul variant.
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
    /// 1 iff this is a padding row.
    #[size = 1]
    IsPadding,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "mul"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for MulChip {
    // Schoolbook constraint is degree 4 (`is_real * is_64bit *
    // is_mul_lo * (val_b*val_d - ...)`).  Sign-correction term
    // pinning is `(mu_su + mu_ss) * (term_a - sign_bit_b * val_d[i])`
    // = degree 3.  Both fit log_size + 2.
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
        let term_a = crate::trace::trace_eval!(trace_eval, Column::MulCorrTermA);
        let term_b = crate::trace::trace_eval!(trace_eval, Column::MulCorrTermB);
        let corr_carry = crate::trace::trace_eval!(trace_eval, Column::MulCorrCarry);
        let sign_bit_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
        let sign_bit_d = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
        let is_rot_l64 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL64);
        let is_rot_r64 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR64);
        let is_rot_l32 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL32);
        let is_rot_r32 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR32);
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
        // sign_bit_b/d are pinned to bit 7 of val_b/val_d's MSB by
        // CpuChip's existing nibble-AND lookups; lookup balance flows
        // them through.  No need to re-pin here.

        let is_real = E::F::one() - is_padding[0].clone();
        let is_mul_upper_e = is_mu_uu[0].clone() + is_mu_su[0].clone() + is_mu_ss[0].clone();
        let is_64bit = E::F::one() - is_32bit[0].clone();

        // Partition: on a real row, exactly one variant flag is 1.
        let variant_sum = is_mul_lo[0].clone()
            + is_mu_uu[0].clone()
            + is_mu_su[0].clone()
            + is_mu_ss[0].clone();
        eval.add_constraint(is_real.clone() * (variant_sum.clone() - E::F::one()));
        eval.add_constraint(is_padding[0].clone() * variant_sum);

        // ── Phase 54b: schoolbook byte-level carry chain ──
        let f256: E::F = E::F::from(BaseField::from(256));
        let full_carry = |k: usize| -> E::F {
            mul_carry[k].clone() + mul_carry_hi[k].clone() * f256.clone()
        };
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

        // ── Phase 54c: Phase 12c MulUpper SS/SU sign-correction ──
        //   high(a_s × b_s) ≡ high(a_u × b_u) − sa·b_u − sb·a_u  (mod 2^64)
        // Materialised as `result + term_a + term_b ≡ uph (mod 2^64)`
        // with byte-level carry chain.  TermA/B definitions:
        //   TermA[i]: SU/SS → sa·val_d[i]; UU → 0.
        //   TermB[i]: SS    → sb·val_b[i]; UU/SU → 0.
        for i in 0..WORD_SIZE {
            // TermA:
            eval.add_constraint(
                (is_mu_su[0].clone() + is_mu_ss[0].clone())
                    * (term_a[i].clone() - sign_bit_b[0].clone() * val_d[i].clone())
            );
            eval.add_constraint(is_mu_uu[0].clone() * term_a[i].clone());
            // TermB:
            eval.add_constraint(
                is_mu_ss[0].clone()
                    * (term_b[i].clone() - sign_bit_d[0].clone() * val_b[i].clone())
            );
            eval.add_constraint((is_mu_uu[0].clone() + is_mu_su[0].clone()) * term_b[i].clone());
        }
        // Result-binding sum with byte-level carry chain.
        // uph[i] + carry_out[i]·256 = result[i] + term_a[i] + term_b[i] + carry_in[i]
        // gated on is_mul_upper.
        for i in 0..WORD_SIZE {
            let carry_in: E::F = if i == 0 {
                E::F::zero()
            } else {
                corr_carry[i - 1].clone()
            };
            eval.add_constraint(
                is_mul_upper_e.clone() * (
                    uph[i].clone()
                        + corr_carry[i].clone() * f256.clone()
                        - result[i].clone()
                        - term_a[i].clone()
                        - term_b[i].clone()
                        - carry_in
                )
            );
        }

        // ── Phase 54d: result-variant dispatch (Phase 32/36 binding) ──
        // For non-rotate is_mul_lo 64-bit: result[i] = upl[i].
        // For RotL64 / RotR64: result[i] = upl[i] + mul_high[i] (byte-wise
        //   sum, no carry — bits non-overlapping by construction of rotation).
        // For non-rotate is_mul_lo 32-bit: result[0..4] = upl[0..4].
        // For RotL32 / RotR32: result[0..4] = upl[0..4] + mul_high[0..4].
        // 32-bit upper result limbs (i ∈ 4..8) are pinned by CpuChip's
        // Phase 19 sign-extension constraint (still on CpuChip side).
        {
            let one_minus_rotate_64 = E::F::one()
                - is_rot_l64[0].clone()
                - is_rot_r64[0].clone();
            let is_rotate_64_either = is_rot_l64[0].clone() + is_rot_r64[0].clone();
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_real.clone() * is_64bit.clone() * is_mul_lo[0].clone()
                        * one_minus_rotate_64.clone()
                        * (result[i].clone() - upl[i].clone())
                );
                eval.add_constraint(
                    is_rotate_64_either.clone()
                        * (result[i].clone() - upl[i].clone() - mul_high[i].clone())
                );
            }
            let one_minus_rotate_32 = E::F::one()
                - is_rot_l32[0].clone()
                - is_rot_r32[0].clone();
            let is_rotate_32_either = is_rot_l32[0].clone() + is_rot_r32[0].clone();
            for i in 0..4 {
                eval.add_constraint(
                    is_real.clone() * is_32bit[0].clone()
                        * one_minus_rotate_32.clone()
                        * (result[i].clone() - upl[i].clone())
                );
                eval.add_constraint(
                    is_rotate_32_either.clone()
                        * (result[i].clone() - upl[i].clone() - mul_high[i].clone())
                );
            }
        }

        // ── Lookup consumer ──
        // Tuple (35 limbs): val_b[8] + val_d[8] + result[8] +
        //   sign_bit_b + sign_bit_d + 4 rotate flags + 5 mul flags.
        let mut tuple: Vec<E::F> = Vec::with_capacity(35);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.push(sign_bit_b[0].clone());
        tuple.push(sign_bit_d[0].clone());
        tuple.push(is_rot_l64[0].clone());
        tuple.push(is_rot_r64[0].clone());
        tuple.push(is_rot_l32[0].clone());
        tuple.push(is_rot_r32[0].clone());
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
            trace.fill_columns_bytes(row, &e.mul_corr_term_a, Column::MulCorrTermA);
            trace.fill_columns_bytes(row, &e.mul_corr_term_b, Column::MulCorrTermB);
            trace.fill_columns_bytes(row, &e.mul_corr_carry, Column::MulCorrCarry);
            trace.fill_columns(row, e.sign_bit_b, Column::SignBitB);
            trace.fill_columns(row, e.sign_bit_d, Column::SignBitD);
            trace.fill_columns(row, e.is_rotate_l64, Column::IsRotateL64);
            trace.fill_columns(row, e.is_rotate_r64, Column::IsRotateR64);
            trace.fill_columns(row, e.is_rotate_l32, Column::IsRotateL32);
            trace.fill_columns(row, e.is_rotate_r32, Column::IsRotateR32);
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
        let sign_bit_b = crate::trace::original_base_column!(component_trace, Column::SignBitB);
        let sign_bit_d = crate::trace::original_base_column!(component_trace, Column::SignBitD);
        let is_rot_l64 = crate::trace::original_base_column!(component_trace, Column::IsRotateL64);
        let is_rot_r64 = crate::trace::original_base_column!(component_trace, Column::IsRotateR64);
        let is_rot_l32 = crate::trace::original_base_column!(component_trace, Column::IsRotateL32);
        let is_rot_r32 = crate::trace::original_base_column!(component_trace, Column::IsRotateR32);
        let is_mul_lo = crate::trace::original_base_column!(component_trace, Column::IsMulLo);
        let is_mu_uu = crate::trace::original_base_column!(component_trace, Column::IsMulUpperUU);
        let is_mu_su = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSU);
        let is_mu_ss = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSS);
        let is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.push(sign_bit_b[0].clone());
        tuple.push(sign_bit_d[0].clone());
        tuple.push(is_rot_l64[0].clone());
        tuple.push(is_rot_r64[0].clone());
        tuple.push(is_rot_l32[0].clone());
        tuple.push(is_rot_r32[0].clone());
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
