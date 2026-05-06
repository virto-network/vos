//! Phase 54g / 54i / 54k / 54j-redux — `DivRemChip`: per-divrem-row chip.
//!
//! CpuChip emits one DivRemLookup producer per `is_div_rem=1` row;
//! DivRemChip consumes once per real row.  DivRemChip witnesses
//! three carry chains internally:
//!
//!   1. (54g) Schoolbook `q·d + r = b` (low 8 bytes) /
//!      `q·d + r = div_corr_hi mod 2^64` (high 8 bytes), in both
//!      64-bit and 32-bit forms.
//!   2. (54i) Unsigned `r < d` uniqueness on
//!      `is_div_rem · ¬div_by_zero · ¬is_div_s` rows.
//!   3. (54k) DivS sign-correction chain pinning DivCorrHi to
//!      `sq·d + sd·q + sr − sb (mod 2^64)` on
//!      `is_div_rem · ¬div_by_zero · is_div_s` rows.  64-bit chain
//!      covers all 8 bytes; 32-bit chain covers low 4.
//!
//! Phase 54j-redux adds the full Phase 30 |val_d|<|div_remainder|
//! chain (was on CpuChip).  The two's-complement conditional
//! negation chains compute AbsD/AbsR from val_d/div_remainder
//! gated on sign_bit_d/sign_bit_r (flowed from CpuChip via the
//! lookup tuple); the AbsCmp chain pins |val_d|>|div_remainder|
//! on signed-div rows.  Per-byte Range256 emissions on DivCmpDiff
//! and AbsCmpDiff enforce byte range.
//!
//! Lookup tuple (40 limbs): val_b[8] + val_d[8] + div_quotient[8] +
//! div_remainder[8] + sign_bit_b + sign_bit_d + sign_bit_q +
//! sign_bit_r + is_div_rem + div_by_zero + is_32bit + is_div_s.

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
    lookups::{DivRemLookupElements, Range256LookupElements},
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct DivRemChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    #[size = 8]
    ValB,
    #[size = 8]
    ValD,
    #[size = 8]
    DivQuotient,
    #[size = 8]
    DivRemainder,
    /// High 8 bytes of the schoolbook output (DivS sign correction
    /// target on signed div rows; 0 on unsigned div rows).  Pinned
    /// CpuChip-side; flowed via the lookup tuple.
    #[size = 8]
    DivCorrHi,
    /// Per-position low byte of the schoolbook carry (16 positions).
    #[size = 16]
    DivMulCarry,
    /// Per-position high byte; full carry = DivMulCarry + 256·DivMulCarryHi.
    #[size = 16]
    DivMulCarryHi,
    #[size = 1]
    IsDivRem,
    #[size = 1]
    DivByZero,
    #[size = 1]
    Is32Bit,
    /// Phase 54i: signed-div flag (flowed via the lookup tuple).  Gates
    /// the unsigned r<d uniqueness chain off so DivS rows aren't forced
    /// through the unsigned predicate (DivS uses |r|<|d| separately —
    /// Phase 30 / 54j).
    #[size = 1]
    IsDivS,
    /// Phase 54i: per-byte `val_d + ~div_remainder + 1` chain witness
    /// (used on unsigned div rows to pin r < d).  Range-checked via
    /// Range256 on every real row.
    #[size = 8]
    DivCmpDiff,
    /// Phase 54i: per-byte boolean carry of the chain.  Top carry = 1
    /// on unsigned div rows.
    #[size = 8]
    DivCmpCarry,
    /// Phase 54k: per-byte carry of the DivS sign-correction chain.
    /// Boolean per byte.
    #[size = 8]
    DivCorrCarry,
    /// Phase 54k: 4 sign bits flowed from CpuChip via the lookup
    /// tuple.  Used by the Phase 16/18 sign-correction chain (54k)
    /// and the Phase 30 conditional-negation chain (54j-redux).
    #[size = 1]
    SignBitB,
    #[size = 1]
    SignBitD,
    #[size = 1]
    SignBitQ,
    #[size = 1]
    SignBitR,
    /// Phase 54j-redux: |val_d| via two's-complement negation gated
    /// on sign_bit_d.  Internal witness; not flowed.
    #[size = 8]
    AbsD,
    #[size = 8]
    AbsDCarry,
    /// Phase 54j-redux: |div_remainder| via two's-complement negation
    /// gated on sign_bit_r.
    #[size = 8]
    AbsR,
    #[size = 8]
    AbsRCarry,
    /// Phase 54j-redux: per-byte `abs_d + ~abs_r + 1` chain witness.
    /// Range-checked via Range256.  Top carry forced to 1 on signed
    /// div rows (`is_div_rem · ¬div_by_zero · is_div_s`).
    #[size = 8]
    AbsCmpDiff,
    #[size = 8]
    AbsCmpCarry,
    #[size = 1]
    IsPadding,

    // ── Phase I-divrem Stwo-v2.x degree-flatten helpers ──
    //
    // DivRemChip's natural form has constraints at degree 3-6, primarily
    // because the gating chains use up to 4 binary flags before
    // multiplying the constraint body.  Helpers below materialise each
    // multi-flag selector and the schoolbook quadratic body so every
    // gated constraint factors into (deg 1 column ref) × (deg 1 body).

    /// `IsDivRem · (1 - DivByZero)` — div is "active" (non-zero divisor).
    #[size = 1] DivActiveH,
    /// `(1 - IsPadding) · DivActiveH` — real row + active div.
    #[size = 1] NotPaddingDivH,
    /// `NotPaddingDivH · Is64Bit` (Is64Bit = 1 - Is32Bit).
    #[size = 1] DivActive64H,
    /// `NotPaddingDivH · Is32Bit`.
    #[size = 1] DivActive32H,
    /// `NotPaddingDivH · (1 - IsDivS)` — unsigned-div uniqueness chain gate.
    #[size = 1] DivUActiveH,
    /// `NotPaddingDivH · IsDivS` — signed-div sign-correction gate.
    #[size = 1] DivSActiveH,
    /// `DivSActiveH · Is64Bit`, `DivSActiveH · Is32Bit` —
    /// per-width signed-div gates.
    #[size = 1] DivS64H,
    #[size = 1] DivS32H,
    /// `(1 - IsPadding) · (1 - SignBitD)` and `(1 - IsPadding) · SignBitD`
    /// — split AbsD chain gates by the conditional-negation case.
    #[size = 1] RealNotSdH,
    #[size = 1] RealSdH,
    /// Same shape on SignBitR for the AbsR chain.
    #[size = 1] RealNotSrH,
    #[size = 1] RealSrH,

    /// 64-bit schoolbook partial-sum helper: `DivPartialSum64[k] :=
    /// Σ_{i+j=k, i,j<8} DivQuotient[i] · ValD[j]` (deg 2 def).  k=0..16.
    #[size = 16] DivPartialSum64,
    /// 32-bit schoolbook partial-sum helper, k=0..8 with i,j<4.
    #[size = 8] DivPartialSum32,

    /// `DivCmpCarry[i] · (1 - DivCmpCarry[i])` — boolean witness for
    /// the unsigned r<d uniqueness chain's per-byte carry.  `is_real ·
    /// boolean` becomes deg-2 via this helper instead of deg-3 inline.
    #[size = 8] DivCmpCarryB,

    /// DivS chain quadratic body helpers (Phase 54k flatten).
    /// `SignQValDH[i] := SignBitQ · ValD[i]`
    #[size = 8] SignQValDH,
    /// `SignDQuotH[i] := SignBitD · DivQuotient[i]`
    #[size = 8] SignDQuotH,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "divrem"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for DivRemChip {
    /// Phase I-divrem flatten: dropped from 3 back to 2 — every
    /// degree-3+ constraint has been lifted via helper columns
    /// (DivActiveH, DivS64H, DivCmpCarryB, DivPartialSum64/32, etc.) so
    /// the chip's actual algebraic degree is now ≤ 2.  Stwo v2.x's
    /// lifted protocol enforces actual degree, not declared bound, but
    /// we keep the declared bound aligned for clarity.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 2;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (DivRemLookupElements, Range256LookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(DivRemLookupElements, Range256LookupElements),
    ) {
        let (divrem_lookup, range256_lookup) = lookup_elements;
        let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let div_quotient = crate::trace::trace_eval!(trace_eval, Column::DivQuotient);
        let div_remainder = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
        let div_corr_hi = crate::trace::trace_eval!(trace_eval, Column::DivCorrHi);
        let mul_carry = crate::trace::trace_eval!(trace_eval, Column::DivMulCarry);
        let mul_carry_hi = crate::trace::trace_eval!(trace_eval, Column::DivMulCarryHi);
        let is_div_rem = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
        let div_by_zero = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
        let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
        let is_div_s = crate::trace::trace_eval!(trace_eval, Column::IsDivS);
        let div_cmp_diff = crate::trace::trace_eval!(trace_eval, Column::DivCmpDiff);
        let div_cmp_carry = crate::trace::trace_eval!(trace_eval, Column::DivCmpCarry);
        let div_corr_carry = crate::trace::trace_eval!(trace_eval, Column::DivCorrCarry);
        let sign_bit_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
        let sign_bit_d = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
        let sign_bit_q = crate::trace::trace_eval!(trace_eval, Column::SignBitQ);
        let sign_bit_r = crate::trace::trace_eval!(trace_eval, Column::SignBitR);
        let abs_d = crate::trace::trace_eval!(trace_eval, Column::AbsD);
        let abs_d_carry = crate::trace::trace_eval!(trace_eval, Column::AbsDCarry);
        let abs_r = crate::trace::trace_eval!(trace_eval, Column::AbsR);
        let abs_r_carry = crate::trace::trace_eval!(trace_eval, Column::AbsRCarry);
        let abs_cmp_diff = crate::trace::trace_eval!(trace_eval, Column::AbsCmpDiff);
        let abs_cmp_carry = crate::trace::trace_eval!(trace_eval, Column::AbsCmpCarry);
        let is_padding = crate::trace::trace_eval!(trace_eval, Column::IsPadding);

        // ── Phase I-divrem degree-flatten helpers ──
        let div_active_h = crate::trace::trace_eval!(trace_eval, Column::DivActiveH);
        let not_padding_div_h = crate::trace::trace_eval!(trace_eval, Column::NotPaddingDivH);
        let div_active_64_h = crate::trace::trace_eval!(trace_eval, Column::DivActive64H);
        let div_active_32_h = crate::trace::trace_eval!(trace_eval, Column::DivActive32H);
        let div_u_active_h = crate::trace::trace_eval!(trace_eval, Column::DivUActiveH);
        let div_s_active_h = crate::trace::trace_eval!(trace_eval, Column::DivSActiveH);
        let div_s_64_h = crate::trace::trace_eval!(trace_eval, Column::DivS64H);
        let div_s_32_h = crate::trace::trace_eval!(trace_eval, Column::DivS32H);
        let real_not_sd_h = crate::trace::trace_eval!(trace_eval, Column::RealNotSdH);
        let real_sd_h = crate::trace::trace_eval!(trace_eval, Column::RealSdH);
        let real_not_sr_h = crate::trace::trace_eval!(trace_eval, Column::RealNotSrH);
        let real_sr_h = crate::trace::trace_eval!(trace_eval, Column::RealSrH);
        let div_partial_sum_64 = crate::trace::trace_eval!(trace_eval, Column::DivPartialSum64);
        let div_partial_sum_32 = crate::trace::trace_eval!(trace_eval, Column::DivPartialSum32);
        let div_cmp_carry_b = crate::trace::trace_eval!(trace_eval, Column::DivCmpCarryB);

        // Boolean constraints on flag columns.
        for flag in [
            &is_div_rem, &div_by_zero, &is_32bit, &is_div_s,
            &sign_bit_b, &sign_bit_d, &sign_bit_q, &sign_bit_r,
            &is_padding,
        ] {
            eval.add_constraint(flag[0].clone() * (E::F::one() - flag[0].clone()));
        }
        let is_real = E::F::one() - is_padding[0].clone();
        let is_64bit = E::F::one() - is_32bit[0].clone();
        let div_active = is_div_rem[0].clone() * (E::F::one() - div_by_zero[0].clone());

        // ── Phase I-divrem helper-defining constraints ──
        eval.add_constraint(
            div_active_h[0].clone() - is_div_rem[0].clone() * (E::F::one() - div_by_zero[0].clone())
        );
        eval.add_constraint(
            not_padding_div_h[0].clone() - is_real.clone() * div_active_h[0].clone()
        );
        eval.add_constraint(
            div_active_64_h[0].clone() - not_padding_div_h[0].clone() * is_64bit.clone()
        );
        eval.add_constraint(
            div_active_32_h[0].clone() - not_padding_div_h[0].clone() * is_32bit[0].clone()
        );
        eval.add_constraint(
            div_u_active_h[0].clone()
                - not_padding_div_h[0].clone() * (E::F::one() - is_div_s[0].clone())
        );
        eval.add_constraint(
            div_s_active_h[0].clone() - not_padding_div_h[0].clone() * is_div_s[0].clone()
        );
        eval.add_constraint(
            div_s_64_h[0].clone() - div_s_active_h[0].clone() * is_64bit.clone()
        );
        eval.add_constraint(
            div_s_32_h[0].clone() - div_s_active_h[0].clone() * is_32bit[0].clone()
        );
        eval.add_constraint(
            real_not_sd_h[0].clone() - is_real.clone() * (E::F::one() - sign_bit_d[0].clone())
        );
        eval.add_constraint(
            real_sd_h[0].clone() - is_real.clone() * sign_bit_d[0].clone()
        );
        eval.add_constraint(
            real_not_sr_h[0].clone() - is_real.clone() * (E::F::one() - sign_bit_r[0].clone())
        );
        eval.add_constraint(
            real_sr_h[0].clone() - is_real.clone() * sign_bit_r[0].clone()
        );
        // Partial-sum bodies (deg 2 def) — without div_remainder term;
        // the schoolbook constraint adds it inline since it's already linear.
        for k in 0..16usize {
            let mut psum = E::F::zero();
            for i in 0..WORD_SIZE {
                let j = k.wrapping_sub(i);
                if j < WORD_SIZE {
                    psum += div_quotient[i].clone() * val_d[j].clone();
                }
            }
            eval.add_constraint(div_partial_sum_64[k].clone() - psum);
        }
        for k in 0..8usize {
            let mut psum = E::F::zero();
            for i in 0..4usize {
                let j = k.wrapping_sub(i);
                if j < 4 {
                    psum += div_quotient[i].clone() * val_d[j].clone();
                }
            }
            eval.add_constraint(div_partial_sum_32[k].clone() - psum);
        }
        // DivCmpCarry boolean witness (deg 2 def).
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                div_cmp_carry_b[i].clone()
                    - div_cmp_carry[i].clone()
                        * (E::F::one() - div_cmp_carry[i].clone())
            );
        }
        let _ = div_active; // helpers above replace it everywhere below

        // ── Phase 54g: schoolbook carry chain ──
        let f256: E::F = E::F::from(BaseField::from(256));
        let full_carry = |k: usize| -> E::F {
            mul_carry[k].clone() + mul_carry_hi[k].clone() * f256.clone()
        };

        // 64-bit chain (16 positions).  Low 8 → val_b; high 8 → div_corr_hi.
        // Phase I-divrem flatten: gate is DivActive64H (deg 1 helper);
        // partial-sum body lifted into DivPartialSum64[k] (deg 1 helper).
        for k in 0..16usize {
            let rem_term = if k < WORD_SIZE {
                div_remainder[k].clone()
            } else {
                E::F::zero()
            };
            let carry_in = if k == 0 { E::F::zero() } else { full_carry(k - 1) };
            let expected = if k < WORD_SIZE {
                val_b[k].clone()
            } else {
                div_corr_hi[k - WORD_SIZE].clone()
            };
            let c = expected + full_carry(k) * f256.clone()
                - div_partial_sum_64[k].clone() - rem_term - carry_in;
            eval.add_constraint(div_active_64_h[0].clone() * c);
        }

        // 32-bit chain (8 positions).  Low 4 → val_b; high 4 → div_corr_hi.
        for k in 0..8usize {
            let rem_term = if k < 4 { div_remainder[k].clone() } else { E::F::zero() };
            let carry_in = if k == 0 { E::F::zero() } else { full_carry(k - 1) };
            let expected = if k < 4 {
                val_b[k].clone()
            } else {
                div_corr_hi[k - 4].clone()
            };
            let c = expected + full_carry(k) * f256.clone()
                - div_partial_sum_32[k].clone() - rem_term - carry_in;
            eval.add_constraint(div_active_32_h[0].clone() * c);
        }

        // ── Phase 54i: r < d uniqueness chain (unsigned div rows) ──
        // Encoded as the carry chain for `val_d - 1 - div_remainder`
        // (= `val_d + ~div_remainder` with carry_in[0] = 0).  The top
        // carry is 1 iff `val_d > div_remainder`.  Without this, the
        // schoolbook q·d+r=b alone admits (q-1, r+d) as another valid
        // pair — see CpuChip's prior comment block at the same spot.
        // Boolean carry on every real row so the column can't drift
        // even when div_u_active=0.
        // Phase I-divrem flatten: boolean carry pinned via DivCmpCarryB
        // helper; gate becomes is_real · helper (deg 2).
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_real.clone() * div_cmp_carry_b[i].clone());
        }
        // Carry chain — gate is DivUActiveH (deg 1 helper).
        let f_255: E::F = E::F::from(BaseField::from(255));
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                div_cmp_carry[i - 1].clone()
            };
            eval.add_constraint(
                div_u_active_h[0].clone() * (
                    div_cmp_diff[i].clone()
                        + div_cmp_carry[i].clone() * f256.clone()
                        - val_d[i].clone()
                        - f_255.clone()
                        + div_remainder[i].clone()
                        - carry_in
                )
            );
        }
        // Top carry must be 1 (val_d > div_remainder ⇔ r < d).
        eval.add_constraint(
            div_u_active_h[0].clone() * (E::F::one() - div_cmp_carry[WORD_SIZE - 1].clone())
        );

        // ── Phase 54k: DivS sign-correction chain ──
        // Was Phase 16/18 on CpuChip.  Pins
        //   div_corr_hi[i] + div_corr_carry[i]·256 + (i==0 ? sb : 0)
        //     = sq·val_d[i] + sd·div_quotient[i] + carry_in + (i==0 ? sr : 0)
        // on `is_real · is_div_rem · ¬div_by_zero · is_div_s` rows.
        // 64-bit chain over all 8 bytes; 32-bit chain over low 4 bytes.
        //
        // No boolean constraint on DivCorrCarry: the trace fill writes
        // carry values in {-1, 0, 1, 2} (see CpuChip trace_fill.rs's
        // Phase 16 block, lines 706-712 region), which are not boolean.
        // The original CpuChip Phase 16/18 had no boolean here either —
        // div_corr_hi is range-checked implicitly via the schoolbook
        // chain (its bytes are bytes of high(q·d+r) mod 2^64), and the
        // prover's freedom in div_corr_carry doesn't enable false
        // proofs given the schoolbook + chain identities.
        // Phase I-divrem flatten: gate via DivS64H / DivS32H (deg 1
        // helpers).  Body has `sign_bit_q · val_d[i]` and `sign_bit_d ·
        // div_quotient[i]` quadratic terms — but they're already deg 2
        // and gated by deg-1 helper, so total deg 3.  STILL TOO HIGH —
        // need body helpers too.
        // Materialise SignQ_ValD[i] and SignD_DivQ[i] inline in the
        // helper-defining section above… actually, easier: the gate is
        // deg 1 (helper), the body has terms like `sign_bit_q · val_d[i]`
        // (deg 2), so total = deg 3.  Need to lift the body too.
        //
        // Use two more body helpers for the DivS chain:
        //   sign_q_d[i]  := sign_bit_q · val_d[i]
        //   sign_d_q[i]  := sign_bit_d · div_quotient[i]
        // Then body = div_corr_hi + div_corr_carry·256 + extra_lhs -
        //             sign_q_d[i] - sign_d_q[i] - carry_in - extra_rhs
        // becomes linear, gate × body = deg 2.
        let sign_q_d = crate::trace::trace_eval!(trace_eval, Column::SignQValDH);
        let sign_d_q = crate::trace::trace_eval!(trace_eval, Column::SignDQuotH);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                sign_q_d[i].clone() - sign_bit_q[0].clone() * val_d[i].clone()
            );
            eval.add_constraint(
                sign_d_q[i].clone() - sign_bit_d[0].clone() * div_quotient[i].clone()
            );
        }
        // 64-bit chain.
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                div_corr_carry[i - 1].clone()
            };
            let extra_lhs = if i == 0 { sign_bit_b[0].clone() } else { E::F::zero() };
            let extra_rhs = if i == 0 { sign_bit_r[0].clone() } else { E::F::zero() };
            eval.add_constraint(
                div_s_64_h[0].clone() * (
                    div_corr_hi[i].clone()
                        + div_corr_carry[i].clone() * f256.clone()
                        + extra_lhs
                        - sign_q_d[i].clone()
                        - sign_d_q[i].clone()
                        - carry_in
                        - extra_rhs
                )
            );
        }
        // 32-bit chain (low 4 bytes only).
        for i in 0..4 {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                div_corr_carry[i - 1].clone()
            };
            let extra_lhs = if i == 0 { sign_bit_b[0].clone() } else { E::F::zero() };
            let extra_rhs = if i == 0 { sign_bit_r[0].clone() } else { E::F::zero() };
            eval.add_constraint(
                div_s_32_h[0].clone() * (
                    div_corr_hi[i].clone()
                        + div_corr_carry[i].clone() * f256.clone()
                        + extra_lhs
                        - sign_q_d[i].clone()
                        - sign_d_q[i].clone()
                        - carry_in
                        - extra_rhs
                )
            );
        }

        // ── Phase 54j-redux: |val_d| / |div_remainder| via two's-
        // complement conditional negation + |val_d|>|div_remainder|
        // comparison chain (was Phase 30 on CpuChip) ──
        //
        // Conditional negation per value X (one of val_d, div_remainder):
        //   sign(X) = 0: Abs[i] = X[i],  AbsCarry[i] = 0
        //   sign(X) = 1: Abs[i] + AbsCarry[i]·256 = (255 − X[i]) + carry_in
        //                 with carry_in[0] = 1 (the +1 of two's complement).
        // Phase I-divrem flatten: AbsD/AbsR conditional negation chains
        // gated via RealNotSdH / RealSdH (and Sr counterparts).  Each is
        // a deg-1 helper; chain bodies are linear.
        let f_255: E::F = E::F::from(BaseField::from(255));
        // AbsD chain.
        for i in 0..WORD_SIZE {
            // sign_bit_d = 0 ⇒ AbsD[i] = val_d[i], AbsDCarry[i] = 0.
            eval.add_constraint(
                real_not_sd_h[0].clone() * (abs_d[i].clone() - val_d[i].clone())
            );
            eval.add_constraint(
                real_not_sd_h[0].clone() * abs_d_carry[i].clone()
            );
            // sign_bit_d = 1 ⇒ chain.
            let neg_carry_in = if i == 0 {
                E::F::one()
            } else {
                abs_d_carry[i - 1].clone()
            };
            eval.add_constraint(
                real_sd_h[0].clone() * (
                    abs_d[i].clone()
                        + abs_d_carry[i].clone() * f256.clone()
                        - f_255.clone()
                        + val_d[i].clone()
                        - neg_carry_in
                )
            );
        }
        // AbsR chain (same shape on div_remainder, sign_bit_r).
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                real_not_sr_h[0].clone() * (abs_r[i].clone() - div_remainder[i].clone())
            );
            eval.add_constraint(
                real_not_sr_h[0].clone() * abs_r_carry[i].clone()
            );
            let neg_carry_in = if i == 0 {
                E::F::one()
            } else {
                abs_r_carry[i - 1].clone()
            };
            eval.add_constraint(
                real_sr_h[0].clone() * (
                    abs_r[i].clone()
                        + abs_r_carry[i].clone() * f256.clone()
                        - f_255.clone()
                        + div_remainder[i].clone()
                        - neg_carry_in
                )
            );
        }
        // AbsCmp chain: |val_d| > |div_remainder| iff (AbsD − 1 − AbsR) ≥ 0.
        // Encoded as `AbsD + ~AbsR` (carry_in[0] = 0); top carry = 1
        // forced on `is_div_rem · ¬div_by_zero · is_div_s` rows.
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                abs_cmp_carry[i - 1].clone()
            };
            eval.add_constraint(
                is_real.clone() * (
                    abs_cmp_diff[i].clone()
                        + abs_cmp_carry[i].clone() * f256.clone()
                        - abs_d[i].clone()
                        - f_255.clone()
                        + abs_r[i].clone()
                        - carry_in
                )
            );
        }
        // Top carry = 1 on signed-div rows.  Phase I-divrem: gate via
        // DivSActiveH (deg 1 helper).
        eval.add_constraint(
            div_s_active_h[0].clone() * (E::F::one() - abs_cmp_carry[WORD_SIZE - 1].clone())
        );

        // Range256 emissions on DivCmpDiff bytes.  8 emissions per real
        // row, gated by is_real (paired with AbsCmpDiff below for the
        // even-count requirement of finalize_logup_in_pairs).
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                &[div_cmp_diff[i].clone()],
            ));
        }
        // Range256 emissions on AbsCmpDiff bytes (8 per real row).
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                &[abs_cmp_diff[i].clone()],
            ));
        }

        // ── Lookup consumer ──
        let mut tuple: Vec<E::F> = Vec::with_capacity(40);
        tuple.extend_from_slice(&val_b);
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&div_quotient);
        tuple.extend_from_slice(&div_remainder);
        tuple.push(sign_bit_b[0].clone());
        tuple.push(sign_bit_d[0].clone());
        tuple.push(sign_bit_q[0].clone());
        tuple.push(sign_bit_r[0].clone());
        tuple.push(is_div_rem[0].clone());
        tuple.push(div_by_zero[0].clone());
        tuple.push(is_32bit[0].clone());
        tuple.push(is_div_s[0].clone());

        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                divrem_lookup,
                (-is_real.clone()).into(),
                &tuple,
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for DivRemChip {
    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let entries = &side_note.divrem_entries;
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
            trace.fill_columns_bytes(row, &e.div_quotient.to_le_bytes(), Column::DivQuotient);
            trace.fill_columns_bytes(row, &e.div_remainder.to_le_bytes(), Column::DivRemainder);
            trace.fill_columns_bytes(row, &e.div_corr_hi, Column::DivCorrHi);
            trace.fill_columns_bytes(row, &e.div_mul_carry, Column::DivMulCarry);
            trace.fill_columns_bytes(row, &e.div_mul_carry_hi, Column::DivMulCarryHi);
            trace.fill_columns(row, true, Column::IsDivRem);
            trace.fill_columns(row, e.div_by_zero, Column::DivByZero);
            trace.fill_columns(row, e.is_32bit, Column::Is32Bit);
            trace.fill_columns(row, e.is_div_s, Column::IsDivS);
            trace.fill_columns_bytes(row, &e.div_cmp_diff, Column::DivCmpDiff);
            trace.fill_columns_bytes(row, &e.div_cmp_carry, Column::DivCmpCarry);
            trace.fill_columns_bytes(row, &e.div_corr_carry, Column::DivCorrCarry);
            trace.fill_columns(row, e.sign_bit_b, Column::SignBitB);
            trace.fill_columns(row, e.sign_bit_d, Column::SignBitD);
            trace.fill_columns(row, e.sign_bit_q, Column::SignBitQ);
            trace.fill_columns(row, e.sign_bit_r, Column::SignBitR);
            trace.fill_columns_bytes(row, &e.abs_d, Column::AbsD);
            trace.fill_columns_bytes(row, &e.abs_d_carry, Column::AbsDCarry);
            trace.fill_columns_bytes(row, &e.abs_r, Column::AbsR);
            trace.fill_columns_bytes(row, &e.abs_r_carry, Column::AbsRCarry);
            trace.fill_columns_bytes(row, &e.abs_cmp_diff, Column::AbsCmpDiff);
            trace.fill_columns_bytes(row, &e.abs_cmp_carry, Column::AbsCmpCarry);
            trace.fill_columns(row, false, Column::IsPadding);

            // ── Phase I-divrem helper fills ──
            // IsDivRem is hardcoded `true` for every real entry (above);
            // div_active = is_div_rem && !div_by_zero collapses to !div_by_zero.
            let div_active = !e.div_by_zero;
            let np_div = div_active; // (1 - is_padding) = 1 on real rows
            let np_div_64 = np_div && !e.is_32bit;
            let np_div_32 = np_div && e.is_32bit;
            let div_u_active = np_div && !e.is_div_s;
            let div_s_active = np_div && e.is_div_s;
            let div_s_64 = div_s_active && !e.is_32bit;
            let div_s_32 = div_s_active && e.is_32bit;
            // Sign-bit columns are u8 ∈ {0, 1}.
            let sd_set = e.sign_bit_d != 0;
            let sr_set = e.sign_bit_r != 0;
            let real_not_sd = !sd_set;
            let real_sd = sd_set;
            let real_not_sr = !sr_set;
            let real_sr = sr_set;
            trace.fill_columns(row, np_div, Column::DivActiveH);
            // DivActiveH ≠ NotPaddingDivH (NotPaddingDivH is the same as
            // np_div on real rows; on padding both are 0).
            trace.fill_columns(row, np_div, Column::NotPaddingDivH);
            trace.fill_columns(row, np_div_64, Column::DivActive64H);
            trace.fill_columns(row, np_div_32, Column::DivActive32H);
            trace.fill_columns(row, div_u_active, Column::DivUActiveH);
            trace.fill_columns(row, div_s_active, Column::DivSActiveH);
            trace.fill_columns(row, div_s_64, Column::DivS64H);
            trace.fill_columns(row, div_s_32, Column::DivS32H);
            trace.fill_columns(row, real_not_sd, Column::RealNotSdH);
            trace.fill_columns(row, real_sd, Column::RealSdH);
            trace.fill_columns(row, real_not_sr, Column::RealNotSrH);
            trace.fill_columns(row, real_sr, Column::RealSrH);

            // PartialSum bodies as BaseField (values can exceed u8).
            use stwo::core::fields::m31::BaseField;
            let q_bytes = e.div_quotient.to_le_bytes();
            let d_bytes = e.val_d.to_le_bytes();
            let mut psum_64 = [BaseField::from(0u32); 16];
            for k in 0..16usize {
                let mut s: u32 = 0;
                for i in 0..WORD_SIZE {
                    let j = k.wrapping_sub(i);
                    if j < WORD_SIZE {
                        s += q_bytes[i] as u32 * d_bytes[j] as u32;
                    }
                }
                psum_64[k] = BaseField::from(s);
            }
            trace.fill_columns_base_field(row, &psum_64, Column::DivPartialSum64);
            let mut psum_32 = [BaseField::from(0u32); 8];
            for k in 0..8usize {
                let mut s: u32 = 0;
                for i in 0..4usize {
                    let j = k.wrapping_sub(i);
                    if j < 4 {
                        s += q_bytes[i] as u32 * d_bytes[j] as u32;
                    }
                }
                psum_32[k] = BaseField::from(s);
            }
            trace.fill_columns_base_field(row, &psum_32, Column::DivPartialSum32);

            // DivCmpCarryB[i] = DivCmpCarry[i] · (1 - DivCmpCarry[i]).
            // For valid div_cmp_carry ∈ {0, 1}, this is always 0.
            let cmp_b = [0u8; 8];
            trace.fill_columns_bytes(row, &cmp_b, Column::DivCmpCarryB);

            // DivS body helpers: SignQValDH[i] = sign_bit_q · val_d[i],
            // SignDQuotH[i] = sign_bit_d · div_quotient[i].
            let mut sqvd = [0u8; 8];
            let mut sdq = [0u8; 8];
            let sq = e.sign_bit_q as u8;
            let sd = e.sign_bit_d as u8;
            for i in 0..WORD_SIZE {
                sqvd[i] = sq * d_bytes[i];
                sdq[i] = sd * q_bytes[i];
            }
            trace.fill_columns_bytes(row, &sqvd, Column::SignQValDH);
            trace.fill_columns_bytes(row, &sdq, Column::SignDQuotH);
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
        use stwo::prover::backend::simd::m31::PackedBaseField;

        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let divrem: &DivRemLookupElements = lookup_elements.as_ref();
        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let div_quotient = crate::trace::original_base_column!(component_trace, Column::DivQuotient);
        let div_remainder = crate::trace::original_base_column!(component_trace, Column::DivRemainder);
        let is_div_rem = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
        let div_by_zero = crate::trace::original_base_column!(component_trace, Column::DivByZero);
        let is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_div_s = crate::trace::original_base_column!(component_trace, Column::IsDivS);
        let sign_bit_b = crate::trace::original_base_column!(component_trace, Column::SignBitB);
        let sign_bit_d = crate::trace::original_base_column!(component_trace, Column::SignBitD);
        let sign_bit_q = crate::trace::original_base_column!(component_trace, Column::SignBitQ);
        let sign_bit_r = crate::trace::original_base_column!(component_trace, Column::SignBitR);
        let div_cmp_diff = crate::trace::original_base_column!(component_trace, Column::DivCmpDiff);
        let abs_cmp_diff = crate::trace::original_base_column!(component_trace, Column::AbsCmpDiff);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        // Range256 emissions for DivCmpDiff bytes (8 per row, gated by is_real).
        for col in &div_cmp_diff {
            logup.add_to_relation_with(
                range256,
                [is_padding[0].clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                &[col.clone()],
            );
        }
        // Range256 emissions for AbsCmpDiff bytes (8 per row, gated by is_real).
        for col in &abs_cmp_diff {
            logup.add_to_relation_with(
                range256,
                [is_padding[0].clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                &[col.clone()],
            );
        }

        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&div_quotient);
        tuple.extend_from_slice(&div_remainder);
        tuple.push(sign_bit_b[0].clone());
        tuple.push(sign_bit_d[0].clone());
        tuple.push(sign_bit_q[0].clone());
        tuple.push(sign_bit_r[0].clone());
        tuple.push(is_div_rem[0].clone());
        tuple.push(div_by_zero[0].clone());
        tuple.push(is_32bit[0].clone());
        tuple.push(is_div_s[0].clone());

        for _ in 0..2 {
            logup.add_to_relation_with(
                divrem,
                [is_padding[0].clone()],
                |[pad]| (-(PackedBaseField::one() - pad)).into(),
                &tuple,
            );
        }

        logup.finalize()
    }
}
