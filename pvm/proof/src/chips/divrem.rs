//! `DivRemChip`: per-divrem-row chip.
//!
//! CpuChip emits one DivRemLookup producer per `is_div_rem=1` row;
//! DivRemChip consumes once per real row and proves, over `W = 64` bits
//! (`W = 32` on a 32-bit row, which reads the operands' low words):
//!
//!   1. The schoolbook `q·d + r = b + 2^W·H` as an exact integer identity:
//!      the quotient, remainder, high half `H` (DivCorrHi) and every carry
//!      are Range256-checked bytes, so no equation wraps in M31.
//!   2. `H` pinned by the operation:
//!      - unsigned division and logical right shift (ShloR): `H = 0`;
//!      - signed division (DivS/RemS):
//!        `H ≡ sq·d + sd·q + sr − sb + k (mod 2^W)`, with `k` the overflow
//!        of `MIN / −1`, the one quotient that does not fit;
//!      - arithmetic right shift (SharR, `d = 2^n`):
//!        `H ≡ sq·d − sb (mod 2^W)`, floor division.
//!      With the sign bits pinned on CpuChip, each makes the schoolbook
//!      the signed (or unsigned) identity over the integers.
//!   3. The remainder's bound: `r < d` unsigned, on every row but signed
//!      division (over the low word on a 32-bit row); `|r| < |d|` on
//!      signed division, through two's-complement magnitude chains with
//!      boolean carries over Range256-checked bytes (a 32-bit divisor
//!      sign-extended). CpuChip pins `sign(r) = sign(b)` when `r ≠ 0`.
//!   4. On a 32-bit row, the quotient's and remainder's high words are
//!      their low words' sign extension.
//!
//! Lookup tuple (41 limbs): val_b\[8\] + val_d\[8\] + div_quotient\[8\] +
//! div_remainder\[8\] + sign_bit_b + sign_bit_d + sign_bit_q +
//! sign_bit_r + is_div_rem + div_by_zero + is_32bit + is_div_s +
//! is_shar_r.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
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

#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::{DivRemEntry, SideNote};
use crate::{
    framework::BuiltInComponent,
    lookups::{DivRemLookupElements, Range256LookupElements},
};

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
    /// High half `H` of the schoolbook `q·d + r = b + 2^W·H`.
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
    /// Signed division or remainder (flowed via the lookup tuple).
    #[size = 1]
    IsDivS,
    /// Arithmetic right shift (flowed via the lookup tuple): floor
    /// division by `d = 2^n`.
    #[size = 1]
    IsSharR,
    /// 1 on the signed division `MIN / −1` alone: the true quotient
    /// `2^(W−1)` does not fit, and the PVM's `MIN` exceeds the schoolbook's
    /// high half by one.
    #[size = 1]
    DivOverflow,
    /// Per-byte `val_d + ~div_remainder` chain witness (`r < d`).
    #[size = 8]
    DivCmpDiff,
    /// Per-byte boolean carry of the chain.
    #[size = 8]
    DivCmpCarry,
    /// Per-byte carry of the signed correction chain, in {0, 1, 2}.
    #[size = 8]
    DivCorrCarry,
    /// 4 sign bits flowed from CpuChip via the lookup tuple.
    #[size = 1]
    SignBitB,
    #[size = 1]
    SignBitD,
    #[size = 1]
    SignBitQ,
    #[size = 1]
    SignBitR,
    /// |val_d| via two's-complement negation gated on sign_bit_d, of the
    /// sign-extended low word on a 32-bit row.
    #[size = 8]
    AbsD,
    #[size = 8]
    AbsDCarry,
    /// |div_remainder| via two's-complement negation gated on sign_bit_r.
    #[size = 8]
    AbsR,
    #[size = 8]
    AbsRCarry,
    /// Per-byte `abs_d + ~abs_r` chain witness.  Top carry forced to 1 on
    /// signed div rows.
    #[size = 8]
    AbsCmpDiff,
    #[size = 8]
    AbsCmpCarry,
    #[size = 1]
    IsPadding,

    // ── Degree-flatten helpers ──
    //
    // Each materialises a multi-flag selector or a quadratic body term so
    // every gated constraint factors into (deg 1 column ref) × (deg 1 body).
    /// `IsDivRem · (1 - DivByZero)` — div is "active" (non-zero divisor).
    #[size = 1]
    DivActiveH,
    /// `(1 - IsPadding) · DivActiveH` — real row + active div.
    #[size = 1]
    NotPaddingDivH,
    /// `NotPaddingDivH · Is64Bit` (Is64Bit = 1 - Is32Bit).
    #[size = 1]
    DivActive64H,
    /// `NotPaddingDivH · Is32Bit`.
    #[size = 1]
    DivActive32H,
    /// `NotPaddingDivH · (1 - IsDivS)` — the unsigned `r < d` chain's gate.
    #[size = 1]
    DivUActiveH,
    /// `DivUActiveH · Is64Bit`, `DivUActiveH · Is32Bit` — where the
    /// `r < d` chain's deciding carry sits (byte 7, byte 3).
    #[size = 1]
    DivU64H,
    #[size = 1]
    DivU32H,
    /// `NotPaddingDivH · IsDivS` — signed division (`|r| < |d|`).
    #[size = 1]
    DivSActiveH,
    /// `NotPaddingDivH · (IsDivS + IsSharR)` — rows whose high half the
    /// signed correction chain pins, and its per-width gates.
    #[size = 1]
    SignChainH,
    #[size = 1]
    SignChain64H,
    #[size = 1]
    SignChain32H,
    /// `NotPaddingDivH · (1 - IsDivS - IsSharR)` — unsigned rows, whose
    /// high half is zero.
    #[size = 1]
    ZeroHighH,
    /// `(1 - IsPadding) · (1 - SignBitD)` and `(1 - IsPadding) · SignBitD`
    /// — split AbsD chain gates by the conditional-negation case.
    #[size = 1]
    RealNotSdH,
    #[size = 1]
    RealSdH,
    /// Same shape on SignBitR for the AbsR chain.
    #[size = 1]
    RealNotSrH,
    #[size = 1]
    RealSrH,
    /// `DivOverflow · Is64Bit`.
    #[size = 1]
    DivOverflow64H,
    /// `SignBitD · IsDivS`: the divisor's sign as signed division reads
    /// it (an arithmetic shift's divisor `2^n` is unsigned).
    #[size = 1]
    SignDDivSH,

    /// 64-bit schoolbook partial-sum helper: `DivPartialSum64[k] :=
    /// Σ_{i+j=k, i,j<8} DivQuotient[i] · ValD[j]` (deg 2 def).  k=0..16.
    #[size = 16]
    DivPartialSum64,
    /// 32-bit schoolbook partial-sum helper, k=0..8 with i,j<4.
    #[size = 8]
    DivPartialSum32,

    /// Signed chain body helpers.
    /// `SignQValDH[i] := SignBitQ · ValD[i]`
    #[size = 8]
    SignQValDH,
    /// `SignDQuotH[i] := SignDDivSH · DivQuotient[i]`
    #[size = 8]
    SignDQuotH,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "divrem"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for DivRemChip {
    /// Every degree-3+ constraint is lifted via helper columns, so the
    /// chip's actual algebraic degree is ≤ 2.
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 1;

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
        let is_shar_r = crate::trace::trace_eval!(trace_eval, Column::IsSharR);
        let div_overflow = crate::trace::trace_eval!(trace_eval, Column::DivOverflow);
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

        // ── Degree-flatten helpers ──
        let div_active_h = crate::trace::trace_eval!(trace_eval, Column::DivActiveH);
        let not_padding_div_h = crate::trace::trace_eval!(trace_eval, Column::NotPaddingDivH);
        let div_active_64_h = crate::trace::trace_eval!(trace_eval, Column::DivActive64H);
        let div_active_32_h = crate::trace::trace_eval!(trace_eval, Column::DivActive32H);
        let div_u_active_h = crate::trace::trace_eval!(trace_eval, Column::DivUActiveH);
        let div_u_64_h = crate::trace::trace_eval!(trace_eval, Column::DivU64H);
        let div_u_32_h = crate::trace::trace_eval!(trace_eval, Column::DivU32H);
        let div_s_active_h = crate::trace::trace_eval!(trace_eval, Column::DivSActiveH);
        let sign_chain_h = crate::trace::trace_eval!(trace_eval, Column::SignChainH);
        let sign_chain_64_h = crate::trace::trace_eval!(trace_eval, Column::SignChain64H);
        let sign_chain_32_h = crate::trace::trace_eval!(trace_eval, Column::SignChain32H);
        let zero_high_h = crate::trace::trace_eval!(trace_eval, Column::ZeroHighH);
        let real_not_sd_h = crate::trace::trace_eval!(trace_eval, Column::RealNotSdH);
        let real_sd_h = crate::trace::trace_eval!(trace_eval, Column::RealSdH);
        let real_not_sr_h = crate::trace::trace_eval!(trace_eval, Column::RealNotSrH);
        let real_sr_h = crate::trace::trace_eval!(trace_eval, Column::RealSrH);
        let div_overflow_64_h = crate::trace::trace_eval!(trace_eval, Column::DivOverflow64H);
        let sign_d_div_s_h = crate::trace::trace_eval!(trace_eval, Column::SignDDivSH);
        let div_partial_sum_64 = crate::trace::trace_eval!(trace_eval, Column::DivPartialSum64);
        let div_partial_sum_32 = crate::trace::trace_eval!(trace_eval, Column::DivPartialSum32);
        let sign_q_d = crate::trace::trace_eval!(trace_eval, Column::SignQValDH);
        let sign_d_q = crate::trace::trace_eval!(trace_eval, Column::SignDQuotH);

        let one = || E::F::one();
        let f256: E::F = E::F::from(BaseField::from(256));
        let f255: E::F = E::F::from(BaseField::from(255));
        let boolean = |x: &E::F| x.clone() * (E::F::one() - x.clone());

        // Flags and carries are boolean (padding rows hold zeros).
        for flag in [
            &is_div_rem,
            &div_by_zero,
            &is_32bit,
            &is_div_s,
            &is_shar_r,
            &div_overflow,
            &sign_bit_b,
            &sign_bit_d,
            &sign_bit_q,
            &sign_bit_r,
            &is_padding,
        ] {
            eval.add_constraint(boolean(&flag[0]));
        }
        for carry in div_cmp_carry
            .iter()
            .chain(&abs_d_carry)
            .chain(&abs_r_carry)
            .chain(&abs_cmp_carry)
        {
            eval.add_constraint(boolean(carry));
        }
        eval.add_constraint(is_div_s[0].clone() * is_shar_r[0].clone());
        let is_real = one() - is_padding[0].clone();
        let is_64bit = one() - is_32bit[0].clone();

        // ── Helper-defining constraints ──
        eval.add_constraint(
            div_active_h[0].clone() - is_div_rem[0].clone() * (one() - div_by_zero[0].clone()),
        );
        eval.add_constraint(
            not_padding_div_h[0].clone() - is_real.clone() * div_active_h[0].clone(),
        );
        eval.add_constraint(
            div_active_64_h[0].clone() - not_padding_div_h[0].clone() * is_64bit.clone(),
        );
        eval.add_constraint(
            div_active_32_h[0].clone() - not_padding_div_h[0].clone() * is_32bit[0].clone(),
        );
        eval.add_constraint(
            div_u_active_h[0].clone()
                - not_padding_div_h[0].clone() * (one() - is_div_s[0].clone()),
        );
        eval.add_constraint(div_u_64_h[0].clone() - div_u_active_h[0].clone() * is_64bit.clone());
        eval.add_constraint(
            div_u_32_h[0].clone() - div_u_active_h[0].clone() * is_32bit[0].clone(),
        );
        eval.add_constraint(
            div_s_active_h[0].clone() - not_padding_div_h[0].clone() * is_div_s[0].clone(),
        );
        eval.add_constraint(
            sign_chain_h[0].clone()
                - not_padding_div_h[0].clone() * (is_div_s[0].clone() + is_shar_r[0].clone()),
        );
        eval.add_constraint(
            sign_chain_64_h[0].clone() - sign_chain_h[0].clone() * is_64bit.clone(),
        );
        eval.add_constraint(
            sign_chain_32_h[0].clone() - sign_chain_h[0].clone() * is_32bit[0].clone(),
        );
        eval.add_constraint(
            zero_high_h[0].clone()
                - not_padding_div_h[0].clone()
                    * (one() - is_div_s[0].clone() - is_shar_r[0].clone()),
        );
        eval.add_constraint(
            real_not_sd_h[0].clone() - is_real.clone() * (one() - sign_bit_d[0].clone()),
        );
        eval.add_constraint(real_sd_h[0].clone() - is_real.clone() * sign_bit_d[0].clone());
        eval.add_constraint(
            real_not_sr_h[0].clone() - is_real.clone() * (one() - sign_bit_r[0].clone()),
        );
        eval.add_constraint(real_sr_h[0].clone() - is_real.clone() * sign_bit_r[0].clone());
        eval.add_constraint(
            div_overflow_64_h[0].clone() - div_overflow[0].clone() * is_64bit.clone(),
        );
        eval.add_constraint(
            sign_d_div_s_h[0].clone() - sign_bit_d[0].clone() * is_div_s[0].clone(),
        );
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
        for i in 0..WORD_SIZE {
            eval.add_constraint(sign_q_d[i].clone() - sign_bit_q[0].clone() * val_d[i].clone());
            eval.add_constraint(
                sign_d_q[i].clone() - sign_d_div_s_h[0].clone() * div_quotient[i].clone(),
            );
        }

        // ── Schoolbook carry chain ──
        // expected[k] + 256·carry[k] = Σ q[i]·d[j] + r[k] + carry[k−1], the
        // expected bytes `b` then `H`.  Every term is a range-checked byte
        // or carry, so both sides stay below 2^25 and the chain holds over
        // the integers; its final carry is then 0, as `q·d + r < 2^(2W)`.
        let full_carry =
            |k: usize| -> E::F { mul_carry[k].clone() + mul_carry_hi[k].clone() * f256.clone() };
        for (width, gate, partial_sum) in [
            (WORD_SIZE, &div_active_64_h, &div_partial_sum_64[..]),
            (4, &div_active_32_h, &div_partial_sum_32[..]),
        ] {
            for k in 0..2 * width {
                let rem_term = if k < width {
                    div_remainder[k].clone()
                } else {
                    E::F::zero()
                };
                let carry_in = if k == 0 {
                    E::F::zero()
                } else {
                    full_carry(k - 1)
                };
                let expected = if k < width {
                    val_b[k].clone()
                } else {
                    div_corr_hi[k - width].clone()
                };
                eval.add_constraint(
                    gate[0].clone()
                        * (expected + full_carry(k) * f256.clone()
                            - partial_sum[k].clone()
                            - rem_term
                            - carry_in),
                );
            }
        }

        // ── A 32-bit row's quotient and remainder ──
        // The 32-bit chains read the low words alone; the high words, the
        // result's and the other's, are their low words' sign extension,
        // so the tuple carries no free byte. (The internal witness's high
        // positions on such a row, `H[4..8]`, their carries and the
        // schoolbook carries past 8, enter no chain and no tuple.)
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                is_32bit[0].clone()
                    * (div_quotient[i].clone() - f255.clone() * sign_bit_q[0].clone()),
            );
            eval.add_constraint(
                is_32bit[0].clone()
                    * (div_remainder[i].clone() - f255.clone() * sign_bit_r[0].clone()),
            );
        }

        // ── The high half ──
        // Unsigned division and logical right shift: `q·d + r = b`.
        for hi in &div_corr_hi {
            eval.add_constraint(zero_high_h[0].clone() * hi.clone());
        }
        // Signed division and arithmetic right shift: per byte,
        //   H[i] + 256·c[i] = sq·d[i] + sd'·q[i] + 255·sb + c[i−1]
        //                     + (i = 0 ? sr + k : 0)
        // with sd' = sd·is_div_s, so `H ≡ sq·d + sd'·q + sr − sb + k`
        // (mod 2^W): `−sb` is added as `sb·(2^W − 1)`, keeping every carry
        // in {0, 1, 2}.  On a SharR row `sr = 0` (its `r < d ≤ 2^(W−1)`) and
        // `k = 0`, which leaves floor division's `sq·d − sb`.
        for (width, gate) in [(WORD_SIZE, &sign_chain_64_h), (4, &sign_chain_32_h)] {
            for i in 0..width {
                let carry_in = if i == 0 {
                    sign_bit_r[0].clone() + div_overflow[0].clone()
                } else {
                    div_corr_carry[i - 1].clone()
                };
                eval.add_constraint(
                    gate[0].clone()
                        * (div_corr_hi[i].clone() + div_corr_carry[i].clone() * f256.clone()
                            - sign_q_d[i].clone()
                            - sign_d_q[i].clone()
                            - f255.clone() * sign_bit_b[0].clone()
                            - carry_in),
                );
            }
        }
        // The overflow `k` only on a signed division by −1 (all-ones low
        // word, and high word on a 64-bit row).  Then `|r| < 1` and the
        // identity `−q + r = b + 2^W` leave `b = q = MIN`, `r = 0`.
        eval.add_constraint(div_overflow[0].clone() * (one() - is_div_s[0].clone()));
        for i in 0..WORD_SIZE {
            let gate = if i < 4 {
                &div_overflow
            } else {
                &div_overflow_64_h
            };
            eval.add_constraint(gate[0].clone() * (val_d[i].clone() - f255.clone()));
        }

        // ── r < d (unsigned rows) ──
        // `val_d + ~div_remainder` with carry_in 0: the carry out of the
        // row's top byte (7, or 3 on a 32-bit row) is 1 iff `d > r`.
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                div_cmp_carry[i - 1].clone()
            };
            eval.add_constraint(
                div_u_active_h[0].clone()
                    * (div_cmp_diff[i].clone() + div_cmp_carry[i].clone() * f256.clone()
                        - val_d[i].clone()
                        - f255.clone()
                        + div_remainder[i].clone()
                        - carry_in),
            );
        }
        eval.add_constraint(div_u_64_h[0].clone() * (one() - div_cmp_carry[WORD_SIZE - 1].clone()));
        eval.add_constraint(div_u_32_h[0].clone() * (one() - div_cmp_carry[3].clone()));

        // ── |val_d| / |div_remainder| and |d| > |r| ──
        //   sign(X) = 0: Abs[i] = X[i],  AbsCarry[i] = 0
        //   sign(X) = 1: Abs[i] + AbsCarry[i]·256 = (255 − X[i]) + carry_in
        //                 with carry_in[0] = 1 (the +1 of two's complement).
        // A 32-bit row's divisor is its low word, sign-extended: its high
        // bytes, zero in the trace, read as 255 when the sign is set.
        for i in 0..WORD_SIZE {
            eval.add_constraint(real_not_sd_h[0].clone() * (abs_d[i].clone() - val_d[i].clone()));
            eval.add_constraint(real_not_sd_h[0].clone() * abs_d_carry[i].clone());
            let neg_carry_in = if i == 0 {
                one()
            } else {
                abs_d_carry[i - 1].clone()
            };
            let extension = if i < 4 {
                E::F::zero()
            } else {
                f255.clone() * is_32bit[0].clone()
            };
            eval.add_constraint(
                real_sd_h[0].clone()
                    * (abs_d[i].clone() + abs_d_carry[i].clone() * f256.clone() - f255.clone()
                        + val_d[i].clone()
                        + extension
                        - neg_carry_in),
            );
        }
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                real_not_sr_h[0].clone() * (abs_r[i].clone() - div_remainder[i].clone()),
            );
            eval.add_constraint(real_not_sr_h[0].clone() * abs_r_carry[i].clone());
            let neg_carry_in = if i == 0 {
                one()
            } else {
                abs_r_carry[i - 1].clone()
            };
            eval.add_constraint(
                real_sr_h[0].clone()
                    * (abs_r[i].clone() + abs_r_carry[i].clone() * f256.clone() - f255.clone()
                        + div_remainder[i].clone()
                        - neg_carry_in),
            );
        }
        // `AbsD + ~AbsR` (carry_in 0); top carry 1 iff |d| > |r|.
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                abs_cmp_carry[i - 1].clone()
            };
            eval.add_constraint(
                is_real.clone()
                    * (abs_cmp_diff[i].clone() + abs_cmp_carry[i].clone() * f256.clone()
                        - abs_d[i].clone()
                        - f255.clone()
                        + abs_r[i].clone()
                        - carry_in),
            );
        }
        eval.add_constraint(
            div_s_active_h[0].clone() * (one() - abs_cmp_carry[WORD_SIZE - 1].clone()),
        );

        // ── Range256: every byte and carry the chains read (96 per real
        // row, in `range_checked_bytes`' order) ──
        for value in [
            &div_quotient[..],
            &div_remainder,
            &div_corr_hi,
            &mul_carry,
            &mul_carry_hi,
            &div_corr_carry,
            &abs_d,
            &abs_r,
            &div_cmp_diff,
            &abs_cmp_diff,
        ]
        .into_iter()
        .flatten()
        {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                core::slice::from_ref(value),
            ));
        }

        // ── Lookup consumer ──
        let mut tuple: Vec<E::F> = Vec::with_capacity(41);
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
        tuple.push(is_shar_r[0].clone());

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

/// The quotient and remainder a division row proves (`d ≠ 0`), as the PVM
/// defines them: truncated signed division, with `MIN / −1 = MIN` (the
/// returned overflow); floor division by `d = 2^n` for an arithmetic right
/// shift; unsigned division otherwise. A 32-bit row divides its operands'
/// low words, and its quotient and remainder are sign-extended words.
#[cfg(feature = "prover")]
fn quotient_remainder(
    val_b: u64,
    val_d: u64,
    is_32bit: bool,
    is_div_s: bool,
    is_shar_r: bool,
) -> (u64, u64, bool) {
    if is_32bit {
        let sign_extend = |word: u32| word as i32 as i64 as u64;
        let (b, d) = (val_b as u32, val_d as u32);
        let (q, r, overflow) = if is_div_s {
            let (b, d) = (b as i32, d as i32);
            (
                b.wrapping_div(d) as u32,
                b.wrapping_rem(d) as u32,
                b == i32::MIN && d == -1,
            )
        } else if is_shar_r {
            let q = ((b as i32) >> d.trailing_zeros()) as u32;
            (q, b.wrapping_sub(q.wrapping_mul(d)), false)
        } else {
            (b / d, b % d, false)
        };
        (sign_extend(q), sign_extend(r), overflow)
    } else if is_div_s {
        let (b, d) = (val_b as i64, val_d as i64);
        (
            b.wrapping_div(d) as u64,
            b.wrapping_rem(d) as u64,
            b == i64::MIN && d == -1,
        )
    } else if is_shar_r {
        let q = ((val_b as i64) >> val_d.trailing_zeros()) as u64;
        (q, val_b.wrapping_sub(q.wrapping_mul(val_d)), false)
    } else {
        (val_b / val_d, val_b % val_d, false)
    }
}

/// The DivRemChip row of a division by `val_d` (a right shift's `2^n`),
/// the operands as the CpuChip reads them.
#[cfg(feature = "prover")]
pub(crate) fn entry(
    val_b: u64,
    val_d: u64,
    is_32bit: bool,
    is_div_s: bool,
    is_shar_r: bool,
) -> DivRemEntry {
    let (q, r, overflow) = if val_d == 0 {
        (0, 0, false)
    } else {
        quotient_remainder(val_b, val_d, is_32bit, is_div_s, is_shar_r)
    };
    witness(val_b, val_d, q, r, overflow, is_32bit, is_div_s, is_shar_r)
}

/// A row's internal witness for the quotient `q` and remainder `r`: the
/// chains' bytes and carries, computed over the integers. A pair that does
/// not divide `val_b` yields a witness the constraints refuse.
#[cfg(feature = "prover")]
#[allow(clippy::too_many_arguments)]
pub fn witness(
    val_b: u64,
    val_d: u64,
    q: u64,
    r: u64,
    overflow: bool,
    is_32bit: bool,
    is_div_s: bool,
    is_shar_r: bool,
) -> DivRemEntry {
    let width = if is_32bit { 4 } else { WORD_SIZE };
    let (d_bytes, q_bytes, r_bytes) = (val_d.to_le_bytes(), q.to_le_bytes(), r.to_le_bytes());
    let sign = |x: u64| ((x >> (8 * width - 1)) & 1) as u8;
    let (sign_bit_b, sign_bit_d, sign_bit_q, sign_bit_r) =
        (sign(val_b), sign(val_d), sign(q), sign(r));

    // Schoolbook: carries and high half of q·d + r over the row's width.
    let mut sum = [0u32; 16];
    for i in 0..width {
        for j in 0..width {
            sum[i + j] += q_bytes[i] as u32 * d_bytes[j] as u32;
        }
        sum[i] += r_bytes[i] as u32;
    }
    let (mut div_mul_carry, mut div_mul_carry_hi) = ([0u8; 16], [0u8; 16]);
    let mut div_corr_hi = [0u8; WORD_SIZE];
    let mut carry = 0u32;
    for k in 0..2 * width {
        let s = sum[k] + carry;
        if k >= width {
            div_corr_hi[k - width] = s as u8;
        }
        carry = s >> 8;
        div_mul_carry[k] = carry as u8;
        div_mul_carry_hi[k] = (carry >> 8) as u8;
    }

    // Signed correction chain (signed division, arithmetic shift).
    let mut div_corr_carry = [0u8; WORD_SIZE];
    if (is_div_s || is_shar_r) && val_d != 0 {
        let sign_d = sign_bit_d * is_div_s as u8;
        let mut carry = sign_bit_r as u32 + overflow as u32;
        for i in 0..width {
            let s = sign_bit_q as u32 * d_bytes[i] as u32
                + sign_d as u32 * q_bytes[i] as u32
                + 255 * sign_bit_b as u32
                + carry;
            carry = s >> 8;
            div_corr_carry[i] = carry as u8;
        }
    }

    let (div_cmp_diff, div_cmp_carry) = add_complement(d_bytes, r_bytes);
    let d_magnitude_source = if is_32bit {
        val_d as u32 as i32 as i64 as u64
    } else {
        val_d
    };
    let (abs_d, abs_d_carry) = magnitude(d_magnitude_source, sign_bit_d);
    let (abs_r, abs_r_carry) = magnitude(r, sign_bit_r);
    let (abs_cmp_diff, abs_cmp_carry) = add_complement(abs_d, abs_r);

    DivRemEntry {
        val_b,
        val_d,
        div_quotient: q,
        div_remainder: r,
        div_corr_hi,
        div_corr_carry,
        div_mul_carry,
        div_mul_carry_hi,
        div_by_zero: val_d == 0,
        is_32bit,
        is_div_s,
        is_shar_r,
        div_overflow: overflow,
        div_cmp_diff,
        div_cmp_carry,
        sign_bit_b,
        sign_bit_d,
        sign_bit_q,
        sign_bit_r,
        abs_d,
        abs_d_carry,
        abs_r,
        abs_r_carry,
        abs_cmp_diff,
        abs_cmp_carry,
    }
}

/// `x + ~y` byte by byte with carry-in 0: the bytes and carries; the top
/// carry is 1 iff `x > y`.
#[cfg(feature = "prover")]
fn add_complement(x: [u8; 8], y: [u8; 8]) -> ([u8; 8], [u8; 8]) {
    let (mut sum, mut carries) = ([0u8; 8], [0u8; 8]);
    let mut carry = 0u16;
    for i in 0..WORD_SIZE {
        let s = x[i] as u16 + 255 - y[i] as u16 + carry;
        sum[i] = s as u8;
        carry = s >> 8;
        carries[i] = carry as u8;
    }
    (sum, carries)
}

/// `x`'s two's-complement magnitude when `sign` is set (`~x + 1`), else
/// `x`: the bytes and the negation's carries.
#[cfg(feature = "prover")]
fn magnitude(x: u64, sign: u8) -> ([u8; 8], [u8; 8]) {
    let x = x.to_le_bytes();
    let mut carries = [0u8; 8];
    if sign == 0 {
        return (x, carries);
    }
    let mut abs = [0u8; 8];
    let mut carry = 1u16;
    for i in 0..WORD_SIZE {
        let s = 255 - x[i] as u16 + carry;
        abs[i] = s as u8;
        carry = s >> 8;
        carries[i] = carry as u8;
    }
    (abs, carries)
}

/// The Range256 values a row emits, as a multiset.
#[cfg(feature = "prover")]
pub fn range_checked_bytes(e: &DivRemEntry) -> impl Iterator<Item = u8> + '_ {
    let q = e.div_quotient.to_le_bytes();
    let r = e.div_remainder.to_le_bytes();
    q.into_iter()
        .chain(r)
        .chain(e.div_corr_hi)
        .chain(e.div_mul_carry)
        .chain(e.div_mul_carry_hi)
        .chain(e.div_corr_carry)
        .chain(e.abs_d)
        .chain(e.abs_r)
        .chain(e.div_cmp_diff)
        .chain(e.abs_cmp_diff)
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for DivRemChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
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

        let log_size =
            crate::trace::utils::ceil_log2_at_least_lanes(entries.len()).max(MIN_LOG_SIZE);
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
            trace.fill_columns(row, e.is_shar_r, Column::IsSharR);
            trace.fill_columns(row, e.div_overflow, Column::DivOverflow);
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

            // ── Helper fills (a real row: IsDivRem = 1, IsPadding = 0) ──
            let active = !e.div_by_zero;
            let unsigned = active && !e.is_div_s;
            let sign_chain = active && (e.is_div_s || e.is_shar_r);
            trace.fill_columns(row, active, Column::DivActiveH);
            trace.fill_columns(row, active, Column::NotPaddingDivH);
            trace.fill_columns(row, active && !e.is_32bit, Column::DivActive64H);
            trace.fill_columns(row, active && e.is_32bit, Column::DivActive32H);
            trace.fill_columns(row, unsigned, Column::DivUActiveH);
            trace.fill_columns(row, unsigned && !e.is_32bit, Column::DivU64H);
            trace.fill_columns(row, unsigned && e.is_32bit, Column::DivU32H);
            trace.fill_columns(row, active && e.is_div_s, Column::DivSActiveH);
            trace.fill_columns(row, sign_chain, Column::SignChainH);
            trace.fill_columns(row, sign_chain && !e.is_32bit, Column::SignChain64H);
            trace.fill_columns(row, sign_chain && e.is_32bit, Column::SignChain32H);
            trace.fill_columns(row, active && !sign_chain, Column::ZeroHighH);
            trace.fill_columns(row, e.sign_bit_d == 0, Column::RealNotSdH);
            trace.fill_columns(row, e.sign_bit_d == 1, Column::RealSdH);
            trace.fill_columns(row, e.sign_bit_r == 0, Column::RealNotSrH);
            trace.fill_columns(row, e.sign_bit_r == 1, Column::RealSrH);
            trace.fill_columns(row, e.div_overflow && !e.is_32bit, Column::DivOverflow64H);
            let sign_d_div_s = e.sign_bit_d * e.is_div_s as u8;
            trace.fill_columns(row, sign_d_div_s, Column::SignDDivSH);

            // PartialSum bodies as BaseField (values can exceed u8).
            let q_bytes = e.div_quotient.to_le_bytes();
            let d_bytes = e.val_d.to_le_bytes();
            let partial_sums = |width: usize, n: usize| -> Vec<BaseField> {
                (0..n)
                    .map(|k| {
                        let s: u32 = (0..width)
                            .filter_map(|i| {
                                let j = k.wrapping_sub(i);
                                (j < width).then(|| q_bytes[i] as u32 * d_bytes[j] as u32)
                            })
                            .sum();
                        BaseField::from(s)
                    })
                    .collect()
            };
            trace.fill_columns_base_field(
                row,
                &partial_sums(WORD_SIZE, 16),
                Column::DivPartialSum64,
            );
            trace.fill_columns_base_field(row, &partial_sums(4, 8), Column::DivPartialSum32);

            let sign_q_d = d_bytes.map(|d| e.sign_bit_q * d);
            let sign_d_q = q_bytes.map(|q| sign_d_div_s * q);
            trace.fill_columns_bytes(row, &sign_q_d, Column::SignQValDH);
            trace.fill_columns_bytes(row, &sign_d_q, Column::SignDQuotH);
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
        let div_quotient =
            crate::trace::original_base_column!(component_trace, Column::DivQuotient);
        let div_remainder =
            crate::trace::original_base_column!(component_trace, Column::DivRemainder);
        let div_corr_hi = crate::trace::original_base_column!(component_trace, Column::DivCorrHi);
        let mul_carry = crate::trace::original_base_column!(component_trace, Column::DivMulCarry);
        let mul_carry_hi =
            crate::trace::original_base_column!(component_trace, Column::DivMulCarryHi);
        let div_corr_carry =
            crate::trace::original_base_column!(component_trace, Column::DivCorrCarry);
        let abs_d = crate::trace::original_base_column!(component_trace, Column::AbsD);
        let abs_r = crate::trace::original_base_column!(component_trace, Column::AbsR);
        let is_div_rem = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
        let div_by_zero = crate::trace::original_base_column!(component_trace, Column::DivByZero);
        let is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_div_s = crate::trace::original_base_column!(component_trace, Column::IsDivS);
        let is_shar_r = crate::trace::original_base_column!(component_trace, Column::IsSharR);
        let sign_bit_b = crate::trace::original_base_column!(component_trace, Column::SignBitB);
        let sign_bit_d = crate::trace::original_base_column!(component_trace, Column::SignBitD);
        let sign_bit_q = crate::trace::original_base_column!(component_trace, Column::SignBitQ);
        let sign_bit_r = crate::trace::original_base_column!(component_trace, Column::SignBitR);
        let div_cmp_diff = crate::trace::original_base_column!(component_trace, Column::DivCmpDiff);
        let abs_cmp_diff = crate::trace::original_base_column!(component_trace, Column::AbsCmpDiff);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        for value in [
            &div_quotient[..],
            &div_remainder,
            &div_corr_hi,
            &mul_carry,
            &mul_carry_hi,
            &div_corr_carry,
            &abs_d,
            &abs_r,
            &div_cmp_diff,
            &abs_cmp_diff,
        ]
        .into_iter()
        .flatten()
        {
            logup.add_to_relation_with(
                range256,
                [is_padding[0].clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                core::slice::from_ref(value),
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
        tuple.push(is_shar_r[0].clone());

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
