//! DivRemChip's constraints.

use alloc::vec::Vec;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Column, DivRemChip, PreprocessedColumn};
use crate::core::step::WORD_SIZE;
use crate::trace::eval::TraceEval;
use crate::{
    framework::BuiltInComponent,
    lookups::{DivRemLookupElements, Range256LookupElements},
};

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
    }
}
