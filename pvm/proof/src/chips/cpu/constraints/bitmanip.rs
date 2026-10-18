//! Bit manipulation: byte ops, popcounts, leading and trailing zeros, sign extension.
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Trace};
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// The BitManip MSB and SignExtBit helpers.
pub(in crate::chips::cpu) fn msb_helpers<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let val_d_byte_indicator_h = crate::trace::trace_eval!(trace_eval, Column::ValDByteIndicatorH);
    // ── BitManip MSB + SignExtBit helpers ──
    let part_nz_msb_times_ind_h = crate::trace::trace_eval!(trace_eval, Column::PartNZMsbTimesIndH);
    let part_nz_msb_lo_times_ind_h =
        crate::trace::trace_eval!(trace_eval, Column::PartNZMsbLoTimesIndH);
    {
        let sign_ext_bit_top = crate::trace::trace_eval!(trace_eval, Column::SignExtBit);
        let val_d_partial_nz_msb_top =
            crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZMsb);
        let val_d_partial_nz_msb_lo_top =
            crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZMsbLo);
        // sign_ext_bit boolean enforced unconditionally.  Trace fills 0
        // on non-sign-ext rows so 0·(1-0)=0 holds; a gated
        // `is_sign_ext · bool_h = 0` form would be redundant.
        eval.add_constraint(
            sign_ext_bit_top[0].clone() * (E::F::one() - sign_ext_bit_top[0].clone()),
        );
        // PartNZMsbTimesIndH[i] = PartialNZMsb[i+1] · ByteIndicator[i] for i ∈ 0..7.
        for i in 0..7 {
            eval.add_constraint(
                part_nz_msb_times_ind_h[i].clone()
                    - val_d_partial_nz_msb_top[i + 1].clone() * val_d_byte_indicator_h[i].clone(),
            );
        }
        // PartNZMsbLoTimesIndH[i] = PartialNZMsbLo[i+1] · ByteIndicator[i] for i ∈ 0..3.
        for i in 0..3 {
            eval.add_constraint(
                part_nz_msb_lo_times_ind_h[i].clone()
                    - val_d_partial_nz_msb_lo_top[i + 1].clone()
                        * val_d_byte_indicator_h[i].clone(),
            );
        }
    }
}

/// ReverseBytes, ZeroExtend16, SignExtend8 and SignExtend16.
pub(in crate::chips::cpu) fn byte_ops<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    // ════════════════════════════════════════════════════════════════════
    // BITMANIP — REVERSE_BYTES: result[i] = val_d[7-i]
    // ════════════════════════════════════════════════════════════════════
    let is_reverse_bytes = crate::trace::trace_eval!(trace_eval, Column::IsReverseBytes);
    for i in 0..WORD_SIZE {
        eval.add_constraint(
            is_reverse_bytes[0].clone() * (result[i].clone() - val_d[WORD_SIZE - 1 - i].clone()),
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // BITMANIP — ZERO_EXTEND_16: result[0..2] = val_d[0..2]; result[2..8] = 0
    // ════════════════════════════════════════════════════════════════════
    let is_zero_ext_16 = crate::trace::trace_eval!(trace_eval, Column::IsZeroExt16);
    eval.add_constraint(is_zero_ext_16[0].clone() * (result[0].clone() - val_d[0].clone()));
    eval.add_constraint(is_zero_ext_16[0].clone() * (result[1].clone() - val_d[1].clone()));
    for i in 2..WORD_SIZE {
        eval.add_constraint(is_zero_ext_16[0].clone() * result[i].clone());
    }

    // ════════════════════════════════════════════════════════════════════
    // BITMANIP — SIGN_EXTEND_8 / SIGN_EXTEND_16  (ground constraints only;
    // the sign-bit-pinning AND lookups are `sign_extend_nibbles`, emitted
    // last, before finalize_logup).
    // ════════════════════════════════════════════════════════════════════
    let is_sign_ext_8 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt8);
    let is_sign_ext_16 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt16);
    let sign_ext_bit = crate::trace::trace_eval!(trace_eval, Column::SignExtBit);
    let is_sign_ext = is_sign_ext_8[0].clone() + is_sign_ext_16[0].clone();
    let ff_se: E::F = E::F::from(BaseField::from(255));

    // SignExtBit ∈ {0, 1} is enforced unconditionally above.  An
    // `is_sign_ext · bool_h = 0` constraint would be redundant once
    // sign_ext_bit is boolean on every row, since bool_h = 0 makes the
    // product trivially zero.
    // SE8 + SE16 both copy byte 0.
    eval.add_constraint(is_sign_ext.clone() * (result[0].clone() - val_d[0].clone()));
    // SE16 also copies byte 1.
    eval.add_constraint(is_sign_ext_16[0].clone() * (result[1].clone() - val_d[1].clone()));
    // SE8: bytes 1..8 = 0xFF · sign_bit.
    for i in 1..WORD_SIZE {
        eval.add_constraint(
            is_sign_ext_8[0].clone()
                * (result[i].clone() - ff_se.clone() * sign_ext_bit[0].clone()),
        );
    }
    // SE16: bytes 2..8 = 0xFF · sign_bit.
    for i in 2..WORD_SIZE {
        eval.add_constraint(
            is_sign_ext_16[0].clone()
                * (result[i].clone() - ff_se.clone() * sign_ext_bit[0].clone()),
        );
    }
}

/// CountSetBits: the result is the sum of the bytes' popcounts.
pub(in crate::chips::cpu) fn count_set_bits<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_64bit_popcount_hi_h = crate::trace::trace_eval!(trace_eval, Column::Is64bitPopcountHiH);
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    // ════════════════════════════════════════════════════════════════════
    // BITMANIP CountSetBits (CSB64 / CSB32):
    //   result[0] = sum(BytePopcount[0..N])  (N = 4 if Is32Bit else 8)
    //   result[1..8] = 0
    //   per-byte popcount lookup `(val_d[i], BytePopcount[i]) ∈ popcount`
    //     emitted in `lookups::table_lookups`.
    // ════════════════════════════════════════════════════════════════════
    let is_count_set_bits = crate::trace::trace_eval!(trace_eval, Column::IsCountSetBits);
    let byte_popcount = crate::trace::trace_eval!(trace_eval, Column::BytePopcount);
    // 64-bit case: result[0] = sum of all 8 byte-popcount witnesses.
    // 32-bit case: result[0] = sum of low 4 byte-popcount witnesses.
    // is_64bit = 1 - is_32bit.
    let mut sum_lo4 = byte_popcount[0].clone();
    for i in 1..4 {
        sum_lo4 += byte_popcount[i].clone();
    }
    let mut sum_hi4 = byte_popcount[4].clone();
    for i in 5..WORD_SIZE {
        sum_hi4 += byte_popcount[i].clone();
    }
    // Combined sum: sum_lo4 + (1 - is_32bit) · sum_hi4.
    // result[0] - that_sum = 0, gated on is_count_set_bits.
    // Route `is_64bit · sum_hi4` through Is64bitPopcountHiH.
    eval.add_constraint(
        is_count_set_bits[0].clone()
            * (result[0].clone() - sum_lo4 - is_64bit_popcount_hi_h[0].clone()),
    );
    // High bytes of result are zero on CSB rows (popcount ≤ 64 fits in result[0]).
    for i in 1..WORD_SIZE {
        eval.add_constraint(is_count_set_bits[0].clone() * result[i].clone());
    }
}

/// LeadingZeroBits and TrailingZeroBits: the partial non-zero recurrences and the result helpers.
pub(in crate::chips::cpu) fn leading_trailing_zeros_helpers<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
) {
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
    let is_64bit = E::F::one() - is_32bit[0].clone();
    let val_d_byte_indicator_h = crate::trace::trace_eval!(trace_eval, Column::ValDByteIndicatorH);
    let part_nz_msb_times_ind_h = crate::trace::trace_eval!(trace_eval, Column::PartNZMsbTimesIndH);
    let part_nz_msb_lo_times_ind_h =
        crate::trace::trace_eval!(trace_eval, Column::PartNZMsbLoTimesIndH);
    // ════════════════════════════════════════════════════════════════════
    // BITMANIP LeadingZeroBits / TrailingZeroBits 32 / 64.
    //
    // Per-byte LZ/TZ are bound via a separate (byte, lz, tz) lookup
    // (BitcountChip, 256-row preprocessed table).  The result formula
    // uses `ValDPartialNZ` (LSB-direction prefix-OR) for TZ, and
    // `ValDPartialNZMsb[8]` (MSB-direction prefix-OR) plus
    // `ValDPartialNZMsbLo[4]` (MSB over low-4-bytes only) for LZ.  All
    // three chains piggyback on `ValDByteInv` to compute byte
    // indicators.
    //
    // First-non-zero indicator at position i: `is_first_nz[i] =
    //   partial[i] − partial[i-1]` (with partial[-1] := 0).  For a
    //   non-zero val_d this is 1 at exactly one index k (the first
    //   non-zero byte) and 0 elsewhere; for val_d = 0 it's 0 at all
    //   positions.  Sum_{i} is_first_nz[i] = partial[last]
    //   (telescoping), so when val_d = 0 the default 64/32 fallback
    //   is gated on `1 − partial[last]`.
    //
    // Result formulas:
    //   TZ64: result[0] = sum_{i=0..7} is_first_nz[i] · (8·i + TzByte[i])
    //                     + (1 − partial[7]) · 64
    //   TZ32: result[0] = sum_{i=0..3} is_first_nz[i] · (8·i + TzByte[i])
    //                     + (1 − partial[3]) · 32
    //   LZ64: result[0] = sum_{i=0..7} is_first_nz_msb[i] · (8·(7−i)
    //                       + LzByte[i])
    //                     + (1 − partial_msb[0]) · 64
    //   LZ32: result[0] = sum_{i=0..3} is_first_nz_msb_lo[i] · (8·(3−i)
    //                       + LzByte[i])
    //                     + (1 − partial_msb_lo[0]) · 32
    // ════════════════════════════════════════════════════════════════════
    let is_lzb = crate::trace::trace_eval!(trace_eval, Column::IsLzb);
    let is_tzb = crate::trace::trace_eval!(trace_eval, Column::IsTzb);
    let bit_op_lz_byte = crate::trace::trace_eval!(trace_eval, Column::BitOpLzByte);
    let bit_op_tz_byte = crate::trace::trace_eval!(trace_eval, Column::BitOpTzByte);
    let val_d_partial_nz_p34 = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZ);
    let val_d_partial_nz_msb = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZMsb);
    let val_d_partial_nz_msb_lo = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZMsbLo);

    // ── ValDPartialNZMsb[8] recurrence ──
    // PartialNZMsb[7] = ByteIndicator[7]; for i < 7, OR-recurrence
    // routed through PartNZMsbTimesIndH[i] body helper.
    eval.add_constraint(
        is_real.clone() * (val_d_partial_nz_msb[7].clone() - val_d_byte_indicator_h[7].clone()),
    );
    for i in (0..7).rev() {
        // OR(prev, ind) = prev + ind - prev·ind, with prev =
        // PartialNZMsb[i+1] and ind = ByteIndicator[i].
        eval.add_constraint(
            is_real.clone()
                * (val_d_partial_nz_msb[i].clone()
                    - val_d_partial_nz_msb[i + 1].clone()
                    - val_d_byte_indicator_h[i].clone()
                    + part_nz_msb_times_ind_h[i].clone()),
        );
    }

    // ── ValDPartialNZMsbLo[4] recurrence ──
    eval.add_constraint(
        is_real.clone() * (val_d_partial_nz_msb_lo[3].clone() - val_d_byte_indicator_h[3].clone()),
    );
    for i in (0..3).rev() {
        eval.add_constraint(
            is_real.clone()
                * (val_d_partial_nz_msb_lo[i].clone()
                    - val_d_partial_nz_msb_lo[i + 1].clone()
                    - val_d_byte_indicator_h[i].clone()
                    + part_nz_msb_lo_times_ind_h[i].clone()),
        );
    }

    // ── TZ / LZ result binding ──
    let tz_lo4_h = crate::trace::trace_eval!(trace_eval, Column::TzLo4H);
    let tz_hi4_h = crate::trace::trace_eval!(trace_eval, Column::TzHi4H);
    let lz64_h = crate::trace::trace_eval!(trace_eval, Column::Lz64H);
    let lz32_h = crate::trace::trace_eval!(trace_eval, Column::Lz32H);
    let is_tzb_64_h = crate::trace::trace_eval!(trace_eval, Column::IsTzb64H);
    let is_tzb_32_h = crate::trace::trace_eval!(trace_eval, Column::IsTzb32H);
    let is_lzb_64_h = crate::trace::trace_eval!(trace_eval, Column::IsLzb64H);
    let is_lzb_32_h = crate::trace::trace_eval!(trace_eval, Column::IsLzb32H);
    // Helper-defining constraints (deg 2 each).
    {
        // TzLo4H = sum_{i<4} (PartialNZ[i] - PartialNZ[i-1]) · (8i + TzByte[i]).
        let mut tz_lo4_expr = E::F::zero();
        let mut tz_hi4_expr = E::F::zero();
        for i in 0..WORD_SIZE {
            let prev = if i == 0 {
                E::F::zero()
            } else {
                val_d_partial_nz_p34[i - 1].clone()
            };
            let is_first_nz = val_d_partial_nz_p34[i].clone() - prev;
            let term = is_first_nz
                * (E::F::from(BaseField::from(8u32 * i as u32)) + bit_op_tz_byte[i].clone());
            if i < 4 {
                tz_lo4_expr += term;
            } else {
                tz_hi4_expr += term;
            }
        }
        eval.add_constraint(tz_lo4_h[0].clone() - tz_lo4_expr);
        eval.add_constraint(tz_hi4_h[0].clone() - tz_hi4_expr);
        // Lz64H = sum_{i<8} (PartialNZMsb[i] - PartialNZMsb[i+1]) · (8(7-i) + LzByte[i]).
        let mut lz64_expr = E::F::zero();
        for i in 0..WORD_SIZE {
            let next = if i + 1 < WORD_SIZE {
                val_d_partial_nz_msb[i + 1].clone()
            } else {
                E::F::zero()
            };
            let is_first_nz_msb = val_d_partial_nz_msb[i].clone() - next;
            let pos_weight = 8u32 * (7 - i as u32);
            lz64_expr += is_first_nz_msb
                * (E::F::from(BaseField::from(pos_weight)) + bit_op_lz_byte[i].clone());
        }
        eval.add_constraint(lz64_h[0].clone() - lz64_expr);
        // Lz32H = sum_{i<4} (PartialNZMsbLo[i] - PartialNZMsbLo[i+1]) · (8(3-i) + LzByte[i]).
        let mut lz32_expr = E::F::zero();
        for i in 0..4 {
            let next = if i + 1 < 4 {
                val_d_partial_nz_msb_lo[i + 1].clone()
            } else {
                E::F::zero()
            };
            let is_first_nz_msb_lo = val_d_partial_nz_msb_lo[i].clone() - next;
            let pos_weight = 8u32 * (3 - i as u32);
            lz32_expr += is_first_nz_msb_lo
                * (E::F::from(BaseField::from(pos_weight)) + bit_op_lz_byte[i].clone());
        }
        eval.add_constraint(lz32_h[0].clone() - lz32_expr);
        // Is{Tzb,Lzb}{64,32}H selectors.
        eval.add_constraint(is_tzb_64_h[0].clone() - is_tzb[0].clone() * is_64bit.clone());
        eval.add_constraint(is_tzb_32_h[0].clone() - is_tzb[0].clone() * is_32bit[0].clone());
        eval.add_constraint(is_lzb_64_h[0].clone() - is_lzb[0].clone() * is_64bit.clone());
        eval.add_constraint(is_lzb_32_h[0].clone() - is_lzb[0].clone() * is_32bit[0].clone());
    }
}

/// LeadingZeroBits and TrailingZeroBits: the results.
pub(in crate::chips::cpu) fn leading_trailing_zeros<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
) {
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    let is_lzb = crate::trace::trace_eval!(trace_eval, Column::IsLzb);
    let is_tzb = crate::trace::trace_eval!(trace_eval, Column::IsTzb);
    let val_d_partial_nz_p34 = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZ);
    let val_d_partial_nz_msb = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZMsb);
    let val_d_partial_nz_msb_lo = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZMsbLo);
    let tz_lo4_h = crate::trace::trace_eval!(trace_eval, Column::TzLo4H);
    let tz_hi4_h = crate::trace::trace_eval!(trace_eval, Column::TzHi4H);
    let lz64_h = crate::trace::trace_eval!(trace_eval, Column::Lz64H);
    let lz32_h = crate::trace::trace_eval!(trace_eval, Column::Lz32H);
    let is_tzb_64_h = crate::trace::trace_eval!(trace_eval, Column::IsTzb64H);
    let is_tzb_32_h = crate::trace::trace_eval!(trace_eval, Column::IsTzb32H);
    let is_lzb_64_h = crate::trace::trace_eval!(trace_eval, Column::IsLzb64H);
    let is_lzb_32_h = crate::trace::trace_eval!(trace_eval, Column::IsLzb32H);
    // Main TZ constraint flattened to a sum of deg-2 terms.
    // Original: is_tzb · (result[0] - tz_expr) = 0 with tz_expr deg 3.
    // Flatten: is_tzb·result - is_tzb·TzLo4H
    //          - IsTzb64H·(TzHi4H + 64·(1 - PartialNZ[7]))
    //          - IsTzb32H · 32·(1 - PartialNZ[3])  = 0
    let tz_default_64_lin =
        E::F::from(BaseField::from(64u32)) * (E::F::one() - val_d_partial_nz_p34[7].clone());
    let tz_default_32_lin =
        E::F::from(BaseField::from(32u32)) * (E::F::one() - val_d_partial_nz_p34[3].clone());
    eval.add_constraint(
        is_tzb[0].clone() * (result[0].clone() - tz_lo4_h[0].clone())
            - is_tzb_64_h[0].clone() * (tz_hi4_h[0].clone() + tz_default_64_lin)
            - is_tzb_32_h[0].clone() * tz_default_32_lin,
    );
    // Main LZ constraint flattened similarly.
    let lz_default_64_lin =
        E::F::from(BaseField::from(64u32)) * (E::F::one() - val_d_partial_nz_msb[0].clone());
    let lz_default_32_lin =
        E::F::from(BaseField::from(32u32)) * (E::F::one() - val_d_partial_nz_msb_lo[0].clone());
    eval.add_constraint(
        is_lzb[0].clone() * result[0].clone()
            - is_lzb_64_h[0].clone() * (lz64_h[0].clone() + lz_default_64_lin)
            - is_lzb_32_h[0].clone() * (lz32_h[0].clone() + lz_default_32_lin),
    );

    // High bytes of result are zero on LZ/TZ rows.
    for i in 1..WORD_SIZE {
        eval.add_constraint((is_lzb[0].clone() + is_tzb[0].clone()) * result[i].clone());
    }
}

/// SignExtend8 and SignExtend16: the nibble lookups.
pub(in crate::chips::cpu) fn sign_extend_nibbles<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let bitwise_and_lookup = lookups.bitwise_and_lookup;
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let is_sign_ext_8 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt8);
    let is_sign_ext_16 = crate::trace::trace_eval!(trace_eval, Column::IsSignExt16);
    let sign_ext_bit = crate::trace::trace_eval!(trace_eval, Column::SignExtBit);
    // ════════════════════════════════════════════════════════════════════
    // BITMANIP — SignExtend8/16 nibble lookups
    //
    // Placed immediately before finalize_logup_in_pairs so the 4 emissions
    // (2a, 2b, 3a, 3b) pair within themselves and don't reshuffle existing
    // pair constraints.  Reshuffling could push a downstream pair past the
    // chip's degree bound.
    //
    // Tuples (degree-1 each, kept simple to stay within bound):
    //   (2a) gated on IsSE8: (SignExtSrcHiNib, 8, 8·SignExtBit)
    //   (2b) gated on IsSE16: same tuple
    //   (3a) gated on IsSE8: (val_d[0] - 16·SignExtSrcHiNib, 0xF, same)
    //   (3b) gated on IsSE16: (val_d[1] - 16·SignExtSrcHiNib, 0xF, same)
    // ════════════════════════════════════════════════════════════════════
    {
        let sign_ext_hi_nib = crate::trace::trace_eval!(trace_eval, Column::SignExtSrcHiNib);
        let sixteen_se: E::F = E::F::from(BaseField::from(16));
        let eight_se: E::F = E::F::from(BaseField::from(8));
        let fifteen_se: E::F = E::F::from(BaseField::from(15));
        // (2a)
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_sign_ext_8[0].clone().into(),
            &[
                sign_ext_hi_nib[0].clone(),
                eight_se.clone(),
                sign_ext_bit[0].clone() * eight_se.clone(),
            ],
        ));
        // (2b)
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_sign_ext_16[0].clone().into(),
            &[
                sign_ext_hi_nib[0].clone(),
                eight_se.clone(),
                sign_ext_bit[0].clone() * eight_se,
            ],
        ));
        // (3a)
        let lo_8 = val_d[0].clone() - sign_ext_hi_nib[0].clone() * sixteen_se.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_sign_ext_8[0].clone().into(),
            &[lo_8.clone(), fifteen_se.clone(), lo_8],
        ));
        // (3b)
        let lo_16 = val_d[1].clone() - sign_ext_hi_nib[0].clone() * sixteen_se;
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_sign_ext_16[0].clone().into(),
            &[lo_16.clone(), fifteen_se, lo_16],
        ));
    }
}
