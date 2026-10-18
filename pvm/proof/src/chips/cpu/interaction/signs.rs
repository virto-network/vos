//! The sign bits' and sign extensions' nibble lookups.

use super::*;

/// The sign extensions' nibble lookups.
pub(super) fn sign_extension(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    let bitwise_and: &BitwiseAndLookupElements = lookup_elements.as_ref();
    let sixteen = PackedBaseField::broadcast(BaseField::from(16));
    let val_d_cols = crate::trace::original_base_column!(component_trace, Column::ValD);
    // ── BitManip SE nibble lookups ──
    // 4 emissions paired with verifier-side (2a, 2b, 3a, 3b).  Last block
    // before finalize() so they pair within themselves.
    {
        let is_se8 = crate::trace::original_base_column!(component_trace, Column::IsSignExt8);
        let is_se16 = crate::trace::original_base_column!(component_trace, Column::IsSignExt16);
        let se_bit = crate::trace::original_base_column!(component_trace, Column::SignExtBit);
        let se_hi = crate::trace::original_base_column!(component_trace, Column::SignExtSrcHiNib);
        let eight_p = PackedBaseField::broadcast(BaseField::from(8));
        let fifteen_p = PackedBaseField::broadcast(BaseField::from(15));
        let val_d_0 = val_d_cols[0].clone();
        let val_d_1 = val_d_cols[1].clone();

        let hi_2a = se_hi[0].clone();
        let bit_2a = se_bit[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [is_se8[0].clone()],
            |[m]| m.into(),
            3,
            |i| vec![hi_2a.at(i), eight_p, bit_2a.at(i) * eight_p],
        );
        let hi_2b = se_hi[0].clone();
        let bit_2b = se_bit[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [is_se16[0].clone()],
            |[m]| m.into(),
            3,
            |i| vec![hi_2b.at(i), eight_p, bit_2b.at(i) * eight_p],
        );
        let hi_3a = se_hi[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [is_se8[0].clone()],
            |[m]| m.into(),
            3,
            |i| {
                let lo = val_d_0.at(i) - hi_3a.at(i) * sixteen;
                vec![lo, fifteen_p, lo]
            },
        );
        let hi_3b = se_hi[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [is_se16[0].clone()],
            |[m]| m.into(),
            3,
            |i| {
                let lo = val_d_1.at(i) - hi_3b.at(i) * sixteen;
                vec![lo, fifteen_p, lo]
            },
        );
    }
}

/// The sign bits' nibble lookups.
pub(super) fn sign_nibbles(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    let bitwise_and: &BitwiseAndLookupElements = lookup_elements.as_ref();
    // ── sign-bit nibble lookups (8 emissions) ──
    // Mirrors the verifier-side block placed just before
    // finalize_logup_in_pairs.  Same tuple shape, same multiplicity
    // (is_real per row), same emission order.
    {
        let is_pad_col = crate::trace::original_base_column!(component_trace, Column::IsPadding);
        let sign_src_b = crate::trace::original_base_column!(component_trace, Column::SignSrcB);
        let sign_src_d = crate::trace::original_base_column!(component_trace, Column::SignSrcD);
        let sign_src_q = crate::trace::original_base_column!(component_trace, Column::SignSrcQ);
        let sign_src_r = crate::trace::original_base_column!(component_trace, Column::SignSrcR);
        let sign_b_hi = crate::trace::original_base_column!(component_trace, Column::SignBHiNib);
        let sign_d_hi = crate::trace::original_base_column!(component_trace, Column::SignDHiNib);
        let sign_q_hi = crate::trace::original_base_column!(component_trace, Column::SignQHiNib);
        let sign_r_hi = crate::trace::original_base_column!(component_trace, Column::SignRHiNib);
        let sign_bit_b = crate::trace::original_base_column!(component_trace, Column::SignBitB);
        let sign_bit_d = crate::trace::original_base_column!(component_trace, Column::SignBitD);
        let sign_bit_q = crate::trace::original_base_column!(component_trace, Column::SignBitQ);
        let sign_bit_r = crate::trace::original_base_column!(component_trace, Column::SignBitR);

        let one_p = PackedBaseField::broadcast(BaseField::from(1));
        let eight_p = PackedBaseField::broadcast(BaseField::from(8));
        let fifteen_p = PackedBaseField::broadcast(BaseField::from(15));
        let sixteen_p = PackedBaseField::broadcast(BaseField::from(16));

        // Emit (hi, 8, 8·bit) and (src - 16·hi, 0xF, same) for each
        // sign bit, in the same order as the verifier-side block:
        // B → D → Q → R, hi-pin first then lo-range each.
        let hi_b = sign_b_hi[0].clone();
        let bit_b = sign_bit_b[0].clone();
        let pad_b1 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_b1],
            |[p]| (one_p - p).into(),
            3,
            |i| vec![hi_b.at(i), eight_p, bit_b.at(i) * eight_p],
        );
        let src_b = sign_src_b[0].clone();
        let hi_b2 = sign_b_hi[0].clone();
        let pad_b2 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_b2],
            |[p]| (one_p - p).into(),
            3,
            |i| {
                let lo = src_b.at(i) - hi_b2.at(i) * sixteen_p;
                vec![lo, fifteen_p, lo]
            },
        );

        let hi_d = sign_d_hi[0].clone();
        let bit_d = sign_bit_d[0].clone();
        let pad_d1 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_d1],
            |[p]| (one_p - p).into(),
            3,
            |i| vec![hi_d.at(i), eight_p, bit_d.at(i) * eight_p],
        );
        let src_d = sign_src_d[0].clone();
        let hi_d2 = sign_d_hi[0].clone();
        let pad_d2 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_d2],
            |[p]| (one_p - p).into(),
            3,
            |i| {
                let lo = src_d.at(i) - hi_d2.at(i) * sixteen_p;
                vec![lo, fifteen_p, lo]
            },
        );

        let hi_q = sign_q_hi[0].clone();
        let bit_q = sign_bit_q[0].clone();
        let pad_q1 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_q1],
            |[p]| (one_p - p).into(),
            3,
            |i| vec![hi_q.at(i), eight_p, bit_q.at(i) * eight_p],
        );
        let src_q = sign_src_q[0].clone();
        let hi_q2 = sign_q_hi[0].clone();
        let pad_q2 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_q2],
            |[p]| (one_p - p).into(),
            3,
            |i| {
                let lo = src_q.at(i) - hi_q2.at(i) * sixteen_p;
                vec![lo, fifteen_p, lo]
            },
        );

        let hi_r = sign_r_hi[0].clone();
        let bit_r = sign_bit_r[0].clone();
        let pad_r1 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_r1],
            |[p]| (one_p - p).into(),
            3,
            |i| vec![hi_r.at(i), eight_p, bit_r.at(i) * eight_p],
        );
        let src_r = sign_src_r[0].clone();
        let hi_r2 = sign_r_hi[0].clone();
        let pad_r2 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_r2],
            |[p]| (one_p - p).into(),
            3,
            |i| {
                let lo = src_r.at(i) - hi_r2.at(i) * sixteen_p;
                vec![lo, fifteen_p, lo]
            },
        );

        // SignBitResult — pin to bit 7 of result[3].
        let result_cols = crate::trace::original_base_column!(component_trace, Column::Result);
        let sign_bit_result_col =
            crate::trace::original_base_column!(component_trace, Column::SignBitResult);
        let result_hi_col =
            crate::trace::original_base_column!(component_trace, Column::ResultHiNib);
        let hi_res = result_hi_col[0].clone();
        let bit_res = sign_bit_result_col[0].clone();
        let pad_res1 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_res1],
            |[p]| (one_p - p).into(),
            3,
            |i| vec![hi_res.at(i), eight_p, bit_res.at(i) * eight_p],
        );
        let src_res = result_cols[3].clone();
        let hi_res2 = result_hi_col[0].clone();
        let pad_res2 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_res2],
            |[p]| (one_p - p).into(),
            3,
            |i| {
                let lo = src_res.at(i) - hi_res2.at(i) * sixteen_p;
                vec![lo, fifteen_p, lo]
            },
        );

        // LoadSignBit — pin to bit 7 of LoadSignSrc.
        let load_sign_src =
            crate::trace::original_base_column!(component_trace, Column::LoadSignSrc);
        let load_sign_bit_col =
            crate::trace::original_base_column!(component_trace, Column::LoadSignBit);
        let load_sign_hi_col =
            crate::trace::original_base_column!(component_trace, Column::LoadSignHiNib);
        let hi_load = load_sign_hi_col[0].clone();
        let bit_load = load_sign_bit_col[0].clone();
        let pad_load1 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_load1],
            |[p]| (one_p - p).into(),
            3,
            |i| vec![hi_load.at(i), eight_p, bit_load.at(i) * eight_p],
        );
        let src_load = load_sign_src[0].clone();
        let hi_load2 = load_sign_hi_col[0].clone();
        let pad_load2 = is_pad_col[0].clone();
        logup.add_to_relation_computed(
            bitwise_and,
            [pad_load2],
            |[p]| (one_p - p).into(),
            3,
            |i| {
                let lo = src_load.at(i) - hi_load2.at(i) * sixteen_p;
                vec![lo, fifteen_p, lo]
            },
        );
    }
}
