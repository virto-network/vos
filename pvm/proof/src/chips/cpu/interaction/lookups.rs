//! The lookups into the table and arithmetic chips.

use super::*;

/// The power-of-two, popcount and bitcount lookups.
pub(super) fn table_lookups(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    // Power-of-two lookup: (shift_amount, val_d[8]) when shift is constrained.
    // Two emissions: one keyed on ShiftAmount with multiplicity
    // `is_shift_c · (1 − is_rotate_r64 − is_rotate_r32)`, and one keyed
    // on ShiftAmountCompl with multiplicity `is_rotate_r64 + is_rotate_r32`.
    let pow2_lookup: &PowerOfTwoLookupElements = lookup_elements.as_ref();
    let shift_amount_col =
        crate::trace::original_base_column!(component_trace, Column::ShiftAmount);
    let is_shift_constrained =
        crate::trace::original_base_column!(component_trace, Column::IsShiftConstrained);
    let is_rotate_r64_col_pow2 =
        crate::trace::original_base_column!(component_trace, Column::IsRotateR64);
    let is_rotate_r32_col_pow2 =
        crate::trace::original_base_column!(component_trace, Column::IsRotateR32);
    let shift_amount_compl_col =
        crate::trace::original_base_column!(component_trace, Column::ShiftAmountCompl);
    let val_d_cols = crate::trace::original_base_column!(component_trace, Column::ValD);
    {
        let mut tuple: Vec<_> = vec![shift_amount_col[0].clone()];
        tuple.extend_from_slice(&val_d_cols);
        logup.add_to_relation_with(
            pow2_lookup,
            [
                is_shift_constrained[0].clone(),
                is_rotate_r64_col_pow2[0].clone(),
                is_rotate_r32_col_pow2[0].clone(),
            ],
            |[shc, r64, r32]| (shc - r64 - r32).into(),
            &tuple,
        );
    }
    // Separate PowerOfTwo emission for RotR64 / RotR32 keyed on
    // ShiftAmountCompl.
    {
        let mut tuple: Vec<_> = vec![shift_amount_compl_col[0].clone()];
        tuple.extend_from_slice(&val_d_cols);
        logup.add_to_relation_with(
            pow2_lookup,
            [
                is_rotate_r64_col_pow2[0].clone(),
                is_rotate_r32_col_pow2[0].clone(),
            ],
            |[r64, r32]| (r64 + r32).into(),
            &tuple,
        );
    }

    // Popcount lookup — per-byte (val_d[i], BytePopcount[i]) on
    // CountSetBits rows.  Mirror of the verifier-side emission.
    {
        let popcount_lookup: &PopcountLookupElements = lookup_elements.as_ref();
        let is_count_set_bits_col =
            crate::trace::original_base_column!(component_trace, Column::IsCountSetBits);
        let byte_popcount_col =
            crate::trace::original_base_column!(component_trace, Column::BytePopcount);
        for i in 0..WORD_SIZE {
            logup.add_to_relation_with(
                popcount_lookup,
                [is_count_set_bits_col[0].clone()],
                |[active]| active.into(),
                &[val_d_cols[i].clone(), byte_popcount_col[i].clone()],
            );
        }
    }

    // Bitcount lookup — per-byte (val_d[i], BitOpLzByte[i],
    // BitOpTzByte[i]) on LZ/TZ rows.  Multiplicity = is_lzb + is_tzb.
    {
        let bitcount_lookup: &BitcountLookupElements = lookup_elements.as_ref();
        let is_lzb_col = crate::trace::original_base_column!(component_trace, Column::IsLzb);
        let is_tzb_col = crate::trace::original_base_column!(component_trace, Column::IsTzb);
        let lz_col = crate::trace::original_base_column!(component_trace, Column::BitOpLzByte);
        let tz_col = crate::trace::original_base_column!(component_trace, Column::BitOpTzByte);
        for i in 0..WORD_SIZE {
            logup.add_to_relation_with(
                bitcount_lookup,
                [is_lzb_col[0].clone(), is_tzb_col[0].clone()],
                |[lz, tz]| (lz + tz).into(),
                &[val_d_cols[i].clone(), lz_col[i].clone(), tz_col[i].clone()],
            );
        }
    }
}

/// The arithmetic chips' tuples: multiplication, division, comparison and
/// the bitwise operations.
pub(super) fn arithmetic(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    // DivCmpDiff Range256 emissions live in DivRemChip
    // (witnesses + range-checks on its own trace).

    // AbsCmpDiff Range256 emissions live in DivRemChip.

    // ── MultiplicationLookup producer (prover-side mirror) ──
    // Tuple (35 limbs): val_b[8] + val_d[8] + result[8] +
    //   sign_bit_b + sign_bit_d + 4 rotate flags + 5 mul flags.
    {
        let mul_p54: &MultiplicationLookupElements = lookup_elements.as_ref();
        let f_is_mul_p54 = crate::trace::original_base_column!(component_trace, Column::IsMul);
        let f_mu_uu_p54 =
            crate::trace::original_base_column!(component_trace, Column::IsMulUpperUU);
        let f_mu_su_p54 =
            crate::trace::original_base_column!(component_trace, Column::IsMulUpperSU);
        let f_mu_ss_p54 =
            crate::trace::original_base_column!(component_trace, Column::IsMulUpperSS);
        let f_is_32bit_p54 = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let f_rot_l64_p54 =
            crate::trace::original_base_column!(component_trace, Column::IsRotateL64);
        let f_rot_r64_p54 =
            crate::trace::original_base_column!(component_trace, Column::IsRotateR64);
        let f_rot_l32_p54 =
            crate::trace::original_base_column!(component_trace, Column::IsRotateL32);
        let f_rot_r32_p54 =
            crate::trace::original_base_column!(component_trace, Column::IsRotateR32);
        let val_b_p54 = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d_p54 = crate::trace::original_base_column!(component_trace, Column::ValD);
        let result_p54 = crate::trace::original_base_column!(component_trace, Column::Result);
        let sign_bit_b_p54 = crate::trace::original_base_column!(component_trace, Column::SignBitB);
        let sign_bit_d_p54 = crate::trace::original_base_column!(component_trace, Column::SignBitD);

        // Slot 30 (= 3*8 + 6) is IsMulLo; override via the closure.
        const IS_MUL_LO_SLOT: usize = 30;
        let mut tuple_p54: Vec<_> = Vec::with_capacity(35);
        tuple_p54.extend_from_slice(&val_b_p54);
        tuple_p54.extend_from_slice(&val_d_p54);
        tuple_p54.extend_from_slice(&result_p54);
        tuple_p54.push(sign_bit_b_p54[0].clone());
        tuple_p54.push(sign_bit_d_p54[0].clone());
        tuple_p54.push(f_rot_l64_p54[0].clone());
        tuple_p54.push(f_rot_r64_p54[0].clone());
        tuple_p54.push(f_rot_l32_p54[0].clone());
        tuple_p54.push(f_rot_r32_p54[0].clone());
        tuple_p54.push(crate::trace::component::FinalizedColumn::Constant(
            BaseField::from(0),
        ));
        tuple_p54.push(f_mu_uu_p54[0].clone());
        tuple_p54.push(f_mu_su_p54[0].clone());
        tuple_p54.push(f_mu_ss_p54[0].clone());
        tuple_p54.push(f_is_32bit_p54[0].clone());

        for _ in 0..2 {
            let is_mul_c = f_is_mul_p54[0].clone();
            let mu_uu_c = f_mu_uu_p54[0].clone();
            let mu_su_c = f_mu_su_p54[0].clone();
            let mu_ss_c = f_mu_ss_p54[0].clone();
            logup.add_to_relation_computed(
                mul_p54,
                [f_is_mul_p54[0].clone()],
                |[m]| m.into(),
                35,
                {
                    let tuple_clone: Vec<_> = tuple_p54.clone();
                    move |i| {
                        let mut t: Vec<_> = tuple_clone.iter().map(|c| c.at(i)).collect();
                        t[IS_MUL_LO_SLOT] =
                            is_mul_c.at(i) - mu_uu_c.at(i) - mu_su_c.at(i) - mu_ss_c.at(i);
                        t
                    }
                },
            );
        }
    }

    // ── DivRemLookup producer (prover-side mirror) ──
    // 41-limb tuple (4 sign bits, is_div_s, is_shar_r).
    {
        let divrem_p54g: &DivRemLookupElements = lookup_elements.as_ref();
        let val_b_p54g = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d_p54g = crate::trace::original_base_column!(component_trace, Column::ValD);
        let dq_p54g = crate::trace::original_base_column!(component_trace, Column::DivQuotient);
        let dr_p54g = crate::trace::original_base_column!(component_trace, Column::DivRemainder);
        let sb_p54k = crate::trace::original_base_column!(component_trace, Column::SignBitB);
        let sd_p54k = crate::trace::original_base_column!(component_trace, Column::SignBitD);
        let sq_p54k = crate::trace::original_base_column!(component_trace, Column::SignBitQ);
        let sr_p54k = crate::trace::original_base_column!(component_trace, Column::SignBitR);
        let dbz_p54g = crate::trace::original_base_column!(component_trace, Column::DivByZero);
        let is_dr_p54g = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
        let is_32_p54g = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_ds_p54g = crate::trace::original_base_column!(component_trace, Column::IsDivS);
        let mut tuple_p54g: Vec<_> = val_b_p54g.to_vec();
        tuple_p54g.extend_from_slice(&val_d_p54g);
        tuple_p54g.extend_from_slice(&dq_p54g);
        tuple_p54g.extend_from_slice(&dr_p54g);
        tuple_p54g.push(sb_p54k[0].clone());
        tuple_p54g.push(sd_p54k[0].clone());
        tuple_p54g.push(sq_p54k[0].clone());
        tuple_p54g.push(sr_p54k[0].clone());
        tuple_p54g.push(is_dr_p54g[0].clone());
        tuple_p54g.push(dbz_p54g[0].clone());
        tuple_p54g.push(is_32_p54g[0].clone());
        tuple_p54g.push(is_ds_p54g[0].clone());
        let is_shar_r = crate::trace::original_base_column!(component_trace, Column::IsSharR);
        tuple_p54g.push(is_shar_r[0].clone());
        for _ in 0..2 {
            logup.add_to_relation_with(
                divrem_p54g,
                [is_dr_p54g[0].clone()],
                |[m]| m.into(),
                &tuple_p54g,
            );
        }
    }

    // ── CompareLookup producer (prover-side mirror) ──
    // Tuple (17 limbs): val_b[8] + val_d[8] + cmp_lt_flag.
    // Multiplicity = is_compare + is_branch (= sum of 18 sub-flags).
    {
        let compare_p54f: &CompareLookupElements = lookup_elements.as_ref();
        let val_b_p54f = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d_p54f = crate::trace::original_base_column!(component_trace, Column::ValD);
        let cmp_lt_p54f = crate::trace::original_base_column!(component_trace, Column::CmpLtFlag);
        let is_setltu = crate::trace::original_base_column!(component_trace, Column::IsSetLtU);
        let is_setlts = crate::trace::original_base_column!(component_trace, Column::IsSetLtS);
        let is_cmoviz = crate::trace::original_base_column!(component_trace, Column::IsCmovIz);
        let is_cmovnz = crate::trace::original_base_column!(component_trace, Column::IsCmovNz);
        let is_mins = crate::trace::original_base_column!(component_trace, Column::IsMinS);
        let is_minu = crate::trace::original_base_column!(component_trace, Column::IsMinU);
        let is_maxs = crate::trace::original_base_column!(component_trace, Column::IsMaxS);
        let is_maxu = crate::trace::original_base_column!(component_trace, Column::IsMaxU);
        let is_br_eq = crate::trace::original_base_column!(component_trace, Column::IsBrEq);
        let is_br_ne = crate::trace::original_base_column!(component_trace, Column::IsBrNe);
        let is_br_lt_u = crate::trace::original_base_column!(component_trace, Column::IsBrLtU);
        let is_br_ge_u = crate::trace::original_base_column!(component_trace, Column::IsBrGeU);
        let is_br_le_u = crate::trace::original_base_column!(component_trace, Column::IsBrLeU);
        let is_br_gt_u = crate::trace::original_base_column!(component_trace, Column::IsBrGtU);
        let is_br_lt_s = crate::trace::original_base_column!(component_trace, Column::IsBrLtS);
        let is_br_ge_s = crate::trace::original_base_column!(component_trace, Column::IsBrGeS);
        let is_br_le_s = crate::trace::original_base_column!(component_trace, Column::IsBrLeS);
        let is_br_gt_s = crate::trace::original_base_column!(component_trace, Column::IsBrGtS);
        let mut tuple_p54f: Vec<_> = val_b_p54f.to_vec();
        tuple_p54f.extend_from_slice(&val_d_p54f);
        tuple_p54f.push(cmp_lt_p54f[0].clone());
        for _ in 0..2 {
            logup.add_to_relation_with(
                compare_p54f,
                [
                    is_setltu[0].clone(),
                    is_setlts[0].clone(),
                    is_cmoviz[0].clone(),
                    is_cmovnz[0].clone(),
                    is_mins[0].clone(),
                    is_minu[0].clone(),
                    is_maxs[0].clone(),
                    is_maxu[0].clone(),
                    is_br_eq[0].clone(),
                    is_br_ne[0].clone(),
                    is_br_lt_u[0].clone(),
                    is_br_ge_u[0].clone(),
                    is_br_le_u[0].clone(),
                    is_br_gt_u[0].clone(),
                    is_br_lt_s[0].clone(),
                    is_br_ge_s[0].clone(),
                    is_br_le_s[0].clone(),
                    is_br_gt_s[0].clone(),
                ],
                |[
                    a,
                    b,
                    c,
                    d,
                    e,
                    f,
                    g,
                    h,
                    br_eq,
                    br_ne,
                    br_lt_u,
                    br_ge_u,
                    br_le_u,
                    br_gt_u,
                    br_lt_s,
                    br_ge_s,
                    br_le_s,
                    br_gt_s,
                ]| {
                    (a + b
                        + c
                        + d
                        + e
                        + f
                        + g
                        + h
                        + br_eq
                        + br_ne
                        + br_lt_u
                        + br_ge_u
                        + br_le_u
                        + br_gt_u
                        + br_lt_s
                        + br_ge_s
                        + br_le_s
                        + br_gt_s)
                        .into()
                },
                &tuple_p54f,
            );
        }
    }

    // ── BitwiseLookup producer (prover-side mirror) ──
    // Tuple (30 limbs): val_b[8] + val_d[8] + result[8] + 6 sub-flags.
    {
        let bitwise_p54e: &BitwiseLookupElements = lookup_elements.as_ref();
        let val_b_p54e = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d_p54e = crate::trace::original_base_column!(component_trace, Column::ValD);
        let result_p54e = crate::trace::original_base_column!(component_trace, Column::Result);
        let f_and = crate::trace::original_base_column!(component_trace, Column::IsAnd);
        let f_or = crate::trace::original_base_column!(component_trace, Column::IsOr);
        let f_xor = crate::trace::original_base_column!(component_trace, Column::IsXor);
        let f_andinv = crate::trace::original_base_column!(component_trace, Column::IsAndInv);
        let f_orinv = crate::trace::original_base_column!(component_trace, Column::IsOrInv);
        let f_xnor = crate::trace::original_base_column!(component_trace, Column::IsXnor);
        let mut tuple_p54e: Vec<_> = val_b_p54e.to_vec();
        tuple_p54e.extend_from_slice(&val_d_p54e);
        tuple_p54e.extend_from_slice(&result_p54e);
        tuple_p54e.push(f_and[0].clone());
        tuple_p54e.push(f_or[0].clone());
        tuple_p54e.push(f_xor[0].clone());
        tuple_p54e.push(f_andinv[0].clone());
        tuple_p54e.push(f_orinv[0].clone());
        tuple_p54e.push(f_xnor[0].clone());
        for _ in 0..2 {
            logup.add_to_relation_with(
                bitwise_p54e,
                [
                    f_and[0].clone(),
                    f_or[0].clone(),
                    f_xor[0].clone(),
                    f_andinv[0].clone(),
                    f_orinv[0].clone(),
                    f_xnor[0].clone(),
                ],
                |[a, b, c, d, e, f]| (a + b + c + d + e + f).into(),
                &tuple_p54e,
            );
        }
    }
}
