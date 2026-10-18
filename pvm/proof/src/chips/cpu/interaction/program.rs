//! The instruction fetch and its flag bits.

use super::*;

/// The instruction's fetch from ProgramMemoryChip.
pub(super) fn program_memory(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    // ── ProgramMemory consumer (prover-side, 2 paired, 37 limbs) ──
    {
        let prog_mem: &ProgramMemoryLookupElements = lookup_elements.as_ref();
        let pc = crate::trace::original_base_column!(component_trace, Column::Pc);
        let opcode = crate::trace::original_base_column!(component_trace, Column::Opcode);
        let skip_len = crate::trace::original_base_column!(component_trace, Column::SkipLen);
        let reg_a = crate::trace::original_base_column!(component_trace, Column::RegA);
        let reg_b = crate::trace::original_base_column!(component_trace, Column::RegB);
        let reg_d = crate::trace::original_base_column!(component_trace, Column::RegD);
        let imm_bytes = crate::trace::original_base_column!(component_trace, Column::ImmBytes);
        let fb0 = crate::trace::original_base_column!(component_trace, Column::FlagByte0);
        let fb1 = crate::trace::original_base_column!(component_trace, Column::FlagByte1);
        let fb2 = crate::trace::original_base_column!(component_trace, Column::FlagByte2);
        let fb3 = crate::trace::original_base_column!(component_trace, Column::FlagByte3);
        let fb4 = crate::trace::original_base_column!(component_trace, Column::FlagByte4);
        let fb5 = crate::trace::original_base_column!(component_trace, Column::FlagByte5);
        let imm_y_for_lookup =
            crate::trace::original_base_column!(component_trace, Column::ImmYBytes);
        let branch_target_for_lookup =
            crate::trace::original_base_column!(component_trace, Column::BranchTarget);
        let host_call_precompile_dispatch = crate::trace::original_base_column!(
            component_trace,
            Column::HostCallPrecompileDispatch
        );
        let is_pad_col = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        let mut tuple: Vec<_> = pc.to_vec();
        tuple.push(opcode[0].clone());
        tuple.push(skip_len[0].clone());
        tuple.push(reg_a[0].clone());
        tuple.push(reg_b[0].clone());
        tuple.push(reg_d[0].clone());
        tuple.extend_from_slice(&imm_bytes);
        tuple.push(fb0[0].clone());
        tuple.push(fb1[0].clone());
        tuple.push(fb2[0].clone());
        tuple.push(fb3[0].clone());
        tuple.push(fb4[0].clone());
        tuple.push(fb5[0].clone());
        for byte in [
            Column::FlagByte6,
            Column::FlagByte7,
            Column::FlagByte8,
            Column::FlagByte9,
        ] {
            tuple.push(component_trace.original_base_column::<1, _>(byte)[0].clone());
        }
        tuple.extend_from_slice(&imm_y_for_lookup);
        tuple.extend_from_slice(&branch_target_for_lookup);
        tuple.push(host_call_precompile_dispatch[0].clone());

        // Two paired emissions, multiplicity = is_real = 1 - is_padding.
        for _ in 0..2 {
            let is_pad = is_pad_col[0].clone();
            logup.add_to_relation_with(
                prog_mem,
                [is_pad],
                |[p]| {
                    let one_packed = stwo::prover::backend::simd::m31::PackedBaseField::broadcast(
                        BaseField::from(1),
                    );
                    (one_packed - p).into()
                },
                &tuple,
            );
        }
    }
}

/// The flag bytes' bits.
pub(super) fn flag_bits(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    let is_setltu_col = crate::trace::original_base_column!(component_trace, Column::IsSetLtU);
    let is_setlts_col = crate::trace::original_base_column!(component_trace, Column::IsSetLtS);
    let is_cmoviz_col = crate::trace::original_base_column!(component_trace, Column::IsCmovIz);
    let is_cmovnz_col = crate::trace::original_base_column!(component_trace, Column::IsCmovNz);
    let is_mins_col = crate::trace::original_base_column!(component_trace, Column::IsMinS);
    let is_minu_col = crate::trace::original_base_column!(component_trace, Column::IsMinU);
    let is_maxs_col = crate::trace::original_base_column!(component_trace, Column::IsMaxS);
    let is_maxu_col = crate::trace::original_base_column!(component_trace, Column::IsMaxU);
    let is_br_eq_col = crate::trace::original_base_column!(component_trace, Column::IsBrEq);
    let is_br_ne_col = crate::trace::original_base_column!(component_trace, Column::IsBrNe);
    let is_br_lt_u_col = crate::trace::original_base_column!(component_trace, Column::IsBrLtU);
    let is_br_ge_u_col = crate::trace::original_base_column!(component_trace, Column::IsBrGeU);
    let is_br_le_u_col = crate::trace::original_base_column!(component_trace, Column::IsBrLeU);
    let is_br_gt_u_col = crate::trace::original_base_column!(component_trace, Column::IsBrGtU);
    let is_br_lt_s_col = crate::trace::original_base_column!(component_trace, Column::IsBrLtS);
    let is_br_ge_s_col = crate::trace::original_base_column!(component_trace, Column::IsBrGeS);
    let is_br_le_s_col = crate::trace::original_base_column!(component_trace, Column::IsBrLeS);
    let is_br_gt_s_col = crate::trace::original_base_column!(component_trace, Column::IsBrGtS);
    // ── ByteToBits decomposition consumer (prover-side, 6 emissions) ──
    //
    // Mirrors the 6 verifier-side emissions in `constraints::program::flag_bits`.  Each tuple
    // is `(FlagByteI, bit0, ..., bit7)` with bit_j either an
    // individual flag column or a sum-of-sub-flags expression.
    // Multiplicity 1 on every row: a padding row's zero bytes pin its flags
    // to zero.
    {
        let bt: &ByteToBitsLookupElements = lookup_elements.as_ref();
        let is_pad_col = crate::trace::original_base_column!(component_trace, Column::IsPadding);
        let fb0 = crate::trace::original_base_column!(component_trace, Column::FlagByte0);
        let fb1 = crate::trace::original_base_column!(component_trace, Column::FlagByte1);
        let fb2 = crate::trace::original_base_column!(component_trace, Column::FlagByte2);
        let fb3 = crate::trace::original_base_column!(component_trace, Column::FlagByte3);
        let fb4 = crate::trace::original_base_column!(component_trace, Column::FlagByte4);
        let fb5 = crate::trace::original_base_column!(component_trace, Column::FlagByte5);
        let f_is_add = crate::trace::original_base_column!(component_trace, Column::IsAdd);
        let f_is_sub = crate::trace::original_base_column!(component_trace, Column::IsSub);
        let f_is_mul = crate::trace::original_base_column!(component_trace, Column::IsMul);
        let f_is_shar_r = crate::trace::original_base_column!(component_trace, Column::IsSharR);
        let f_is_and = crate::trace::original_base_column!(component_trace, Column::IsAnd);
        let f_is_or = crate::trace::original_base_column!(component_trace, Column::IsOr);
        let f_is_xor = crate::trace::original_base_column!(component_trace, Column::IsXor);
        let f_is_and_inv = crate::trace::original_base_column!(component_trace, Column::IsAndInv);
        let f_is_or_inv = crate::trace::original_base_column!(component_trace, Column::IsOrInv);
        let f_is_xnor = crate::trace::original_base_column!(component_trace, Column::IsXnor);
        let f_is_shift = crate::trace::original_base_column!(component_trace, Column::IsShift);
        let f_is_move = crate::trace::original_base_column!(component_trace, Column::IsMove);
        let f_is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let f_is_jump = crate::trace::original_base_column!(component_trace, Column::IsJump);
        let f_is_div_rem = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
        let f_is_load = crate::trace::original_base_column!(component_trace, Column::IsLoad);
        let f_is_exit = crate::trace::original_base_column!(component_trace, Column::IsExit);
        let f_is_neg_add = crate::trace::original_base_column!(component_trace, Column::IsNegAdd);
        let f_is_reverse_bytes =
            crate::trace::original_base_column!(component_trace, Column::IsReverseBytes);
        let f_is_zero_ext_16 =
            crate::trace::original_base_column!(component_trace, Column::IsZeroExt16);
        let f_is_sign_ext_8 =
            crate::trace::original_base_column!(component_trace, Column::IsSignExt8);
        let f_is_sign_ext_16 =
            crate::trace::original_base_column!(component_trace, Column::IsSignExt16);
        let f_is_trap = crate::trace::original_base_column!(component_trace, Column::IsTrap);
        let f_is_jump_ind = crate::trace::original_base_column!(component_trace, Column::IsJumpInd);
        let f_is_load_imm_jump_ind =
            crate::trace::original_base_column!(component_trace, Column::IsLoadImmJumpInd);
        let f_is_mul_upper_uu =
            crate::trace::original_base_column!(component_trace, Column::IsMulUpperUU);
        let f_is_mul_upper_su =
            crate::trace::original_base_column!(component_trace, Column::IsMulUpperSU);
        let f_is_mul_upper_ss =
            crate::trace::original_base_column!(component_trace, Column::IsMulUpperSS);
        let f_is_div_s = crate::trace::original_base_column!(component_trace, Column::IsDivS);
        let f_is_load_i8 = crate::trace::original_base_column!(component_trace, Column::IsLoadI8);
        let f_is_load_i16 = crate::trace::original_base_column!(component_trace, Column::IsLoadI16);
        let f_is_load_i32 = crate::trace::original_base_column!(component_trace, Column::IsLoadI32);
        let f_is_mem_size_1 =
            crate::trace::original_base_column!(component_trace, Column::IsMemSize1);
        let f_is_mem_size_2 =
            crate::trace::original_base_column!(component_trace, Column::IsMemSize2);
        let f_is_mem_size_4 =
            crate::trace::original_base_column!(component_trace, Column::IsMemSize4);
        let f_is_mem_size_8 =
            crate::trace::original_base_column!(component_trace, Column::IsMemSize8);
        let f_is_store_direct =
            crate::trace::original_base_column!(component_trace, Column::IsStoreDirect);
        let f_is_load_direct =
            crate::trace::original_base_column!(component_trace, Column::IsLoadDirect);
        let f_is_mem_indirect =
            crate::trace::original_base_column!(component_trace, Column::IsMemIndirect);
        let f_is_store_imm_any =
            crate::trace::original_base_column!(component_trace, Column::IsStoreImmAny);
        let f_is_store_imm_direct =
            crate::trace::original_base_column!(component_trace, Column::IsStoreImmDirect);
        let f_is_store_ind =
            crate::trace::original_base_column!(component_trace, Column::IsStoreInd);
        let f_is_rotate_l64 =
            crate::trace::original_base_column!(component_trace, Column::IsRotateL64);
        let f_is_count_set_bits =
            crate::trace::original_base_column!(component_trace, Column::IsCountSetBits);
        let f_is_lzb = crate::trace::original_base_column!(component_trace, Column::IsLzb);
        let f_is_tzb = crate::trace::original_base_column!(component_trace, Column::IsTzb);
        let f_is_rotate_r64 =
            crate::trace::original_base_column!(component_trace, Column::IsRotateR64);
        let f_is_rotate_l32 =
            crate::trace::original_base_column!(component_trace, Column::IsRotateL32);
        let f_is_rotate_r32 =
            crate::trace::original_base_column!(component_trace, Column::IsRotateR32);
        let f_is_imm_alt = crate::trace::original_base_column!(component_trace, Column::IsImmAlt);

        let one_pkg =
            || stwo::prover::backend::simd::m31::PackedBaseField::broadcast(BaseField::from(1));

        // byte 0: (FlagByte0, is_add, is_sub, is_mul, is_shar_r, BW_SUM,
        //          is_shift, CMP_SUM, is_move)
        {
            let pad = is_pad_col[0].clone();
            let fbc = fb0[0].clone();
            let a = f_is_add[0].clone();
            let s = f_is_sub[0].clone();
            let m = f_is_mul[0].clone();
            let shar = f_is_shar_r[0].clone();
            let bw_and = f_is_and[0].clone();
            let bw_or = f_is_or[0].clone();
            let bw_xor = f_is_xor[0].clone();
            let bw_andinv = f_is_and_inv[0].clone();
            let bw_orinv = f_is_or_inv[0].clone();
            let bw_xnor = f_is_xnor[0].clone();
            let sh = f_is_shift[0].clone();
            let cmp_setltu = is_setltu_col[0].clone();
            let cmp_setlts = is_setlts_col[0].clone();
            let cmp_cmoviz = is_cmoviz_col[0].clone();
            let cmp_cmovnz = is_cmovnz_col[0].clone();
            let cmp_mins = is_mins_col[0].clone();
            let cmp_minu = is_minu_col[0].clone();
            let cmp_maxs = is_maxs_col[0].clone();
            let cmp_maxu = is_maxu_col[0].clone();
            let mv = f_is_move[0].clone();
            logup.add_to_relation_computed(
                bt,
                [pad],
                move |[_]| one_pkg().into(),
                9,
                move |i| {
                    vec![
                        fbc.at(i),
                        a.at(i),
                        s.at(i),
                        m.at(i),
                        shar.at(i),
                        bw_and.at(i)
                            + bw_or.at(i)
                            + bw_xor.at(i)
                            + bw_andinv.at(i)
                            + bw_orinv.at(i)
                            + bw_xnor.at(i),
                        sh.at(i),
                        cmp_setltu.at(i)
                            + cmp_setlts.at(i)
                            + cmp_cmoviz.at(i)
                            + cmp_cmovnz.at(i)
                            + cmp_mins.at(i)
                            + cmp_minu.at(i)
                            + cmp_maxs.at(i)
                            + cmp_maxu.at(i),
                        mv.at(i),
                    ]
                },
            );
        }

        // byte 1: (FlagByte1, is_32bit, BR_SUM, is_jump, is_div_rem,
        //          is_load, ST_SUM, is_exit, is_neg_add)
        {
            let pad = is_pad_col[0].clone();
            let fbc = fb1[0].clone();
            let b32 = f_is_32bit[0].clone();
            let br_eq = is_br_eq_col[0].clone();
            let br_ne = is_br_ne_col[0].clone();
            let br_ltu = is_br_lt_u_col[0].clone();
            let br_geu = is_br_ge_u_col[0].clone();
            let br_leu = is_br_le_u_col[0].clone();
            let br_gtu = is_br_gt_u_col[0].clone();
            let br_lts = is_br_lt_s_col[0].clone();
            let br_ges = is_br_ge_s_col[0].clone();
            let br_les = is_br_le_s_col[0].clone();
            let br_gts = is_br_gt_s_col[0].clone();
            let jp = f_is_jump[0].clone();
            let dr = f_is_div_rem[0].clone();
            let ld = f_is_load[0].clone();
            let st_dir = f_is_store_direct[0].clone();
            let st_imm = f_is_store_imm_any[0].clone();
            let st_ind = f_is_store_ind[0].clone();
            let ex = f_is_exit[0].clone();
            let na = f_is_neg_add[0].clone();
            logup.add_to_relation_computed(
                bt,
                [pad],
                move |[_]| one_pkg().into(),
                9,
                move |i| {
                    vec![
                        fbc.at(i),
                        b32.at(i),
                        br_eq.at(i)
                            + br_ne.at(i)
                            + br_ltu.at(i)
                            + br_geu.at(i)
                            + br_leu.at(i)
                            + br_gtu.at(i)
                            + br_lts.at(i)
                            + br_ges.at(i)
                            + br_les.at(i)
                            + br_gts.at(i),
                        jp.at(i),
                        dr.at(i),
                        ld.at(i),
                        st_dir.at(i) + st_imm.at(i) + st_ind.at(i),
                        ex.at(i),
                        na.at(i),
                    ]
                },
            );
        }

        // byte 2: (FlagByte2, is_reverse_bytes, is_zero_ext_16,
        //          is_sign_ext_8, is_sign_ext_16, is_trap, is_jump_ind,
        //          is_load_imm_jump_ind, is_mul_upper_uu)
        {
            let pad = is_pad_col[0].clone();
            let fbc = fb2[0].clone();
            let rb = f_is_reverse_bytes[0].clone();
            let ze16 = f_is_zero_ext_16[0].clone();
            let se8 = f_is_sign_ext_8[0].clone();
            let se16 = f_is_sign_ext_16[0].clone();
            let tp = f_is_trap[0].clone();
            let ji = f_is_jump_ind[0].clone();
            let lij = f_is_load_imm_jump_ind[0].clone();
            let mu_uu = f_is_mul_upper_uu[0].clone();
            logup.add_to_relation_computed(
                bt,
                [pad],
                move |[_]| one_pkg().into(),
                9,
                move |i| {
                    vec![
                        fbc.at(i),
                        rb.at(i),
                        ze16.at(i),
                        se8.at(i),
                        se16.at(i),
                        tp.at(i),
                        ji.at(i),
                        lij.at(i),
                        mu_uu.at(i),
                    ]
                },
            );
        }

        // byte 3: (FlagByte3, is_mul_upper_su, is_mul_upper_ss, is_div_s,
        //          is_load_i8, is_load_i16, is_load_i32,
        //          is_mem_size_1, is_mem_size_2)
        {
            let pad = is_pad_col[0].clone();
            let fbc = fb3[0].clone();
            let mu_su = f_is_mul_upper_su[0].clone();
            let mu_ss = f_is_mul_upper_ss[0].clone();
            let ds = f_is_div_s[0].clone();
            let li8 = f_is_load_i8[0].clone();
            let li16 = f_is_load_i16[0].clone();
            let li32 = f_is_load_i32[0].clone();
            let ms1 = f_is_mem_size_1[0].clone();
            let ms2 = f_is_mem_size_2[0].clone();
            logup.add_to_relation_computed(
                bt,
                [pad],
                move |[_]| one_pkg().into(),
                9,
                move |i| {
                    vec![
                        fbc.at(i),
                        mu_su.at(i),
                        mu_ss.at(i),
                        ds.at(i),
                        li8.at(i),
                        li16.at(i),
                        li32.at(i),
                        ms1.at(i),
                        ms2.at(i),
                    ]
                },
            );
        }

        // byte 4: (FlagByte4, is_mem_size_4, is_mem_size_8,
        //          is_store_direct, is_load_direct, is_mem_indirect,
        //          is_store_imm_any, is_store_imm_direct, is_store_ind)
        {
            let pad = is_pad_col[0].clone();
            let fbc = fb4[0].clone();
            let ms4 = f_is_mem_size_4[0].clone();
            let ms8 = f_is_mem_size_8[0].clone();
            let sd = f_is_store_direct[0].clone();
            let lod = f_is_load_direct[0].clone();
            let mi = f_is_mem_indirect[0].clone();
            let sia = f_is_store_imm_any[0].clone();
            let sid = f_is_store_imm_direct[0].clone();
            let si = f_is_store_ind[0].clone();
            logup.add_to_relation_computed(
                bt,
                [pad],
                move |[_]| one_pkg().into(),
                9,
                move |i| {
                    vec![
                        fbc.at(i),
                        ms4.at(i),
                        ms8.at(i),
                        sd.at(i),
                        lod.at(i),
                        mi.at(i),
                        sia.at(i),
                        sid.at(i),
                        si.at(i),
                    ]
                },
            );
        }

        // byte 5: (FlagByte5, is_rotate_l64, is_count_set_bits,
        //          is_lzb, is_tzb, is_rotate_r64, is_rotate_l32,
        //          is_rotate_r32, is_imm_alt)
        {
            let pad = is_pad_col[0].clone();
            let fbc = fb5[0].clone();
            let rl64 = f_is_rotate_l64[0].clone();
            let csb = f_is_count_set_bits[0].clone();
            let lz = f_is_lzb[0].clone();
            let tz = f_is_tzb[0].clone();
            let rr64 = f_is_rotate_r64[0].clone();
            let rl32 = f_is_rotate_l32[0].clone();
            let rr32 = f_is_rotate_r32[0].clone();
            let rria = f_is_imm_alt[0].clone();
            logup.add_to_relation_computed(
                bt,
                [pad],
                move |[_]| one_pkg().into(),
                9,
                move |i| {
                    vec![
                        fbc.at(i),
                        rl64.at(i),
                        csb.at(i),
                        lz.at(i),
                        tz.at(i),
                        rr64.at(i),
                        rl32.at(i),
                        rr32.at(i),
                        rria.at(i),
                    ]
                },
            );
        }
    }
}
