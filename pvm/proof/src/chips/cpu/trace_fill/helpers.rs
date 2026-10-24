//! The helper columns: products of flags and witnesses that keep the constraints at degree 2.

use super::*;

/// The helper columns the constraints' degree reduction reads.
pub(super) fn helpers(
    out: &mut Sinks,
    s: Step,
    ops: &Operands,
    cmp: &Compare,
    div: &DivRem,
    counts: &BitCounts,
    branch_taken: bool,
) {
    let Sinks { trace, .. } = out;
    let Step { row, flags, .. } = s;
    let Operands {
        val_d,
        val_b_bytes,
        val_d_bytes,
        ..
    } = *ops;
    let Compare {
        cmp_lt_flag,
        val_d_byte_inv,
        val_d_partial_nz,
        sign_bit_b,
        sign_bit_d,
        cmp_lt_s_flag,
        eq_flag,
        ..
    } = *cmp;
    let DivRem { div_by_zero, .. } = *div;
    let BitCounts {
        bit_op_lz,
        bit_op_tz,
        val_d_partial_nz_msb,
        val_d_partial_nz_msb_lo,
        ..
    } = *counts;
    let signs_diff_b = (sign_bit_b ^ sign_bit_d) != 0;
    trace.fill_columns(row, signs_diff_b, Column::SignsDiffH);
    let vd_zero_b = val_d == 0;
    let is_compare_b = flags.is_set_lt_u
        || flags.is_set_lt_s
        || flags.is_cmov_iz
        || flags.is_cmov_nz
        || flags.is_min_s
        || flags.is_min_u
        || flags.is_max_s
        || flags.is_max_u;
    trace.fill_columns(row, is_compare_b && vd_zero_b, Column::IsCmpVdzH);
    trace.fill_columns(row, flags.is_cmov_iz && vd_zero_b, Column::IsCmovIzVdzH);
    trace.fill_columns(row, flags.is_cmov_nz && !vd_zero_b, Column::IsCmovNzNotVdzH);
    // CmpLtValB/D body helpers — byte-wise products with the
    // min/max's less-than: signed on MinS/MaxS rows.
    let cmp_lt_u8: u8 = if flags.is_min_s || flags.is_max_s {
        cmp_lt_s_flag
    } else {
        cmp_lt_flag
    };
    trace.fill_columns(row, cmp_lt_u8, Column::MinMaxLtFlag);
    let mut cmp_lt_vb = [0u8; 8];
    let mut cmp_lt_vd = [0u8; 8];
    for i in 0..8 {
        cmp_lt_vb[i] = cmp_lt_u8 * val_b_bytes[i];
        cmp_lt_vd[i] = cmp_lt_u8 * val_d_bytes[i];
    }
    trace.fill_columns_bytes(row, &cmp_lt_vb, Column::CmpLtValBH);
    trace.fill_columns_bytes(row, &cmp_lt_vd, Column::CmpLtValDH);

    // DivRem helpers.
    let div_active_b = flags.is_div_rem && div_by_zero == 0;
    let op_i32 = flags.div_rem_op as i32;
    let gate_div_v =
        ((op_i32 - 2) * (op_i32 - 3)).rem_euclid(stwo::core::fields::m31::P as i32) as u32;
    let gate_rem_v = (op_i32 * (op_i32 - 1)).rem_euclid(stwo::core::fields::m31::P as i32) as u32;
    trace.fill_columns(row, div_active_b, Column::CpuDivActiveH);
    trace.fill_columns_base_field(row, &[BaseField::from(gate_div_v)], Column::GateDivH);
    trace.fill_columns_base_field(row, &[BaseField::from(gate_rem_v)], Column::GateRemH);
    let active_v: u32 = if div_active_b { 1 } else { 0 };
    trace.fill_columns_base_field(
        row,
        &[BaseField::from(
            (active_v * gate_div_v).rem_euclid(stwo::core::fields::m31::P),
        )],
        Column::DivActiveQuotH,
    );
    trace.fill_columns_base_field(
        row,
        &[BaseField::from(
            (active_v * gate_rem_v).rem_euclid(stwo::core::fields::m31::P),
        )],
        Column::DivActiveRemH,
    );
    trace.fill_columns(
        row,
        flags.is_div_rem && flags.is_32bit,
        Column::IsDivRem32bitH,
    );

    // ── val_d byte-indicator helpers ──
    // From `compare`'s val_d_byte_inv and val_d_partial_nz.
    let mut indicator = [BaseField::from(0u32); 8];
    let mut ind_minus1 = [BaseField::from(0u32); 8];
    let mut part_nz_times_ind = [BaseField::from(0u32); 7];
    for i in 0..WORD_SIZE {
        let vd_i = BaseField::from(val_d_bytes[i] as u32);
        indicator[i] = vd_i * val_d_byte_inv[i];
        // ValDByteIndMinus1H = val_d · (indicator - 1).
        // For valid traces with vd=0 → ind=0, helper=0;
        // with vd≠0 → ind=1, helper=0.  Either way 0.
        ind_minus1[i] = BaseField::from(0u32);
        if i >= 1 {
            // PartialNZ[i-1] · ByteIndicator[i].
            let pnz_prev = BaseField::from(val_d_partial_nz[i - 1] as u32);
            part_nz_times_ind[i - 1] = pnz_prev * indicator[i];
        }
    }
    trace.fill_columns_base_field(row, &indicator, Column::ValDByteIndicatorH);
    trace.fill_columns_base_field(row, &ind_minus1, Column::ValDByteIndMinus1H);
    trace.fill_columns_base_field(row, &part_nz_times_ind, Column::PartNZTimesIndH);
    // is_div_rem · val_d_is_zero (booleans).
    trace.fill_columns(
        row,
        flags.is_div_rem && vd_zero_b,
        Column::IsDivRemTimesVdzH,
    );
    // dbz_active = is_div_rem · div_by_zero (boolean).
    let dbz_active_b = flags.is_div_rem && (div_by_zero != 0);
    trace.fill_columns(row, dbz_active_b, Column::DbzActiveH);
    // dbz_active * gate_div / gate_rem (field-element products).
    let dbz_active_v: u32 = if dbz_active_b { 1 } else { 0 };
    trace.fill_columns_base_field(
        row,
        &[BaseField::from(
            (dbz_active_v * gate_div_v).rem_euclid(stwo::core::fields::m31::P),
        )],
        Column::DbzActiveQuotH,
    );
    trace.fill_columns_base_field(
        row,
        &[BaseField::from(
            (dbz_active_v * gate_rem_v).rem_euclid(stwo::core::fields::m31::P),
        )],
        Column::DbzActiveRemH,
    );
    let width_64_v = !flags.is_32bit as u32;
    trace.fill_columns_base_field(
        row,
        &[BaseField::from(
            (dbz_active_v * gate_rem_v * width_64_v).rem_euclid(stwo::core::fields::m31::P),
        )],
        Column::DbzActiveRem64H,
    );

    // ── Partial-NZ (MSB direction) times-indicator helpers ──
    // PartNZMsbTimesIndH[i] = PartialNZMsb[i+1] · ByteIndicator[i] for i ∈ 0..7.
    // The MSB-direction partial ORs, as `bit_counts` computes them.
    let mut pnz_msb = [0u8; 8];
    let mut running_msb: u8 = 0;
    for i in (0..WORD_SIZE).rev() {
        let nz = if val_d_bytes[i] != 0 { 1 } else { 0 };
        running_msb |= nz;
        pnz_msb[i] = running_msb;
    }
    let mut pnz_msb_lo = [0u8; 4];
    let mut running_msb_lo: u8 = 0;
    for i in (0..4).rev() {
        let nz = if val_d_bytes[i] != 0 { 1 } else { 0 };
        running_msb_lo |= nz;
        pnz_msb_lo[i] = running_msb_lo;
    }
    let mut pnz_msb_times_ind = [BaseField::from(0u32); 7];
    for i in 0..7 {
        let pnz_next = BaseField::from(pnz_msb[i + 1] as u32);
        pnz_msb_times_ind[i] = pnz_next * indicator[i];
    }
    trace.fill_columns_base_field(row, &pnz_msb_times_ind, Column::PartNZMsbTimesIndH);
    let mut pnz_msb_lo_times_ind = [BaseField::from(0u32); 3];
    for i in 0..3 {
        let pnz_next = BaseField::from(pnz_msb_lo[i + 1] as u32);
        pnz_msb_lo_times_ind[i] = pnz_next * indicator[i];
    }
    trace.fill_columns_base_field(row, &pnz_msb_lo_times_ind, Column::PartNZMsbLoTimesIndH);

    // ── TZ/LZ result-binding helpers ──
    // is_first_nz[i] = partial[i] - partial[i-1] (i ∈ 0..8)
    //                = 1 at the first nonzero byte, else 0.
    // TzLo4H = sum_{i<4} is_first_nz[i] · (8i + TzByte[i]).
    // BaseField arithmetic to dodge u8 overflow on byte products.
    let mut tz_lo4: u32 = 0;
    let mut tz_hi4: u32 = 0;
    for i in 0..WORD_SIZE {
        let prev = if i == 0 { 0u8 } else { val_d_partial_nz[i - 1] };
        let is_first = val_d_partial_nz[i].wrapping_sub(prev);
        // is_first ∈ {0, 1} (or 255 if prev > curr, which shouldn't happen).
        let weight = 8u32 * i as u32 + bit_op_tz[i] as u32;
        let term = (is_first as u32) * weight;
        if i < 4 {
            tz_lo4 += term;
        } else {
            tz_hi4 += term;
        }
    }
    trace.fill_columns_base_field(
        row,
        &[BaseField::from(
            tz_lo4.rem_euclid(stwo::core::fields::m31::P),
        )],
        Column::TzLo4H,
    );
    trace.fill_columns_base_field(
        row,
        &[BaseField::from(
            tz_hi4.rem_euclid(stwo::core::fields::m31::P),
        )],
        Column::TzHi4H,
    );

    // Lz64H = sum_{i<8} (PartialNZMsb[i] - PartialNZMsb[i+1])
    //                   · (8(7-i) + LzByte[i]).
    let mut lz_64: u32 = 0;
    for i in 0..WORD_SIZE {
        let next = if i + 1 < WORD_SIZE {
            val_d_partial_nz_msb[i + 1]
        } else {
            0u8
        };
        let is_first = val_d_partial_nz_msb[i].wrapping_sub(next);
        let weight = 8u32 * (7 - i as u32) + bit_op_lz[i] as u32;
        lz_64 += (is_first as u32) * weight;
    }
    trace.fill_columns_base_field(
        row,
        &[BaseField::from(
            lz_64.rem_euclid(stwo::core::fields::m31::P),
        )],
        Column::Lz64H,
    );
    // Lz32H = sum over LOW 4 bytes using PartialNZMsbLo.
    let mut lz_32: u32 = 0;
    for i in 0..4 {
        let next = if i + 1 < 4 {
            val_d_partial_nz_msb_lo[i + 1]
        } else {
            0u8
        };
        let is_first = val_d_partial_nz_msb_lo[i].wrapping_sub(next);
        let weight = 8u32 * (3 - i as u32) + bit_op_lz[i] as u32;
        lz_32 += (is_first as u32) * weight;
    }
    trace.fill_columns_base_field(
        row,
        &[BaseField::from(
            lz_32.rem_euclid(stwo::core::fields::m31::P),
        )],
        Column::Lz32H,
    );

    // Is{Tzb,Lzb}{64,32}H selectors (bool products of flags).
    let is_64bit_b = !flags.is_32bit;
    trace.fill_columns(row, flags.is_tzb && is_64bit_b, Column::IsTzb64H);
    trace.fill_columns(row, flags.is_tzb && flags.is_32bit, Column::IsTzb32H);
    trace.fill_columns(row, flags.is_lzb && is_64bit_b, Column::IsLzb64H);
    trace.fill_columns(row, flags.is_lzb && flags.is_32bit, Column::IsLzb32H);

    // ── Branch / sequential PC selectors ──
    let bt = branch_taken;
    let eq_b = eq_flag != 0;
    let is_branch_b = flags.is_br_eq
        || flags.is_br_ne
        || flags.is_br_lt_u
        || flags.is_br_ge_u
        || flags.is_br_le_u
        || flags.is_br_gt_u
        || flags.is_br_lt_s
        || flags.is_br_ge_s
        || flags.is_br_le_s
        || flags.is_br_gt_s;
    trace.fill_columns(
        row,
        is_compare_b && eq_b || is_branch_b && eq_b,
        Column::IsCmpOrBranchEqH,
    );
    trace.fill_columns(row, is_branch_b && bt, Column::IsBranchTakenH);

    // ── Memory monotonicity helper ──
    trace.fill_columns_bytes(row, &[0u8; 7], Column::MemByteActiveMonoH);
}

/// The selectors that are products of booleans.
pub(super) fn selectors(
    out: &mut Sinks,
    s: Step,
    shift: &Shift,
    host: &HostCall,
    accesses: &StepRegAccesses,
    is_truncated: u8,
) {
    let Sinks { trace, .. } = out;
    let Step { row, flags, .. } = s;
    let Shift {
        is_shift_constrained,
        ..
    } = *shift;
    let HostCall {
        flag_bool,
        flag_sum,
        flag_inv,
    } = *host;
    // ── Boolean / selector helper fills ──
    // is_truncated, val_b_is_reg / val_d_is_reg / result_is_reg,
    // flag_bool, is_blake_ecall_b, is_shift_constrained are all
    // booleans (or u8 ∈ {0,1}) in valid traces.  All Bool-helpers
    // are 0 in valid traces (boolean identity always holds).
    // Selector helpers are simple bool products of known flags.
    let is_truncated_b = is_truncated != 0;
    let val_b_is_reg_b = accesses.val_b_read.is_some();
    let val_d_is_reg_b = accesses.val_d_read.is_some();
    let flag_bool_b = flag_bool != 0;
    let real_b = true; // not padding
    let is_32bit_b = flags.is_32bit;
    let is_shift_c_b = is_shift_constrained;
    let is_rot_r_either_b = flags.is_rotate_r64 || flags.is_rotate_r32;
    // IsTruncated / ValBIsReg / ValDIsReg / ResultIsReg / FlagBool /
    // IsBlakeEcall are enforced as unconditional `X·(1-X)=0`, so they
    // need no boolean-helper columns.
    // Selector helpers.
    trace.fill_columns(row, real_b && is_32bit_b, Column::Real32bitH);
    trace.fill_columns(row, val_b_is_reg_b, Column::ValBIsRegH);
    trace.fill_columns(
        row,
        val_b_is_reg_b && !is_truncated_b,
        Column::ValBIsRegNotTruncH,
    );
    trace.fill_columns(
        row,
        val_b_is_reg_b && is_truncated_b,
        Column::ValBIsRegTruncH,
    );
    trace.fill_columns(row, !val_d_is_reg_b, Column::ValDIsImmH);
    trace.fill_columns(row, !is_shift_c_b, Column::NonShiftGateH);
    trace.fill_columns(
        row,
        !is_shift_c_b && !is_truncated_b,
        Column::NonShiftGateNotTruncH,
    );
    trace.fill_columns(
        row,
        !is_shift_c_b && is_truncated_b,
        Column::NonShiftGateTruncH,
    );
    trace.fill_columns(row, is_shift_c_b, Column::RealShiftCH);
    trace.fill_columns(row, real_b && is_rot_r_either_b, Column::IsRotateRGateH);
    // Flag helpers.
    trace.fill_columns(row, real_b && !flag_bool_b, Column::RealNotFlagBoolH);
    trace.fill_columns(row, real_b && flag_bool_b, Column::RealFlagBoolH);
    // FlagTimesInvH = (Σ Flag bytes) · FlagInv: 0 or 1.
    trace.fill_columns_base_field(row, &[flag_sum * flag_inv], Column::FlagTimesInvH);

    // Additional degree-3 selector patterns in CpuChip.
    trace.fill_columns(
        row,
        flags.is_imm_alt && !is_truncated_b,
        Column::IsImmAltNotTruncH,
    );
    trace.fill_columns(
        row,
        flags.is_imm_alt && is_truncated_b,
        Column::IsImmAltTruncH,
    );
    trace.fill_columns(
        row,
        flags.is_32bit && is_shift_constrained,
        Column::Is32ShiftCH,
    );
}

/// The remaining helpers.
pub(super) fn residual(out: &mut Sinks, s: Step, shift: &Shift, div: &DivRem, counts: &BitCounts) {
    let Sinks { trace, .. } = out;
    let Step { row, step, flags } = s;
    let Shift {
        is_shift_constrained,
        ..
    } = *shift;
    let DivRem {
        div_remainder,
        div_by_zero,
        val_r_byte_inv,
        val_r_partial_nz,
        ..
    } = *div;
    let BitCounts { byte_popcount, .. } = *counts;
    // ── Residual helper fills ──
    trace.fill_columns(row, flags.is_trap, Column::IsRealTrapH);
    // Is64bitPopcountHiH = (1 - is_32bit) · (popcount[4]+...+popcount[7]).
    let is_64bit_b = !flags.is_32bit;
    let pop_hi: u32 = if is_64bit_b {
        byte_popcount[4..8].iter().map(|&b| b as u32).sum()
    } else {
        0
    };
    trace.fill_columns_base_field(row, &[BaseField::from(pop_hi)], Column::Is64bitPopcountHiH);
    // IsLoadLocalNotActiveH[i] = is_load · (1 - mem_byte_active[i]).
    let mut load_not_active = [0u8; 8];
    if flags.is_load {
        // MemByteActive, as `memory` fills it, from the access's size.
        let mem_size: u8 = step
            .mem_read
            .as_ref()
            .or(step.mem_write.as_ref())
            .map(|m| m.size)
            .unwrap_or(0);
        for i in 0..8 {
            let active = (i as u8) < mem_size;
            load_not_active[i] = if !active { 1 } else { 0 };
        }
    }
    trace.fill_columns_bytes(row, &load_not_active, Column::IsLoadLocalNotActiveH);
    // ValR* helpers.  In valid traces ind_minus_1 = 0.
    // val_r_byte_inv and val_r_partial_nz are computed earlier from
    // div_remainder (the local array), so use that as the source —
    // the constraint reads `div_remainder_top[i]·val_r_byte_inv_top[i]`.
    let mut vr_indicator = [BaseField::from(0u32); 8];
    let mut vr_part_nz_times_ind = [BaseField::from(0u32); 7];
    for i in 0..8 {
        let vr_i = BaseField::from(div_remainder[i] as u32);
        vr_indicator[i] = vr_i * val_r_byte_inv[i];
        if i >= 1 {
            let pnz_prev = BaseField::from(val_r_partial_nz[i - 1] as u32);
            vr_part_nz_times_ind[i - 1] = pnz_prev * vr_indicator[i];
        }
    }
    trace.fill_columns_base_field(row, &vr_indicator, Column::ValRByteIndicatorH);
    trace.fill_columns_base_field(row, &[BaseField::from(0u32); 8], Column::ValRByteIndMinus1H);
    trace.fill_columns_base_field(row, &vr_part_nz_times_ind, Column::ValRPartNZTimesIndH);
    // DivS remainder-sign helpers.
    let div_s_not_dbz_b = flags.is_div_s && (div_by_zero == 0);
    trace.fill_columns(row, div_s_not_dbz_b, Column::IsDivSNotDbzH);
    // DivSActivePartialH = (IsDivSNotDbz) · ValRPartialNZ[7].
    let dsap_v: u32 = if div_s_not_dbz_b {
        val_r_partial_nz[7] as u32
    } else {
        0
    };
    trace.fill_columns_base_field(row, &[BaseField::from(dsap_v)], Column::DivSActivePartialH);
    // Lookup-multiplicity helper: IsShiftCNotRotrH = is_shift_c · (1 - rot_r64 - rot_r32).
    let no_rotr = !flags.is_rotate_r64 && !flags.is_rotate_r32;
    trace.fill_columns(
        row,
        is_shift_constrained && no_rotr,
        Column::IsShiftCNotRotrH,
    );
}
