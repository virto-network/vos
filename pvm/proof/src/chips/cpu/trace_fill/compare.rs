//! Comparisons, and the operands' and results' signs.

use super::*;

/// A row's comparison of its operands, and their signs.
#[derive(Clone, Copy)]
pub(super) struct Compare {
    pub cmp_lt_flag: u8,
    pub cmp_sub_result: [u8; WORD_SIZE],
    pub val_d_byte_inv: [BaseField; 8],
    pub val_d_partial_nz: [u8; 8],
    pub sign_src_b: u8,
    pub sign_src_d: u8,
    pub sign_bit_b: u8,
    pub sign_bit_d: u8,
    pub cmp_lt_s_flag: u8,
    pub eq_flag: u8,
}

/// The comparison: CompareChip's row, the operands' signs, the less-than and
/// equality flags.
pub(super) fn compare(out: &mut Sinks, s: Step, ops: &Operands) -> Compare {
    let Sinks {
        trace, side_note, ..
    } = out;
    let Step { row, flags, .. } = s;
    let Operands {
        val_b,
        val_d,
        val_b_bytes,
        val_d_bytes,
        ..
    } = *ops;
    // ── Compare auxiliary (populated for is_compare OR is_branch) ──
    // CmpCarry + CmpSubResult are witnessed on CompareChip;
    // CompareChip mirrors via side_note.compare_entries.
    let mut cmp_carry = [0u8; WORD_SIZE];
    let mut cmp_sub_result = [0u8; WORD_SIZE];
    let mut cmp_lt_flag: u8 = 0;
    if flags.is_compare || flags.is_branch {
        // Unsigned comparison via subtraction: val_b + ~val_d + 1
        let mut c: u16 = 1;
        for i in 0..WORD_SIZE {
            let sum = val_b_bytes[i] as u16 + (val_d_bytes[i] ^ 0xFF) as u16 + c;
            cmp_sub_result[i] = (sum & 0xFF) as u8;
            cmp_carry[i] = (sum >> 8) as u8;
            c = cmp_carry[i] as u16;
        }
        // a - b via a + ~b + 1: carry_out=1 means a>=b, carry_out=0 means a<b
        cmp_lt_flag = 1 - cmp_carry[WORD_SIZE - 1];
        side_note
            .compare_entries
            .push(crate::side_note::CompareEntry {
                val_b,
                val_d,
                cmp_lt_flag,
                cmp_sub_result,
                cmp_carry,
            });
    }
    trace.fill_columns(row, cmp_lt_flag, Column::CmpLtFlag);
    let val_d_is_zero: u8 = if val_d == 0 { 1 } else { 0 };
    trace.fill_columns(row, val_d_is_zero, Column::ValDIsZero);

    // Byte-wise val_d zero-check infrastructure.
    //   - ValDByteInv[i] = 1/val_d[i] in M31 when val_d[i] ≠ 0;
    //     0 (or any value) when val_d[i] = 0.
    //   - ValDPartialNZ[i] = OR(val_d[0..=i] != 0) as a 0/1 byte.
    // The constraint forces ByteIndicator[i] = val_d[i]·ByteInv[i]
    // to equal 1 whenever val_d[i] ≠ 0, so the cumulative OR
    // accumulates correctly.
    let mut val_d_byte_inv = [stwo::core::fields::m31::BaseField::from(0u32); 8];
    let mut val_d_partial_nz = [0u8; 8];
    let mut running_nz: u8 = 0;
    for i in 0..8 {
        let b = val_d_bytes[i];
        if b != 0 {
            val_d_byte_inv[i] = stwo::core::fields::m31::BaseField::from(b as u32).inverse();
            running_nz = 1;
        }
        val_d_partial_nz[i] = running_nz;
    }
    trace.fill_columns_base_field(row, &val_d_byte_inv, Column::ValDByteInv);
    trace.fill_columns_bytes(row, &val_d_partial_nz, Column::ValDPartialNZ);
    // SignBitB/D are pinned to bit 7 of the multiplexed source
    // byte (val_b[7] in 64-bit, val_b[3] in 32-bit) via nibble-AND
    // lookups (`constraints::signs::sign_nibbles`).
    // Compute the source byte explicitly and derive the sign +
    // hi-nibble + lo-nibble from it; bit-31-of-u64 and bit-63-of-u64
    // give the same answer when val_b[4..8] are constrained to 0
    // on 32-bit, but going through the byte makes it obvious that
    // the AIR pin and trace fill use the same source.
    let sign_src_b: u8 = if flags.is_32bit {
        val_b_bytes[3]
    } else {
        val_b_bytes[7]
    };
    let sign_src_d: u8 = if flags.is_32bit {
        val_d_bytes[3]
    } else {
        val_d_bytes[7]
    };
    let sign_bit_b: u8 = (sign_src_b >> 7) & 1;
    let sign_bit_d: u8 = (sign_src_d >> 7) & 1;
    trace.fill_columns(row, sign_bit_b, Column::SignBitB);
    trace.fill_columns(row, sign_bit_d, Column::SignBitD);
    trace.fill_columns(row, sign_src_b, Column::SignSrcB);
    trace.fill_columns(row, sign_src_d, Column::SignSrcD);

    // Signed lt: if signs differ, negative is smaller. If same, use unsigned compare.
    let cmp_lt_s_flag: u8 = if sign_bit_b != sign_bit_d {
        sign_bit_b // b is negative (sign=1) → b < d
    } else {
        cmp_lt_flag // same sign → unsigned comparison
    };
    trace.fill_columns(row, cmp_lt_s_flag, Column::CmpLtSFlag);
    let eq_flag: u8 = if val_b == val_d { 1 } else { 0 };
    trace.fill_columns(row, eq_flag, Column::EqFlag);
    // EqFlag's converse: the sum of squared byte differences and its
    // inverse.
    let squares: u64 = val_b_bytes
        .iter()
        .zip(&val_d_bytes)
        .map(|(&b, &d)| (i64::from(b) - i64::from(d)).pow(2) as u64)
        .sum();
    let squares = BaseField::from(squares as u32);
    let squares_inv = if eq_flag == 1 {
        BaseField::from(0u32)
    } else {
        squares.inverse()
    };
    trace.fill_columns_base_field(row, &[squares], Column::EqDiffSquaresH);
    trace.fill_columns_base_field(row, &[squares_inv], Column::EqDiffSquaresInv);
    trace.fill_columns_base_field(
        row,
        &[squares * squares_inv],
        Column::EqDiffSquaresTimesInvH,
    );
    trace.fill_columns(row, flags.is_set_lt_u, Column::IsSetLtU);
    trace.fill_columns(row, flags.is_set_lt_s, Column::IsSetLtS);
    trace.fill_columns(row, flags.is_set_gt, Column::IsSetGt);
    trace.fill_columns(row, flags.is_cmov_iz, Column::IsCmovIz);
    trace.fill_columns(row, flags.is_cmov_nz, Column::IsCmovNz);
    trace.fill_columns(row, flags.is_cmov_imm, Column::IsCmovImm);
    trace.fill_columns(row, flags.is_min_s, Column::IsMinS);
    trace.fill_columns(row, flags.is_min_u, Column::IsMinU);
    trace.fill_columns(row, flags.is_max_s, Column::IsMaxS);
    trace.fill_columns(row, flags.is_max_u, Column::IsMaxU);
    Compare {
        cmp_lt_flag,
        cmp_sub_result,
        val_d_byte_inv,
        val_d_partial_nz,
        sign_src_b,
        sign_src_d,
        sign_bit_b,
        sign_bit_d,
        cmp_lt_s_flag,
        eq_flag,
    }
}

/// The sign bits' nibble lookups, and the result's sign.
pub(super) fn sign_nibbles(out: &mut Sinks, s: Step, ops: &Operands, cmp: &Compare, div: &DivRem) {
    let Sinks {
        trace, side_note, ..
    } = out;
    let Step { row, .. } = s;
    let Operands { result_bytes, .. } = *ops;
    let Compare {
        sign_src_b,
        sign_src_d,
        ..
    } = *cmp;
    let DivRem {
        sign_src_q,
        sign_src_r,
        ..
    } = *div;
    // Hi nibbles + BitwiseLookupChip charges for the 8 sign-bit
    // pinning lookups emitted on every real row.
    let hi_b = sign_src_b >> 4;
    let lo_b = sign_src_b & 0xF;
    let hi_d = sign_src_d >> 4;
    let lo_d = sign_src_d & 0xF;
    let hi_q = sign_src_q >> 4;
    let lo_q = sign_src_q & 0xF;
    let hi_r = sign_src_r >> 4;
    let lo_r = sign_src_r & 0xF;
    trace.fill_columns(row, hi_b, Column::SignBHiNib);
    trace.fill_columns(row, hi_d, Column::SignDHiNib);
    trace.fill_columns(row, hi_q, Column::SignQHiNib);
    trace.fill_columns(row, hi_r, Column::SignRHiNib);
    *side_note.bitwise_and_counts.entry((hi_b, 8)).or_insert(0) += 1;
    *side_note.bitwise_and_counts.entry((lo_b, 0xF)).or_insert(0) += 1;
    *side_note.bitwise_and_counts.entry((hi_d, 8)).or_insert(0) += 1;
    *side_note.bitwise_and_counts.entry((lo_d, 0xF)).or_insert(0) += 1;
    *side_note.bitwise_and_counts.entry((hi_q, 8)).or_insert(0) += 1;
    *side_note.bitwise_and_counts.entry((lo_q, 0xF)).or_insert(0) += 1;
    *side_note.bitwise_and_counts.entry((hi_r, 8)).or_insert(0) += 1;
    *side_note.bitwise_and_counts.entry((lo_r, 0xF)).or_insert(0) += 1;

    // SignBitResult / ResultHiNib pinning.  On padding rows
    // result_bytes = 0 so SignBitResult = 0 (consistent with
    // the lookup).
    let sign_bit_result = (result_bytes[3] >> 7) & 1;
    let hi_res = result_bytes[3] >> 4;
    let lo_res = result_bytes[3] & 0xF;
    trace.fill_columns(row, sign_bit_result, Column::SignBitResult);
    trace.fill_columns(row, hi_res, Column::ResultHiNib);
    *side_note.bitwise_and_counts.entry((hi_res, 8)).or_insert(0) += 1;
    *side_note
        .bitwise_and_counts
        .entry((lo_res, 0xF))
        .or_insert(0) += 1;
}
