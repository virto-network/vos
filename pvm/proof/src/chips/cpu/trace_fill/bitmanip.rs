//! Sign extension and bit counts.

use super::*;

/// The operand's per-byte bit counts.
#[derive(Clone, Copy)]
pub(super) struct BitCounts {
    pub byte_popcount: [u8; WORD_SIZE],
    pub bit_op_lz: [u8; WORD_SIZE],
    pub bit_op_tz: [u8; WORD_SIZE],
    pub val_d_partial_nz_msb: [u8; WORD_SIZE],
    pub val_d_partial_nz_msb_lo: [u8; 4],
}

/// The sign extensions' source byte and sign bit.
pub(super) fn sign_extend(out: &mut Sinks, s: Step, ops: &Operands) {
    let Sinks {
        trace, side_note, ..
    } = out;
    let Step { row, flags, .. } = s;
    let Operands { val_d_bytes, .. } = *ops;
    // Sign-extend witnesses: high nibble + bit-7 of the
    // sign-source byte.  val_d[0] for SE8, val_d[1] for SE16.  Zero on
    // non-SE rows; the lookup multiplicities below are gated to match.
    let (se_src_byte, se_active) = if flags.is_sign_ext_8 {
        (val_d_bytes[0], true)
    } else if flags.is_sign_ext_16 {
        (val_d_bytes[1], true)
    } else {
        (0u8, false)
    };
    if se_active {
        let hi = se_src_byte >> 4;
        let lo = se_src_byte & 0xF;
        let bit = (se_src_byte >> 7) & 1;
        trace.fill_columns(row, hi, Column::SignExtSrcHiNib);
        trace.fill_columns(row, bit, Column::SignExtBit);
        // Charge BitwiseLookupChip for the two nibble lookups this row emits.
        *side_note.bitwise_and_counts.entry((hi, 8)).or_insert(0) += 1;
        *side_note.bitwise_and_counts.entry((lo, 0xF)).or_insert(0) += 1;
    }
}

/// The bit counts: the bytes' popcounts and leading and trailing zeros.
pub(super) fn bit_counts(out: &mut Sinks, s: Step, ops: &Operands) -> BitCounts {
    let Sinks {
        trace, side_note, ..
    } = out;
    let Step { row, flags, .. } = s;
    let Operands { val_d_bytes, .. } = *ops;
    // CountSetBits — fill IsCountSetBits flag and the 8
    // BytePopcount witnesses, and charge popcount_counts for each
    // active emission so PopcountChip's multiplicity column balances.
    trace.fill_columns(row, flags.is_count_set_bits, Column::IsCountSetBits);
    let mut byte_popcount = [0u8; WORD_SIZE];
    for i in 0..WORD_SIZE {
        byte_popcount[i] = val_d_bytes[i].count_ones() as u8;
    }
    trace.fill_columns_bytes(row, &byte_popcount, Column::BytePopcount);
    if flags.is_count_set_bits {
        for i in 0..WORD_SIZE {
            side_note.popcount_counts[val_d_bytes[i] as usize] += 1;
        }
    }
    // LeadingZeroBits / TrailingZeroBits witnesses.
    // Per-byte LZ/TZ (8 if byte = 0, else byte.leading_zeros() /
    // trailing_zeros()).  ValDPartialNZMsb (MSB-direction OR over
    // 8 bytes) and ValDPartialNZMsbLo (MSB-direction OR over the
    // low 4 bytes only — for LZ32).
    trace.fill_columns(row, flags.is_lzb, Column::IsLzb);
    trace.fill_columns(row, flags.is_tzb, Column::IsTzb);
    let mut bit_op_lz = [0u8; WORD_SIZE];
    let mut bit_op_tz = [0u8; WORD_SIZE];
    for i in 0..WORD_SIZE {
        let b = val_d_bytes[i];
        bit_op_lz[i] = if b == 0 { 8 } else { b.leading_zeros() as u8 };
        bit_op_tz[i] = if b == 0 { 8 } else { b.trailing_zeros() as u8 };
    }
    trace.fill_columns_bytes(row, &bit_op_lz, Column::BitOpLzByte);
    trace.fill_columns_bytes(row, &bit_op_tz, Column::BitOpTzByte);
    // ValDPartialNZMsb: cumulative-OR from byte 7 down.
    let mut val_d_partial_nz_msb = [0u8; WORD_SIZE];
    let mut running_msb: u8 = 0;
    for i in (0..WORD_SIZE).rev() {
        let nz = if val_d_bytes[i] != 0 { 1 } else { 0 };
        running_msb |= nz;
        val_d_partial_nz_msb[i] = running_msb;
    }
    trace.fill_columns_bytes(row, &val_d_partial_nz_msb, Column::ValDPartialNZMsb);
    // ValDPartialNZMsbLo: cumulative-OR from byte 3 down (low 4 only).
    let mut val_d_partial_nz_msb_lo = [0u8; 4];
    let mut running_msb_lo: u8 = 0;
    for i in (0..4).rev() {
        let nz = if val_d_bytes[i] != 0 { 1 } else { 0 };
        running_msb_lo |= nz;
        val_d_partial_nz_msb_lo[i] = running_msb_lo;
    }
    trace.fill_columns_bytes(row, &val_d_partial_nz_msb_lo, Column::ValDPartialNZMsbLo);
    // Charge bitcount_counts for the 8 emissions when this is an
    // LZ/TZ row.  Mutually exclusive — at most one of is_lzb / is_tzb.
    if flags.is_lzb || flags.is_tzb {
        for i in 0..WORD_SIZE {
            side_note.bitcount_counts[val_d_bytes[i] as usize] += 1;
        }
    }
    BitCounts {
        byte_popcount,
        bit_op_lz,
        bit_op_tz,
        val_d_partial_nz_msb,
        val_d_partial_nz_msb_lo,
    }
}
