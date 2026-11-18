//! Division and remainder.

use super::*;

/// A division's remainder and signs.
#[derive(Clone, Copy)]
pub(super) struct DivRem {
    pub div_remainder: [u8; WORD_SIZE],
    pub div_by_zero: u8,
    pub val_r_byte_inv: [BaseField; 8],
    pub val_r_partial_nz: [u8; 8],
    pub sign_src_q: u8,
    pub sign_src_r: u8,
}

/// The division: DivRemChip's row, the quotient, the remainder and their signs.
pub(super) fn divrem(out: &mut Sinks, s: Step, ops: &Operands) -> DivRem {
    let Sinks {
        trace,
        side_note,
        range_bytes,
        ..
    } = out;
    let Step { row, flags, .. } = s;
    let Operands { val_b, val_d, .. } = *ops;
    // ── DivRem auxiliary ──
    // DivRemChip's row: the quotient and remainder the AIR proves, and
    // the chip's internal witness.
    let divrem_entry = flags.is_div_rem.then(|| {
        crate::chips::divrem::entry(
            val_b,
            val_d,
            flags.is_32bit,
            flags.is_div_s,
            flags.is_shar_r,
        )
    });
    let (div_quotient, div_remainder, div_by_zero) = match &divrem_entry {
        Some(e) => (
            e.div_quotient.to_le_bytes(),
            e.div_remainder.to_le_bytes(),
            e.div_by_zero as u8,
        ),
        None => ([0u8; WORD_SIZE], [0u8; WORD_SIZE], 0),
    };
    trace.fill_columns_bytes(row, &div_quotient, Column::DivQuotient);
    trace.fill_columns_bytes(row, &div_remainder, Column::DivRemainder);
    trace.fill_columns(row, div_by_zero, Column::DivByZero);

    // Byte-wise zero-check for div_remainder (as `compare`'s for val_d).
    // Drives the sign-of-r uniqueness constraint.
    let mut val_r_byte_inv = [stwo::core::fields::m31::BaseField::from(0u32); 8];
    let mut val_r_partial_nz = [0u8; 8];
    let mut running_nz: u8 = 0;
    for i in 0..8 {
        let b = div_remainder[i];
        if b != 0 {
            val_r_byte_inv[i] = stwo::core::fields::m31::BaseField::from(b as u32).inverse();
            running_nz = 1;
        }
        val_r_partial_nz[i] = running_nz;
    }
    trace.fill_columns_base_field(row, &val_r_byte_inv, Column::ValRByteInv);
    trace.fill_columns_bytes(row, &val_r_partial_nz, Column::ValRPartialNZ);

    // SignBitQ / SignBitR are pinned to bit 7 of the multiplexed
    // source byte (div_quotient[7] in 64-bit, div_quotient[3] in
    // 32-bit; same for remainder).
    // On non-divrem rows div_quotient/remainder bytes are all
    // 0, so SignBitQ/R fall to 0 — consistent with the
    // nibble lookups.
    let sign_src_q: u8 = if flags.is_32bit {
        div_quotient[3]
    } else {
        div_quotient[7]
    };
    let sign_src_r: u8 = if flags.is_32bit {
        div_remainder[3]
    } else {
        div_remainder[7]
    };
    let sign_bit_q: u8 = (sign_src_q >> 7) & 1;
    let sign_bit_r: u8 = (sign_src_r >> 7) & 1;
    trace.fill_columns(row, sign_bit_q, Column::SignBitQ);
    trace.fill_columns(row, sign_bit_r, Column::SignBitR);
    trace.fill_columns(row, sign_src_q, Column::SignSrcQ);
    trace.fill_columns(row, sign_src_r, Column::SignSrcR);

    if let Some(entry) = divrem_entry {
        range_bytes.extend(crate::chips::divrem::range_checked_bytes(&entry));
        side_note.divrem_entries.push(entry);
    }
    DivRem {
        div_remainder,
        div_by_zero,
        val_r_byte_inv,
        val_r_partial_nz,
        sign_src_q,
        sign_src_r,
    }
}
