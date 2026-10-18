//! Addition, subtraction, multiplication and the bitwise operations.

use super::*;

/// A multiplication's witness: the schoolbook product's halves and carries, and
/// the sign correction's terms.
#[derive(Clone, Copy)]
pub(super) struct MulWitness {
    pub mul_high: [u8; WORD_SIZE],
    pub mul_carry: [u8; 16],
    pub mul_carry_hi: [u8; 16],
    pub unsigned_product_hi_bytes: [u8; WORD_SIZE],
    pub unsigned_product_low_bytes: [u8; WORD_SIZE],
    pub mul_corr_term_a: [u8; WORD_SIZE],
    pub mul_corr_term_b: [u8; WORD_SIZE],
    pub mul_corr_carry: [u8; WORD_SIZE],
}

/// The add and sub carries.
pub(super) fn add_sub(out: &mut Sinks, s: Step, ops: &Operands) {
    let Sinks { trace, .. } = out;
    let Step { row, flags, .. } = s;
    let Operands {
        val_b_bytes,
        val_d_bytes,
        ..
    } = *ops;
    // ── Add/Sub carry ──
    let carry_limbs = if flags.is_32bit { 4 } else { WORD_SIZE };
    let mut carry = [0u8; WORD_SIZE];
    if flags.is_add {
        let mut c: u16 = 0;
        for i in 0..carry_limbs {
            let sum = val_b_bytes[i] as u16 + val_d_bytes[i] as u16 + c;
            carry[i] = (sum >> 8) as u8;
            c = carry[i] as u16;
        }
    } else if flags.is_sub {
        let (a, b) = if flags.is_neg_add {
            (val_d_bytes, val_b_bytes)
        } else {
            (val_b_bytes, val_d_bytes)
        };
        let mut c: u16 = 1;
        for i in 0..carry_limbs {
            let sum = a[i] as u16 + (b[i] ^ 0xFF) as u16 + c;
            carry[i] = (sum >> 8) as u8;
            c = carry[i] as u16;
        }
    }
    trace.fill_columns_bytes(row, &carry, Column::Carry);
}

/// The multiplication's witness, which MulChip's row carries.
pub(super) fn mul(s: Step, ops: &Operands) -> MulWitness {
    let Step { step, flags, .. } = s;
    let Operands {
        val_b,
        val_d,
        val_b_bytes,
        val_d_bytes,
        ..
    } = *ops;
    // ── Mul auxiliary ──
    let mut mul_high = [0u8; WORD_SIZE];
    let mut mul_carry = [0u8; 16];
    let mut mul_carry_hi = [0u8; 16];
    let mut unsigned_product_hi_bytes = [0u8; WORD_SIZE];
    // Low-64 bytes of the unsigned schoolbook product.
    // Filled on 64-bit `is_mul_low` rows so the schoolbook
    // constraint is satisfied (the schoolbook writes low-64
    // here rather than to `result`).
    let mut unsigned_product_low_bytes = [0u8; WORD_SIZE];
    let mut mul_corr_term_a = [0u8; WORD_SIZE];
    let mut mul_corr_term_b = [0u8; WORD_SIZE];
    let mut mul_corr_carry = [0u8; WORD_SIZE];
    if flags.is_mul {
        let full = (val_b as u128) * (val_d as u128);
        if flags.is_32bit {
            // 32-bit: split at 32 bits.  low-32 →
            // UnsignedProductLow[0..4].
            let low32 = full as u32;
            let low_bytes = low32.to_le_bytes();
            unsigned_product_low_bytes[..4].copy_from_slice(&low_bytes);
            let high32 = (full >> 32) as u32;
            let high_bytes = high32.to_le_bytes();
            mul_high[..4].copy_from_slice(&high_bytes);
        } else if flags.is_mul_upper {
            // MulUpper: mul_high holds positions 0..7 (low 64 of
            // unsigned product); positions 8..15 (unsigned high)
            // land in UnsignedProductHi.  result holds the
            // signedness-adjusted high (for UU: same as unsigned;
            // for SU/SS: unsigned − sign correction, computed by
            // the interpreter and reflected in step.regs_after).
            let low = full as u64;
            mul_high = low.to_le_bytes();
            let high = (full >> 64) as u64;
            unsigned_product_hi_bytes = high.to_le_bytes();
        } else {
            // 64-bit is_mul_low (Mul64 / MulImm64 / ShloL64 /
            // RotL64 / etc.).  Low-64 → UnsignedProductLow,
            // high-64 → mul_high.
            let low = full as u64;
            let high = (full >> 64) as u64;
            unsigned_product_low_bytes = low.to_le_bytes();
            mul_high = high.to_le_bytes();
        }
        let input_limbs = if flags.is_32bit { 4 } else { WORD_SIZE };
        let out_limbs = input_limbs * 2;
        let mut accum = [0u32; 16];
        for i in 0..input_limbs {
            for j in 0..input_limbs {
                accum[i + j] += val_b_bytes[i] as u32 * val_d_bytes[j] as u32;
            }
        }
        // Schoolbook carry per position is up to ~16 bits at busy
        // middle positions (e.g. 0xFFFFFFFF² → carry 0x3FB at k=3).
        // Split across mul_carry (low byte) and mul_carry_hi (high
        // byte); the AIR reconstructs as mul_carry + 256·mul_carry_hi.
        for k in 0..out_limbs.min(16).saturating_sub(1) {
            let carry = accum[k] >> 8;
            mul_carry[k] = carry as u8;
            mul_carry_hi[k] = (carry >> 8) as u8;
            accum[k + 1] += carry;
        }
        if out_limbs <= 16 && out_limbs > 0 {
            let carry = accum[out_limbs - 1] >> 8;
            mul_carry[out_limbs - 1] = carry as u8;
            mul_carry_hi[out_limbs - 1] = (carry >> 8) as u8;
        }

        // Sign-correction columns for MulUpper SS / SU.
        // TermA = sa·val_d (SU/SS); TermB = sb·val_b (SS only).
        // Carry chain: result + TermA + TermB ≡ unsigned_high (mod 2^64).
        if flags.is_mul_upper && !flags.is_32bit {
            let sa = (val_b >> 63) & 1;
            let sb = (val_d >> 63) & 1;
            let term_a_full = if flags.is_mul_upper_su || flags.is_mul_upper_ss {
                if sa == 1 { val_d } else { 0 }
            } else {
                0
            };
            let term_b_full = if flags.is_mul_upper_ss {
                if sb == 1 { val_b } else { 0 }
            } else {
                0
            };
            mul_corr_term_a = term_a_full.to_le_bytes();
            mul_corr_term_b = term_b_full.to_le_bytes();
            let result_bytes_le = step.regs_after[dest_reg(step)].to_le_bytes();
            let mut carry_in: u16 = 0;
            for i in 0..WORD_SIZE {
                let s = result_bytes_le[i] as u16
                    + mul_corr_term_a[i] as u16
                    + mul_corr_term_b[i] as u16
                    + carry_in;
                carry_in = s >> 8;
                mul_corr_carry[i] = carry_in as u8;
            }
        }
    }
    // MulCarry/MulCarryHi, UnsignedProductHi, MulCorrTermA/B/Carry,
    // MulHigh, and UnsignedProductLow are witnessed on MulChip, not
    // CpuChip; `mul_entry` captures MulChip's row once `compare` has the
    // operands' signs.
    MulWitness {
        mul_high,
        mul_carry,
        mul_carry_hi,
        unsigned_product_hi_bytes,
        unsigned_product_low_bytes,
        mul_corr_term_a,
        mul_corr_term_b,
        mul_corr_carry,
    }
}

/// The bitwise operation's BitwiseChip row and AND lookups.
pub(super) fn bitwise(out: &mut Sinks, s: Step, ops: &Operands) {
    let Sinks {
        side_note,
        bitwise_and_bytes,
        ..
    } = out;
    let Step { flags, .. } = s;
    let Operands {
        val_b,
        val_d,
        result,
        val_b_bytes,
        val_d_bytes,
        ..
    } = *ops;
    // ── Bitwise auxiliary (BitwiseChip witnesses
    //   AndResult/ValBHiNib/ValDHiNib/AndResultHiNib) ──
    let mut and_result = [0u8; WORD_SIZE];
    let mut val_b_hi_nib = [0u8; WORD_SIZE];
    let mut val_d_hi_nib = [0u8; WORD_SIZE];
    let mut and_result_hi_nib = [0u8; WORD_SIZE];
    if flags.is_bitwise {
        for i in 0..WORD_SIZE {
            and_result[i] = val_b_bytes[i] & val_d_bytes[i];
            bitwise_and_bytes.push((val_b_bytes[i], val_d_bytes[i]));
            val_b_hi_nib[i] = val_b_bytes[i] >> 4;
            val_d_hi_nib[i] = val_d_bytes[i] >> 4;
            and_result_hi_nib[i] = and_result[i] >> 4;
        }
        side_note
            .bitwise_entries
            .push(crate::side_note::BitwiseEntry {
                val_b,
                val_d,
                result,
                and_result,
                val_b_hi_nib,
                val_d_hi_nib,
                and_result_hi_nib,
                is_and: flags.is_and,
                is_or: flags.is_or,
                is_xor: flags.is_xor,
                is_and_inv: flags.is_and_inv,
                is_or_inv: flags.is_or_inv,
                is_xnor: flags.is_xnor,
            });
    }
}

/// MulChip's row for a multiplication.
pub(super) fn mul_entry(out: &mut Sinks, s: Step, ops: &Operands, mul: &MulWitness, cmp: &Compare) {
    let Sinks {
        side_note,
        range_bytes,
        ..
    } = out;
    let Step { flags, .. } = s;
    let Operands {
        val_b,
        val_d,
        result,
        ..
    } = *ops;
    let MulWitness {
        mul_high,
        mul_carry,
        mul_carry_hi,
        unsigned_product_hi_bytes,
        unsigned_product_low_bytes,
        mul_corr_term_a,
        mul_corr_term_b,
        mul_corr_carry,
    } = *mul;
    let Compare {
        sign_bit_b,
        sign_bit_d,
        ..
    } = *cmp;
    // Capture this mul row for MulChip's main trace.
    // Placed after sign_bit_b/d so MulEntry can carry them too.
    if flags.is_mul {
        let mul_high_u64 = u64::from_le_bytes(mul_high);
        let unsigned_product_low_u64 = u64::from_le_bytes(unsigned_product_low_bytes);
        let unsigned_product_hi_u64 = u64::from_le_bytes(unsigned_product_hi_bytes);
        let entry = crate::side_note::MulEntry {
            val_b,
            val_d,
            result,
            mul_high: mul_high_u64,
            unsigned_product_low: unsigned_product_low_u64,
            unsigned_product_hi: unsigned_product_hi_u64,
            mul_carry,
            mul_carry_hi,
            mul_corr_term_a,
            mul_corr_term_b,
            mul_corr_carry,
            sign_bit_b,
            sign_bit_d,
            is_rotate_l64: flags.is_rotate_l64,
            is_rotate_r64: flags.is_rotate_r64,
            is_rotate_l32: flags.is_rotate_l32,
            is_rotate_r32: flags.is_rotate_r32,
            is_mul_lo: !flags.is_mul_upper,
            is_mul_upper_uu: flags.is_mul_upper_uu,
            is_mul_upper_su: flags.is_mul_upper_su,
            is_mul_upper_ss: flags.is_mul_upper_ss,
            is_32bit: flags.is_32bit,
        };
        range_bytes.extend(crate::chips::mul::range_checked_bytes(&entry));
        side_note.mul_entries.push(entry);
    }
}
