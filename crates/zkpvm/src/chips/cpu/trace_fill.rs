//! CpuChip main-trace generation (Phase 47 split).
//!
//! Holds the per-step witness fill: for every traced PVM step, write
//! the corresponding row of every CpuChip column.  The column shapes
//! mirror the constraints defined in `cpu/mod.rs::add_constraints`
//! one-to-one — if you add a column there, the fill for it lives
//! here.
//!
//! Lookup multiplicities (`SideNote::range256_counts`,
//! `bitwise_and_counts`, `power_of_two_counts`, `popcount_counts`,
//! `bitcount_counts`, `program_memory_counts`, `jump_table_counts`)
//! are charged here as a side-effect of writing the consumer rows;
//! the producer chips read them in `generate_main_trace`.

#![cfg(feature = "prover")]

use stwo::prover::backend::simd::m31::LOG_N_LANES;

use crate::core::ecall::ECALL_BLAKE2B_COMPRESS;
use crate::core::step::WORD_SIZE;
use crate::trace::builder::{FinalizedTrace, TraceBuilder};
use crate::side_note::SideNote;

use super::classify::{classify_opcode, dest_reg, uses_immediate};
use super::columns::Column;
use super::reg_access::step_reg_accesses;

pub(super) fn generate_main_trace(side_note: &mut SideNote) -> FinalizedTrace {
        let num_steps = side_note.num_steps();
        let log_size = (num_steps as f64).log2().ceil().max(LOG_N_LANES as f64) as u32;
        let log_size = log_size.max(LOG_N_LANES);

        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();
        let mut range_bytes: Vec<u8> = Vec::new();
        let mut bitwise_and_bytes: Vec<(u8, u8)> = Vec::new();

        for (row, step) in side_note.steps.iter().enumerate() {
            trace.fill_columns(row, step.timestamp, Column::Timestamp);
            trace.fill_columns_bytes(row, &step.pc.to_le_bytes(), Column::Pc);
            trace.fill_columns_bytes(row, &step.next_pc.to_le_bytes(), Column::NextPc);
            trace.fill_columns(row, step.opcode as u8, Column::Opcode);
            trace.fill_columns(row, step.skip_len as u8, Column::SkipLen);
            // Phase 13b: 8-byte immediate witness for the ProgramMemory lookup.
            trace.fill_columns_bytes(row, &step.imm.to_le_bytes(), Column::ImmBytes);
            // Phase 13b: charge ProgramMemoryChip for this step's instruction
            // fetch.  Two consumer emissions per step (paired) → producer
            // multiplicity = 2 · count_at_pc.
            *side_note.program_memory_counts.entry(step.pc).or_insert(0) += 2;
            // PC carry for sequential next_pc = pc + 1 + skip_len
            {
                let pc_bytes = step.pc.to_le_bytes();
                let sum0 = pc_bytes[0] as u16 + 1 + step.skip_len as u16;
                let c0 = (sum0 >> 8) as u8;
                let sum1 = pc_bytes[1] as u16 + c0 as u16;
                let c1 = (sum1 >> 8) as u8;
                let sum2 = pc_bytes[2] as u16 + c1 as u16;
                let c2 = (sum2 >> 8) as u8;
                trace.fill_columns_bytes(row, &[c0, c1, c2], Column::PcCarry);
            }
            trace.fill_columns(row, step.reg_a as u8, Column::RegA);
            trace.fill_columns(row, step.reg_b as u8, Column::RegB);
            trace.fill_columns(row, step.reg_d as u8, Column::RegD);

            let flags = classify_opcode(step.opcode);

            // Source operands.  Default convention (used by all but
            // the Phase-40 swap):
            //   ThreeReg     → (regs[ra], regs[rb])
            //   TwoRegOneImm → (regs[rb], imm)
            //   TwoReg       → (0, regs[rb])
            //   OneRegImmOffset → (regs[ra], imm)  [imm-compare branches]
            //   Other immediate-source ops → (0, imm)
            //
            // Phase 40: RotR64ImmAlt / RotR32ImmAlt swap the source
            // convention — the immediate is the rotated value, the
            // register is the shift amount.  In AIR terms: val_b ←
            // imm, val_d ← regs[rb].
            let (mut val_b, mut val_d) = match step.opcode.category() {
                javm::instruction::InstructionCategory::ThreeReg => {
                    (step.regs_before[step.reg_a], step.regs_before[step.reg_b])
                }
                javm::instruction::InstructionCategory::TwoRegOneImm
                    if flags.is_rotate_r_imm_alt =>
                {
                    // Phase 40 swap.
                    (step.imm, step.regs_before[step.reg_b])
                }
                javm::instruction::InstructionCategory::TwoRegOneImm => {
                    (step.regs_before[step.reg_b], step.imm)
                }
                javm::instruction::InstructionCategory::TwoReg => {
                    (0, step.regs_before[step.reg_b])
                }
                javm::instruction::InstructionCategory::OneRegImmOffset => {
                    // BranchEqImm/NeImm/LtImm/etc: compare regs[ra] vs imm
                    (step.regs_before[step.reg_a], step.imm)
                }
                _ if uses_immediate(step.opcode) => {
                    (0, step.imm)
                }
                _ => (step.regs_before[step.reg_a], step.regs_before[step.reg_b]),
            };

            // For left/right shifts and Phase-32/36 rotates: save shift
            // amount, then replace val_d with 2^shift_amount.
            //
            // Phase 35 / 36: RotR64 / RotR32 are also pow2-replacements,
            // but with val_d = 2^((modulus − n_real) mod modulus) (the
            // complement) so the mul-schoolbook's low+high yields the
            // rotated-right value.  modulus = 32 for 32-bit, 64 for 64-bit.
            let mut saved_shift_amount: u8 = 0;
            let mut saved_shift_amount_compl: u8 = 0;
            let mut saved_shift_quotient_compl: u64 = 0;
            let is_pow2_replacement = (flags.is_shift && flags.shift_op <= 2)
                || flags.is_rotate_l64
                || flags.is_rotate_r64
                || flags.is_rotate_l32
                || flags.is_rotate_r32;
            if is_pow2_replacement {
                let modulus = if flags.is_32bit { 32u64 } else { 64 };
                let shift = val_d % modulus; // n_real = reg_val_d mod modulus
                saved_shift_amount = shift as u8;
                let is_rotate_r = flags.is_rotate_r64 || flags.is_rotate_r32;
                if is_rotate_r {
                    // val_d = 2^((modulus − n_real) mod modulus).
                    let compl = if shift == 0 { 0 } else { modulus - shift };
                    saved_shift_amount_compl = compl as u8;
                    // reg_val_d + compl = modulus · ShiftQuotientCompl.
                    saved_shift_quotient_compl = (val_d + compl) / modulus;
                    val_d = 1u64 << compl;
                    side_note.power_of_two_counts[compl as usize] += 1;
                } else {
                    val_d = 1u64 << shift;
                    side_note.power_of_two_counts[shift as usize] += 1;
                }
            }

            // Truncate for 32-bit ALU ops (including divrem for right shifts)
            if flags.is_32bit && (flags.is_add || flags.is_sub || flags.is_mul || flags.is_div_rem) {
                val_b &= 0xFFFF_FFFF;
                val_d &= 0xFFFF_FFFF;
            }

            trace.fill_columns(row, val_b, Column::ValB);
            trace.fill_columns(row, val_d, Column::ValD);

            let dr = dest_reg(step);
            let result = step.regs_after[dr];
            trace.fill_columns(row, result, Column::Result);

            let val_b_bytes = val_b.to_le_bytes();
            let val_d_bytes = val_d.to_le_bytes();
            let result_bytes = result.to_le_bytes();

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
                let (a, b) = if flags.is_neg_add { (val_d_bytes, val_b_bytes) } else { (val_b_bytes, val_d_bytes) };
                let mut c: u16 = 1;
                for i in 0..carry_limbs {
                    let sum = a[i] as u16 + (b[i] ^ 0xFF) as u16 + c;
                    carry[i] = (sum >> 8) as u8;
                    c = carry[i] as u16;
                }
            }
            trace.fill_columns_bytes(row, &carry, Column::Carry);

            // ── Mul auxiliary ──
            let mut mul_high = [0u8; WORD_SIZE];
            let mut mul_carry = [0u8; 16];
            let mut mul_carry_hi = [0u8; 16];
            let mut unsigned_product_hi_bytes = [0u8; WORD_SIZE];
            // Phase 32: low-64 bytes of the unsigned schoolbook product.
            // Filled on 64-bit `is_mul_low` rows so the schoolbook
            // constraint is satisfied (the schoolbook now writes
            // low-64 here instead of `result`).
            let mut unsigned_product_low_bytes = [0u8; WORD_SIZE];
            let mut mul_corr_term_a = [0u8; WORD_SIZE];
            let mut mul_corr_term_b = [0u8; WORD_SIZE];
            let mut mul_corr_carry = [0u8; WORD_SIZE];
            if flags.is_mul {
                let full = (val_b as u128) * (val_d as u128);
                if flags.is_32bit {
                    // 32-bit: split at 32 bits.  Phase 36: low-32 →
                    // UnsignedProductLow[0..4] (was: result[0..4]).
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

                // Phase 12c: sign-correction columns for MulUpper SS / SU.
                // TermA = sa·val_d (SU/SS); TermB = sb·val_b (SS only).
                // Carry chain: result + TermA + TermB ≡ unsigned_high (mod 2^64).
                if flags.is_mul_upper && !flags.is_32bit {
                    let sa = (val_b >> 63) & 1;
                    let sb = (val_d >> 63) & 1;
                    let term_a_full = if flags.is_mul_upper_su || flags.is_mul_upper_ss {
                        if sa == 1 { val_d } else { 0 }
                    } else { 0 };
                    let term_b_full = if flags.is_mul_upper_ss {
                        if sb == 1 { val_b } else { 0 }
                    } else { 0 };
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
            // Phase 54b: MulCarry/MulCarryHi moved to MulChip.
            // Phase 54c: UnsignedProductHi + MulCorrTermA/B/Carry moved to MulChip.
            // Phase 54d: MulHigh + UnsignedProductLow moved to MulChip.

            // Phase 54a/b/c/d: MulEntry capture moved below — needs
            // sign_bit_b/sign_bit_d which are computed further down.

            // ── Bitwise auxiliary (Phase 54e: BitwiseChip witnesses
            //   AndResult/ValBHiNib/ValDHiNib/AndResultHiNib now) ──
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
                side_note.bitwise_entries.push(crate::side_note::BitwiseEntry {
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

            // ── Compare auxiliary (populated for is_compare OR is_branch) ──
            // Phase 54f: CmpCarry + CmpSubResult moved to CompareChip;
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
                side_note.compare_entries.push(crate::side_note::CompareEntry {
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

            // Phase 29: byte-wise val_d zero-check infrastructure.
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
            // Phase 17: SignBitB/D are now pinned to bit 7 of the
            // multiplexed source byte (val_b[7] in 64-bit, val_b[3] in
            // 32-bit) via nibble-AND lookups at the end of add_constraints.
            // Compute the source byte explicitly and derive the sign +
            // hi-nibble + lo-nibble from it; bit-31-of-u64 and bit-63-of-u64
            // give the same answer when val_b[4..8] are constrained to 0
            // on 32-bit, but going through the byte makes it obvious that
            // the AIR pin and trace fill use the same source.
            let sign_src_b: u8 = if flags.is_32bit { val_b_bytes[3] } else { val_b_bytes[7] };
            let sign_src_d: u8 = if flags.is_32bit { val_d_bytes[3] } else { val_d_bytes[7] };
            let sign_bit_b: u8 = (sign_src_b >> 7) & 1;
            let sign_bit_d: u8 = (sign_src_d >> 7) & 1;
            trace.fill_columns(row, sign_bit_b, Column::SignBitB);
            trace.fill_columns(row, sign_bit_d, Column::SignBitD);
            trace.fill_columns(row, sign_src_b, Column::SignSrcB);
            trace.fill_columns(row, sign_src_d, Column::SignSrcD);

            // Phase 54a/b/c: capture this mul row for MulChip's main trace.
            // Placed after sign_bit_b/d so MulEntry can carry them too.
            if flags.is_mul {
                let mul_high_u64 = u64::from_le_bytes(mul_high);
                let unsigned_product_low_u64 = u64::from_le_bytes(unsigned_product_low_bytes);
                let unsigned_product_hi_u64 = u64::from_le_bytes(unsigned_product_hi_bytes);
                side_note.mul_entries.push(crate::side_note::MulEntry {
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
                });
            }
            // Signed lt: if signs differ, negative is smaller. If same, use unsigned compare.
            let cmp_lt_s_flag: u8 = if sign_bit_b != sign_bit_d {
                sign_bit_b // b is negative (sign=1) → b < d
            } else {
                cmp_lt_flag // same sign → unsigned comparison
            };
            trace.fill_columns(row, cmp_lt_s_flag, Column::CmpLtSFlag);
            let eq_flag: u8 = if val_b == val_d { 1 } else { 0 };
            trace.fill_columns(row, eq_flag, Column::EqFlag);
            // Phase 54h: ByteEq[8] + ByteDiffInv[8] dropped — branch
            // constraints now read `val_b[i] - val_d[i]` directly.
            trace.fill_columns(row, flags.is_set_lt_u, Column::IsSetLtU);
            trace.fill_columns(row, flags.is_set_lt_s, Column::IsSetLtS);
            trace.fill_columns(row, flags.is_cmov_iz, Column::IsCmovIz);
            trace.fill_columns(row, flags.is_cmov_nz, Column::IsCmovNz);
            trace.fill_columns(row, flags.is_min_s, Column::IsMinS);
            trace.fill_columns(row, flags.is_min_u, Column::IsMinU);
            trace.fill_columns(row, flags.is_max_s, Column::IsMaxS);
            trace.fill_columns(row, flags.is_max_u, Column::IsMaxU);

            // ── Shift auxiliary ──
            let shift_amount = if flags.is_shift {
                if flags.shift_op <= 2
                    || flags.is_rotate_l64 || flags.is_rotate_r64
                    || flags.is_rotate_l32 || flags.is_rotate_r32
                {
                    saved_shift_amount // saved before val_d was replaced
                } else {
                    let modulus = if flags.is_32bit { 32u64 } else { 64 };
                    (val_d % modulus) as u8 // for non-constrained shifts, val_d is original
                }
            } else {
                0
            };
            trace.fill_columns(row, shift_amount, Column::ShiftAmount);
            trace.fill_columns(row, flags.shift_op, Column::ShiftOp);
            // Phase 32 / 35 / 36: extend IsShiftConstrained to cover all
            // four rotate variants.  val_d gets rewritten to a power of
            // two; the val_d-vs-RegValD cross-constraint then skips
            // equality on those rows.
            let is_shift_constrained = (flags.is_shift && flags.shift_op <= 2)
                || flags.is_rotate_l64 || flags.is_rotate_r64
                || flags.is_rotate_l32 || flags.is_rotate_r32;
            trace.fill_columns(row, is_shift_constrained, Column::IsShiftConstrained);
            // Phase 35 / 36: rotate flags + complementary shift columns.
            trace.fill_columns(row, flags.is_rotate_r64, Column::IsRotateR64);
            trace.fill_columns(row, flags.is_rotate_l32, Column::IsRotateL32);
            trace.fill_columns(row, flags.is_rotate_r32, Column::IsRotateR32);
            trace.fill_columns(row, flags.is_rotate_r_imm_alt, Column::IsRotateRImmAlt);
            trace.fill_columns(row, saved_shift_amount_compl, Column::ShiftAmountCompl);
            trace.fill_columns(row, saved_shift_quotient_compl, Column::ShiftQuotientCompl);

            // ── Flags ──
            trace.fill_columns(row, false, Column::IsPadding);
            trace.fill_columns(row, step.reg_write.is_some(), Column::RegAWritten);
            trace.fill_columns(row, step.gas_after, Column::Gas);
            trace.fill_columns(row, flags.is_add, Column::IsAdd);
            trace.fill_columns(row, flags.is_sub, Column::IsSub);
            trace.fill_columns(row, flags.is_mul, Column::IsMul);

            // Phase I-cpu Wave-1 selector helpers (filled inline next to
            // the flags they're derived from).
            let is_64bit_b = !flags.is_32bit;
            trace.fill_columns(row, flags.is_add && is_64bit_b, Column::IsAdd64bitH);
            trace.fill_columns(row, flags.is_add && flags.is_32bit, Column::IsAdd32bitH);
            trace.fill_columns(
                row, flags.is_sub && !flags.is_neg_add, Column::IsSubNotNegaddH
            );
            trace.fill_columns(row, flags.is_sub && flags.is_neg_add, Column::IsSubNegaddH);
            trace.fill_columns(
                row, flags.is_sub && !flags.is_neg_add && is_64bit_b, Column::IsSub64NotNegaddH
            );
            trace.fill_columns(
                row, flags.is_sub && flags.is_neg_add && is_64bit_b, Column::IsSub64NegaddH
            );
            trace.fill_columns(row, flags.is_sub && flags.is_32bit, Column::IsSub32bitH);
            trace.fill_columns(row, flags.is_mul && flags.is_32bit, Column::IsMul32bitH);
            // Wave-2 helpers depend on val_b/val_d/cmp_lt_flag/sign_bit_b/d/
            // div_by_zero, which are computed later in this iteration.  See
            // "Phase I-cpu Wave-2 helper fills" near the end of the loop body.
            // Phase 53: IsMulUpper folded into the (mu_uu+mu_su+mu_ss)
            // sum expression — no CpuChip column to fill.
            trace.fill_columns(row, flags.is_mul_upper_uu, Column::IsMulUpperUU);
            trace.fill_columns(row, flags.is_mul_upper_su, Column::IsMulUpperSU);
            trace.fill_columns(row, flags.is_mul_upper_ss, Column::IsMulUpperSS);
            trace.fill_columns(row, flags.is_div_s, Column::IsDivS);
            // Phase 53c: IsBitwise folded — no column to fill.
            trace.fill_columns(row, flags.is_shift, Column::IsShift);
            // Phase 53d: IsCompare folded — no column to fill.
            trace.fill_columns(row, flags.is_move, Column::IsMove);
            trace.fill_columns(row, flags.is_32bit, Column::Is32Bit);
            trace.fill_columns(row, flags.is_and, Column::IsAnd);
            trace.fill_columns(row, flags.is_or, Column::IsOr);
            trace.fill_columns(row, flags.is_xor, Column::IsXor);
            trace.fill_columns(row, flags.is_and_inv, Column::IsAndInv);
            trace.fill_columns(row, flags.is_or_inv, Column::IsOrInv);
            trace.fill_columns(row, flags.is_xnor, Column::IsXnor);
            trace.fill_columns(row, flags.is_neg_add, Column::IsNegAdd);
            // Phase 53e: IsBranch folded into the 10 br_* sub-flag sum.
            trace.fill_columns(row, flags.is_br_eq, Column::IsBrEq);
            trace.fill_columns(row, flags.is_br_ne, Column::IsBrNe);
            trace.fill_columns(row, flags.is_br_lt_u, Column::IsBrLtU);
            trace.fill_columns(row, flags.is_br_ge_u, Column::IsBrGeU);
            trace.fill_columns(row, flags.is_br_le_u, Column::IsBrLeU);
            trace.fill_columns(row, flags.is_br_gt_u, Column::IsBrGtU);
            trace.fill_columns(row, flags.is_br_lt_s, Column::IsBrLtS);
            trace.fill_columns(row, flags.is_br_ge_s, Column::IsBrGeS);
            trace.fill_columns(row, flags.is_br_le_s, Column::IsBrLeS);
            trace.fill_columns(row, flags.is_br_gt_s, Column::IsBrGtS);
            trace.fill_columns(row, flags.is_jump, Column::IsJump);
            trace.fill_columns(row, step.branch_taken, Column::BranchTaken);
            trace.fill_columns_bytes(row, &step.branch_target.to_le_bytes(), Column::BranchTarget);
            trace.fill_columns(row, flags.is_div_rem, Column::IsDivRem);
            trace.fill_columns(row, flags.div_rem_op, Column::DivRemOp);
            trace.fill_columns(row, flags.is_reverse_bytes, Column::IsReverseBytes);
            trace.fill_columns(row, flags.is_zero_ext_16, Column::IsZeroExt16);
            trace.fill_columns(row, flags.is_sign_ext_8, Column::IsSignExt8);
            trace.fill_columns(row, flags.is_sign_ext_16, Column::IsSignExt16);
            trace.fill_columns(row, flags.is_trap, Column::IsTrap);
            trace.fill_columns(row, flags.is_jump_ind, Column::IsJumpInd);
            trace.fill_columns(row, flags.is_load_imm_jump_ind, Column::IsLoadImmJumpInd);
            // Phase 13d-loadimmjumpind: ImmYBytes always carries low 4 bytes
            // of step.imm_y so the prog_mem lookup balances on every row
            // (canonical = 0 for non-LoadImmJumpInd ops).
            trace.fill_columns_bytes(
                row, &(step.imm_y as u32).to_le_bytes(), Column::ImmYBytes
            );
            // Phase 13d: per-byte add-with-carry chain for JumpIndAddr =
            // (val_b + step.imm) mod 2^32.  The constraint is gated by
            // IsJumpInd, so on non-JumpInd rows the columns are left at
            // zero (default fill).  The runtime addr feeds JumpTableChip's
            // multiplicity counter via side_note.jump_table_counts.
            if flags.is_jump_ind {
                let val_b_lo = (val_b as u32).to_le_bytes();
                let imm_lo = (step.imm as u32).to_le_bytes();
                let mut carry_in: u16 = 0;
                let mut addr_bytes = [0u8; 4];
                let mut carry_bytes = [0u8; 4];
                for i in 0..4 {
                    let s = val_b_lo[i] as u16 + imm_lo[i] as u16 + carry_in;
                    addr_bytes[i] = s as u8;
                    carry_in = s >> 8;
                    carry_bytes[i] = carry_in as u8;
                }
                trace.fill_columns_bytes(row, &addr_bytes, Column::JumpIndAddr);
                trace.fill_columns_bytes(row, &carry_bytes, Column::JumpIndCarry);

                // Count this dispatch in side_note.jump_table_counts so
                // JumpTableChip's producer multiplicity matches.  Index =
                // addr/2 - 1 (mirrors the runtime djump indexing).
                let addr = u32::from_le_bytes(addr_bytes);
                if addr >= 2 && addr.is_multiple_of(2) {
                    let idx = (addr / 2 - 1) as usize;
                    if let Some(counts) = side_note.jump_table_counts.get_mut(idx) {
                        *counts += 1;
                    }
                }
            }
            // Phase 13d-loadimmjumpind: LoadImmJumpInd carry chain for
            // LoadImmJumpIndAddr = (val_d + imm_y) mod 2^32.
            if flags.is_load_imm_jump_ind {
                let val_d_lo = (val_d as u32).to_le_bytes();
                let imm_y_lo = (step.imm_y as u32).to_le_bytes();
                let mut carry_in: u16 = 0;
                let mut addr_bytes = [0u8; 4];
                let mut carry_bytes = [0u8; 4];
                for i in 0..4 {
                    let s = val_d_lo[i] as u16 + imm_y_lo[i] as u16 + carry_in;
                    addr_bytes[i] = s as u8;
                    carry_in = s >> 8;
                    carry_bytes[i] = carry_in as u8;
                }
                trace.fill_columns_bytes(row, &addr_bytes, Column::LoadImmJumpIndAddr);
                trace.fill_columns_bytes(row, &carry_bytes, Column::LoadImmJumpIndCarry);

                let addr = u32::from_le_bytes(addr_bytes);
                if addr >= 2 && addr.is_multiple_of(2) {
                    let idx = (addr / 2 - 1) as usize;
                    if let Some(counts) = side_note.jump_table_counts.get_mut(idx) {
                        *counts += 1;
                    }
                }
            }
            // Sign-extend witnesses (Phase 12b-2): high nibble + bit-7 of the
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

            // ── DivRem auxiliary ──
            let mut div_quotient = [0u8; WORD_SIZE];
            let mut div_remainder = [0u8; WORD_SIZE];
            let mut div_mul_carry = [0u8; 16];
            let mut div_mul_carry_hi = [0u8; 16];
            let mut div_by_zero: u8 = 0;
            let mut div_corr_hi = [0u8; WORD_SIZE];
            let mut div_corr_carry = [0u8; WORD_SIZE];
            if flags.is_div_rem {
                let dividend = val_b;
                let divisor = val_d;
                if divisor == 0 {
                    div_by_zero = 1;
                    // For div-by-zero: result is special (u64::MAX for div, dividend for rem)
                    // quotient/remainder don't matter, constraint is bypassed
                } else {
                    // Compute the canonical (q, r) the interpreter wrote.
                    // For DivS / RemS we need *signed* round-toward-zero
                    // division so the byte-level decomposition matches
                    // two's complement (e.g. -100/7 → q = -14 →
                    // q.to_le_bytes() = 0xF2,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF).
                    // Phase 16: previously the trace used unsigned division
                    // for DivS too — silently wrong on negatives, hidden
                    // because no positive DivS test had a negative operand.
                    let (q_bytes, r_bytes): ([u8; 8], [u8; 8]) = if flags.is_div_s {
                        if flags.is_32bit {
                            let b32 = dividend as i32;
                            let d32 = divisor as i32;
                            // i32 div / rem with the standard PVM
                            // overflow guard (INT_MIN / -1 = INT_MIN, rem = 0).
                            let (q32, r32) = if b32 == i32::MIN && d32 == -1 {
                                (i32::MIN, 0i32)
                            } else {
                                (b32 / d32, b32 % d32)
                            };
                            // Phase 19: sign-extend div_quotient / div_remainder
                            // to match the result column (which is the
                            // interpreter's `q as i64 as u64`).  The 32-bit
                            // schoolbook + Phase 18 sign-correction chain
                            // only reference [0..4]; the result-quotient
                            // binding requires [4..8] to track sign-
                            // extension too.
                            ((q32 as i64 as u64).to_le_bytes(),
                             (r32 as i64 as u64).to_le_bytes())
                        } else {
                            let bs = dividend as i64;
                            let ds = divisor as i64;
                            let (qs, rs) = if bs == i64::MIN && ds == -1 {
                                (i64::MIN, 0i64)
                            } else {
                                (bs / ds, bs % ds)
                            };
                            ((qs as u64).to_le_bytes(), (rs as u64).to_le_bytes())
                        }
                    } else {
                        // DivU / RemU: unsigned division.
                        ((dividend / divisor).to_le_bytes(),
                         (dividend % divisor).to_le_bytes())
                    };
                    div_quotient = q_bytes;
                    div_remainder = r_bytes;

                    // Carry chain for q * divisor + remainder = dividend (schoolbook)
                    let divisor_bytes = divisor.to_le_bytes();
                    let input_limbs = if flags.is_32bit { 4 } else { WORD_SIZE };
                    let out_limbs = input_limbs * 2;
                    let mut accum = [0u32; 16];
                    for i in 0..input_limbs {
                        for j in 0..input_limbs {
                            accum[i + j] += div_quotient[i] as u32 * divisor_bytes[j] as u32;
                        }
                    }
                    // Add remainder to low limbs
                    for i in 0..input_limbs {
                        accum[i] += div_remainder[i] as u32;
                    }
                    for k in 0..out_limbs.min(16).saturating_sub(1) {
                        let carry = accum[k] >> 8;
                        div_mul_carry[k] = carry as u8;
                        div_mul_carry_hi[k] = (carry >> 8) as u8;
                        accum[k + 1] += carry;
                    }
                    if out_limbs > 0 && out_limbs <= 16 {
                        let carry = accum[out_limbs - 1] >> 8;
                        div_mul_carry[out_limbs - 1] = carry as u8;
                        div_mul_carry_hi[out_limbs - 1] = (carry >> 8) as u8;
                    }

                    // Phase 16: DivS sign-correction for the 64-bit
                    // schoolbook's high bytes.  See the "DivS sign
                    // correction" constraint block in add_constraints.
                    //
                    //   div_corr_hi[i] + carry_out·256 + (i==0 ? sa : 0)
                    //     = sq·d_u[i] + sd·q_u[i] + carry_in + (i==0 ? sr : 0)
                    if flags.is_div_s && !flags.is_32bit {
                        let sa = (val_b >> 63) & 1;
                        let sd = (val_d >> 63) & 1;
                        let term_d = if (div_quotient[7] >> 7) & 1 == 1 { val_d } else { 0 };
                        let term_q = if sd == 1 {
                            u64::from_le_bytes(div_quotient)
                        } else {
                            0
                        };
                        let term_d_bytes = term_d.to_le_bytes();
                        let term_q_bytes = term_q.to_le_bytes();
                        let sr_bit = (div_remainder[7] >> 7) & 1;
                        let mut carry: i32 = 0;
                        for i in 0..WORD_SIZE {
                            let extra_lhs = if i == 0 { sa as i32 } else { 0 };
                            let extra_rhs = if i == 0 { sr_bit as i32 } else { 0 };
                            // s = sq·d_u[i] + sd·q_u[i] + carry_in + (i==0 ? sr : 0)
                            //     − (i==0 ? sa : 0)
                            let s = term_d_bytes[i] as i32
                                + term_q_bytes[i] as i32
                                + carry
                                + extra_rhs
                                - extra_lhs;
                            // Want: div_corr_hi[i] + carry_out·256 = s.
                            // s ∈ [−1, 511 + carry_in]; with carry_in ≤ 2
                            // and per-byte cap, take low byte and carry out.
                            let s_mod = s.rem_euclid(256);
                            div_corr_hi[i] = s_mod as u8;
                            carry = (s - s_mod) / 256;
                            div_corr_carry[i] = carry as u8;
                        }
                    } else if flags.is_div_s && flags.is_32bit {
                        // Phase 18: 32-bit DivS sign-correction.
                        // Same equation as the 64-bit case but over 4
                        // bytes; sa/sd/sq/sr derive from byte 3 (32-bit
                        // sign), not byte 7.  DivCorrHi[4..8] and
                        // DivCorrCarry[4..8] left at 0 — unused by both
                        // the 32-bit schoolbook and the 32-bit chain.
                        let sa = (val_b_bytes[3] >> 7) & 1;
                        let sd = (val_d_bytes[3] >> 7) & 1;
                        let sq = (div_quotient[3] >> 7) & 1;
                        let sr = (div_remainder[3] >> 7) & 1;
                        // val_d / div_quotient as 32-bit unsigned.
                        let d_u32 = u32::from_le_bytes([
                            val_d_bytes[0], val_d_bytes[1], val_d_bytes[2], val_d_bytes[3],
                        ]);
                        let q_u32 = u32::from_le_bytes([
                            div_quotient[0], div_quotient[1], div_quotient[2], div_quotient[3],
                        ]);
                        let term_d = if sq == 1 { d_u32 } else { 0 };
                        let term_q = if sd == 1 { q_u32 } else { 0 };
                        let term_d_bytes = term_d.to_le_bytes();
                        let term_q_bytes = term_q.to_le_bytes();
                        let mut carry: i32 = 0;
                        for i in 0..4 {
                            let extra_lhs = if i == 0 { sa as i32 } else { 0 };
                            let extra_rhs = if i == 0 { sr as i32 } else { 0 };
                            let s = term_d_bytes[i] as i32
                                + term_q_bytes[i] as i32
                                + carry
                                + extra_rhs
                                - extra_lhs;
                            let s_mod = s.rem_euclid(256);
                            div_corr_hi[i] = s_mod as u8;
                            carry = (s - s_mod) / 256;
                            div_corr_carry[i] = carry as u8;
                        }
                    }
                }
            }
            trace.fill_columns_bytes(row, &div_quotient, Column::DivQuotient);
            trace.fill_columns_bytes(row, &div_remainder, Column::DivRemainder);
            // Phase 54g: DivMulCarry/DivMulCarryHi moved to DivRemChip.
            trace.fill_columns(row, div_by_zero, Column::DivByZero);
            // Phase 16 → 54k: DivCorrHi[8] + DivCorrCarry[8] no longer
            // CpuChip columns.  div_corr_hi / div_corr_carry are
            // captured in DivRemEntry below and witnessed on DivRemChip.

            // Phase 21 → 54i: DivCmpDiff / DivCmpCarry chain witnesses
            // moved to DivRemChip.  Compute them here only on divrem
            // rows so they can flow into the DivRemEntry below; non-divrem
            // rows skip the work entirely.
            let mut div_cmp_diff = [0u8; WORD_SIZE];
            let mut div_cmp_carry = [0u8; WORD_SIZE];
            if flags.is_div_rem {
                let mut c: u16 = 0;
                for i in 0..WORD_SIZE {
                    let s = val_d_bytes[i] as u16
                        + (255u16 - div_remainder[i] as u16)
                        + c;
                    div_cmp_diff[i] = (s & 0xFF) as u8;
                    c = s >> 8;
                    div_cmp_carry[i] = c as u8;
                }
                // 8 Range256 charges per divrem row (matches DivRemChip's
                // 8 emissions on each real row of its narrower trace).
                for &b in &div_cmp_diff {
                    range_bytes.push(b);
                }
            }

            // Phase 54g/54i/54k: DivRemEntry push deferred until after
            // sign_bit_q/r are computed (Phase 17/18 block below) so
            // they can flow into DivRemChip via the entry.

            // Phase 31: byte-wise zero-check for div_remainder
            // (mirrors Phase 29's pattern for val_d).  Drives the
            // sign-of-r uniqueness constraint.
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

            // Phase 30 → 54j-redux: |val_d| / |div_remainder| chains
            // and the AbsCmp comparison chain moved to DivRemChip.
            // We still compute the bytes here so the DivRemEntry can
            // ship them; only divrem rows allocate, and on those rows
            // the AbsCmpDiff bytes feed the Range256 multiplicity.
            let mut abs_d = [0u8; WORD_SIZE];
            let mut abs_d_carry = [0u8; WORD_SIZE];
            let mut abs_r = [0u8; WORD_SIZE];
            let mut abs_r_carry = [0u8; WORD_SIZE];
            let mut abs_cmp_diff = [0u8; WORD_SIZE];
            let mut abs_cmp_carry = [0u8; WORD_SIZE];
            if flags.is_div_rem {
                let sign_d_p30: u8 = if flags.is_32bit { (val_d_bytes[3] >> 7) & 1 } else { (val_d_bytes[7] >> 7) & 1 };
                let sign_r_p30: u8 = if flags.is_32bit { (div_remainder[3] >> 7) & 1 } else { (div_remainder[7] >> 7) & 1 };
                if sign_d_p30 == 0 {
                    abs_d.copy_from_slice(&val_d_bytes);
                } else {
                    let mut c: u16 = 1; // +1 of two's complement
                    for i in 0..WORD_SIZE {
                        let s = (255u16 - val_d_bytes[i] as u16) + c;
                        abs_d[i] = (s & 0xFF) as u8;
                        c = s >> 8;
                        abs_d_carry[i] = c as u8;
                    }
                }
                if sign_r_p30 == 0 {
                    abs_r.copy_from_slice(&div_remainder);
                } else {
                    let mut c: u16 = 1;
                    for i in 0..WORD_SIZE {
                        let s = (255u16 - div_remainder[i] as u16) + c;
                        abs_r[i] = (s & 0xFF) as u8;
                        c = s >> 8;
                        abs_r_carry[i] = c as u8;
                    }
                }
                let mut c: u16 = 0;
                for i in 0..WORD_SIZE {
                    let s = abs_d[i] as u16 + (255u16 - abs_r[i] as u16) + c;
                    abs_cmp_diff[i] = (s & 0xFF) as u8;
                    c = s >> 8;
                    abs_cmp_carry[i] = c as u8;
                }
                // 8 Range256 charges per divrem row (matches DivRemChip's
                // 8 emissions on each real row of its narrower trace).
                for &b in &abs_cmp_diff {
                    range_bytes.push(b);
                }
            }
            // Phase 17 / 18: SignBitQ / SignBitR are pinned to bit 7
            // of the multiplexed source byte (div_quotient[7] in
            // 64-bit, div_quotient[3] in 32-bit; same for remainder).
            // On non-divrem rows div_quotient/remainder bytes are all
            // 0, so SignBitQ/R fall to 0 — consistent with the
            // nibble lookups.
            let sign_src_q: u8 = if flags.is_32bit { div_quotient[3] } else { div_quotient[7] };
            let sign_src_r: u8 = if flags.is_32bit { div_remainder[3] } else { div_remainder[7] };
            let sign_bit_q: u8 = (sign_src_q >> 7) & 1;
            let sign_bit_r: u8 = (sign_src_r >> 7) & 1;
            trace.fill_columns(row, sign_bit_q, Column::SignBitQ);
            trace.fill_columns(row, sign_bit_r, Column::SignBitR);
            trace.fill_columns(row, sign_src_q, Column::SignSrcQ);
            trace.fill_columns(row, sign_src_r, Column::SignSrcR);

            // Phase 54g/54i/54k: capture this row for DivRemChip's
            // main trace.  Pushed here (rather than just after
            // div_quotient/div_remainder are filled) so all 4 sign
            // bits are available — DivRemChip's Phase 16/18 sign-
            // correction chain reads them via the lookup tuple.
            if flags.is_div_rem {
                let div_quotient_u64 = u64::from_le_bytes(div_quotient);
                let div_remainder_u64 = u64::from_le_bytes(div_remainder);
                side_note.divrem_entries.push(crate::side_note::DivRemEntry {
                    val_b,
                    val_d,
                    div_quotient: div_quotient_u64,
                    div_remainder: div_remainder_u64,
                    div_corr_hi,
                    div_corr_carry,
                    div_mul_carry,
                    div_mul_carry_hi,
                    div_by_zero: div_by_zero != 0,
                    is_32bit: flags.is_32bit,
                    is_div_s: flags.is_div_s,
                    div_cmp_diff,
                    div_cmp_carry,
                    sign_bit_b,
                    sign_bit_d,
                    sign_bit_q,
                    sign_bit_r,
                    abs_d,
                    abs_d_carry,
                    abs_r,
                    abs_r_carry,
                    abs_cmp_diff,
                    abs_cmp_carry,
                });
            }

            // Phase 17 / 18: hi nibbles + BitwiseLookupChip charges
            // for the 8 sign-bit pinning lookups emitted on every
            // real row.
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

            // Phase 19: SignBitResult / ResultHiNib pinning.  On
            // padding rows result_bytes = 0 so SignBitResult = 0
            // (consistent with the lookup).
            let sign_bit_result = (result_bytes[3] >> 7) & 1;
            let hi_res = result_bytes[3] >> 4;
            let lo_res = result_bytes[3] & 0xF;
            trace.fill_columns(row, sign_bit_result, Column::SignBitResult);
            trace.fill_columns(row, hi_res, Column::ResultHiNib);
            *side_note.bitwise_and_counts.entry((hi_res, 8)).or_insert(0) += 1;
            *side_note.bitwise_and_counts.entry((lo_res, 0xF)).or_insert(0) += 1;

            // ── Memory access columns ──
            trace.fill_columns(row, flags.is_exit, Column::IsExit);
            trace.fill_columns(row, flags.is_load, Column::IsLoad);
            // Phase 53f: IsStore folded — sum of the 3 store sub-flags.
            // Phase 20: signed-load flags + sign-bit pinning.
            trace.fill_columns(row, flags.is_load_i8, Column::IsLoadI8);
            trace.fill_columns(row, flags.is_load_i16, Column::IsLoadI16);
            trace.fill_columns(row, flags.is_load_i32, Column::IsLoadI32);
            // Phase 23: per-size flags (cover both load and store variants).
            trace.fill_columns(row, flags.is_mem_size_1, Column::IsMemSize1);
            trace.fill_columns(row, flags.is_mem_size_2, Column::IsMemSize2);
            trace.fill_columns(row, flags.is_mem_size_4, Column::IsMemSize4);
            trace.fill_columns(row, flags.is_mem_size_8, Column::IsMemSize8);
            // Phase 24: direct-store flag (StoreU8/16/32/64 only).
            trace.fill_columns(row, flags.is_store_direct, Column::IsStoreDirect);
            // Phase 25: direct-load flag (LoadU8/I8/U16/I16/U32/I32/U64).
            trace.fill_columns(row, flags.is_load_direct, Column::IsLoadDirect);
            // Phase 26: indirect-mem flag + MemAddr add-with-carry chain.
            trace.fill_columns(row, flags.is_mem_indirect, Column::IsMemIndirect);
            // Phase 27: StoreImm / StoreImmInd flags.
            trace.fill_columns(row, flags.is_store_imm_any, Column::IsStoreImmAny);
            trace.fill_columns(row, flags.is_store_imm_direct, Column::IsStoreImmDirect);
            // Phase 28: StoreInd flag + RegValA (regs_before[reg_a]).
            trace.fill_columns(row, flags.is_store_ind, Column::IsStoreInd);
            let reg_val_a_u64 = if flags.is_store_ind {
                step.regs_before[step.reg_a]
            } else {
                0
            };
            trace.fill_columns(row, reg_val_a_u64, Column::RegValA);
            // Phase 32: RotL64 flag.  RotL64's val_d gets rewritten to
            // 2^n + ShiftQuotient infra fires (gated on the extended
            // IsShiftConstrained above).
            trace.fill_columns(row, flags.is_rotate_l64, Column::IsRotateL64);
            // Phase 33: CountSetBits — fill IsCountSetBits flag and the 8
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
            // Phase 34: LeadingZeroBits / TrailingZeroBits witnesses.
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
            let mut mem_addr_carry = [0u8; 4];
            if flags.is_mem_indirect {
                let val_b_bytes_le = val_b.to_le_bytes();
                let imm_bytes_le = step.imm.to_le_bytes();
                let mut c: u16 = 0;
                for i in 0..4 {
                    let s = val_b_bytes_le[i] as u16 + imm_bytes_le[i] as u16 + c;
                    c = s >> 8;
                    mem_addr_carry[i] = c as u8;
                }
            }
            trace.fill_columns_bytes(row, &mem_addr_carry, Column::MemAddrCarry);
            let load_sign_src: u8 = if flags.is_load_i8 {
                result_bytes[0]
            } else if flags.is_load_i16 {
                result_bytes[1]
            } else if flags.is_load_i32 {
                result_bytes[3]
            } else {
                0
            };
            let load_sign_bit: u8 = (load_sign_src >> 7) & 1;
            let load_sign_hi: u8 = load_sign_src >> 4;
            let load_sign_lo: u8 = load_sign_src & 0xF;
            trace.fill_columns(row, load_sign_src, Column::LoadSignSrc);
            trace.fill_columns(row, load_sign_bit, Column::LoadSignBit);
            trace.fill_columns(row, load_sign_hi, Column::LoadSignHiNib);
            *side_note.bitwise_and_counts.entry((load_sign_hi, 8)).or_insert(0) += 1;
            *side_note.bitwise_and_counts.entry((load_sign_lo, 0xF)).or_insert(0) += 1;
            let mem = step.mem_read.as_ref().or(step.mem_write.as_ref());
            if let Some(m) = mem {
                trace.fill_columns_bytes(row, &m.address.to_le_bytes(), Column::MemAddr);
                trace.fill_columns(row, m.value, Column::MemValue);
                trace.fill_columns(row, m.size, Column::MemSize);
                let mut byte_active = [0u8; 8];
                for i in 0..m.size as usize { byte_active[i] = 1; }
                trace.fill_columns_bytes(row, &byte_active, Column::MemByteActive);
            }

            // NextTimestamp = timestamp + 1
            trace.fill_columns(row, step.timestamp + 1, Column::NextTimestamp);

            // ── Blake2b ECALL binding (Phase 8c) ──
            // Detect Ecalli with imm == ECALL_BLAKE2B_COMPRESS and snapshot the
            // regs_before values that the precompile reads (φ[10], [11], [12])
            // plus the derived boolean form of φ[7].
            let is_blake_ecall = matches!(step.opcode,
                    crate::core::opcode::Opcode::Ecalli | crate::core::opcode::Opcode::Ecall)
                && step.imm == ECALL_BLAKE2B_COMPRESS as u64;
            trace.fill_columns(row, is_blake_ecall, Column::IsBlakeEcall);
            trace.fill_columns(row, step.regs_before[10], Column::Phi10);
            trace.fill_columns(row, step.regs_before[11], Column::Phi11);
            trace.fill_columns(row, step.regs_before[12], Column::Phi12);
            let phi7_u64 = step.regs_before[7];
            trace.fill_columns(row, phi7_u64, Column::Phi7);
            let phi7_bool: u8 = if phi7_u64 != 0 { 1 } else { 0 };
            trace.fill_columns(row, phi7_bool, Column::Phi7Bool);
            // Phi7Inv = field-element inverse of (Phi7 interpreted as u64, mod M31).
            // If Phi7 == 0 we store 0; the boolean-identity constraint
            //   Phi7Bool · (1 - Phi7_combined · Phi7Inv_combined) = 0
            // forces Phi7Inv to be the real inverse whenever Phi7Bool = 1.
            let phi7_inv_u64: u64 = if phi7_u64 != 0 {
                // Combine bytes with powers of 256 modulo the M31 prime,
                // then invert.  Rust's u128 multiplication + manual mod is
                // enough since M31 = 2^31 - 1.
                const M31_P: u64 = (1u64 << 31) - 1;
                let mut combined: u64 = 0;
                let bytes = phi7_u64.to_le_bytes();
                let mut pow: u64 = 1;
                for b in bytes {
                    combined = (combined + (b as u64) * pow) % M31_P;
                    pow = (pow * 256) % M31_P;
                }
                // Fermat's little theorem: inverse = combined^(p-2) mod p.
                let mut result: u64 = 1;
                let mut base = combined;
                let mut exp = M31_P - 2;
                while exp > 0 {
                    if exp & 1 == 1 {
                        result = (result * base) % M31_P;
                    }
                    base = (base * base) % M31_P;
                    exp >>= 1;
                }
                result
            } else {
                0
            };
            trace.fill_columns(row, phi7_inv_u64, Column::Phi7Inv);

            // ── Register-memory producer descriptors (Phase 9d) ──
            let accesses = step_reg_accesses(step);
            trace.fill_columns(row, accesses.val_b_read.is_some(), Column::ValBIsReg);
            trace.fill_columns(
                row,
                accesses.val_b_read.map(|(a, _)| a).unwrap_or(0),
                Column::ValBRegIdx,
            );
            trace.fill_columns(row, accesses.val_d_read.is_some(), Column::ValDIsReg);
            trace.fill_columns(
                row,
                accesses.val_d_read.map(|(a, _)| a).unwrap_or(0),
                Column::ValDRegIdx,
            );
            trace.fill_columns(row, accesses.result_write.is_some(), Column::ResultIsReg);
            trace.fill_columns(
                row,
                accesses.result_write.map(|(a, _)| a).unwrap_or(0),
                Column::ResultRegIdx,
            );

            // ── Phase I-cpu Wave-2 helper fills ──
            // All inputs (val_b, val_d, sign_bit_b, sign_bit_d, cmp_lt_flag,
            // div_by_zero, val_d_is_zero, flags.div_rem_op) are now in scope.
            {
                use stwo::core::fields::m31::BaseField;
                let signs_diff_b = (sign_bit_b ^ sign_bit_d) != 0;
                trace.fill_columns(row, signs_diff_b, Column::SignsDiffH);
                let vd_zero_b = val_d == 0;
                let is_compare_b = flags.is_set_lt_u || flags.is_set_lt_s
                    || flags.is_cmov_iz || flags.is_cmov_nz
                    || flags.is_min_s || flags.is_min_u
                    || flags.is_max_s || flags.is_max_u;
                trace.fill_columns(row, is_compare_b && vd_zero_b, Column::IsCmpVdzH);
                trace.fill_columns(row, flags.is_cmov_iz && vd_zero_b, Column::IsCmovIzVdzH);
                trace.fill_columns(
                    row, flags.is_cmov_nz && !vd_zero_b, Column::IsCmovNzNotVdzH
                );
                // CmpLtValB/D body helpers — byte-wise products.
                let cmp_lt_u8: u8 = if cmp_lt_flag != 0 { 1 } else { 0 };
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
                let gate_div_v = ((op_i32 - 2) * (op_i32 - 3)).rem_euclid(stwo::core::fields::m31::P as i32) as u32;
                let gate_rem_v = (op_i32 * (op_i32 - 1)).rem_euclid(stwo::core::fields::m31::P as i32) as u32;
                trace.fill_columns(row, div_active_b, Column::CpuDivActiveH);
                trace.fill_columns_base_field(
                    row, &[BaseField::from(gate_div_v)], Column::GateDivH
                );
                trace.fill_columns_base_field(
                    row, &[BaseField::from(gate_rem_v)], Column::GateRemH
                );
                let active_v: u32 = if div_active_b { 1 } else { 0 };
                trace.fill_columns_base_field(
                    row,
                    &[BaseField::from((active_v * gate_div_v).rem_euclid(stwo::core::fields::m31::P))],
                    Column::DivActiveQuotH,
                );
                trace.fill_columns_base_field(
                    row,
                    &[BaseField::from((active_v * gate_rem_v).rem_euclid(stwo::core::fields::m31::P))],
                    Column::DivActiveRemH,
                );
                trace.fill_columns(
                    row, flags.is_div_rem && flags.is_32bit, Column::IsDivRem32bitH
                );

                // ── Wave-3 helpers ──
                // val_d_byte_inv / val_d_partial_nz are filled at line 356-357.
                // Reuse the locals from that fill.
                let mut indicator = [BaseField::from(0u32); 8];
                let mut ind_minus1 = [BaseField::from(0u32); 8];
                let mut part_nz_times_ind = [BaseField::from(0u32); 8];
                for i in 0..WORD_SIZE {
                    let vd_i = BaseField::from(val_d_bytes[i] as u32);
                    indicator[i] = vd_i * val_d_byte_inv[i];
                    // ValDByteIndMinus1H = val_d · (indicator - 1).
                    // For valid traces with vd=0 → ind=0, helper=0;
                    // with vd≠0 → ind=1, helper=0.  Either way 0.
                    let _ = vd_i; // implicit in the math
                    ind_minus1[i] = BaseField::from(0u32);
                    if i >= 1 {
                        // PartialNZ[i-1] · ByteIndicator[i].
                        let pnz_prev = BaseField::from(val_d_partial_nz[i - 1] as u32);
                        part_nz_times_ind[i] = pnz_prev * indicator[i];
                    }
                }
                trace.fill_columns_base_field(row, &indicator, Column::ValDByteIndicatorH);
                trace.fill_columns_base_field(row, &ind_minus1, Column::ValDByteIndMinus1H);
                trace.fill_columns_base_field(row, &part_nz_times_ind, Column::PartNZTimesIndH);
                // is_div_rem · val_d_is_zero (booleans).
                trace.fill_columns(
                    row, flags.is_div_rem && vd_zero_b, Column::IsDivRemTimesVdzH
                );
                // dbz_active = is_div_rem · div_by_zero (boolean).
                let dbz_active_b = flags.is_div_rem && (div_by_zero != 0);
                trace.fill_columns(row, dbz_active_b, Column::DbzActiveH);
                // dbz_active * gate_div / gate_rem (field-element products).
                let dbz_active_v: u32 = if dbz_active_b { 1 } else { 0 };
                trace.fill_columns_base_field(
                    row,
                    &[BaseField::from((dbz_active_v * gate_div_v).rem_euclid(stwo::core::fields::m31::P))],
                    Column::DbzActiveQuotH,
                );
                trace.fill_columns_base_field(
                    row,
                    &[BaseField::from((dbz_active_v * gate_rem_v).rem_euclid(stwo::core::fields::m31::P))],
                    Column::DbzActiveRemH,
                );
            }

            // Phase 9g: raw register value behind ValB + IsTruncated flag.
            let reg_val_b_u64 = accesses.val_b_read.map(|(_, v)| v).unwrap_or(0);
            trace.fill_columns(row, reg_val_b_u64, Column::RegValB);
            let is_truncated: u8 = if flags.is_32bit
                && (flags.is_add || flags.is_sub || flags.is_mul || flags.is_div_rem)
            { 1 } else { 0 };
            trace.fill_columns(row, is_truncated, Column::IsTruncated);

            // Phase 9f: raw register value behind ValD + the shift quotient.
            let reg_val_d_u64 = accesses.val_d_read.map(|(_, v)| v).unwrap_or(0);
            trace.fill_columns(row, reg_val_d_u64, Column::RegValD);
            let shift_q: u64 = if (flags.is_shift && flags.shift_op <= 2)
                || flags.is_rotate_l64
                || flags.is_rotate_r64
                || flags.is_rotate_l32
                || flags.is_rotate_r32
            {
                let modulus = if flags.is_32bit { 32u64 } else { 64 };
                reg_val_d_u64 / modulus
            } else {
                0
            };
            trace.fill_columns(row, shift_q, Column::ShiftQuotient);

            for &b in &result_bytes {
                range_bytes.push(b);
            }
            // Range-check cmp_sub_result bytes for carry chain soundness
            if flags.is_compare || flags.is_branch {
                for &b in &cmp_sub_result {
                    range_bytes.push(b);
                }
            }

            // ── Phase 55b: pack the 48 individual flags into 6 bytes ──
            // The packing matches `program_memory::pack_flags` and the
            // canonical 48-flag layout in `classify_opcode_for_program_memory`.
            // Per-row byte-to-bits lookups (in cpu/mod.rs) bind individual
            // flag columns / sum-of-sub-flags expressions to these bytes.
            // ProgramMemoryChip's preprocessed FlagByte0..5 columns hold
            // the canonical packing for each PC; the prog_mem lookup
            // balance pins each FlagByteI on CpuChip to canonical.
            let canonical_flags =
                super::classify::classify_opcode_for_program_memory(step.opcode);
            let flag_bytes = crate::chips::program_memory::pack_flags(&canonical_flags);
            trace.fill_columns(row, flag_bytes[0], Column::FlagByte0);
            trace.fill_columns(row, flag_bytes[1], Column::FlagByte1);
            trace.fill_columns(row, flag_bytes[2], Column::FlagByte2);
            trace.fill_columns(row, flag_bytes[3], Column::FlagByte3);
            trace.fill_columns(row, flag_bytes[4], Column::FlagByte4);
            trace.fill_columns(row, flag_bytes[5], Column::FlagByte5);
            // 6 byte-to-bits emissions per real row, one per packed byte.
            for &fb in &flag_bytes {
                side_note.byte_to_bits_counts[fb as usize] += 1;
            }
        }

        for &b in &range_bytes {
            side_note.add_range256(b);
        }
        for &(a, b) in &bitwise_and_bytes {
            side_note.add_bitwise_and(a, b);
        }

        let last_ts = side_note.steps.last().map(|s| s.timestamp).unwrap_or(0);
        for row in num_steps..num_rows {
            let ts = last_ts + (row - num_steps + 1) as u64;
            trace.fill_columns(row, true, Column::IsPadding);
            trace.fill_columns(row, ts, Column::Timestamp);
            trace.fill_columns(row, ts + 1, Column::NextTimestamp);
        }

        trace.finalize_bit_reversed()
    }
