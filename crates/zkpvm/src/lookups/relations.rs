use crate::core::step::WORD_SIZE;

/// PC is 4 bytes (u32), timestamps are 8 bytes (u64).
const PC_SIZE: usize = 4;
const TS_SIZE: usize = WORD_SIZE; // 8

// (clk, pc)
// clk is 8 bytes, PC is 4 bytes.
const REL_PROG_EXEC_LOOKUP_SIZE: usize = TS_SIZE + PC_SIZE;
stwo_constraint_framework::relation!(
    ProgramExecutionLookupElements,
    REL_PROG_EXEC_LOOKUP_SIZE
);

// (reg-addr, reg-val, reg-ts)
// Address is 1 column, value is 8 bytes, timestamp is 8 bytes.
const REL_REG_MEMORY_LOOKUP_SIZE: usize = 1 + WORD_SIZE + TS_SIZE;
stwo_constraint_framework::relation!(
    RegisterMemoryLookupElements,
    REL_REG_MEMORY_LOOKUP_SIZE
);

// (pc[4], opcode, skip_len, reg_a, reg_b, reg_d, imm[8],
//  flag_bytes[N_FLAG_BYTES], imm_y_canon[4], branch_target_canon[4])
//
// Authenticates instruction-fetch tuples: every CpuChip step emits this
// tuple, and ProgramMemoryChip's preprocessed table holds the canonical
// decoding at every basic-block-starting PC of `code`.  Phase 13a defined
// the chip; 13b wired the (pc, opcode, skip_len, regs, imm) consumer; 13c
// extended the tuple with category/sub-category flags so a prover can't
// clear flags to skip per-op constraints.
//
// Phase 55b: the 48 individual flag columns were packed into 6 bytes
// (`flag_bytes[i] = sum_{j=0..8} 2^j * flag[8*i+j]`) on both sides of
// the lookup.  CpuChip emits 6 byte-to-bits lookups per row to bind
// each individual flag column (or its sum-of-sub-flags expression for
// the 5 folded category slots) back to its packed byte.  The prog_mem
// tuple shrinks from 73 → 31 limbs.
//
// Flag layout per byte (0-indexed within byte; little-endian bits):
//   byte 0: is_add, is_sub, is_mul, is_mul_upper, is_bitwise, is_shift,
//           is_compare, is_move
//   byte 1: is_32bit, is_branch, is_jump, is_div_rem, is_load, is_store,
//           is_exit, is_neg_add
//   byte 2: is_reverse_bytes, is_zero_ext_16, is_sign_ext_8,
//           is_sign_ext_16, is_trap, is_jump_ind, is_load_imm_jump_ind,
//           is_mul_upper_uu
//   byte 3: is_mul_upper_su, is_mul_upper_ss, is_div_s, is_load_i8,
//           is_load_i16, is_load_i32, is_mem_size_1, is_mem_size_2
//   byte 4: is_mem_size_4, is_mem_size_8, is_store_direct, is_load_direct,
//           is_mem_indirect, is_store_imm_any, is_store_imm_direct,
//           is_store_ind
//   byte 5: is_rotate_l64, is_count_set_bits, is_lzb, is_tzb,
//           is_rotate_r64, is_rotate_l32, is_rotate_r32,
//           is_rotate_r_imm_alt
/// Canonical flag count (kept as a public constant so external readers
/// — fuzz harnesses, security docs — can refer to the AIR-side count
/// regardless of the on-tuple packing.  Each FlagByteI on the prog_mem
/// tuple carries 8 of these.
pub const PROG_MEMORY_N_FLAGS: usize = 48;
pub const PROG_MEMORY_N_FLAG_BYTES: usize = PROG_MEMORY_N_FLAGS / 8;
// Tuple shape: pc[4] + opcode + skip_len + reg_a + reg_b + reg_d + imm[8]
//   + 6 packed flag bytes + imm_y_canon[4] + branch_target_canon[4] = 31 limbs.
const REL_PROG_MEMORY_LOOKUP_SIZE: usize =
    PC_SIZE + 1 + 1 + 1 + 1 + 1 + WORD_SIZE + PROG_MEMORY_N_FLAG_BYTES + PC_SIZE + PC_SIZE;
stwo_constraint_framework::relation!(
    ProgramMemoryLookupElements,
    REL_PROG_MEMORY_LOOKUP_SIZE
);

// Phase 13d: JumpTableChip lookup. Tuple: (addr[4], target[4]) — 8 limbs.
// Pins runtime indirect jump targets: CpuChip emits (val_b+imm, next_pc) per
// JumpInd row; JumpTableChip's preprocessed table holds the canonical
// (addr=2*(idx+1), target=jump_table[idx]) for each entry.
const REL_JUMP_TABLE_LOOKUP_SIZE: usize = PC_SIZE + PC_SIZE;
stwo_constraint_framework::relation!(
    JumpTableLookupElements,
    REL_JUMP_TABLE_LOOKUP_SIZE
);

// Byte-level: (addr[4], value[1], timestamp[8], is_write[1])
const REL_MEMORY_ACCESS_LOOKUP_SIZE: usize = PC_SIZE + 1 + TS_SIZE + 1;
stwo_constraint_framework::relation!(
    MemoryAccessLookupElements,
    REL_MEMORY_ACCESS_LOOKUP_SIZE
);

// (shift_amount[1], power_val[8]) — proves val_d = 2^shift_amount
const REL_POWER_OF_TWO_LOOKUP_SIZE: usize = 1 + WORD_SIZE;
stwo_constraint_framework::relation!(
    PowerOfTwoLookupElements,
    REL_POWER_OF_TWO_LOOKUP_SIZE
);

// (a, b, a_and_b) — per-byte bitwise AND lookup
const REL_BITWISE_AND_LOOKUP_SIZE: usize = 3;
stwo_constraint_framework::relation!(
    BitwiseAndLookupElements,
    REL_BITWISE_AND_LOOKUP_SIZE
);

// (byte, popcount) — per-byte popcount lookup (Phase 33)
const REL_POPCOUNT_LOOKUP_SIZE: usize = 2;
stwo_constraint_framework::relation!(
    PopcountLookupElements,
    REL_POPCOUNT_LOOKUP_SIZE
);

// (byte, lz_byte, tz_byte) — per-byte leading/trailing-zeros lookup (Phase 34)
const REL_BITCOUNT_LOOKUP_SIZE: usize = 3;
stwo_constraint_framework::relation!(
    BitcountLookupElements,
    REL_BITCOUNT_LOOKUP_SIZE
);

// (cid[4], slot[1], value[8]) — Blake2b state lookup between boundary chip
// and main Blake2b chip for initial-state + final-state authentication.
const REL_BLAKE2B_STATE_LOOKUP_SIZE: usize = 4 + 1 + WORD_SIZE;
stwo_constraint_framework::relation!(
    Blake2bStateLookupElements,
    REL_BLAKE2B_STATE_LOOKUP_SIZE
);

// Phase 54g — DivRem lookup.  CpuChip emits one producer per
// `is_div_rem` row; DivRemChip consumes once per real (non-padding)
// row.  Tuple binds val_b/val_d/div_quotient/div_remainder/div_corr_hi
// + is_div_rem/div_by_zero/is_32bit so DivRemChip's AIR can re-prove
// the schoolbook identity (q·d + r = b mod 2^128) via the byte-wise
// carry chain over its narrower trace.
//
// Tuple: (val_b[8], val_d[8], div_quotient[8], div_remainder[8],
//   div_corr_hi[8], is_div_rem, div_by_zero, is_32bit) — 43 limbs.
const REL_DIVREM_LOOKUP_SIZE: usize = WORD_SIZE * 5 + 3;
stwo_constraint_framework::relation!(
    DivRemLookupElements,
    REL_DIVREM_LOOKUP_SIZE
);

// Phase 54f — Compare lookup.  CpuChip emits one producer per
// `is_compare + is_branch` row; CompareChip consumes once per real
// (non-padding) row.  Tuple binds val_b/val_d/cmp_lt_flag so
// CompareChip's AIR can re-prove the unsigned-LT result over its
// narrower trace via the byte-wise subtraction carry chain.
//
// Tuple: (val_b[8], val_d[8], cmp_lt_flag) — 17 limbs.
const REL_COMPARE_LOOKUP_SIZE: usize = WORD_SIZE * 2 + 1;
stwo_constraint_framework::relation!(
    CompareLookupElements,
    REL_COMPARE_LOOKUP_SIZE
);

// Phase 54e — Bitwise lookup.  CpuChip emits one producer per
// `is_bitwise` row (sum of 6 sub-flags); BitwiseChip consumes once
// per real (non-padding) row.  Tuple binds val_b/val_d/result + 6
// sub-flags so BitwiseChip's AIR can prove the per-op result-binding
// identities (AND/OR/XOR/AndInv/OrInv/Xnor) over its narrower trace.
//
// Tuple: (val_b[8], val_d[8], result[8], is_and, is_or, is_xor,
//   is_and_inv, is_or_inv, is_xnor) — 30 limbs.
const REL_BITWISE_LOOKUP_SIZE: usize = WORD_SIZE * 3 + 6;
stwo_constraint_framework::relation!(
    BitwiseLookupElements,
    REL_BITWISE_LOOKUP_SIZE
);

// Phase 54a/b/c/d — Multiplication lookup.  CpuChip emits one producer
// per `is_mul + is_mul_upper_uu + is_mul_upper_su + is_mul_upper_ss`
// row; MulChip consumes once per real (non-padding) row.  Tuple binds
// the per-row mul I/O state so MulChip's AIR proves the schoolbook
// + sign-correction + result-variant dispatch over its narrower trace.
//
// Tuple (Phase 54d): (val_b[8], val_d[8], result[8], sign_bit_b,
//   sign_bit_d, is_rotate_l64, is_rotate_r64, is_rotate_l32,
//   is_rotate_r32, is_mul_lo, is_mul_upper_uu, is_mul_upper_su,
//   is_mul_upper_ss, is_32bit) — 35 limbs.
//
// vs Phase 54c: dropped mul_high[8] + unsigned_product_low[8]
// (MulChip witnesses both internally; result variant binding moved
// to MulChip).  Added 4 rotate flags so MulChip's variant-dispatch
// constraint can fire correctly per row.
const REL_MULTIPLICATION_LOOKUP_SIZE: usize =
    WORD_SIZE * 3 + 11;
stwo_constraint_framework::relation!(
    MultiplicationLookupElements,
    REL_MULTIPLICATION_LOOKUP_SIZE
);

// Phase 55a — ByteToBits lookup.  256-row preprocessed table proving
// `(byte, bit0, bit1, bit2, bit3, bit4, bit5, bit6, bit7)` where
// `byte = sum_{i=0..8} 2^i * bit_i`.  Phase 55b uses this table to
// bind CpuChip's individual flag columns to the 6 packed flag bytes
// that flow through the prog_mem tuple.
//
// Tuple: (byte, bit0..bit7) — 9 limbs.
const REL_BYTE_TO_BITS_LOOKUP_SIZE: usize = 1 + 8;
stwo_constraint_framework::relation!(
    ByteToBitsLookupElements,
    REL_BYTE_TO_BITS_LOOKUP_SIZE
);

// (h_ptr[4], m_ptr[4], t_low[8], f[1], ts[8]) — binds Blake2bChip's HPtr,
// MPtr, T[0..8], F and CallTs to CpuChip's ECALL-step register snapshot +
// timestamp so the precompile can't fabricate the pointer / counter /
// finalise-flag triple.  CpuChip emits 1 producer per blake2b ECALL step,
// Blake2bChip emits 1 consumer per compression.
const REL_BLAKE2B_CALL_LOOKUP_SIZE: usize = 4 + 4 + WORD_SIZE + 1 + TS_SIZE;
stwo_constraint_framework::relation!(
    Blake2bCallLookupElements,
    REL_BLAKE2B_CALL_LOOKUP_SIZE
);
