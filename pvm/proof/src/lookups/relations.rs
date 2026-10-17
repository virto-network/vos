use stwo::core::fields::qm31::SecureField;

use crate::core::step::WORD_SIZE;

/// `(z, alpha)` of the three boundary-binding relations, in order
/// `[register_memory, program_execution, merkle_node]`. The native-recursion
/// verifier-AIR binds each relation's challenges to its Fiat-Shamir draw squeeze
/// to recompute the boundary chips' claimed sums in-circuit. The wrapped
/// `LookupElements` field is private to this module, so this accessor lives here.
pub fn boundary_relation_challenges(
    elements: &super::AllLookupElements,
) -> [(SecureField, SecureField); 3] {
    let reg: &RegisterMemoryLookupElements = elements.as_ref();
    let prog: &ProgramExecutionLookupElements = elements.as_ref();
    let merkle: &MerkleNodeLookupElements = elements.as_ref();
    [
        (reg.0.z, reg.0.alpha),
        (prog.0.z, prog.0.alpha),
        (merkle.0.z, merkle.0.alpha),
    ]
}

/// PC is 4 bytes (u32), timestamps are 8 bytes (u64).
const PC_SIZE: usize = 4;
const TS_SIZE: usize = WORD_SIZE; // 8

// (clk, pc)
// clk is 8 bytes, PC is 4 bytes.
const REL_PROG_EXEC_LOOKUP_SIZE: usize = TS_SIZE + PC_SIZE;
stwo_constraint_framework::relation!(ProgramExecutionLookupElements, REL_PROG_EXEC_LOOKUP_SIZE);

// (reg-addr, reg-val, reg-ts, is-write)
// Address is 1 column, value is 8 bytes, timestamp is 8 bytes, is_write is 1.
// is_write binds reads vs writes so a read can't masquerade as a write to skip
// the ledger's read-consistency constraint.
const REL_REG_MEMORY_LOOKUP_SIZE: usize = 1 + WORD_SIZE + TS_SIZE + 1;
stwo_constraint_framework::relation!(RegisterMemoryLookupElements, REL_REG_MEMORY_LOOKUP_SIZE);

// (pc[4], opcode, skip_len, reg_a, reg_b, reg_d, imm[8],
//  flag_bytes[N_FLAG_BYTES], imm_y_canon[5], branch_target_canon[4],
//  host_call_precompile_dispatch)
//
// Authenticates instruction-fetch tuples: every CpuChip step emits this
// tuple, and ProgramMemoryChip's preprocessed table holds the canonical
// decoding at every basic-block-starting PC of `code`.  The tuple carries
// (pc, opcode, skip_len, regs, imm) plus category/sub-category flags so a
// prover can't clear flags to skip per-op constraints.
//
// The 80 individual flags are packed into 10 bytes
// (`flag_bytes[i] = sum_{j=0..8} 2^j * flag[8*i+j]`) on both sides of
// the lookup.  CpuChip emits 6 byte-to-bits lookups per row to bind
// each individual flag column (or its sum-of-sub-flags expression for
// the 4 folded category slots) of bytes 0..5 back to its packed byte,
// and recomposes bytes 6..9 from their bits in its own constraints.
// The prog_mem tuple is 37 limbs.
//
// Flag layout per byte (0-indexed within byte; little-endian bits):
//   byte 0: is_add, is_sub, is_mul, is_shar_r, is_bitwise, is_shift,
//           is_compare, is_move
//           (is_mul_upper is the sum of its three variants, in bytes 2
//           and 3, so it needs no bit of its own)
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
//           is_imm_alt
//   byte 6: val_b_is_reg, val_b_from_a, val_d_is_reg, result_is_reg,
//           result_to_d, is_rem, is_set_gt, is_cmov_imm
//   byte 7: is_set_lt_u, is_set_lt_s, is_cmov_iz, is_cmov_nz, is_min_s,
//           is_min_u, is_max_s, is_max_u
//   byte 8: is_br_eq, is_br_ne, is_br_lt_u, is_br_ge_u, is_br_le_u,
//           is_br_gt_u, is_br_lt_s, is_br_ge_s
//   byte 9: is_br_le_s, is_br_gt_s, is_and, is_or, is_xor, is_and_inv,
//           is_or_inv, is_xnor
/// Canonical flag count (kept as a public constant so external readers
/// — fuzz harnesses, security docs — can refer to the AIR-side count
/// regardless of the on-tuple packing.  Each FlagByteI on the prog_mem
/// tuple carries 8 of these.
pub const PROG_MEMORY_N_FLAGS: usize = 80;
pub const PROG_MEMORY_N_FLAG_BYTES: usize = PROG_MEMORY_N_FLAGS / 8;
// Tuple shape: pc[4] + opcode + skip_len + reg_a + reg_b + reg_d + imm[8]
//   + 10 packed flag bytes + imm_y_canon[5] + branch_target_canon[4]
//   + host_call_precompile_dispatch = 37 limbs.
const REL_PROG_MEMORY_LOOKUP_SIZE: usize =
    PC_SIZE + 1 + 1 + 1 + 1 + 1 + WORD_SIZE + PROG_MEMORY_N_FLAG_BYTES + 5 + PC_SIZE + 1;
stwo_constraint_framework::relation!(ProgramMemoryLookupElements, REL_PROG_MEMORY_LOOKUP_SIZE);

// JumpTableChip lookup. Tuple: (addr[4], target[4]) — 8 limbs.
// Pins runtime indirect jump targets: CpuChip emits (val_b+imm, next_pc) per
// JumpInd row; JumpTableChip's preprocessed table holds the canonical
// (addr=2*(idx+1), target=jump_table[idx]) for each entry.
const REL_JUMP_TABLE_LOOKUP_SIZE: usize = PC_SIZE + PC_SIZE;
stwo_constraint_framework::relation!(JumpTableLookupElements, REL_JUMP_TABLE_LOOKUP_SIZE);

// Byte-level: (addr[4], value[1], timestamp[8], is_write[1], is_closing[1]).
// is_closing distinguishes the §2 per-page closing read (emitted only by
// MemoryPageChip) from every other entry (which emit 0), so MemoryChip's
// group-end constraint can require each address group to end on a closing row.
const REL_MEMORY_ACCESS_LOOKUP_SIZE: usize = PC_SIZE + 1 + TS_SIZE + 1 + 1;
stwo_constraint_framework::relation!(MemoryAccessLookupElements, REL_MEMORY_ACCESS_LOOKUP_SIZE);

// (shift_amount[1], power_val[8]) — proves val_d = 2^shift_amount
const REL_POWER_OF_TWO_LOOKUP_SIZE: usize = 1 + WORD_SIZE;
stwo_constraint_framework::relation!(PowerOfTwoLookupElements, REL_POWER_OF_TWO_LOOKUP_SIZE);

// (a, b, a_and_b) — per-nibble bitwise AND lookup (16×16 BitwiseLookupChip;
// CpuChip + ALU BitwiseChip consumers).
const REL_BITWISE_AND_LOOKUP_SIZE: usize = 3;
stwo_constraint_framework::relation!(BitwiseAndLookupElements, REL_BITWISE_AND_LOOKUP_SIZE);

// (a, b, a_and_b) — per-BYTE bitwise AND lookup against the 2^16-row
// BitwiseAndByteChip.  Same tuple shape as the nibble relation but a distinct
// type so the two tables don't collide: the blake2b chips consume this one
// (one emission per byte AND, halving their AND lookup count), and byte-ness
// of a/b comes free from table membership.
const REL_BITWISE_AND_BYTE_LOOKUP_SIZE: usize = 3;
stwo_constraint_framework::relation!(
    BitwiseAndByteLookupElements,
    REL_BITWISE_AND_BYTE_LOOKUP_SIZE
);

// (byte, popcount) — per-byte popcount lookup
const REL_POPCOUNT_LOOKUP_SIZE: usize = 2;
stwo_constraint_framework::relation!(PopcountLookupElements, REL_POPCOUNT_LOOKUP_SIZE);

// (byte, lz_byte, tz_byte) — per-byte leading/trailing-zeros lookup
const REL_BITCOUNT_LOOKUP_SIZE: usize = 3;
stwo_constraint_framework::relation!(BitcountLookupElements, REL_BITCOUNT_LOOKUP_SIZE);

// DivRem lookup.  CpuChip emits one producer
// per `is_div_rem` row; DivRemChip consumes once per real (non-
// padding) row.  Tuple binds the per-row inputs to DivRemChip's
// schoolbook + r<d uniqueness + DivS sign-correction chains.
//
// Tuple: (val_b[8], val_d[8], div_quotient[8], div_remainder[8],
//   sign_bit_b, sign_bit_d, sign_bit_q, sign_bit_r,
//   is_div_rem, div_by_zero, is_32bit, is_div_s, is_shar_r) — 41 limbs.
//
// The tuple omits div_corr_hi[8]: DivCorrHi is DivRemChip-internal,
// pinned by the schoolbook and by the operation (zero, or the signed
// correction).  SignBitB/D/Q/R, is_div_s and is_shar_r select the
// operation: unsigned division and logical shift, signed division, or
// an arithmetic shift's floor division.
const REL_DIVREM_LOOKUP_SIZE: usize = WORD_SIZE * 4 + 9;
stwo_constraint_framework::relation!(DivRemLookupElements, REL_DIVREM_LOOKUP_SIZE);

// Compare lookup.  CpuChip emits one producer per
// `is_compare + is_branch` row; CompareChip consumes once per real
// (non-padding) row.  Tuple binds val_b/val_d/cmp_lt_flag so
// CompareChip's AIR can re-prove the unsigned-LT result over its
// narrower trace via the byte-wise subtraction carry chain.
//
// Tuple: (val_b[8], val_d[8], cmp_lt_flag) — 17 limbs.
const REL_COMPARE_LOOKUP_SIZE: usize = WORD_SIZE * 2 + 1;
stwo_constraint_framework::relation!(CompareLookupElements, REL_COMPARE_LOOKUP_SIZE);

// Bitwise lookup.  CpuChip emits one producer per
// `is_bitwise` row (sum of 6 sub-flags); BitwiseChip consumes once
// per real (non-padding) row.  Tuple binds val_b/val_d/result + 6
// sub-flags so BitwiseChip's AIR can prove the per-op result-binding
// identities (AND/OR/XOR/AndInv/OrInv/Xnor) over its narrower trace.
//
// Tuple: (val_b[8], val_d[8], result[8], is_and, is_or, is_xor,
//   is_and_inv, is_or_inv, is_xnor) — 30 limbs.
const REL_BITWISE_LOOKUP_SIZE: usize = WORD_SIZE * 3 + 6;
stwo_constraint_framework::relation!(BitwiseLookupElements, REL_BITWISE_LOOKUP_SIZE);

// Multiplication lookup.  CpuChip emits one producer
// per `is_mul + is_mul_upper_uu + is_mul_upper_su + is_mul_upper_ss`
// row; MulChip consumes once per real (non-padding) row.  Tuple binds
// the per-row mul I/O state so MulChip's AIR proves the schoolbook
// + sign-correction + result-variant dispatch over its narrower trace.
//
// Tuple: (val_b[8], val_d[8], result[8], sign_bit_b,
//   sign_bit_d, is_rotate_l64, is_rotate_r64, is_rotate_l32,
//   is_rotate_r32, is_mul_lo, is_mul_upper_uu, is_mul_upper_su,
//   is_mul_upper_ss, is_32bit) — 35 limbs.
//
// The tuple omits mul_high[8] and unsigned_product_low[8] (MulChip
// witnesses both internally; result-variant binding lives in MulChip).
// The 4 rotate flags let MulChip's variant-dispatch constraint fire
// correctly per row.
const REL_MULTIPLICATION_LOOKUP_SIZE: usize = WORD_SIZE * 3 + 11;
stwo_constraint_framework::relation!(MultiplicationLookupElements, REL_MULTIPLICATION_LOOKUP_SIZE);

// ByteToBits lookup.  256-row preprocessed table proving
// `(byte, bit0, bit1, bit2, bit3, bit4, bit5, bit6, bit7)` where
// `byte = sum_{i=0..8} 2^i * bit_i`.  This table binds CpuChip's
// individual flag columns to the 6 packed flag bytes that flow
// through the prog_mem tuple.
//
// Tuple: (byte, bit0..bit7) — 9 limbs.
const REL_BYTE_TO_BITS_LOOKUP_SIZE: usize = 1 + 8;
stwo_constraint_framework::relation!(ByteToBitsLookupElements, REL_BYTE_TO_BITS_LOOKUP_SIZE);

// (h_ptr[4], m_ptr[4], t_low[8], f[1], ts[8]) — binds Blake2bChip's HPtr,
// MPtr, T[0..8], F and CallTs to CpuChip's ECALL-step register snapshot +
// timestamp so the precompile can't fabricate the pointer / counter /
// finalise-flag triple.  CpuChip emits 1 producer per blake2b ECALL step,
// Blake2bChip emits 1 consumer per compression.
const REL_BLAKE2B_CALL_LOOKUP_SIZE: usize = 4 + 4 + WORD_SIZE + 1 + TS_SIZE;
stwo_constraint_framework::relation!(Blake2bCallLookupElements, REL_BLAKE2B_CALL_LOOKUP_SIZE);

// (ts[8], destination[4], count[1]) — one tuple per witness-input call that
// wrote bytes.  CpuChip produces it twice from the call's row (its timestamp,
// φ[7]'s low four bytes, and the count it writes to φ[7], below 2^24);
// WitnessInputChip consumes it twice at the call's first byte row, which
// starts the chain of `count` rows writing consecutive addresses from the
// destination at that timestamp.
const REL_WITNESS_CALL_LOOKUP_SIZE: usize = TS_SIZE + 4 + 1;
stwo_constraint_framework::relation!(WitnessCallLookupElements, REL_WITNESS_CALL_LOOKUP_SIZE);

// (h_in[64], m[128], t[8], f[1], h_out[64]) — one tuple per blake2b
// compression of the in-AIR memory-page Merkle boundary multiproof, bound
// WITHOUT a memory-ledger / CPU-call binding.  Blake2bBoundaryChip PRODUCES
// one per compression at its row-95 output; MemoryPageChip (leaf h-chain)
// and MemoryMerkleChip (node hashes) CONSUME them (step 5).
const REL_BLAKE2B_COMPRESSION_LOOKUP_SIZE: usize = 64 + 128 + 8 + 1 + 64;
stwo_constraint_framework::relation!(
    Blake2bCompressionLookupElements,
    REL_BLAKE2B_COMPRESSION_LOOKUP_SIZE
);

// (level[1], index[1], hash_before[32], hash_after[32]) — one tuple per node
// of the in-AIR memory-page Merkle trie (design §1).  `index` is a SINGLE M31
// limb (2^DEPTH − 1 < p), NOT byte limbs — logup tuples match per-limb and a
// byte-limbed index would break the degree-1 child doubling on merge rows.
// MemoryPageChip PRODUCES one leaf tuple `(DEPTH, page_idx, leaf_before,
// leaf_after)` per listed page; MemoryMerkleChip CONSUMES two children and
// PRODUCES the parent per merge row; MemoryRootBoundaryChip CONSUMES exactly
// one root tuple `(0, 0, initial_root, final_root)`.  Logup balance over this
// relation is what enforces the trie schedule.
const REL_MERKLE_NODE_LOOKUP_SIZE: usize = 1 + 1 + 32 + 32;
stwo_constraint_framework::relation!(MerkleNodeLookupElements, REL_MERKLE_NODE_LOOKUP_SIZE);
