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
//  flags[N_FLAGS])  — N_FLAGS = 20 category + sub-category booleans.
//
// Authenticates instruction-fetch tuples: every CpuChip step emits this
// tuple, and ProgramMemoryChip's preprocessed table holds the canonical
// decoding at every basic-block-starting PC of `code`.  Phase 13a defined
// the chip; 13b wired the (pc, opcode, skip_len, regs, imm) consumer; 13c
// extends the tuple with the category/sub-category flags so a prover
// can't clear flags to skip per-op constraints — flag values are now
// pinned to the canonical classify_opcode(opcode) decoding.
//
// Flag layout in the tuple, in order (Phase 13c → 12c):
//   is_add, is_sub, is_mul, is_mul_upper, is_bitwise, is_shift, is_compare,
//   is_move, is_32bit, is_branch, is_jump, is_div_rem, is_load, is_store,
//   is_exit, is_neg_add, is_reverse_bytes, is_zero_ext_16, is_sign_ext_8,
//   is_sign_ext_16, is_trap, is_jump_ind, is_load_imm_jump_ind,
//   is_mul_upper_uu, is_mul_upper_su, is_mul_upper_ss
pub const PROG_MEMORY_N_FLAGS: usize = 26;
// Tuple shape: pc[4] + opcode + skip_len + reg_a + reg_b + reg_d + imm[8]
//   + 23 flags + imm_y_canon[4] + branch_target_canon[4] = 48 limbs.
//   imm_y_canon added in 13d-loadimmjumpind for LoadImmJumpInd's
//   second-immediate (jump-offset) binding.
const REL_PROG_MEMORY_LOOKUP_SIZE: usize =
    PC_SIZE + 1 + 1 + 1 + 1 + 1 + WORD_SIZE + PROG_MEMORY_N_FLAGS + PC_SIZE + PC_SIZE;
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

// (cid[4], slot[1], value[8]) — Blake2b state lookup between boundary chip
// and main Blake2b chip for initial-state + final-state authentication.
const REL_BLAKE2B_STATE_LOOKUP_SIZE: usize = 4 + 1 + WORD_SIZE;
stwo_constraint_framework::relation!(
    Blake2bStateLookupElements,
    REL_BLAKE2B_STATE_LOOKUP_SIZE
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
