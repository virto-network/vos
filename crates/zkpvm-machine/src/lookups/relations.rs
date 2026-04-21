use zkpvm_core::step::WORD_SIZE;

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

// (pc, opcode, skip_len)
const REL_PROG_MEMORY_LOOKUP_SIZE: usize = PC_SIZE + 2;
stwo_constraint_framework::relation!(
    ProgramMemoryLookupElements,
    REL_PROG_MEMORY_LOOKUP_SIZE
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
