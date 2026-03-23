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
// PC is 4 bytes, opcode is 1, skip_len is 1.
const REL_PROG_MEMORY_LOOKUP_SIZE: usize = PC_SIZE + 2;
stwo_constraint_framework::relation!(
    ProgramMemoryLookupElements,
    REL_PROG_MEMORY_LOOKUP_SIZE
);
