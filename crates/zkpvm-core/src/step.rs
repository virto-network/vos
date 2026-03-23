use javm::instruction::Opcode;
use javm::PVM_REGISTER_COUNT;

/// Number of PVM registers.
pub const NUM_REGS: usize = PVM_REGISTER_COUNT;
/// 64-bit values decomposed as 8 × 8-bit limbs.
pub const WORD_SIZE: usize = 8;

/// A single PVM execution step witness, capturing the full state transition.
#[derive(Clone, Debug)]
pub struct PvmStep {
    /// Monotonic timestamp (step index).
    pub timestamp: u64,
    /// Program counter before this instruction.
    pub pc: u32,
    /// Opcode byte.
    pub opcode: Opcode,
    /// Skip length (ℓ) — distance to next instruction byte.
    pub skip_len: u32,
    /// Register state before execution.
    pub regs_before: [u64; NUM_REGS],
    /// Register state after execution.
    pub regs_after: [u64; NUM_REGS],
    /// Which register was written (None if no register write).
    pub reg_write: Option<usize>,
    /// Decoded register indices (from bytecode). For three-reg: ra, rb, rd.
    pub reg_a: usize,
    pub reg_b: usize,
    pub reg_d: usize,
    /// Decoded immediate value (sign-extended, for imm-category ops).
    pub imm: u64,
    /// Branch/jump target address (decoded from offset). 0 for non-branch ops.
    pub branch_target: u32,
    /// Whether a branch was taken.
    pub branch_taken: bool,
    /// Memory read: (address, value, size_bytes). None if no memory read.
    pub mem_read: Option<MemAccess>,
    /// Memory write: (address, value, size_bytes). None if no memory write.
    pub mem_write: Option<MemAccess>,
    /// Gas remaining after this step.
    pub gas_after: u64,
    /// Gas charged at this step (non-zero only at basic block start).
    pub gas_charged: u64,
    /// Program counter after execution.
    pub next_pc: u32,
    /// Whether this step caused an exit.
    pub exit: bool,
}

/// A memory access record.
#[derive(Clone, Debug)]
pub struct MemAccess {
    pub address: u32,
    pub value: u64,
    pub size: u8,
}
