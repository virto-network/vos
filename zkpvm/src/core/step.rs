#[cfg(feature = "prover")]
use javm::instruction::Opcode;

/// Number of PVM registers: 13, φ0..φ12 (Gray Paper Appendix A / §I.4.4).
///
/// Defined locally so the verifier-only build (no `prover` feature) does not
/// pull `javm` — the register count is a protocol constant, not an
/// implementation detail of the interpreter.  The prover build cross-checks
/// it against the reference interpreter below.
pub const PVM_REGISTER_COUNT: usize = 13;

// Prover builds carry the javm reference interpreter; assert at compile time
// that our local protocol constant agrees with it so the two can never drift.
#[cfg(feature = "prover")]
const _: () = assert!(PVM_REGISTER_COUNT == javm::PVM_REGISTER_COUNT);

/// Number of PVM registers.
pub const NUM_REGS: usize = PVM_REGISTER_COUNT;
/// 64-bit values decomposed as 8 × 8-bit limbs.
pub const WORD_SIZE: usize = 8;

/// A single PVM execution step witness, capturing the full state transition.
///
/// Prover-only: step witnesses exist to fill traces; the standalone verifier
/// never sees one (and the `Opcode` field type lives in prover-only `javm`).
#[cfg(feature = "prover")]
#[derive(Clone, Debug, PartialEq)]
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
    /// Second immediate for `LoadImmJumpInd`
    /// (TwoRegTwoImm category) — the jump-offset side.  `imm` holds the
    /// load-value `imm_x`; this holds the jump-offset `imm_y`.  Default 0
    /// for opcodes without a second immediate.
    pub imm_y: u64,
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
#[derive(Clone, Debug, PartialEq)]
pub struct MemAccess {
    pub address: u32,
    pub value: u64,
    pub size: u8,
}

/// The one register write a step performed: file index + written value.
/// A PVM instruction writes at most one register (every interpreter opcode
/// arm is a single `registers[x] = …` assignment), so this pair is the
/// entire register-file delta of a step — `None` when the step left the
/// file unchanged (including a write of the value already held, which is
/// unobservable and recorded as no write, matching [`PvmStep::reg_write`]).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RegWrite {
    pub index: u8,
    pub value: u64,
}

/// A [`PvmStep`] without the two register-file snapshots — the chain-side
/// step form. The snapshots are ~208 of a full step's ~360 bytes and are
/// redundant across a trace: `regs_before` of step k+1 equals `regs_after`
/// of step k (the tracer's continuity invariant — nothing mutates registers
/// between steps), and within a step only [`Self::reg_write`] changes the
/// file. A window's full steps are rebuilt by [`expand_steps`] from the
/// register file entering the window, so the chips keep consuming
/// [`PvmStep`] unchanged while a multi-million-step chain holds ~2.6× less.
#[cfg(feature = "prover")]
#[derive(Clone, Debug, PartialEq)]
pub struct CompactStep {
    /// Monotonic timestamp (step index).
    pub timestamp: u64,
    /// Program counter before this instruction.
    pub pc: u32,
    /// Opcode byte.
    pub opcode: Opcode,
    /// Skip length (ℓ) — distance to next instruction byte.
    pub skip_len: u32,
    /// The step's register-file delta (see [`RegWrite`]).
    pub reg_write: Option<RegWrite>,
    /// Decoded register indices (from bytecode). For three-reg: ra, rb, rd.
    pub reg_a: u8,
    pub reg_b: u8,
    pub reg_d: u8,
    /// Decoded immediate value (sign-extended, for imm-category ops).
    pub imm: u64,
    /// Second immediate for `LoadImmJumpInd` (see [`PvmStep::imm_y`]).
    pub imm_y: u64,
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

#[cfg(feature = "prover")]
impl CompactStep {
    /// Rebuild the full step from the register file entering it:
    /// `regs_after` is `regs_before` with [`Self::reg_write`] applied.
    pub fn expand(&self, regs_before: [u64; NUM_REGS]) -> PvmStep {
        let mut regs_after = regs_before;
        let reg_write = self.reg_write.map(|w| {
            regs_after[w.index as usize] = w.value;
            w.index as usize
        });
        PvmStep {
            timestamp: self.timestamp,
            pc: self.pc,
            opcode: self.opcode,
            skip_len: self.skip_len,
            regs_before,
            regs_after,
            reg_write,
            reg_a: self.reg_a as usize,
            reg_b: self.reg_b as usize,
            reg_d: self.reg_d as usize,
            imm: self.imm,
            imm_y: self.imm_y,
            branch_target: self.branch_target,
            branch_taken: self.branch_taken,
            mem_read: self.mem_read.clone(),
            mem_write: self.mem_write.clone(),
            gas_after: self.gas_after,
            gas_charged: self.gas_charged,
            next_pc: self.next_pc,
            exit: self.exit,
        }
    }
}

#[cfg(feature = "prover")]
impl PvmStep {
    /// The compact form of this step. Panics if the snapshots' delta is not
    /// representable — `regs_after` differing from `regs_before` anywhere
    /// other than `reg_write` — which the tracer never records (one
    /// interpreter step writes at most one register); only hand-edited
    /// snapshots can trip it.
    pub fn to_compact(&self) -> CompactStep {
        for i in 0..NUM_REGS {
            let changed = self.regs_before[i] != self.regs_after[i];
            assert!(
                !changed || self.reg_write == Some(i),
                "step at ts {}: register {i} changed outside reg_write {:?} — \
                 not representable as a compact step",
                self.timestamp,
                self.reg_write,
            );
        }
        CompactStep {
            timestamp: self.timestamp,
            pc: self.pc,
            opcode: self.opcode,
            skip_len: self.skip_len,
            reg_write: self.reg_write.map(|i| RegWrite {
                index: i as u8,
                value: self.regs_after[i],
            }),
            reg_a: self.reg_a as u8,
            reg_b: self.reg_b as u8,
            reg_d: self.reg_d as u8,
            imm: self.imm,
            imm_y: self.imm_y,
            branch_target: self.branch_target,
            branch_taken: self.branch_taken,
            mem_read: self.mem_read.clone(),
            mem_write: self.mem_write.clone(),
            gas_after: self.gas_after,
            gas_charged: self.gas_charged,
            next_pc: self.next_pc,
            exit: self.exit,
        }
    }
}

/// Expand a run of compact steps into full steps, threading the register
/// file forward from `entering_regs`: `regs_before` of each step is
/// `regs_after` of the previous (the tracer's continuity invariant).
#[cfg(feature = "prover")]
pub fn expand_steps(
    steps: &[CompactStep],
    entering_regs: [u64; NUM_REGS],
) -> alloc::vec::Vec<PvmStep> {
    let mut regs = entering_regs;
    steps
        .iter()
        .map(|c| {
            let s = c.expand(regs);
            regs = s.regs_after;
            s
        })
        .collect()
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;

    fn sample(ts: u64, regs_before: [u64; NUM_REGS], reg_write: Option<usize>) -> PvmStep {
        let mut regs_after = regs_before;
        if let Some(i) = reg_write {
            regs_after[i] = 0xF00 + ts;
        }
        PvmStep {
            timestamp: ts,
            pc: ts as u32 * 3,
            opcode: Opcode::Add64,
            skip_len: 3,
            regs_before,
            regs_after,
            reg_write,
            reg_a: 1,
            reg_b: 2,
            reg_d: 3,
            imm: 7,
            imm_y: 9,
            branch_target: 0x40,
            branch_taken: ts % 2 == 0,
            mem_read: (ts % 3 == 0).then(|| MemAccess {
                address: 0x100,
                value: 5,
                size: 4,
            }),
            mem_write: (ts % 3 == 1).then(|| MemAccess {
                address: 0x200,
                value: 6,
                size: 8,
            }),
            gas_after: 1000 - ts,
            gas_charged: u64::from(ts == 1),
            next_pc: ts as u32 * 3 + 4,
            exit: false,
        }
    }

    /// Round trip across a run: compact then expand with threaded
    /// registers reproduces every field, covering a write, a no-write
    /// step, and a write to the same register again.
    #[test]
    fn compact_round_trips_a_threaded_run() {
        let mut regs = [0u64; NUM_REGS];
        regs[1] = 42;
        let mut steps = alloc::vec::Vec::new();
        for (ts, w) in [(1, Some(4)), (2, None), (3, Some(4)), (4, Some(7))] {
            let s = sample(ts, regs, w);
            regs = s.regs_after;
            steps.push(s);
        }
        let compact: alloc::vec::Vec<CompactStep> = steps.iter().map(|s| s.to_compact()).collect();
        assert_eq!(expand_steps(&compact, steps[0].regs_before), steps);
    }

    /// The point of the exercise: a compact step drops the two register
    /// snapshots (~208 B), better than halving the per-step footprint.
    #[test]
    fn compact_step_is_less_than_half_a_full_step() {
        assert!(
            core::mem::size_of::<CompactStep>() * 2 < core::mem::size_of::<PvmStep>(),
            "CompactStep {} B vs PvmStep {} B",
            core::mem::size_of::<CompactStep>(),
            core::mem::size_of::<PvmStep>(),
        );
    }

    /// A hand-built step whose snapshots disagree beyond `reg_write` is
    /// not representable and must fail loudly, not silently drop a delta.
    #[test]
    #[should_panic(expected = "not representable")]
    fn to_compact_rejects_multi_register_deltas() {
        let mut s = sample(1, [0u64; NUM_REGS], Some(4));
        s.regs_after[5] = 99; // second delta outside reg_write
        let _ = s.to_compact();
    }
}
