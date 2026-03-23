use javm::args;
use javm::instruction::Opcode;
use javm::vm::{ExitReason, Pvm};
use javm::PVM_REGISTER_COUNT;

use crate::step::PvmStep;

/// A tracing wrapper around javm's Pvm that records a full execution trace.
pub struct TracingPvm {
    pub pvm: Pvm,
    pub steps: Vec<PvmStep>,
    timestamp: u64,
}

impl TracingPvm {
    pub fn new(pvm: Pvm) -> Self {
        Self {
            pvm,
            steps: Vec::new(),
            timestamp: 0,
        }
    }

    /// Execute a single step, recording the witness.
    pub fn step(&mut self) -> Option<ExitReason> {
        let pc_before = self.pvm.pc;
        let regs_before = self.pvm.registers;
        let gas_before = self.pvm.gas;
        let need_gas_charge = self.pvm.need_gas_charge;

        // Decode opcode and args BEFORE stepping
        let opcode_byte = if (pc_before as usize) < self.pvm.code.len() {
            self.pvm.code[pc_before as usize]
        } else {
            0
        };
        let opcode = Opcode::from_byte(opcode_byte).unwrap_or(Opcode::Trap);
        let skip_len = compute_skip(&self.pvm.bitmask, pc_before as usize);
        let category = opcode.category();
        let decoded_args = args::decode_args(&self.pvm.code, pc_before as usize, skip_len as usize, category);

        // Decode register indices from args
        let (reg_a, reg_b, reg_d) = decode_reg_indices(opcode, &decoded_args);

        let result = self.pvm.step();

        let regs_after = self.pvm.registers;
        let gas_after = self.pvm.gas;
        let next_pc = self.pvm.pc;

        let reg_write = (0..PVM_REGISTER_COUNT)
            .find(|&i| regs_before[i] != regs_after[i]);

        let gas_charged = if need_gas_charge {
            gas_before - gas_after
        } else {
            0
        };

        let exit = result.is_some();

        self.steps.push(PvmStep {
            timestamp: self.timestamp,
            pc: pc_before,
            opcode,
            skip_len,
            regs_before,
            regs_after,
            reg_write,
            reg_a,
            reg_b,
            reg_d,
            mem_read: None,
            mem_write: None,
            gas_after,
            gas_charged,
            next_pc,
            exit,
        });

        self.timestamp += 1;
        result
    }

    /// Run until exit, recording all steps. Returns the exit reason.
    pub fn run(&mut self) -> ExitReason {
        loop {
            if let Some(exit) = self.step() {
                return exit;
            }
        }
    }

    /// Consume and return the recorded trace.
    pub fn into_trace(self) -> Vec<PvmStep> {
        self.steps
    }
}

/// Compute skip(i) — distance to next instruction minus 1.
fn compute_skip(bitmask: &[u8], i: usize) -> u32 {
    for j in 0..25u32 {
        let idx = i + 1 + j as usize;
        let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
        if bit == 1 {
            return j;
        }
    }
    24
}

/// Decode register indices from decoded instruction arguments.
fn decode_reg_indices(_opcode: Opcode, decoded_args: &args::Args) -> (usize, usize, usize) {
    match decoded_args {
        args::Args::ThreeReg { ra, rb, rd } => (*ra, *rb, *rd),
        args::Args::TwoReg { rd, ra } => (*rd, *ra, 0),
        args::Args::TwoRegImm { ra, rb, .. } => (*ra, *rb, 0),
        args::Args::TwoRegOffset { ra, rb, .. } => (*ra, *rb, 0),
        args::Args::TwoRegTwoImm { ra, rb, .. } => (*ra, *rb, 0),
        args::Args::RegImm { ra, .. } => (*ra, 0, 0),
        args::Args::RegExtImm { ra, .. } => (*ra, 0, 0),
        args::Args::RegTwoImm { ra, .. } => (*ra, 0, 0),
        args::Args::RegImmOffset { ra, .. } => (*ra, 0, 0),
        _ => (0, 0, 0),
    }
}
