use javm::args;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use javm::ExitReason;
use javm::PVM_REGISTER_COUNT;

use crate::step::{MemAccess, PvmStep};

/// A tracing wrapper around javm's Pvm that records a full execution trace.
pub struct TracingPvm {
    pub pvm: Interpreter,
    pub steps: Vec<PvmStep>,
    timestamp: u64,
}

impl TracingPvm {
    pub fn new(pvm: Interpreter) -> Self {
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

        // Decode register indices and immediate from args
        let (reg_a, reg_b, reg_d) = decode_reg_indices(opcode, &decoded_args);
        let imm = decode_immediate(&decoded_args);
        let branch_target = decode_branch_target(&decoded_args);

        // Default next_pc for sequential execution
        let sequential_next_pc = (pc_before as usize + 1 + skip_len as usize) as u32;

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
        let branch_taken = !exit && next_pc != sequential_next_pc;

        // Reconstruct memory accesses from opcode + args + register state
        let (mem_read, mem_write) = decode_mem_access(
            opcode, &decoded_args, &regs_before, &regs_after,
        );

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
            imm,
            branch_target,
            branch_taken,
            mem_read,
            mem_write,
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

/// Extract immediate value from decoded args (0 if none).
fn decode_immediate(decoded_args: &args::Args) -> u64 {
    match decoded_args {
        args::Args::Imm { imm } => *imm,
        args::Args::RegImm { imm, .. } => *imm,
        args::Args::RegExtImm { imm, .. } => *imm,
        args::Args::RegTwoImm { imm_x, .. } => *imm_x,
        args::Args::RegImmOffset { imm, .. } => *imm,
        args::Args::TwoImm { imm_x, .. } => *imm_x,
        args::Args::TwoRegImm { imm, .. } => *imm,
        args::Args::TwoRegTwoImm { imm_x, .. } => *imm_x,
        _ => 0,
    }
}

/// Extract branch/jump target address from decoded args (0 if none).
fn decode_branch_target(decoded_args: &args::Args) -> u32 {
    match decoded_args {
        args::Args::Offset { offset } => *offset as u32,
        args::Args::RegImmOffset { offset, .. } => *offset as u32,
        args::Args::TwoRegOffset { offset, .. } => *offset as u32,
        _ => 0,
    }
}

/// Reconstruct memory access from opcode, args, and register state.
/// Returns (mem_read, mem_write).
fn decode_mem_access(
    opcode: Opcode,
    decoded_args: &args::Args,
    regs_before: &[u64; PVM_REGISTER_COUNT],
    regs_after: &[u64; PVM_REGISTER_COUNT],
) -> (Option<MemAccess>, Option<MemAccess>) {
    match opcode {
        // Direct loads (A.5.6): addr = imm, result in ra
        Opcode::LoadU8 | Opcode::LoadI8 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_after[*ra];
                return (Some(MemAccess { address: addr, value, size: 1 }), None);
            }
        }
        Opcode::LoadU16 | Opcode::LoadI16 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_after[*ra];
                return (Some(MemAccess { address: addr, value, size: 2 }), None);
            }
        }
        Opcode::LoadU32 | Opcode::LoadI32 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_after[*ra];
                return (Some(MemAccess { address: addr, value, size: 4 }), None);
            }
        }
        Opcode::LoadU64 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_after[*ra];
                return (Some(MemAccess { address: addr, value, size: 8 }), None);
            }
        }
        // Direct stores (A.5.6): addr = imm, value from ra
        Opcode::StoreU8 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_before[*ra] & 0xFF;
                return (None, Some(MemAccess { address: addr, value, size: 1 }));
            }
        }
        Opcode::StoreU16 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_before[*ra] & 0xFFFF;
                return (None, Some(MemAccess { address: addr, value, size: 2 }));
            }
        }
        Opcode::StoreU32 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_before[*ra] & 0xFFFF_FFFF;
                return (None, Some(MemAccess { address: addr, value, size: 4 }));
            }
        }
        Opcode::StoreU64 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_before[*ra];
                return (None, Some(MemAccess { address: addr, value, size: 8 }));
            }
        }
        // Indirect loads (A.5.10): addr = φ[rb] + imm, result in ra
        Opcode::LoadIndU8 | Opcode::LoadIndI8 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = regs_before[*rb].wrapping_add(*imm) as u32;
                let value = regs_after[*ra];
                return (Some(MemAccess { address: addr, value, size: 1 }), None);
            }
        }
        Opcode::LoadIndU16 | Opcode::LoadIndI16 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = regs_before[*rb].wrapping_add(*imm) as u32;
                let value = regs_after[*ra];
                return (Some(MemAccess { address: addr, value, size: 2 }), None);
            }
        }
        Opcode::LoadIndU32 | Opcode::LoadIndI32 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = regs_before[*rb].wrapping_add(*imm) as u32;
                let value = regs_after[*ra];
                return (Some(MemAccess { address: addr, value, size: 4 }), None);
            }
        }
        Opcode::LoadIndU64 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = regs_before[*rb].wrapping_add(*imm) as u32;
                let value = regs_after[*ra];
                return (Some(MemAccess { address: addr, value, size: 8 }), None);
            }
        }
        // Indirect stores (A.5.10): addr = φ[rb] + imm, value from ra
        Opcode::StoreIndU8 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = regs_before[*rb].wrapping_add(*imm) as u32;
                let value = regs_before[*ra] & 0xFF;
                return (None, Some(MemAccess { address: addr, value, size: 1 }));
            }
        }
        Opcode::StoreIndU16 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = regs_before[*rb].wrapping_add(*imm) as u32;
                let value = regs_before[*ra] & 0xFFFF;
                return (None, Some(MemAccess { address: addr, value, size: 2 }));
            }
        }
        Opcode::StoreIndU32 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = regs_before[*rb].wrapping_add(*imm) as u32;
                let value = regs_before[*ra] & 0xFFFF_FFFF;
                return (None, Some(MemAccess { address: addr, value, size: 4 }));
            }
        }
        Opcode::StoreIndU64 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = regs_before[*rb].wrapping_add(*imm) as u32;
                let value = regs_before[*ra];
                return (None, Some(MemAccess { address: addr, value, size: 8 }));
            }
        }
        // Store immediate (A.5.4): addr = imm_x, value = imm_y
        Opcode::StoreImmU8 => {
            if let args::Args::TwoImm { imm_x, imm_y } = decoded_args {
                let addr = *imm_x as u32;
                let value = *imm_y & 0xFF;
                return (None, Some(MemAccess { address: addr, value, size: 1 }));
            }
        }
        Opcode::StoreImmU16 => {
            if let args::Args::TwoImm { imm_x, imm_y } = decoded_args {
                let addr = *imm_x as u32;
                let value = *imm_y & 0xFFFF;
                return (None, Some(MemAccess { address: addr, value, size: 2 }));
            }
        }
        Opcode::StoreImmU32 => {
            if let args::Args::TwoImm { imm_x, imm_y } = decoded_args {
                let addr = *imm_x as u32;
                let value = *imm_y & 0xFFFF_FFFF;
                return (None, Some(MemAccess { address: addr, value, size: 4 }));
            }
        }
        Opcode::StoreImmU64 => {
            if let args::Args::TwoImm { imm_x, imm_y } = decoded_args {
                let addr = *imm_x as u32;
                let value = *imm_y;
                return (None, Some(MemAccess { address: addr, value, size: 8 }));
            }
        }
        // Store immediate indirect (A.5.7): addr = φ[ra] + imm_x, value = imm_y
        Opcode::StoreImmIndU8 => {
            if let args::Args::RegTwoImm { ra, imm_x, imm_y } = decoded_args {
                let addr = regs_before[*ra].wrapping_add(*imm_x) as u32;
                let value = *imm_y & 0xFF;
                return (None, Some(MemAccess { address: addr, value, size: 1 }));
            }
        }
        Opcode::StoreImmIndU16 => {
            if let args::Args::RegTwoImm { ra, imm_x, imm_y } = decoded_args {
                let addr = regs_before[*ra].wrapping_add(*imm_x) as u32;
                let value = *imm_y & 0xFFFF;
                return (None, Some(MemAccess { address: addr, value, size: 2 }));
            }
        }
        Opcode::StoreImmIndU32 => {
            if let args::Args::RegTwoImm { ra, imm_x, imm_y } = decoded_args {
                let addr = regs_before[*ra].wrapping_add(*imm_x) as u32;
                let value = *imm_y & 0xFFFF_FFFF;
                return (None, Some(MemAccess { address: addr, value, size: 4 }));
            }
        }
        Opcode::StoreImmIndU64 => {
            if let args::Args::RegTwoImm { ra, imm_x, imm_y } = decoded_args {
                let addr = regs_before[*ra].wrapping_add(*imm_x) as u32;
                let value = *imm_y;
                return (None, Some(MemAccess { address: addr, value, size: 8 }));
            }
        }
        _ => {}
    }
    (None, None)
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
