use javm::args;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use javm::ExitReason;
use javm::PVM_REGISTER_COUNT;

use crate::core::step::{MemAccess, PvmStep};

pub use crate::core::ecall::ECALL_BLAKE2B_COMPRESS;

/// A recorded blake2b call for the precompile chip.
#[derive(Clone, Debug)]
pub struct Blake2bRecord {
    pub h: [u64; 8],
    pub m: [u64; 16],
    pub t: u128,
    pub f: bool,
}

/// Per-byte memory operations for a single blake2b_compress ECALL, so the
/// MemoryChip ledger can account for the reads (h, m) and writes (output
/// overwrites h) that happened atomically inside the precompile.  All
/// entries share a single `ts` matching the ECALL step's timestamp; the
/// MemoryChip insertion order keeps reads before writes at tie-break.
#[derive(Clone, Debug)]
pub struct Blake2bMemOp {
    /// Pointer register φ[10] — base of h and also base of the output write.
    pub h_ptr: u32,
    /// Pointer register φ[11] — base of m.
    pub m_ptr: u32,
    /// Timestamp of the ECALL step that triggered the precompile.
    pub ts: u64,
    /// 64 bytes of h (little-endian u64 words 0..8) read at (h_ptr + i, ts).
    pub h_bytes: [u8; 64],
    /// 128 bytes of m (LE u64 words 0..16) read at (m_ptr + k, ts).
    pub m_bytes: [u8; 128],
    /// 64 bytes of blake2b output written at (h_ptr + i, ts).
    pub out_bytes: [u8; 64],
}

pub struct TracingPvm {
    pub pvm: Interpreter,
    pub steps: Vec<PvmStep>,
    pub blake2b_records: Vec<Blake2bRecord>,
    pub blake2b_mem_ops: Vec<Blake2bMemOp>,
    timestamp: u64,
}

impl TracingPvm {
    pub fn new(pvm: Interpreter) -> Self {
        Self {
            pvm,
            steps: Vec::new(),
            blake2b_records: Vec::new(),
            blake2b_mem_ops: Vec::new(),
            timestamp: 1, // 0 is reserved for initial memory entries
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
        let imm_y = decode_imm_y(&decoded_args);
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
            imm_y,
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

    /// Run with precompile support. Blake2b ecalls are intercepted,
    /// executed natively, and recorded for the Blake2bChip.
    pub fn run_with_precompiles(&mut self) -> ExitReason {
        loop {
            if let Some(exit) = self.step() {
                match exit {
                    ExitReason::HostCall(id) if id == ECALL_BLAKE2B_COMPRESS => {
                        self.handle_blake2b_ecall();
                        // Continue execution — advance PC past the ecall
                        // The PVM already recorded the step; we just resume
                    }
                    other => return other,
                }
            }
        }
    }

    fn handle_blake2b_ecall(&mut self) {
        // Read h (64 bytes) from memory at address in φ[10]
        let h_ptr_u = self.pvm.registers[10] as usize;
        let m_ptr_u = self.pvm.registers[11] as usize;
        let h_ptr = self.pvm.registers[10] as u32;
        let m_ptr = self.pvm.registers[11] as u32;
        let t_low = self.pvm.registers[12];
        let f = self.pvm.registers[7] != 0; // φ[7] as finalization flag

        let mut h = [0u64; 8];
        let mut m = [0u64; 16];
        let mut h_bytes = [0u8; 64];
        let mut m_bytes = [0u8; 128];

        for i in 0..8 {
            let off = h_ptr_u + i * 8;
            if off + 8 <= self.pvm.flat_mem.len() {
                h[i] = u64::from_le_bytes(self.pvm.flat_mem[off..off+8].try_into().unwrap());
                h_bytes[i * 8..(i + 1) * 8].copy_from_slice(&self.pvm.flat_mem[off..off+8]);
            }
        }
        for i in 0..16 {
            let off = m_ptr_u + i * 8;
            if off + 8 <= self.pvm.flat_mem.len() {
                m[i] = u64::from_le_bytes(self.pvm.flat_mem[off..off+8].try_into().unwrap());
                m_bytes[i * 8..(i + 1) * 8].copy_from_slice(&self.pvm.flat_mem[off..off+8]);
            }
        }

        let t = t_low as u128;

        // Execute blake2b compression
        let result = blake2b_compress_sw(&h, &m, t, f);

        // Write result back to h_ptr and capture the exact bytes that hit memory
        let mut out_bytes = [0u8; 64];
        for i in 0..8 {
            let off = h_ptr_u + i * 8;
            let bytes = result[i].to_le_bytes();
            out_bytes[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
            if off + 8 <= self.pvm.flat_mem.len() {
                self.pvm.flat_mem[off..off+8].copy_from_slice(&bytes);
            }
        }

        // The ECALL step's timestamp was already assigned and incremented by
        // the preceding self.step() call; its value is self.timestamp - 1.
        let ts = self.timestamp - 1;

        self.blake2b_records.push(Blake2bRecord { h, m, t, f });
        self.blake2b_mem_ops.push(Blake2bMemOp {
            h_ptr, m_ptr, ts, h_bytes, m_bytes, out_bytes,
        });
    }

    /// Consume and return the recorded trace.
    pub fn into_trace(self) -> Vec<PvmStep> {
        self.steps
    }

    /// Return recorded blake2b calls for the precompile chip.
    pub fn blake2b_calls(&self) -> &[Blake2bRecord] {
        &self.blake2b_records
    }
}

// ── Software blake2b for the precompile ──────────────────────

const BLAKE2B_IV: [u64; 8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

fn blake2b_compress_sw(h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if f { v[14] = !v[14]; }

    for round in 0..12 {
        let s = &BLAKE2B_SIGMA[round];
        g_sw(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g_sw(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g_sw(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g_sw(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g_sw(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g_sw(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g_sw(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g_sw(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    let mut result = [0u64; 8];
    for i in 0..8 { result[i] = h[i] ^ v[i] ^ v[i + 8]; }
    result
}

fn g_sw(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, mx: u64, my: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Compute skip(i) — distance to next instruction minus 1.
pub(crate) fn compute_skip(bitmask: &[u8], i: usize) -> u32 {
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
pub(crate) fn decode_immediate(decoded_args: &args::Args) -> u64 {
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
/// Phase 13d-loadimmjumpind: extract the second immediate (`imm_y`) for
/// opcodes that have one (TwoImm, RegTwoImm, TwoRegTwoImm).  Default 0
/// for everything else.  LoadImmJumpInd uses this as the jump-offset
/// (added to regs[rb] for djump dispatch); the existing `imm` holds
/// the load-value `imm_x`.
pub(crate) fn decode_imm_y(decoded_args: &args::Args) -> u64 {
    match decoded_args {
        args::Args::TwoImm { imm_y, .. } => *imm_y,
        args::Args::RegTwoImm { imm_y, .. } => *imm_y,
        args::Args::TwoRegTwoImm { imm_y, .. } => *imm_y,
        _ => 0,
    }
}

pub(crate) fn decode_branch_target(decoded_args: &args::Args) -> u32 {
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
pub(crate) fn decode_reg_indices(_opcode: Opcode, decoded_args: &args::Args) -> (usize, usize, usize) {
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
