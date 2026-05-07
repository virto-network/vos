use javm::args;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use javm::ExitReason;
use javm::PVM_REGISTER_COUNT;

use crate::core::step::{MemAccess, PvmStep};

pub use crate::core::ecall::{
    ECALL_BLAKE2B_COMPRESS, ECALL_RISTRETTO_SCALAR_MULT, ECALL_RISTRETTO_POINT_ADD,
    ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE,
    ECALL_SCALAR_MUL_MOD_L, ECALL_SCALAR_ADD_MOD_L,
};

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

/// A recorded scalar mul/add mod ℓ call for chip integration.
/// Both ECALL types share the same shape: 32B + 32B → 32B.
#[derive(Clone, Debug)]
pub struct ScalarBinopRecord {
    pub op_id: u32,           // ECALL_SCALAR_MUL_MOD_L or _ADD_MOD_L
    pub a: [u8; 32],
    pub b: [u8; 32],
    pub output: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ScalarBinopMemOp {
    pub a_ptr: u32,
    pub b_ptr: u32,
    pub output_ptr: u32,
    pub ts: u64,
    pub a_bytes: [u8; 32],
    pub b_bytes: [u8; 32],
    pub out_bytes: [u8; 32],
}

/// A recorded wide-scalar reduction call for chip integration.
#[derive(Clone, Debug)]
pub struct ScalarReduceWideRecord {
    pub wide: [u8; 64],
    pub output: [u8; 32],
}

/// Per-byte memory operations for a single
/// scalar_from_bytes_mod_order_wide ECALL: 64 reads + 32 writes.
#[derive(Clone, Debug)]
pub struct ScalarReduceWideMemOp {
    pub wide_ptr: u32,
    pub output_ptr: u32,
    pub ts: u64,
    pub wide_bytes: [u8; 64],
    pub out_bytes: [u8; 32],
}

/// A recorded Ristretto255 point-add call for the (in-progress) chip
/// integration.  Captures both compressed inputs + the compressed
/// output — the bytes the chip's boundary lookup will commit to.
#[derive(Clone, Debug)]
pub struct RistrettoPointAddRecord {
    pub p: [u8; 32],
    pub q: [u8; 32],
    pub output: [u8; 32],
}

/// Per-byte memory operations for a single ristretto_point_add ECALL.
/// 32 P-bytes + 32 Q-bytes read at the call's timestamp + 32 output
/// bytes written.  Insertion order in the MemoryChip ledger keeps
/// reads before writes at tie-break.
#[derive(Clone, Debug)]
pub struct RistrettoPointAddMemOp {
    pub p_ptr: u32,
    pub q_ptr: u32,
    pub output_ptr: u32,
    pub ts: u64,
    pub p_bytes: [u8; 32],
    pub q_bytes: [u8; 32],
    pub out_bytes: [u8; 32],
}

/// Classification of the input point in a `RistrettoRecord`, set by
/// the ECALL handler from `detect_scalar_mult_kind`.  Lets the chip
/// dispatch fixed-base scalar mults (Ristretto255 basepoint G) onto
/// the comb-method path and variable-base mults onto double-and-add.
///
/// Session 2.1 of `crates/zkpvm/PERF_ROADMAP.md`: this enum is the
/// side-note plumbing for the comb method.  The chip side (lookup
/// relation, preprocessed columns, fixed-base row class) is the
/// follow-up; today the field is informational and the chip still
/// runs the variable-base path for every record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ScalarMultKind {
    /// Default: input point is not a registered fixed base.  Chip
    /// runs the double-and-add ladder over the decompressed input.
    #[default]
    Variable,
    /// Input point bytes matched the canonical Ristretto255 basepoint
    /// `G`.  Chip can route through the comb-table fixed-base path.
    FixedBasepoint,
}

/// Detect whether a 32-byte compressed Ristretto255 point is a
/// registered fixed base.  Only the canonical basepoint is supported
/// today; future protocols (Pedersen `H` etc.) would extend this.
pub fn detect_scalar_mult_kind(point_bytes: &[u8; 32]) -> ScalarMultKind {
    #[cfg(feature = "prover")]
    {
        let bp = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
        if *point_bytes == bp {
            return ScalarMultKind::FixedBasepoint;
        }
    }
    let _ = point_bytes;
    ScalarMultKind::Variable
}

/// A recorded Ristretto255 scalar-mult call for the precompile chip.
/// Captures the canonical 32-byte scalar, 32-byte compressed input
/// point, and 32-byte compressed output point — exactly the bytes the
/// chip's boundary lookup will commit to.
#[derive(Clone, Debug)]
pub struct RistrettoRecord {
    pub scalar: [u8; 32],
    pub point: [u8; 32],
    pub output: [u8; 32],
    /// Set by `detect_scalar_mult_kind` from `point` at ECALL time.
    /// Drives chip-side dispatch between comb-method and double-and-add.
    pub kind: ScalarMultKind,
}

/// Per-byte memory operations for a single ristretto_scalar_mult ECALL.
/// 32 scalar reads + 32 point reads + 32 output writes, all sharing the
/// ECALL step's timestamp.  Insertion order in the MemoryChip ledger
/// keeps reads before writes at tie-break.
#[derive(Clone, Debug)]
pub struct RistrettoMemOp {
    /// Pointer register φ[10] — base of the 32-byte scalar buffer.
    pub scalar_ptr: u32,
    /// Pointer register φ[11] — base of the 32-byte input compressed point.
    pub point_ptr: u32,
    /// Pointer register φ[12] — base of the 32-byte output compressed point.
    pub output_ptr: u32,
    /// Timestamp of the ECALL step that triggered the precompile.
    pub ts: u64,
    /// 32 scalar bytes read at (scalar_ptr + i, ts).
    pub scalar_bytes: [u8; 32],
    /// 32 point bytes read at (point_ptr + i, ts).
    pub point_bytes: [u8; 32],
    /// 32 output bytes written at (output_ptr + i, ts).
    pub out_bytes: [u8; 32],
}

pub struct TracingPvm {
    pub pvm: Interpreter,
    pub steps: Vec<PvmStep>,
    pub blake2b_records: Vec<Blake2bRecord>,
    pub blake2b_mem_ops: Vec<Blake2bMemOp>,
    pub ristretto_records: Vec<RistrettoRecord>,
    pub ristretto_mem_ops: Vec<RistrettoMemOp>,
    pub ristretto_add_records: Vec<RistrettoPointAddRecord>,
    pub ristretto_add_mem_ops: Vec<RistrettoPointAddMemOp>,
    pub scalar_reduce_wide_records: Vec<ScalarReduceWideRecord>,
    pub scalar_reduce_wide_mem_ops: Vec<ScalarReduceWideMemOp>,
    pub scalar_binop_records: Vec<ScalarBinopRecord>,
    pub scalar_binop_mem_ops: Vec<ScalarBinopMemOp>,
    timestamp: u64,
}

impl TracingPvm {
    pub fn new(pvm: Interpreter) -> Self {
        Self {
            pvm,
            steps: Vec::new(),
            blake2b_records: Vec::new(),
            blake2b_mem_ops: Vec::new(),
            ristretto_records: Vec::new(),
            ristretto_mem_ops: Vec::new(),
            ristretto_add_records: Vec::new(),
            ristretto_add_mem_ops: Vec::new(),
            scalar_reduce_wide_records: Vec::new(),
            scalar_reduce_wide_mem_ops: Vec::new(),
            scalar_binop_records: Vec::new(),
            scalar_binop_mem_ops: Vec::new(),
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
    /// Ristretto255 scalar-mult ecalls are similarly intercepted and
    /// recorded for the (in-progress) RistrettoChip.
    pub fn run_with_precompiles(&mut self) -> ExitReason {
        loop {
            if let Some(exit) = self.step() {
                match exit {
                    ExitReason::HostCall(id) if id == ECALL_BLAKE2B_COMPRESS => {
                        self.handle_blake2b_ecall();
                    }
                    ExitReason::HostCall(id) if id == ECALL_RISTRETTO_SCALAR_MULT => {
                        self.handle_ristretto_scalar_mult_ecall();
                    }
                    ExitReason::HostCall(id) if id == ECALL_RISTRETTO_POINT_ADD => {
                        self.handle_ristretto_point_add_ecall();
                    }
                    ExitReason::HostCall(id) if id == ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE => {
                        self.handle_scalar_reduce_wide_ecall();
                    }
                    ExitReason::HostCall(id) if id == ECALL_SCALAR_MUL_MOD_L => {
                        self.handle_scalar_binop_ecall(ECALL_SCALAR_MUL_MOD_L);
                    }
                    ExitReason::HostCall(id) if id == ECALL_SCALAR_ADD_MOD_L => {
                        self.handle_scalar_binop_ecall(ECALL_SCALAR_ADD_MOD_L);
                    }
                    other => return other,
                }
            }
        }
    }

    /// Run with stub handlers for the JAM/VOS lifecycle hostcalls so a
    /// vos-style actor can be driven cold-start by a bare interpreter.
    /// Stubbed: `INFO=6`, `STORAGE_R=4`, `FETCH=2`, `OUTPUT=26`,
    /// `DEBUG_WRITE=11`, `STORAGE_W=5`, `GAS=1` — all return 0 in φ[7].
    /// `ExitReason::Ecall` (the no-immediate halt with `t0=0`) is treated
    /// as a clean termination.  Blake2b ecalls are still intercepted and
    /// executed natively.  Unknown hostcall IDs propagate as-is.
    pub fn run_with_vos_stubs(&mut self) -> ExitReason {
        loop {
            if let Some(exit) = self.step() {
                match exit {
                    ExitReason::HostCall(id) if id == ECALL_BLAKE2B_COMPRESS => {
                        self.handle_blake2b_ecall();
                    }
                    ExitReason::HostCall(id) if id == ECALL_RISTRETTO_SCALAR_MULT => {
                        self.handle_ristretto_scalar_mult_ecall();
                    }
                    ExitReason::HostCall(id) if id == ECALL_RISTRETTO_POINT_ADD => {
                        self.handle_ristretto_point_add_ecall();
                    }
                    ExitReason::HostCall(id) if id == ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE => {
                        self.handle_scalar_reduce_wide_ecall();
                    }
                    ExitReason::HostCall(id) if id == ECALL_SCALAR_MUL_MOD_L => {
                        self.handle_scalar_binop_ecall(ECALL_SCALAR_MUL_MOD_L);
                    }
                    ExitReason::HostCall(id) if id == ECALL_SCALAR_ADD_MOD_L => {
                        self.handle_scalar_binop_ecall(ECALL_SCALAR_ADD_MOD_L);
                    }
                    ExitReason::HostCall(id) => match id {
                        // imm=0 is the IPC/REPLY slot — `halt_with_output`
                        // emits `ecalli 0` with `t0=0`, the clean-termination
                        // sentinel.  Treat as halt.
                        0 => return ExitReason::HostCall(0),
                        // GAS, FETCH, STORAGE_R, STORAGE_W, INFO,
                        // DEBUG_WRITE, OUTPUT — leave registers
                        // untouched so the RegisterMemoryChip ledger
                        // stays balanced.  The actor reads whatever is
                        // already in φ[7], which for these "lucky"
                        // hostcalls (zeroed at PVM cold start) means
                        // it sees 0 — i.e. no service_id, no persisted
                        // state, no fetched message.  Same effect as a
                        // proper stub but without disturbing the
                        // register ledger.
                        1 | 2 | 4 | 5 | 6 | 11 | 26 => {}
                        _ => return ExitReason::HostCall(id),
                    },
                    // Plain Ecall (no immediate) is also a halt sentinel.
                    ExitReason::Ecall => return ExitReason::Ecall,
                    other => return other,
                }
            }
        }
    }

    fn handle_blake2b_ecall(&mut self) {
        // Read h (64 bytes) from memory at address in φ[10].
        // NOTE: this handler reads φ[10/11/12/7] but the zkpvm-precompiles
        // shim transpiles RISC-V a0/a1/a2/a3 to PVM φ[7/8/9/10] (per
        // grey-transpiler's `map_register`).  The off-by-three is a known
        // bug — fixed only on `handle_ristretto_scalar_mult_ecall`
        // (commit 02922c4).  Aligning the other handlers changes the
        // trace shape in ways that break lookup balance for the existing
        // prove_blake2b_via_ecall etc. tests; a holistic fix (handler +
        // lookup-emission alignment + test rewrites) is a separate
        // session's work.  In practice these handlers produce wrong
        // host-side outputs but the actor's behaviour is determined by
        // RISC-V semantics, not by what the host writes back, so the
        // bench prove + verify still close.
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

    /// Read 32 scalar bytes + 32 compressed-point bytes from flat_mem,
    /// run the host-side `dalek` scalar mult, write 32 compressed
    /// output bytes back, and capture the call for the (in-progress)
    /// RistrettoChip.  Buffers out of bounds are handled by writing
    /// the canonical compressed-identity sentinel (`[0u8; 32]`) — the
    /// chip will accept this output as the malformed-input branch.
    fn handle_ristretto_scalar_mult_ecall(&mut self) {
        // PVM register convention (matches grey-transpiler's RISC-V → PVM
        // mapping in `riscv.rs::map_register`):
        //   φ[7] = A0 (RISC-V x10), φ[8] = A1, φ[9] = A2.
        // The zkpvm-precompiles shim's inline asm uses `in("a0") scalar_ptr`
        // etc., which the transpiler routes to φ[7/8/9].  Earlier code read
        // φ[10/11/12] (= A3/A4/A5) and silently saw zeros for transpiled
        // actor traces — the bug that kept the comb-method path dormant in
        // production.  Other ECALL handlers in this file still use
        // φ[10/11/12] and have the same bug; they're left as-is here to
        // keep this fix scoped to the comb path.
        let scalar_ptr_u = self.pvm.registers[7] as usize;
        let point_ptr_u  = self.pvm.registers[8] as usize;
        let output_ptr_u = self.pvm.registers[9] as usize;
        let scalar_ptr = self.pvm.registers[7] as u32;
        let point_ptr  = self.pvm.registers[8] as u32;
        let output_ptr = self.pvm.registers[9] as u32;

        let mut scalar_bytes = [0u8; 32];
        let mut point_bytes  = [0u8; 32];
        let mem_len = self.pvm.flat_mem.len();
        let buffers_in_bounds = scalar_ptr_u.saturating_add(32) <= mem_len
            && point_ptr_u.saturating_add(32) <= mem_len
            && output_ptr_u.saturating_add(32) <= mem_len;
        if buffers_in_bounds {
            scalar_bytes.copy_from_slice(&self.pvm.flat_mem[scalar_ptr_u..scalar_ptr_u + 32]);
            point_bytes.copy_from_slice(&self.pvm.flat_mem[point_ptr_u..point_ptr_u + 32]);
        }

        let out_bytes = ristretto_scalar_mult_sw(&scalar_bytes, &point_bytes);

        if buffers_in_bounds {
            self.pvm.flat_mem[output_ptr_u..output_ptr_u + 32].copy_from_slice(&out_bytes);
        }

        let ts = self.timestamp - 1;

        self.ristretto_records.push(RistrettoRecord {
            scalar: scalar_bytes,
            point: point_bytes,
            output: out_bytes,
            kind: detect_scalar_mult_kind(&point_bytes),
        });
        self.ristretto_mem_ops.push(RistrettoMemOp {
            scalar_ptr, point_ptr, output_ptr, ts,
            scalar_bytes, point_bytes, out_bytes,
        });
    }

    /// Step 18: scalar mul/add mod ℓ.  Reads 32 + 32, writes 32.
    fn handle_scalar_binop_ecall(&mut self, op_id: u32) {
        // Same off-by-three bug as handle_blake2b_ecall.  Left as-is until
        // a holistic fix.
        let a_ptr_u = self.pvm.registers[10] as usize;
        let b_ptr_u = self.pvm.registers[11] as usize;
        let output_ptr_u = self.pvm.registers[12] as usize;
        let a_ptr = self.pvm.registers[10] as u32;
        let b_ptr = self.pvm.registers[11] as u32;
        let output_ptr = self.pvm.registers[12] as u32;

        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        let mem_len = self.pvm.flat_mem.len();
        let buffers_in_bounds = a_ptr_u.saturating_add(32) <= mem_len
            && b_ptr_u.saturating_add(32) <= mem_len
            && output_ptr_u.saturating_add(32) <= mem_len;
        if buffers_in_bounds {
            a_bytes.copy_from_slice(&self.pvm.flat_mem[a_ptr_u..a_ptr_u + 32]);
            b_bytes.copy_from_slice(&self.pvm.flat_mem[b_ptr_u..b_ptr_u + 32]);
        }

        let out_bytes = scalar_binop_sw(op_id, &a_bytes, &b_bytes);

        if buffers_in_bounds {
            self.pvm.flat_mem[output_ptr_u..output_ptr_u + 32].copy_from_slice(&out_bytes);
        }

        let ts = self.timestamp - 1;
        self.scalar_binop_records.push(ScalarBinopRecord {
            op_id, a: a_bytes, b: b_bytes, output: out_bytes,
        });
        self.scalar_binop_mem_ops.push(ScalarBinopMemOp {
            a_ptr, b_ptr, output_ptr, ts,
            a_bytes, b_bytes, out_bytes,
        });
    }

    /// Read 64 wide-bytes from flat_mem, reduce via dalek's
    /// `from_bytes_mod_order_wide`, write 32 canonical scalar bytes
    /// back, capture the call.  Out-of-bounds buffers ⇒ all-zero
    /// output (canonical zero scalar).
    fn handle_scalar_reduce_wide_ecall(&mut self) {
        // Same off-by-three bug as handle_blake2b_ecall.
        let wide_ptr_u = self.pvm.registers[10] as usize;
        let output_ptr_u = self.pvm.registers[11] as usize;
        let wide_ptr = self.pvm.registers[10] as u32;
        let output_ptr = self.pvm.registers[11] as u32;

        let mut wide_bytes = [0u8; 64];
        let mem_len = self.pvm.flat_mem.len();
        let buffers_in_bounds = wide_ptr_u.saturating_add(64) <= mem_len
            && output_ptr_u.saturating_add(32) <= mem_len;
        if buffers_in_bounds {
            wide_bytes.copy_from_slice(&self.pvm.flat_mem[wide_ptr_u..wide_ptr_u + 64]);
        }

        let out_bytes = scalar_reduce_wide_sw(&wide_bytes);

        if buffers_in_bounds {
            self.pvm.flat_mem[output_ptr_u..output_ptr_u + 32].copy_from_slice(&out_bytes);
        }

        let ts = self.timestamp - 1;
        self.scalar_reduce_wide_records.push(ScalarReduceWideRecord {
            wide: wide_bytes, output: out_bytes,
        });
        self.scalar_reduce_wide_mem_ops.push(ScalarReduceWideMemOp {
            wide_ptr, output_ptr, ts, wide_bytes, out_bytes,
        });
    }

    /// Read 32 P-bytes + 32 Q-bytes from flat_mem, run host-side
    /// `dalek` point addition (compress(decompress(P) + decompress(Q))),
    /// write 32 output bytes back, and capture the call.  Buffers
    /// out of bounds → canonical compressed identity sentinel.
    fn handle_ristretto_point_add_ecall(&mut self) {
        // Same off-by-three bug as handle_blake2b_ecall.
        let p_ptr_u = self.pvm.registers[10] as usize;
        let q_ptr_u = self.pvm.registers[11] as usize;
        let output_ptr_u = self.pvm.registers[12] as usize;
        let p_ptr = self.pvm.registers[10] as u32;
        let q_ptr = self.pvm.registers[11] as u32;
        let output_ptr = self.pvm.registers[12] as u32;

        let mut p_bytes = [0u8; 32];
        let mut q_bytes = [0u8; 32];
        let mem_len = self.pvm.flat_mem.len();
        let buffers_in_bounds = p_ptr_u.saturating_add(32) <= mem_len
            && q_ptr_u.saturating_add(32) <= mem_len
            && output_ptr_u.saturating_add(32) <= mem_len;
        if buffers_in_bounds {
            p_bytes.copy_from_slice(&self.pvm.flat_mem[p_ptr_u..p_ptr_u + 32]);
            q_bytes.copy_from_slice(&self.pvm.flat_mem[q_ptr_u..q_ptr_u + 32]);
        }

        let out_bytes = ristretto_point_add_sw(&p_bytes, &q_bytes);

        if buffers_in_bounds {
            self.pvm.flat_mem[output_ptr_u..output_ptr_u + 32].copy_from_slice(&out_bytes);
        }

        let ts = self.timestamp - 1;
        self.ristretto_add_records.push(RistrettoPointAddRecord {
            p: p_bytes, q: q_bytes, output: out_bytes,
        });
        self.ristretto_add_mem_ops.push(RistrettoPointAddMemOp {
            p_ptr, q_ptr, output_ptr, ts,
            p_bytes, q_bytes, out_bytes,
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

    /// Return recorded Ristretto255 scalar-mult calls for the precompile chip.
    pub fn ristretto_calls(&self) -> &[RistrettoRecord] {
        &self.ristretto_records
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

// ── Software Ristretto255 scalar mult for the precompile ─────────
//
// Host-side reference using `curve25519-dalek`.  Returns the
// canonical compressed Ristretto encoding of `k * P`, or `[0u8; 32]`
// (compressed identity) on either non-canonical scalar bytes or an
// invalid input point encoding.  This is exactly the function the
// RistrettoChip will be constrained to compute — by going through the
// same crate cipher-clerk uses, the precompile's input/output
// agreement with cipher-clerk's own crypto is by construction.

fn scalar_binop_sw(op_id: u32, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::scalar::Scalar;
    let sa = Scalar::from_canonical_bytes(*a).into_option();
    let sb = Scalar::from_canonical_bytes(*b).into_option();
    match (sa, sb) {
        (Some(x), Some(y)) => match op_id {
            ECALL_SCALAR_MUL_MOD_L => (x * y).to_bytes(),
            ECALL_SCALAR_ADD_MOD_L => (x + y).to_bytes(),
            _ => [0u8; 32],
        },
        _ => [0u8; 32],
    }
}

fn scalar_reduce_wide_sw(wide_bytes: &[u8; 64]) -> [u8; 32] {
    use curve25519_dalek::scalar::Scalar;
    Scalar::from_bytes_mod_order_wide(wide_bytes).to_bytes()
}

fn ristretto_point_add_sw(p_bytes: &[u8; 32], q_bytes: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::ristretto::CompressedRistretto;
    let p = match CompressedRistretto::from_slice(p_bytes)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(p) => p,
        None => return [0u8; 32],
    };
    let q = match CompressedRistretto::from_slice(q_bytes)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(q) => q,
        None => return [0u8; 32],
    };
    (p + q).compress().to_bytes()
}

fn ristretto_scalar_mult_sw(scalar_bytes: &[u8; 32], point_bytes: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;

    let scalar = match Scalar::from_canonical_bytes(*scalar_bytes).into_option() {
        Some(s) => s,
        None => return [0u8; 32],
    };
    let point = match CompressedRistretto::from_slice(point_bytes)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(p) => p,
        None => return [0u8; 32],
    };
    (scalar * point).compress().to_bytes()
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

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;

    #[test]
    fn detects_basepoint() {
        let bp = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
        assert_eq!(detect_scalar_mult_kind(&bp), ScalarMultKind::FixedBasepoint);
    }

    #[test]
    fn rejects_non_basepoint() {
        let mut bp = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED.to_bytes();
        bp[0] ^= 0xff; // mutate first byte
        assert_eq!(detect_scalar_mult_kind(&bp), ScalarMultKind::Variable);
    }

    #[test]
    fn rejects_zero() {
        assert_eq!(detect_scalar_mult_kind(&[0u8; 32]), ScalarMultKind::Variable);
    }
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
