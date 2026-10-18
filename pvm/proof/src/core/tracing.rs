use vos_pvm::ExitReason;
use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::args;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;

use vos_pvm::precompile::{WITNESS_INPUT, WitnessFault, WitnessInput, WitnessRead};

use crate::core::step::{CompactStep, MemAccess, PvmStep, RegWrite, WitnessWrite, expand_steps};

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
#[derive(Clone, Debug, PartialEq)]
pub struct Blake2bMemOp {
    /// Pointer register φ\[7\] — base of h and also base of the output write.
    pub h_ptr: u32,
    /// Pointer register φ\[8\] — base of m.
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
    /// Recorded steps in compact form — the register-file snapshots are
    /// reconstructible from `initial_regs` + the per-step [`RegWrite`]s
    /// (see [`CompactStep`]), so a multi-million-step trace holds ~2.6×
    /// less than full [`PvmStep`]s. [`Self::trace`] / [`Self::into_trace`]
    /// expand back to full steps for consumers that want snapshots.
    steps: Vec<CompactStep>,
    /// Register file entering the first recorded step, captured at that
    /// step (not at construction, so pre-run register seeding is honored).
    /// `None` until a step is recorded.
    initial_regs: Option<[u64; PVM_REGISTER_COUNT]>,
    /// `regs_after` of the last recorded step. Compact reconstruction
    /// leans on register continuity across steps, so [`Self::step`]
    /// asserts the interpreter's file still matches this before stepping —
    /// out-of-band register mutation between steps would otherwise be
    /// silently lost in expansion.
    last_regs: [u64; PVM_REGISTER_COUNT],
    pub blake2b_records: Vec<Blake2bRecord>,
    pub blake2b_mem_ops: Vec<Blake2bMemOp>,
    /// The input a kernel's witness-input calls read, when the run has one;
    /// without it a witness-input call is an unhandled host call.
    witness_input: Option<WitnessInput<Vec<u8>>>,
    /// Each witness-input call served, in order.
    pub witness_reads: Vec<WitnessRead>,
    timestamp: u64,
}

impl TracingPvm {
    /// Trace an initialized interpreter.
    pub fn new(pvm: Interpreter) -> Self {
        Self {
            pvm,
            steps: Vec::new(),
            initial_regs: None,
            last_regs: [0u64; PVM_REGISTER_COUNT],
            blake2b_records: Vec::new(),
            blake2b_mem_ops: Vec::new(),
            witness_input: None,
            witness_reads: Vec::new(),
            timestamp: 1, // 0 is reserved for initial memory entries
        }
    }

    /// Serve the run's witness-input calls from `input`, as the agent
    /// served the kernel's live run from the bytes its attest recorded.
    /// `None` past an input's cap ([`vos_pvm::precompile::WITNESS_INPUT_MAX`]).
    pub fn with_witness_input(mut self, input: Vec<u8>) -> Option<Self> {
        self.witness_input = Some(WitnessInput::new(input)?);
        Some(self)
    }

    /// The witness input's bytes read so far, and how many remain.
    pub fn witness_cursor(&self) -> Option<(usize, usize)> {
        self.witness_input
            .as_ref()
            .map(|input| (input.cursor(), input.remaining()))
    }

    /// Execute a single step, recording the witness.
    pub fn step(&mut self) -> Option<ExitReason> {
        let pc_before = self.pvm.pc;
        let regs_before = self.pvm.registers;
        let gas_before = self.pvm.gas;
        let need_gas_charge = self.pvm.need_gas_charge;

        // Compact recording drops the per-step register snapshots, so the
        // trace is only faithful if the file really is continuous across
        // steps. Nothing in this crate mutates registers between steps
        // (precompile handlers touch memory only), but a
        // silent violation would corrupt every later reconstructed
        // snapshot — fail loudly instead.
        match self.initial_regs {
            Some(_) => assert!(
                regs_before == self.last_regs,
                "registers mutated between traced steps (ts {}): the compact \
                 trace cannot represent out-of-band register changes",
                self.timestamp,
            ),
            None => self.initial_regs = Some(regs_before),
        }

        // Decode opcode and args BEFORE stepping
        let opcode_byte = if (pc_before as usize) < self.pvm.code.len() {
            self.pvm.code[pc_before as usize]
        } else {
            0
        };
        let opcode = Opcode::from_byte(opcode_byte).unwrap_or(Opcode::Trap);
        let skip_len = compute_skip(&self.pvm.bitmask, pc_before as usize);
        let category = opcode.category();
        let decoded_args = args::decode_args(
            &self.pvm.code,
            pc_before as usize,
            skip_len as usize,
            category,
        );

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
        // A halting step continues at the halt address, outside a derived
        // program's code: its segment ends there only at a halt.
        let next_pc = if result == Some(ExitReason::Halt) {
            vos_pvm::PVM_HALT_ADDR as u32
        } else {
            self.pvm.pc
        };

        let reg_write = recorded_write(
            opcode,
            (reg_a, reg_b, reg_d),
            &regs_before,
            &regs_after,
            result.as_ref(),
        )
        .unwrap_or_else(|error| panic!("step at ts {}: {error}", self.timestamp));
        self.last_regs = regs_after;

        let gas_charged = if need_gas_charge {
            gas_before - gas_after
        } else {
            0
        };

        let exit = result.is_some();
        let branch_taken = !exit && next_pc != sequential_next_pc;

        // Reconstruct memory accesses only after the instruction completed.
        // A page fault, low-zone exception, out-of-gas exit, or any other
        // panic leaves memory untouched and must not manufacture a memory
        // ledger row for the rejected access.
        let (mem_read, mem_write) = if result.is_none() {
            decode_mem_access(opcode, &decoded_args, &regs_before, &regs_after)
        } else {
            (None, None)
        };

        self.steps.push(CompactStep {
            timestamp: self.timestamp,
            pc: pc_before,
            opcode,
            skip_len,
            reg_write: reg_write.map(|i| RegWrite {
                index: i as u8,
                value: regs_after[i],
            }),
            reg_a: reg_a as u8,
            reg_b: reg_b as u8,
            reg_d: reg_d as u8,
            imm,
            imm_y,
            branch_target,
            branch_taken,
            mem_read,
            mem_write,
            gas_after,
            gas_charged,
            next_pc,
            host_call_acknowledged: false,
            witness: None,
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

    /// Run with precompile support: precompile calls are intercepted,
    /// executed natively, recorded for their chips and acknowledged. Any
    /// other exit, including an unknown host call, is returned.
    pub fn run_with_precompiles(&mut self) -> ExitReason {
        loop {
            if let Some(exit) = self.step_with_precompiles() {
                return exit;
            }
        }
    }

    /// One iteration of [`Self::run_with_precompiles`]: execute exactly one
    /// recorded step, execute and acknowledge a precompile call, and return
    /// `Some(exit)` only when the run terminates.
    pub fn step_with_precompiles(&mut self) -> Option<ExitReason> {
        let exit = self.step()?;
        // A served call pays its VOS price first, exactly as on the refine
        // host; an unpayable call stops out of gas, unserved.
        if let ExitReason::HostCall(id) = exit
            && crate::core::ecall::is_proof_host_call_allowed(id)
            && !vos_pvm::precompile::charge(id, &mut self.pvm.gas)
        {
            return Some(ExitReason::OutOfGas);
        }
        match exit {
            ExitReason::HostCall(WITNESS_INPUT) if self.witness_input.is_some() => {
                if let Some(stop) = self.handle_witness_input() {
                    return Some(stop);
                }
            }
            ExitReason::HostCall(id) if id == u64::from(ECALL_BLAKE2B_COMPRESS) => {
                // An argument range the machine cannot read or write
                // panics it, as the refine host's serving does.
                if !self.handle_blake2b_ecall() {
                    return Some(ExitReason::Panic);
                }
            }
            other => return Some(other),
        }
        self.acknowledge_handled_host_call();
        None
    }

    /// Commit the continuation of a host call that this tracer handled.
    ///
    /// `ecalli` deliberately leaves the interpreter at its cause PC until the
    /// embedder acknowledges the call. Keeping this after the handler
    /// prevents failed or unknown host calls from being consumed
    /// accidentally.
    fn acknowledge_handled_host_call(&mut self) {
        let pending = self.pvm.pending_host_call();
        if let Some(call) = pending {
            assert!(
                crate::core::ecall::is_proof_host_call_allowed(call.id),
                "proof tracer attempted to acknowledge unsupported host call {}",
                call.id,
            );
        }
        let call = pending.expect("a handled host call must be pending");
        assert!(self.pvm.resume_after_host_call());
        {
            let step = self
                .steps
                .last_mut()
                .expect("a handled host call must have a recorded instruction");
            assert_eq!(
                (step.pc, step.next_pc),
                (call.cause_pc, call.cause_pc),
                "standard host-call row does not expose its unacknowledged cause PC",
            );
            assert_eq!(
                self.pvm.pc, call.resume_pc,
                "standard host-call acknowledgment selected the wrong resume PC",
            );

            // `step()` records the architectural state at the host boundary,
            // where standard ECALLI deliberately retains the cause PC. Once
            // this embedder handles and acknowledges the call, the proof row
            // must instead produce the committed continuation consumed by the
            // following row. Calls that are propagated never reach this path
            // and therefore keep the cause PC as their observable boundary.
            step.next_pc = call.resume_pc;
            step.host_call_acknowledged = true;
        }
    }

    /// Serve a witness-input call from the run's input, as the agent serves
    /// it: its bytes written at φ7, its count in φ7, which the step records
    /// as its register write, and its bytes as its witness write. A call
    /// that cannot pay stops the run out of gas, and one whose bytes cannot
    /// land panics it, neither acknowledged.
    fn handle_witness_input(&mut self) -> Option<ExitReason> {
        let input = self.witness_input.as_mut().expect("a witness input");
        let mut registers = self.pvm.registers;
        let mut gas = self.pvm.gas;
        let served = input.serve(&mut registers, self.pvm.memory_mut(), &mut gas);
        self.pvm.gas = gas;
        let read = match served {
            Ok(read) => read,
            Err(WitnessFault::OutOfGas) => return Some(ExitReason::OutOfGas),
            Err(WitnessFault::Unwritable) => return Some(ExitReason::Panic),
        };
        let bytes = input.read()[read.cursor..read.cursor + read.count].to_vec();
        self.pvm.registers = registers;
        self.last_regs = registers;
        let step = self
            .steps
            .last_mut()
            .expect("a served call has its recorded instruction");
        // The count is the call's register write, even when φ7 held it.
        step.reg_write = Some(RegWrite {
            index: 7,
            value: registers[7],
        });
        step.witness = (read.count > 0).then(|| {
            Box::new(WitnessWrite {
                address: read.destination as u32,
                bytes,
            })
        });
        self.witness_reads.push(read);
        None
    }

    /// Serve one compression and record it for the BLAKE2b chip: false when
    /// an argument range is out of the machine's accessible memory.
    ///
    /// Served by the runtime's own [`vos_pvm::precompile::execute`], the
    /// refine host's serving, through the memory's permission-checked
    /// accessors, over a flat or a sparse memory alike: a range the runtime
    /// refuses (a 64-bit pointer, an inaccessible or wrapping range) is a
    /// panic here too, never a read of zeros.
    fn handle_blake2b_ecall(&mut self) -> bool {
        let registers = self.pvm.registers;
        let Some(vos_pvm::precompile::PrecompileCall::Blake2bCompress {
            h_ptr,
            m_ptr,
            h,
            m,
            t,
            f,
            h_bytes,
            m_bytes,
            out_bytes,
        }) = vos_pvm::precompile::execute(
            u64::from(ECALL_BLAKE2B_COMPRESS),
            &registers,
            self.pvm.memory_mut(),
        )
        else {
            return false;
        };
        let ts = self.timestamp - 1;
        self.blake2b_records.push(Blake2bRecord { h, m, t, f });
        self.blake2b_mem_ops.push(Blake2bMemOp {
            h_ptr,
            m_ptr,
            ts,
            h_bytes,
            m_bytes,
            out_bytes,
        });
        true
    }

    /// Number of steps recorded so far.
    pub fn num_steps(&self) -> usize {
        self.steps.len()
    }

    /// The register file entering the first recorded step (the file the
    /// interpreter was seeded with); current registers if nothing was
    /// recorded yet.
    pub fn initial_regs(&self) -> [u64; PVM_REGISTER_COUNT] {
        self.initial_regs.unwrap_or(self.pvm.registers)
    }

    /// The recorded trace expanded to full steps (snapshots rebuilt by
    /// threading the register file from [`Self::initial_regs`]).
    pub fn trace(&self) -> Vec<PvmStep> {
        expand_steps(&self.steps, self.initial_regs())
    }

    /// Consume and return the recorded trace as full steps.
    ///
    /// This is an analysis-level escape hatch: the returned steps do not carry
    /// the precompile records. Proof-building callers should use
    /// [`Self::into_side_note`].
    pub fn into_trace(self) -> Vec<PvmStep> {
        let regs = self.initial_regs();
        expand_steps(&self.steps, regs)
    }

    /// Consume this trace into a proof [`crate::SideNote`], preserving every
    /// recorded precompile boundary.
    ///
    /// Program bytes, instruction starts and jump table come from the
    /// interpreter itself, so a caller cannot accidentally pair the recorded
    /// steps with a different static program view. Initial memory remains
    /// explicit because the interpreter contains the post-execution image;
    /// attach the saved entering image with `SideNote::with_memory`.
    pub fn into_side_note(self) -> crate::SideNote {
        let code = self.pvm.code.to_vec();
        let bitmask = self.pvm.bitmask.to_vec();
        let jump_table = self.pvm.jump_table.to_vec();
        let steps = self.trace();
        let mut side_note = crate::SideNote::new(steps, code, bitmask).with_jump_table(jump_table);
        side_note.blake2b_calls = self
            .blake2b_records
            .into_iter()
            .map(|record| crate::chips::blake2b::Blake2bCall {
                h: record.h,
                m: record.m,
                t: record.t,
                f: record.f,
            })
            .collect();
        side_note.blake2b_mem_ops = self.blake2b_mem_ops;
        side_note
    }

    /// Return recorded blake2b calls for the precompile chip.
    pub fn blake2b_calls(&self) -> &[Blake2bRecord] {
        &self.blake2b_records
    }
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
/// Extract the second immediate (`imm_y`) for
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
#[inline]
fn wrapping_effective_address(base: u64, offset: u64) -> u32 {
    // PVM addresses are cyclic N_2^32 values. Truncate each decoded operand
    // to that domain before addition so the witness calculation states the
    // same modulo-2^32 rule as execution, independently of host word width.
    (base as u32).wrapping_add(offset as u32)
}

pub(crate) fn decode_mem_access(
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
                return (
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 1,
                    }),
                    None,
                );
            }
        }
        Opcode::LoadU16 | Opcode::LoadI16 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_after[*ra];
                return (
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 2,
                    }),
                    None,
                );
            }
        }
        Opcode::LoadU32 | Opcode::LoadI32 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_after[*ra];
                return (
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 4,
                    }),
                    None,
                );
            }
        }
        Opcode::LoadU64 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_after[*ra];
                return (
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 8,
                    }),
                    None,
                );
            }
        }
        // Direct stores (A.5.6): addr = imm, value from ra
        Opcode::StoreU8 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_before[*ra] & 0xFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 1,
                    }),
                );
            }
        }
        Opcode::StoreU16 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_before[*ra] & 0xFFFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 2,
                    }),
                );
            }
        }
        Opcode::StoreU32 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_before[*ra] & 0xFFFF_FFFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 4,
                    }),
                );
            }
        }
        Opcode::StoreU64 => {
            if let args::Args::RegImm { ra, imm } = decoded_args {
                let addr = *imm as u32;
                let value = regs_before[*ra];
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 8,
                    }),
                );
            }
        }
        // Indirect loads (A.5.10): addr = φ[rb] + imm, result in ra
        Opcode::LoadIndU8 | Opcode::LoadIndI8 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*rb], *imm);
                let value = regs_after[*ra];
                return (
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 1,
                    }),
                    None,
                );
            }
        }
        Opcode::LoadIndU16 | Opcode::LoadIndI16 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*rb], *imm);
                let value = regs_after[*ra];
                return (
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 2,
                    }),
                    None,
                );
            }
        }
        Opcode::LoadIndU32 | Opcode::LoadIndI32 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*rb], *imm);
                let value = regs_after[*ra];
                return (
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 4,
                    }),
                    None,
                );
            }
        }
        Opcode::LoadIndU64 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*rb], *imm);
                let value = regs_after[*ra];
                return (
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 8,
                    }),
                    None,
                );
            }
        }
        // Indirect stores (A.5.10): addr = φ[rb] + imm, value from ra
        Opcode::StoreIndU8 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*rb], *imm);
                let value = regs_before[*ra] & 0xFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 1,
                    }),
                );
            }
        }
        Opcode::StoreIndU16 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*rb], *imm);
                let value = regs_before[*ra] & 0xFFFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 2,
                    }),
                );
            }
        }
        Opcode::StoreIndU32 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*rb], *imm);
                let value = regs_before[*ra] & 0xFFFF_FFFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 4,
                    }),
                );
            }
        }
        Opcode::StoreIndU64 => {
            if let args::Args::TwoRegImm { ra, rb, imm } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*rb], *imm);
                let value = regs_before[*ra];
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 8,
                    }),
                );
            }
        }
        // Store immediate (A.5.4): addr = imm_x, value = imm_y
        Opcode::StoreImmU8 => {
            if let args::Args::TwoImm { imm_x, imm_y } = decoded_args {
                let addr = *imm_x as u32;
                let value = *imm_y & 0xFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 1,
                    }),
                );
            }
        }
        Opcode::StoreImmU16 => {
            if let args::Args::TwoImm { imm_x, imm_y } = decoded_args {
                let addr = *imm_x as u32;
                let value = *imm_y & 0xFFFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 2,
                    }),
                );
            }
        }
        Opcode::StoreImmU32 => {
            if let args::Args::TwoImm { imm_x, imm_y } = decoded_args {
                let addr = *imm_x as u32;
                let value = *imm_y & 0xFFFF_FFFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 4,
                    }),
                );
            }
        }
        Opcode::StoreImmU64 => {
            if let args::Args::TwoImm { imm_x, imm_y } = decoded_args {
                let addr = *imm_x as u32;
                let value = *imm_y;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 8,
                    }),
                );
            }
        }
        // Store immediate indirect (A.5.7): addr = φ[ra] + imm_x, value = imm_y
        Opcode::StoreImmIndU8 => {
            if let args::Args::RegTwoImm { ra, imm_x, imm_y } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*ra], *imm_x);
                let value = *imm_y & 0xFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 1,
                    }),
                );
            }
        }
        Opcode::StoreImmIndU16 => {
            if let args::Args::RegTwoImm { ra, imm_x, imm_y } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*ra], *imm_x);
                let value = *imm_y & 0xFFFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 2,
                    }),
                );
            }
        }
        Opcode::StoreImmIndU32 => {
            if let args::Args::RegTwoImm { ra, imm_x, imm_y } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*ra], *imm_x);
                let value = *imm_y & 0xFFFF_FFFF;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 4,
                    }),
                );
            }
        }
        Opcode::StoreImmIndU64 => {
            if let args::Args::RegTwoImm { ra, imm_x, imm_y } = decoded_args {
                let addr = wrapping_effective_address(regs_before[*ra], *imm_x);
                let value = *imm_y;
                return (
                    None,
                    Some(MemAccess {
                        address: addr,
                        value,
                        size: 8,
                    }),
                );
            }
        }
        _ => {}
    }
    (None, None)
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;

    fn rejected_memory_step(opcode: Opcode, address: u64) -> (ExitReason, PvmStep) {
        let mut registers = [0u64; PVM_REGISTER_COUNT];
        registers[0] = 0x8877_6655_4433_2211;
        registers[1] = address;
        // All indirect load/store opcodes use TwoRegImm. ra=0, rb=1 and a
        // zero immediate make the requested register value the exact address.
        let code = vec![opcode as u8, 0x10, 0, 0, 0, 0];
        let bitmask = vec![1, 0, 0, 0, 0, 0];
        let pvm = Interpreter::new(
            code,
            bitmask,
            vec![],
            registers,
            vec![0; vos_pvm::PVM_ZONE_SIZE as usize],
            10_000,
        );
        let mut tracing = TracingPvm::new(pvm);
        let exit = tracing.step().expect("memory instruction must be rejected");
        let mut steps = tracing.into_trace();
        assert_eq!(steps.len(), 1);
        (exit, steps.remove(0))
    }

    #[test]
    fn rejected_memory_instructions_emit_no_access() {
        for opcode in [Opcode::LoadIndU64, Opcode::StoreIndU64] {
            let (exit, low_zone) = rejected_memory_step(opcode, 0x100);
            assert_eq!(exit, ExitReason::Panic, "{opcode:?} low-zone result");
            assert!(low_zone.mem_read.is_none(), "{opcode:?} false read");
            assert!(low_zone.mem_write.is_none(), "{opcode:?} false write");

            let (exit, unmapped) = rejected_memory_step(opcode, 2 * vos_pvm::PVM_ZONE_SIZE as u64);
            assert_eq!(
                exit,
                ExitReason::PageFault(2 * vos_pvm::PVM_ZONE_SIZE),
                "{opcode:?} unmapped result"
            );
            assert!(unmapped.mem_read.is_none(), "{opcode:?} false read");
            assert!(unmapped.mem_write.is_none(), "{opcode:?} false write");
        }
    }

    #[test]
    fn indirect_trace_address_is_cyclic_u32() {
        let mut before = [0u64; PVM_REGISTER_COUNT];
        let mut after = before;
        before[1] = 0x1234_5678_ffff_fffe;
        after[2] = 0xa5;
        let args = args::Args::TwoRegImm {
            ra: 2,
            rb: 1,
            imm: 4,
        };

        let (read, write) = decode_mem_access(Opcode::LoadIndU8, &args, &before, &after);
        assert!(write.is_none());
        assert_eq!(read.expect("load access").address, 2);
    }

    #[test]
    fn conformance_trace_retains_the_full_ecalli_identifier() {
        let cases: &[(&[u8], u64)] = &[
            (&[0xff], u64::MAX),
            (&[0x00, 0x00, 0x00, 0x80], 0xffff_ffff_8000_0000),
        ];

        for (immediate, expected) in cases {
            let mut code = vec![Opcode::Ecalli as u8];
            code.extend_from_slice(immediate);
            code.push(Opcode::Trap as u8);
            let mut bitmask = vec![1];
            bitmask.extend(core::iter::repeat_n(0, immediate.len()));
            bitmask.push(1);
            let pvm = Interpreter::new(
                code,
                bitmask,
                vec![],
                [0; PVM_REGISTER_COUNT],
                vec![0; vos_pvm::PVM_ZONE_SIZE as usize],
                10_000,
            );
            let mut tracing = TracingPvm::new(pvm);
            assert_eq!(tracing.run(), ExitReason::HostCall(*expected));
            let trace = tracing.into_trace();
            assert_eq!(trace.len(), 1);
            assert_eq!(trace[0].imm, *expected, "witness immediate");
        }
    }

    #[test]
    fn precompile_call_is_acknowledged_before_continuing() {
        let [low, high, ..] = ECALL_BLAKE2B_COMPRESS.to_le_bytes();
        let code = vec![Opcode::Ecalli as u8, low, high, Opcode::Trap as u8];
        let bitmask = vec![1, 0, 0, 1];
        let pvm = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; PVM_REGISTER_COUNT],
            vec![0; vos_pvm::PVM_ZONE_SIZE as usize],
            10_000,
        );
        let mut tracing = TracingPvm::new(pvm);

        assert_eq!(tracing.step_with_precompiles(), None);
        assert_eq!(tracing.pvm.pc, 3, "handled call must advance exactly once");
        assert!(tracing.pvm.pending_host_call().is_none());
        assert_eq!(
            tracing.trace()[0].next_pc,
            3,
            "acknowledged row must produce the continuation PC",
        );
        assert!(
            tracing.trace()[0].host_call_acknowledged,
            "acknowledgment disposition must survive compact expansion",
        );
        assert_eq!(tracing.step_with_precompiles(), Some(ExitReason::Panic));
        assert_eq!(tracing.num_steps(), 2, "execution must not replay ecalli");
    }

    #[test]
    fn unknown_standard_host_call_retains_cause_pc_in_trace() {
        let code = vec![Opcode::Ecalli as u8, 11, Opcode::Trap as u8];
        let bitmask = vec![1, 0, 1];
        let pvm = Interpreter::new(
            code,
            bitmask,
            vec![],
            [0; PVM_REGISTER_COUNT],
            vec![0; vos_pvm::PVM_ZONE_SIZE as usize],
            10_000,
        );
        let mut tracing = TracingPvm::new(pvm);

        assert_eq!(tracing.run_with_precompiles(), ExitReason::HostCall(11));
        assert_eq!(tracing.pvm.pc, 0, "unhandled call must remain pending");
        assert_eq!(
            tracing.pvm.pending_host_call(),
            Some(vos_pvm::PendingHostCall {
                id: 11,
                cause_pc: 0,
                resume_pc: 2,
            }),
        );
        let trace = tracing.into_trace();
        assert_eq!(trace.len(), 1);
        assert_eq!(
            trace[0].next_pc, 0,
            "unhandled row must expose the cause PC",
        );
    }
}

/// Decode register indices from decoded instruction arguments.
/// The register write a step records: the register its opcode writes when
/// it executed, even if it wrote the value the register held (the proof
/// fixes each instruction's write), and otherwise what it changed, if
/// anything. A dynamic jump to the halt address executes, writing before it
/// jumps; a step the machine stopped (out of gas, a fault, a trap, a host
/// call) does not. An error when the step changed a register other than
/// that one, or more than one.
pub(crate) fn recorded_write(
    opcode: Opcode,
    (reg_a, reg_b, reg_d): (usize, usize, usize),
    regs_before: &[u64; PVM_REGISTER_COUNT],
    regs_after: &[u64; PVM_REGISTER_COUNT],
    exit: Option<&ExitReason>,
) -> Result<Option<usize>, &'static str> {
    let mut changed = (0..PVM_REGISTER_COUNT).filter(|&i| regs_before[i] != regs_after[i]);
    let first = changed.next();
    if changed.next().is_some() {
        return Err("one instruction changed more than one register");
    }
    if exit.is_some() && exit != Some(&ExitReason::Halt) {
        return Ok(first);
    }
    let destination =
        crate::chips::cpu::static_destination(opcode, reg_a, reg_b, reg_d, regs_before);
    if first.is_some() && first != destination {
        return Err("an instruction changed a register other than its destination");
    }
    Ok(destination)
}

pub(crate) fn decode_reg_indices(
    _opcode: Opcode,
    decoded_args: &args::Args,
) -> (usize, usize, usize) {
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
