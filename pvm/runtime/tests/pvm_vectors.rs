//! PVM instruction-level conformance vectors.
//!
//! Two deliberately separate corpora are checked in:
//!
//! - `tests/vectors/*.gp072.json` preserves the historical GP 0.7.2/Jar
//!   fixtures. Its unary family uses the frozen capability-manifest opcode
//!   numbering and is never presented as current conformance coverage.
//! - `tests/vectors-v080/*.gp080.json` pins the Gray Paper v0.8.0 standard
//!   machine. Every case runs in [`IsaMode::Conformance`]. It covers every
//!   instruction family, control-flow and gas boundaries, memory widths and
//!   faults, arithmetic edge cases, and the complete renumbered unary family.
//!
//! Both corpora pin instruction semantics case-by-case: pre/post register file,
//! memory effects, page-fault classification (page-base addresses), the
//! basic-block strictness of branches/djumps, and gas under the
//! per-instruction model (`GasModel::PerInstruction` — a flat 1 gas per
//! instruction, the model the gp072 Lean variants pin).
//!
//! Provenance: the v0.8 opcode/category/terminator manifest below is a frozen
//! transcription of Appendix A.5 and equations A.19/A.20 of the official
//! `gavofyork/graypaper` v0.8.0 release. Every executable case is synthesized
//! by the hand-written tables in this file — code bytes, bitmask, and
//! *expected outcomes* are hand-derived from that specification, never
//! recorded from an implementation run. No third-party vector data is copied
//! (the canonical `w3f/jamtestvectors` repository has no PVM instruction
//! corpus). The cross-check is differential: every vector
//! must satisfy the interpreter under per-instruction gas, AND (on
//! linux-x86_64) the JIT recompiler, AND the interpreter under block gas —
//! with block-gas consumption asserted equal between interpreter and
//! recompiler (the deterministic slice of the fuzz harness's parity
//! contract).
//!
//! Schema (one self-contained JSON file per case):
//! ```json
//! {
//!   "name": "alu64_add_64",
//!   "family": "alu64",
//!   "program": { "code": "0x…", "bitmask": "0x…", "jump_table": [5] },
//!   "initial": {
//!     "pc": 0, "gas": 100, "regs": ["0x0", …13],
//!     "page_map": [{ "address": 65536, "length": 4096, "access": "ro" }],
//!     "memory":   [{ "address": 65536, "contents": "0x8182…" }]
//!   },
//!   "expected": {
//!     "status": "trap", "pc": 3, "gas": 98, "regs": ["0x0", …13],
//!     "memory": [{ "address": …, "contents": "0x…" }],
//!     "page_fault_address": 4096,   // iff status == "page_fault"
//!     "host_call": 7                // iff status == "host_call"
//!   },
//!   "backends": ["interpreter", "recompiler"]
//! }
//! ```
//! - `bitmask` is packed 1 bit per code byte, LSB-first (deblob packing).
//! - `regs` are 13 `0x…` hex strings (φ0..φ12); addresses/gas are numbers.
//! - `status` ∈ halt | trap | panic | out_of_gas | page_fault | host_call.
//!   `trap` is the transitional JAR profile's deliberate-opcode-0 exit;
//!   standard v0.8 vectors require the exact panic ☇ result. Vectors whose
//!   outcome depends on the gas
//!   model (out-of-gas cases) list only the interpreter backend.
//! - `expected.gas` is the REMAINING gas under the per-instruction model.
//! - `expected.pc` is checked on the interpreter and, for every valid
//!   standard-profile program, on the recompiler. Full v0.8 Ψ normalizes
//!   halt/panic to zero and retains the causing counter for host/fault/OOG.
//!   Standard registers, counters and every mapped memory byte are compared
//!   corpus-wide at all exits, including panic, fault and out-of-gas.
//!
//! Re-bless (regenerates the corpus from the table below):
//! ```bash
//! VOS_PVM_BLESS_VECTORS=1 cargo test -p vos-pvm --test pvm_vectors
//! ```

use serde_json::{Value, json};
use std::path::PathBuf;
use vos_pvm::gas_cost::DEFAULT_MEM_CYCLES;
use vos_pvm::instruction::{InstructionCategory, Opcode};
use vos_pvm::interpreter::{Interpreter, Memory, PERM_NONE, PERM_RO, PERM_RW};
use vos_pvm::{ExitReason, GasModel, IsaMode, PVM_HALT_ADDR};

/// Base of the read-only page every memory case maps.
const RO_BASE: u32 = 0x10000;
/// Base of the read-write page every memory case maps.
const RW_BASE: u32 = 0x20000;
/// One 4 KiB page.
const PAGE: u32 = 4096;
/// Default gas budget for funded cases.
const GAS: u64 = 100;
/// Reviewed cardinality of the complete v0.8 semantic transition corpus.
const V080_CASE_COUNT: usize = 173;
/// The three per-instruction OOG cases intentionally do not run on the JIT.
const V080_RECOMPILER_CASE_COUNT: usize = 170;
/// Reviewed cardinality of the independently derived block-gas oracle.
const V080_BLOCK_GAS_CASE_COUNT: usize = 16;

/// The 16 seed bytes at `RO_BASE`: 0x81..=0x90 (high bits set, so
/// zero- vs sign-extension of loads is observable).
fn ro_seed() -> Vec<u8> {
    (0..16).map(|i| 0x81 + i).collect()
}

/// One synthesized conformance case. `exp_gas` is the remaining gas under
/// the per-instruction model; `exp_regs` is the full post register file.
struct Case {
    name: String,
    family: &'static str,
    code: Vec<u8>,
    /// Unpacked bitmask, one byte per code byte (1 = instruction start).
    bitmask: Vec<u8>,
    jump_table: Vec<u32>,
    regs: [u64; 13],
    gas: u64,
    /// (base address, length, perm) — page-aligned regions.
    page_map: Vec<(u32, u32, u8)>,
    /// (address, bytes) seeded before execution.
    memory: Vec<(u32, Vec<u8>)>,
    exp_status: ExitReason,
    exp_pc: u32,
    exp_gas: u64,
    exp_regs: [u64; 13],
    /// (address, bytes) asserted after execution.
    exp_memory: Vec<(u32, Vec<u8>)>,
    /// Whether the recompiler leg runs this case (false for gas-model-
    /// specific outcomes, i.e. out-of-gas under per-instruction charging).
    recompiler: bool,
}

/// Assemble instructions into (code, unpacked bitmask).
fn asm(instrs: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
    let mut code = Vec::new();
    let mut bits = Vec::new();
    for inst in instrs {
        bits.push(1);
        bits.extend(std::iter::repeat_n(0, inst.len() - 1));
        code.extend_from_slice(inst);
    }
    (code, bits)
}

/// A default case: no memory, zeroed registers, budget [`GAS`], expected
/// to end in a deliberate trap with no register effects. Constructors
/// override what their instruction changes.
fn base(family: &'static str, name: &str, program: (Vec<u8>, Vec<u8>)) -> Case {
    Case {
        name: format!("{family}_{name}"),
        family,
        code: program.0,
        bitmask: program.1,
        jump_table: vec![],
        regs: [0; 13],
        gas: GAS,
        page_map: vec![],
        memory: vec![],
        exp_status: ExitReason::Trap,
        exp_pc: 0,
        exp_gas: GAS,
        exp_regs: [0; 13],
        exp_memory: vec![],
        recompiler: true,
    }
}

/// Three-register ALU case: `[op, 0x32, 4]` = φ4 ← φ2 op φ3, then trap.
/// Two instructions: trap at pc 3, 2 gas.
fn alu3(family: &'static str, name: &str, op: u8, a: u64, b: u64, want: u64) -> Case {
    let mut c = base(family, name, asm(&[&[op, 0x32, 4], &[0]]));
    c.regs[2] = a;
    c.regs[3] = b;
    c.exp_regs = c.regs;
    c.exp_regs[4] = want;
    c.exp_pc = 3;
    c.exp_gas = GAS - 2;
    c
}

/// Like [`alu3`] but with a preloaded destination φ4 (for cmov cases).
fn alu3_dst(family: &'static str, name: &str, op: u8, a: u64, b: u64, dst: u64, want: u64) -> Case {
    let mut c = alu3(family, name, op, a, b, want);
    c.regs[4] = dst;
    c.exp_regs = c.regs;
    c.exp_regs[4] = want;
    c
}

/// Two-register-one-immediate ALU case with a 1-byte immediate:
/// `[op, 0x32, imm]` = φ2 ← f(φ3, sext₁(imm)), then trap.
fn alu_imm(family: &'static str, name: &str, op: u8, b: u64, imm: u8, want: u64) -> Case {
    let mut c = base(family, name, asm(&[&[op, 0x32, imm], &[0]]));
    c.regs[3] = b;
    c.exp_regs = c.regs;
    c.exp_regs[2] = want;
    c.exp_pc = 3;
    c.exp_gas = GAS - 2;
    c
}

/// Two-register (unary) case: `[op, 0x34]` = φ4 ← f(φ3), then trap.
fn unary(family: &'static str, name: &str, op: u8, src: u64, want: u64) -> Case {
    let mut c = base(family, name, asm(&[&[op, 0x34], &[0]]));
    c.regs[3] = src;
    c.exp_regs = c.regs;
    c.exp_regs[4] = want;
    c.exp_pc = 2;
    c.exp_gas = GAS - 2;
    c
}

/// The standard memory map: one RO page at [`RO_BASE`] seeded with
/// [`ro_seed`], one zeroed RW page at [`RW_BASE`].
fn with_memory(mut c: Case) -> Case {
    c.page_map = vec![(RO_BASE, PAGE, PERM_RO), (RW_BASE, PAGE, PERM_RW)];
    c.memory = vec![(RO_BASE, ro_seed())];
    c
}

/// Absolute load from `RO_BASE + off`: `[op, 2, addr₃]` = φ2 ← mem, trap.
fn abs_load(family: &'static str, name: &str, op: u8, off: u32, want: u64) -> Case {
    let addr = (RO_BASE + off).to_le_bytes();
    let mut c = base(
        family,
        name,
        asm(&[&[op, 2, addr[0], addr[1], addr[2]], &[0]]),
    );
    c.exp_regs[2] = want;
    c.exp_pc = 5;
    c.exp_gas = GAS - 2;
    with_memory(c)
}

fn abs_store_imm(name: &str, op: u8, immediate: &[u8], want: &[u8]) -> Case {
    let address = RW_BASE.to_le_bytes();
    let mut instruction = vec![op, 3, address[0], address[1], address[2]];
    instruction.extend_from_slice(immediate);
    let mut c = base("store", name, asm(&[&instruction, &[0]]));
    c.exp_pc = instruction.len() as u32;
    c.exp_gas = GAS - 2;
    c.exp_memory = vec![(RW_BASE, want.to_vec())];
    with_memory(c)
}

fn abs_store_reg(name: &str, op: u8, value: u64, want: &[u8]) -> Case {
    let address = RW_BASE.to_le_bytes();
    let instruction = [op, 2, address[0], address[1], address[2]];
    let mut c = base("store", name, asm(&[&instruction, &[0]]));
    c.regs[2] = value;
    c.exp_regs = c.regs;
    c.exp_pc = instruction.len() as u32;
    c.exp_gas = GAS - 2;
    c.exp_memory = vec![(RW_BASE, want.to_vec())];
    with_memory(c)
}

fn store_imm_ind(name: &str, op: u8, immediate: &[u8], want: &[u8]) -> Case {
    // r2 + 0x20; high nibble 1 means a one-byte address offset.
    let mut instruction = vec![op, 0x12, 0x20];
    instruction.extend_from_slice(immediate);
    let mut c = base("store", name, asm(&[&instruction, &[0]]));
    c.regs[2] = RW_BASE as u64;
    c.exp_regs = c.regs;
    c.exp_pc = instruction.len() as u32;
    c.exp_gas = GAS - 2;
    c.exp_memory = vec![(RW_BASE + 0x20, want.to_vec())];
    with_memory(c)
}

fn store_ind(name: &str, op: u8, value: u64, want: &[u8]) -> Case {
    // mem[r2 + 0x10] <- r3.
    let instruction = [op, 0x23, 0x10];
    let mut c = base("store", name, asm(&[&instruction, &[0]]));
    c.regs[2] = RW_BASE as u64;
    c.regs[3] = value;
    c.exp_regs = c.regs;
    c.exp_pc = instruction.len() as u32;
    c.exp_gas = GAS - 2;
    c.exp_memory = vec![(RW_BASE + 0x10, want.to_vec())];
    with_memory(c)
}

fn load_ind(name: &str, op: u8, want: u64) -> Case {
    // r2 <- mem[r3 + 0].
    let instruction = [op, 0x32, 0];
    let mut c = base("load", name, asm(&[&instruction, &[0]]));
    c.regs[3] = RO_BASE as u64;
    c.exp_regs = c.regs;
    c.exp_regs[2] = want;
    c.exp_pc = instruction.len() as u32;
    c.exp_gas = GAS - 2;
    with_memory(c)
}

/// A memory access (2-instruction program, access first) that faults at
/// `fault_page` on the first instruction: 1 gas, pc 0, no effects.
fn faulting(mut c: Case, fault_page: u32) -> Case {
    c.exp_status = ExitReason::PageFault(fault_page);
    c.exp_pc = 0;
    c.exp_gas = GAS - 1;
    c.exp_regs = c.regs;
    with_memory(c)
}

/// Immediate branch (A.5.8) template: `[op, 0x12, imm, 6]` at pc 0 with
/// traps at pc 4/5, `load_imm φ5 ← 1` at the taken target pc 6, trap at
/// pc 9. Taken ⇒ φ5 = 1, trap at pc 9, 3 gas; not taken ⇒ trap at pc 4,
/// 2 gas.
fn branch_imm(family: &'static str, name: &str, op: u8, a: u64, imm: u8, taken: bool) -> Case {
    let mut c = base(
        family,
        name,
        asm(&[&[op, 0x12, imm, 6], &[0], &[0], &[51, 5, 1], &[0]]),
    );
    c.regs[2] = a;
    c.exp_regs = c.regs;
    if taken {
        c.exp_regs[5] = 1;
        c.exp_pc = 9;
        c.exp_gas = GAS - 3;
    } else {
        c.exp_pc = 4;
        c.exp_gas = GAS - 2;
    }
    c
}

/// Register-register branch (A.5.11) template: `[op, 0x32, 6]` at pc 0
/// (φ2 vs φ3), traps at pc 3/4/5, `load_imm φ5 ← 1` at the taken target
/// pc 6, trap at pc 9.
fn branch_reg(family: &'static str, name: &str, op: u8, a: u64, b: u64, taken: bool) -> Case {
    let mut c = base(
        family,
        name,
        asm(&[&[op, 0x32, 6], &[0], &[0], &[0], &[51, 5, 1], &[0]]),
    );
    c.regs[2] = a;
    c.regs[3] = b;
    c.exp_regs = c.regs;
    if taken {
        c.exp_regs[5] = 1;
        c.exp_pc = 9;
        c.exp_gas = GAS - 3;
    } else {
        c.exp_pc = 3;
        c.exp_gas = GAS - 2;
    }
    c
}

/// jump_ind through φ2 (`[50, 2]` then trap): panic cases share this.
fn jump_ind_panic(name: &str, a: u64, jump_table: Vec<u32>) -> Case {
    let mut c = base("djump", name, asm(&[&[50, 2], &[0]]));
    c.jump_table = jump_table;
    c.regs[2] = a;
    c.exp_regs = c.regs;
    c.exp_status = ExitReason::Panic;
    c.exp_pc = 0;
    c.exp_gas = GAS - 1;
    c
}

/// The hand-written conformance corpus. Every expected value is derived
/// from the graypaper / Lean oracle semantics by hand — see the case
/// comments for the judgement each one pins.
#[allow(clippy::vec_init_then_push)]
fn corpus() -> Vec<Case> {
    let mut v: Vec<Case> = Vec::new();

    // --- flow: termination, host calls, invalid opcodes, gas edges ---
    {
        let mut c = base("flow", "trap", asm(&[&[0]]));
        c.exp_gas = GAS - 1;
        v.push(c);

        let mut c = base("flow", "fallthrough", asm(&[&[1], &[0]]));
        c.exp_pc = 1;
        c.exp_gas = GAS - 2;
        v.push(c);

        let mut c = base("flow", "unlikely", asm(&[&[2], &[0]]));
        c.exp_pc = 1;
        c.exp_gas = GAS - 2;
        v.push(c);

        // The historical per-instruction/JAR adapter exposes its already-
        // advanced host-call PC; the v0.8 corpus below rewrites this to the
        // causing instruction counter required by full Ψ.
        let mut c = base("flow", "ecalli", asm(&[&[10, 7]]));
        c.exp_status = ExitReason::HostCall(7);
        c.exp_pc = 2;
        c.exp_gas = GAS - 1;
        v.push(c);

        // Opcode 3 (jar's Ecall) is not a GP instruction: panic under the
        // conformance ISA profile.
        let mut c = base("flow", "ecall_panics_under_conformance", asm(&[&[3]]));
        c.exp_status = ExitReason::Panic;
        c.exp_gas = GAS - 1;
        v.push(c);

        // 77 is not in the opcode table: executing it panics (charged).
        let mut c = base("flow", "invalid_opcode_panics", asm(&[&[77]]));
        c.exp_status = ExitReason::Panic;
        c.exp_gas = GAS - 1;
        v.push(c);

        // GP: the bitmask beyond the code is all-set and ζ zero-extends, so
        // sequential flow past the end executes opcode 0 = trap (charged).
        let mut c = base("flow", "fall_off_end_traps", asm(&[&[1]]));
        c.exp_pc = 1;
        c.exp_gas = GAS - 2;
        v.push(c);

        // Degenerate: an empty program immediately hits the implicit trap.
        let mut c = base("flow", "empty_program_traps", (vec![], vec![]));
        c.exp_gas = GAS - 1;
        v.push(c);

        // Per-instruction OOG: budget 5 executes exactly 5 fallthroughs;
        // the 6th (pc 5) is never executed and remaining gas is 0.
        // Gas-model-specific ⇒ interpreter only.
        let mut c = base(
            "flow",
            "out_of_gas_straight_line",
            (vec![1; 10], vec![1; 10]),
        );
        c.gas = 5;
        c.exp_status = ExitReason::OutOfGas;
        c.exp_pc = 5;
        c.exp_gas = 0;
        c.recompiler = false;
        v.push(c);

        // A zero budget is out of gas before executing anything — the gas
        // check precedes even opcode validation.
        let mut c = base("flow", "out_of_gas_zero_budget", asm(&[&[0]]));
        c.gas = 0;
        c.exp_status = ExitReason::OutOfGas;
        c.exp_pc = 0;
        c.exp_gas = 0;
        c.recompiler = false;
        v.push(c);
    }

    // --- load_imm ---
    {
        let mut c = base("load_imm", "load_imm", asm(&[&[51, 2, 42], &[0]]));
        c.exp_regs[2] = 42;
        c.exp_pc = 3;
        c.exp_gas = GAS - 2;
        v.push(c);

        // 1-byte immediates sign-extend (X₁): 0xFF ⇒ 2⁶⁴−1.
        let mut c = base(
            "load_imm",
            "load_imm_sign_extends",
            asm(&[&[51, 2, 0xFF], &[0]]),
        );
        c.exp_regs[2] = u64::MAX;
        c.exp_pc = 3;
        c.exp_gas = GAS - 2;
        v.push(c);

        // load_imm_64 takes a raw 8-byte LE immediate, no extension.
        let imm = 0x123456789ABCDEF0u64.to_le_bytes();
        let mut inst = vec![20, 2];
        inst.extend_from_slice(&imm);
        let mut c = base("load_imm", "load_imm_64", asm(&[&inst, &[0]]));
        c.exp_regs[2] = 0x123456789ABCDEF0;
        c.exp_pc = 10;
        c.exp_gas = GAS - 2;
        v.push(c);
    }

    // --- alu64 ---
    {
        v.push(alu3("alu64", "add_64", 200, 7, 5, 12));
        v.push(alu3("alu64", "add_64_wraps", 200, u64::MAX, 1, 0));
        // sub is φ2 − φ3; underflow wraps.
        v.push(alu3("alu64", "sub_64_underflows", 201, 5, 7, u64::MAX - 1));
        v.push(alu3("alu64", "and", 210, 0xC, 0xA, 0x8));
        v.push(alu3("alu64", "or", 212, 0xC, 0xA, 0xE));
        v.push(alu3("alu64", "xor", 211, 0xC, 0xA, 0x6));
        v.push(alu3("alu64", "and_inv", 224, 0xC, 0xA, 0x4));
        v.push(alu3(
            "alu64",
            "or_inv",
            225,
            0xC,
            0xA,
            0xFFFF_FFFF_FFFF_FFFD,
        ));
        v.push(alu3("alu64", "xnor", 226, 0xC, 0xA, 0xFFFF_FFFF_FFFF_FFF9));
        // 7 < 2⁶⁴−5 unsigned, but 7 > −5 signed: the pair pins signedness.
        let neg5 = (-5i64) as u64;
        v.push(alu3("alu64", "set_lt_u", 216, 7, neg5, 1));
        v.push(alu3("alu64", "set_lt_s", 217, 7, neg5, 0));
        let neg3 = (-3i64) as u64;
        v.push(alu3("alu64", "max", 227, neg3, 2, 2));
        v.push(alu3("alu64", "max_u", 228, neg3, 2, neg3));
        v.push(alu3("alu64", "min", 229, neg3, 2, neg3));
        v.push(alu3("alu64", "min_u", 230, neg3, 2, 2));
        // cmov: φ4 ← φ2 iff φ3 ==/!= 0; otherwise φ4 keeps its value.
        v.push(alu3_dst("alu64", "cmov_iz_taken", 218, 7, 0, 111, 7));
        v.push(alu3_dst("alu64", "cmov_iz_not_taken", 218, 7, 1, 111, 111));
        v.push(alu3_dst("alu64", "cmov_nz_taken", 219, 7, 1, 111, 7));
        // add_imm_64: φ2 ← φ3 + sext(imm).
        v.push(alu_imm("alu64", "add_imm_64_negative", 149, 10, 0xFF, 9));
        // neg_add_imm_64: φ2 ← imm − φ3 (operand order is the point).
        v.push(alu_imm("alu64", "neg_add_imm_64", 154, 7, 5, u64::MAX - 1));
    }

    // --- alu32: 32-bit ops truncate inputs and sign-extend results ---
    {
        v.push(alu3(
            "alu32",
            "add_32_sign_extends",
            190,
            0x7FFF_FFFF,
            1,
            0xFFFF_FFFF_8000_0000,
        ));
        v.push(alu3(
            "alu32",
            "add_32_truncates_inputs",
            190,
            0x1_0000_0001,
            2,
            3,
        ));
        v.push(alu3("alu32", "sub_32_underflows", 191, 0, 1, u64::MAX));
        v.push(alu3(
            "alu32",
            "mul_32",
            192,
            3,
            0xFFFF_FFFE,
            0xFFFF_FFFF_FFFF_FFFA,
        ));
        v.push(alu_imm(
            "alu32",
            "add_imm_32_wraps_to_zero",
            131,
            0xFFFF_FFFF,
            1,
            0,
        ));
    }

    // --- shift: SharR sign-fill, mod-width amounts, 32-bit sign-extension ---
    {
        let top = 0x8000_0000_0000_0000u64;
        v.push(alu3(
            "shift",
            "shar_r_64_sign_fills",
            209,
            top,
            63,
            u64::MAX,
        ));
        v.push(alu3("shift", "shlo_r_64_zero_fills", 208, top, 63, 1));
        // Shift amounts are mod 64: 127 ≡ 63.
        v.push(alu3("shift", "shlo_l_64_amount_mod_64", 207, 1, 127, top));
        v.push(alu3(
            "shift",
            "shar_r_32_sign_fills",
            199,
            0x8000_0000,
            31,
            u64::MAX,
        ));
        // 63 ≡ 31 mod 32; the 32-bit result 0x80000000 sign-extends.
        v.push(alu3(
            "shift",
            "shlo_l_32_mod_32_sign_extends",
            197,
            1,
            63,
            0xFFFF_FFFF_8000_0000,
        ));
        // Immediate arithmetic shift right, sign-filling.
        v.push(alu_imm(
            "shift",
            "shar_r_imm_64",
            153,
            top,
            4,
            0xF800_0000_0000_0000,
        ));
        // Alt form swaps operands (φ2 ← sext(imm) >>ₐ φ3) AND the 1-byte
        // immediate sign-extends: 0x80 ⇒ −128; −128 >>ₐ 4 = −8.
        v.push(alu_imm(
            "shift",
            "shar_r_imm_alt_64",
            157,
            4,
            0x80,
            (-8i64) as u64,
        ));
        v.push(alu3("shift", "rot_r_64", 222, 1, 1, top));
        // 32-bit rotate: result sign-extends (0x80000000 ⇒ 0xFFFFFFFF80000000).
        v.push(alu_imm(
            "shift",
            "rot_r_32_imm_sign_extends",
            160,
            1,
            1,
            0xFFFF_FFFF_8000_0000,
        ));
    }

    // --- muldiv: wrap, upper halves, and the GP div/rem edge cases ---
    {
        let two32 = 1u64 << 32;
        v.push(alu3("muldiv", "mul_64_wraps", 202, two32, two32, 0));
        v.push(alu3("muldiv", "mul_upper_u_u", 214, two32, two32, 1));
        // (−2³²)·(2³²) = −2⁶⁴ ⇒ upper 64 bits are −1.
        v.push(alu3(
            "muldiv",
            "mul_upper_s_s",
            213,
            (-(1i64 << 32)) as u64,
            two32,
            u64::MAX,
        ));
        // signed −1 × unsigned 2 = −2 ⇒ upper −1.
        v.push(alu3("muldiv", "mul_upper_s_u", 215, u64::MAX, 2, u64::MAX));
        v.push(alu3("muldiv", "div_u_64", 203, 35, 5, 7));
        // GP: division by zero yields 2⁶⁴−1.
        v.push(alu3("muldiv", "div_u_64_by_zero", 203, 35, 0, u64::MAX));
        v.push(alu3(
            "muldiv",
            "div_s_64",
            204,
            (-35i64) as u64,
            5,
            (-7i64) as u64,
        ));
        // GP: i64::MIN / −1 overflows to i64::MIN.
        v.push(alu3(
            "muldiv",
            "div_s_64_overflow",
            204,
            i64::MIN as u64,
            u64::MAX,
            i64::MIN as u64,
        ));
        v.push(alu3("muldiv", "rem_u_64", 205, 37, 5, 2));
        // GP: remainder by zero yields the dividend.
        v.push(alu3("muldiv", "rem_u_64_by_zero", 205, 37, 0, 37));
        // Signed remainder takes the dividend's sign.
        v.push(alu3(
            "muldiv",
            "rem_s_64_dividend_sign",
            206,
            (-37i64) as u64,
            5,
            (-2i64) as u64,
        ));
        v.push(alu3(
            "muldiv",
            "rem_s_64_overflow",
            206,
            i64::MIN as u64,
            u64::MAX,
            0,
        ));
        // 32-bit division truncates its inputs to u32 first.
        v.push(alu3(
            "muldiv",
            "div_u_32_truncates_inputs",
            193,
            0x1_0000_0007,
            3,
            2,
        ));
        v.push(alu3(
            "muldiv",
            "div_s_32_overflow",
            194,
            0x8000_0000,
            u64::MAX,
            0xFFFF_FFFF_8000_0000,
        ));
        v.push(alu3("muldiv", "rem_u_32_by_zero", 195, 0x1_0000_0007, 0, 7));
    }

    // --- unary (two-register forms) ---
    {
        v.push(unary("unary", "move_reg", 100, 0xDEAD_BEEF, 0xDEAD_BEEF));
        v.push(unary("unary", "count_set_bits_64", 102, 0xF0F0, 8));
        v.push(unary("unary", "leading_zero_bits_64", 104, 1, 63));
        v.push(unary("unary", "leading_zero_bits_32", 105, 1, 31));
        v.push(unary(
            "unary",
            "trailing_zero_bits_64",
            106,
            0x8000_0000_0000_0000,
            63,
        ));
        // The 32-bit view of 2³² is 0: ctz of zero is the full width.
        v.push(unary(
            "unary",
            "trailing_zero_bits_32_of_zero",
            107,
            1 << 32,
            32,
        ));
        v.push(unary(
            "unary",
            "sign_extend_8",
            108,
            0x1F80,
            0xFFFF_FFFF_FFFF_FF80,
        ));
        v.push(unary(
            "unary",
            "sign_extend_16",
            109,
            0x1_8000,
            0xFFFF_FFFF_FFFF_8000,
        ));
        v.push(unary("unary", "zero_extend_16", 110, 0xFFFF_8000, 0x8000));
        v.push(unary(
            "unary",
            "reverse_bytes",
            111,
            0x0102_0304_0506_0708,
            0x0807_0605_0403_0201,
        ));
    }

    // --- load: widths, extensions, indirect addressing, faults ---
    {
        v.push(abs_load("load", "load_u8", 52, 0, 0x81));
        v.push(abs_load("load", "load_i8", 53, 0, 0xFFFF_FFFF_FFFF_FF81));
        v.push(abs_load("load", "load_u16", 54, 0, 0x8281));
        v.push(abs_load("load", "load_i16", 55, 0, 0xFFFF_FFFF_FFFF_8281));
        v.push(abs_load("load", "load_u32", 56, 0, 0x8483_8281));
        v.push(abs_load("load", "load_i32", 57, 0, 0xFFFF_FFFF_8483_8281));
        v.push(abs_load("load", "load_u64", 58, 0, 0x8887_8685_8483_8281));

        // load_ind_u32: φ2 ← mem[φ3 + 4].
        let mut c = base("load", "load_ind_u32", asm(&[&[128, 0x32, 4], &[0]]));
        c.regs[3] = RO_BASE as u64;
        c.exp_regs = c.regs;
        c.exp_regs[2] = 0x8887_8685;
        c.exp_pc = 3;
        c.exp_gas = GAS - 2;
        v.push(with_memory(c));

        // Negative indirect offset with i16 sign-extension of the value.
        let mut c = base(
            "load",
            "load_ind_i16_negative_offset",
            asm(&[&[127, 0x32, 0xFE], &[0]]),
        );
        c.regs[3] = RO_BASE as u64 + 8;
        c.exp_regs = c.regs;
        c.exp_regs[2] = 0xFFFF_FFFF_FFFF_8887; // mem[RO_BASE+6..8] = 87 88
        c.exp_pc = 3;
        c.exp_gas = GAS - 2;
        v.push(with_memory(c));

        // Faults classify with the page base of the first failing page.
        let c = base("load", "load_fault_unmapped_low", asm(&[&[58, 2], &[0]]));
        v.push(faulting(c, 0));

        let c = base(
            "load",
            "load_fault_unmapped_gap",
            asm(&[&[52, 2, 0x00, 0x10, 0x01], &[0]]),
        );
        v.push(faulting(c, 0x11000));

        // A u64 load at RO_BASE+0xFFC touches the readable RO page AND the
        // unmapped page after it: the fault reports the second page.
        let c = base(
            "load",
            "load_fault_cross_page",
            asm(&[&[58, 2, 0xFC, 0x0F, 0x01], &[0]]),
        );
        v.push(faulting(c, 0x11000));
    }

    // --- store: widths, imm/ind forms, RO + unmapped faults, atomicity ---
    {
        // store_imm_u8: mem[0x20000] ← 0xAB.
        let mut c = base(
            "store",
            "store_imm_u8",
            asm(&[&[30, 3, 0x00, 0x00, 0x02, 0xAB], &[0]]),
        );
        c.exp_pc = 6;
        c.exp_gas = GAS - 2;
        c.exp_memory = vec![(RW_BASE, vec![0xAB])];
        v.push(with_memory(c));

        // store_u64 writes all 8 bytes little-endian.
        let mut c = base(
            "store",
            "store_u64",
            asm(&[&[62, 2, 0x00, 0x00, 0x02], &[0]]),
        );
        c.regs[2] = 0x1122_3344_5566_7788;
        c.exp_regs = c.regs;
        c.exp_pc = 5;
        c.exp_gas = GAS - 2;
        c.exp_memory = vec![(
            RW_BASE,
            vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        )];
        v.push(with_memory(c));

        // store_ind_u8: mem[φ2 + 0x10] ← φ3 (low byte).
        let mut c = base("store", "store_ind_u8", asm(&[&[120, 0x23, 0x10], &[0]]));
        c.regs[2] = RW_BASE as u64;
        c.regs[3] = 0xCD;
        c.exp_regs = c.regs;
        c.exp_pc = 3;
        c.exp_gas = GAS - 2;
        c.exp_memory = vec![(RW_BASE + 0x10, vec![0xCD])];
        v.push(with_memory(c));

        // store_imm_ind_u32: mem[φ2 + 0x20] ← 0xDEADBEEF (truncated to u32).
        let mut c = base(
            "store",
            "store_imm_ind_u32",
            asm(&[&[72, 0x12, 0x20, 0xEF, 0xBE, 0xAD, 0xDE], &[0]]),
        );
        c.regs[2] = RW_BASE as u64;
        c.exp_regs = c.regs;
        c.exp_pc = 7;
        c.exp_gas = GAS - 2;
        c.exp_memory = vec![(RW_BASE + 0x20, vec![0xEF, 0xBE, 0xAD, 0xDE])];
        v.push(with_memory(c));

        // Writing the read-only page faults with its page base, and the
        // page contents stay untouched.
        let mut c = base(
            "store",
            "store_ro_page_faults",
            asm(&[&[59, 2, 0x00, 0x00, 0x01], &[0]]),
        );
        c.regs[2] = 0xAB;
        let mut c = faulting(c, RO_BASE);
        c.exp_memory = vec![(RO_BASE, ro_seed())];
        v.push(c);

        let c = base(
            "store",
            "store_fault_unmapped",
            asm(&[&[62, 2, 0x00, 0x00, 0x03], &[0]]),
        );
        v.push(faulting(c, 0x30000));

        // A u64 store at RW_BASE+0xFFC crosses into the unmapped page: the
        // fault reports the second page and NOTHING is written (stores are
        // atomic — no partial first-page write).
        let mut c = base(
            "store",
            "store_cross_page_is_atomic",
            asm(&[&[62, 2, 0xFC, 0x0F, 0x02], &[0]]),
        );
        c.regs[2] = u64::MAX;
        let mut c = faulting(c, 0x21000);
        c.exp_memory = vec![(RW_BASE + 0xFF8, vec![0; 8])];
        v.push(c);
    }

    // --- branch: every condition, signedness splits, strictness ---
    {
        let neg1 = u64::MAX;
        let neg5 = (-5i64) as u64;
        let neg6 = (-6i64) as u64;
        v.push(branch_imm("branch", "eq_imm_taken", 81, 5, 5, true));
        v.push(branch_imm("branch", "eq_imm_not_taken", 81, 4, 5, false));
        v.push(branch_imm("branch", "ne_imm_taken", 82, 4, 5, true));
        v.push(branch_imm("branch", "lt_u_imm_taken", 83, 4, 5, true));
        v.push(branch_imm(
            "branch",
            "le_u_imm_boundary_taken",
            84,
            5,
            5,
            true,
        ));
        v.push(branch_imm(
            "branch",
            "ge_u_imm_boundary_taken",
            85,
            5,
            5,
            true,
        ));
        v.push(branch_imm(
            "branch",
            "gt_u_imm_boundary_not_taken",
            86,
            5,
            5,
            false,
        ));
        // −1 < 0 signed but 2⁶⁴−1 > 0 unsigned: the pair pins signedness.
        v.push(branch_imm(
            "branch",
            "lt_s_imm_signed_taken",
            87,
            neg1,
            0,
            true,
        ));
        v.push(branch_imm(
            "branch",
            "ge_u_imm_signed_taken",
            85,
            neg1,
            0,
            true,
        ));
        v.push(branch_imm("branch", "le_s_imm_taken", 88, neg5, 0xFB, true));
        v.push(branch_imm("branch", "gt_s_imm_taken", 90, 3, 2, true));
        v.push(branch_imm(
            "branch",
            "ge_s_imm_not_taken",
            89,
            neg6,
            0xFB,
            false,
        ));

        v.push(branch_reg("branch", "eq_taken", 170, 9, 9, true));
        v.push(branch_reg("branch", "ne_not_taken", 171, 9, 9, false));
        v.push(branch_reg("branch", "lt_u_taken", 172, 1, neg1, true));
        v.push(branch_reg(
            "branch",
            "lt_s_signed_not_taken",
            173,
            1,
            neg1,
            false,
        ));
        v.push(branch_reg("branch", "ge_u_taken", 174, neg1, 1, true));
        v.push(branch_reg("branch", "ge_s_taken", 175, 1, neg1, true));

        // GP eq A.17 strictness: a taken branch to a non-block-start (pc 6
        // is mid-load_imm) panics; the branch is charged.
        let mut c = base(
            "branch",
            "taken_to_mid_block_panics",
            asm(&[&[81, 0x12, 5, 6], &[0], &[51, 5, 1], &[0]]),
        );
        c.regs[2] = 5;
        c.exp_regs = c.regs;
        c.exp_status = ExitReason::Panic;
        c.exp_pc = 0;
        c.exp_gas = GAS - 1;
        v.push(c);

        // Unconditional jump to a block start.
        let mut c = base("branch", "jump", asm(&[&[40, 3], &[0], &[51, 5, 1], &[0]]));
        c.exp_regs[5] = 1;
        c.exp_pc = 6;
        c.exp_gas = GAS - 3;
        v.push(c);

        // Unconditional jump into the middle of an instruction panics.
        let mut c = base(
            "branch",
            "jump_to_mid_block_panics",
            asm(&[&[40, 4], &[0], &[51, 5, 1], &[0]]),
        );
        c.exp_status = ExitReason::Panic;
        c.exp_pc = 0;
        c.exp_gas = GAS - 1;
        v.push(c);

        // A backward loop: φ2 counts 3 → 0; 9 instructions execute.
        let loop_prog = (
            vec![51, 2, 3, 1, 149, 0x22, 0xFF, 82, 2, 0xFD, 0],
            vec![1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1],
        );
        let mut c = base("branch", "loop_countdown", loop_prog.clone());
        c.exp_regs[2] = 0;
        c.exp_pc = 10;
        c.exp_gas = GAS - 9;
        v.push(c);

        // The same loop with budget 5 runs out mid-loop (per-instruction
        // charging): 5 instructions execute, φ2 has reached 1, and the
        // unfunded branch at pc 7 never runs. Interpreter only.
        let mut c = base("branch", "loop_out_of_gas", loop_prog);
        c.gas = 5;
        c.exp_status = ExitReason::OutOfGas;
        c.exp_regs[2] = 1;
        c.exp_pc = 7;
        c.exp_gas = 0;
        c.recompiler = false;
        v.push(c);
    }

    // --- djump (jump_ind): halt address, table dispatch, panics ---
    {
        // djump(2³² − 2¹⁶) is the graceful halt.
        let mut c = base("djump", "jump_ind_halt", asm(&[&[50, 2], &[0]]));
        c.regs[2] = PVM_HALT_ADDR;
        c.exp_regs = c.regs;
        c.exp_status = ExitReason::Halt;
        c.exp_pc = 0;
        c.exp_gas = GAS - 1;
        v.push(c);

        // The djump address is (φ + imm) mod 2³².
        let mut c = base("djump", "jump_ind_wraps_mod_2_32", asm(&[&[50, 2], &[0]]));
        c.regs[2] = (1u64 << 32) + PVM_HALT_ADDR;
        c.exp_regs = c.regs;
        c.exp_status = ExitReason::Halt;
        c.exp_pc = 0;
        c.exp_gas = GAS - 1;
        v.push(c);

        // a = 2 ⇒ jump-table entry 0 ⇒ pc 5 (a block start): dispatches.
        let mut c = base(
            "djump",
            "jump_ind_through_table",
            asm(&[&[50, 2], &[0], &[0], &[0], &[51, 5, 1], &[0]]),
        );
        c.jump_table = vec![5];
        c.regs[2] = 2;
        c.exp_regs = c.regs;
        c.exp_regs[5] = 1;
        c.exp_pc = 8;
        c.exp_gas = GAS - 3;
        v.push(c);

        // GP eq A.18 panic set: a = 0; a misaligned (Z_A = 2); a beyond the
        // table; a whose table entry is not a block start.
        v.push(jump_ind_panic("jump_ind_zero_panics", 0, vec![5]));
        v.push(jump_ind_panic("jump_ind_misaligned_panics", 3, vec![5]));
        v.push(jump_ind_panic("jump_ind_beyond_table_panics", 4, vec![5]));
        {
            // Entry 0 points mid-instruction (pc 6 inside the load_imm).
            let mut c = base(
                "djump",
                "jump_ind_to_mid_block_panics",
                asm(&[&[50, 2], &[0], &[0], &[0], &[51, 5, 1], &[0]]),
            );
            c.jump_table = vec![6];
            c.regs[2] = 2;
            c.exp_regs = c.regs;
            c.exp_status = ExitReason::Panic;
            c.exp_pc = 0;
            c.exp_gas = GAS - 1;
            v.push(c);
        }
    }

    // --- limj: load_imm_jump and load_imm_jump_ind ---
    {
        // load_imm_jump: φ2 ← 99, then jump to pc 6.
        let mut c = base(
            "limj",
            "load_imm_jump",
            asm(&[&[80, 0x12, 99, 6], &[0], &[0], &[51, 5, 1], &[0]]),
        );
        c.exp_regs[2] = 99;
        c.exp_regs[5] = 1;
        c.exp_pc = 9;
        c.exp_gas = GAS - 3;
        v.push(c);

        // GP A.5.12: the djump address uses the PRE-state base register.
        // ra == rb == φ2: with φ2 = HALT and ν_X = 7, a post-state read
        // would djump(7) and panic; the pre-state read halts with φ2 = 7.
        let mut c = base(
            "limj",
            "load_imm_jump_ind_pre_state_base",
            asm(&[&[180, 0x22, 1, 7], &[0]]),
        );
        c.regs[2] = PVM_HALT_ADDR;
        c.exp_regs = c.regs;
        c.exp_regs[2] = 7;
        c.exp_status = ExitReason::Halt;
        c.exp_pc = 0;
        c.exp_gas = GAS - 1;
        v.push(c);

        // load_imm_jump_ind through the table: φ2 ← 55, djump(φ3 = 2) ⇒
        // entry 0 ⇒ pc 5.
        let mut c = base(
            "limj",
            "load_imm_jump_ind_through_table",
            asm(&[&[180, 0x32, 1, 55], &[0], &[51, 5, 1], &[0]]),
        );
        c.jump_table = vec![5];
        c.regs[3] = 2;
        c.exp_regs = c.regs;
        c.exp_regs[2] = 55;
        c.exp_regs[5] = 1;
        c.exp_pc = 8;
        c.exp_gas = GAS - 3;
        v.push(c);
    }

    v
}

/// Gray Paper v0.8.0 executable corpus.
///
/// Most instruction semantics did not change between the historical corpus
/// and v0.8.0, so those hand-derived cases are shared. The old unary family is
/// intentionally discarded and rebuilt with the v0.8.0 opcode assignments.
/// Unlike the historical loader, the v0.8.0 runner forces *every* case through
/// the standard conformance decoder.
fn v080_corpus() -> Vec<Case> {
    let mut v: Vec<Case> = corpus()
        .into_iter()
        .filter(|case| case.family != "unary")
        .collect();

    // A.5.2 decodes an immediate as a signed machine register. The single
    // byte 0xff therefore crosses the host boundary as 2^64-1, rather than
    // being narrowed to the historical JAR u32 host-slot representation.
    let mut wide_host = base("flow", "ecalli_negative_one_is_u64", asm(&[&[10, 0xff]]));
    wide_host.exp_status = ExitReason::HostCall(u64::MAX);
    wide_host.exp_gas = GAS - 1;
    v.push(wide_host);

    // Appendix A.5.9 after v0.8.0 removed sbrk: the unary operations occupy
    // bytes 101..=110. Keep boundary inputs that distinguish 32/64-bit views,
    // zero handling, signed extension, and byte order.
    v.push(unary("unary", "move_reg", 100, 0xDEAD_BEEF, 0xDEAD_BEEF));
    v.push(unary("unary", "count_set_bits_64", 101, 0xF0F0, 8));
    v.push(unary(
        "unary",
        "count_set_bits_32_ignores_upper",
        102,
        0xFFFF_FFFF_0000_00FF,
        8,
    ));
    v.push(unary("unary", "leading_zero_bits_64", 103, 1, 63));
    v.push(unary("unary", "leading_zero_bits_64_zero", 103, 0, 64));
    v.push(unary("unary", "leading_zero_bits_32", 104, 1, 31));
    v.push(unary(
        "unary",
        "trailing_zero_bits_64",
        105,
        0x8000_0000_0000_0000,
        63,
    ));
    v.push(unary(
        "unary",
        "trailing_zero_bits_32_of_zero",
        106,
        1 << 32,
        32,
    ));
    v.push(unary(
        "unary",
        "sign_extend_8",
        107,
        0x1F80,
        0xFFFF_FFFF_FFFF_FF80,
    ));
    v.push(unary(
        "unary",
        "sign_extend_16",
        108,
        0x1_8000,
        0xFFFF_FFFF_FFFF_8000,
    ));
    v.push(unary("unary", "zero_extend_16", 109, 0xFFFF_8000, 0x8000));
    v.push(unary(
        "unary",
        "reverse_bytes",
        110,
        0x0102_0304_0506_0708,
        0x0807_0605_0403_0201,
    ));

    // Complete executable coverage of Appendix A.5. Every standard opcode
    // appears at an instruction-start position in at least one independently
    // expected vector; the exact-set assertion below prevents future gaps.

    // A.5.4/A.5.6/A.5.7/A.5.10 memory-width variants.
    v.push(abs_store_imm(
        "store_imm_u16",
        31,
        &[0x34, 0x12],
        &[0x34, 0x12],
    ));
    v.push(abs_store_imm(
        "store_imm_u32",
        32,
        &[0x78, 0x56, 0x34, 0x12],
        &[0x78, 0x56, 0x34, 0x12],
    ));
    v.push(abs_store_imm(
        "store_imm_u64_zero_extends_positive_imm32",
        33,
        &[0x78, 0x56, 0x34, 0x12],
        &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0],
    ));
    v.push(abs_store_reg("store_u16", 60, 0x1122_3344, &[0x44, 0x33]));
    v.push(abs_store_reg(
        "store_u32",
        61,
        0x1122_3344_5566_7788,
        &[0x88, 0x77, 0x66, 0x55],
    ));
    v.push(store_imm_ind("store_imm_ind_u8", 70, &[0x7f], &[0x7f]));
    v.push(store_imm_ind(
        "store_imm_ind_u16",
        71,
        &[0x34, 0x12],
        &[0x34, 0x12],
    ));
    v.push(store_imm_ind(
        "store_imm_ind_u64",
        73,
        &[0x78, 0x56, 0x34, 0x12],
        &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0],
    ));
    v.push(store_ind("store_ind_u16", 121, 0x1122_3344, &[0x44, 0x33]));
    v.push(store_ind(
        "store_ind_u32",
        122,
        0x1122_3344_5566_7788,
        &[0x88, 0x77, 0x66, 0x55],
    ));
    v.push(store_ind(
        "store_ind_u64",
        123,
        0x1122_3344_5566_7788,
        &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
    ));
    v.push(load_ind("load_ind_u8", 124, 0x81));
    v.push(load_ind("load_ind_i8", 125, 0xffff_ffff_ffff_ff81));
    v.push(load_ind("load_ind_u16", 126, 0x8281));
    v.push(load_ind("load_ind_i32", 129, 0xffff_ffff_8483_8281));
    v.push(load_ind("load_ind_u64", 130, 0x8887_8685_8483_8281));

    // A.5.10 immediate arithmetic, comparisons, shifts, moves, and rotates.
    v.push(alu_imm("alu64", "and_imm", 132, 0x0c, 0x0a, 0x08));
    v.push(alu_imm("alu64", "xor_imm", 133, 0x0c, 0x0a, 0x06));
    v.push(alu_imm("alu64", "or_imm", 134, 0x0c, 0x0a, 0x0e));
    v.push(alu_imm(
        "alu32",
        "mul_imm_32_sign_extends",
        135,
        0x4000_0000,
        2,
        0xffff_ffff_8000_0000,
    ));
    v.push(alu_imm("alu64", "set_lt_u_imm", 136, 4, 5, 1));
    v.push(alu_imm("alu64", "set_lt_s_imm", 137, u64::MAX, 0, 1));
    v.push(alu_imm(
        "shift",
        "shlo_l_imm_32_sign_extends",
        138,
        1,
        31,
        0xffff_ffff_8000_0000,
    ));
    v.push(alu_imm("shift", "shlo_r_imm_32", 139, 0x8000_0000, 31, 1));
    v.push(alu_imm(
        "shift",
        "shar_r_imm_32_sign_fills",
        140,
        0x8000_0000,
        31,
        u64::MAX,
    ));
    v.push(alu_imm("alu32", "neg_add_imm_32", 141, 7, 5, u64::MAX - 1));
    v.push(alu_imm("alu64", "set_gt_u_imm", 142, 6, 5, 1));
    v.push(alu_imm("alu64", "set_gt_s_imm", 143, u64::MAX, 0, 0));
    v.push(alu_imm(
        "shift",
        "shlo_l_imm_alt_32",
        144,
        31,
        1,
        0xffff_ffff_8000_0000,
    ));
    v.push(alu_imm("shift", "shlo_r_imm_alt_32", 145, 31, 0x80, 1));
    v.push(alu_imm(
        "shift",
        "shar_r_imm_alt_32",
        146,
        4,
        0x80,
        (-8i64) as u64,
    ));
    v.push(alu_imm("alu64", "cmov_iz_imm", 147, 0, 7, 7));
    v.push(alu_imm("alu64", "cmov_nz_imm", 148, 1, 7, 7));
    v.push(alu_imm(
        "alu64",
        "mul_imm_64_wraps",
        150,
        u64::MAX,
        2,
        u64::MAX - 1,
    ));
    v.push(alu_imm(
        "shift",
        "shlo_l_imm_64",
        151,
        1,
        63,
        0x8000_0000_0000_0000,
    ));
    v.push(alu_imm(
        "shift",
        "shlo_r_imm_64",
        152,
        0x8000_0000_0000_0000,
        63,
        1,
    ));
    v.push(alu_imm(
        "shift",
        "shlo_l_imm_alt_64",
        155,
        63,
        1,
        0x8000_0000_0000_0000,
    ));
    v.push(alu_imm("shift", "shlo_r_imm_alt_64", 156, 63, 0x80, 1));
    v.push(alu_imm(
        "shift",
        "rot_r_64_imm",
        158,
        1,
        1,
        0x8000_0000_0000_0000,
    ));
    v.push(alu_imm(
        "shift",
        "rot_r_64_imm_alt",
        159,
        1,
        1,
        0x8000_0000_0000_0000,
    ));
    v.push(alu_imm(
        "shift",
        "rot_r_32_imm_alt_sign_extends",
        161,
        1,
        1,
        0xffff_ffff_8000_0000,
    ));

    // Remaining A.5.13 three-register operations.
    v.push(alu3(
        "muldiv",
        "rem_s_32_dividend_sign",
        196,
        (-37i64) as u64,
        5,
        (-2i64) as u64,
    ));
    v.push(alu3("shift", "shlo_r_32", 198, 0x8000_0000, 31, 1));
    v.push(alu3("shift", "rot_l_64", 220, 1, 63, 0x8000_0000_0000_0000));
    v.push(alu3(
        "shift",
        "rot_l_32_sign_extends",
        221,
        1,
        31,
        0xffff_ffff_8000_0000,
    ));
    v.push(alu3(
        "shift",
        "rot_r_32_sign_extends",
        223,
        1,
        1,
        0xffff_ffff_8000_0000,
    ));

    // The shared historical constructors terminate ordinary cases with
    // opcode 0 and therefore record the transitional JAR `Trap` result.
    // Gray Paper v0.8 classifies the same instruction as panic (☇); keep
    // that distinction explicit in the standard corpus instead of folding
    // backend results in the runner.
    for case in &mut v {
        match case.name.as_str() {
            "flow_trap" => case.name = "flow_opcode_zero_panics".into(),
            "flow_fall_off_end_traps" => {
                case.name = "flow_fall_off_end_panics".into();
                // v0.8 defines opcode 1 as sjump(next). End-of-code is not
                // in varpi, so it panics at pc 0 after one instruction charge.
                case.exp_pc = 0;
                case.exp_gas = GAS - 1;
            }
            "flow_empty_program_traps" => case.name = "flow_empty_program_panics".into(),
            // Standard A.15 classifies every address below 2^16 as panic
            // before consulting page accessibility. The historical JAR
            // corpus intentionally retains its PageFault(0) behavior.
            "load_load_fault_unmapped_low" => {
                case.exp_status = ExitReason::Panic;
                case.exp_pc = 0;
            }
            _ => {}
        }
        if case.exp_status == ExitReason::Trap {
            case.exp_status = ExitReason::Panic;
        }
        match case.exp_status {
            // Full Ψ normalizes final counters to zero.
            ExitReason::Halt | ExitReason::Panic => case.exp_pc = 0,
            // The sole host-call vector begins its ecalli at PC 0. Standard
            // Ψ returns that causing counter; the host advances on resume.
            ExitReason::HostCall(_) => case.exp_pc = 0,
            _ => {}
        }
    }

    v
}

/// A hand-derived v0.8.0 block-gas judgement. These cases are deliberately
/// smaller than the instruction-state corpus: each isolates one part of the
/// current gas rule so its checked-in outcome is auditable without executing
/// VOS code to discover the answer.
struct BlockGasCase {
    name: &'static str,
    code: Vec<u8>,
    bitmask: Vec<u8>,
    gas: u64,
    regs: [u64; 13],
    expected_starts_and_costs: Vec<(u32, u32)>,
    first_exit: ExitReason,
    first_remaining_gas: u64,
    resume: Option<(ExitReason, u64)>,
}

fn block_gas_case(
    name: &'static str,
    program: (Vec<u8>, Vec<u8>),
    gas: u64,
    expected_starts_and_costs: &[(u32, u32)],
    first_exit: ExitReason,
    first_remaining_gas: u64,
) -> BlockGasCase {
    BlockGasCase {
        name,
        code: program.0,
        bitmask: program.1,
        gas,
        regs: [0; 13],
        expected_starts_and_costs: expected_starts_and_costs.to_vec(),
        first_exit,
        first_remaining_gas,
        resume: None,
    }
}

/// Frozen v0.8.0 block-gas oracle cases.
///
/// Derivations follow the priority loop in Gray Paper v0.8.0 equations
/// A.49--A.57: whole-instruction decode into a 32-entry ROB, oldest-ready
/// dispatch (at most five starts per cycle), persistent execution-unit
/// occupancy, and in-order retirement. A block costs
/// `max(simulation_cycles - 3, 1)`. Blocks begin only at pc 0 and immediately
/// after members of [`V080_TERMINATORS`]. The numerical derivations are noted
/// beside each case and stored in `tests/vectors-v080-gas`.
fn v080_block_gas_corpus() -> Vec<BlockGasCase> {
    let mut cases = Vec::new();

    // unlikely(40 cycles), ecalli(100), and trap are one block because only
    // trap belongs to T. Whole-slot decode delays ecalli by one cycle, so the
    // converged block cost is 101. Resuming after
    // ecalli must not charge the already-funded block again.
    let mut c = block_gas_case(
        "unlikely_ecalli_share_one_block",
        asm(&[&[2], &[10, 7], &[0]]),
        200,
        &[(0, 101)],
        ExitReason::HostCall(7),
        99,
    );
    c.resume = Some((ExitReason::Panic, 99));
    cases.push(c);

    // fallthrough is in T: its isolated two-cycle block costs 2. The following
    // unlikely+trap block converges with cost 40.
    cases.push(block_gas_case(
        "fallthrough_splits_before_unlikely",
        asm(&[&[1], &[2], &[0]]),
        100,
        &[(0, 2), (1, 40)],
        ExitReason::Panic,
        58,
    ));

    // Three chained div_u_64 operations write r2, r4, r6 and consume those
    // destinations in the next operation. The dependency and the single DIV
    // unit serialize all three, giving a converged block cost of 180. This catches the
    // tempting but incorrect interpretation of encoded rA as the destination;
    // Appendix A.5.13 makes rD the destination.
    cases.push(block_gas_case(
        "three_register_destination_dependency_chain",
        asm(&[&[203, 0x10, 2], &[203, 0x32, 4], &[203, 0x54, 6], &[0]]),
        500,
        &[(0, 180)],
        ExitReason::Panic,
        320,
    ));

    // These divisions share no registers, but the virtual CPU has one DIV
    // unit. It remains occupied for all 60 execution cycles, so the second
    // division cannot overlap the first and the block costs 120.
    cases.push(block_gas_case(
        "independent_divisions_serialize_on_div_unit",
        asm(&[&[203, 0x10, 2], &[203, 0x54, 6], &[0]]),
        200,
        &[(0, 120)],
        ExitReason::Panic,
        80,
    ));

    // load_imm consumes one of four decode slots. The following four-slot DIV
    // cannot partially enter the remaining three slots and waits for the next
    // cycle's reset. Its otherwise-independent block therefore costs 61.
    cases.push(block_gas_case(
        "four_slot_instruction_waits_after_partial_decode",
        asm(&[&[51, 0, 0], &[203, 0x32, 4], &[0]]),
        100,
        &[(0, 61)],
        ExitReason::Panic,
        39,
    ));

    // Absolute load completes at 25; the following add consumes its r2
    // destination and completes at 26. The complete block therefore costs
    // 26 even though execution faults on the first instruction.
    cases.push(block_gas_case(
        "memory_fault_charges_dependent_tail",
        asm(&[&[58, 2, 0, 0, 3], &[200, 0x32, 4], &[0]]),
        100,
        &[(0, 26)],
        ExitReason::PageFault(0x30000),
        74,
    ));

    // The same block with insufficient funding reports OOG before attempting
    // the invalid memory access and leaves the counter unchanged.
    cases.push(block_gas_case(
        "out_of_gas_precedes_memory_fault",
        asm(&[&[58, 2, 0, 0, 3], &[200, 0x32, 4], &[0]]),
        25,
        &[(0, 26)],
        ExitReason::OutOfGas,
        25,
    ));

    // Four one-slot unlikely instructions decode in cycle 0; the fifth and
    // sixth decode in cycle 1. The second decode cohort completes one cycle
    // later, hence block cost 41 after pipeline convergence.
    cases.push(block_gas_case(
        "decode_width_rolls_after_four_slots",
        asm(&[&[2], &[2], &[2], &[2], &[2], &[2], &[0]]),
        100,
        &[(0, 41)],
        ExitReason::Panic,
        59,
    ));

    // A branch aimed at unlikely has latency 1; the following unlikely+trap
    // block costs 40. The target is also the required post-branch block start.
    cases.push(block_gas_case(
        "branch_to_unlikely_uses_short_latency",
        asm(&[&[81, 0x12, 0, 4], &[2], &[0]]),
        100,
        &[(0, 1), (4, 40)],
        ExitReason::Panic,
        59,
    ));

    // A branch to an ordinary instruction has latency/cost 20; its
    // load_imm+trap target block costs 2.
    cases.push(block_gas_case(
        "branch_to_likely_target_uses_long_latency",
        asm(&[&[81, 0x12, 0, 4], &[51, 5, 1], &[0]]),
        100,
        &[(0, 20), (4, 2)],
        ExitReason::Panic,
        78,
    ));

    // The explicit target (load_imm at pc 6) is ordinary, but the sequential
    // byte is unlikely. v0.8's `b` equation tests both bytes, so the branch is
    // short. The fallthrough at pc 5 makes pc 6 a valid block target. Make the
    // condition false to execute the auditable fallthrough path.
    let mut c = block_gas_case(
        "branch_fallthrough_unlikely_target_likely_is_short",
        asm(&[&[81, 0x12, 0, 6], &[2], &[1], &[51, 5, 1], &[0]]),
        100,
        &[(0, 1), (4, 40), (6, 2)],
        ExitReason::Panic,
        57,
    );
    c.regs[2] = 1;
    cases.push(c);

    // Conversely the fallthrough byte is ordinary (fallthrough opcode 1),
    // while the explicit target at pc 5 is unlikely. It is short for the
    // target half of the same equation. The intervening terminator makes pc 5
    // an independently funded block start.
    cases.push(block_gas_case(
        "branch_target_unlikely_fallthrough_likely_is_short",
        asm(&[&[81, 0x12, 0, 5], &[1], &[2], &[0]]),
        100,
        &[(0, 1), (4, 2), (5, 40)],
        ExitReason::Panic,
        59,
    ));

    // The target is pc 0 and therefore valid, but the sequential successor is
    // beyond varpi. v0.8 validates both successors before selecting the valid
    // target, so this panics at the branch after its short one-gas block.
    cases.push(block_gas_case(
        "branch_invalid_fallthrough_panics_when_target_selected",
        asm(&[&[81, 0x12, 0, 0]]),
        100,
        &[(0, 1)],
        ExitReason::Panic,
        99,
    ));

    // The same invalid sequential successor is rejected before selecting it.
    let mut c = block_gas_case(
        "branch_invalid_fallthrough_panics_when_fallthrough_selected",
        asm(&[&[81, 0x12, 0, 0]]),
        100,
        &[(0, 1)],
        ExitReason::Panic,
        99,
    );
    c.regs[2] = 1;
    cases.push(c);

    // A positive explicit target beyond varpi is rejected even when the
    // condition selects the valid sequential successor.
    let mut c = block_gas_case(
        "branch_invalid_target_panics_when_fallthrough_selected",
        asm(&[&[81, 0x12, 0, 127], &[1], &[0]]),
        100,
        &[(0, 1), (4, 2), (5, 2)],
        ExitReason::Panic,
        99,
    );
    c.regs[2] = 1;
    cases.push(c);

    // A negative decoded target wraps to a high machine address outside
    // varpi and is likewise rejected when the condition selects it.
    cases.push(block_gas_case(
        "branch_invalid_target_panics_when_target_selected",
        asm(&[&[81, 0x12, 0, 0xff], &[1], &[0]]),
        100,
        &[(0, 1), (4, 2), (5, 2)],
        ExitReason::Panic,
        99,
    ));

    cases
}

// --- JSON encoding / decoding ---

fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex_bytes(s: &str) -> Vec<u8> {
    let s = s
        .strip_prefix("0x")
        .expect("hex strings carry an 0x prefix");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Pack an unpacked bitmask (one byte per code byte) LSB-first.
fn pack_bitmask(bits: &[u8]) -> Vec<u8> {
    let mut packed = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        if b != 0 {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    packed
}

fn unpack_bitmask(packed: &[u8], code_len: usize) -> Vec<u8> {
    (0..code_len)
        .map(|i| (packed[i / 8] >> (i % 8)) & 1)
        .collect()
}

fn status_str(exit: &ExitReason) -> &'static str {
    match exit {
        ExitReason::Halt => "halt",
        ExitReason::Trap => "trap",
        ExitReason::Panic => "panic",
        ExitReason::OutOfGas => "out_of_gas",
        ExitReason::PageFault(_) => "page_fault",
        ExitReason::HostCall(_) => "host_call",
        ExitReason::Ecall => unreachable!("no vector expects the jar ecall exit"),
    }
}

fn regs_json(regs: &[u64; 13]) -> Value {
    Value::Array(regs.iter().map(|r| json!(format!("{r:#x}"))).collect())
}

fn regs_from_json(v: &Value) -> [u64; 13] {
    let arr = v.as_array().expect("regs is an array");
    assert_eq!(arr.len(), 13, "13 registers");
    let mut regs = [0u64; 13];
    for (i, r) in arr.iter().enumerate() {
        let s = r.as_str().expect("register values are hex strings");
        regs[i] = u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("valid hex");
    }
    regs
}

fn memory_json(mem: &[(u32, Vec<u8>)]) -> Value {
    Value::Array(
        mem.iter()
            .map(|(addr, bytes)| json!({ "address": addr, "contents": hex_bytes(bytes) }))
            .collect(),
    )
}

fn memory_from_json(v: &Value) -> Vec<(u32, Vec<u8>)> {
    v.as_array()
        .expect("memory is an array")
        .iter()
        .map(|e| {
            (
                e["address"].as_u64().expect("address") as u32,
                unhex_bytes(e["contents"].as_str().expect("contents")),
            )
        })
        .collect()
}

fn perm_str(perm: u8) -> &'static str {
    match perm {
        PERM_RO => "ro",
        PERM_RW => "rw",
        _ => unreachable!("page maps only list mapped pages"),
    }
}

fn to_json(c: &Case) -> Value {
    let mut expected = serde_json::Map::new();
    expected.insert("status".into(), json!(status_str(&c.exp_status)));
    expected.insert("pc".into(), json!(c.exp_pc));
    expected.insert("gas".into(), json!(c.exp_gas));
    expected.insert("regs".into(), regs_json(&c.exp_regs));
    expected.insert("memory".into(), memory_json(&c.exp_memory));
    if let ExitReason::PageFault(addr) = c.exp_status {
        expected.insert("page_fault_address".into(), json!(addr));
    }
    if let ExitReason::HostCall(id) = c.exp_status {
        expected.insert("host_call".into(), json!(id));
    }
    let backends: Vec<&str> = if c.recompiler {
        vec!["interpreter", "recompiler"]
    } else {
        vec!["interpreter"]
    };
    json!({
        "name": c.name,
        "family": c.family,
        "program": {
            "code": hex_bytes(&c.code),
            "bitmask": hex_bytes(&pack_bitmask(&c.bitmask)),
            "jump_table": c.jump_table,
        },
        "initial": {
            "pc": 0,
            "gas": c.gas,
            "regs": regs_json(&c.regs),
            "page_map": c.page_map.iter().map(|(addr, len, perm)| json!({
                "address": addr, "length": len, "access": perm_str(*perm),
            })).collect::<Vec<_>>(),
            "memory": memory_json(&c.memory),
        },
        "expected": Value::Object(expected),
        "backends": backends,
    })
}

fn to_v080_json(c: &Case) -> Value {
    let mut value = to_json(c);
    value
        .as_object_mut()
        .expect("vector JSON is an object")
        .insert("spec".into(), json!("gray-paper-0.8.0"));
    value
}

fn exit_json(exit: &ExitReason, remaining_gas: u64) -> Value {
    let mut value = serde_json::Map::new();
    value.insert("status".into(), json!(status_str(exit)));
    value.insert("remaining_gas".into(), json!(remaining_gas));
    if let ExitReason::PageFault(address) = exit {
        value.insert("page_fault_address".into(), json!(address));
    }
    if let ExitReason::HostCall(id) = exit {
        value.insert("host_call".into(), json!(id));
    }
    Value::Object(value)
}

fn block_gas_to_json(case: &BlockGasCase) -> Value {
    json!({
        "name": case.name,
        "spec": "gray-paper-0.8.0",
        "rule": "gray-paper-v0.8-rob-block-gas",
        "program": {
            "code": hex_bytes(&case.code),
            "bitmask": hex_bytes(&pack_bitmask(&case.bitmask)),
        },
        "initial": {
            "gas": case.gas,
            "regs": regs_json(&case.regs),
        },
        "expected": {
            "blocks": case.expected_starts_and_costs.iter().map(|(pc, gas)| json!({
                "pc": pc,
                "gas": gas,
            })).collect::<Vec<_>>(),
            "first": exit_json(&case.first_exit, case.first_remaining_gas),
            "resume": case.resume.as_ref().map(|(exit, gas)| exit_json(exit, *gas)),
        },
    })
}

/// A vector as parsed back from disk — the loaders run from THIS (never
/// from the in-memory table), so the JSON files are the actual contract.
struct Vector {
    name: String,
    code: Vec<u8>,
    bitmask: Vec<u8>,
    jump_table: Vec<u32>,
    initial_pc: u32,
    gas: u64,
    regs: [u64; 13],
    page_map: Vec<(u32, u32, u8)>,
    memory: Vec<(u32, Vec<u8>)>,
    exp_status: ExitReason,
    exp_pc: u32,
    exp_gas: u64,
    exp_regs: [u64; 13],
    exp_memory: Vec<(u32, Vec<u8>)>,
    recompiler: bool,
}

fn from_json(v: &Value) -> Vector {
    let code = unhex_bytes(v["program"]["code"].as_str().expect("code"));
    let bitmask = unpack_bitmask(
        &unhex_bytes(v["program"]["bitmask"].as_str().expect("bitmask")),
        code.len(),
    );
    let exp = &v["expected"];
    let exp_status = match exp["status"].as_str().expect("status") {
        "halt" => ExitReason::Halt,
        "trap" => ExitReason::Trap,
        "panic" => ExitReason::Panic,
        "out_of_gas" => ExitReason::OutOfGas,
        "page_fault" => {
            ExitReason::PageFault(exp["page_fault_address"].as_u64().expect("fault addr") as u32)
        }
        "host_call" => ExitReason::HostCall(exp["host_call"].as_u64().expect("host id")),
        other => panic!("unknown status {other}"),
    };
    Vector {
        name: v["name"].as_str().expect("name").to_string(),
        jump_table: v["program"]["jump_table"]
            .as_array()
            .expect("jump table")
            .iter()
            .map(|e| e.as_u64().expect("entry") as u32)
            .collect(),
        code,
        bitmask,
        initial_pc: v["initial"]["pc"].as_u64().expect("pc") as u32,
        gas: v["initial"]["gas"].as_u64().expect("gas"),
        regs: regs_from_json(&v["initial"]["regs"]),
        page_map: v["initial"]["page_map"]
            .as_array()
            .expect("page map")
            .iter()
            .map(|e| {
                let perm = match e["access"].as_str().expect("access") {
                    "ro" => PERM_RO,
                    "rw" => PERM_RW,
                    other => panic!("unknown access {other}"),
                };
                (
                    e["address"].as_u64().expect("address") as u32,
                    e["length"].as_u64().expect("length") as u32,
                    perm,
                )
            })
            .collect(),
        memory: memory_from_json(&v["initial"]["memory"]),
        exp_status,
        exp_pc: exp["pc"].as_u64().expect("pc") as u32,
        exp_gas: exp["gas"].as_u64().expect("gas"),
        exp_regs: regs_from_json(&exp["regs"]),
        exp_memory: memory_from_json(&exp["memory"]),
        recompiler: v["backends"]
            .as_array()
            .expect("backends")
            .iter()
            .any(|b| b.as_str() == Some("recompiler")),
    }
}

fn exit_from_json(value: &Value) -> ExitReason {
    match value["status"].as_str().expect("status") {
        "halt" => ExitReason::Halt,
        "trap" => ExitReason::Trap,
        "panic" => ExitReason::Panic,
        "out_of_gas" => ExitReason::OutOfGas,
        "page_fault" => ExitReason::PageFault(
            value["page_fault_address"]
                .as_u64()
                .expect("page fault address") as u32,
        ),
        "host_call" => ExitReason::HostCall(value["host_call"].as_u64().expect("host call id")),
        other => panic!("unknown exit status {other}"),
    }
}

// --- corpus location + discovery ---

fn vectors_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors"))
}

fn v080_vectors_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors-v080"))
}

fn v080_gas_vectors_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors-v080-gas"
    ))
}

fn discover_in(dir: PathBuf, suffix: &str, required_spec: Option<&str>) -> Vec<(String, Vector)> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e} (bless the corpus first)", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no pvm vectors found in {}",
        dir.display()
    );
    files
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p).expect("read vector");
            let value: Value = serde_json::from_str(&text).expect("parse vector json");
            let file = p.file_name().unwrap().to_string_lossy().into_owned();
            if let Some(spec) = required_spec {
                assert_eq!(
                    value["spec"].as_str(),
                    Some(spec),
                    "{file}: explicit specification identity"
                );
            }
            let vector = from_json(&value);
            assert_eq!(
                file,
                format!("{}.{}.json", vector.name, suffix),
                "file name matches the vector's name field"
            );
            (file, vector)
        })
        .collect()
}

fn discover() -> Vec<(String, Vector)> {
    discover_in(vectors_dir(), "gp072", None)
}

fn discover_v080() -> Vec<(String, Vector)> {
    discover_in(v080_vectors_dir(), "gp080", Some("gray-paper-0.8.0"))
}

// --- backend runners ---

/// The guest memory span implied by the page map (page-aligned).
fn span_of(page_map: &[(u32, u32, u8)]) -> u32 {
    page_map.iter().map(|(a, l, _)| a + l).max().unwrap_or(0)
}

/// Per-page permission table over the span (PERM_NONE off the map).
fn perms_of(v: &Vector) -> Vec<u8> {
    let span = span_of(&v.page_map);
    let mut perms = vec![PERM_NONE; (span / PAGE) as usize];
    for (addr, len, perm) in &v.page_map {
        for page in (addr / PAGE)..((addr + len) / PAGE) {
            perms[page as usize] = *perm;
        }
    }
    perms
}

fn isa_mode_for_vector(v: &Vector) -> IsaMode {
    // The gp072 corpus is retained through the transitional JAR adapter.
    // Its one explicit private-opcode exclusion case intentionally selects
    // the strict decoder; the independently versioned v0.8 corpus below is
    // always run in Conformance mode.
    if v.name == "flow_ecall_panics_under_conformance" {
        IsaMode::Conformance
    } else {
        IsaMode::Jar
    }
}

/// Run `v` on the interpreter under the given gas model. Returns the exit
/// and the machine for post-state inspection.
fn run_interpreter(v: &Vector, model: GasModel, isa_mode: IsaMode) -> (ExitReason, Interpreter) {
    let span = span_of(&v.page_map) as usize;
    let mut flat = vec![0u8; span];
    for (addr, bytes) in &v.memory {
        flat[*addr as usize..*addr as usize + bytes.len()].copy_from_slice(bytes);
    }
    let mut vm = Interpreter::new(
        v.code.clone(),
        v.bitmask.clone(),
        v.jump_table.clone(),
        v.regs,
        flat,
        v.gas,
        DEFAULT_MEM_CYCLES,
    );
    vm.set_isa_mode(isa_mode);
    vm.set_gas_model(model);
    vm.set_page_perms(perms_of(v));
    vm.set_pc(v.initial_pc);
    let (exit, _gas_used) = vm.run();
    (exit, vm)
}

fn check_interpreter(name: &str, v: &Vector, isa_mode: IsaMode) {
    let (exit, vm) = run_interpreter(v, GasModel::PerInstruction, isa_mode);
    assert_eq!(exit, v.exp_status, "{name}: exit status");
    assert_eq!(vm.pc, v.exp_pc, "{name}: post pc");
    assert_eq!(vm.gas, v.exp_gas, "{name}: remaining gas (per-instruction)");
    assert_eq!(vm.registers, v.exp_regs, "{name}: post register file");
    for (addr, want) in &v.exp_memory {
        let mut got = vec![0u8; want.len()];
        vm.memory().read_bytes(*addr, &mut got);
        assert_eq!(&got, want, "{name}: memory at {addr:#x}");
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn check_recompiler(name: &str, v: &Vector, isa_mode: IsaMode) {
    use vos_pvm::recompiler::{DataLayout, RecompiledPvm};

    let span = span_of(&v.page_map);
    let mut jit = RecompiledPvm::new_with_mode(
        &v.code,
        v.bitmask.clone(),
        v.jump_table.clone(),
        v.regs,
        v.gas,
        Some(DataLayout {
            mem_size: span,
            arg_start: 0,
            arg_data: vec![],
            ro_start: 0,
            ro_data: vec![],
            rw_start: 0,
            rw_data: vec![],
        }),
        DEFAULT_MEM_CYCLES,
        isa_mode,
    )
    .unwrap_or_else(|e| panic!("{name}: recompile failed: {e}"));
    for (addr, bytes) in &v.memory {
        assert!(jit.write_bytes(*addr, bytes), "{name}: seed memory");
    }
    jit.set_page_perms(&perms_of(v));
    jit.set_pc(v.initial_pc);
    let exit = jit.run();

    assert_eq!(exit, v.exp_status, "{name}: recompiler exit");
    for (addr, want) in &v.exp_memory {
        let got = jit
            .read_bytes(*addr, want.len() as u32)
            .unwrap_or_else(|| panic!("{name}: expected memory at {addr:#x} unreadable"));
        assert_eq!(&got, want, "{name}: recompiler memory at {addr:#x}");
    }

    // Differential gas anchor: under the block model the interpreter and
    // the recompiler must charge identically at every terminal boundary.
    // In particular, panic and page-fault exits are part of standard v0.8
    // metering and must not be masked by exit-only parity.
    let (block_exit, block_vm) = run_interpreter(v, GasModel::BlockPipeline, isa_mode);
    assert_eq!(
        block_exit, exit,
        "{name}: block-gas interpreter and recompiler classify identically"
    );
    let has_only_profile_opcodes = v
        .code
        .iter()
        .enumerate()
        .filter(|(pc, _)| v.bitmask.get(*pc) == Some(&1))
        .all(|(_, byte)| Opcode::from_byte_in_mode(*byte, isa_mode).is_some());
    if isa_mode == IsaMode::Conformance && has_only_profile_opcodes {
        assert_eq!(jit.pc(), v.exp_pc, "{name}: standard recompiler exit pc");
        assert_eq!(
            *jit.registers(),
            block_vm.registers,
            "{name}: complete standard register state"
        );
        assert_eq!(
            *jit.registers(),
            v.exp_regs,
            "{name}: standard registers match the reviewed oracle"
        );
        // Compare every byte on every mapped page, not only the explicitly
        // changed slices listed by the vector. This catches partial faulting
        // stores and accidental writes on panic/OOG paths.
        const CHUNK: u32 = 64 * 1024;
        for (base, len, _) in &v.page_map {
            let mut offset = 0u32;
            while offset < *len {
                let count = (*len - offset).min(CHUNK);
                let address = base.checked_add(offset).expect("mapped range address");
                let jit_bytes = jit
                    .read_bytes(address, count)
                    .unwrap_or_else(|| panic!("{name}: mapped memory at {address:#x}"));
                let mut interpreter_bytes = vec![0; count as usize];
                block_vm
                    .memory()
                    .read_bytes(address, &mut interpreter_bytes);
                assert_eq!(
                    jit_bytes, interpreter_bytes,
                    "{name}: complete mapped memory at {address:#x}"
                );
                offset += count;
            }
        }
    }
    if has_only_profile_opcodes {
        assert_eq!(
            jit.gas(),
            block_vm.gas,
            "{name}: block-gas consumption (interpreter vs recompiler)"
        );
    }
}

fn exact_state_interpreter(
    code: &[u8],
    bitmask: &[u8],
    registers: [u64; 13],
    memory: Vec<u8>,
    gas: u64,
    isa_mode: IsaMode,
) -> Interpreter {
    let mut vm = Interpreter::new(
        code.to_vec(),
        bitmask.to_vec(),
        vec![],
        registers,
        memory,
        gas,
        DEFAULT_MEM_CYCLES,
    );
    vm.set_isa_mode(isa_mode);
    vm.set_gas_model(GasModel::BlockPipeline);
    vm
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn exact_state_recompiler(
    code: &[u8],
    bitmask: &[u8],
    registers: [u64; 13],
    memory_span: u32,
    gas: u64,
    isa_mode: IsaMode,
) -> vos_pvm::recompiler::RecompiledPvm {
    use vos_pvm::recompiler::{DataLayout, RecompiledPvm};

    RecompiledPvm::new_with_mode(
        code,
        bitmask.to_vec(),
        vec![],
        registers,
        gas,
        Some(DataLayout {
            mem_size: memory_span,
            arg_start: 0,
            arg_data: vec![],
            ro_start: 0,
            ro_data: vec![],
            rw_start: 0,
            rw_data: vec![],
        }),
        DEFAULT_MEM_CYCLES,
        isa_mode,
    )
    .expect("compile exact-state regression")
}

/// Standard-memory harness spanning the complete 32-bit guest address
/// space without allocating a 4 GiB host buffer.
fn cyclic_sparse_interpreter(
    code: &[u8],
    bitmask: &[u8],
    registers: [u64; 13],
    gas: u64,
    isa_mode: IsaMode,
) -> Interpreter {
    let mut vm = Interpreter::with_memory(
        code.to_vec(),
        bitmask.to_vec(),
        vec![],
        registers,
        Memory::sparse(1u64 << 32),
        gas,
        DEFAULT_MEM_CYCLES,
    );
    vm.set_isa_mode(isa_mode);
    vm.set_gas_model(GasModel::BlockPipeline);
    vm
}

fn cyclic_permissions(high: u8) -> Vec<u8> {
    let mut permissions = vec![PERM_NONE; 1 << 20];
    // Deliberately map the low page: standard execution must still panic on
    // the initialization zone rather than trusting embedder permissions.
    permissions[0] = PERM_RW;
    permissions[(1 << 20) - 1] = high;
    permissions
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn cyclic_recompiler(
    code: &[u8],
    bitmask: &[u8],
    registers: [u64; 13],
    gas: u64,
    isa_mode: IsaMode,
) -> vos_pvm::recompiler::RecompiledPvm {
    exact_state_recompiler(code, bitmask, registers, u32::MAX, gas, isa_mode)
}

// --- tests ---

/// Independent Appendix A.5 category manifest. Keeping this transcription in
/// the conformance test (rather than deriving it from `Opcode::category`)
/// catches additions, omissions, and range drift in the production decoder.
const V080_CATEGORIES: &[(InstructionCategory, &[u8])] = &[
    (InstructionCategory::NoArgs, &[0, 1, 2]),
    (InstructionCategory::OneImm, &[10]),
    (InstructionCategory::OneRegExtImm, &[20]),
    (InstructionCategory::TwoImm, &[30, 31, 32, 33]),
    (InstructionCategory::OneOffset, &[40]),
    (
        InstructionCategory::OneRegOneImm,
        &[50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62],
    ),
    (InstructionCategory::OneRegTwoImm, &[70, 71, 72, 73]),
    (
        InstructionCategory::OneRegImmOffset,
        &[80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90],
    ),
    (
        InstructionCategory::TwoReg,
        &[100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110],
    ),
    (
        InstructionCategory::TwoRegOneImm,
        &[
            120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136,
            137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153,
            154, 155, 156, 157, 158, 159, 160, 161,
        ],
    ),
    (
        InstructionCategory::TwoRegOneOffset,
        &[170, 171, 172, 173, 174, 175],
    ),
    (InstructionCategory::TwoRegTwoImm, &[180]),
    (
        InstructionCategory::ThreeReg,
        &[
            190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206,
            207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
            224, 225, 226, 227, 228, 229, 230,
        ],
    ),
];

/// Appendix A.20 set T in v0.8.0. In particular, `unlikely` and `ecalli`
/// are not block terminators, and private opcode 3 is not an instruction.
const V080_TERMINATORS: &[u8] = &[
    0, 1, 40, 50, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 170, 171, 172, 173, 174, 175, 180,
];

#[test]
fn graypaper_v080_opcode_manifest_is_exact() {
    let mut valid_count = 0;
    for raw in 0u8..=u8::MAX {
        let expected: Vec<_> = V080_CATEGORIES
            .iter()
            .filter_map(|(category, bytes)| bytes.contains(&raw).then_some(*category))
            .collect();
        assert!(expected.len() <= 1, "opcode {raw} is listed more than once");

        match (Opcode::from_byte(raw), expected.first()) {
            (Some(opcode), Some(category)) => {
                valid_count += 1;
                assert_eq!(opcode as u8, raw, "opcode {raw}: discriminant");
                assert_eq!(opcode.category(), *category, "opcode {raw}: category");
                assert_eq!(
                    opcode.is_terminator(),
                    V080_TERMINATORS.contains(&raw),
                    "opcode {raw}: termination-set membership"
                );
            }
            (None, None) => {}
            (Some(opcode), None) => panic!("unlisted v0.8 opcode accepted: {opcode:?}"),
            (None, Some(_)) => panic!("listed v0.8 opcode rejected: {raw}"),
        }
    }
    assert_eq!(valid_count, 139, "v0.8.0 standard opcode count");
}

#[test]
fn graypaper_v080_executable_opcode_coverage_is_exact() {
    let expected: std::collections::BTreeSet<u8> = V080_CATEGORIES
        .iter()
        .flat_map(|(_, opcodes)| opcodes.iter().copied())
        .collect();
    // Count only each vector's initial instruction, rather than padding or an
    // instruction that a preceding exit may make unreachable. Thus equality
    // proves that every member of U owns at least one state-transition case in
    // which it is the first instruction actually submitted for execution.
    let covered: std::collections::BTreeSet<u8> = v080_corpus()
        .iter()
        .filter_map(|case| case.code.first().copied())
        .filter(|opcode| Opcode::from_byte(*opcode).is_some())
        .collect();

    let missing: Vec<_> = expected.difference(&covered).copied().collect();
    let unexpected: Vec<_> = covered.difference(&expected).copied().collect();
    assert_eq!(
        covered, expected,
        "v0.8 executable opcode coverage must be exactly U; missing={missing:?}, unexpected={unexpected:?}",
    );
}

/// The checked-in corpus is byte-identical to what the generator table
/// produces. Set `VOS_PVM_BLESS_VECTORS=1` to (re)write the files; stale
/// files (not produced by the table) fail the check and are removed by a
/// bless run.
#[test]
fn corpus_matches_the_generator_table() {
    let bless = std::env::var("VOS_PVM_BLESS_VECTORS").is_ok();
    let dir = vectors_dir();
    if bless {
        std::fs::create_dir_all(&dir).expect("create vectors dir");
    }

    let cases = corpus();
    let mut expected_files = Vec::new();
    for case in &cases {
        let file = format!("{}.gp072.json", case.name);
        let path = dir.join(&file);
        let rendered = serde_json::to_string_pretty(&to_json(case)).expect("render") + "\n";
        if bless {
            std::fs::write(&path, &rendered).expect("write vector");
        } else {
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{file}: {e} (re-bless the corpus)"));
            assert_eq!(on_disk, rendered, "{file} is stale — re-bless the corpus");
        }
        expected_files.push(file);
    }

    // No orphans: the corpus is exactly the table.
    for entry in std::fs::read_dir(&dir).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|e| e == "json") {
            let file = path.file_name().unwrap().to_string_lossy().into_owned();
            if !expected_files.contains(&file) {
                if bless {
                    std::fs::remove_file(&path).expect("remove stale vector");
                } else {
                    panic!("stale vector file {file} — re-bless the corpus");
                }
            }
        }
    }

    // Names are unique (files map 1:1 onto cases).
    let mut names: Vec<_> = cases.iter().map(|c| c.name.clone()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), cases.len(), "duplicate case names");
}

/// The v0.8.0 corpus is a separately checked-in, explicitly identified
/// contract. A bless run regenerates it only from [`v080_corpus`].
#[test]
fn graypaper_v080_corpus_matches_the_generator_table() {
    let bless = std::env::var("VOS_PVM_BLESS_VECTORS").is_ok();
    let dir = v080_vectors_dir();
    if bless {
        std::fs::create_dir_all(&dir).expect("create v0.8 vectors dir");
    }

    let cases = v080_corpus();
    let mut expected_files = Vec::new();
    for case in &cases {
        let file = format!("{}.gp080.json", case.name);
        let path = dir.join(&file);
        let rendered = serde_json::to_string_pretty(&to_v080_json(case)).expect("render") + "\n";
        if bless {
            std::fs::write(&path, &rendered).expect("write v0.8 vector");
        } else {
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{file}: {e} (re-bless the corpus)"));
            assert_eq!(on_disk, rendered, "{file} is stale — re-bless the corpus");
        }
        expected_files.push(file);
    }

    for entry in std::fs::read_dir(&dir).expect("read v0.8 vectors dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|e| e == "json") {
            let file = path.file_name().unwrap().to_string_lossy().into_owned();
            if !expected_files.contains(&file) {
                if bless {
                    std::fs::remove_file(&path).expect("remove stale v0.8 vector");
                } else {
                    panic!("stale v0.8 vector file {file} — re-bless the corpus");
                }
            }
        }
    }

    let mut names: Vec<_> = cases.iter().map(|c| c.name.clone()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), cases.len(), "duplicate v0.8 case names");
    assert_eq!(cases.len(), V080_CASE_COUNT, "reviewed v0.8 case count");
}

/// The small, auditable gas oracle is also checked in. It is intentionally a
/// separate schema so historical per-instruction vectors cannot silently
/// acquire v0.8 block-gas meaning.
#[test]
fn graypaper_v080_block_gas_corpus_matches_the_oracle_table() {
    let bless = std::env::var("VOS_PVM_BLESS_VECTORS").is_ok();
    let dir = v080_gas_vectors_dir();
    if bless {
        std::fs::create_dir_all(&dir).expect("create v0.8 gas vectors dir");
    }

    let cases = v080_block_gas_corpus();
    let mut expected_files = Vec::new();
    for case in &cases {
        let file = format!("{}.gp080.json", case.name);
        let path = dir.join(&file);
        let rendered =
            serde_json::to_string_pretty(&block_gas_to_json(case)).expect("render") + "\n";
        if bless {
            std::fs::write(&path, &rendered).expect("write v0.8 gas vector");
        } else {
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{file}: {e} (re-bless the corpus)"));
            assert_eq!(on_disk, rendered, "{file} is stale — re-bless the corpus");
        }
        expected_files.push(file);
    }

    for entry in std::fs::read_dir(&dir).expect("read v0.8 gas vectors dir") {
        let path = entry.expect("dir entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let file = path.file_name().unwrap().to_string_lossy().into_owned();
            if !expected_files.contains(&file) {
                if bless {
                    std::fs::remove_file(&path).expect("remove stale v0.8 gas vector");
                } else {
                    panic!("stale v0.8 gas vector file {file} — re-bless the corpus");
                }
            }
        }
    }
    assert_eq!(
        cases.len(),
        V080_BLOCK_GAS_CASE_COUNT,
        "v0.8 gas oracle case count",
    );
}

/// Every checked-in vector holds on the interpreter under the GP 0.7.2
/// per-instruction gas model.
#[test]
fn interpreter_satisfies_every_vector() {
    let vectors = discover();
    for (file, v) in &vectors {
        check_interpreter(file, v, isa_mode_for_vector(v));
    }
    // Guard against silently running an emptied corpus.
    assert!(vectors.len() >= 100, "corpus shrank: {}", vectors.len());
}

/// The complete current corpus executes only under the strict v0.8.0
/// profile. This is the release conformance gate; the gp072 test above is a
/// historical compatibility check.
#[test]
fn graypaper_v080_interpreter_satisfies_every_vector() {
    let vectors = discover_v080();
    for (file, vector) in &vectors {
        check_interpreter(file, vector, IsaMode::Conformance);
    }
    assert_eq!(
        vectors.len(),
        V080_CASE_COUNT,
        "complete v0.8 corpus cardinality",
    );
}

/// Execute the checked-in v0.8.0 block-gas judgements. Both block boundaries
/// and numerical costs are asserted before execution; exit precedence and
/// remaining gas are then checked from the JSON contract.
#[test]
fn graypaper_v080_block_gas_matches_checked_in_oracle() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use vos_pvm::recompiler::{DataLayout, RecompiledPvm};

    let dir = v080_gas_vectors_dir();
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("gas vector entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    assert_eq!(
        files.len(),
        V080_BLOCK_GAS_CASE_COUNT,
        "complete v0.8 block-gas oracle",
    );

    for path in files {
        let file = path.file_name().unwrap().to_string_lossy();
        let text = std::fs::read_to_string(&path).expect("read gas vector");
        let value: Value = serde_json::from_str(&text).expect("parse gas vector");
        assert_eq!(
            value["spec"].as_str(),
            Some("gray-paper-0.8.0"),
            "{file}: specification identity"
        );
        assert_eq!(
            value["rule"].as_str(),
            Some("gray-paper-v0.8-rob-block-gas"),
            "{file}: gas rule identity"
        );

        let code = unhex_bytes(value["program"]["code"].as_str().expect("code"));
        let bitmask = unpack_bitmask(
            &unhex_bytes(value["program"]["bitmask"].as_str().expect("bitmask")),
            code.len(),
        );
        let gas = value["initial"]["gas"].as_u64().expect("initial gas");
        let regs = regs_from_json(&value["initial"]["regs"]);

        let blocks: Vec<(u32, u32)> = value["expected"]["blocks"]
            .as_array()
            .expect("blocks")
            .iter()
            .map(|block| {
                (
                    block["pc"].as_u64().expect("block pc") as u32,
                    block["gas"].as_u64().expect("block gas") as u32,
                )
            })
            .collect();

        let mut vm = Interpreter::new(
            code.clone(),
            bitmask.clone(),
            vec![],
            regs,
            vec![],
            gas,
            DEFAULT_MEM_CYCLES,
        );
        vm.set_isa_mode(IsaMode::Conformance);
        vm.set_gas_model(GasModel::BlockPipeline);

        for pc in 0..code.len() {
            let expected = blocks.iter().find(|(start, _)| *start as usize == pc);
            assert_eq!(
                vm.is_basic_block_start(pc as u64),
                expected.is_some(),
                "{file}: block-start membership at pc {pc}"
            );
            assert_eq!(
                vm.block_gas_costs[pc],
                expected.map_or(0, |(_, cost)| *cost),
                "{file}: block cost at pc {pc}"
            );
        }

        let first = &value["expected"]["first"];
        let (exit, _) = vm.run();
        assert_eq!(exit, exit_from_json(first), "{file}: first exit");
        assert_eq!(
            vm.gas,
            first["remaining_gas"].as_u64().expect("remaining gas"),
            "{file}: first remaining gas"
        );

        if !value["expected"]["resume"].is_null() {
            let resume = &value["expected"]["resume"];
            assert!(
                vm.resume_after_host_call(),
                "{file}: resume follows a standard host call"
            );
            let (exit, _) = vm.run();
            assert_eq!(exit, exit_from_json(resume), "{file}: resume exit");
            assert_eq!(
                vm.gas,
                resume["remaining_gas"].as_u64().expect("resume gas"),
                "{file}: resume remaining gas"
            );
        }

        // The checked-in oracle is also a backend-parity gate. It includes
        // panic, page-fault, out-of-gas, and resumable host-call boundaries,
        // so every independently reviewed ROB judgement is consumed by both
        // implementations rather than merely by the interpreter.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let memory_span = 0x40000u32;
            let mut jit = RecompiledPvm::new_with_mode(
                &code,
                bitmask,
                vec![],
                regs,
                gas,
                Some(DataLayout {
                    mem_size: memory_span,
                    arg_start: 0,
                    arg_data: vec![],
                    ro_start: 0,
                    ro_data: vec![],
                    rw_start: 0,
                    rw_data: vec![],
                }),
                DEFAULT_MEM_CYCLES,
                IsaMode::Conformance,
            )
            .unwrap_or_else(|error| panic!("{file}: recompile oracle: {error}"));
            jit.set_page_perms(&vec![PERM_NONE; (memory_span / PAGE) as usize]);

            let exit = jit.run();
            assert_eq!(exit, exit_from_json(first), "{file}: JIT first exit");
            assert_eq!(
                jit.gas(),
                first["remaining_gas"].as_u64().expect("remaining gas"),
                "{file}: JIT first remaining gas"
            );

            if !value["expected"]["resume"].is_null() {
                let resume = &value["expected"]["resume"];
                assert!(
                    jit.acknowledge_host_call(),
                    "{file}: JIT resume follows a standard host call"
                );
                let exit = jit.run();
                assert_eq!(exit, exit_from_json(resume), "{file}: JIT resume exit");
                assert_eq!(
                    jit.gas(),
                    resume["remaining_gas"].as_u64().expect("resume gas"),
                    "{file}: JIT resume remaining gas"
                );
            }
        }
    }
}

/// A program declaring more than 2,048 pages selects the 50-cycle VOS page
/// tier. That tier must remain observable under the capability/JAR profile,
/// while standard v0.8 execution stays at its fixed 25-cycle memory latency.
#[test]
fn high_page_memory_latency_is_profile_scoped() {
    let high_page_tier = vos_pvm::compute_mem_cycles(2_049);
    assert_eq!(
        high_page_tier, 50,
        "regression must cross the first VOS tier"
    );
    let (code, bitmask) = asm(&[&[58, 2, 0, 0, 3], &[0]]);

    let make_vm = |isa_mode, mem_cycles| {
        let mut vm = Interpreter::new(
            code.clone(),
            bitmask.clone(),
            vec![],
            [0; 13],
            vec![0; 0x40000],
            100,
            mem_cycles,
        );
        vm.set_isa_mode(isa_mode);
        vm.set_gas_model(GasModel::BlockPipeline);
        vm.set_page_perms(vec![PERM_NONE; 0x40000 / PAGE as usize]);
        vm
    };

    let standard_baseline = make_vm(IsaMode::Conformance, DEFAULT_MEM_CYCLES);
    let mut standard_high_pages = make_vm(IsaMode::Conformance, high_page_tier);
    let jar_baseline = make_vm(IsaMode::Jar, DEFAULT_MEM_CYCLES);
    let jar_high_pages = make_vm(IsaMode::Jar, high_page_tier);

    assert_eq!(standard_high_pages.mem_cycles, DEFAULT_MEM_CYCLES);
    assert_eq!(standard_high_pages.block_gas_costs[0], 25);
    assert_eq!(
        standard_high_pages.block_gas_costs, standard_baseline.block_gas_costs,
        "declared page count cannot change standard v0.8 gas"
    );
    assert_ne!(
        jar_high_pages.block_gas_costs, jar_baseline.block_gas_costs,
        "the VOS service profile retains its page-tier gas contract"
    );

    let (exit, _) = standard_high_pages.run();
    assert_eq!(exit, ExitReason::PageFault(0x30000));
    assert_eq!(standard_high_pages.gas, 75, "standard load block costs 25");

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use vos_pvm::recompiler::{DataLayout, RecompiledPvm};

        let mut jit = RecompiledPvm::new_with_mode(
            &code,
            bitmask,
            vec![],
            [0; 13],
            100,
            Some(DataLayout {
                mem_size: 0x40000,
                arg_start: 0,
                arg_data: vec![],
                ro_start: 0,
                ro_data: vec![],
                rw_start: 0,
                rw_data: vec![],
            }),
            high_page_tier,
            IsaMode::Conformance,
        )
        .expect("compile high-page standard regression");
        jit.set_page_perms(&vec![PERM_NONE; 0x40000 / PAGE as usize]);
        assert_eq!(jit.run(), exit);
        assert_eq!(jit.gas(), standard_high_pages.gas);
    }
}

/// Full standard Ψ exposes the causing counter for retryable exits, but
/// normalizes successful halt and panic to zero. Host continuation is an
/// explicit transition and does not fund the surrounding block twice.
#[test]
fn v080_external_exit_counters_and_host_resume_are_exact() {
    // A posterior register write is retained even though the following
    // nonzero opcode-0 instruction panics and normalizes the final PC.
    let (panic_code, panic_bits) = asm(&[&[51, 2, 9], &[0]]);
    let mut interpreter = exact_state_interpreter(
        &panic_code,
        &panic_bits,
        [0; 13],
        vec![],
        100,
        IsaMode::Conformance,
    );
    assert_eq!(interpreter.run().0, ExitReason::Panic);
    assert_eq!(interpreter.pc, 0);
    assert_eq!(interpreter.registers[2], 9);

    // The transitional profile remains distinct: opcode zero is Trap and
    // retains its causing PC.
    let mut jar =
        exact_state_interpreter(&panic_code, &panic_bits, [0; 13], vec![], 100, IsaMode::Jar);
    assert_eq!(jar.run().0, ExitReason::Trap);
    assert_eq!(jar.pc, 3);

    // A jump-indirect at a nonzero PC exits successfully through the halt
    // sentinel. Full standard Ψ still returns PC zero.
    let (halt_code, halt_bits) = asm(&[&[1], &[50, 2]]);
    let mut halt_regs = [0; 13];
    halt_regs[2] = PVM_HALT_ADDR;
    let mut interpreter = exact_state_interpreter(
        &halt_code,
        &halt_bits,
        halt_regs,
        vec![],
        100,
        IsaMode::Conformance,
    );
    assert_eq!(interpreter.run().0, ExitReason::Halt);
    assert_eq!(interpreter.pc, 0);

    // ecalli is at PC 3. The external host boundary exposes 3, then the
    // explicit resume enters PC 5 without charging the prepaid block again.
    let (host_code, host_bits) = asm(&[&[51, 2, 9], &[10, 7], &[0]]);
    let mut interpreter = exact_state_interpreter(
        &host_code,
        &host_bits,
        [0; 13],
        vec![],
        200,
        IsaMode::Conformance,
    );
    assert_eq!(interpreter.run().0, ExitReason::HostCall(7));
    assert_eq!(interpreter.pc, 3);
    assert_eq!(interpreter.registers[2], 9);
    let host_gas = interpreter.gas;
    assert!(interpreter.resume_after_host_call());
    assert_eq!(interpreter.run().0, ExitReason::Panic);
    assert_eq!(interpreter.pc, 0);
    assert_eq!(interpreter.gas, host_gas);

    let mut jar =
        exact_state_interpreter(&host_code, &host_bits, [0; 13], vec![], 200, IsaMode::Jar);
    assert_eq!(jar.run().0, ExitReason::HostCall(7));
    assert_eq!(jar.pc, 5, "JAR retains its advanced host-call counter");

    // The first fallthrough block is funded, but the block beginning at PC
    // 1 is not. OOG exposes that cause and preserves pre-instruction state.
    let (oog_code, oog_bits) = asm(&[&[1], &[51, 2, 9], &[0]]);
    let mut oog_regs = [0; 13];
    oog_regs[2] = 77;
    let mut interpreter = exact_state_interpreter(
        &oog_code,
        &oog_bits,
        oog_regs,
        vec![],
        2,
        IsaMode::Conformance,
    );
    assert_eq!(interpreter.run().0, ExitReason::OutOfGas);
    assert_eq!(interpreter.pc, 1);
    assert_eq!(interpreter.gas, 0);
    assert_eq!(interpreter.registers[2], 77);

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let mut jit = exact_state_recompiler(
            &panic_code,
            &panic_bits,
            [0; 13],
            PAGE,
            100,
            IsaMode::Conformance,
        );
        assert_eq!(jit.run(), ExitReason::Panic);
        assert_eq!(jit.pc(), 0);
        assert_eq!(jit.registers()[2], 9);

        let mut jit = exact_state_recompiler(
            &halt_code,
            &halt_bits,
            halt_regs,
            PAGE,
            100,
            IsaMode::Conformance,
        );
        assert_eq!(jit.run(), ExitReason::Halt);
        assert_eq!(jit.pc(), 0);

        let mut jit = exact_state_recompiler(
            &host_code,
            &host_bits,
            [0; 13],
            PAGE,
            200,
            IsaMode::Conformance,
        );
        assert_eq!(jit.run(), ExitReason::HostCall(7));
        assert_eq!(jit.pc(), 3);
        assert_eq!(jit.registers()[2], 9);
        let host_gas = jit.gas();
        assert_eq!(jit.run(), ExitReason::HostCall(7));
        assert_eq!(jit.gas(), host_gas);
        assert!(jit.acknowledge_host_call());
        assert_eq!(jit.run(), ExitReason::Panic);
        assert_eq!(jit.pc(), 0);
        assert_eq!(jit.gas(), host_gas);

        let mut jit = exact_state_recompiler(
            &oog_code,
            &oog_bits,
            oog_regs,
            PAGE,
            2,
            IsaMode::Conformance,
        );
        assert_eq!(jit.run(), ExitReason::OutOfGas);
        assert_eq!(jit.pc(), 1);
        assert_eq!(jit.gas(), 0);
        assert_eq!(jit.registers()[2], 77);
    }
}

/// The standard machine exposes the complete sign-extended immediate as the
/// host identifier. The transitional JAR profile deliberately retains its
/// frozen zero-extended-u32 projection so existing Service traces and
/// capability dispatch remain byte-for-byte compatible.
#[test]
fn ecalli_identifier_width_is_profile_scoped() {
    let cases: &[(&[u8], u64, u64)] = &[
        (&[0xff], u64::MAX, u64::from(u32::MAX)),
        (
            &[0x00, 0x00, 0x00, 0x80],
            0xffff_ffff_8000_0000,
            0x8000_0000,
        ),
        (&[0xff, 0xff, 0xff, 0x7f], 0x7fff_ffff, 0x7fff_ffff),
    ];
    let registers = core::array::from_fn(|index| 0x5a00 + index as u64);

    for (immediate, standard_id, jar_id) in cases {
        let mut code = vec![10];
        code.extend_from_slice(immediate);
        code.push(0);
        let mut bitmask = vec![1];
        bitmask.extend(core::iter::repeat_n(0, immediate.len()));
        bitmask.push(1);

        let mut standard = exact_state_interpreter(
            &code,
            &bitmask,
            registers,
            vec![0xa5; PAGE as usize],
            1_000,
            IsaMode::Conformance,
        );
        assert_eq!(standard.run().0, ExitReason::HostCall(*standard_id));
        assert_eq!(standard.registers, registers);
        let mut actual = vec![0; PAGE as usize];
        standard.memory().read_bytes(0, &mut actual);
        assert_eq!(actual, vec![0xa5; PAGE as usize]);

        let mut jar = exact_state_interpreter(
            &code,
            &bitmask,
            registers,
            vec![0xa5; PAGE as usize],
            1_000,
            IsaMode::Jar,
        );
        assert_eq!(jar.run().0, ExitReason::HostCall(*jar_id));
        assert_eq!(jar.registers, registers);

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let mut standard = exact_state_recompiler(
                &code,
                &bitmask,
                registers,
                PAGE,
                1_000,
                IsaMode::Conformance,
            );
            assert_eq!(standard.run(), ExitReason::HostCall(*standard_id));
            assert_eq!(*standard.registers(), registers);

            let mut jar =
                exact_state_recompiler(&code, &bitmask, registers, PAGE, 1_000, IsaMode::Jar);
            assert_eq!(jar.run(), ExitReason::HostCall(*jar_id));
            assert_eq!(*jar.registers(), registers);
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn rem_u32_zero_divisor_jit_result_is_profile_scoped() {
    let (code, bitmask) = asm(&[&[Opcode::RemU32 as u8, 0x32, 4], &[0]]);
    let cases = [(0x1_0000_0007, 7), (0x8000_0000, 0xffff_ffff_8000_0000)];

    for (dividend, standard_result) in cases {
        let mut registers = [0; 13];
        registers[2] = dividend;

        let mut interpreter = exact_state_interpreter(
            &code,
            &bitmask,
            registers,
            vec![],
            1_000,
            IsaMode::Conformance,
        );
        assert_eq!(interpreter.run().0, ExitReason::Panic);
        assert_eq!(interpreter.registers[4], standard_result);

        let mut standard = exact_state_recompiler(
            &code,
            &bitmask,
            registers,
            PAGE,
            1_000,
            IsaMode::Conformance,
        );
        assert_eq!(standard.run(), ExitReason::Panic);
        assert_eq!(standard.registers()[4], standard_result);

        let mut jar = exact_state_recompiler(&code, &bitmask, registers, PAGE, 1_000, IsaMode::Jar);
        assert_eq!(jar.run(), ExitReason::Trap);
        assert_eq!(
            jar.registers()[4],
            dividend,
            "frozen JAR/JIT copies the complete dividend on zero divisor"
        );
    }
}

/// Standard addresses below 2^16 panic before consulting page permissions,
/// even if the embedder maps those bytes. JAR retains its legacy mapped-low
/// memory behavior.
#[test]
fn v080_low_zone_panics_before_a_mapped_memory_access() {
    let (code, bitmask) = asm(&[&[58, 3, 0, 0, 0], &[0]]);
    let mut registers = [0; 13];
    registers[3] = 77;
    let mut memory = vec![0; PAGE as usize];
    memory[0] = 0xab;

    let mut interpreter = exact_state_interpreter(
        &code,
        &bitmask,
        registers,
        memory.clone(),
        100,
        IsaMode::Conformance,
    );
    interpreter.set_page_perms(vec![PERM_RW]);
    assert_eq!(interpreter.run().0, ExitReason::Panic);
    assert_eq!(interpreter.pc, 0);
    assert_eq!(interpreter.registers[3], 77);

    let mut jar = exact_state_interpreter(&code, &bitmask, registers, memory, 100, IsaMode::Jar);
    jar.set_page_perms(vec![PERM_RW]);
    assert_eq!(jar.run().0, ExitReason::Trap);
    assert_eq!(jar.registers[3], 0xab);

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let mut jit =
            exact_state_recompiler(&code, &bitmask, registers, PAGE, 100, IsaMode::Conformance);
        assert!(jit.write_bytes(0, &[0xab]));
        jit.set_page_perms(&[PERM_RW]);
        assert_eq!(jit.run(), ExitReason::Panic);
        assert_eq!(jit.pc(), 0);
        assert_eq!(jit.registers()[3], 77);

        let mut jit = exact_state_recompiler(&code, &bitmask, registers, PAGE, 100, IsaMode::Jar);
        assert!(jit.write_bytes(0, &[0xab]));
        jit.set_page_perms(&[PERM_RW]);
        assert_eq!(jit.run(), ExitReason::Trap);
        assert_eq!(jit.registers()[3], 0xab);
    }
}

/// Wide accesses are ordered over their raw integer indices before each byte
/// address is reduced modulo 2^32. An inaccessible high tail therefore faults
/// before the later wrapped low-zone byte; an accessible high tail reaches
/// that low byte and panics even when page zero was mapped by the embedder.
#[test]
fn v080_cyclic_wide_access_orders_high_tail_before_low_zone() {
    const ADDRESS: u32 = 0xffff_fffc;
    const SENTINEL: u64 = 0xfeed_face_cafe_beef;
    let (code, bitmask) = asm(&[&[130, 2 + 16 * 3], &[0]]); // load_ind_u64 r2,[r3]
    let mut registers = [0; 13];
    registers[2] = SENTINEL;
    registers[3] = u64::from(ADDRESS);

    for (high_perm, expected) in [
        (PERM_RW, ExitReason::Panic),
        (PERM_RO, ExitReason::Panic),
        (PERM_NONE, ExitReason::PageFault(0xffff_f000)),
    ] {
        let permissions = cyclic_permissions(high_perm);
        let mut interpreter =
            cyclic_sparse_interpreter(&code, &bitmask, registers, 100, IsaMode::Conformance);
        interpreter.set_page_perms(permissions.clone());
        assert_eq!(
            interpreter.run().0,
            expected,
            "interpreter perm={high_perm}"
        );
        assert_eq!(interpreter.registers[2], SENTINEL);

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let mut jit = cyclic_recompiler(&code, &bitmask, registers, 100, IsaMode::Conformance);
            jit.set_page_perms(&permissions);
            assert_eq!(jit.run(), expected, "JIT perm={high_perm}");
            assert_eq!(jit.registers()[2], SENTINEL);
            assert_eq!(jit.gas(), interpreter.gas);
        }
    }

    // The transitional profile remains safe and backend-identical without
    // changing its old overflowing-range classification.
    for (high_perm, expected) in [
        (PERM_RW, ExitReason::PageFault(0)),
        (PERM_NONE, ExitReason::PageFault(0xffff_f000)),
    ] {
        let permissions = cyclic_permissions(high_perm);
        let mut interpreter =
            cyclic_sparse_interpreter(&code, &bitmask, registers, 100, IsaMode::Jar);
        interpreter.set_page_perms(permissions.clone());
        assert_eq!(interpreter.run().0, expected);

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let mut jit = cyclic_recompiler(&code, &bitmask, registers, 100, IsaMode::Jar);
            jit.set_page_perms(&permissions);
            assert_eq!(jit.run(), expected);
        }
    }
}

/// A wrapped store validates its complete ordered access before mutation.
/// Repeated high-page faults and the eventual repaired-page retry all reuse
/// the already funded gas block.
#[test]
fn v080_cyclic_store_is_atomic_and_retry_does_not_recharge() {
    const ADDRESS: u32 = 0xffff_fffc;
    const VALUE: u64 = 0x1122_3344_5566_7788;
    const OLD: [u8; 8] = [0xa0, 0xa1, 0xa2, 0xa3, 0xb0, 0xb1, 0xb2, 0xb3];
    let (code, bitmask) = asm(&[&[123, 2 + 16 * 3], &[0]]); // store_ind_u64 [r3],r2
    let mut registers = [0; 13];
    registers[2] = VALUE;
    registers[3] = u64::from(ADDRESS);

    let read_interpreter = |vm: &Interpreter| {
        let mut bytes = [0; 8];
        vm.memory().read_bytes(ADDRESS, &mut bytes[..4]);
        vm.memory().read_bytes(0, &mut bytes[4..]);
        bytes
    };

    let mut interpreter =
        cyclic_sparse_interpreter(&code, &bitmask, registers, 100, IsaMode::Conformance);
    interpreter.memory_mut().init_copy(ADDRESS, &OLD[..4]);
    interpreter.memory_mut().init_copy(0, &OLD[4..]);
    interpreter.set_page_perms(cyclic_permissions(PERM_NONE));
    assert_eq!(interpreter.run().0, ExitReason::PageFault(0xffff_f000));
    let funded_gas = interpreter.gas;
    assert_eq!(read_interpreter(&interpreter), OLD);
    assert_eq!(interpreter.run().0, ExitReason::PageFault(0xffff_f000));
    assert_eq!(interpreter.gas, funded_gas, "repeated fault stays funded");
    interpreter.set_page_perms(cyclic_permissions(PERM_RW));
    assert_eq!(interpreter.run().0, ExitReason::Panic);
    assert_eq!(
        interpreter.gas, funded_gas,
        "fault-to-panic retry stays funded"
    );
    assert_eq!(
        read_interpreter(&interpreter),
        OLD,
        "store is failure-atomic"
    );

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let mut jit = cyclic_recompiler(&code, &bitmask, registers, 100, IsaMode::Conformance);
        assert!(jit.write_bytes(ADDRESS, &OLD));
        jit.set_page_perms(&cyclic_permissions(PERM_NONE));
        assert_eq!(jit.run(), ExitReason::PageFault(0xffff_f000));
        let jit_funded_gas = jit.gas();
        assert_eq!(jit.run(), ExitReason::PageFault(0xffff_f000));
        assert_eq!(jit.gas(), jit_funded_gas);
        jit.set_page_perms(&cyclic_permissions(PERM_RW));
        assert_eq!(jit.read_bytes(ADDRESS, 8).as_deref(), Some(&OLD[..]));
        assert_eq!(jit.run(), ExitReason::Panic);
        assert_eq!(jit.gas(), jit_funded_gas);
        assert_eq!(jit.gas(), funded_gas);
        assert_eq!(jit.read_bytes(ADDRESS, 8).as_deref(), Some(&OLD[..]));
    }

    // Gas funding precedes memory validation and is itself atomic on OOG.
    let probe = cyclic_sparse_interpreter(&code, &bitmask, registers, 100, IsaMode::Conformance);
    let insufficient = u64::from(probe.block_gas_costs[0]) - 1;
    let mut interpreter = cyclic_sparse_interpreter(
        &code,
        &bitmask,
        registers,
        insufficient,
        IsaMode::Conformance,
    );
    interpreter.set_page_perms(cyclic_permissions(PERM_NONE));
    assert_eq!(interpreter.run().0, ExitReason::OutOfGas);
    assert_eq!(interpreter.gas, insufficient);

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let mut jit = cyclic_recompiler(
            &code,
            &bitmask,
            registers,
            insufficient,
            IsaMode::Conformance,
        );
        jit.set_page_perms(&cyclic_permissions(PERM_NONE));
        assert_eq!(jit.run(), ExitReason::OutOfGas);
        assert_eq!(jit.gas(), insufficient);
    }
}

/// Exact top-of-space boundaries catch unsigned and off-by-one errors in the
/// native overflow branch for every scalar load width.
#[test]
fn v080_cyclic_load_width_boundaries_are_exact() {
    const SENTINEL: u64 = 0xfeed_face_cafe_beef;
    const HIGH: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    for (opcode, width) in [(124u8, 1usize), (126, 2), (128, 4), (130, 8)] {
        let (code, bitmask) = asm(&[&[opcode, 2 + 16 * 3], &[0]]);
        let safe_addr = u32::MAX - (width as u32 - 1);
        let mut registers = [0; 13];
        registers[2] = SENTINEL;
        registers[3] = u64::from(safe_addr);

        let mut interpreter =
            cyclic_sparse_interpreter(&code, &bitmask, registers, 100, IsaMode::Conformance);
        interpreter.memory_mut().init_copy(u32::MAX - 7, &HIGH);
        interpreter.set_page_perms(cyclic_permissions(PERM_RO));
        assert_eq!(interpreter.run().0, ExitReason::Panic);
        let mut expected_bytes = [0u8; 8];
        expected_bytes[..width].copy_from_slice(&HIGH[8 - width..]);
        let expected = u64::from_le_bytes(expected_bytes);
        assert_eq!(interpreter.registers[2], expected, "safe width {width}");

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let mut jit = cyclic_recompiler(&code, &bitmask, registers, 100, IsaMode::Conformance);
            assert!(jit.write_bytes(u32::MAX - 7, &HIGH));
            jit.set_page_perms(&cyclic_permissions(PERM_RO));
            assert_eq!(jit.run(), ExitReason::Panic);
            assert_eq!(jit.registers()[2], expected, "JIT safe width {width}");
        }

        if width > 1 {
            registers[3] = u64::from(safe_addr + 1);
            let mut interpreter =
                cyclic_sparse_interpreter(&code, &bitmask, registers, 100, IsaMode::Conformance);
            interpreter.set_page_perms(cyclic_permissions(PERM_RO));
            assert_eq!(interpreter.run().0, ExitReason::Panic);
            assert_eq!(interpreter.registers[2], SENTINEL, "wrapped width {width}");

            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                let mut jit =
                    cyclic_recompiler(&code, &bitmask, registers, 100, IsaMode::Conformance);
                jit.set_page_perms(&cyclic_permissions(PERM_RO));
                assert_eq!(jit.run(), ExitReason::Panic);
                assert_eq!(jit.registers()[2], SENTINEL, "JIT wrapped width {width}");
            }
        }
    }
}

/// Run all distinct JIT memory emitters in a child process. If any family
/// misses the cyclic guard, a native access past the 4 GiB mapping can kill
/// only the child and this test reports a deterministic failure.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn v080_cyclic_jit_memory_families_stay_inside_native_window() {
    const CHILD_ENV: &str = "VOS_PVM_CYCLIC_MEMORY_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "v080_cyclic_jit_memory_families_stay_inside_native_window",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .status()
            .expect("spawn cyclic-memory child");
        assert!(status.success(), "cyclic-memory child exited {status}");
        return;
    }

    const ADDRESS: u32 = 0xffff_fffe;
    const A: [u8; 4] = ADDRESS.to_le_bytes();
    const OLD: [u8; 4] = [0xa1, 0xa2, 0xb1, 0xb2];
    let programs = [
        asm(&[&[58, 2, A[0], A[1], A[2], A[3]], &[0]]), // direct load
        asm(&[&[62, 2, A[0], A[1], A[2], A[3]], &[0]]), // direct store
        asm(&[
            &[33, 4, A[0], A[1], A[2], A[3], 0x78, 0x56, 0x34, 0x12],
            &[0],
        ]),
        asm(&[&[130, 2 + 16 * 3], &[0]]), // indirect load
        asm(&[&[123, 2 + 16 * 3], &[0]]), // indirect store
        asm(&[&[73, 2, 0x78, 0x56, 0x34, 0x12], &[0]]), // store imm indirect
    ];
    let mut registers = [0; 13];
    registers[2] = u64::from(ADDRESS);
    registers[3] = u64::from(ADDRESS);
    let fault_permissions = cyclic_permissions(PERM_NONE);
    let mapped_permissions = cyclic_permissions(PERM_RW);

    for (family, (code, bitmask)) in programs.into_iter().enumerate() {
        let mut interpreter =
            cyclic_sparse_interpreter(&code, &bitmask, registers, 100, IsaMode::Conformance);
        interpreter.set_page_perms(fault_permissions.clone());
        assert_eq!(
            interpreter.run().0,
            ExitReason::PageFault(0xffff_f000),
            "interpreter family {family}"
        );

        let mut jit = cyclic_recompiler(&code, &bitmask, registers, 100, IsaMode::Conformance);
        jit.set_page_perms(&fault_permissions);
        assert_eq!(
            jit.run(),
            ExitReason::PageFault(0xffff_f000),
            "JIT family {family}"
        );
        assert_eq!(jit.gas(), interpreter.gas, "family {family} gas");

        // With the high tail accessible, all six emitters must classify the
        // subsequently wrapped low-zone byte as Panic before executing the
        // load/store. Register and memory state therefore remain unchanged.
        let mut interpreter =
            cyclic_sparse_interpreter(&code, &bitmask, registers, 100, IsaMode::Conformance);
        interpreter.memory_mut().init_copy(ADDRESS, &OLD[..2]);
        interpreter.memory_mut().init_copy(0, &OLD[2..]);
        interpreter.set_page_perms(mapped_permissions.clone());
        assert_eq!(
            interpreter.run().0,
            ExitReason::Panic,
            "mapped interpreter family {family}"
        );
        assert_eq!(
            interpreter.registers, registers,
            "family {family} registers"
        );
        let mut interpreter_bytes = [0; 4];
        interpreter
            .memory()
            .read_bytes(ADDRESS, &mut interpreter_bytes[..2]);
        interpreter
            .memory()
            .read_bytes(0, &mut interpreter_bytes[2..]);
        assert_eq!(interpreter_bytes, OLD, "family {family} memory");

        let mut jit = cyclic_recompiler(&code, &bitmask, registers, 100, IsaMode::Conformance);
        assert!(jit.write_bytes(ADDRESS, &OLD));
        jit.set_page_perms(&mapped_permissions);
        assert_eq!(jit.run(), ExitReason::Panic, "mapped JIT family {family}");
        assert_eq!(*jit.registers(), registers, "JIT family {family} registers");
        assert_eq!(
            jit.read_bytes(ADDRESS, OLD.len() as u32).as_deref(),
            Some(&OLD[..]),
            "JIT family {family} memory"
        );
        assert_eq!(jit.gas(), interpreter.gas, "mapped family {family} gas");
    }
}

/// A faulting cross-page store has no partial effect. After the missing page
/// is mapped, retry begins at the same causing PC after the already-paid gas
/// charge and completes exactly once.
#[test]
fn v080_page_fault_retry_preserves_state_and_does_not_recharge() {
    const STORE_ADDR: u32 = 0x30ffc;
    const MEMORY_SPAN: u32 = 0x32000;
    const VALUE: u64 = 0x1122_3344_5566_7788;

    let address = STORE_ADDR.to_le_bytes();
    let store = [62, 2, address[0], address[1], address[2]];
    let (code, bitmask) = asm(&[&[1], &store, &[0]]);
    let mut registers = [0; 13];
    registers[2] = VALUE;
    let old = [0x55; 8];
    let new = VALUE.to_le_bytes();
    let mut memory = vec![0; MEMORY_SPAN as usize];
    memory[STORE_ADDR as usize..STORE_ADDR as usize + old.len()].copy_from_slice(&old);
    let mut fault_perms = vec![PERM_NONE; (MEMORY_SPAN / PAGE) as usize];
    fault_perms[(STORE_ADDR / PAGE) as usize] = PERM_RW;
    let mut repaired_perms = fault_perms.clone();
    repaired_perms[(STORE_ADDR / PAGE + 1) as usize] = PERM_RW;

    let mut interpreter = exact_state_interpreter(
        &code,
        &bitmask,
        registers,
        memory,
        100,
        IsaMode::Conformance,
    );
    interpreter.set_page_perms(fault_perms.clone());
    assert_eq!(interpreter.run().0, ExitReason::PageFault(0x31000));
    assert_eq!(interpreter.pc, 1);
    assert_eq!(interpreter.gas, 73);
    assert_eq!(interpreter.registers, registers);
    interpreter.set_page_perms(repaired_perms.clone());
    let mut bytes = [0; 8];
    interpreter.memory().read_bytes(STORE_ADDR, &mut bytes);
    assert_eq!(bytes, old, "faulting store has no partial effect");
    assert_eq!(interpreter.run().0, ExitReason::Panic);
    assert_eq!(interpreter.pc, 0);
    assert_eq!(interpreter.gas, 73, "retry does not recharge the block");
    interpreter.memory().read_bytes(STORE_ADDR, &mut bytes);
    assert_eq!(bytes, new);

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let mut jit = exact_state_recompiler(
            &code,
            &bitmask,
            registers,
            MEMORY_SPAN,
            100,
            IsaMode::Conformance,
        );
        assert!(jit.write_bytes(STORE_ADDR, &old));
        jit.set_page_perms(&fault_perms);
        assert_eq!(jit.run(), ExitReason::PageFault(0x31000));
        assert_eq!(jit.pc(), 1);
        assert_eq!(jit.gas(), 73);
        assert_eq!(*jit.registers(), registers);

        jit.set_page_perms(&repaired_perms);
        assert_eq!(jit.read_bytes(STORE_ADDR, 8).as_deref(), Some(&old[..]));
        assert_eq!(jit.run(), ExitReason::Panic);
        assert_eq!(jit.pc(), 0);
        assert_eq!(jit.gas(), 73, "JIT retry does not recharge the block");
        assert_eq!(jit.read_bytes(STORE_ADDR, 8).as_deref(), Some(&new[..]));
    }
}

/// Every recompiler-applicable vector holds on the JIT, and its block-gas
/// consumption matches the interpreter's exactly.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn recompiler_satisfies_every_vector() {
    let mut ran = 0;
    for (file, v) in discover() {
        if v.recompiler {
            check_recompiler(&file, &v, isa_mode_for_vector(&v));
            ran += 1;
        }
    }
    assert!(ran >= 100, "recompiler corpus shrank: {ran}");
}

/// Every recompiler-applicable v0.8.0 vector agrees with the interpreter,
/// including block-gas classification and consumption.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn graypaper_v080_recompiler_satisfies_every_vector() {
    let mut ran = 0;
    for (file, vector) in discover_v080() {
        if vector.recompiler {
            check_recompiler(&file, &vector, IsaMode::Conformance);
            ran += 1;
        }
    }
    assert_eq!(
        ran, V080_RECOMPILER_CASE_COUNT,
        "complete v0.8 recompiler corpus cardinality",
    );
}
