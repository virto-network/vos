//! PVM instruction-level conformance vectors (JAM-alignment Phase 3).
//!
//! The corpus lives in `spec/tests/vectors/pvm/*.gp072.json` and pins
//! GP 0.7.2 instruction semantics case-by-case: pre/post register file,
//! memory effects, page-fault classification (page-base addresses), the
//! basic-block strictness of branches/djumps, and gas under the
//! per-instruction model (`GasModel::PerInstruction` — a flat 1 gas per
//! instruction, the model the gp072 Lean variants pin).
//!
//! Provenance: every case is synthesized by the hand-written table in this
//! file — code bytes, bitmask, and *expected outcomes* are all hand-derived
//! from the graypaper / the Lean oracle (`spec/Jar/JAVM/`), never recorded
//! from an implementation run. No third-party vector data is copied (the
//! canonical `w3f/jamtestvectors` has no pvm/ directory; the community
//! mirror is unlicensed). The cross-check is differential: every vector
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
//!   `trap` is jar's deliberate-opcode-0 exit; GP folds it into panic ☇,
//!   which is also what the recompiler reports — the recompiler leg
//!   therefore folds trap→panic. Vectors whose outcome depends on the gas
//!   model (out-of-gas cases) list only the interpreter backend.
//! - `expected.gas` is the REMAINING gas under the per-instruction model.
//! - `expected.pc` is checked on the interpreter only (the recompiler does
//!   not define pc equivalence on every exit; the fuzz harness does not
//!   compare it either). Registers are compared on the recompiler at
//!   halt/host-call exits, matching the fuzz harness's contract (the JIT
//!   keeps registers in host registers mid-block, so fault exits do not
//!   guarantee a synced file).
//!
//! Re-bless (regenerates the corpus from the table below):
//! ```bash
//! JAVM_BLESS_PVM_VECTORS=1 cargo test -p vos_pvm --test pvm_vectors
//! ```

use serde_json::{Value, json};
use std::path::PathBuf;
use vos_pvm::gas_cost::DEFAULT_MEM_CYCLES;
use vos_pvm::interpreter::{Interpreter, PERM_NONE, PERM_RO, PERM_RW};
use vos_pvm::{ExitReason, GasModel, IsaMode, PVM_HALT_ADDR};

/// Base of the read-only page every memory case maps.
const RO_BASE: u32 = 0x10000;
/// Base of the read-write page every memory case maps.
const RW_BASE: u32 = 0x20000;
/// One 4 KiB page.
const PAGE: u32 = 4096;
/// Default gas budget for funded cases.
const GAS: u64 = 100;

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

        // ecalli exits HostCall(imm) with pc already advanced; the exiting
        // instruction is charged.
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
        "host_call" => ExitReason::HostCall(exp["host_call"].as_u64().expect("host id") as u32),
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

// --- corpus location + discovery ---

fn vectors_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors"))
}

fn discover() -> Vec<(String, Vector)> {
    let dir = vectors_dir();
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
            let vector = from_json(&value);
            assert_eq!(
                file,
                format!("{}.gp072.json", vector.name),
                "file name matches the vector's name field"
            );
            (file, vector)
        })
        .collect()
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

/// Run `v` on the interpreter under the given gas model. Returns the exit
/// and the machine for post-state inspection.
fn run_interpreter(v: &Vector, model: GasModel) -> (ExitReason, Interpreter) {
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
    vm.isa_mode = IsaMode::Conformance;
    vm.set_gas_model(model);
    vm.set_page_perms(perms_of(v));
    vm.set_pc(v.initial_pc);
    let (exit, _gas_used) = vm.run();
    (exit, vm)
}

fn check_interpreter(name: &str, v: &Vector) {
    let (exit, vm) = run_interpreter(v, GasModel::PerInstruction);
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

/// GP folds jar's deliberate trap (opcode 0) into the panic exit ☇, and
/// that is what the recompiler reports; fold for cross-backend checks.
fn fold_trap(exit: &ExitReason) -> ExitReason {
    match exit {
        ExitReason::Trap => ExitReason::Panic,
        other => other.clone(),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn check_recompiler(name: &str, v: &Vector) {
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
        IsaMode::Conformance,
    )
    .unwrap_or_else(|e| panic!("{name}: recompile failed: {e}"));
    for (addr, bytes) in &v.memory {
        assert!(jit.write_bytes(*addr, bytes), "{name}: seed memory");
    }
    jit.set_page_perms(&perms_of(v));
    jit.set_pc(v.initial_pc);
    let exit = jit.run();

    assert_eq!(
        fold_trap(&exit),
        fold_trap(&v.exp_status),
        "{name}: recompiler exit (trap folds to GP panic)"
    );
    // Registers are only guaranteed synced at resumable/graceful exits
    // (halt, host call) — the fuzz harness's contract.
    if matches!(v.exp_status, ExitReason::Halt | ExitReason::HostCall(_)) {
        assert_eq!(*jit.registers(), v.exp_regs, "{name}: recompiler registers");
    }
    for (addr, want) in &v.exp_memory {
        let got = jit
            .read_bytes(*addr, want.len() as u32)
            .unwrap_or_else(|| panic!("{name}: expected memory at {addr:#x} unreadable"));
        assert_eq!(&got, want, "{name}: recompiler memory at {addr:#x}");
    }

    // Differential gas anchor: under the block model the interpreter and
    // the recompiler must charge identically (the deterministic slice of
    // the fuzz harness's parity contract). Gas is compared at graceful
    // exits; classification must agree everywhere.
    let (block_exit, block_vm) = run_interpreter(v, GasModel::BlockSinglePass);
    assert_eq!(
        fold_trap(&block_exit),
        fold_trap(&exit),
        "{name}: block-gas interpreter and recompiler classify identically"
    );
    if matches!(
        block_exit,
        ExitReason::Halt | ExitReason::Trap | ExitReason::HostCall(_)
    ) {
        assert_eq!(
            jit.gas(),
            block_vm.gas,
            "{name}: block-gas consumption (interpreter vs recompiler)"
        );
    }
}

// --- tests ---

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

/// Every checked-in vector holds on the interpreter under the GP 0.7.2
/// per-instruction gas model.
#[test]
fn interpreter_satisfies_every_vector() {
    let vectors = discover();
    for (file, v) in &vectors {
        check_interpreter(file, v);
    }
    // Guard against silently running an emptied corpus.
    assert!(vectors.len() >= 100, "corpus shrank: {}", vectors.len());
}

/// Every recompiler-applicable vector holds on the JIT, and its block-gas
/// consumption matches the interpreter's exactly.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn recompiler_satisfies_every_vector() {
    let mut ran = 0;
    for (file, v) in discover() {
        if v.recompiler {
            check_recompiler(&file, &v);
            ran += 1;
        }
    }
    assert!(ran >= 100, "recompiler corpus shrank: {ran}");
}
