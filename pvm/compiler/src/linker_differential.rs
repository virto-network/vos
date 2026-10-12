//! Differential tests of the RISC-V translation: random RV64EM programs run
//! on a reference interpreter and, linked by the production path, on the PVM
//! interpreter. The registers and a scratch memory region must agree.
//!
//! Programs use x0 often, as a source and as a destination, branch forward
//! over the generated instructions and run bounded loops, so fusion state
//! meets forward and backward branch targets the way compiled code arranges
//! them.

use std::collections::{HashMap, HashSet};

use proptest::prelude::*;
use vos_pvm::{ExitReason, refine};

use super::{LinkedElf, spi_blob, transpile_linked};

const TEXT: u64 = 0x40_0000;
/// The registers a program may read and write besides x0: t0..a5. ra holds
/// the halt address and sp the stack; gp and tp have no PVM register.
const REGS: [u8; 11] = [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const SP: u32 = 2;
const RA: u32 = 1;
const A0: u32 = 10;
const A1: u32 = 11;
/// Scratch memory for loads and stores, at sp - 512 .. sp - 256.
const SCRATCH: i32 = -512;
const SCRATCH_LEN: usize = 256;
/// The program's output: sp - 512 .. sp, which holds the scratch region and,
/// at sp - 96 .. sp - 8, the final registers.
const OUT: i32 = -512;
const OUT_LEN: usize = 512;
const REGS_AT: i32 = -96;

#[derive(Clone, Debug)]
enum Inst {
    Op {
        f3: u32,
        f7: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Op32 {
        f3: u32,
        f7: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    OpImm {
        f3: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    OpImm32 {
        f3: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Lui {
        rd: u8,
        imm: i32,
    },
    Load {
        f3: u32,
        rd: u8,
        offset: i32,
    },
    Store {
        f3: u32,
        rs2: u8,
        offset: i32,
    },
    /// `to` is the number of instructions skipped, as generated, and the
    /// target's index once [`flatten`]ed.
    Branch {
        f3: u32,
        rs1: u8,
        rs2: u8,
        to: usize,
    },
    Jump {
        to: usize,
    },
}

/// A generated item: an instruction; a constant loaded by `lui` and `addi`
/// and an instruction right after that reads it, as the translation fuses
/// them; or a loop that runs its body `count` times with x15 as the
/// counter, which the body never writes.
#[derive(Clone, Debug)]
enum Item {
    Plain(Inst),
    Constant { rd: u8, value: i32, reader: Inst },
    Loop { count: i32, body: Vec<Inst> },
}

/// `lui` and `addi` loading `value` into `rd`.
fn constant(rd: u8, value: i32) -> [Inst; 2] {
    let low = (value << 20) >> 20;
    [
        Inst::Lui {
            rd,
            imm: value.wrapping_sub(low),
        },
        Inst::OpImm {
            f3: 0,
            rd,
            rs1: rd,
            imm: low,
        },
    ]
}

const COUNTER: u8 = 15;

/// Lay items out as instructions with absolute branch targets. A branch at
/// the top level lands on the start of a later item or the epilogue, never
/// inside a loop; a branch in a loop body stays inside the body.
fn flatten(items: &[Item]) -> Vec<Inst> {
    let mut starts = Vec::new();
    let mut end = 0;
    for item in items {
        starts.push(end);
        end += match item {
            Item::Plain(_) => 1,
            Item::Constant { .. } => 3,
            Item::Loop { body, .. } => body.len() + 3,
        };
    }
    let resolve = |inst: &Inst, target: &dyn Fn(usize) -> usize| match *inst {
        Inst::Branch { f3, rs1, rs2, to } => Inst::Branch {
            f3,
            rs1,
            rs2,
            to: target(to),
        },
        Inst::Jump { to } => Inst::Jump { to: target(to) },
        ref other => other.clone(),
    };
    let mut flat = Vec::with_capacity(end);
    for (index, item) in items.iter().enumerate() {
        match item {
            Item::Plain(inst) => {
                flat.push(resolve(inst, &|skip| {
                    starts.get(index + 1 + skip).copied().unwrap_or(end)
                }));
            }
            Item::Constant { rd, value, reader } => {
                flat.extend(constant(*rd, *value));
                flat.push(resolve(reader, &|skip| {
                    starts.get(index + 1 + skip).copied().unwrap_or(end)
                }));
            }
            Item::Loop { count, body } => {
                flat.push(Inst::OpImm {
                    f3: 0,
                    rd: COUNTER,
                    rs1: 0,
                    imm: *count,
                });
                let first = flat.len();
                let last = first + body.len();
                for (j, inst) in body.iter().enumerate() {
                    flat.push(resolve(inst, &|skip| (first + j + 1 + skip).min(last)));
                }
                flat.push(Inst::OpImm {
                    f3: 0,
                    rd: COUNTER,
                    rs1: COUNTER,
                    imm: -1,
                });
                flat.push(Inst::Branch {
                    f3: 1,
                    rs1: COUNTER,
                    rs2: 0,
                    to: first,
                });
            }
        }
    }
    flat
}

fn r_type(opcode: u32, f3: u32, f7: u32, rd: u32, rs1: u32, rs2: u32) -> u32 {
    (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | opcode
}

fn i_type(opcode: u32, f3: u32, rd: u32, rs1: u32, imm: i32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | opcode
}

fn s_type(f3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let imm = imm as u32;
    (((imm >> 5) & 0x7f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (f3 << 12)
        | ((imm & 0x1f) << 7)
        | 0x23
}

fn b_type(f3: u32, rs1: u32, rs2: u32, offset: i32) -> u32 {
    let o = offset as u32;
    (((o >> 12) & 1) << 31)
        | (((o >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (f3 << 12)
        | (((o >> 1) & 0xf) << 8)
        | (((o >> 11) & 1) << 7)
        | 0x63
}

fn j_type(rd: u32, offset: i32) -> u32 {
    let o = offset as u32;
    (((o >> 20) & 1) << 31)
        | (((o >> 1) & 0x3ff) << 21)
        | (((o >> 11) & 1) << 20)
        | (((o >> 12) & 0xff) << 12)
        | (rd << 7)
        | 0x6f
}

fn encode(index: usize, inst: &Inst) -> u32 {
    let reg = u32::from;
    match *inst {
        Inst::Op {
            f3,
            f7,
            rd,
            rs1,
            rs2,
        } => r_type(0x33, f3, f7, reg(rd), reg(rs1), reg(rs2)),
        Inst::Op32 {
            f3,
            f7,
            rd,
            rs1,
            rs2,
        } => r_type(0x3b, f3, f7, reg(rd), reg(rs1), reg(rs2)),
        Inst::OpImm { f3, rd, rs1, imm } => i_type(0x13, f3, reg(rd), reg(rs1), imm),
        Inst::OpImm32 { f3, rd, rs1, imm } => i_type(0x1b, f3, reg(rd), reg(rs1), imm),
        Inst::Lui { rd, imm } => ((imm as u32) & 0xffff_f000) | (reg(rd) << 7) | 0x37,
        Inst::Load { f3, rd, offset } => i_type(0x03, f3, reg(rd), SP, offset),
        Inst::Store { f3, rs2, offset } => s_type(f3, SP, reg(rs2), offset),
        Inst::Branch { f3, rs1, rs2, to } => {
            b_type(f3, reg(rs1), reg(rs2), (to as i32 - index as i32) * 4)
        }
        Inst::Jump { to } => j_type(0, (to as i32 - index as i32) * 4),
    }
}

/// The whole program: load the registers from the arguments, run the body,
/// store the registers below sp and return sp - 512 .. sp as the output.
fn assemble(body: &[Inst]) -> Vec<u8> {
    let mut words = Vec::new();
    for (k, &r) in REGS.iter().enumerate() {
        if u32::from(r) != A0 {
            words.push(i_type(0x03, 3, u32::from(r), A0, 8 * k as i32));
        }
    }
    let a0_at = REGS.iter().position(|&r| u32::from(r) == A0).unwrap();
    words.push(i_type(0x03, 3, A0, A0, 8 * a0_at as i32));
    for (index, inst) in body.iter().enumerate() {
        words.push(encode(index, inst));
    }
    for (k, &r) in REGS.iter().enumerate() {
        words.push(s_type(3, SP, u32::from(r), REGS_AT + 8 * k as i32));
    }
    words.push(i_type(0x13, 0, A0, SP, OUT));
    words.push(i_type(0x13, 0, A1, 0, OUT_LEN as i32));
    words.push(i_type(0x67, 0, 0, RA, 0));
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn link(text: &[u8]) -> Vec<u8> {
    let elf = LinkedElf {
        is_64bit: true,
        code_sections: vec![(0, TEXT, text.to_vec())],
        ro_data: Vec::new(),
        ro_base: 0x1_0000,
        rw_data: Vec::new(),
        rw_base: 0x2_0000,
        rw_min: 0x2_0000,
        stack_size: 0x1_0000,
        heap_pages: 0,
        functions: Vec::new(),
        hi20_targets: HashMap::new(),
        lo12_targets: HashMap::new(),
        call_targets: HashMap::new(),
        abs_code_ptrs: Vec::new(),
        sub32_relocs: Vec::new(),
        data_relocation_ranges: Vec::new(),
        code_ranges: vec![(TEXT, TEXT + text.len() as u64)],
        // As the production linker sees a compiled function: its entry is a
        // symbol; branch targets inside it are not.
        control_flow_targets: HashSet::from([TEXT]),
        entry_vaddr: TEXT,
        accumulate_vaddr: None,
    };
    spi_blob(transpile_linked(&elf).expect("translates")).expect("links")
}

/// RV64IM semantics for the generated subset.
struct Reference {
    x: [u64; 16],
    scratch: [u8; SCRATCH_LEN],
}

impl Reference {
    fn get(&self, r: u8) -> u64 {
        if r == 0 { 0 } else { self.x[usize::from(r)] }
    }

    fn set(&mut self, r: u8, value: u64) {
        if r != 0 {
            self.x[usize::from(r)] = value;
        }
    }

    fn load(&self, offset: i32, width: usize) -> u64 {
        let at = (offset - SCRATCH) as usize;
        let mut bytes = [0u8; 8];
        bytes[..width].copy_from_slice(&self.scratch[at..at + width]);
        u64::from_le_bytes(bytes)
    }

    fn store(&mut self, offset: i32, width: usize, value: u64) {
        let at = (offset - SCRATCH) as usize;
        self.scratch[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }

    fn run(&mut self, body: &[Inst]) {
        let sext32 = |v: u32| v as i32 as i64 as u64;
        let mut pc = 0;
        while pc < body.len() {
            let mut next = pc + 1;
            match body[pc] {
                Inst::Op {
                    f3,
                    f7,
                    rd,
                    rs1,
                    rs2,
                } => {
                    let (a, b) = (self.get(rs1), self.get(rs2));
                    let (sa, sb) = (a as i64, b as i64);
                    let value = match (f7, f3) {
                        (0, 0) => a.wrapping_add(b),
                        (0x20, 0) => a.wrapping_sub(b),
                        (0, 1) => a << (b & 63),
                        (0, 2) => u64::from(sa < sb),
                        (0, 3) => u64::from(a < b),
                        (0, 4) => a ^ b,
                        (0, 5) => a >> (b & 63),
                        (0x20, 5) => (sa >> (b & 63)) as u64,
                        (0, 6) => a | b,
                        (0, 7) => a & b,
                        (1, 0) => a.wrapping_mul(b),
                        (1, 1) => ((i128::from(sa) * i128::from(sb)) >> 64) as u64,
                        (1, 2) => ((i128::from(sa) * i128::from(b)) >> 64) as u64,
                        (1, 3) => ((u128::from(a) * u128::from(b)) >> 64) as u64,
                        (1, 4) => match (sa, sb) {
                            (_, 0) => u64::MAX,
                            (i64::MIN, -1) => a,
                            _ => (sa / sb) as u64,
                        },
                        (1, 5) => a.checked_div(b).unwrap_or(u64::MAX),
                        (1, 6) => match (sa, sb) {
                            (_, 0) => a,
                            (i64::MIN, -1) => 0,
                            _ => (sa % sb) as u64,
                        },
                        (1, 7) => a.checked_rem(b).unwrap_or(a),
                        _ => unreachable!(),
                    };
                    self.set(rd, value);
                }
                Inst::Op32 {
                    f3,
                    f7,
                    rd,
                    rs1,
                    rs2,
                } => {
                    let (a, b) = (self.get(rs1) as u32, self.get(rs2) as u32);
                    let (sa, sb) = (a as i32, b as i32);
                    let value = match (f7, f3) {
                        (0, 0) => sext32(a.wrapping_add(b)),
                        (0x20, 0) => sext32(a.wrapping_sub(b)),
                        (0, 1) => sext32(a << (b & 31)),
                        (0, 5) => sext32(a >> (b & 31)),
                        (0x20, 5) => sext32((sa >> (b & 31)) as u32),
                        (1, 0) => sext32(a.wrapping_mul(b)),
                        (1, 4) => match (sa, sb) {
                            (_, 0) => u64::MAX,
                            (i32::MIN, -1) => sext32(a),
                            _ => sext32((sa / sb) as u32),
                        },
                        (1, 5) => sext32(a.checked_div(b).unwrap_or(u32::MAX)),
                        (1, 6) => match (sa, sb) {
                            (_, 0) => sext32(a),
                            (i32::MIN, -1) => 0,
                            _ => sext32((sa % sb) as u32),
                        },
                        (1, 7) => sext32(a.checked_rem(b).unwrap_or(a)),
                        _ => unreachable!(),
                    };
                    self.set(rd, value);
                }
                Inst::OpImm { f3, rd, rs1, imm } => {
                    let a = self.get(rs1);
                    let i = i64::from(imm) as u64;
                    let shamt = (imm & 63) as u32;
                    let value = match f3 {
                        0 => a.wrapping_add(i),
                        1 => a << shamt,
                        2 => u64::from((a as i64) < i64::from(imm)),
                        3 => u64::from(a < i),
                        4 => a ^ i,
                        5 if imm & 0x400 != 0 => ((a as i64) >> shamt) as u64,
                        5 => a >> shamt,
                        6 => a | i,
                        7 => a & i,
                        _ => unreachable!(),
                    };
                    self.set(rd, value);
                }
                Inst::OpImm32 { f3, rd, rs1, imm } => {
                    let a = self.get(rs1) as u32;
                    let shamt = (imm & 31) as u32;
                    let value = match f3 {
                        0 => sext32(a.wrapping_add(imm as u32)),
                        1 => sext32(a << shamt),
                        5 if imm & 0x400 != 0 => sext32(((a as i32) >> shamt) as u32),
                        5 => sext32(a >> shamt),
                        _ => unreachable!(),
                    };
                    self.set(rd, value);
                }
                Inst::Lui { rd, imm } => self.set(rd, i64::from(imm & !0xfff) as u64),
                Inst::Load { f3, rd, offset } => {
                    let value = match f3 {
                        0 => self.load(offset, 1) as u8 as i8 as i64 as u64,
                        1 => self.load(offset, 2) as u16 as i16 as i64 as u64,
                        2 => self.load(offset, 4) as u32 as i32 as i64 as u64,
                        3 => self.load(offset, 8),
                        4 => self.load(offset, 1),
                        5 => self.load(offset, 2),
                        6 => self.load(offset, 4),
                        _ => unreachable!(),
                    };
                    self.set(rd, value);
                }
                Inst::Store { f3, rs2, offset } => {
                    self.store(offset, 1 << f3, self.get(rs2));
                }
                Inst::Branch { f3, rs1, rs2, to } => {
                    let (a, b) = (self.get(rs1), self.get(rs2));
                    let taken = match f3 {
                        0 => a == b,
                        1 => a != b,
                        4 => (a as i64) < (b as i64),
                        5 => (a as i64) >= (b as i64),
                        6 => a < b,
                        7 => a >= b,
                        _ => unreachable!(),
                    };
                    if taken {
                        next = to;
                    }
                }
                Inst::Jump { to } => next = to,
            }
            pc = next;
        }
    }
}

fn register() -> impl Strategy<Value = u8> {
    prop_oneof![1 => Just(0u8), 3 => prop::sample::select(&REGS[..])]
}

fn instruction() -> impl Strategy<Value = Inst> {
    const OP: [(u32, u32); 18] = [
        (0, 0),
        (0x20, 0),
        (0, 1),
        (0, 2),
        (0, 3),
        (0, 4),
        (0, 5),
        (0x20, 5),
        (0, 6),
        (0, 7),
        (1, 0),
        (1, 1),
        (1, 2),
        (1, 3),
        (1, 4),
        (1, 5),
        (1, 6),
        (1, 7),
    ];
    const OP32: [(u32, u32); 10] = [
        (0, 0),
        (0x20, 0),
        (0, 1),
        (0, 5),
        (0x20, 5),
        (1, 0),
        (1, 4),
        (1, 5),
        (1, 6),
        (1, 7),
    ];
    let imm = prop_oneof![
        -2048i32..2048,
        prop::sample::select(vec![0, 1, -1, 2047, -2048])
    ];
    let op = (
        prop::sample::select(&OP[..]),
        register(),
        register(),
        register(),
    )
        .prop_map(|((f7, f3), rd, rs1, rs2)| Inst::Op {
            f3,
            f7,
            rd,
            rs1,
            rs2,
        });
    let op32 = (
        prop::sample::select(&OP32[..]),
        register(),
        register(),
        register(),
    )
        .prop_map(|((f7, f3), rd, rs1, rs2)| Inst::Op32 {
            f3,
            f7,
            rd,
            rs1,
            rs2,
        });
    let op_imm = (
        prop::sample::select(&[0u32, 2, 3, 4, 6, 7][..]),
        register(),
        register(),
        imm.clone(),
    )
        .prop_map(|(f3, rd, rs1, imm)| Inst::OpImm { f3, rd, rs1, imm });
    let shift = (
        prop::sample::select(&[(1u32, 0i32), (5, 0), (5, 0x400)][..]),
        register(),
        register(),
        0i32..64,
    )
        .prop_map(|((f3, high), rd, rs1, shamt)| Inst::OpImm {
            f3,
            rd,
            rs1,
            imm: high | shamt,
        });
    let addiw = (register(), register(), imm.clone()).prop_map(|(rd, rs1, imm)| Inst::OpImm32 {
        f3: 0,
        rd,
        rs1,
        imm,
    });
    let shift32 = (
        prop::sample::select(&[(1u32, 0i32), (5, 0), (5, 0x400)][..]),
        register(),
        register(),
        0i32..32,
    )
        .prop_map(|((f3, high), rd, rs1, shamt)| Inst::OpImm32 {
            f3,
            rd,
            rs1,
            imm: high | shamt,
        });
    let lui = (register(), any::<i32>()).prop_map(|(rd, imm)| Inst::Lui { rd, imm });
    let width = |f3: u32| match f3 & 3 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let load = (
        prop::sample::select(&[0u32, 1, 2, 3, 4, 5, 6][..]),
        register(),
        0i32..32,
    )
        .prop_map(move |(f3, rd, slot)| {
            let w = width(f3);
            Inst::Load {
                f3,
                rd,
                offset: SCRATCH + (slot * 8 / w) * w,
            }
        });
    let store = (
        prop::sample::select(&[0u32, 1, 2, 3][..]),
        register(),
        0i32..32,
    )
        .prop_map(move |(f3, rs2, slot)| {
            let w = width(f3);
            Inst::Store {
                f3,
                rs2,
                offset: SCRATCH + (slot * 8 / w) * w,
            }
        });
    let branch = (
        prop::sample::select(&[0u32, 1, 4, 5, 6, 7][..]),
        register(),
        register(),
        0usize..4,
    )
        .prop_map(|(f3, rs1, rs2, to)| Inst::Branch { f3, rs1, rs2, to });
    let jump = (0usize..4).prop_map(|to| Inst::Jump { to });
    prop_oneof![
        4 => op,
        2 => op32,
        3 => op_imm,
        2 => shift,
        1 => addiw,
        1 => shift32,
        2 => lui,
        2 => load,
        2 => store,
        3 => branch,
        1 => jump,
    ]
}

/// The same instruction, writing anything but the loop counter.
fn spare_counter(inst: Inst) -> Inst {
    let spare = |rd: u8| if rd == COUNTER { COUNTER - 1 } else { rd };
    match inst {
        Inst::Op {
            f3,
            f7,
            rd,
            rs1,
            rs2,
        } => Inst::Op {
            f3,
            f7,
            rd: spare(rd),
            rs1,
            rs2,
        },
        Inst::Op32 {
            f3,
            f7,
            rd,
            rs1,
            rs2,
        } => Inst::Op32 {
            f3,
            f7,
            rd: spare(rd),
            rs1,
            rs2,
        },
        Inst::OpImm { f3, rd, rs1, imm } => Inst::OpImm {
            f3,
            rd: spare(rd),
            rs1,
            imm,
        },
        Inst::OpImm32 { f3, rd, rs1, imm } => Inst::OpImm32 {
            f3,
            rd: spare(rd),
            rs1,
            imm,
        },
        Inst::Lui { rd, imm } => Inst::Lui { rd: spare(rd), imm },
        Inst::Load { f3, rd, offset } => Inst::Load {
            f3,
            rd: spare(rd),
            offset,
        },
        other => other,
    }
}

/// A constant and an instruction that reads it as either operand: a branch,
/// or a 64- or 32-bit operation writing any register.
fn constant_item() -> impl Strategy<Value = Item> {
    let rd = prop::sample::select(&REGS[..]);
    let value = prop_oneof![any::<i32>(), Just(100_000_000), -4096i32..4096];
    let reader = (instruction(), any::<bool>(), register());
    (rd, value, reader).prop_map(|(rd, value, (inst, left, other))| {
        let (rs1, rs2) = if left { (rd, other) } else { (other, rd) };
        let reader = match inst {
            Inst::Op { f3, f7, rd, .. } => Inst::Op {
                f3,
                f7,
                rd,
                rs1,
                rs2,
            },
            Inst::Op32 { f3, f7, rd, .. } => Inst::Op32 {
                f3,
                f7,
                rd,
                rs1,
                rs2,
            },
            Inst::Branch { f3, to, .. } => Inst::Branch { f3, rs1, rs2, to },
            _ => Inst::Branch {
                f3: 6,
                rs1,
                rs2,
                to: 0,
            },
        };
        Item::Constant { rd, value, reader }
    })
}

fn item() -> impl Strategy<Value = Item> {
    prop_oneof![
        8 => instruction().prop_map(Item::Plain),
        2 => constant_item(),
        1 => (1i32..4, prop::collection::vec(instruction().prop_map(spare_counter), 1..6))
            .prop_map(|(count, body)| Item::Loop { count, body }),
    ]
}

fn check(items: &[Item], registers: &[u64; 11]) -> Result<(), TestCaseError> {
    let body = &flatten(items)[..];
    let args: Vec<u8> = registers.iter().flat_map(|r| r.to_le_bytes()).collect();
    let mut reference = Reference {
        x: [0; 16],
        scratch: [0; SCRATCH_LEN],
    };
    for (k, &r) in REGS.iter().enumerate() {
        reference.x[usize::from(r)] = registers[k];
    }
    reference.run(body);
    let mut expected = vec![0u8; OUT_LEN];
    expected[..SCRATCH_LEN].copy_from_slice(&reference.scratch);
    for (k, &r) in REGS.iter().enumerate() {
        let at = (REGS_AT - OUT) as usize + 8 * k;
        expected[at..at + 8].copy_from_slice(&reference.x[usize::from(r)].to_le_bytes());
    }

    let program = link(&assemble(body));
    let invocation = refine::execute(&program, &args, 10_000_000).expect("executes");
    prop_assert_eq!(&invocation.exit, &ExitReason::Halt);
    let output = invocation.output_bounded(OUT_LEN).expect("output");
    for (k, &r) in REGS.iter().enumerate() {
        let at = (REGS_AT - OUT) as usize + 8 * k;
        prop_assert_eq!(
            &output[at..at + 8],
            &expected[at..at + 8],
            "x{} differs: pvm {:#x}, reference {:#x}",
            r,
            u64::from_le_bytes(output[at..at + 8].try_into().unwrap()),
            reference.x[usize::from(r)]
        );
    }
    prop_assert_eq!(
        &output[..SCRATCH_LEN],
        &expected[..SCRATCH_LEN],
        "scratch differs"
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn translation_matches_the_reference(
        items in prop::collection::vec(item(), 1..20),
        registers in prop::array::uniform11(prop_oneof![
            any::<u64>(),
            prop::sample::select(vec![0, 1, u64::MAX, i64::MIN as u64, i64::MAX as u64, 0x8000_0000, 0xffff_ffff]),
        ]),
    ) {
        check(&items, &registers)?;
    }
}

/// A constant loaded for one instruction stays in its register: lowering the
/// instruction to an immediate form may drop the load only when the
/// instruction overwrites the register. Code that compares a value with a
/// cap and then takes the cap (`x.min(cap)`) reads it again.
#[test]
fn a_fused_constant_stays_in_its_register() {
    let op = |f7, f3| Inst::Op {
        f3,
        f7,
        rd: 11,
        rs1: 12,
        rs2: 10,
    };
    let op32 = |f7, f3| Inst::Op32 {
        f3,
        f7,
        rd: 11,
        rs1: 12,
        rs2: 10,
    };
    let branch = |f3| Inst::Branch {
        f3,
        rs1: 6,
        rs2: 10,
        to: 0,
    };
    let readers = [
        branch(0),
        branch(1),
        branch(4),
        branch(5),
        branch(6),
        branch(7),
        op(0, 0),
        op(0x20, 0),
        op(0, 1),
        op(0, 5),
        op(0x20, 5),
        op(1, 0),
        op32(0, 0),
        op32(0x20, 0),
        op32(0, 1),
        op32(0, 5),
        op32(0x20, 5),
        op32(1, 0),
    ];
    // The same readers with the constant as both operands and destination.
    let both = readers.clone().map(|reader| match reader {
        Inst::Op { f3, f7, .. } => Inst::Op {
            f3,
            f7,
            rd: 10,
            rs1: 10,
            rs2: 10,
        },
        Inst::Op32 { f3, f7, .. } => Inst::Op32 {
            f3,
            f7,
            rd: 10,
            rs1: 10,
            rs2: 10,
        },
        Inst::Branch { f3, to, .. } => Inst::Branch {
            f3,
            rs1: 10,
            rs2: 10,
            to,
        },
        other => other,
    });
    for reader in readers.into_iter().chain(both) {
        let items = [
            Item::Constant {
                rd: 10,
                value: 100_000_000,
                reader: reader.clone(),
            },
            // mv t1, a0
            Item::Plain(Inst::OpImm {
                f3: 0,
                rd: 6,
                rs1: 10,
                imm: 0,
            }),
        ];
        check(&items, &[0x5555_5555_5555_5555; 11])
            .unwrap_or_else(|error| panic!("{reader:?}: {error}"));
    }
}

/// `beq x0, x0` always branches and `bne x0, x0` never does: register 0 of
/// the PVM holds the return address, not zero.
#[test]
fn branches_between_zero_registers_are_static() {
    let body = [
        Inst::Branch {
            f3: 0,
            rs1: 0,
            rs2: 0,
            to: 1,
        },
        Inst::OpImm {
            f3: 0,
            rd: 5,
            rs1: 0,
            imm: 1,
        },
        Inst::Branch {
            f3: 1,
            rs1: 0,
            rs2: 0,
            to: 1,
        },
        Inst::OpImm {
            f3: 0,
            rd: 6,
            rs1: 0,
            imm: 2,
        },
    ];
    let items: Vec<_> = body.into_iter().map(Item::Plain).collect();
    check(&items, &[0; 11]).unwrap();
}

/// A load, store or jump based on x0 reaches the absolute address in its
/// immediate. Below 64 KiB nothing is mapped, so each stops there, not at
/// an address derived from the return address in PVM register 0.
#[test]
fn zero_based_accesses_are_absolute() {
    const AT: i32 = 0x7f8;
    let cases = [
        ("ld", i_type(0x03, 3, 5, 0, AT)),
        ("lbu", i_type(0x03, 4, 5, 0, AT)),
        ("sd", s_type(3, 0, 5, AT)),
        ("sd x0", s_type(3, 0, 0, AT)),
        ("jalr", i_type(0x67, 0, 0, 0, AT)),
    ];
    for (what, word) in cases {
        let words = [word, i_type(0x67, 0, 0, RA, 0)];
        let text: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let invocation = refine::execute(&link(&text), &[], 1_000_000).expect("executes");
        match invocation.exit {
            ExitReason::Panic => {}
            ExitReason::PageFault(address) => assert!(
                address < 0x1_0000,
                "{what}: faulted at {address:#x}, not at its absolute address"
            ),
            other => panic!("{what}: {other:?}"),
        }
    }
}
