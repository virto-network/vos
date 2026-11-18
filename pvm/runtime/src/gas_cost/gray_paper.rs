//! The Gray Paper v0.8.0 gas cost tables, written out again from the text
//! alone (`pvm.tex`, "Gas Cost Tables", the instruction tables of A.5 for
//! each instruction's source and destination registers, and the
//! termination set), never from the production table above: the literal
//! reference scheduler runs on these costs, so a wrong row of the
//! production table shows as a difference.
//!
//! Two edges the text leaves to a reading, resolved here and in production
//! alike:
//! - A branch target below 0: `ı_target = ı + Z(...)` is an instruction
//!   counter, a register value (`N_R`), so it wraps; the byte there is past
//!   the code, a zero (`ζ = c ⌢ [0, 0, ...]`), the `trap` opcode, and the
//!   branch costs `b = 1`.
//! - A conditional move: its destination's new value is the old one when
//!   the condition fails (`φ'_D = φ_D`), so `ŝ`, the registers the
//!   instruction's equation reads "regardless of whether those registers
//!   would actually have been modified", holds the destination.

use crate::gas_cost::FastCost;

/// A cost column's entry.
#[derive(Clone, Copy)]
enum Cost {
    Fixed(u8),
    /// `P(a, b)`: `a` when a source is also a destination, else `b`.
    Overlap(u8, u8),
    /// `P_S(a, b)`: `a` when `r_A = r_D`, else `b`.
    Shift(u8, u8),
    /// `b`, a branch's: 1 when its fallthrough or target opcode byte is
    /// `trap` or `unlikely`, else 20.
    Branch,
}

/// A row: cycles, decode slots, execution units `(A, L, S, M, D)`.
type Row = (Cost, Cost, [u8; 5]);

const M: Cost = Cost::Fixed(25);
const ALU: [u8; 5] = [1, 0, 0, 0, 0];
const NONE: [u8; 5] = [0; 5];
const LOAD: [u8; 5] = [1, 1, 0, 0, 0];
const STORE: [u8; 5] = [1, 0, 1, 0, 0];
const MUL: [u8; 5] = [1, 0, 0, 1, 0];
const DIV: [u8; 5] = [1, 0, 0, 0, 1];

/// The table's row for `opcode`, `None` for no instruction.
fn row(opcode: u8) -> Option<Row> {
    use Cost::{Fixed as F, Overlap as P, Shift as S};
    let simple_alu = (F(1), P(1, 2), ALU);
    let simple_alu_32 = (F(2), P(2, 3), ALU);
    let one_cycle = (F(1), F(1), ALU);
    let comparison = (F(3), F(3), ALU);
    let min_max = (F(3), P(2, 3), ALU);
    let load = (M, F(1), LOAD);
    let store = (F(25), F(1), STORE);
    let branch = (Cost::Branch, F(1), ALU);
    let div_rem = (F(60), F(4), DIV);
    Some(match opcode {
        100 => (F(0), F(1), NONE),                 // move_reg
        210 | 211 | 212 | 200 | 201 => simple_alu, // and xor or add_64 sub_64
        190 | 191 => simple_alu_32,                // add_32 sub_32
        132 | 133 | 134 | 149 | 152 | 153 | 151 | 158 | 110 => simple_alu, // and_imm .. reverse_bytes
        131 | 139 | 140 | 138 | 160 => simple_alu_32, // add_imm_32 .. rot_r_32_imm
        101..=104 | 107..=109 => one_cycle,           // count, leading zeros, extends
        105 | 106 => (F(2), F(1), [2, 0, 0, 0, 0]),   // trailing_zero_bits
        207 | 208 | 209 | 220 | 222 => (F(1), S(2, 3), ALU), // 64-bit shifts and rotates
        197 | 198 | 199 | 221 | 223 => (F(2), S(3, 4), ALU), // 32-bit shifts and rotates
        155 | 156 | 157 | 159 => (F(1), F(3), ALU),   // *_imm_alt_64
        144 | 145 | 146 | 161 => (F(2), F(4), ALU),   // *_imm_alt_32
        216 | 217 => comparison,                      // set_lt_u set_lt_s
        136 | 137 | 142 | 143 => comparison,          // set_*_imm
        218 | 219 => (F(2), F(2), ALU),               // cmov_iz cmov_nz
        147 | 148 => (F(2), F(3), ALU),               // cmov_*_imm
        227..=230 => min_max,                         // max max_u min min_u
        124..=130 | 52..=58 => load,                  // load_ind_*, load_*
        70..=73 | 120..=123 | 30..=33 | 59..=62 => store, // the stores
        170..=175 | 81..=90 => branch,                // the branches
        193..=196 | 203..=206 => div_rem,             // div, rem
        224 | 225 => (F(2), F(3), ALU),               // and_inv or_inv
        226 => (F(2), P(2, 3), ALU),                  // xnor
        154 => (F(2), F(3), ALU),                     // neg_add_imm_64
        141 => (F(3), F(4), ALU),                     // neg_add_imm_32
        51 => (F(1), F(1), NONE),                     // load_imm
        20 => (F(1), F(2), NONE),                     // load_imm_64
        202 => (F(3), P(1, 2), MUL),                  // mul_64
        192 => (F(4), P(2, 3), MUL),                  // mul_32
        150 => (F(3), P(1, 2), MUL),                  // mul_imm_64
        135 => (F(4), P(2, 3), MUL),                  // mul_imm_32
        213 | 214 => (F(4), F(4), MUL),               // mul_upper_s_s mul_upper_u_u
        215 => (F(6), F(4), MUL),                     // mul_upper_s_u
        0 | 1 => (F(2), F(1), NONE),                  // trap fallthrough
        2 => (F(40), F(1), NONE),                     // unlikely
        40 | 80 => (F(15), F(1), NONE),               // jump load_imm_jump
        50 | 180 => (F(22), F(1), NONE),              // jump_ind load_imm_jump_ind
        10 => (F(100), F(4), ALU),                    // ecalli
        _ => return None,
    })
}

/// The termination set `T` (`pvm.tex`): trap, fallthrough, the jumps, the
/// load-and-jumps and the branches.
fn terminates(opcode: u8) -> bool {
    matches!(opcode, 0 | 1 | 40 | 50 | 80 | 180 | 81..=90 | 170..=175)
}

/// `min(12, x)`.
fn reg(x: u8) -> u8 {
    x.min(12)
}

/// The registers instruction `opcode` at `pc` of `zeta` (the code,
/// zero-extended) reads and writes (`ŝ`, `ř`), from its A.5 equation, and
/// for a branch its target (`None` otherwise).
fn registers(
    opcode: u8,
    zeta: impl Fn(usize) -> u8,
    pc: usize,
    skip: usize,
) -> (Vec<u8>, Vec<u8>, Option<u64>) {
    let low = reg(zeta(pc + 1) % 16);
    let high = reg(zeta(pc + 1) / 16);
    let none = Vec::new;
    // An offset of `len` bytes at `at`, sign-extended, from `pc`, in N_R.
    let target = |at: usize, len: usize| {
        let mut value = 0u64;
        for i in 0..len {
            value |= u64::from(zeta(at + i)) << (8 * i);
        }
        let shift = 64 - 8 * len as u32;
        let signed = if len == 0 {
            0
        } else {
            ((value << shift) as i64) >> shift
        };
        (pc as u64).wrapping_add(signed as u64)
    };
    match opcode {
        0..=2 | 10 | 30..=33 | 40 => (none(), none(), None),
        20 | 51..=58 => (none(), vec![low], None),
        50 | 59..=62 | 70..=73 => (vec![low], none(), None),
        80 => (none(), vec![low], None),
        81..=90 => {
            let lx = (usize::from(zeta(pc + 1) / 16) % 8).min(4);
            let ly = skip.saturating_sub(lx + 1).min(4);
            (vec![low], none(), Some(target(pc + 2 + lx, ly)))
        }
        // Two registers: r_D the low nibble, r_A the high.
        100..=110 => (vec![high], vec![low], None),
        120..=123 => (vec![low, high], none(), None),
        124..=146 | 149..=161 => (vec![high], vec![low], None),
        // φ'_A = ν_X when φ_B = 0 (or ≠ 0), else φ_A.
        147 | 148 => (vec![high, low], vec![low], None),
        170..=175 => {
            let lx = skip.saturating_sub(1).min(4);
            (vec![low, high], none(), Some(target(pc + 2, lx)))
        }
        180 => (vec![high], vec![low], None),
        _ => {
            // Three registers: r_A, r_B the nibbles, r_D the next byte.
            let d = reg(zeta(pc + 2));
            let mut sources = vec![low, high];
            // φ'_D = φ_A when φ_B = 0 (or ≠ 0), else φ_D.
            if matches!(opcode, 218 | 219) {
                sources.push(d);
            }
            (sources, vec![d], None)
        }
    }
}

/// The cost of the instruction at `pc` of `code` under the text's tables,
/// in the simulator's form; `None` for no instruction.
pub(crate) fn cost(code: &[u8], bitmask: &[u8], pc: usize) -> Option<FastCost> {
    let opcode = *code.get(pc)?;
    let (cycles, decode, units) = row(opcode)?;
    let zeta = |i: usize| code.get(i).copied().unwrap_or(0);
    let skip = crate::skip(bitmask, pc);
    let (sources, destinations, target) = registers(opcode, zeta, pc, skip);
    let mask = |registers: &[u8]| registers.iter().fold(0u16, |mask, &r| mask | 1 << r);
    let (src_mask, dst_mask) = (mask(&sources), mask(&destinations));
    let low = reg(zeta(pc + 1) % 16);
    let d = if opcode >= 190 {
        reg(zeta(pc + 2))
    } else {
        low
    };
    let value = |cost: Cost| match cost {
        Cost::Fixed(value) => value,
        Cost::Overlap(a, b) => {
            if src_mask & dst_mask != 0 {
                a
            } else {
                b
            }
        }
        Cost::Shift(a, b) => {
            if low == d {
                a
            } else {
                b
            }
        }
        Cost::Branch => {
            let at = |index: u64| usize::try_from(index).map_or(0, zeta);
            let fallthrough = at((pc + 1 + skip) as u64);
            let target = at(target.expect("a branch's target"));
            if [fallthrough, target]
                .iter()
                .any(|&byte| matches!(byte, 0 | 2))
            {
                1
            } else {
                20
            }
        }
    };
    let exec_unit = match units {
        [0, 0, 0, 0, 0] => 0,
        [1, 0, 0, 0, 0] => 1,
        [1, 1, 0, 0, 0] => 2,
        [1, 0, 1, 0, 0] => 3,
        [1, 0, 0, 1, 0] => 4,
        [1, 0, 0, 0, 1] => 5,
        [2, 0, 0, 0, 0] => 6,
        _ => unreachable!("the table's unit tuples"),
    };
    Some(FastCost {
        cycles: value(cycles),
        decode_slots: value(decode),
        exec_unit,
        src_mask,
        dst_mask,
        is_terminator: terminates(opcode),
        is_move_reg: opcode == 100,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Every valid opcode, at the head of code of random bytes and a random
    /// skip, costs in production what the text's tables give.
    #[test]
    fn the_production_table_is_the_texts_for_every_opcode() {
        let mut seen = 0;
        for opcode in 0..=u8::MAX {
            if crate::instruction::Opcode::from_byte(opcode).is_none() {
                assert!(row(opcode).is_none(), "{opcode}: a row for no instruction");
                continue;
            }
            seen += 1;
            for seed in 0..512u32 {
                let bytes = seed.wrapping_mul(0x9e37_79b9).to_le_bytes();
                let skip = (seed % 13) as usize;
                let mut code = vec![opcode];
                for i in 0..skip + 1 {
                    code.push(bytes[i % 4].rotate_left(i as u32));
                }
                let mut bitmask = vec![0; code.len()];
                bitmask[0] = 1;
                *bitmask.last_mut().unwrap() = 1;
                let expected = cost(&code, &bitmask, 0).expect("a row");
                let production = crate::gas_cost::fast_cost_from_raw(
                    opcode,
                    code[1] & 0x0f,
                    code[1] >> 4,
                    code.get(2).copied().unwrap_or(0),
                    0,
                    &code,
                    &bitmask,
                );
                assert_eq!(production, expected, "opcode {opcode}, code {code:?}");
            }
        }
        assert_eq!(seen, 139, "the valid opcodes");
    }

    proptest! {
        /// Programs of several blocks of valid instructions, each ended by
        /// a terminator, cost block by block in both backends' preparation
        /// (the interpreter's predecode, the recompiler's compile) what the
        /// literal scheduler gives on the text's tables.
        #[test]
        fn both_backends_price_blocks_as_the_texts_table(
            blocks in proptest::collection::vec(
                (proptest::collection::vec((any::<u8>(), any::<[u8; 3]>()), 0..30), any::<u8>()),
                1..6,
            ),
        ) {
            let body: alloc::vec::Vec<u8> = (0..=u8::MAX)
                .filter(|&op| crate::instruction::Opcode::from_byte(op).is_some() && !terminates(op))
                .collect();
            let ends: alloc::vec::Vec<u8> = (0..=u8::MAX).filter(|&op| terminates(op)).collect();
            let mut code = alloc::vec::Vec::new();
            let mut starts = alloc::vec::Vec::new();
            let mut block_starts = alloc::vec::Vec::new();
            for (instructions, end) in &blocks {
                block_starts.push(code.len());
                for (pick, operands) in instructions {
                    starts.push(code.len());
                    code.push(body[usize::from(*pick) % body.len()]);
                    code.extend_from_slice(operands);
                }
                starts.push(code.len());
                code.push(ends[usize::from(*end) % ends.len()]);
                code.extend_from_slice(&[0x21, 0x43, 0x65]);
            }
            let mut bitmask = alloc::vec![0u8; code.len()];
            for &start in &starts {
                bitmask[start] = 1;
            }
            let expected: alloc::vec::Vec<u32> = block_starts
                .iter()
                .map(|&start| {
                    let costs: alloc::vec::Vec<FastCost> = starts
                        .iter()
                        .filter(|&&pc| pc >= start)
                        .map(|&pc| cost(&code, &bitmask, pc).expect("a row"))
                        .scan(false, |ended, cost| {
                            (!core::mem::replace(ended, cost.is_terminator)).then_some(cost)
                        })
                        .collect();
                    crate::gas_sim::reference_conformance_cost(&costs)
                })
                .collect();
            let interpreter = crate::Interpreter::predecode(&code, &bitmask, &[]);
            let priced = |costs: &[u32]| -> alloc::vec::Vec<u32> {
                block_starts.iter().map(|&start| costs[start]).collect()
            };
            prop_assert_eq!(priced(&interpreter.block_gas_costs), expected.clone());
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            {
                let native = crate::recompiler::compile_code(&code, &bitmask, &[]).unwrap();
                prop_assert_eq!(priced(&native.block_gas_costs), expected);
            }
        }

        /// Blocks of valid instructions cost on the production simulator
        /// what the literal scheduler gives on the text's tables.
        #[test]
        fn blocks_cost_the_literal_schedule_of_the_texts_table(
            raw in proptest::collection::vec((any::<u8>(), any::<[u8; 3]>()), 1..40),
        ) {
            let valid: alloc::vec::Vec<u8> = (0..=u8::MAX)
                .filter(|&op| crate::instruction::Opcode::from_byte(op).is_some() && !terminates(op))
                .collect();
            let mut code = alloc::vec::Vec::new();
            let mut starts = alloc::vec::Vec::new();
            for (pick, operands) in &raw {
                starts.push(code.len());
                code.push(valid[usize::from(*pick) % valid.len()]);
                code.extend_from_slice(operands);
            }
            starts.push(code.len());
            code.push(0);
            let mut bitmask = alloc::vec![0u8; code.len()];
            for &start in &starts {
                bitmask[start] = 1;
            }
            let costs: alloc::vec::Vec<FastCost> = starts
                .iter()
                .map(|&pc| cost(&code, &bitmask, pc).expect("a row"))
                .collect();
            // Within the 64 entries the literal scheduler's words index.
            prop_assume!(costs.len() <= 64);
            let mut simulator = crate::gas_sim::GasSimulator::new();
            for &pc in &starts {
                let production = crate::gas_cost::fast_cost_from_raw(
                    code[pc],
                    code.get(pc + 1).copied().unwrap_or(0) & 0x0f,
                    code.get(pc + 1).copied().unwrap_or(0) >> 4,
                    code.get(pc + 2).copied().unwrap_or(0),
                    pc as u32,
                    &code,
                    &bitmask,
                );
                simulator.feed(&production);
            }
            prop_assert_eq!(
                simulator.flush_and_get_cost(),
                crate::gas_sim::reference_conformance_cost(&costs)
            );
        }
    }
}
