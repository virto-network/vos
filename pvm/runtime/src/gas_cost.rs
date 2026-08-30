//! Profile-scoped per-basic-block gas costs.
//!
//! Simulates a CPU pipeline to compute gas cost for a basic block.
//! Cost = max(simulation_cycles - 3, 1).
//!
//! Pipeline model:
//! - Reorder buffer: max 32 entries
//! - 4 decode slots per cycle, 5 dispatch slots per cycle
//! - Execution units: ALU:4, LOAD:4, STORE:4, MUL:1, DIV:1

/// Normalize encoded register fields to the gas table's `(dst, src1, src2)`
/// convention.
///
/// Most PVM formats encode their destination in the low nibble (`rA`), which
/// is already the convention used by the gas tables below. Appendix A.5.13 is
/// different: three-register instructions encode sources `rA`, `rB` in the
/// first operand byte and destination `rD` in the second. Keeping the raw
/// `(rA, rB, rD)` order here would invert data dependencies while producing
/// otherwise plausible block costs.
#[inline(always)]
fn gas_register_roles(
    isa_mode: crate::IsaMode,
    opcode: u8,
    raw_a: u8,
    raw_b: u8,
    raw_d: u8,
) -> (u8, u8, u8) {
    if isa_mode == crate::IsaMode::Conformance && (190..=230).contains(&opcode) {
        // A.5.13 clamps the complete second operand byte, not just its low
        // nibble. Bytes 13..=255 therefore all name r12.
        (raw_d.min(12), raw_a.min(12), raw_b.min(12))
    } else {
        // Temporary compatibility boundary: frozen capability-manifest/Jar
        // artifacts were metered with the encoded low nibble treated as the
        // destination. Preserve that consensus-visible profile until the
        // private adapter is removed; standard v0.8 programs never use it.
        (raw_a, raw_b, raw_d & 0x0f)
    }
}

#[inline(always)]
fn gas_raw_d(isa_mode: crate::IsaMode, encoded: u8) -> u8 {
    if isa_mode == crate::IsaMode::Conformance {
        encoded
    } else {
        encoded & 0x0f
    }
}

#[inline(always)]
fn missing_raw_register(isa_mode: crate::IsaMode) -> u8 {
    if isa_mode == crate::IsaMode::Conformance {
        0
    } else {
        // Frozen decoded/LUT fallback; standard ζ uses zero extension.
        0xff
    }
}

/// Branch latency `b` from the v0.8.0 gas-cost table.
///
/// The standard profile reads zero-extended instruction data at both the
/// explicit target and the sequential fallthrough (`pc + 1 + skip`). A branch
/// is short when either byte is trap (0) or unlikely (2). These are byte reads,
/// not validated instruction fetches, so neither position must be in bounds or
/// marked as an instruction start.
///
/// The temporary Jar profile preserves its frozen target-only/in-bounds/
/// instruction-start predicate because changing it would alter existing
/// service consensus semantics.
fn branch_cost(
    code: &[u8],
    bitmask: &[u8],
    pc: usize,
    target: usize,
    isa_mode: crate::IsaMode,
) -> u32 {
    if isa_mode == crate::IsaMode::Jar {
        return if target < code.len()
            && target < bitmask.len()
            && bitmask[target] == 1
            && matches!(code[target], 0 | 2)
        {
            1
        } else {
            20
        };
    }

    let fallthrough = pc.saturating_add(1 + skip_distance(bitmask, pc));
    let zero_extended = |index: usize| code.get(index).copied().unwrap_or(0);
    if matches!(zero_extended(target), 0 | 2) || matches!(zero_extended(fallthrough), 0 | 2) {
        1
    } else {
        20
    }
}

/// Compute skip distance (bytes to next instruction start).
pub fn skip_distance(bitmask: &[u8], pc: usize) -> usize {
    for j in 0..25 {
        let idx = pc + 1 + j;
        let bit = if idx < bitmask.len() { bitmask[idx] } else { 1 };
        if bit == 1 {
            return j;
        }
    }
    24
}

// ============================================================================
// Compact instruction-cost representation (safe Rust, fixed-width)
// ============================================================================

/// Compact instruction cost for the fast simulator.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct FastCost {
    pub cycles: u8,
    pub decode_slots: u8,
    /// 0=none, 1=alu, 2=load(+alu), 3=store(+alu), 4=mul(+alu),
    /// 5=div(+alu), 6=two ALUs.
    pub exec_unit: u8,
    pub src_mask: u16,
    pub dst_mask: u16,
    pub is_terminator: bool,
    pub is_move_reg: bool,
}

const EU_NONE: u8 = 0;
const EU_ALU: u8 = 1;
const EU_LOAD: u8 = 2;
const EU_STORE: u8 = 3;
const EU_MUL: u8 = 4;
const EU_DIV: u8 = 5;
const EU_ALU2: u8 = 6;

#[inline(always)]
fn reg_bit(r: u8) -> u16 {
    // PVM clamps registers to 0-12; raw nibble 13/14/15 all map to register 12.
    1u16 << r.min(12)
}

/// Extract branch target from raw code bytes (for gas cost computation).
/// Works for both OneRegImmOffset and TwoRegOneOffset categories.
fn extract_branch_target_raw(code: &[u8], bitmask: &[u8], pc: usize) -> usize {
    let skip = {
        // No instruction start within 25 bytes → 24 (GP F_skip cap).
        let mut s = 24;
        for j in 0..25 {
            let idx = pc + 1 + j;
            if idx >= bitmask.len() || bitmask[idx] == 1 {
                s = j;
                break;
            }
        }
        s
    };
    let opcode = code[pc];
    // For branches, use the existing decode_args to get the offset
    let cat = crate::instruction::Opcode::from_byte(opcode)
        .map(|o| o.category())
        .unwrap_or(crate::instruction::InstructionCategory::NoArgs);
    let args = crate::args::decode_args(code, pc, skip, cat);
    match args {
        crate::args::Args::RegImmOffset { offset, .. } => offset as usize,
        crate::args::Args::TwoRegOffset { offset, .. } => offset as usize,
        crate::args::Args::Offset { offset } => offset as usize,
        _ => pc,
    }
}

/// Compute FastCost from raw register bytes (no Args enum needed).
/// For branches, extracts target from raw code bytes.
/// Default load/store latency (L2 cache hit baseline).
pub const DEFAULT_MEM_CYCLES: u8 = 25;

#[allow(clippy::too_many_arguments)]
pub fn fast_cost_from_raw(
    opcode_byte: u8,
    raw_a: u8,
    raw_b: u8,
    raw_d: u8,
    pc: u32,
    code: &[u8],
    bitmask: &[u8],
    mem_cycles: u8,
    isa_mode: crate::IsaMode,
) -> FastCost {
    let mem_cycles = crate::mem_cycles_for_mode(mem_cycles, isa_mode);
    let (ra, rb, rd) = gas_register_roles(isa_mode, opcode_byte, raw_a, raw_b, raw_d);
    let r1 = |r: u8| reg_bit(r);
    let r2 = |a: u8, b: u8| reg_bit(a) | reg_bit(b);
    let r3 = |a: u8, b: u8, c: u8| reg_bit(a) | reg_bit(b) | reg_bit(c);
    let dst_src_overlap = |dst: u8, s: u16| (reg_bit(dst) & s) != 0;

    let opcode = opcode_byte;
    match opcode {
        // No-arg instruction costs (unlikely is not in set T).
        0 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        1 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        2 => FastCost {
            cycles: 40,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        // Opcode 3 is the capability-runtime extension and exits to that
        // runtime. Standard ecalli (10) is not in Gray Paper set T.
        3 => FastCost {
            cycles: 100,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        10 => FastCost {
            cycles: 100,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Control flow
        40 => FastCost {
            cycles: 15,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_NONE
            } else {
                EU_ALU
            },
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        80 => FastCost {
            cycles: 15,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_NONE
            } else {
                EU_ALU
            },
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: true,
            is_move_reg: false,
        },
        50 => FastCost {
            cycles: 22,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_NONE
            } else {
                EU_ALU
            },
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                r1(ra)
            } else {
                0
            },
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        180 => FastCost {
            cycles: 22,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_NONE
            } else {
                EU_ALU
            },
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: true,
            is_move_reg: false,
        },

        // Loads
        52..=58 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_LOAD,
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                0
            } else {
                r1(rb)
            },
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        124..=130 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_LOAD,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Stores
        59..=62 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                r1(ra)
            } else {
                r2(ra, rb)
            },
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        120..=123 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r2(ra, rb),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        30..=33 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        70..=73 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r1(ra),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Load immediates
        51 => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        20 => FastCost {
            cycles: 1,
            decode_slots: 2,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // move_reg — no ROB entry
        100 => FastCost {
            cycles: 0,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: true,
        },

        // Frozen capability-manifest `sbrk`, normalized to private opcode 254.
        254 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Branches (reg+imm+offset)
        81..=90 => {
            let target = extract_branch_target_raw(code, bitmask, pc as usize);
            let bc = branch_cost(code, bitmask, pc as usize, target, isa_mode);
            FastCost {
                cycles: bc as u8,
                decode_slots: 1,
                exec_unit: EU_ALU,
                src_mask: r1(ra),
                dst_mask: 0,
                is_terminator: true,
                is_move_reg: false,
            }
        }
        // Branches (two-reg+offset)
        170..=175 => {
            let target = extract_branch_target_raw(code, bitmask, pc as usize);
            let bc = branch_cost(code, bitmask, pc as usize, target, isa_mode);
            FastCost {
                cycles: bc as u8,
                decode_slots: 1,
                exec_unit: EU_ALU,
                src_mask: r2(ra, rb),
                dst_mask: 0,
                is_terminator: true,
                is_move_reg: false,
            }
        }

        // ALU 64-bit 3-reg
        200 | 201 | 210 | 211 | 212 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 32-bit 3-reg
        190 | 191 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 2-op imm 64-bit
        132 | 133 | 134 | 149 | 151 | 152 | 153 | 158 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 2-op imm 32-bit
        131 | 138 | 139 | 140 | 160 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Trivial 2-op: popcount, clz, sign_extend, zero_extend.
        101 | 102 | 103 | 104 | 107 | 108 | 109 => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // reverse_bytes uses the ordinary two-operand overlap rule in v0.8.
        110 => FastCost {
            cycles: 1,
            decode_slots: if isa_mode == crate::IsaMode::Conformance && reg_bit(ra) != reg_bit(rb) {
                2
            } else {
                1
            },
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // ctz requires two ALU units in standard v0.8.
        105 | 106 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_ALU2
            } else {
                EU_ALU
            },
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Shifts 64-bit 3-reg
        207 | 208 | 209 | 220 | 222 => {
            let dc = if rb == ra { 2 } else { 3 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r2(rb, rd),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Shifts 32-bit 3-reg
        197 | 198 | 199 | 221 | 223 => {
            let dc = if rb == ra { 3 } else { 4 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r2(rb, rd),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Shift alt 64-bit
        155 | 156 | 157 | 159 => FastCost {
            cycles: 1,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Shift alt 32-bit
        144 | 145 | 146 | 161 => FastCost {
            cycles: 2,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Comparisons 3-reg
        216 | 217 => FastCost {
            cycles: 3,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Comparisons imm
        136 | 137 | 142 | 143 => FastCost {
            cycles: 3,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Conditional moves 3-reg
        218 | 219 => FastCost {
            cycles: 2,
            decode_slots: 2,
            exec_unit: EU_ALU,
            // rD' = rA/rD selected by rB: the old destination is a source.
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                r3(ra, rb, rd)
            } else {
                r2(rb, rd)
            },
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Conditional moves imm
        147 | 148 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            // rA' = imm/rA selected by rB: the old destination is a source.
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                r2(ra, rb)
            } else {
                r1(rb)
            },
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Min/Max
        227..=230 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // and_inv, or_inv
        224 | 225 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // xnor
        226 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // neg_add_imm
        154 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        141 => FastCost {
            cycles: 3,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Multiply 64-bit 3-reg
        202 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // mul_imm_64
        150 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Multiply 32-bit 3-reg
        192 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 4,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // mul_imm_32
        135 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost {
                cycles: 4,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Multiply upper
        213 | 214 => FastCost {
            cycles: 4,
            decode_slots: 4,
            exec_unit: EU_MUL,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        215 => FastCost {
            cycles: 6,
            decode_slots: 4,
            exec_unit: EU_MUL,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Divide
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 => FastCost {
            cycles: 60,
            decode_slots: 4,
            exec_unit: EU_DIV,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Default
        _ => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
    }
}

/// Compute FastCost using pre-decoded branch target from Args.
///
/// For non-branch instructions, identical to `fast_cost_from_raw`. For branches,
/// avoids the redundant `extract_branch_target_raw` call which re-computes skip
/// distances and re-decodes args just to extract the branch offset.
#[inline(always)]
pub fn fast_cost_from_decoded(
    opcode_byte: u8,
    args: &crate::args::Args,
    pc: u32,
    code: &[u8],
    bitmask: &[u8],
    mem_cycles: u8,
    isa_mode: crate::IsaMode,
) -> FastCost {
    use crate::args::Args;

    let mem_cycles = crate::mem_cycles_for_mode(mem_cycles, isa_mode);

    // Use raw byte positions for register fields (same as fast_cost_from_raw).
    // The raw nibble positions don't correspond to semantic arg names — the
    // mapping varies by instruction format — so we read directly from code[].
    let pcu = pc as usize;
    let raw_a = if pcu + 1 < code.len() {
        code[pcu + 1] & 0x0F
    } else {
        missing_raw_register(isa_mode)
    };
    let raw_b = if pcu + 1 < code.len() {
        (code[pcu + 1] >> 4) & 0x0F
    } else {
        missing_raw_register(isa_mode)
    };
    let raw_d = if pcu + 2 < code.len() {
        gas_raw_d(isa_mode, code[pcu + 2])
    } else {
        missing_raw_register(isa_mode)
    };

    let (ra, rb, rd) = gas_register_roles(isa_mode, opcode_byte, raw_a, raw_b, raw_d);

    // Extract branch target from already-decoded offset (the main optimization:
    // avoids extract_branch_target_raw which does skip computation + decode_args)
    let branch_target = match args {
        Args::RegImmOffset { offset, .. } => *offset as usize,
        Args::TwoRegOffset { offset, .. } => *offset as usize,
        Args::Offset { offset } => *offset as usize,
        _ => pcu,
    };

    let r1 = |r: u8| reg_bit(r);
    let r2 = |a: u8, b: u8| reg_bit(a) | reg_bit(b);
    let r3 = |a: u8, b: u8, c: u8| reg_bit(a) | reg_bit(b) | reg_bit(c);
    let dst_src_overlap = |dst: u8, s: u16| (reg_bit(dst) & s) != 0;

    let opcode = opcode_byte;
    match opcode {
        // No-arg instruction costs (unlikely is not in set T).
        0 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        1 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        2 => FastCost {
            cycles: 40,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        // Opcode 3 is the capability-runtime extension and exits to that
        // runtime. Standard ecalli (10) is not in Gray Paper set T.
        3 => FastCost {
            cycles: 100,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        10 => FastCost {
            cycles: 100,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Control flow
        40 => FastCost {
            cycles: 15,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_NONE
            } else {
                EU_ALU
            },
            src_mask: 0,
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        80 => FastCost {
            cycles: 15,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_NONE
            } else {
                EU_ALU
            },
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: true,
            is_move_reg: false,
        },
        50 => FastCost {
            cycles: 22,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_NONE
            } else {
                EU_ALU
            },
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                r1(ra)
            } else {
                0
            },
            dst_mask: 0,
            is_terminator: true,
            is_move_reg: false,
        },
        180 => FastCost {
            cycles: 22,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_NONE
            } else {
                EU_ALU
            },
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: true,
            is_move_reg: false,
        },

        // Loads
        52..=58 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_LOAD,
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                0
            } else {
                r1(rb)
            },
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        124..=130 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_LOAD,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Stores
        59..=62 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                r1(ra)
            } else {
                r2(ra, rb)
            },
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        120..=123 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r2(ra, rb),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        30..=33 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
        70..=73 => FastCost {
            cycles: mem_cycles,
            decode_slots: 1,
            exec_unit: EU_STORE,
            src_mask: r1(ra),
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Load immediates
        51 => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        20 => FastCost {
            cycles: 1,
            decode_slots: 2,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // move_reg — no ROB entry
        100 => FastCost {
            cycles: 0,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: true,
        },

        // Frozen capability-manifest `sbrk`, normalized to private opcode 254.
        254 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },

        // Branches (reg+imm+offset) — uses pre-decoded branch target
        81..=90 => {
            let bc = branch_cost(code, bitmask, pcu, branch_target, isa_mode);
            FastCost {
                cycles: bc as u8,
                decode_slots: 1,
                exec_unit: EU_ALU,
                src_mask: r1(ra),
                dst_mask: 0,
                is_terminator: true,
                is_move_reg: false,
            }
        }
        // Branches (two-reg+offset) — uses pre-decoded branch target
        170..=175 => {
            let bc = branch_cost(code, bitmask, pcu, branch_target, isa_mode);
            FastCost {
                cycles: bc as u8,
                decode_slots: 1,
                exec_unit: EU_ALU,
                src_mask: r2(ra, rb),
                dst_mask: 0,
                is_terminator: true,
                is_move_reg: false,
            }
        }

        // ALU 64-bit 3-reg
        200 | 201 | 210 | 211 | 212 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 32-bit 3-reg
        190 | 191 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 2-op imm 64-bit
        132 | 133 | 134 | 149 | 151 | 152 | 153 | 158 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // ALU 2-op imm 32-bit
        131 | 138 | 139 | 140 | 160 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Trivial 2-op: popcount, clz, sign_extend, zero_extend.
        101 | 102 | 103 | 104 | 107 | 108 | 109 => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // reverse_bytes uses the ordinary two-operand overlap rule in v0.8.
        110 => FastCost {
            cycles: 1,
            decode_slots: if isa_mode == crate::IsaMode::Conformance && reg_bit(ra) != reg_bit(rb) {
                2
            } else {
                1
            },
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // ctz requires two ALU units in standard v0.8.
        105 | 106 => FastCost {
            cycles: 2,
            decode_slots: 1,
            exec_unit: if isa_mode == crate::IsaMode::Conformance {
                EU_ALU2
            } else {
                EU_ALU
            },
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Shifts 64-bit 3-reg
        207 | 208 | 209 | 220 | 222 => {
            let dc = if rb == ra { 2 } else { 3 };
            FastCost {
                cycles: 1,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r2(rb, rd),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Shifts 32-bit 3-reg
        197 | 198 | 199 | 221 | 223 => {
            let dc = if rb == ra { 3 } else { 4 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: r2(rb, rd),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Shift alt 64-bit
        155 | 156 | 157 | 159 => FastCost {
            cycles: 1,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Shift alt 32-bit
        144 | 145 | 146 | 161 => FastCost {
            cycles: 2,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Comparisons 3-reg
        216 | 217 => FastCost {
            cycles: 3,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Comparisons imm
        136 | 137 | 142 | 143 => FastCost {
            cycles: 3,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Conditional moves 3-reg
        218 | 219 => FastCost {
            cycles: 2,
            decode_slots: 2,
            exec_unit: EU_ALU,
            // rD' = rA/rD selected by rB: the old destination is a source.
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                r3(ra, rb, rd)
            } else {
                r2(rb, rd)
            },
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // Conditional moves imm
        147 | 148 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            // rA' = imm/rA selected by rB: the old destination is a source.
            src_mask: if isa_mode == crate::IsaMode::Conformance {
                r2(ra, rb)
            } else {
                r1(rb)
            },
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Min/Max
        227..=230 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // and_inv, or_inv
        224 | 225 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        // xnor
        226 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 2,
                decode_slots: dc,
                exec_unit: EU_ALU,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // neg_add_imm
        154 => FastCost {
            cycles: 2,
            decode_slots: 3,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        141 => FastCost {
            cycles: 3,
            decode_slots: 4,
            exec_unit: EU_ALU,
            src_mask: r1(rb),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Multiply 64-bit 3-reg
        202 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 1 } else { 2 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // mul_imm_64
        150 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 1 } else { 2 };
            FastCost {
                cycles: 3,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Multiply 32-bit 3-reg
        192 => {
            let s = r2(rb, rd);
            let dc = if dst_src_overlap(ra, s) { 2 } else { 3 };
            FastCost {
                cycles: 4,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: s,
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // mul_imm_32
        135 => {
            let dc = if dst_src_overlap(ra, r1(rb)) { 2 } else { 3 };
            FastCost {
                cycles: 4,
                decode_slots: dc,
                exec_unit: EU_MUL,
                src_mask: r1(rb),
                dst_mask: r1(ra),
                is_terminator: false,
                is_move_reg: false,
            }
        }
        // Multiply upper
        213 | 214 => FastCost {
            cycles: 4,
            decode_slots: 4,
            exec_unit: EU_MUL,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },
        215 => FastCost {
            cycles: 6,
            decode_slots: 4,
            exec_unit: EU_MUL,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Divide
        193 | 194 | 195 | 196 | 203 | 204 | 205 | 206 => FastCost {
            cycles: 60,
            decode_slots: 4,
            exec_unit: EU_DIV,
            src_mask: r2(rb, rd),
            dst_mask: r1(ra),
            is_terminator: false,
            is_move_reg: false,
        },

        // Default
        _ => FastCost {
            cycles: 1,
            decode_slots: 1,
            exec_unit: EU_NONE,
            src_mask: 0,
            dst_mask: 0,
            is_terminator: false,
            is_move_reg: false,
        },
    }
}

// === Gas cost lookup table ===
// Replaces the 256-arm match in fast_cost_from_decoded with a single array
// lookup + lightweight mask computation. Eliminates branch-heavy dispatch.

/// Register pattern encoding for the lookup table.
/// Describes which raw register fields contribute to src_mask and dst_mask.
#[derive(Clone, Copy)]
struct GasCostEntry {
    cycles: u8,
    /// Base decode_slots (before overlap adjustment).
    decode_slots: u8,
    exec_unit: u8,
    /// Source mask pattern: 0=none, 1=ra, 2=rb, 3=ra|rb, 4=rb|rd,
    /// 5=ra|rb|rd.
    src_pat: u8,
    /// Destination mask pattern: 0=none, 1=ra, 2=rd
    dst_pat: u8,
    flags: u8, // bit0=terminator, bit1=move_reg, bit2=needs_branch_cost, bit3=overlap_adjust
    /// For overlap_adjust: decode_slots_if_overlap (lower) and decode_slots_no_overlap (upper nibble)
    overlap_slots: u8,
}

const F_TERM: u8 = 1;
const F_MOVE: u8 = 2;
const F_BRANCH: u8 = 4;
const F_OVERLAP: u8 = 8;
const F_BRANCH2: u8 = 16; // two-reg branch (src=ra|rb)
const F_SHIFT_OVERLAP: u8 = 32; // shift: overlap is rb==ra, not dst_src_overlap
const F_COMPLEX_SRC: u8 = 64; // three source registers; use the full-mask path

const fn gc(
    cycles: u8,
    decode_slots: u8,
    exec_unit: u8,
    src_pat: u8,
    dst_pat: u8,
    flags: u8,
) -> GasCostEntry {
    GasCostEntry {
        cycles,
        decode_slots,
        exec_unit,
        src_pat,
        dst_pat,
        flags,
        overlap_slots: 0,
    }
}
const fn gc_ov(
    cycles: u8,
    overlap_if: u8,
    overlap_no: u8,
    exec_unit: u8,
    src_pat: u8,
    dst_pat: u8,
    flags: u8,
) -> GasCostEntry {
    GasCostEntry {
        cycles,
        decode_slots: 0,
        exec_unit,
        src_pat,
        dst_pat,
        flags: flags | F_OVERLAP,
        overlap_slots: overlap_if | (overlap_no << 4),
    }
}

static GAS_COST_LUT: [GasCostEntry; 256] = {
    let d = gc(1, 1, EU_NONE, 0, 0, 0); // default
    let mut t = [d; 256];
    // No-arg instruction costs. Only trap/fallthrough are in standard set T.
    t[0] = gc(2, 1, EU_NONE, 0, 0, F_TERM);
    t[1] = gc(2, 1, EU_NONE, 0, 0, F_TERM);
    t[2] = gc(40, 1, EU_NONE, 0, 0, 0);
    // Ecall (3): capability-runtime management-op/dynamic-CALL exit. Missing
    // F_TERM here meant post-Ecall PCs never became gas-block
    // starts, so the JIT had no dispatch entry to resume at after the kernel
    // handled the ecall (re-entry dispatched to offset 0 = the prologue).
    t[3] = gc(100, 4, EU_ALU, 0, 0, F_TERM);
    t[10] = gc(100, 4, EU_ALU, 0, 0, 0);
    // Control flow
    t[40] = gc(15, 1, EU_ALU, 0, 0, F_TERM);
    t[80] = gc(15, 1, EU_ALU, 0, 1, F_TERM); // dst=ra
    t[50] = gc(22, 1, EU_ALU, 0, 0, F_TERM);
    t[180] = gc(22, 1, EU_ALU, 2, 1, F_TERM); // src=rb, dst=ra
    // Loads (src=rb, dst=ra)
    let mut i = 52;
    while i <= 58 {
        t[i] = gc(25, 1, EU_LOAD, 2, 1, 0);
        i += 1;
    }
    i = 124;
    while i <= 130 {
        t[i] = gc(25, 1, EU_LOAD, 2, 1, 0);
        i += 1;
    }
    // Stores (src=ra|rb, dst=none)
    i = 59;
    while i <= 62 {
        t[i] = gc(25, 1, EU_STORE, 3, 0, 0);
        i += 1;
    }
    i = 120;
    while i <= 123 {
        t[i] = gc(25, 1, EU_STORE, 3, 0, 0);
        i += 1;
    }
    i = 30;
    while i <= 33 {
        t[i] = gc(25, 1, EU_STORE, 0, 0, 0);
        i += 1;
    }
    i = 70;
    while i <= 73 {
        t[i] = gc(25, 1, EU_STORE, 1, 0, 0);
        i += 1;
    } // src=ra
    // Load immediates
    t[51] = gc(1, 1, EU_NONE, 0, 1, 0);
    t[20] = gc(1, 2, EU_NONE, 0, 1, 0);
    // move_reg
    t[100] = gc(0, 1, EU_NONE, 2, 1, F_MOVE); // src=rb, dst=ra
    // Frozen capability-manifest `sbrk` after private normalization.
    t[254] = gc(2, 1, EU_NONE, 0, 0, 0);
    // Branches (reg+imm+offset) — needs branch_cost
    i = 81;
    while i <= 90 {
        t[i] = gc(0, 1, EU_ALU, 1, 0, F_TERM | F_BRANCH);
        i += 1;
    } // src=ra
    // Branches (two-reg+offset)
    i = 170;
    while i <= 175 {
        t[i] = gc(0, 1, EU_ALU, 3, 0, F_TERM | F_BRANCH2);
        i += 1;
    } // src=ra|rb
    // ALU 64-bit 3-reg (src=rb|rd, dst=ra, overlap adjust)
    t[200] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    t[201] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    t[210] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    t[211] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    t[212] = gc_ov(1, 1, 2, EU_ALU, 4, 1, 0);
    // ALU 32-bit 3-reg
    t[190] = gc_ov(2, 2, 3, EU_ALU, 4, 1, 0);
    t[191] = gc_ov(2, 2, 3, EU_ALU, 4, 1, 0);
    // ALU 2-op imm 64-bit (src=rb, dst=ra, overlap adjust)
    {
        let e = gc_ov(1, 1, 2, EU_ALU, 2, 1, 0);
        t[132] = e;
        t[133] = e;
        t[134] = e;
        t[149] = e;
        t[151] = e;
        t[152] = e;
        t[153] = e;
        t[158] = e;
    }
    // ALU 2-op imm 32-bit
    {
        let e = gc_ov(2, 2, 3, EU_ALU, 2, 1, 0);
        t[131] = e;
        t[138] = e;
        t[139] = e;
        t[140] = e;
        t[160] = e;
    }
    // Trivial 2-op (src=rb, dst=ra)
    {
        let e = gc(1, 1, EU_ALU, 2, 1, 0);
        t[101] = e;
        t[102] = e;
        t[103] = e;
        t[104] = e;
        t[107] = e;
        t[108] = e;
        t[109] = e;
        t[110] = e;
    }
    // ctz
    t[105] = gc(2, 1, EU_ALU, 2, 1, 0);
    t[106] = gc(2, 1, EU_ALU, 2, 1, 0);
    // Shifts 64-bit 3-reg (src=rb|rd, dst=ra, shift overlap: rb==ra)
    {
        let e = gc_ov(1, 2, 3, EU_ALU, 4, 1, F_SHIFT_OVERLAP);
        t[207] = e;
        t[208] = e;
        t[209] = e;
        t[220] = e;
        t[222] = e;
    }
    // Shifts 32-bit 3-reg
    {
        let e = gc_ov(2, 3, 4, EU_ALU, 4, 1, F_SHIFT_OVERLAP);
        t[197] = e;
        t[198] = e;
        t[199] = e;
        t[221] = e;
        t[223] = e;
    }
    // Shift alt 64-bit
    {
        let e = gc(1, 3, EU_ALU, 2, 1, 0);
        t[155] = e;
        t[156] = e;
        t[157] = e;
        t[159] = e;
    }
    // Shift alt 32-bit
    {
        let e = gc(2, 4, EU_ALU, 2, 1, 0);
        t[144] = e;
        t[145] = e;
        t[146] = e;
        t[161] = e;
    }
    // Comparisons 3-reg (src=rb|rd, dst=ra)
    t[216] = gc(3, 3, EU_ALU, 4, 1, 0);
    t[217] = gc(3, 3, EU_ALU, 4, 1, 0);
    // Comparisons imm (src=rb, dst=ra)
    {
        let e = gc(3, 3, EU_ALU, 2, 1, 0);
        t[136] = e;
        t[137] = e;
        t[142] = e;
        t[143] = e;
    }
    // Frozen JAR operand patterns. `gas_cost_entry` overlays the corrected
    // standard-v0.8 source sets without changing existing service metering.
    t[218] = gc(2, 2, EU_ALU, 4, 1, 0);
    t[219] = gc(2, 2, EU_ALU, 4, 1, 0);
    t[147] = gc(2, 3, EU_ALU, 2, 1, 0);
    t[148] = gc(2, 3, EU_ALU, 2, 1, 0);
    // Min/Max (src=rb|rd, dst=ra, overlap adjust)
    {
        let e = gc_ov(3, 2, 3, EU_ALU, 4, 1, 0);
        t[227] = e;
        t[228] = e;
        t[229] = e;
        t[230] = e;
    }
    // and_inv, or_inv
    t[224] = gc(2, 3, EU_ALU, 4, 1, 0);
    t[225] = gc(2, 3, EU_ALU, 4, 1, 0);
    // xnor (overlap adjust)
    t[226] = gc_ov(2, 2, 3, EU_ALU, 4, 1, 0);
    // neg_add_imm
    t[154] = gc(2, 3, EU_ALU, 2, 1, 0);
    t[141] = gc(3, 4, EU_ALU, 2, 1, 0);
    // Multiply 64-bit 3-reg (overlap adjust)
    t[202] = gc_ov(3, 1, 2, EU_MUL, 4, 1, 0);
    // mul_imm_64
    t[150] = gc_ov(3, 1, 2, EU_MUL, 2, 1, 0);
    // Multiply 32-bit 3-reg
    t[192] = gc_ov(4, 2, 3, EU_MUL, 4, 1, 0);
    // mul_imm_32
    t[135] = gc_ov(4, 2, 3, EU_MUL, 2, 1, 0);
    // Multiply upper
    t[213] = gc(4, 4, EU_MUL, 4, 1, 0);
    t[214] = gc(4, 4, EU_MUL, 4, 1, 0);
    t[215] = gc(6, 4, EU_MUL, 4, 1, 0);
    // Divide (src=rb|rd, dst=ra)
    {
        let e = gc(60, 4, EU_DIV, 4, 1, 0);
        t[193] = e;
        t[194] = e;
        t[195] = e;
        t[196] = e;
        t[203] = e;
        t[204] = e;
        t[205] = e;
        t[206] = e;
    }
    t
};

/// Return the profile-specific A.58 entry. The static table is the frozen JAR
/// contract; strict v0.8 corrections are applied only for Conformance mode.
#[inline(always)]
fn gas_cost_entry(isa_mode: crate::IsaMode, opcode: u8) -> GasCostEntry {
    let mut entry = GAS_COST_LUT[opcode as usize];
    if isa_mode != crate::IsaMode::Conformance {
        return entry;
    }

    match opcode {
        // Static/dynamic jumps require no execution unit in A.58.
        40 | 80 | 50 | 180 => entry.exec_unit = EU_NONE,
        _ => {}
    }
    match opcode {
        // Direct operands do not contain an encoded base register.
        50 => entry.src_pat = 1,      // jump_ind reads rA
        52..=58 => entry.src_pat = 0, // direct load reads no register
        59..=62 => entry.src_pat = 1, // direct store reads only rA
        // Conditional moves read their old destination as well.
        147 | 148 => entry.src_pat = 3, // rA | rB
        218 | 219 => {
            entry.src_pat = 5; // rD(old) | rA | rB after role normalization
            entry.flags |= F_COMPLEX_SRC;
        }
        _ => {}
    }
    match opcode {
        // `trivialtwooptwocycles` consumes two of the four ALUs.
        105 | 106 => entry.exec_unit = EU_ALU2,
        // reverse_bytes is `simplealutwoop`: one slot on overlap, two otherwise.
        110 => {
            entry.flags |= F_OVERLAP;
            entry.overlap_slots = 1 | (2 << 4);
        }
        _ => {}
    }
    entry
}

/// Feed the gas simulator directly from raw register bytes, skipping FastCost
/// construction. Returns (is_terminator, is_branch_or_special) — the caller
/// uses is_branch_or_special to fall back to the full path for rare cases.
#[inline(always)]
pub fn feed_gas_direct(
    opcode_byte: u8,
    raw_a: u8,
    raw_b: u8,
    raw_d: u8,
    gas_sim: &mut crate::gas_sim::GasSimulator,
    mem_cycles: u8,
    isa_mode: crate::IsaMode,
) -> (bool, bool) {
    let mem_cycles = crate::mem_cycles_for_mode(mem_cycles, isa_mode);
    let (ra, rb, rd) = gas_register_roles(isa_mode, opcode_byte, raw_a, raw_b, raw_d);
    let entry = gas_cost_entry(isa_mode, opcode_byte);
    let flags = entry.flags;

    // Fast path: non-branch, non-overlap, non-move (~90% of instructions).
    if flags & (F_BRANCH | F_BRANCH2 | F_OVERLAP | F_MOVE | F_SHIFT_OVERLAP | F_COMPLEX_SRC) == 0 {
        // Map src_pat to register indices (0xFF = "no source")
        let (src1, src2) = match entry.src_pat {
            0 => (0xFF, 0xFF),
            1 => (ra.min(12), 0xFF),
            2 => (rb.min(12), 0xFF),
            3 => (ra.min(12), rb.min(12)),
            4 => (rb.min(12), rd.min(12)),
            _ => (0xFF, 0xFF),
        };
        let dst = if entry.dst_pat == 1 {
            ra.min(12)
        } else if entry.dst_pat == 2 {
            rd.min(12)
        } else {
            0xFF
        };
        // Override cycles for load/store with tier-dependent mem_cycles
        let cycles = if entry.exec_unit == EU_LOAD || entry.exec_unit == EU_STORE {
            mem_cycles
        } else {
            entry.cycles
        };
        gas_sim.feed_direct_with_unit(cycles, entry.decode_slots, entry.exec_unit, src1, src2, dst);
        return (flags & F_TERM != 0, false);
    }

    // Slow path needed — caller must use the full FastCost path
    (flags & F_TERM != 0, true)
}

/// Compute FastCost via lookup table — replaces the 256-arm match dispatch
/// with a single array access + lightweight mask computation.
#[inline(always)]
pub fn fast_cost_lut(
    opcode_byte: u8,
    args: &crate::args::Args,
    pc: u32,
    code: &[u8],
    bitmask: &[u8],
    mem_cycles: u8,
    isa_mode: crate::IsaMode,
) -> FastCost {
    let pcu = pc as usize;
    let reg_byte1 = if pcu + 1 < code.len() {
        code[pcu + 1]
    } else {
        missing_raw_register(isa_mode)
    };
    let ra = reg_byte1 & 0x0F;
    let rb = (reg_byte1 >> 4) & 0x0F;
    let rd = if pcu + 2 < code.len() {
        gas_raw_d(isa_mode, code[pcu + 2])
    } else {
        missing_raw_register(isa_mode)
    };

    fast_cost_lut_inner(
        opcode_byte,
        args,
        pcu,
        code,
        bitmask,
        ra,
        rb,
        rd,
        mem_cycles,
        isa_mode,
    )
}

/// Like `fast_cost_lut` but takes pre-extracted register bytes to avoid
/// re-reading code[pc+1] and code[pc+2] (already decoded by the caller).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn fast_cost_lut_regs(
    opcode_byte: u8,
    args: &crate::args::Args,
    pc: usize,
    code: &[u8],
    bitmask: &[u8],
    ra: u8,
    rb: u8,
    rd: u8,
    mem_cycles: u8,
    isa_mode: crate::IsaMode,
) -> FastCost {
    fast_cost_lut_inner(
        opcode_byte,
        args,
        pc,
        code,
        bitmask,
        ra,
        rb,
        rd,
        mem_cycles,
        isa_mode,
    )
}

/// Inner implementation — separated to allow the compiler to inline the
/// caller-side register extraction and keep the complex logic out-of-line.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn fast_cost_lut_inner(
    opcode_byte: u8,
    args: &crate::args::Args,
    pcu: usize,
    code: &[u8],
    bitmask: &[u8],
    ra: u8,
    rb: u8,
    rd: u8,
    mem_cycles: u8,
    isa_mode: crate::IsaMode,
) -> FastCost {
    use crate::args::Args;

    let mem_cycles = crate::mem_cycles_for_mode(mem_cycles, isa_mode);

    let (ra, rb, rd) = gas_register_roles(isa_mode, opcode_byte, ra, rb, rd);
    let entry = gas_cost_entry(isa_mode, opcode_byte);
    let flags = entry.flags;

    // Fast path: most instructions are non-branch, non-overlap.
    // Skip the expensive branch cost and overlap calculations.
    if flags & (F_BRANCH | F_BRANCH2 | F_OVERLAP) == 0 {
        // Compute masks inline (branchless via LUT could be even faster,
        // but the match is well-predicted for the common patterns).
        let ra_bit = 1u16 << ra.min(12);
        let rb_bit = 1u16 << rb.min(12);
        let rd_bit = 1u16 << rd.min(12);
        let src_mask: u16 = match entry.src_pat {
            0 => 0,
            1 => ra_bit,
            2 => rb_bit,
            3 => ra_bit | rb_bit,
            4 => rb_bit | rd_bit,
            5 => ra_bit | rb_bit | rd_bit,
            _ => 0,
        };
        let dst_mask: u16 = if entry.dst_pat == 1 { ra_bit } else { 0 };
        let cycles = if entry.exec_unit == EU_LOAD || entry.exec_unit == EU_STORE {
            mem_cycles
        } else {
            entry.cycles
        };
        return FastCost {
            cycles,
            decode_slots: entry.decode_slots,
            exec_unit: entry.exec_unit,
            src_mask,
            dst_mask,
            is_terminator: flags & F_TERM != 0,
            is_move_reg: flags & F_MOVE != 0,
        };
    }

    // Slow path: branch or overlap instructions
    let ra_bit = 1u16 << ra.min(12);
    let rb_bit = 1u16 << rb.min(12);
    let rd_bit = 1u16 << rd.min(12);

    let src_mask: u16 = match entry.src_pat {
        0 => 0,
        1 => ra_bit,
        2 => rb_bit,
        3 => ra_bit | rb_bit,
        4 => rb_bit | rd_bit,
        5 => ra_bit | rb_bit | rd_bit,
        _ => 0,
    };
    let dst_mask: u16 = if entry.dst_pat == 1 { ra_bit } else { 0 };

    let cycles = if flags & (F_BRANCH | F_BRANCH2) != 0 {
        let branch_target = match args {
            Args::RegImmOffset { offset, .. } => *offset as usize,
            Args::TwoRegOffset { offset, .. } => *offset as usize,
            Args::Offset { offset } => *offset as usize,
            _ => pcu,
        };
        branch_cost(code, bitmask, pcu, branch_target, isa_mode) as u8
    } else if entry.exec_unit == EU_LOAD || entry.exec_unit == EU_STORE {
        mem_cycles
    } else {
        entry.cycles
    };

    let decode_slots = if flags & F_OVERLAP != 0 {
        let overlap = if flags & F_SHIFT_OVERLAP != 0 {
            rb == ra
        } else {
            (dst_mask & src_mask) != 0
        };
        if overlap {
            entry.overlap_slots & 0x0F
        } else {
            entry.overlap_slots >> 4
        }
    } else {
        entry.decode_slots
    };

    FastCost {
        cycles,
        decode_slots,
        exec_unit: entry.exec_unit,
        src_mask,
        dst_mask,
        is_terminator: flags & F_TERM != 0,
        is_move_reg: flags & F_MOVE != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gas_sim::GasSimulator;

    /// Every opcode must cost the same whether the gas is derived by the
    /// interpreter's hand-written `fast_cost_from_raw` or the JIT's
    /// `GAS_COST_LUT`-based `fast_cost_lut_regs`. The two are independent
    /// implementations of the same model; any per-opcode disagreement is a
    /// consensus bug (gas is consensus-visible), which the differential
    /// fuzzer surfaces one instance at a time — this test finds them all.
    #[test]
    fn lut_matches_hand_table_for_every_opcode() {
        let code = [0u8; 32];
        let mut bitmask = [0u8; 32];
        bitmask[0] = 1;
        let mem_cycles = crate::gas_cost::DEFAULT_MEM_CYCLES;

        // Register bytes to try: covers distinct regs, dst==src overlap, and
        // ra==rb (shift/move overlap paths take different decode-slot counts).
        let reg_bytes: [(u8, u8); 9] = [
            (0, 0),
            (0x21, 3),
            (0x22, 2),
            (0x11, 1),
            (0x30, 0),
            // High nibbles (>12) exercise the register-index clamp, which the
            // two feed paths must apply identically.
            (0xde, 0x07),
            (0xed, 0x0e),
            (0xff, 0x0f),
            (0xcd, 0x0c),
        ];

        let mut mismatches = alloc::vec::Vec::new();
        for opcode in 0u16..256 {
            let opcode = opcode as u8;
            let Some(op) = crate::instruction::Opcode::from_byte(opcode) else {
                continue; // invalid opcodes are rejected before gas is charged
            };
            for (reg_byte1, reg_byte2) in reg_bytes {
                let mut buf = code;
                buf[0] = opcode;
                buf[1] = reg_byte1;
                buf[2] = reg_byte2;
                let skip = crate::interpreter::skip_for_bitmask(&bitmask, 0);
                let (ra, rb, rd) = (buf[1] & 0x0F, (buf[1] >> 4) & 0x0F, buf[2]);

                // Compare the ACTUAL simulator cost of a single-instruction
                // block through each backend's real feed path:
                //   interpreter → fast_cost_from_raw → GasSimulator::feed
                //   JIT (non-branch fast path) → feed_gas_direct → feed_direct
                //   JIT (branch slow path)     → fast_cost_lut_regs → feed
                let mut sim_i = GasSimulator::new_for_mode(crate::IsaMode::Conformance);
                sim_i.feed(&fast_cost_from_raw(
                    opcode,
                    ra,
                    rb,
                    rd,
                    0,
                    &buf,
                    &bitmask,
                    mem_cycles,
                    crate::IsaMode::Conformance,
                ));
                let interp = sim_i.flush_and_get_cost();

                let mut sim_j = GasSimulator::new_for_mode(crate::IsaMode::Conformance);
                let (_, needs_full) = feed_gas_direct(
                    opcode,
                    ra,
                    rb,
                    rd,
                    &mut sim_j,
                    mem_cycles,
                    crate::IsaMode::Conformance,
                );
                if needs_full {
                    let args = crate::args::decode_args(&buf, 0, skip, op.category());
                    sim_j.feed(&fast_cost_lut_regs(
                        opcode,
                        &args,
                        0,
                        &buf,
                        &bitmask,
                        ra,
                        rb,
                        rd,
                        mem_cycles,
                        crate::IsaMode::Conformance,
                    ));
                }
                let jit = sim_j.flush_and_get_cost();

                // Compare the full ROB state, not just the lone-block cost:
                // a per-register completion-time divergence only changes the
                // block total once a LATER instruction depends on that
                // register, which the fuzzer hits but a single-instruction
                // cost comparison misses.
                if interp != jit || sim_i.state() != sim_j.state() {
                    mismatches.push((
                        opcode,
                        reg_byte1,
                        reg_byte2,
                        (interp, sim_i.state()),
                        (jit, sim_j.state()),
                    ));
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "gas cost divergence between interpreter (fast_cost_from_raw) and \
             JIT (GAS_COST_LUT) for opcodes: {mismatches:#?}"
        );
    }

    #[test]
    fn three_register_gas_roles_are_profile_scoped() {
        // div_u_64 r2 <- r0/r1; r4 <- r2/r3; r6 <- r4/r5; trap.
        // Under the standard A.5.13 roles, the 60-cycle divisions form a
        // dependency chain and the single DIV unit serialize all three. The
        // v0.8 pipeline drains in 183 cycles, hence cost 180. The
        // frozen Jar adapter deliberately preserves its old low-nibble-as-
        // destination metering, where they remain independent => cost 59.
        let code = [203, 0x10, 2, 203, 0x32, 4, 203, 0x54, 6, 0];
        let bitmask = [1, 0, 0, 1, 0, 0, 1, 0, 0, 1];

        let hand_cost = |isa_mode| {
            let mut sim = GasSimulator::new_for_mode(isa_mode);
            for pc in [0usize, 3, 6, 9] {
                let raw_a = code.get(pc + 1).copied().unwrap_or(0) & 0x0f;
                let raw_b = code.get(pc + 1).copied().unwrap_or(0) >> 4;
                let encoded_d = code.get(pc + 2).copied().unwrap_or(0);
                let raw_d = gas_raw_d(isa_mode, encoded_d);
                sim.feed(&fast_cost_from_raw(
                    code[pc],
                    raw_a,
                    raw_b,
                    raw_d,
                    pc as u32,
                    &code,
                    &bitmask,
                    DEFAULT_MEM_CYCLES,
                    isa_mode,
                ));
            }
            sim.flush_and_get_cost()
        };

        let lut_cost = |isa_mode| {
            let mut sim = GasSimulator::new_for_mode(isa_mode);
            for pc in [0usize, 3, 6, 9] {
                let raw_a = code.get(pc + 1).copied().unwrap_or(0) & 0x0f;
                let raw_b = code.get(pc + 1).copied().unwrap_or(0) >> 4;
                let encoded_d = code.get(pc + 2).copied().unwrap_or(0);
                let raw_d = gas_raw_d(isa_mode, encoded_d);
                let opcode = crate::instruction::Opcode::from_byte(code[pc]).unwrap();
                let args = crate::args::decode_args(
                    &code,
                    pc,
                    skip_distance(&bitmask, pc),
                    opcode.category(),
                );
                sim.feed(&fast_cost_lut_regs(
                    code[pc],
                    &args,
                    pc,
                    &code,
                    &bitmask,
                    raw_a,
                    raw_b,
                    raw_d,
                    DEFAULT_MEM_CYCLES,
                    isa_mode,
                ));
            }
            sim.flush_and_get_cost()
        };

        for (isa_mode, expected) in [
            (crate::IsaMode::Conformance, 180),
            (crate::IsaMode::Jar, 59),
        ] {
            assert_eq!(hand_cost(isa_mode), expected);
            assert_eq!(lut_cost(isa_mode), expected);
        }
    }

    #[test]
    fn standard_a58_operands_units_and_overlap_are_profile_scoped() {
        let code = [0u8; 8];
        let bitmask = [1u8; 8];
        let cost = |opcode, raw_a, raw_b, raw_d, mode| {
            fast_cost_from_raw(
                opcode,
                raw_a,
                raw_b,
                raw_d,
                0,
                &code,
                &bitmask,
                DEFAULT_MEM_CYCLES,
                mode,
            )
        };
        let strict = crate::IsaMode::Conformance;
        let jar = crate::IsaMode::Jar;

        // Direct operands: only rA is a register. The high nibble belongs to
        // immediate-length encoding and is not a base/source register.
        assert_eq!(cost(50, 2, 7, 0, strict).src_mask, reg_bit(2));
        assert_eq!(cost(50, 2, 7, 0, jar).src_mask, 0);
        assert_eq!(cost(52, 4, 7, 0, strict).src_mask, 0);
        assert_eq!(cost(52, 4, 7, 0, jar).src_mask, reg_bit(7));
        assert_eq!(cost(59, 4, 7, 0, strict).src_mask, reg_bit(4));
        assert_eq!(cost(59, 4, 7, 0, jar).src_mask, reg_bit(4) | reg_bit(7));

        // Standard jumps reserve no execution units; JAR retains its frozen
        // historical ALU reservation in the FastCost contract.
        for opcode in [40, 80, 50, 180] {
            assert_eq!(cost(opcode, 2, 3, 4, strict).exec_unit, EU_NONE);
            assert_eq!(cost(opcode, 2, 3, 4, jar).exec_unit, EU_ALU);
        }

        // Conditional moves read the old destination on the unmodified leg.
        assert_eq!(cost(147, 2, 3, 0, strict).src_mask, reg_bit(2) | reg_bit(3));
        assert_eq!(cost(147, 2, 3, 0, jar).src_mask, reg_bit(3));
        assert_eq!(
            cost(218, 4, 5, 2, strict).src_mask,
            reg_bit(2) | reg_bit(4) | reg_bit(5)
        );
        assert_eq!(cost(218, 4, 5, 2, jar).src_mask, reg_bit(5) | reg_bit(2));

        // ctz needs two ALUs; reverse_bytes uses P(1,2) decode width.
        assert_eq!(cost(105, 2, 3, 0, strict).exec_unit, EU_ALU2);
        assert_eq!(cost(105, 2, 3, 0, jar).exec_unit, EU_ALU);
        assert_eq!(cost(110, 2, 2, 0, strict).decode_slots, 1);
        assert_eq!(cost(110, 2, 3, 0, strict).decode_slots, 2);
        assert_eq!(cost(110, 2, 3, 0, jar).decode_slots, 1);

        // A.5.13 clamps the complete rD byte. 0x10 names r12, not r0.
        assert_eq!(cost(203, 0, 1, 0x10, strict).dst_mask, reg_bit(12));
    }

    #[test]
    fn standard_dependency_and_alu_contention_anchors() {
        let code = [0u8; 8];
        let bitmask = [1u8; 8];
        let fc = |opcode, raw_a, raw_b, raw_d| {
            fast_cost_from_raw(
                opcode,
                raw_a,
                raw_b,
                raw_d,
                0,
                &code,
                &bitmask,
                DEFAULT_MEM_CYCLES,
                crate::IsaMode::Conformance,
            )
        };
        let block = |costs: &[FastCost]| {
            let mut sim = GasSimulator::new_for_mode(crate::IsaMode::Conformance);
            for cost in costs {
                sim.feed(cost);
            }
            sim.flush_and_get_cost()
        };

        // A 60-cycle DIV writes r2. jump/store/cmov must wait for it; a
        // direct load whose length nibble happens to be 2 must not.
        let producer = fc(203, 0, 1, 2);
        assert_eq!(block(&[producer, fc(50, 2, 0, 0)]), 82);
        assert_eq!(block(&[producer, fc(59, 2, 7, 0)]), 85);
        assert_eq!(block(&[producer, fc(52, 4, 2, 0)]), 60);
        assert_eq!(block(&[producer, fc(147, 2, 3, 0)]), 62);
        assert_eq!(block(&[producer, fc(218, 4, 5, 2)]), 62);

        // Five independent ctz instructions cannot all overlap: each needs
        // two ALUs and the virtual CPU has four. Nine simulation ticks yield
        // six gas after pipeline convergence.
        let ctz = [
            fc(105, 8, 0, 0),
            fc(105, 9, 1, 0),
            fc(105, 10, 2, 0),
            fc(105, 11, 3, 0),
            fc(105, 12, 4, 0),
        ];
        assert_eq!(block(&ctz), 6);
    }

    #[test]
    fn standard_missing_operands_are_zero_extended_in_every_cost_path() {
        // A truncated two-register branch reads zeta bytes of zero. It must
        // not acquire a false dependency on r12 through a 0xff fallback.
        let code = [170u8];
        let bitmask = [1u8];
        let args = crate::args::decode_args(
            &code,
            0,
            skip_distance(&bitmask, 0),
            crate::instruction::Opcode::BranchEq.category(),
        );
        let raw = fast_cost_from_raw(
            170,
            0,
            0,
            0,
            0,
            &code,
            &bitmask,
            DEFAULT_MEM_CYCLES,
            crate::IsaMode::Conformance,
        );
        let decoded = fast_cost_from_decoded(
            170,
            &args,
            0,
            &code,
            &bitmask,
            DEFAULT_MEM_CYCLES,
            crate::IsaMode::Conformance,
        );
        let lut = fast_cost_lut(
            170,
            &args,
            0,
            &code,
            &bitmask,
            DEFAULT_MEM_CYCLES,
            crate::IsaMode::Conformance,
        );
        assert_eq!(raw.src_mask, reg_bit(0));
        assert_eq!(decoded, raw);
        assert_eq!(lut, raw);
    }

    #[test]
    fn branch_latency_equation_is_profile_scoped() {
        // Standard v0.8 reads both positions as zero-extended bytes. The Jar
        // adapter keeps its frozen target-only, in-bounds, instruction-start
        // rule. Exercise both mixed classifications and both out-of-code
        // sides directly so the two implementations cannot accidentally
        // agree on only ordinary in-code targets.
        let fallthrough_short = [81, 0, 0, 0, 2, 51];
        let fallthrough_short_mask = [1, 0, 0, 0, 1, 1];
        assert_eq!(
            branch_cost(
                &fallthrough_short,
                &fallthrough_short_mask,
                0,
                5,
                crate::IsaMode::Conformance,
            ),
            1,
        );
        assert_eq!(
            branch_cost(
                &fallthrough_short,
                &fallthrough_short_mask,
                0,
                5,
                crate::IsaMode::Jar,
            ),
            20,
        );

        let target_short = [81, 0, 0, 0, 51, 2];
        let target_short_mask = [1, 0, 0, 0, 1, 1];
        assert_eq!(
            branch_cost(
                &target_short,
                &target_short_mask,
                0,
                5,
                crate::IsaMode::Conformance,
            ),
            1,
        );
        assert_eq!(
            branch_cost(&target_short, &target_short_mask, 0, 5, crate::IsaMode::Jar,),
            1,
        );

        let out_of_code_fallthrough = [81, 0, 0, 0];
        let out_of_code_fallthrough_mask = [1, 0, 0, 0];
        assert_eq!(
            branch_cost(
                &out_of_code_fallthrough,
                &out_of_code_fallthrough_mask,
                0,
                0,
                crate::IsaMode::Conformance,
            ),
            1,
        );
        assert_eq!(
            branch_cost(
                &out_of_code_fallthrough,
                &out_of_code_fallthrough_mask,
                0,
                0,
                crate::IsaMode::Jar,
            ),
            20,
        );

        let out_of_code_target = [81, 0, 0, 0, 51];
        let out_of_code_target_mask = [1, 0, 0, 0, 1];
        assert_eq!(
            branch_cost(
                &out_of_code_target,
                &out_of_code_target_mask,
                0,
                usize::MAX,
                crate::IsaMode::Conformance,
            ),
            1,
        );
        assert_eq!(
            branch_cost(
                &out_of_code_target,
                &out_of_code_target_mask,
                0,
                usize::MAX,
                crate::IsaMode::Jar,
            ),
            20,
        );
    }

    /// Helper: compute gas cost for a single-block program using GasSimulator.
    fn block_cost(code: &[u8], bitmask: &[u8]) -> u32 {
        let mut sim = GasSimulator::new_for_mode(crate::IsaMode::Conformance);
        let mut pc = 0;
        while pc < code.len() {
            if pc < bitmask.len() && bitmask[pc] != 1 {
                pc += 1;
                continue;
            }
            let opcode_byte = code[pc];
            let raw_ra = if pc + 1 < code.len() {
                code[pc + 1] & 0x0F
            } else {
                0
            };
            let raw_rb = if pc + 1 < code.len() {
                (code[pc + 1] >> 4) & 0x0F
            } else {
                0
            };
            let raw_rd = code.get(pc + 2).copied().unwrap_or(0);
            let fc = fast_cost_from_raw(
                opcode_byte,
                raw_ra,
                raw_rb,
                raw_rd,
                pc as u32,
                code,
                bitmask,
                DEFAULT_MEM_CYCLES,
                crate::IsaMode::Conformance,
            );
            sim.feed(&fc);
            if fc.is_terminator {
                break;
            }
            let skip = skip_distance(bitmask, pc);
            pc += 1 + skip;
        }
        sim.flush_and_get_cost()
    }

    #[test]
    fn test_single_trap() {
        assert_eq!(block_cost(&[0u8], &[1u8]), 2);
    }

    #[test]
    fn test_single_ecalli() {
        assert_eq!(block_cost(&[10u8, 0], &[1, 0]), 100);
    }

    #[test]
    fn test_single_jump() {
        assert_eq!(block_cost(&[40u8, 0], &[1, 0]), 15);
    }

    #[test]
    fn test_single_fallthrough() {
        assert_eq!(block_cost(&[1u8], &[1]), 2);
    }

    #[test]
    fn test_load_imm_then_trap() {
        let cost = block_cost(&[51, 0, 42, 0], &[1, 0, 0, 1]);
        assert!(cost >= 1, "cost should be >= 1, got {cost}");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// skip_distance never exceeds 24.
        #[test]
        fn skip_distance_bounded(
            bitmask in proptest::collection::vec(0u8..=1, 1..64),
            pc in 0usize..63,
        ) {
            let dist = skip_distance(&bitmask, pc);
            prop_assert!(dist <= 24);
        }

        /// reg_bit always returns a power of two (single bit set).
        #[test]
        fn reg_bit_is_power_of_two(r in 0u8..16) {
            let bit = reg_bit(r);
            prop_assert!(bit.is_power_of_two());
        }

        /// reg_bit clamps register indices >= 13 to register 12.
        #[test]
        fn reg_bit_clamps_high_registers(r in 13u8..=15) {
            prop_assert_eq!(reg_bit(r), reg_bit(12));
        }

    }
}
