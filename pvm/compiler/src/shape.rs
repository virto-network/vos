//! A kernel's shape: the chips of the segment AIR its code can reach, and
//! the log size of each per class of segment ([`vos_wire::records::Shape`]).
//!
//! - **The chips** come from the kernel's code alone, so a path a run does
//!   not take (an error branch's division) is still covered: every
//!   instruction's opcode selects the chips it uses, and an `ecalli` the
//!   chips of the precompile it names. The chips no segment proves without
//!   are always in: the CPU, the memory and register ledgers and their
//!   boundaries, the program's memory and boundary, the page Merkle chips
//!   and the fixed tables.
//! - **A class** is a cut: at most 2^`log_steps` steps and `pages` pages a
//!   segment. Each chip's log size is the class's capacity for it: the
//!   fixed tables' sizes, the program's code and jump table's, and for the
//!   chips whose rows a run fills, a size the cut's budgets bound or
//!   provision. A segment whose rows overflow a class proves at the next
//!   that holds it; a prover cuts it again when none does.
//!
//! The chips' order and the opcodes each serves are the segment AIR's
//! (`vos_pvm_proof::chip_idx`, its CPU's opcode classes); the prover's
//! tests hold this module to them, opcode by opcode and size by size.

use vos_pvm::instruction::{Opcode, decode_opcode_fast};
use vos_pvm::precompile::{BLAKE2B_COMPRESS, WITNESS_INPUT};
use vos_wire::records::{SegmentClass, Shape};

/// The segment AIR's chips, in its order.
pub mod chip {
    pub const CPU: usize = 0;
    pub const BLAKE2B: usize = 1;
    pub const BLAKE2B_BOUNDARY: usize = 2;
    pub const MEMORY: usize = 3;
    pub const MEMORY_PAGE: usize = 4;
    pub const MEMORY_MERKLE: usize = 5;
    pub const MEMORY_ROOT_BOUNDARY: usize = 6;
    pub const REGISTER_MEMORY: usize = 7;
    pub const REGISTER_MEMORY_BOUNDARY: usize = 8;
    pub const REGISTER_MEMORY_CLOSING: usize = 9;
    pub const PROGRAM_BOUNDARY: usize = 10;
    pub const PROGRAM_MEMORY: usize = 11;
    pub const JUMP_TABLE: usize = 12;
    pub const WITNESS_INPUT: usize = 13;
    pub const RANGE_MULTIPLICITY_256: usize = 14;
    pub const BITWISE_LOOKUP: usize = 15;
    pub const POWER_OF_TWO: usize = 16;
    pub const POPCOUNT: usize = 17;
    pub const BITCOUNT: usize = 18;
    pub const BYTE_TO_BITS: usize = 19;
    pub const MUL: usize = 20;
    pub const BITWISE: usize = 21;
    pub const COMPARE: usize = 22;
    pub const DIVREM: usize = 23;
    pub const BITWISE_AND_BYTE: usize = 24;
    /// The chips of the segment AIR.
    pub const COUNT: usize = vos_wire::records::SEGMENT_CHIPS;
}

/// The chips a code selects: the rest are in every shape.
const SELECTED: u32 = 1 << chip::BLAKE2B
    | 1 << chip::JUMP_TABLE
    | 1 << chip::WITNESS_INPUT
    | 1 << chip::POPCOUNT
    | 1 << chip::BITCOUNT
    | 1 << chip::MUL
    | 1 << chip::BITWISE
    | 1 << chip::COMPARE
    | 1 << chip::DIVREM;

/// The chips in every shape: the CPU, the ledgers, the boundaries, the
/// program's memory, the page Merkle chips and the fixed tables.
pub const ALWAYS: u32 = ((1 << chip::COUNT) - 1) & !SELECTED;

/// The version of the policy below, the classes and each chip's capacity
/// in them, that a shape's record names (`Shape::policy`): a change to
/// either derives other shapes from the same code, so it takes a new
/// version.
pub const POLICY: u32 = 1;

/// The classes a kernel's segments prove at, cheapest first, as
/// `(log_steps, pages)`: a short segment's; the 32k cut's; and a short
/// segment's with room for a whole argument written at once, as a kernel's
/// prologue reads it (at most a request's 64 KiB, 17 pages), with the pages
/// around it.
pub const CLASSES: [(u8, u16); 3] = [(12, 8), (15, 8), (12, 24)];

const _: () = assert!(CLASSES.len() <= vos_wire::records::MAX_CLASSES);

/// The rows of a SIMD lane, the least a chip has: 2^4.
const LOG_LANES: u8 = 4;

/// The chips opcode `op` uses beyond those in every shape.
pub fn opcode_chips(op: Opcode) -> u32 {
    use Opcode::*;
    match op {
        Mul64 | MulImm64 | Mul32 | MulImm32 | MulUpperUU | MulUpperSU | MulUpperSS | ShloL64
        | ShloLImm64 | ShloLImmAlt64 | ShloL32 | ShloLImm32 | ShloLImmAlt32 | RotL64 | RotL32
        | RotR64 | RotR64Imm | RotR64ImmAlt | RotR32 | RotR32Imm | RotR32ImmAlt => 1 << chip::MUL,
        DivU64 | DivU32 | DivS64 | DivS32 | RemU64 | RemU32 | RemS64 | RemS32 | ShloR64
        | ShloRImm64 | ShloRImmAlt64 | ShloR32 | ShloRImm32 | ShloRImmAlt32 | SharR64
        | SharRImm64 | SharRImmAlt64 | SharR32 | SharRImm32 | SharRImmAlt32 => 1 << chip::DIVREM,
        And | AndImm | Or | OrImm | Xor | XorImm | AndInv | OrInv | Xnor => 1 << chip::BITWISE,
        SetLtU | SetLtUImm | SetLtS | SetLtSImm | SetGtUImm | SetGtSImm | CmovIz | CmovIzImm
        | CmovNz | CmovNzImm | Min | MinU | Max | MaxU | BranchEq | BranchEqImm | BranchNe
        | BranchNeImm | BranchLtU | BranchLtUImm | BranchLtS | BranchLtSImm | BranchGeU
        | BranchGeUImm | BranchGeS | BranchGeSImm | BranchLeUImm | BranchGtUImm | BranchLeSImm
        | BranchGtSImm => 1 << chip::COMPARE,
        CountSetBits64 | CountSetBits32 => 1 << chip::POPCOUNT,
        LeadingZeroBits64 | LeadingZeroBits32 | TrailingZeroBits64 | TrailingZeroBits32 => {
            1 << chip::BITCOUNT
        }
        JumpInd | LoadImmJumpInd => 1 << chip::JUMP_TABLE,
        _ => 0,
    }
}

/// The chips host call `id` uses: a precompile's. The witness input
/// compares each call's count with its capacity.
pub fn host_call_chips(id: u64) -> u32 {
    match id {
        id if id == BLAKE2B_COMPRESS => 1 << chip::BLAKE2B,
        id if id == WITNESS_INPUT => 1 << chip::WITNESS_INPUT | 1 << chip::COMPARE,
        _ => 0,
    }
}

/// The chips `code` can reach, its instruction starts marked in `bitmask`.
pub fn code_chips(code: &[u8], bitmask: &[u8]) -> u32 {
    let mut chips = ALWAYS;
    for (pc, &byte) in code.iter().enumerate() {
        if bitmask.get(pc) != Some(&1) {
            continue;
        }
        let Some((op, category)) = decode_opcode_fast(byte) else {
            continue;
        };
        chips |= opcode_chips(op);
        if op == Opcode::Ecalli {
            let skip = vos_pvm::gas_cost::skip_distance(bitmask, pc);
            if let vos_pvm::args::Args::Imm { imm } =
                vos_pvm::args::decode_args(code, pc, skip, category)
            {
                chips |= host_call_chips(imm);
            }
        }
    }
    chips
}

/// `ceil(log2(n))`, at least a lane's: the rows a chip of `n` rows takes.
fn lanes(n: usize) -> u8 {
    (n.max(1).next_power_of_two().trailing_zeros() as u8).max(LOG_LANES)
}

/// Chip `index`'s log size in class `(log_steps, pages)`, for a code of
/// `code` bytes and a jump table of `jump_table` entries.
fn capacity(index: usize, log_steps: u8, pages: u16, code: usize, jump_table: usize) -> u8 {
    let s = log_steps;
    // The pages a segment lists: those it touches, and page 0.
    let listed = usize::from(pages) + 1;
    match index {
        chip::CPU => s,
        // 96 rows a compression.
        chip::BLAKE2B => s - 1,
        // 96 rows a compression: a listed page's leaf before and after, 64,
        // and its share of the merges above, about 8 for clustered pages.
        chip::BLAKE2B_BOUNDARY => lanes(96 * 72 * listed),
        // Each byte a step accesses, most steps fewer than eight, or each
        // byte of each listed page, before and after, whichever is more.
        chip::MEMORY => (s + 3).max(lanes(2 * 4096 * listed)),
        // 32 blocks a listed page.
        chip::MEMORY_PAGE => lanes(32 * listed),
        // At most a merge a listed page a level, 20 levels.
        chip::MEMORY_MERKLE => lanes(20 * listed),
        // At most three accesses a step, and the boundaries' 26.
        chip::REGISTER_MEMORY => s + 2,
        // A kernel's arguments, a byte a row.
        chip::WITNESS_INPUT => 16,
        // At most an entry a step.
        chip::MUL | chip::BITWISE | chip::COMPARE | chip::DIVREM => s,
        chip::PROGRAM_MEMORY => lanes(code),
        chip::JUMP_TABLE => lanes(jump_table),
        chip::MEMORY_ROOT_BOUNDARY
        | chip::REGISTER_MEMORY_BOUNDARY
        | chip::REGISTER_MEMORY_CLOSING
        | chip::PROGRAM_BOUNDARY => LOG_LANES,
        chip::POWER_OF_TWO => 6,
        chip::RANGE_MULTIPLICITY_256
        | chip::BITWISE_LOOKUP
        | chip::POPCOUNT
        | chip::BITCOUNT
        | chip::BYTE_TO_BITS => 8,
        chip::BITWISE_AND_BYTE => 16,
        _ => unreachable!("chip {index} of {}", chip::COUNT),
    }
}

/// The shape of kernel `blob`, a standard program; `None` if it is not one.
pub fn kernel_shape(blob: &[u8]) -> Option<Shape> {
    let program = vos_pvm_program::parse_standard_program(blob)?;
    let code = &program.code;
    let chips = code_chips(&code.code, &code.bitmask);
    let classes = CLASSES
        .iter()
        .map(|&(log_steps, pages)| SegmentClass {
            log_steps,
            pages,
            log_sizes: core::array::from_fn(|index| {
                if chips & 1 << index == 0 {
                    return 0;
                }
                capacity(
                    index,
                    log_steps,
                    pages,
                    code.code.len(),
                    code.jump_table.len(),
                )
            }),
        })
        .collect();
    Some(Shape {
        policy: POLICY,
        chips,
        classes,
    })
}
