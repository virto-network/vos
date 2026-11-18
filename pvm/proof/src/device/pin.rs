//! The chip set a device program's code selects: pin code, computed from
//! the code alone.

use super::*;

/// The chips a device shape of `code` holds, its instruction starts marked
/// in `bitmask`: every chip it always holds, each instruction's opcode's,
/// and each precompile's an `ecalli` names. From the code alone, so a path a
/// run does not take is covered and the shape is the program's.
pub fn device_chips_of_code(code: &[u8], bitmask: &[u8]) -> u32 {
    use crate::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2, ECALL_WITNESS_INPUT};
    use vos_pvm::instruction::{Opcode, decode_opcode_fast};
    let mut chips = DEVICE_ALWAYS;
    for (pc, &byte) in code.iter().enumerate() {
        if bitmask.get(pc) != Some(&1) {
            continue;
        }
        let Some((op, category)) = decode_opcode_fast(byte) else {
            continue;
        };
        chips |= crate::opcode_component_mask(op) & chip_idx::OPTIONAL;
        if op == Opcode::Ecalli {
            let skip = vos_pvm::skip(bitmask, pc);
            if let vos_pvm::args::Args::Imm { imm } =
                vos_pvm::args::decode_args(code, pc, skip, category)
            {
                chips |= match imm {
                    id if id == u64::from(ECALL_BLAKE2B_COMPRESS) => {
                        1 << chip_idx::BLAKE2B | 1 << chip_idx::BITWISE_AND_BYTE
                    }
                    id if id == u64::from(ECALL_WITNESS_INPUT) => {
                        1 << chip_idx::WITNESS_INPUT | 1 << chip_idx::COMPARE
                    }
                    id if id == u64::from(ECALL_POSEIDON2) => 1 << chip_idx::POSEIDON2,
                    _ => 0,
                };
            }
        }
    }
    chips
}
