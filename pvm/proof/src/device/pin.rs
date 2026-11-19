//! The chip set a device program's code selects: pin code, computed from
//! the code alone.

use super::*;

/// The chips a device shape of `code` holds, its instruction starts marked
/// in `bitmask`: every chip it always holds, each instruction's opcode's,
/// and each precompile's an `ecalli` names. From the code alone, so a path a
/// run does not take is covered and the shape is the program's. `None` for
/// a code that names the BLAKE2b precompile: a device kernel makes no
/// BLAKE2b call (`vos_pvm::precompile::is_device_kernel_call`), its io-hash
/// and its shape hold no BLAKE2b, so no device program holds BLAKE2b's
/// chips.
pub fn device_chips_of_code(code: &[u8], bitmask: &[u8]) -> Option<u32> {
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
                    id if id == u64::from(ECALL_BLAKE2B_COMPRESS) => return None,
                    id if id == u64::from(ECALL_WITNESS_INPUT) => {
                        1 << chip_idx::WITNESS_INPUT | 1 << chip_idx::COMPARE
                    }
                    id if id == u64::from(ECALL_POSEIDON2) => 1 << chip_idx::POSEIDON2,
                    _ => 0,
                };
            }
        }
    }
    Some(chips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2};
    use vos_pvm::instruction::Opcode;

    /// `ecalli id`, then a trap.
    fn calling(id: u32) -> (Vec<u8>, Vec<u8>) {
        let mut code = vec![Opcode::Ecalli as u8];
        code.extend_from_slice(&id.to_le_bytes());
        code.push(Opcode::Trap as u8);
        (code, vec![1, 0, 0, 0, 0, 1])
    }

    /// A code naming the BLAKE2b precompile has no device shape; one naming
    /// Poseidon2's holds its chip.
    #[test]
    fn a_device_code_naming_blake2b_is_refused() {
        let (code, bitmask) = calling(ECALL_BLAKE2B_COMPRESS);
        assert_eq!(device_chips_of_code(&code, &bitmask), None);
        let (code, bitmask) = calling(ECALL_POSEIDON2);
        let chips = device_chips_of_code(&code, &bitmask).expect("a device shape");
        assert_ne!(chips & 1 << chip_idx::POSEIDON2, 0);
        assert_eq!(chips & 1 << chip_idx::BLAKE2B, 0);
    }
}
