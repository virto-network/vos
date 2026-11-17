//! Standard-PVM program loading for the executor.
//!
//! Portable byte parsing and memory layout live in `vos-pvm-program`, shared
//! with the compiler and guest agent runtimes. This module adds executor
//! opcode validation and the static host-call scan of a standard program.

use alloc::vec::Vec;

use crate::args::{Args, decode_args};
use crate::instruction::Opcode;

pub use vos_pvm_program::{
    CodeBlob, Region as SpiRegion, StandardLayout, StandardProgram, parse_compact_code_blob,
    read_nat,
};

/// The most code bytes a program may hold, on either backend: what every
/// validation of a code blob ([`validate_code_blob`]) and every compile
/// (`backend::compile`, `recompiler::compile_code`, `RecompiledPvm::new`)
/// refuses past, so a program's prepared tables and native code stay
/// bounded by its length and the recompiler's offsets fit an `i32` (at
/// most `recompiler::asm::INSTRUCTION` native bytes for each code byte).
pub const MAX_CODE: usize = 2 << 20;

/// `code` refused past [`MAX_CODE`] bytes: a compile's guard.
pub(crate) fn code_fits(code: &[u8]) -> Result<(), alloc::string::String> {
    if code.len() > MAX_CODE {
        return Err(alloc::format!(
            "{} bytes of code, past {MAX_CODE}",
            code.len()
        ));
    }
    Ok(())
}

/// Whether a machine of `program` may start at `pc`: an instruction's first
/// byte, with a known opcode. Runtime counters are u32 even on a 64-bit
/// host, so a larger register is no entry rather than truncated.
pub(crate) fn is_entry(program: &CodeBlob, pc: u64) -> bool {
    let Ok(pc) = u32::try_from(pc) else {
        return false;
    };
    let pc = pc as usize;
    pc < program.code.len()
        && program.bitmask.get(pc) == Some(&1)
        && Opcode::from_byte(program.code[pc]).is_some()
}

/// Validate an executable code blob and its initial instruction counter.
///
/// The external counter is a full PVM register. Values outside the host's
/// index domain are invalid rather than truncated.
pub fn validate_code_blob(program: &CodeBlob, initial_pc: u64) -> bool {
    let code = &program.code;
    let bitmask = &program.bitmask;
    if code.is_empty()
        || code.len() > MAX_CODE
        || bitmask.len() != code.len()
        || !is_entry(program, initial_pc)
    {
        return false;
    }

    let mut pc = 0usize;
    loop {
        if pc >= code.len() || bitmask[pc] != 1 {
            return false;
        }
        let Some(opcode) = Opcode::from_byte(code[pc]) else {
            return false;
        };
        let next = (1..=25)
            .map(|delta| pc + delta)
            .find(|&candidate| candidate >= code.len() || bitmask[candidate] == 1)
            .unwrap_or(pc + 25);
        if next > code.len() {
            return false;
        }
        if next == code.len() {
            return opcode.is_terminator();
        }
        pc = next;
    }
}

/// Full Gray Paper `deblob(program, initial_pc)` boundary.
///
/// This combines canonical compact decoding, whole-program validation and
/// initial-instruction validation. Callers implementing full Ψ must turn a
/// `None` result into a no-charge panic over the unchanged input state;
/// callers implementing Ω_M retain its specified `HUH` mapping.
pub fn deblob(data: &[u8], initial_pc: u64) -> Option<CodeBlob> {
    let program = parse_compact_code_blob(data)?;
    validate_code_blob(&program, initial_pc).then_some(program)
}

/// Parse and executor-validate a standard program.
pub fn parse_standard_program(blob: &[u8]) -> Option<StandardProgram> {
    let program = vos_pvm_program::parse_standard_program(blob)?;
    validate_code_blob(&program.code, 0).then_some(program)
}

/// Every statically present `ecalli` immediate, in instruction order;
/// `None` when `blob` is no executor-valid standard program.
///
/// The scan covers unreachable blocks as well as the entry-reachable graph,
/// so a call a data-dependent branch skips in one run is listed.
pub fn inspect_standard_program_host_calls(blob: &[u8]) -> Option<Vec<u64>> {
    let program = parse_standard_program(blob)?;
    let code = &program.code.code;
    let bitmask = &program.code.bitmask;
    let mut calls = Vec::new();

    for pc in 0..code.len() {
        if bitmask[pc] != 1 {
            continue;
        }
        let opcode = Opcode::from_byte(code[pc])?;
        if opcode != Opcode::Ecalli {
            continue;
        }
        let next = ((pc + 1)..code.len())
            .find(|candidate| bitmask[*candidate] == 1)
            .unwrap_or(code.len());
        let skip = next.checked_sub(pc + 1)?;
        let Args::Imm { imm } = decode_args(code, pc, skip, opcode.category()) else {
            return None;
        };
        calls.push(imm);
    }

    Some(calls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use vos_pvm_program::{CodeBlob, build_standard_program};

    fn standard_blob(
        ro: &[u8],
        rw: &[u8],
        heap_pages: u32,
        stack_size: u32,
        code: &[u8],
        bitmask: &[u8],
    ) -> Vec<u8> {
        build_standard_program(&StandardProgram {
            ro_data: ro.to_vec(),
            rw_data: rw.to_vec(),
            heap_pages,
            stack_size,
            code: CodeBlob {
                jump_table: Vec::new(),
                code: code.to_vec(),
                bitmask: bitmask.to_vec(),
            },
        })
        .unwrap()
    }

    fn host_call_program(calls: &[u32]) -> Vec<u8> {
        let mut code = Vec::new();
        let mut bitmask = Vec::new();
        for call in calls {
            code.push(Opcode::Ecalli as u8);
            bitmask.push(1);
            for byte in call.to_le_bytes() {
                code.push(byte);
                bitmask.push(0);
            }
        }
        code.push(Opcode::Trap as u8);
        bitmask.push(1);
        standard_blob(&[], &[], 0, 0, &code, &bitmask)
    }

    #[test]
    fn parser_adds_opcode_validation() {
        let valid = standard_blob(&[], &[], 0, 0, &[0], &[1]);
        assert!(parse_standard_program(&valid).is_some());
        let invalid = standard_blob(&[], &[], 0, 0, &[0xff], &[1]);
        assert!(parse_standard_program(&invalid).is_none());
        let runtime_extension = standard_blob(&[], &[], 0, 0, &[3], &[1]);
        assert!(
            parse_standard_program(&runtime_extension).is_none(),
            "opcode 3 is not in the Gray Paper v0.8.0 opcode set"
        );
        let retired_unary_number = standard_blob(&[], &[], 0, 0, &[111], &[1]);
        assert!(
            parse_standard_program(&retired_unary_number).is_none(),
            "opcode 111 is not in the Gray Paper v0.8.0 opcode set"
        );
    }

    #[test]
    fn whole_program_host_call_inspection_is_exact_and_ordered() {
        let blob = host_call_program(&[14, 9, 0x400, 0x480, 14]);
        assert_eq!(
            inspect_standard_program_host_calls(&blob),
            Some(vec![14, 9, 0x400, 0x480, 14])
        );
    }

    #[test]
    fn inspection_lists_unreachable_calls() {
        // A trap before the call makes it unreachable from entry; the scan
        // still lists its static presence.
        let code = [
            Opcode::Trap as u8,
            Opcode::Ecalli as u8,
            118,
            0,
            0,
            0,
            Opcode::Trap as u8,
        ];
        let bitmask = [1, 1, 0, 0, 0, 0, 1];
        let blob = standard_blob(&[], &[], 0, 0, &code, &bitmask);
        assert_eq!(inspect_standard_program_host_calls(&blob), Some(vec![118]));
    }

    #[test]
    fn inspection_rejects_non_programs_and_preserves_full_immediates() {
        assert_eq!(
            inspect_standard_program_host_calls(b"not a standard program"),
            None
        );
        let blob = host_call_program(&[u32::MAX]);
        assert_eq!(
            inspect_standard_program_host_calls(&blob),
            Some(vec![u64::MAX])
        );
    }

    #[test]
    fn validator_rejects_a_counter_outside_the_runtime_pc_domain() {
        let executable = CodeBlob {
            jump_table: Vec::new(),
            code: vec![0],
            bitmask: vec![1],
        };
        assert!(!validate_code_blob(&executable, u64::from(u32::MAX) + 1));
    }

    #[test]
    fn layout_places_regions_per_specification() {
        let ro = [0xaa; 40];
        let rw = [0xbb; 12];
        let blob = standard_blob(&ro, &rw, 3, 4096, &[0], &[1]);
        let program = parse_standard_program(&blob).unwrap();
        let layout = program.layout(&[0x11; 8]).unwrap();
        assert_eq!(layout.ro.base, u64::from(crate::PVM_ZONE_SIZE));
        assert!(!layout.ro.writable);
        assert!(layout.rw.writable);
        assert_eq!(layout.registers[0], crate::PVM_HALT_ADDR);
        assert_eq!(layout.registers[7], layout.args.base);
        assert_eq!(layout.registers[8], 8);
    }

    #[test]
    fn compact_parser_rejects_trailing_bytes() {
        let code = CodeBlob {
            jump_table: vec![],
            code: vec![0],
            bitmask: vec![1],
        };
        let mut bytes = vos_pvm_program::build_compact_code_blob(&code).unwrap();
        assert!(parse_compact_code_blob(&bytes).is_some());
        bytes.push(0);
        assert!(parse_compact_code_blob(&bytes).is_none());
    }
}
