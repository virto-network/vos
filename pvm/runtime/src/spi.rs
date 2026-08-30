//! Standard-PVM program loading for the executor.
//!
//! Portable byte parsing and memory layout live in `vos-pvm-program`, shared
//! with the compiler and guest agent runtimes. This module adds executor
//! opcode validation and the temporary capability-manifest adapter used by
//! the pre-agent kernel path.

use alloc::vec::Vec;

use crate::cap::Access;
use crate::instruction::Opcode;
use crate::program::{
    CapEntryType, CapManifestEntry, ParsedCodeBlob, build_blob, encode_code_blob,
};

pub use vos_pvm_program::{Region as SpiRegion, StandardLayout, StandardProgram, read_nat};

/// Cap-table slot for the standard program's CODE cap.
pub(crate) const SPI_CODE_SLOT: u8 = 64;
const SPI_RO_SLOT: u8 = 65;
const SPI_RW_SLOT: u8 = 66;
const SPI_STACK_SLOT: u8 = 67;
const SPI_ARGS_SLOT: u8 = 68;

/// `true` if `blob` begins with the retired capability-manifest magic.
///
/// This remains only while the old host kernel is being replaced by the
/// guest agent runtime.
pub fn is_jar_manifest(blob: &[u8]) -> bool {
    blob.get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        == Some(crate::program::JAR_MAGIC)
}

/// Decode the canonical compact code blob used by the standard `machine`
/// host call.
pub fn parse_compact_code_blob(data: &[u8]) -> Option<ParsedCodeBlob> {
    let code = vos_pvm_program::parse_compact_code_blob(data)?;
    Some(ParsedCodeBlob {
        jump_table: code.jump_table,
        code: code.code,
        bitmask: code.bitmask,
    })
}

/// Validate an executable code blob and its initial instruction counter.
///
/// The external counter is a full PVM register. Values outside the host's
/// index domain are invalid rather than truncated.
pub fn validate_code_blob(program: &ParsedCodeBlob, initial_pc: u64) -> bool {
    let code = &program.code;
    let bitmask = &program.bitmask;
    // Runtime counters are u32 even on a 64-bit host. Establish that domain
    // here so full Ψ remains total for arbitrarily large caller-provided
    // registers instead of relying on a later infallible conversion.
    let Ok(initial_pc) = u32::try_from(initial_pc) else {
        return false;
    };
    let initial_pc = initial_pc as usize;
    if code.is_empty()
        || bitmask.len() != code.len()
        || initial_pc >= code.len()
        || bitmask[initial_pc] != 1
        || Opcode::from_byte(code[initial_pc]).is_none()
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
pub fn deblob(data: &[u8], initial_pc: u64) -> Option<ParsedCodeBlob> {
    let program = parse_compact_code_blob(data)?;
    validate_code_blob(&program, initial_pc).then_some(program)
}

/// Parse and executor-validate a standard program.
pub fn parse_standard_program(blob: &[u8]) -> Option<StandardProgram> {
    let program = vos_pvm_program::parse_standard_program(blob)?;
    let executable = ParsedCodeBlob {
        jump_table: program.code.jump_table.clone(),
        code: program.code.code.clone(),
        bitmask: program.code.bitmask.clone(),
    };
    validate_code_blob(&executable, 0).then_some(program)
}

/// Translate a standard program into the temporary manifest representation
/// used by the old capability kernel.
pub(crate) fn to_manifest_blob(prog: &StandardProgram, args: &[u8]) -> Option<Vec<u8>> {
    let layout = prog.layout(args)?;
    let code_data = encode_code_blob(&prog.code.code, &prog.code.bitmask, &prog.code.jump_table);

    let mut data_section = Vec::new();
    data_section.extend_from_slice(&code_data);
    let ro_off = data_section.len() as u32;
    data_section.extend_from_slice(&prog.ro_data);
    let rw_off = data_section.len() as u32;
    data_section.extend_from_slice(&prog.rw_data);
    let args_off = data_section.len() as u32;
    data_section.extend_from_slice(args);

    let base_page = |addr: u64| (addr / u64::from(crate::PVM_PAGE_SIZE)) as u32;
    let page_count = |size: u64| (size / u64::from(crate::PVM_PAGE_SIZE)) as u32;
    let mut caps = alloc::vec![CapManifestEntry {
        cap_index: SPI_CODE_SLOT,
        cap_type: CapEntryType::Code,
        base_page: 0,
        page_count: 0,
        init_access: Access::RO,
        data_offset: 0,
        data_len: code_data.len() as u32,
    }];

    let mut push_region = |slot: u8, region: SpiRegion, data_off: u32, data_len: u32| {
        if region.size == 0 {
            return;
        }
        caps.push(CapManifestEntry {
            cap_index: slot,
            cap_type: CapEntryType::Data,
            base_page: base_page(region.base),
            page_count: page_count(region.size),
            init_access: if region.writable {
                Access::RW
            } else {
                Access::RO
            },
            data_offset: data_off,
            data_len,
        });
    };

    push_region(SPI_RO_SLOT, layout.ro, ro_off, prog.ro_data.len() as u32);
    push_region(SPI_RW_SLOT, layout.rw, rw_off, prog.rw_data.len() as u32);
    push_region(SPI_STACK_SLOT, layout.stack, 0, 0);
    push_region(SPI_ARGS_SLOT, layout.args, args_off, args.len() as u32);

    let memory_pages = caps
        .iter()
        .filter(|cap| cap.cap_type == CapEntryType::Data)
        .map(|cap| cap.page_count)
        .sum();
    Some(build_blob(
        memory_pages,
        SPI_CODE_SLOT,
        layout.registers[1] as u32,
        &caps,
        &data_section,
    ))
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
    fn validator_rejects_a_counter_outside_the_runtime_pc_domain() {
        let executable = ParsedCodeBlob {
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

    #[test]
    fn jar_manifest_is_detected_during_cutover() {
        let manifest = crate::program::build_simple_blob(&[0], &[1], &[]);
        assert!(is_jar_manifest(&manifest));
        let standard = standard_blob(&[], &[], 0, 0, &[0], &[1]);
        assert!(!is_jar_manifest(&standard));
    }
}
