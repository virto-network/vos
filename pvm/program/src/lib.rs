#![no_std]

//! Portable standard-PVM program bytes and initial memory layout.
//!
//! This crate deliberately contains no executor. A compiler can emit the
//! format, a host can validate and execute it, and a guest runtime can create
//! inner machines from it through the standard PVM host calls.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

pub const PAGE_SIZE: u32 = 1 << 12;
pub const ZONE_SIZE: u32 = 1 << 16;
pub const INPUT_SIZE: u32 = 1 << 24;
pub const REGISTER_COUNT: usize = 13;
pub const HALT_ADDRESS: u64 = (1 << 32) - (1 << 16);

const ADDRESS_SPACE: u64 = 1 << 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBlob {
    pub jump_table: Vec<u32>,
    pub code: Vec<u8>,
    /// One byte per code byte. Instruction starts are `1`.
    pub bitmask: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardProgram {
    pub ro_data: Vec<u8>,
    pub rw_data: Vec<u8>,
    pub heap_pages: u32,
    pub stack_size: u32,
    pub code: CodeBlob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    pub writable: bool,
}

#[derive(Debug, Clone)]
pub struct StandardLayout<'a> {
    pub ro: Region,
    pub rw: Region,
    pub stack: Region,
    pub args: Region,
    pub ro_data: &'a [u8],
    pub rw_data: &'a [u8],
    pub args_data: &'a [u8],
    pub heap_top: u64,
    pub registers: [u64; REGISTER_COUNT],
}

fn page_round(value: u64) -> Option<u64> {
    value
        .checked_add(u64::from(PAGE_SIZE) - 1)
        .map(|rounded| rounded / u64::from(PAGE_SIZE) * u64::from(PAGE_SIZE))
}

fn zone_round(value: u64) -> Option<u64> {
    value
        .checked_add(u64::from(ZONE_SIZE) - 1)
        .map(|rounded| rounded / u64::from(ZONE_SIZE) * u64::from(ZONE_SIZE))
}

impl StandardProgram {
    /// Compute the initial flat-memory layout and register file.
    pub fn layout<'a>(&'a self, args: &'a [u8]) -> Option<StandardLayout<'a>> {
        let ro_size = self.ro_data.len() as u64;
        let rw_size = self.rw_data.len() as u64;
        let stack_size = u64::from(self.stack_size);
        let args_size = args.len() as u64;
        if args_size > u64::from(INPUT_SIZE) {
            return None;
        }

        let ro_zone = zone_round(ro_size)?;
        let rw_total = rw_size.checked_add(u64::from(self.heap_pages) * u64::from(PAGE_SIZE))?;
        let rw_zone = zone_round(rw_total)?;
        let stack_zone = zone_round(stack_size)?;
        let total = 5u64
            .checked_mul(u64::from(ZONE_SIZE))?
            .checked_add(ro_zone)?
            .checked_add(rw_zone)?
            .checked_add(stack_zone)?
            .checked_add(u64::from(INPUT_SIZE))?;
        if total > ADDRESS_SPACE {
            return None;
        }

        let ro_base = u64::from(ZONE_SIZE);
        let rw_base = 2 * u64::from(ZONE_SIZE) + ro_zone;
        let stack_top = ADDRESS_SPACE - 2 * u64::from(ZONE_SIZE) - u64::from(INPUT_SIZE);
        let stack_bottom = stack_top.checked_sub(page_round(stack_size)?)?;
        let args_base = ADDRESS_SPACE - u64::from(ZONE_SIZE) - u64::from(INPUT_SIZE);
        let heap_top = rw_base.checked_add(page_round(rw_total)?)?;

        let mut registers = [0; REGISTER_COUNT];
        registers[0] = HALT_ADDRESS;
        registers[1] = stack_top;
        registers[7] = args_base;
        registers[8] = args_size;

        Some(StandardLayout {
            ro: Region {
                base: ro_base,
                size: page_round(ro_size)?,
                writable: false,
            },
            rw: Region {
                base: rw_base,
                size: page_round(rw_total)?,
                writable: true,
            },
            stack: Region {
                base: stack_bottom,
                size: page_round(stack_size)?,
                writable: true,
            },
            args: Region {
                base: args_base,
                size: page_round(args_size)?,
                writable: false,
            },
            ro_data: &self.ro_data,
            rw_data: &self.rw_data,
            args_data: args,
            heap_top,
            registers,
        })
    }

    /// Re-encode the program's executable portion for the `machine` host call.
    pub fn compact_code(&self) -> Option<Vec<u8>> {
        build_compact_code_blob(&self.code)
    }
}

/// Decode a standard variable-length natural at `offset`.
pub fn read_nat(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let header = *data.get(offset)?;
    let length = header.leading_ones() as usize;
    let (value, consumed) = if length == 0 {
        (u64::from(header), 1)
    } else if length >= 8 {
        let bytes = data.get(offset + 1..offset + 9)?;
        (u64::from_le_bytes(bytes.try_into().ok()?), 9)
    } else {
        let bytes = data.get(offset + 1..offset + 1 + length)?;
        let mut low = 0u64;
        for (index, byte) in bytes.iter().copied().enumerate() {
            low |= u64::from(byte) << (8 * index);
        }
        let top = u64::from(header) & ((1u64 << (8 - length)) - 1);
        (low | (top << (8 * length)), 1 + length)
    };

    // The wire has exactly one representation for each natural. Rejecting a
    // wider-than-necessary length class prevents distinct program bytes from
    // decoding to the same executable image.
    let canonical_length = (0usize..8)
        .find(|candidate| value < 1u64 << (7 * (*candidate as u32 + 1)))
        .unwrap_or(8);
    (length == canonical_length).then_some((value, consumed))
}

/// Encode a standard variable-length natural.
pub fn encode_nat(value: u64, output: &mut Vec<u8>) {
    let length = (0u8..8).find(|length| value < 1u64 << (7 * (u32::from(*length) + 1)));
    match length {
        Some(0) => output.push(value as u8),
        Some(length) => {
            output.push((256u64 - (256u64 >> length) + (value >> (8 * u32::from(length)))) as u8);
            output.extend_from_slice(&value.to_le_bytes()[..usize::from(length)]);
        }
        None => {
            output.push(0xff);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn read_le(data: &[u8], offset: usize, width: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(width)?)?;
    let mut value = 0u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        value |= u64::from(byte) << (8 * index);
    }
    Some(value)
}

fn entry_size(jump_table: &[u32]) -> u8 {
    match jump_table.iter().copied().max().unwrap_or(0) {
        0..=0xff => 1,
        0x100..=0xffff => 2,
        0x1_0000..=0xff_ffff => 3,
        _ => 4,
    }
}

fn pack_bitmask(bitmask: &[u8]) -> Vec<u8> {
    let mut packed = vec![0; bitmask.len().div_ceil(8)];
    for (index, bit) in bitmask.iter().copied().enumerate() {
        if bit != 0 {
            packed[index / 8] |= 1 << (index % 8);
        }
    }
    packed
}

fn copy_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    output.try_reserve_exact(bytes.len()).ok()?;
    output.extend_from_slice(bytes);
    Some(output)
}

pub fn parse_compact_code_blob(data: &[u8]) -> Option<CodeBlob> {
    let (jump_len, jump_nat_len) = read_nat(data, 0)?;
    let mut offset = jump_nat_len;
    let width = usize::from(*data.get(offset)?);
    offset += 1;
    if !(1..=4).contains(&width) {
        return None;
    }
    let (code_len, code_nat_len) = read_nat(data, offset)?;
    offset = offset.checked_add(code_nat_len)?;
    let jump_len = usize::try_from(jump_len).ok()?;
    let code_len = usize::try_from(code_len).ok()?;

    // Prove that every declared item is present before reserving from an
    // attacker-controlled count. In particular, a tiny blob declaring
    // u64::MAX jump entries must fail here rather than panic in the allocator.
    let jump_bytes = jump_len.checked_mul(width)?;
    let jump_end = offset.checked_add(jump_bytes)?;
    let code_end = jump_end.checked_add(code_len)?;
    let packed_len = code_len.div_ceil(8);
    let packed_end = code_end.checked_add(packed_len)?;
    if packed_end != data.len() {
        return None;
    }

    let mut jump_table = Vec::new();
    jump_table.try_reserve_exact(jump_len).ok()?;
    for _ in 0..jump_len {
        jump_table.push(u32::try_from(read_le(data, offset, width)?).ok()?);
        offset = offset.checked_add(width)?;
    }
    if usize::from(entry_size(&jump_table)) != width {
        return None;
    }
    let code = copy_bytes(data.get(offset..code_end)?)?;
    offset = code_end;
    let packed = data.get(offset..)?;
    if let Some(last) = packed.last()
        && code_len % 8 != 0
        && last & !((1u8 << (code_len % 8)) - 1) != 0
    {
        return None;
    }
    let mut bitmask = Vec::new();
    bitmask.try_reserve_exact(code_len).ok()?;
    bitmask.resize(code_len, 0);
    for index in 0..code_len {
        bitmask[index] = (packed[index / 8] >> (index % 8)) & 1;
    }

    Some(CodeBlob {
        jump_table,
        code,
        bitmask,
    })
}

pub fn build_compact_code_blob(code: &CodeBlob) -> Option<Vec<u8>> {
    if code.code.len() != code.bitmask.len() {
        return None;
    }
    let width = entry_size(&code.jump_table);
    let mut output = Vec::new();
    encode_nat(code.jump_table.len() as u64, &mut output);
    output.push(width);
    encode_nat(code.code.len() as u64, &mut output);
    for entry in &code.jump_table {
        output.extend_from_slice(&entry.to_le_bytes()[..usize::from(width)]);
    }
    output.extend_from_slice(&code.code);
    output.extend_from_slice(&pack_bitmask(&code.bitmask));
    Some(output)
}

pub fn parse_standard_program(blob: &[u8]) -> Option<StandardProgram> {
    if blob.len() < 15 {
        return None;
    }
    let ro_size = usize::try_from(read_le(blob, 0, 3)?).ok()?;
    let rw_size = usize::try_from(read_le(blob, 3, 3)?).ok()?;
    let heap_pages = u32::try_from(read_le(blob, 6, 2)?).ok()?;
    let stack_size = u32::try_from(read_le(blob, 8, 3)?).ok()?;
    let mut offset = 11usize;
    let ro_end = offset.checked_add(ro_size)?;
    let ro_data = copy_bytes(blob.get(offset..ro_end)?)?;
    offset = ro_end;
    let rw_end = offset.checked_add(rw_size)?;
    let rw_data = copy_bytes(blob.get(offset..rw_end)?)?;
    offset = rw_end;
    let code_len = usize::try_from(read_le(blob, offset, 4)?).ok()?;
    offset = offset.checked_add(4)?;
    let code_end = offset.checked_add(code_len)?;
    if code_end != blob.len() {
        return None;
    }
    let code = parse_compact_code_blob(blob.get(offset..code_end)?)?;
    Some(StandardProgram {
        ro_data,
        rw_data,
        heap_pages,
        stack_size,
        code,
    })
}

pub fn build_standard_program(program: &StandardProgram) -> Option<Vec<u8>> {
    if program.ro_data.len() >= 1 << 24
        || program.rw_data.len() >= 1 << 24
        || program.stack_size >= 1 << 24
        || program.heap_pages > u32::from(u16::MAX)
    {
        return None;
    }
    let code = build_compact_code_blob(&program.code)?;
    let code_len = u32::try_from(code.len()).ok()?;
    let mut output = Vec::with_capacity(
        15usize
            .checked_add(program.ro_data.len())?
            .checked_add(program.rw_data.len())?
            .checked_add(code.len())?,
    );
    output.extend_from_slice(&(program.ro_data.len() as u32).to_le_bytes()[..3]);
    output.extend_from_slice(&(program.rw_data.len() as u32).to_le_bytes()[..3]);
    output.extend_from_slice(&(program.heap_pages as u16).to_le_bytes());
    output.extend_from_slice(&program.stack_size.to_le_bytes()[..3]);
    output.extend_from_slice(&program.ro_data);
    output.extend_from_slice(&program.rw_data);
    output.extend_from_slice(&code_len.to_le_bytes());
    output.extend_from_slice(&code);
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> StandardProgram {
        StandardProgram {
            ro_data: (0..=255).collect(),
            rw_data: vec![0xbb; 77],
            heap_pages: 3,
            stack_size: 8192,
            code: CodeBlob {
                jump_table: vec![0, 300, 70_000],
                code: vec![0, 1, 2],
                bitmask: vec![1, 1, 1],
            },
        }
    }

    #[test]
    fn complete_program_round_trips() {
        let program = sample();
        let bytes = build_standard_program(&program).unwrap();
        assert_eq!(parse_standard_program(&bytes), Some(program));
    }

    #[test]
    fn layout_matches_standard_addresses() {
        let program = sample();
        let layout = program.layout(&[1, 2, 3]).unwrap();
        assert_eq!(layout.ro.base, u64::from(ZONE_SIZE));
        assert_eq!(layout.rw.base, 3 * u64::from(ZONE_SIZE));
        assert_eq!(layout.registers[0], HALT_ADDRESS);
        assert_eq!(layout.registers[7], layout.args.base);
        assert_eq!(layout.registers[8], 3);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = build_standard_program(&sample()).unwrap();
        bytes.push(0);
        assert!(parse_standard_program(&bytes).is_none());
    }

    #[test]
    fn obsolete_metadata_prefix_is_rejected() {
        let program = build_standard_program(&sample()).unwrap();
        let mut prefixed = vec![3, 1, 2, 3];
        prefixed.extend_from_slice(&program);
        assert!(parse_standard_program(&prefixed).is_none());
    }

    #[test]
    fn noncanonical_naturals_are_rejected() {
        assert_eq!(read_nat(&[0x80, 0x01], 0), None);
        assert_eq!(read_nat(&[0xff, 1, 0, 0, 0, 0, 0, 0, 0], 0), None);
    }

    #[test]
    fn impossible_jump_table_size_is_rejected_without_allocating() {
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.extend_from_slice(&[1, 0]);
        assert!(parse_compact_code_blob(&bytes).is_none());
    }

    #[test]
    fn unused_bitmask_bits_are_rejected() {
        let code = CodeBlob {
            jump_table: Vec::new(),
            code: vec![0],
            bitmask: vec![1],
        };
        let mut bytes = build_compact_code_blob(&code).unwrap();
        *bytes.last_mut().unwrap() |= 0x80;
        assert!(parse_compact_code_blob(&bytes).is_none());
    }

    #[test]
    fn nonminimal_jump_entry_width_is_rejected() {
        // One jump-table entry with value 1 fits in one byte. Encoding it in
        // two bytes would otherwise decode to the same CodeBlob.
        let bytes = [1, 2, 1, 1, 0, 0, 1];
        assert!(parse_compact_code_blob(&bytes).is_none());
    }

    proptest! {
        #[test]
        fn naturals_round_trip(value: u64) {
            let mut bytes = Vec::new();
            encode_nat(value, &mut bytes);
            prop_assert_eq!(read_nat(&bytes, 0), Some((value, bytes.len())));
        }
    }
}
