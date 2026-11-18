#![no_std]

//! Portable standard-PVM program bytes and initial memory layout.
//!
//! This crate deliberately contains no executor. A compiler can emit the
//! format, a host can validate and execute it, and a guest runtime can create
//! inner machines from it through the standard PVM host calls.

extern crate alloc;

pub mod image;

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

/// A standard program's memory sizes, from the first [`Self::LEN`] bytes of
/// its blob: all its layout needs, without its data or code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardHeader {
    pub ro_size: u32,
    pub rw_size: u32,
    pub heap_pages: u32,
    pub stack_size: u32,
}

impl StandardHeader {
    /// The bytes of a blob that hold its header.
    pub const LEN: usize = 11;

    /// The header `blob` starts with.
    pub fn read(blob: &[u8]) -> Option<Self> {
        let field = |offset, width| u32::try_from(read_le(blob, offset, width)?).ok();
        Some(Self {
            ro_size: field(0, 3)?,
            rw_size: field(3, 3)?,
            heap_pages: field(6, 2)?,
            stack_size: field(8, 3)?,
        })
    }

    /// Where the standard layout places the read-only data, the read-write
    /// data with its heap, and the stack, each whole pages; `None` when
    /// they do not fit the address space beside the argument window.
    pub fn regions(&self) -> Option<[Region; 3]> {
        let ro_size = u64::from(self.ro_size);
        let stack_size = u64::from(self.stack_size);
        let ro_zone = zone_round(ro_size)?;
        let rw_total = u64::from(self.rw_size)
            .checked_add(u64::from(self.heap_pages) * u64::from(PAGE_SIZE))?;
        let total = 5u64
            .checked_mul(u64::from(ZONE_SIZE))?
            .checked_add(ro_zone)?
            .checked_add(zone_round(rw_total)?)?
            .checked_add(zone_round(stack_size)?)?
            .checked_add(u64::from(INPUT_SIZE))?;
        if total > ADDRESS_SPACE {
            return None;
        }
        let stack_top = ADDRESS_SPACE - 2 * u64::from(ZONE_SIZE) - u64::from(INPUT_SIZE);
        Some([
            Region {
                base: u64::from(ZONE_SIZE),
                size: page_round(ro_size)?,
                writable: false,
            },
            Region {
                base: 2 * u64::from(ZONE_SIZE) + ro_zone,
                size: page_round(rw_total)?,
                writable: true,
            },
            Region {
                base: stack_top.checked_sub(page_round(stack_size)?)?,
                size: page_round(stack_size)?,
                writable: true,
            },
        ])
    }
}

impl StandardProgram {
    /// Compute the initial flat-memory layout and register file.
    pub fn layout<'a>(&'a self, args: &'a [u8]) -> Option<StandardLayout<'a>> {
        let args_size = args.len() as u64;
        if args_size > u64::from(INPUT_SIZE) {
            return None;
        }
        let header = StandardHeader {
            ro_size: u32::try_from(self.ro_data.len()).ok()?,
            rw_size: u32::try_from(self.rw_data.len()).ok()?,
            heap_pages: self.heap_pages,
            stack_size: self.stack_size,
        };
        let [ro, rw, stack] = header.regions()?;
        let stack_top = stack.base + stack.size;
        let args_base = ADDRESS_SPACE - u64::from(ZONE_SIZE) - u64::from(INPUT_SIZE);
        let heap_top = rw.base.checked_add(rw.size)?;

        let mut registers = [0; REGISTER_COUNT];
        registers[0] = HALT_ADDRESS;
        registers[1] = stack_top;
        registers[7] = args_base;
        registers[8] = args_size;

        Some(StandardLayout {
            ro,
            rw,
            stack,
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

/// The `width` little-endian bytes at `offset`, `width` at most 8.
fn read_le(data: &[u8], offset: usize, width: usize) -> Option<u64> {
    debug_assert!(width <= 8, "a natural of at most eight bytes");
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

/// A jump-table entry: `width` little-endian bytes at `offset`, a natural
/// of the Gray Paper's register domain (`N_R`, below 2^64), so bytes past
/// the eighth must be zero; `None` when it is not one or the bytes are
/// missing. Every width is admitted, 0 included (then the entry is 0).
fn read_entry(data: &[u8], offset: usize, width: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(width)?)?;
    let (low, high) = bytes.split_at(width.min(8));
    if high.iter().any(|&byte| byte != 0) {
        return None;
    }
    Some(
        low.iter()
            .rev()
            .fold(0, |value, &byte| value << 8 | u64::from(byte)),
    )
}

/// Decode a compact code blob as Gray Paper v0.8.0's `deblob` reads it
/// (`pvm.tex`): `E(|j|) ⌢ E_1(z) ⌢ E(|c|) ⌢ E_z(j) ⌢ E(c) ⌢ E(k)`.
///
/// The entry width `z` is any octet, and an entry is any natural of the
/// register domain in exactly `z` bytes, leading zeroes allowed
/// (`serialization.tex`, fixed-length integer encoding). The naturals and
/// the bitmask have one encoding each, so their wider or padded forms are
/// refused. An entry at or past 2^32 decodes to `u32::MAX`: neither is a
/// basic block start of a code the host indexes with a u32, so a dynamic
/// jump through either panics alike.
///
/// One host bound departs from the text: a zero-width table, whose entries
/// take no bytes, holds at most as many entries as the blob has bytes, so
/// a few bytes cannot ask for an unbounded table.
///
/// Distinct blobs may thus decode to one [`CodeBlob`]; where one program
/// must have one blob, [`parse_canonical_standard_program`] says so.
pub fn parse_compact_code_blob(data: &[u8]) -> Option<CodeBlob> {
    let (jump_len, jump_nat_len) = read_nat(data, 0)?;
    let mut offset = jump_nat_len;
    let width = usize::from(*data.get(offset)?);
    offset += 1;
    let (code_len, code_nat_len) = read_nat(data, offset)?;
    offset = offset.checked_add(code_nat_len)?;
    let jump_len = usize::try_from(jump_len).ok()?;
    let code_len = usize::try_from(code_len).ok()?;

    // Prove that every declared item is present before reserving from an
    // attacker-controlled count. In particular, a tiny blob declaring
    // u64::MAX jump entries must fail here rather than panic in the
    // allocator.
    if width == 0 && jump_len > data.len() {
        return None;
    }
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
        let entry = read_entry(data, offset, width)?;
        jump_table.push(u32::try_from(entry).unwrap_or(u32::MAX));
        offset = offset.checked_add(width)?;
    }
    let code = copy_bytes(data.get(offset..code_end)?)?;
    offset = code_end;
    let packed = data.get(offset..)?;
    if let Some(last) = packed.last()
        && !code_len.is_multiple_of(8)
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
    let header = StandardHeader::read(blob)?;
    let (ro_size, rw_size) = (header.ro_size as usize, header.rw_size as usize);
    let (heap_pages, stack_size) = (header.heap_pages, header.stack_size);
    let mut offset = StandardHeader::LEN;
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

/// [`parse_standard_program`], refused unless `blob` is the program's one
/// encoding, [`build_standard_program`]'s: for a boundary where one program
/// has one blob, as a program whose identity is its blob's hash. A Gray
/// Paper program whose jump table is wider than its entries need parses
/// with [`parse_standard_program`] and is refused here.
pub fn parse_canonical_standard_program(blob: &[u8]) -> Option<StandardProgram> {
    let program = parse_standard_program(blob)?;
    (build_standard_program(&program)? == blob).then_some(program)
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

    /// A blob's first bytes alone place its regions as its whole layout does.
    #[test]
    fn the_header_places_the_layouts_regions() {
        let program = sample();
        let bytes = build_standard_program(&program).unwrap();
        let header = StandardHeader::read(&bytes[..StandardHeader::LEN]).unwrap();
        let layout = program.layout(&[]).unwrap();
        assert_eq!(header.regions(), Some([layout.ro, layout.rw, layout.stack]));
        assert_eq!(
            StandardHeader::read(&bytes[..StandardHeader::LEN - 1]),
            None
        );
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

    /// One trap, its jump table `entries`, each `width` bytes as given:
    /// the compact blob's raw bytes, written without the writer.
    fn raw_code(entries: &[&[u8]], width: u8) -> Vec<u8> {
        let mut bytes = vec![entries.len() as u8, width, 1];
        for entry in entries {
            assert_eq!(entry.len(), usize::from(width));
            bytes.extend_from_slice(entry);
        }
        bytes.extend_from_slice(&[0, 1]);
        bytes
    }

    fn table(bytes: &[u8]) -> Option<Vec<u32>> {
        parse_compact_code_blob(bytes).map(|code| {
            assert_eq!((code.code, code.bitmask), (vec![0], vec![1]));
            code.jump_table
        })
    }

    /// An entry in more bytes than it needs reads as its value: a width is
    /// the blob's, not the table's least.
    #[test]
    fn padded_jump_entries_read_as_their_values() {
        assert_eq!(table(&[1, 1, 1, 0, 0, 1]), Some(vec![0]));
        assert_eq!(table(&[1, 2, 1, 0, 0, 0, 1]), Some(vec![0]));
        assert_eq!(
            table(&[2, 2, 1, 1, 0, 0x34, 0x12, 0, 1]),
            Some(vec![1, 0x1234])
        );
        assert_eq!(table(&raw_code(&[&[7, 0, 0, 0]], 4)), Some(vec![7]));
    }

    /// Width 0: every entry is 0, in no bytes; with no entries any width
    /// reads.
    #[test]
    fn a_zero_width_table_holds_zeros() {
        assert_eq!(table(&[3, 0, 1, 0, 1]), Some(vec![0, 0, 0]));
        assert_eq!(table(&[0, 0, 1, 0, 1]), Some(vec![]));
        assert_eq!(table(&[0, 200, 1, 0, 1]), Some(vec![]));
        // More zero-width entries than the blob has bytes: the host's bound.
        assert_eq!(table(&[6, 0, 1, 0, 1]), None);
    }

    /// Widths 5 to 8 read a whole register; an entry past 2^32 is no block
    /// start, as `u32::MAX` is none.
    #[test]
    fn wide_entries_read_up_to_a_register() {
        for width in 5..=8u8 {
            let mut entry = vec![0u8; usize::from(width)];
            entry[0] = 9;
            assert_eq!(table(&raw_code(&[&entry], width)), Some(vec![9]), "{width}");
            entry[usize::from(width) - 1] = 1;
            assert_eq!(
                table(&raw_code(&[&entry], width)),
                Some(vec![u32::MAX]),
                "{width}: past 2^32"
            );
        }
        assert_eq!(
            table(&raw_code(&[&[0xff; 4]], 4)),
            Some(vec![u32::MAX]),
            "2^32 - 1 itself"
        );
    }

    /// Past 8 bytes an entry is a register's natural only if its bytes past
    /// the eighth are zero.
    #[test]
    fn entries_past_a_register_are_refused() {
        for width in [9u8, 16, 255] {
            let mut entry = vec![0u8; usize::from(width)];
            entry[0] = 3;
            assert_eq!(table(&raw_code(&[&entry], width)), Some(vec![3]), "{width}");
            entry[8] = 1;
            assert_eq!(table(&raw_code(&[&entry], width)), None, "{width}");
            entry[8] = 0;
            entry[usize::from(width) - 1] = 0x80;
            assert_eq!(table(&raw_code(&[&entry], width)), None, "{width}");
        }
    }

    /// The canonical reader takes the writer's bytes alone: a padded
    /// table, a zero width or a saturated entry is the same program in
    /// other bytes.
    #[test]
    fn the_canonical_reader_takes_the_writers_bytes_alone() {
        let program = |code: Vec<u8>| {
            let mut blob = vec![0; 11];
            blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
            blob.extend_from_slice(&code);
            blob
        };
        let canonical = program(vec![1, 1, 1, 0, 0, 1]);
        assert!(parse_canonical_standard_program(&canonical).is_some());
        for other in [
            vec![1, 2, 1, 0, 0, 0, 1],
            vec![1, 0, 1, 0, 1],
            raw_code(&[&[0, 0, 0, 0, 1]], 5),
            vec![0, 7, 1, 0, 1],
        ] {
            let blob = program(other);
            assert!(parse_standard_program(&blob).is_some());
            assert!(parse_canonical_standard_program(&blob).is_none());
        }
    }

    /// Every length class of a natural (GP eq C.1) round-trips at its
    /// boundaries, on both sides.
    #[test]
    fn naturals_round_trip_at_class_boundaries() {
        let cases: Vec<u64> = (1..=7u32)
            .flat_map(|l| [(1u64 << (7 * l)) - 1, 1u64 << (7 * l)])
            .chain([0, 1, (1 << 56) - 1, 1 << 56, u64::MAX])
            .collect();
        for x in cases {
            let mut buf = Vec::new();
            encode_nat(x, &mut buf);
            assert_eq!(
                read_nat(&buf, 0),
                Some((x, buf.len())),
                "round-trip failed for {x}"
            );
        }
    }

    /// Every header field, both data sections and the code survive a
    /// round trip, with a jump table wide enough for 2-byte entries and a
    /// code section long enough for a multi-byte length.
    #[test]
    fn a_long_program_with_wide_jump_entries_round_trips() {
        // 300 one-byte instructions (> 127 forces a 2-byte code length):
        // trap and fallthrough. Entries above 0xFF force 2-byte entries.
        let code: Vec<u8> = (0..300).map(|i| (i % 2) as u8).collect();
        let program = StandardProgram {
            ro_data: (0..300u32).map(|i| i as u8).collect(),
            rw_data: vec![0xbb; 77],
            heap_pages: 3,
            stack_size: 8192,
            code: CodeBlob {
                jump_table: (0..40).map(|i| 10 + i * 12).collect(),
                bitmask: vec![1; code.len()],
                code,
            },
        };
        let bytes = build_standard_program(&program).unwrap();
        assert_eq!(parse_standard_program(&bytes), Some(program));
    }

    /// No data, no jump table, one instruction.
    #[test]
    fn empty_sections_round_trip() {
        let program = StandardProgram {
            ro_data: Vec::new(),
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: 0,
            code: CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        };
        let bytes = build_standard_program(&program).unwrap();
        assert_eq!(parse_standard_program(&bytes), Some(program));
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
