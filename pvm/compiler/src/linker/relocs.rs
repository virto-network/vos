//! The relocations an ELF holds, and the address ranges they and its
//! code cover.

use std::collections::{BTreeMap, BTreeSet};

use crate::TranspileError;

use super::elf::{RELA_ENTRY, SHF_ALLOC, Sections, limits, span};

/// RISC-V relocation types we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelocType {
    /// R_RISCV_32 (1): Absolute 32-bit address
    Abs32,
    /// R_RISCV_64 (2): Absolute 64-bit address
    Abs64,
    /// R_RISCV_CALL_PLT (19): AUIPC+JALR pair for function calls
    CallPlt,
    /// R_RISCV_PCREL_HI20 (23): Upper 20 bits of PC-relative address (AUIPC)
    PcrelHi20,
    /// R_RISCV_PCREL_LO12_I (24): Lower 12 bits, I-type (load/addi)
    PcrelLo12I,
    /// R_RISCV_PCREL_LO12_S (25): Lower 12 bits, S-type (store)
    PcrelLo12S,
    /// R_RISCV_ADD32 (35): Add 32-bit (paired with SUB32 for relative jump tables)
    Add32,
    /// R_RISCV_SUB32 (39): Subtract 32-bit (paired with ADD32 for relative jump tables)
    Sub32,
}

impl RelocType {
    fn from_raw(r: u32) -> Option<Self> {
        match r {
            1 => Some(Self::Abs32),
            2 => Some(Self::Abs64),
            19 => Some(Self::CallPlt),
            23 => Some(Self::PcrelHi20),
            24 => Some(Self::PcrelLo12I),
            25 => Some(Self::PcrelLo12S),
            35 => Some(Self::Add32),
            39 => Some(Self::Sub32),
            _ => None,
        }
    }

    /// The bytes a relocation placing an address in data covers: eight for
    /// `R_RISCV_64`, four for `R_RISCV_32` and `_ADD32`.
    fn width(self) -> u8 {
        if self == Self::Abs64 { 8 } else { 4 }
    }
}

/// `R_RISCV_BRANCH` and `R_RISCV_JAL`: branches and jumps, which resolve
/// within the code as linked.
const R_RISCV_BRANCH: u32 = 16;
const R_RISCV_JAL: u32 = 17;

/// What an ELF's relocations give the linker; the names are
/// [`LinkedElf`]'s.
#[derive(Default)]
pub(super) struct Relocations {
    pub(super) count: usize,
    pub(super) unknown: Option<u32>,
    pub(super) hi20_targets: BTreeMap<u64, u64>,
    pub(super) lo12_sites: BTreeSet<u64>,
    pub(super) call_targets: BTreeMap<u64, u64>,
    pub(super) abs_code_ptrs: Vec<(u64, u64, u8)>,
    pub(super) sub32_relocs: Vec<(u64, u64)>,
    pub(super) data_relocs: Vec<(u64, u64)>,
    pub(super) symbol_refs: Vec<(u64, u64)>,
    /// The bytes relocations in data cover, merged.
    pub(super) ranges: Vec<(u64, u64)>,
}

/// Read every relocation section of `elf`, `data`'s, whose code lies in
/// `code_ranges`.
pub(super) fn relocations(
    data: &[u8],
    elf: &Sections,
    code_ranges: &[(u64, u64)],
) -> Result<Relocations, TranspileError> {
    let mut found = Relocations::default();
    // Each LO12's address, and its paired HI20's: kept once every HI20 is
    // known.
    let mut lo12_entries: Vec<(u64, u64)> = Vec::new();
    let mut ranges = Vec::new();

    for &ri in &elf.relas {
        let rs = &elf.headers[ri];
        let count = (rs.size / RELA_ENTRY as u64) as usize;
        found.count = found.count.saturating_add(count);
        if found.count > limits::RELOCATIONS {
            return Err(TranspileError::ElfParse(format!(
                "past {} relocations",
                limits::RELOCATIONS
            )));
        }
        // The section the relocations apply to: one not loaded, as debug
        // information, places no pointer in the program.
        let applies = elf
            .headers
            .get(rs.info)
            .is_some_and(|target| target.flags & SHF_ALLOC != 0);
        let table = span(data, rs.file_off, rs.size).unwrap_or(&[]);
        for entry in table.chunks_exact(RELA_ENTRY) {
            let r_offset = u64::from_le_bytes(entry[0..8].try_into().expect("eight bytes"));
            let r_info = u64::from_le_bytes(entry[8..16].try_into().expect("eight bytes"));
            let r_addend = i64::from_le_bytes(entry[16..24].try_into().expect("eight bytes"));
            let r_type = (r_info & 0xFFFFFFFF) as u32;
            let r_sym = (r_info >> 32) as usize;

            let Some(rtype) = RelocType::from_raw(r_type) else {
                if applies && !matches!(r_type, R_RISCV_BRANCH | R_RISCV_JAL) {
                    found.unknown.get_or_insert(r_type);
                }
                continue;
            };

            let sym_value = elf.values.get(r_sym).copied().unwrap_or(0);
            let target = (sym_value as i64).wrapping_add(r_addend) as u64;

            match rtype {
                RelocType::Abs32 | RelocType::Abs64 | RelocType::Add32 => {
                    let width = rtype.width();
                    ranges.push((r_offset, r_offset.saturating_add(width.into())));
                    if applies {
                        found.data_relocs.push((r_offset, target));
                        found.symbol_refs.push((r_offset, sym_value));
                    }
                    if in_ranges(code_ranges, target) {
                        found.abs_code_ptrs.push((r_offset, target, width));
                    }
                }
                RelocType::Sub32 => {
                    ranges.push((r_offset, r_offset.saturating_add(4)));
                    // The subtracted address, typically a table's base.
                    found.sub32_relocs.push((r_offset, target));
                }
                RelocType::PcrelHi20 => {
                    if applies {
                        found.symbol_refs.push((r_offset, sym_value));
                    }
                    // The resolved data or function address.
                    found.hi20_targets.insert(r_offset, target);
                }
                RelocType::CallPlt => {
                    found.call_targets.insert(r_offset, target);
                }
                // The symbol is the paired HI20 instruction.
                RelocType::PcrelLo12I | RelocType::PcrelLo12S => {
                    lo12_entries.push((r_offset, sym_value));
                }
            }
        }
    }

    found.ranges = merge_ranges(ranges);
    found.lo12_sites = lo12_entries
        .into_iter()
        .filter(|(_, hi20)| found.hi20_targets.contains_key(hi20))
        .map(|(lo12, _)| lo12)
        .collect();
    Ok(found)
}

/// Address ranges, sorted and merged where they overlap or touch: the bytes
/// relocations cover, or the code sections. Relocation metadata owns every
/// byte it covers, including the other half of an eight-byte heuristic
/// candidate and relocations to non-code addresses.
pub(crate) fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

/// The one of `ranges`, sorted and merged, holding `address`.
pub(crate) fn range_at(ranges: &[(u64, u64)], address: u64) -> Option<(u64, u64)> {
    let index = ranges.partition_point(|&(start, _)| start <= address);
    let (start, end) = *ranges.get(index.checked_sub(1)?)?;
    (address < end).then_some((start, end))
}

/// Whether `address` lies in one of `ranges`, sorted and merged.
pub(crate) fn in_ranges(ranges: &[(u64, u64)], address: u64) -> bool {
    range_at(ranges, address).is_some()
}

pub(crate) fn overlaps_data_relocation(ranges: &[(u64, u64)], address: u64, size: u8) -> bool {
    let end = address.saturating_add(u64::from(size));
    let index = ranges.partition_point(|&(start, _)| start < end);
    index != 0 && ranges[index - 1].1 > address
}
