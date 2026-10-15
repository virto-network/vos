//! Where control may enter an ELF's code, and the code pointers its data
//! holds.

use std::collections::HashSet;

use crate::riscv::{self, decode_b_imm, decode_j_imm, op};

use super::LinkedElf;
use super::relocs::{in_ranges, overlaps_data_relocation};

/// Every statically reachable instruction address of `elf`, whose symbols'
/// values by index are `values`: its entries, its symbols in code, its
/// relocations' code targets and the returns of their calls, the code
/// pointers its data's rewrite accepts, the code an AUIPC pair names, and
/// direct branches' and jumps' targets with the returns of calls.
pub(super) fn control_flow_targets(elf: &LinkedElf, values: &[u64]) -> HashSet<u64> {
    let is_code_target = |target: u64| in_ranges(&elf.code_ranges, target);
    let mut targets = HashSet::new();
    targets.insert(elf.entry_vaddr);
    targets.extend(elf.accumulate_vaddr);
    targets.extend(
        values
            .iter()
            .copied()
            .filter(|value| is_code_target(*value)),
    );
    for (&call_site, &target) in &elf.call_targets {
        targets.insert(target);
        // CALL_PLT occupies AUIPC+JALR; execution resumes after both.
        targets.insert(call_site.wrapping_add(8));
    }
    targets.extend(elf.abs_code_ptrs.iter().map(|(_, target, _)| *target));
    targets.extend(
        elf.hi20_targets
            .values()
            .copied()
            .filter(|target| is_code_target(*target)),
    );

    // The data-pointer rewrite accepts stripped linked ELFs whose only
    // reference to a function entry is a raw pointer or an orphan SUB32 table
    // value. Collect those exact accepted targets before translating code so
    // they receive the same predecessor-fusion barrier as symbolic entries.
    let absolute: HashSet<u64> = elf
        .abs_code_ptrs
        .iter()
        .map(|(vaddr, _, _)| *vaddr)
        .collect();
    for &(data_vaddr, base) in &elf.sub32_relocs {
        if !absolute.contains(&data_vaddr)
            && let Some(target) = relative_target(elf.initialized(), data_vaddr, base)
            && is_code_target(target)
        {
            targets.insert(target);
        }
    }
    targets.extend(
        raw_code_pointers(
            elf.initialized(),
            &elf.data_relocation_ranges,
            &elf.code_ranges,
        )
        .map(|(_, target)| target),
    );

    for (_, base, code) in &elf.code_sections {
        for (index, instruction) in riscv::words(code).enumerate() {
            let address = *base + (index * 4) as u64;
            if riscv::opcode(instruction) == op::AUIPC
                && let Some(next) = riscv::word_at(code, index * 4 + 4)
            {
                let auipc_rd = riscv::rd(instruction);
                let paired = riscv::rs1(next) == auipc_rd && riscv::funct3(next) == 0;
                // A call or a jump through the AUIPC's register, or an
                // address it completes there.
                let call = riscv::opcode(next) == op::JALR;
                let address_load = riscv::opcode(next) == op::OP_IMM
                    && auipc_rd != 0
                    && riscv::rd(next) == auipc_rd;
                let target = riscv::auipc_pair_target(address, instruction, next);
                if paired && (call || address_load) && is_code_target(target) {
                    targets.insert(target);
                }
            }
            // A call returns to the instruction after it.
            if matches!(riscv::opcode(instruction), op::JAL | op::JALR)
                && riscv::rd(instruction) != 0
            {
                targets.insert(address + 4);
            }
        }
    }
    targets.extend(direct_targets(&elf.code_sections));
    targets
}

/// What the SUB32 slot at `vaddr` names, read in the first of `regions`
/// that holds it: `base` plus the signed word there.
pub(super) fn relative_target(regions: [(u64, &[u8]); 2], vaddr: u64, base: u64) -> Option<u64> {
    let bytes = regions.into_iter().find_map(|(start, data)| {
        let offset = usize::try_from(vaddr.checked_sub(start)?).ok()?;
        data.get(offset..offset.checked_add(4)?)
    })?;
    let relative = i32::from_le_bytes(bytes.try_into().expect("four bytes"));
    Some((base as i64).wrapping_add(i64::from(relative)) as u64)
}

/// The eight-byte words of `regions`, each a base address and its bytes,
/// that no relocation (`covered`) defines and that hold an address in
/// `code`: where each lies, and that address. Relocations normally name
/// these; the scan also supports stripped-but-still-linked inputs.
pub(crate) fn raw_code_pointers<'a>(
    regions: impl IntoIterator<Item = (u64, &'a [u8])> + 'a,
    covered: &'a [(u64, u64)],
    code: &'a [(u64, u64)],
) -> impl Iterator<Item = (u64, u64)> + 'a {
    regions.into_iter().flat_map(move |(base, data)| {
        data.chunks_exact(8)
            .enumerate()
            .filter_map(move |(index, bytes)| {
                let at = base + index as u64 * 8;
                let target = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
                (!overlaps_data_relocation(covered, at, 8) && in_ranges(code, target))
                    .then_some((at, target))
            })
    })
}

/// Addresses that direct branches and jumps in `code_sections` reach.
/// Translation must not carry fusion state into them: an incoming edge
/// brings its own registers.
pub(crate) fn direct_targets(
    code_sections: &[(u64, u64, Vec<u8>)],
) -> impl Iterator<Item = u64> + '_ {
    code_sections.iter().flat_map(|(_, base, data)| {
        riscv::words(data)
            .enumerate()
            .filter_map(move |(index, inst)| {
                let offset = match riscv::opcode(inst) {
                    op::BRANCH => decode_b_imm(inst),
                    op::JAL => decode_j_imm(inst),
                    _ => return None,
                };
                let address = base + 4 * index as u64;
                Some(address.wrapping_add_signed(i64::from(offset)))
            })
    })
}
