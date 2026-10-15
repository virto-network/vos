//! An ELF's code translated with its relocations, and the code pointers in
//! its data rewritten.

use std::collections::{BTreeSet, HashMap, HashSet};

use vos_pvm::instruction::Opcode;

use crate::TranspileError;
use crate::riscv::{self, TranslationContext, op};

use super::LinkedElf;
use super::relocs::in_ranges;
use super::targets::{raw_code_pointers, relative_target};

/// How a code pointer in data is written.
#[derive(Clone, Copy)]
enum Slot {
    /// A 64-bit address.
    Abs64,
    /// A 32-bit address.
    Abs32,
    /// A 32-bit offset from a table's base: an LLVM relative jump table's
    /// entry, which code reads as `lw off, table(idx); add target, off,
    /// base; jr target`.
    Rel32 { base: u64 },
}

/// The `len` bytes at `vaddr` in the first of `regions`, each a base
/// address and its bytes, that holds them.
fn slot_mut(regions: [(u64, &mut [u8]); 2], vaddr: u64, len: usize) -> Option<&mut [u8]> {
    regions.into_iter().find_map(|(base, data)| {
        let offset = usize::try_from(vaddr.checked_sub(base)?).ok()?;
        data.get_mut(offset..offset.checked_add(len)?)
    })
}

/// Rewrite code pointers in data sections (LLVM switch/jump tables, vtables).
///
/// Detects code pointers via:
/// 1. R_RISCV_32/64 absolute relocations targeting code sections
/// 2. R_RISCV_SUB32 relocations (relative jump table entries: value = target - table_base)
/// 3. Heuristic scan for 8-byte values in initialized data that match code addresses
///
/// Creates PVM jump table entries for each target and rewrites the data
/// so that the loaded values are valid PVM djump addresses. A target never
/// translated is left as it was, or with `pruned` given, becomes that
/// address, which no jump table reaches.
pub(super) fn rewrite_data_code_ptrs(
    elf: &LinkedElf,
    ctx: &mut TranslationContext,
    ro_data: &mut [u8],
    rw_data: &mut [u8],
    pruned: Option<u32>,
) {
    let ro_base = elf.ro_base;
    let rw_base = elf.rw_base;
    let is_code_addr = |addr: u64| -> bool { in_ranges(&elf.code_ranges, addr) };

    struct Entry {
        data_vaddr: u64,
        rv_target: u64,
        slot: Slot,
    }
    let mut entries: Vec<Entry> = Vec::new();

    // From absolute relocations (R_RISCV_32/64/ADD32).
    // If a matching SUB32 exists at the same offset, this is a relative entry
    // (ADD32/SUB32 pair for jump tables). Use the SUB32 target as table base.
    // Each address's first SUB32, as a search of them in order finds it.
    let mut bases: HashMap<u64, u64> = HashMap::with_capacity(elf.sub32_relocs.len());
    for &(vaddr, base) in &elf.sub32_relocs {
        bases.entry(vaddr).or_insert(base);
    }
    for &(vaddr, target, size) in &elf.abs_code_ptrs {
        let slot = match (size, bases.get(&vaddr)) {
            (8, _) => Slot::Abs64,
            (_, None) => Slot::Abs32,
            (_, Some(&base)) => Slot::Rel32 { base },
        };
        entries.push(Entry {
            data_vaddr: vaddr,
            rv_target: target,
            slot,
        });
    }

    // The data addresses entries already rewrite.
    let mut seen: HashSet<u64> = entries.iter().map(|entry| entry.data_vaddr).collect();
    // A SUB32 no ADD32 pairs with: its word in data is the entry.
    for &(data_vaddr, base) in &elf.sub32_relocs {
        if seen.contains(&data_vaddr) {
            continue;
        }
        if let Some(target) = relative_target(
            [(ro_base, &*ro_data), (rw_base, &*rw_data)],
            data_vaddr,
            base,
        ) && is_code_addr(target)
        {
            seen.insert(data_vaddr);
            entries.push(Entry {
                data_vaddr,
                rv_target: target,
                slot: Slot::Rel32 { base },
            });
        }
    }

    // Heuristic: 8-byte values in either initialized region that are code
    // addresses.
    for (vaddr, target) in raw_code_pointers(
        [(ro_base, &*ro_data), (rw_base, &*rw_data)],
        &elf.data_relocation_ranges,
        &elf.code_ranges,
    ) {
        if seen.insert(vaddr) {
            entries.push(Entry {
                data_vaddr: vaddr,
                rv_target: target,
                slot: Slot::Abs64,
            });
        }
    }

    if entries.is_empty() {
        return;
    }

    let targets: BTreeSet<u64> = entries.iter().map(|e| e.rv_target).collect();
    let rv_to_jt = ctx.build_function_pointer_map(&targets);

    for entry in &entries {
        let Some(jt_addr) = rv_to_jt.get(&entry.rv_target).copied().or(pruned) else {
            continue;
        };
        let (bytes, len) = match entry.slot {
            Slot::Abs64 => (u64::from(jt_addr).to_le_bytes(), 8),
            Slot::Abs32 => (u64::from(jt_addr).to_le_bytes(), 4),
            Slot::Rel32 { base } => {
                let pvm_base = ctx.address_map.get(&base).copied().unwrap_or(base as u32);
                let value = (jt_addr as i64 - pvm_base as i64) as i32;
                (i64::from(value).to_le_bytes(), 4)
            }
        };
        if let Some(slot) = slot_mut(
            [(ro_base, &mut *ro_data), (rw_base, &mut *rw_data)],
            entry.data_vaddr,
            len,
        ) {
            slot.copy_from_slice(&bytes[..len]);
        }
    }
}

/// Translate one code section. The ELF's control-flow targets are every
/// address another control-flow edge may enter.
pub(super) fn translate_section_linked(
    ctx: &mut TranslationContext,
    data: &[u8],
    base_addr: u64,
    elf: &LinkedElf,
) -> Result<(), TranspileError> {
    let targets = &elf.control_flow_targets;
    let mut offset = 0;
    while offset < data.len() {
        let rv_addr = base_addr + offset as u64;
        ctx.begin_instruction(rv_addr, targets.contains(&rv_addr))?;

        let Some(inst) = riscv::word_at(data, offset) else {
            break;
        };

        // A compressed instruction: rv64em has none.
        if inst & 0x3 != 0x3 {
            return Err(TranspileError::UnsupportedInstruction {
                offset: rv_addr as usize,
                detail: "compressed instruction in rv64em ELF".into(),
            });
        }

        if riscv::opcode(inst) == op::AUIPC {
            let rd = riscv::rd(inst);

            // CALL_PLT: an AUIPC+JALR pair calling a function.
            if let Some(&target_addr) = elf.call_targets.get(&rv_addr)
                && let Some(jalr) = riscv::word_at(data, offset + 4)
            {
                if targets.contains(&(rv_addr + 4)) {
                    return Err(TranspileError::InvalidSection(format!(
                        "control-flow target {:#x} splits a relocated AUIPC+JALR call pair at {rv_addr:#x}",
                        rv_addr + 4
                    )));
                }
                // This relocation override bypasses `translate_one`, so flush
                // any LUI/AUIPC buffered by the linear predecessor before the
                // call can transfer control. This also clears load-immediate
                // fusion state: a later consumer must not fuse backwards across
                // the emitted call and truncate its bytes.
                ctx.flush_pending()?;
                // Fused load_imm_jump: set return address and jump in one instruction
                ctx.emit_call(riscv::rd(jalr), rv_addr + 8, target_addr)?;
                ctx.address_map.insert(rv_addr + 4, ctx.code.len() as u32);
                offset += 8;
                continue;
            }

            if let Some(&target_addr) = elf.hi20_targets.get(&rv_addr) {
                // PCREL_HI20: AUIPC for data reference.
                // Peek ahead: if the next instruction is a paired LO12 ADDI (nop),
                // skip it and set pending_load_imm to enable cascading fusion
                // with the instruction after (load_ind, store_ind, ALU, branch).
                let next_addr = rv_addr + 4;
                if let Some(next_inst) = riscv::word_at(data, offset + 4)
                    && elf.lo12_sites.contains(&next_addr)
                {
                    if targets.contains(&next_addr) {
                        return Err(TranspileError::InvalidSection(
                            "control-flow target splits a relocated HI20+LO12 pair".into(),
                        ));
                    }
                    if riscv::opcode(next_inst) == op::OP_IMM
                        && riscv::funct3(next_inst) == 0
                        && riscv::rs1(next_inst) == rd
                    {
                        // LO12 ADDI: address is already complete from HI20.
                        // Load it into the ADDI's destination register,
                        // pending for cascading fusion.
                        let next_rd = riscv::rd(next_inst);
                        let dest = if next_rd != 0 { next_rd } else { rd };
                        ctx.load_address(dest, target_addr)?;
                        ctx.address_map.insert(next_addr, ctx.code.len() as u32);
                        offset += 8;
                        continue;
                    }
                }

                // No paired LO12 ADDI next — load it pending, which fuses
                // with the next load/store/ALU/branch even when the LO12 is a
                // LOAD or STORE directly.
                ctx.load_address(rd, target_addr)?;
                offset += 4;
                continue;
            }
        }

        // A PCREL_LO12 instruction's rs1 already holds the full resolved
        // address, loaded by the paired AUIPC above: its immediate is 0, and
        // a load or store goes through translate_load/translate_store to fuse
        // with the pending_load_imm the HI20 set.
        let lo12 = elf.lo12_sites.contains(&rv_addr);
        let (rd, rs1, funct3) = (riscv::rd(inst), riscv::rs1(inst), riscv::funct3(inst));
        match riscv::opcode(inst) {
            // ADDI rd, rs1, lo12 → address already loaded by HI20, reached
            // when the HI20 peek-ahead didn't consume this ADDI (e.g. a
            // non-adjacent HI20/LO12 pair).
            op::OP_IMM if lo12 && funct3 == 0 => {
                if rd != rs1 && rd != 0 {
                    let pvm_src = ctx.require_reg(rs1)?;
                    let pvm_dst = ctx.require_reg(rd)?;
                    ctx.emit_op(Opcode::MoveReg);
                    ctx.emit_data(pvm_dst | (pvm_src << 4));
                } else {
                    ctx.emit_op(Opcode::Fallthrough);
                }
            }
            // LOAD rd, lo12(rs1): with the HI20's load pending, a direct
            // load (load_* rd, addr), which saves an instruction.
            op::LOAD if lo12 => ctx.translate_load(funct3, rd, rs1, 0, rv_addr)?,
            // STORE rs2, lo12(rs1)
            op::STORE if lo12 => ctx.translate_store(funct3, rs1, riscv::rs2(inst), 0, rv_addr)?,
            _ => ctx.translate_one(inst, rv_addr)?,
        }
        offset += 4;
    }

    ctx.flush_pending()?;

    Ok(())
}
