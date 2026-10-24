use super::relocs::overlaps_data_relocation;
use super::*;
use crate::riscv::rv::{addi, auipc, jal, jalr, ld, lui, sd};
use vos_pvm::{ExitReason, refine};

#[test]
fn relocation_interval_index_matches_byte_overlap() {
    let original = vec![(20, 24), (4, 8), (6, 14), (24, 28), (4, 8), (40, 48)];
    let merged = merge_ranges(original.clone());
    assert_eq!(merged, vec![(4, 14), (20, 28), (40, 48)]);
    for address in 0..56 {
        for size in 1..=8u8 {
            let expected = original
                .iter()
                .any(|&(start, end)| address < end && start < address + u64::from(size));
            assert_eq!(overlaps_data_relocation(&merged, address, size), expected);
        }
    }
    assert!(!overlaps_data_relocation(&[], 4, 8));
}

const TEXT_VADDR: u64 = 0x40_0000;
const RA: u32 = 1;
const SP: u32 = 2;
const T0: u32 = 5;
const T2: u32 = 7;
const A0: u32 = 10;
const A1: u32 = 11;
const A2: u32 = 12;

fn assemble(insts: &[u32]) -> Vec<u8> {
    insts.iter().flat_map(|inst| inst.to_le_bytes()).collect()
}

/// A linked ELF of `text` at `TEXT_VADDR`, whose code reaches twice as
/// far as `text` does: the rest pruned, as a kernel's is.
fn pruned(text: &[u8], ro_data: Vec<u8>, pointers: Vec<(u64, u64, u8)>) -> LinkedElf {
    let len = text.len() as u64;
    LinkedElf {
        ro_data,
        relocations: pointers.len(),
        abs_code_ptrs: pointers,
        code_ranges: vec![(TEXT_VADDR, TEXT_VADDR + 2 * len + 0x1000)],
        ..LinkedElf::text(TEXT_VADDR, text.to_vec())
    }
}

/// A kernel's code pointer to code it pruned becomes an address no jump
/// table reaches: jumping to it panics, never runs other code.
#[test]
fn a_pointer_into_pruned_code_cannot_be_jumped_to() {
    const T1: u32 = 6;
    let text = assemble(&[
        lui(T1, 0x10), // the pointer's address, the read-only base
        ld(T1, T1, 0), // the pointer
        jalr(RA, T1),  // call through it
        jalr(0, RA),
    ]);
    let target = TEXT_VADDR + 0x1000;
    let elf = pruned(
        &text,
        target.to_le_bytes().to_vec(),
        vec![(0x1_0000, target, 8)],
    );
    let kernel = transpile_with(&elf, Link::Kernel).expect("translates");
    assert_eq!(kernel.ro_data, u64::from(PRUNED).to_le_bytes());
    assert!(kernel.jump_table.len() * 2 < PRUNED as usize);
    let blob = spi_blob(kernel).expect("links");
    let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
    assert_eq!(invocation.exit, ExitReason::Panic);
    // Linked whole, the pointer is left as it was.
    let whole = transpile_with(&elf, Link::Whole).expect("translates");
    assert_eq!(whole.ro_data, target.to_le_bytes());
}

/// A kernel's branch to code it pruned reaches a trap, and code that
/// would fall off its end traps too.
#[test]
fn a_branch_into_pruned_code_traps() {
    let text = assemble(&[jal(0, 0x1000)]);
    let elf = pruned(&text, Vec::new(), Vec::new());
    let kernel = transpile_with(&elf, Link::Kernel).expect("translates");
    let blob = spi_blob(kernel).expect("links");
    let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
    assert_eq!(invocation.exit, ExitReason::Panic);
    let falls = pruned(&assemble(&[addi(A0, A0, 1)]), Vec::new(), Vec::new());
    let kernel = transpile_with(&falls, Link::Kernel).expect("translates");
    let blob = spi_blob(kernel).expect("links");
    let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
    assert_eq!(invocation.exit, ExitReason::Panic);
}

#[test]
fn relocated_call_flushes_pending_lui_before_transfer() {
    const LIMIT: u64 = 8192;
    const CALL_SITE: u64 = TEXT_VADDR + 8;
    const RETURN_ADDR: u64 = TEXT_VADDR + 16;
    const CALLEE: u64 = TEXT_VADDR + 32;

    // The LUI is deliberately adjacent to the relocated AUIPC+JALR pair.
    // The callee snapshots A2 before the caller can execute another normal
    // instruction. If CALL_PLT bypasses the buffered-LUI flush, it observes
    // zero instead of LIMIT (the agent-runtime bytes_bounded failure mode).
    let text = assemble(&[
        addi(T2, RA, 0),  // preserve the host return address
        lui(A2, 2),       // buffered A2 = 8192
        auipc(T0, 0),     // R_RISCV_CALL_PLT relocation lives here
        jalr(RA, T0),     // relocation override consumes this instruction
        addi(RA, T2, 0),  // restore the host return address
        addi(A0, SP, -8), // designate the callee's snapshot as output
        addi(A1, 0, 8),
        jalr(0, RA), // return to the host
        sd(A2, SP, -8),
        jalr(0, RA), // callee return
    ]);

    let mut elf = LinkedElf {
        relocations: 1,
        call_targets: BTreeMap::from([(CALL_SITE, CALLEE)]),
        ..LinkedElf::text(TEXT_VADDR, text)
    };
    elf.control_flow_targets.extend([RETURN_ADDR, CALLEE]);
    let blob = spi_blob(transpile_with(&elf, Link::Whole).expect("translates")).expect("links");
    let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");

    assert_eq!(invocation.exit, ExitReason::Halt);
    assert_eq!(
        invocation
            .output_bounded(core::mem::size_of::<u64>())
            .as_deref(),
        Some(&LIMIT.to_le_bytes()[..]),
        "the callee must observe the LUI value before control transfers"
    );
}
