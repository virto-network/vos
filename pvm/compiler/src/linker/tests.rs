use super::relocs::overlaps_data_relocation;
use super::*;
use crate::riscv::rv::{add, addi, auipc, jal, jalr, ld, lui, sd, sub};
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

/// A kernel's code address it pruned, named by an immediate and by data,
/// is one value in both: the entry the immediate took.
#[test]
fn a_pruned_address_is_one_value_from_code_and_data() {
    const T1: u32 = 6;
    let text = assemble(&[
        auipc(T0, 0),        //  0
        addi(T0, T0, 0x100), //  4: t0 = the pruned address, an immediate
        lui(T1, 0x10),       //  8: the pointer's address, the read-only base
        ld(T1, T1, 0),       // 12: t1 = the same address, from data
        sub(A0, T0, T1),     // 16: zero iff equal
        jalr(0, RA),         // 20
    ]);
    let target = TEXT_VADDR + 0x100;
    let elf = pruned(
        &text,
        target.to_le_bytes().to_vec(),
        vec![(0x1_0000, target, 8)],
    );
    let kernel = transpile_with(&elf, Link::Kernel).expect("translates");
    assert_ne!(kernel.ro_data, u64::from(PRUNED).to_le_bytes());
    let blob = spi_blob(kernel).expect("links");
    let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
    assert_eq!(invocation.exit, ExitReason::Halt);
    assert_eq!(invocation.registers[7], 0, "one value from code and data");
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
    // Linked whole, the same branch reaches no code: a link error.
    assert!(matches!(
        transpile_with(&elf, Link::Whole),
        Err(TranspileError::UnresolvedTarget { target }) if target == TEXT_VADDR + 0x1000
    ));
    let falls = pruned(&assemble(&[addi(A0, A0, 1)]), Vec::new(), Vec::new());
    let kernel = transpile_with(&falls, Link::Kernel).expect("translates");
    let blob = spi_blob(kernel).expect("links");
    let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
    assert_eq!(invocation.exit, ExitReason::Panic);
}

/// A control-flow target between a relocated call pair's AUIPC and JALR,
/// which the link fuses into one instruction, would split the pair: the
/// link refuses it.
#[test]
fn a_target_splitting_a_call_pair_is_refused() {
    const CALLEE: u64 = TEXT_VADDR + 12;
    let text = assemble(&[
        auipc(T0, 0), // R_RISCV_CALL_PLT relocation lives here
        jalr(RA, T0),
        jal(0, -4), // to the pair's JALR
        jalr(0, RA),
    ]);
    let mut elf = LinkedElf {
        relocations: 1,
        call_targets: BTreeMap::from([(TEXT_VADDR, CALLEE)]),
        ..LinkedElf::text(TEXT_VADDR, text)
    };
    elf.control_flow_targets.extend([TEXT_VADDR + 4, CALLEE]);
    for link in [Link::Whole, Link::Kernel] {
        let refused = transpile_with(&elf, link).err().expect("refused");
        assert!(
            refused
                .to_string()
                .contains("splits a relocated AUIPC+JALR call pair"),
            "{refused}"
        );
    }
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

const A3: u32 = 13;
/// The read-write base, which `LinkedElf::text` links at.
const RW: u64 = 0x2_0000;

/// `text` with a PC-relative pair's HI20 at each of `hi20` naming the
/// read-write base, and each of `lo12` a LO12 site of it, run with
/// read-write data `rw`: its output, the eight bytes at `a0`.
fn run_relocated(text: Vec<u8>, hi20: &[u64], lo12: &[u64], rw: u64) -> Option<Vec<u8>> {
    let elf = LinkedElf {
        relocations: hi20.len() + lo12.len(),
        hi20_targets: hi20.iter().map(|&at| (TEXT_VADDR + at, RW)).collect(),
        lo12_sites: lo12.iter().map(|&at| TEXT_VADDR + at).collect(),
        rw_data: rw.to_le_bytes().to_vec(),
        rw_len: 8,
        ..LinkedElf::text(TEXT_VADDR, text)
    };
    let blob = spi_blob(transpile_with(&elf, Link::Whole).expect("translates")).expect("links");
    let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
    assert_eq!(invocation.exit, ExitReason::Halt);
    invocation.output_bounded(8)
}

/// A LO12 store whose value a LUI buffered just before it loads stores
/// that value, not the register's earlier one: the LUI is emitted first.
#[test]
fn a_lo12_store_stores_the_lui_before_it() {
    let text = assemble(&[
        auipc(A0, 0),   // 0: HI20, a0 = RW
        lui(A1, 0x10),  // 4: buffered, a1 = 0x10000
        sd(A1, A0, 0),  // 8: LO12, [RW] = a1
        addi(A1, 0, 8), // 12
        jalr(0, RA),    // 16
    ]);
    let output = run_relocated(text, &[0], &[8], 0);
    assert_eq!(output.as_deref(), Some(&0x1_0000u64.to_le_bytes()[..]));
}

/// A LO12 load or address into the register a LUI buffered just before it
/// keeps what the LO12 site writes: the LUI is not emitted after it.
#[test]
fn a_lo12_load_or_addi_is_not_overwritten_by_the_lui_before_it() {
    let load = assemble(&[
        auipc(A0, 0),   // 0: HI20, a0 = RW
        lui(A2, 0x5),   // 4: buffered, a2 = 0x5000
        ld(A2, A0, 0),  // 8: LO12, a2 = [RW] = 7
        sd(A2, A0, 0),  // 12
        addi(A1, 0, 8), // 16
        jalr(0, RA),    // 20
    ]);
    let output = run_relocated(load, &[0], &[8], 7);
    assert_eq!(output.as_deref(), Some(&7u64.to_le_bytes()[..]));
    let address = assemble(&[
        auipc(A0, 0),    // 0: HI20, a0 = RW
        lui(A2, 0x5),    // 4: buffered, a2 = 0x5000
        addi(A2, A0, 0), // 8: LO12, a2 = RW
        sd(A2, A0, 0),   // 12
        addi(A1, 0, 8),  // 16
        jalr(0, RA),     // 20
    ]);
    let output = run_relocated(address, &[0], &[8], 7);
    assert_eq!(output.as_deref(), Some(&RW.to_le_bytes()[..]));
}

/// A LUI buffered before a HI20's AUIPC is emitted before the AUIPC's
/// load, so a fusion that removes that load as dead keeps the LUI's.
#[test]
fn a_lui_before_a_hi20_survives_the_fusion_of_its_load() {
    let text = assemble(&[
        addi(A2, 0, 0),  // 0
        lui(A3, 0x5),    // 4: buffered, a3 = 0x5000
        auipc(A0, 0),    // 8: HI20, a0 = RW
        add(A0, A0, A2), // 12: fuses with the HI20's load
        sd(A3, A0, 0),   // 16
        addi(A1, 0, 8),  // 20
        jalr(0, RA),     // 24
    ]);
    let output = run_relocated(text, &[8], &[], 0);
    assert_eq!(output.as_deref(), Some(&0x5000u64.to_le_bytes()[..]));
}

/// `auipc a0; addi a1, a0, %pcrel_lo` writes both registers: a second LO12
/// site of the pair, which reads `a0`, finds the address there.
#[test]
fn a_lo12_addi_into_another_register_writes_the_auipcs_too() {
    let text = assemble(&[
        auipc(A0, 0),    // 0: HI20, a0 = RW
        addi(A1, A0, 0), // 4: LO12, a1 = RW
        sd(A1, A0, 0),   // 8: LO12, [RW] = a1
        addi(A1, 0, 8),  // 12
        jalr(0, RA),     // 16
    ]);
    let output = run_relocated(text, &[0], &[4, 8], 0);
    assert_eq!(output.as_deref(), Some(&RW.to_le_bytes()[..]));
}

/// A word of data equal to a code address is a code pointer only in an
/// ELF without relocations: in one with them, where every code pointer has
/// its relocation, it is plain data (a `u64` constant) and kept as it is.
#[test]
fn a_code_like_word_is_rewritten_only_without_relocations() {
    let text = assemble(&[addi(A0, A0, 0), jalr(0, RA)]);
    let word = (TEXT_VADDR + 4).to_le_bytes().to_vec();
    let elf = |relocations| LinkedElf {
        ro_data: word.clone(),
        relocations,
        ..LinkedElf::text(TEXT_VADDR, text.clone())
    };
    let relocated = transpile_with(&elf(1), Link::Whole).expect("translates");
    assert_eq!(relocated.ro_data, word, "plain data is kept");
    let unrelocated = transpile_with(&elf(0), Link::Whole).expect("translates");
    assert_ne!(unrelocated.ro_data, word, "a code pointer is rewritten");
}

/// `csrw 0x801, zero`, which marks the next ecall an `ecalli`, and `ecall`.
const MARK: u32 = crate::riscv::rv::i_type(0x73, 1, 0, 0, 0x801);
const ECALL: u32 = 0x73;

/// `text` linked whole: each `ecalli` it emits, by its ecall's address, or
/// the refusal.
fn host_calls(text: &[u32]) -> Result<Vec<(u64, u32)>, TranspileError> {
    let elf = LinkedElf::text(TEXT_VADDR, assemble(text));
    transpile_with(&elf, Link::Whole).map(|linked| linked.host_calls)
}

/// A marked ecall's id is the constant its block loads into t0, by `li`
/// whether one instruction or two.
#[test]
fn an_ecalli_takes_the_constant_its_block_loads_into_t0() {
    let calls = host_calls(&[addi(T0, 0, 0x401), MARK, ECALL, jalr(0, RA)]);
    assert_eq!(calls.unwrap(), [(TEXT_VADDR + 8, 0x401)]);
    let calls = host_calls(&[lui(T0, 1), addi(T0, T0, 1), MARK, ECALL, jalr(0, RA)]);
    assert_eq!(calls.unwrap(), [(TEXT_VADDR + 12, 0x1001)]);
}

/// A marked ecall whose t0 its block does not fix is refused, naming it:
/// t0 written after its `li`, loaded in another block, or never loaded.
/// Each was an `ecalli` of the last `li t0` translated, or of 0.
#[test]
fn an_ecalli_of_no_constant_t0_is_refused() {
    let written = [
        addi(T0, 0, 0x401),
        addi(T0, A1, 0),
        MARK,
        ECALL,
        jalr(0, RA),
    ];
    let other_block = [addi(T0, 0, 0x401), jal(0, 4), MARK, ECALL, jalr(0, RA)];
    let never = [MARK, ECALL, jalr(0, RA)];
    for (text, ecall) in [(&written[..], 12), (&other_block[..], 12), (&never[..], 4)] {
        match host_calls(text) {
            Err(TranspileError::UnsupportedInstruction { offset, detail }) => {
                assert_eq!(offset as u64, TEXT_VADDR + ecall, "{detail}");
            }
            other => panic!("{other:?}"),
        }
    }
    // A branch target between the marker and its ecall.
    let split = [addi(T0, 0, 0x401), MARK, jal(0, 4), ECALL, jalr(0, RA)];
    assert!(matches!(
        host_calls(&split),
        Err(TranspileError::UnsupportedInstruction { .. })
    ));
}

/// Encodings the target never emits are refused at their address, never
/// translated as another instruction: Zbs's `bseti` (once an SLLI) and
/// `bexti` (once an SRAI), Zba's `slli.uw` (once an SLLIW), Zbkb's `packw`
/// (once a `zext.h`), `fence.i` and a cache-block operation (once no-ops).
#[test]
fn encodings_the_target_never_emits_are_refused() {
    use crate::riscv::rv::{i_type, r_type};
    let refused = [
        i_type(0x13, 1, A0, A1, (0x14 << 5) | 3), // bseti a0, a1, 3
        i_type(0x13, 5, A0, A1, (0x24 << 5) | 3), // bexti a0, a1, 3
        i_type(0x13, 5, A0, A1, (0x35 << 5) | 3), // rev8's funct7, another shift
        i_type(0x1b, 1, A0, A1, (0x04 << 5) | 3), // slli.uw a0, a1, 3
        i_type(0x1b, 5, A0, A1, (0x01 << 5) | 3), // srliw of a sixth shift bit
        r_type(0x3b, 4, 0x04, A0, A1, A2),        // packw a0, a1, a2
        0x0000_100f,                              // fence.i
        0x0010_200f,                              // cbo.clean (a0)
        i_type(0x13, 1, A0, 0, (0x14 << 5) | 3),  // bseti a0, x0, 3
    ];
    for inst in refused {
        let text = assemble(&[addi(A0, A0, 0), inst, jalr(0, RA)]);
        let elf = LinkedElf::text(TEXT_VADDR, text);
        match transpile_with(&elf, Link::Whole) {
            Err(TranspileError::UnsupportedInstruction { offset, .. }) => {
                assert_eq!(offset as u64, TEXT_VADDR + 4, "{inst:#010x}")
            }
            other => panic!("{inst:#010x}: {:?}", other.err()),
        }
    }
    // A plain fence, which the toolchain emits, is a no-op.
    assert!(host_calls(&[0x0100_000f, jalr(0, RA)]).is_ok());
}

/// Zbb's counts of x0 are the counts of zero: `clz` and `ctz` give the
/// width, not 0.
#[test]
fn zbb_counts_of_x0_are_the_widths() {
    use crate::riscv::rv::i_type;
    for (inst, value) in [
        (i_type(0x13, 1, A0, 0, 0x600), 64), // clz a0, x0
        (i_type(0x13, 1, A0, 0, 0x601), 64), // ctz a0, x0
        (i_type(0x13, 1, A0, 0, 0x602), 0),  // cpop a0, x0
        (i_type(0x1b, 1, A0, 0, 0x600), 32), // clzw a0, x0
        (i_type(0x1b, 1, A0, 0, 0x601), 32), // ctzw a0, x0
    ] {
        let elf = LinkedElf::text(TEXT_VADDR, assemble(&[inst, jalr(0, RA)]));
        let blob = spi_blob(transpile_with(&elf, Link::Whole).expect("translates")).expect("links");
        let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.registers[7], value, "{inst:#010x}");
    }
}
