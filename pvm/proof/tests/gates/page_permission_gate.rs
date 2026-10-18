#![cfg(feature = "debug-internals")]

//! Negative AIR gates for page permissions: a proof's run is the run on
//! its program's pages, whose permissions its program identity carries
//! (MemoryPageChip's preprocessed regions). A store to a read-only page, or
//! any access to an unmapped page, faults on the machine; its run continued
//! on a machine with that page writable is refused, and so is a page
//! claiming a region it does not lie in.

use crate::forge::*;
use stwo::core::fields::m31::BaseField;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::{Interpreter, Memory, PERM_NONE, PERM_RO, PERM_RW};
use vos_pvm::{ExitReason, PVM_REGISTER_COUNT, PVM_ZONE_SIZE};
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::MemoryPageChip;
use vos_pvm_proof::chips::memory_page::{Column as Page, MemoryLayout, PageRange};
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::harness::MachineProverComponent;
use vos_pvm_proof::trace::component::ComponentTrace;

/// A byte in the middle of page 17, above the protected low zone.
const A: u32 = PVM_ZONE_SIZE + 0x1000 + 0x800;
const PAGE: u32 = A >> 12;
const V: u8 = 0x42;

/// `StoreIndU8 φ0 → [φ1]`, `LoadIndU8 [φ1 + 8] → φ2`, a trap, with φ0 = V
/// and φ1 = A, on a machine whose page at A has `permission`.
fn machine(permission: u8) -> (Interpreter, Vec<u8>, Vec<u8>, Vec<u8>) {
    let code = vec![
        Opcode::StoreIndU8 as u8,
        0x10,
        0,
        0,
        0,
        0,
        Opcode::LoadIndU8 as u8,
        0x12,
        8,
        0,
        0,
        0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[0] = u64::from(V);
    registers[1] = u64::from(A);
    let memory = vec![0u8; 4 * 1024 * 1024];
    let mut pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        memory.clone(),
        10_000,
    );
    assert!(
        pvm.memory_mut()
            .set_page_range(PAGE as usize, 1, permission)
    );
    (pvm, code, bitmask, memory)
}

/// Every page writable but A's, which is read-only (`readable`) or
/// unmapped.
fn layout(readable: bool) -> MemoryLayout {
    let page = |first, end| PageRange { first, end };
    MemoryLayout {
        regions: [
            if readable {
                page(PAGE, PAGE + 1)
            } else {
                page(0, 0)
            },
            page(0, 0),
            page(0, PAGE),
            page(PAGE + 1, 1 << 20),
        ],
    }
}

/// The run on a machine with A's page writable, its trace with `layout`.
fn writable_run(layout: MemoryLayout) -> SideNote {
    let (pvm, code, bitmask, memory) = machine(PERM_RW);
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(tracer.run(), ExitReason::Panic);
    SideNote::new(tracer.into_trace(), code, bitmask)
        .with_memory(memory)
        .with_memory_layout(layout)
}

fn refused(mut side_note: SideNote) -> bool {
    match vos_pvm_proof::prove(&mut side_note) {
        Err(_) => true,
        Ok(proof) => vos_pvm_proof::verify(proof, &side_note).is_err(),
    }
}

/// The store faults on a read-only or unmapped page; the run on a machine
/// with the page writable, proven under the program's layout, is refused.
/// Under a layout with the page writable it proves, with another program
/// identity.
#[test]
fn a_store_to_a_read_only_page_is_refused() {
    for permission in [PERM_RO, PERM_NONE] {
        let (pvm, ..) = machine(permission);
        let mut tracer = TracingPvm::new(pvm);
        assert_eq!(tracer.run(), ExitReason::PageFault(A & !0xfff));
    }
    for readable in [true, false] {
        assert!(
            refused(writable_run(layout(readable))),
            "SOUNDNESS GAP: the run on a writable page proved (readable: {readable})"
        );
    }
    let mut side_note = writable_run(MemoryLayout::writable());
    let proof = vos_pvm_proof::prove(&mut side_note).expect("proving failed");
    vos_pvm_proof::verify(proof, &side_note).expect("verification failed");
    let regions = |layout: MemoryLayout| -> Vec<Vec<BaseField>> {
        let mut side_note = writable_run(layout);
        vos_pvm_proof::prepare_side_note_for_verification(&mut side_note);
        side_note.ingest_memory_pages();
        MemoryPageChip
            .generate_component_trace(&mut side_note)
            .preprocessed_trace
            .iter()
            .map(|column| column.as_slice().to_vec())
            .collect()
    };
    assert_ne!(
        regions(MemoryLayout::writable()),
        regions(layout(true)),
        "a layout is part of the program identity"
    );
}

/// A read of a read-only page proves: `LoadIndU8 [φ1] → φ2`.
#[test]
fn a_read_of_a_read_only_page_proves() {
    let code = vec![
        Opcode::LoadIndU8 as u8,
        0x12,
        0,
        0,
        0,
        0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[1] = u64::from(A);
    let mut memory = vec![0u8; 4 * 1024 * 1024];
    memory[A as usize] = V;
    let mut pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        memory.clone(),
        10_000,
    );
    assert!(pvm.memory_mut().set_page_range(PAGE as usize, 1, PERM_RO));
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(tracer.run(), ExitReason::Panic);
    let steps = tracer.into_trace();
    assert_eq!(steps[0].regs_after[2], u64::from(V));
    let mut side_note = SideNote::new(steps, code, bitmask)
        .with_memory(memory)
        .with_memory_layout(layout(true));
    let proof = vos_pvm_proof::prove(&mut side_note).expect("proving failed");
    vos_pvm_proof::verify(proof, &side_note).expect("verification failed");
}

fn get(trace: &ComponentTrace, offset: usize, row: usize) -> BaseField {
    trace.original_trace[offset].as_slice()[stored(trace.log_size, row)]
}

/// A's read-only page claiming the writable region below it, `[0, 17)`:
/// its distance to that region's end, `16 − 17`, is negative, and so are
/// the bits standing for it.
#[test]
fn a_page_lies_in_the_region_it_claims() {
    let mut side_note = writable_run(layout(true));
    vos_pvm_proof::prepare_side_note_for_verification(&mut side_note);
    side_note.ingest_memory_pages();
    let mut trace = MemoryPageChip.generate_component_trace(&mut side_note);
    assert_chip(&MemoryPageChip, &trace, &side_note);
    if !in_child!("a_page_lies_in_the_region_it_claims") {
        return;
    }
    let index = |trace: &ComponentTrace, row: usize| -> u32 {
        (0..20)
            .map(|bit| get(trace, Page::IdxBits.offset() + bit, row).0 << bit)
            .sum()
    };
    let rows: Vec<usize> = (0..1usize << trace.log_size)
        .filter(|&row| {
            index(&trace, row) == PAGE
                && get(&trace, Page::IsReal.offset(), row) == BaseField::from(1u32)
        })
        .collect();
    assert_eq!(rows.len(), 32, "the page's 32 blocks");
    for row in rows {
        assert_eq!(
            get(&trace, Page::RegionSelect.offset(), row),
            BaseField::from(1u32)
        );
        set(&mut trace, Page::RegionSelect.offset(), row, 0);
        set(&mut trace, Page::RegionSelect.offset() + 2, row, 1);
        set(&mut trace, Page::RegionFirstH.offset(), row, 0);
        set(&mut trace, Page::RegionEndH.offset(), row, PAGE);
        let from_first = PAGE;
        let to_end = PAGE.wrapping_sub(1).wrapping_sub(PAGE);
        for bit in 0..20 {
            set(
                &mut trace,
                Page::FromFirstBits.offset() + bit,
                row,
                (from_first >> bit) & 1,
            );
            set(
                &mut trace,
                Page::ToEndBits.offset() + bit,
                row,
                (to_end >> bit) & 1,
            );
        }
    }
    assert_chip(&MemoryPageChip, &trace, &side_note);
}

/// A load alone from an unmapped page: no store, so only the unreadable
/// rule (a group's start followed by anything but its closing read)
/// refuses it.
#[test]
fn a_load_from_an_unmapped_page_is_refused() {
    let code = vec![
        Opcode::LoadIndU8 as u8,
        0x12,
        0,
        0,
        0,
        0,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1];
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[1] = u64::from(A);
    let memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        memory.clone(),
        10_000,
    );
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(tracer.run(), ExitReason::Panic);
    let side_note = SideNote::new(tracer.into_trace(), code, bitmask)
        .with_memory(memory)
        .with_memory_layout(layout(false));
    assert!(
        refused(side_note),
        "SOUNDNESS GAP: a load from an unmapped page proved"
    );
}

/// A BLAKE2b compression whose output lands on a read-only page: the write
/// is Blake2bChip's, not CpuChip's, and the ledger refuses it all the same.
#[test]
fn a_blake2b_write_to_a_read_only_page_is_refused() {
    use vos_pvm_proof::core::tracing::ECALL_BLAKE2B_COMPRESS;
    const H: u64 = 0x2_0000;
    let memory = vec![0u8; 0x3_0000];
    let mut code = vec![Opcode::Ecalli as u8];
    code.extend_from_slice(&ECALL_BLAKE2B_COMPRESS.to_le_bytes());
    code.push(Opcode::Trap as u8);
    let mut bitmask = vec![0; code.len()];
    bitmask[0] = 1;
    bitmask[code.len() - 1] = 1;
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[7] = H;
    registers[8] = H + 64;
    registers[10] = 1;
    let pvm = Interpreter::new(code, bitmask, vec![], registers, memory.clone(), 10_000);
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(
        tracer.run_with_precompiles(),
        ExitReason::Panic,
        "the compression is served and the trap ends the run"
    );
    let h_page = (H >> 12) as u32;
    let page = |first, end| PageRange { first, end };
    let read_only_h = MemoryLayout {
        regions: [
            page(h_page, h_page + 1),
            page(0, 0),
            page(0, h_page),
            page(h_page + 1, 1 << 20),
        ],
    };
    let side_note = tracer
        .into_side_note()
        .with_initial_regs(registers)
        .with_memory(memory.clone())
        .with_memory_layout(read_only_h);
    assert!(
        refused(side_note),
        "SOUNDNESS GAP: a BLAKE2b write to a read-only page proved"
    );
}

// ── The layout is explicit ─────────────────────────────────────────────

/// A trap on a sparse memory holding one page at A, the image a kernel's
/// run starts from.
fn sparse_run() -> SideNote {
    let code = vec![Opcode::Trap as u8];
    let bitmask = vec![1];
    let mut memory = Memory::sparse(1u64 << 32);
    memory.init_copy(A, &[V]);
    let image = memory.nonzero_page_image().into();
    let pvm = Interpreter::with_memory(
        code.clone(),
        bitmask.clone(),
        vec![],
        [0; PVM_REGISTER_COUNT],
        memory,
        10_000,
    );
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(tracer.run(), ExitReason::Panic);
    SideNote::new(tracer.into_trace(), code, bitmask).with_sparse_memory(image)
}

/// A sparse image without its program's layout is neither proven nor
/// verified: its identity would make every page writable. Asked for
/// explicitly, every page writable proves.
#[test]
fn a_sparse_image_without_its_layout_is_refused() {
    let mut bare = sparse_run();
    assert_eq!(bare.memory_layout(), None);
    assert!(matches!(
        vos_pvm_proof::prove(&mut bare),
        Err(vos_pvm_proof::ProvingError::NoMemoryLayout)
    ));
    let mut side_note = sparse_run().with_memory_layout(MemoryLayout::writable());
    let proof = vos_pvm_proof::prove(&mut side_note).expect("proving failed");
    vos_pvm_proof::prepare_side_note_for_verification(&mut bare);
    assert!(vos_pvm_proof::verify(proof.clone(), &bare).is_err());
    vos_pvm_proof::verify(proof, &side_note).expect("verification failed");
}

/// Regions are disjoint, or a page in two could select the permissive one.
#[test]
fn a_layout_s_regions_are_disjoint() {
    let page = |first, end| PageRange { first, end };
    let of = |regions| MemoryLayout { regions };
    assert!(MemoryLayout::writable().is_disjoint());
    assert!(layout(true).is_disjoint());
    assert!(of([page(0, 5), page(5, 9), page(9, 9), page(3, 3)]).is_disjoint());
    assert!(!of([page(0, 5), page(4, 9), page(0, 0), page(0, 0)]).is_disjoint());
    assert!(!of([page(0, 0), page(2, 3), page(0, 0), page(0, 10)]).is_disjoint());
}

#[test]
#[should_panic(expected = "overlap")]
fn an_overlapping_layout_is_refused() {
    let page = |first, end| PageRange { first, end };
    let _ = writable_run(MemoryLayout {
        regions: [
            page(PAGE, PAGE + 1),
            page(0, 0),
            page(0, 1 << 20),
            page(0, 0),
        ],
    });
}
