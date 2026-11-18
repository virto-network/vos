#![cfg(feature = "debug-internals")]

//! Local constraints of the boundary chips, each refusing at the chip what
//! the claimed-sum binding alone would otherwise hold.
//!
//! - `ProgramBoundaryChip`, `RegisterMemoryBoundaryChip` and
//!   `RegisterMemoryClosingChip` hold `IsReal` boolean: a row whose `IsReal`
//!   is 2 emits its tuple twice, which the chip refuses.
//! - `MemoryPageChip` holds one closing timestamp on every row: a page
//!   closing at another timestamp than the others is refused.

use crate::forge::*;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::{
    MemoryPageChip, ProgramBoundaryChip, RegisterMemoryBoundaryChip, RegisterMemoryClosingChip,
};
use vos_pvm_proof::harness::MachineProverComponent;

/// A byte stored at `0x2_0000`, an addition and a trap: every boundary chip
/// has real rows, the page chip two pages (page 0 and the store's).
fn side_note() -> SideNote {
    use vos_pvm::instruction::Opcode;
    let memory = vec![0u8; 0x3_0000];
    let code = vec![
        Opcode::StoreIndU8 as u8,
        0x10,
        0,
        0,
        0,
        0,
        Opcode::Add64 as u8,
        0x22,
        3,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 1];
    let mut registers = [0u64; vos_pvm::PVM_REGISTER_COUNT];
    registers[0] = 5;
    registers[1] = 0x2_0000;
    let pvm = vos_pvm::interpreter::Interpreter::new(
        code,
        bitmask,
        vec![],
        registers,
        memory.clone(),
        10_000,
    );
    let mut tracer = vos_pvm_proof::core::tracing::TracingPvm::new(pvm);
    let _ = tracer.run_with_precompiles();
    let mut side_note = tracer.into_side_note().with_memory(memory);
    vos_pvm_proof::prepare_side_note_for_verification(&mut side_note);
    side_note.ingest_memory_pages();
    side_note
}

/// `chip`'s first real row with `IsReal = 2`: the honest trace holds, the
/// forged one is refused by the chip's booleanity constraint.
fn doubled_row_is_refused<C: MachineProverComponent>(chip: &C, is_real: usize, test: &str) {
    let mut side_note = side_note();
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(chip, &trace, &side_note);
    assert_eq!(get(&trace, is_real, 0), 1, "row 0 is real");
    if !crate::forge::in_child(module_path!(), test) {
        return;
    }
    set(&mut trace, is_real, 0, 2);
    assert_chip(chip, &trace, &side_note);
}

#[test]
fn the_program_boundary_s_is_real_is_boolean() {
    use vos_pvm_proof::chips::program_boundary::Column;
    doubled_row_is_refused(
        &ProgramBoundaryChip,
        Column::IsReal.offset(),
        "the_program_boundary_s_is_real_is_boolean",
    );
}

#[test]
fn the_register_boundary_s_is_real_is_boolean() {
    use vos_pvm_proof::chips::register_memory_boundary::Column;
    doubled_row_is_refused(
        &RegisterMemoryBoundaryChip,
        Column::IsReal.offset(),
        "the_register_boundary_s_is_real_is_boolean",
    );
}

#[test]
fn the_register_closing_s_is_real_is_boolean() {
    use vos_pvm_proof::chips::register_memory_closing::Column;
    doubled_row_is_refused(
        &RegisterMemoryClosingChip,
        Column::IsReal.offset(),
        "the_register_closing_s_is_real_is_boolean",
    );
}

/// The first listed page's 32 rows closing one step later than every other
/// row: its closing reads still sort last in their groups, and the page
/// chip refuses the second timestamp.
#[test]
fn every_page_closes_at_one_timestamp() {
    use vos_pvm_proof::chips::memory_page::Column as Page;
    let mut side_note = side_note();
    let chip = MemoryPageChip;
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note);
    assert_eq!(get(&trace, Page::IsReal.offset(), 32), 1, "two pages");
    if !in_child!("every_page_closes_at_one_timestamp") {
        return;
    }
    let low = Page::ClosingTs.offset();
    let closing = get(&trace, low, 0);
    for row in 0..32 {
        set(&mut trace, low, row, closing + 1);
    }
    assert_chip(&chip, &trace, &side_note);
}
