#![cfg(feature = "debug-internals")]

//! Negative AIR gate for the jump table's padding: its padding rows hold the
//! tuple `(address 0, target 0)`, which no dynamic jump may use — a jump to
//! address 0 panics. A padding row given a multiplicity, so that a jump
//! whose address wraps to 0 continues at pc 0, is refused by
//! JumpTableChip's own constraints.

use crate::forge::*;
use stwo::core::fields::m31::BaseField;
use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::JumpTableChip;
use vos_pvm_proof::chips::jump_table::{Column, PreprocessedColumn as Preprocessed};
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::harness::MachineProverComponent;

/// `JumpInd φ0` through the table's one entry, to pc 3, then a trap.
fn side_note() -> SideNote {
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[0] = 2;
    let code = vec![Opcode::JumpInd as u8, 0, 0, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![3],
        registers,
        vec![0; 1 << 16],
        10_000,
    );
    let mut tracer = TracingPvm::new(pvm);
    let _ = tracer.run();
    SideNote::new(tracer.into_trace(), code, bitmask).with_jump_table(vec![3])
}

/// The table's last row, padding past its one entry, consumed twice, as a
/// JumpInd row's paired lookups of `(0, 0)` would.
#[test]
fn a_padding_row_is_no_entry() {
    let mut side_note = side_note();
    let chip = JumpTableChip;
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note);
    if !in_child!("a_padding_row_is_no_entry") {
        return;
    }
    // Every row but the entry's, address 2, is padding, in whichever order
    // the rows are stored.
    let address = Preprocessed::Addr.offset();
    let padding = (0..trace.preprocessed_trace[address].as_slice().len())
        .find(|&row| trace.preprocessed_trace[address].as_slice()[row] == BaseField::from(0u32))
        .expect("a padding row");
    trace.original_trace[Column::Multiplicity.offset()].as_mut_slice()[padding] =
        BaseField::from(2u32);
    assert_chip(&chip, &trace, &side_note);
}
