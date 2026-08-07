#![cfg(feature = "debug-internals")]

//! Negative AIR gates for the distinguished dynamic-jump HALT selectors.
//!
//! A HALT selector suppresses the ordinary JumpTable lookup. These tests
//! start from a one-step, non-HALT dynamic jump and tamper the finalized
//! CpuChip trace exactly as a malicious prover would: select HALT, pin the
//! synthetic address to `PVM_HALT_ADDR`, and solve the byte-addition chain
//! with arbitrary field-valued carries. The AIR must reject both opcode
//! forms because carries are bits, not free field elements.

use javm::PVM_REGISTER_COUNT;
use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use zkpvm::AirColumn;
use zkpvm::SideNote;
use zkpvm::chips::CpuChip;
use zkpvm::chips::cpu::Column;
use zkpvm::core::tracing::TracingPvm;
use zkpvm::framework_access::AllLookupElements;
use zkpvm::harness::MachineProverComponent;
use zkpvm::trace::component::ComponentTrace;

fn assert_chip<C: MachineProverComponent>(chip: &C, trace: &ComponentTrace, side_note: &SideNote) {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel);
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
}

/// Stwo's assertion evaluator panics before finalizing its LogupAtRow when a
/// constraint fails, whose Drop guard intentionally aborts a double-panic.
/// Run the forged trace in a subprocess: rejection is a non-success status;
/// if the carry-bit constraint is removed the child returns success and the
/// parent test fails.
fn run_forgery_child(env_key: &str, test_name: &str) -> bool {
    if std::env::var_os(env_key).is_some() {
        return true;
    }
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg(test_name)
        .env(env_key, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run forged AIR trace in child process");
    assert!(
        !status.success(),
        "SOUNDNESS GAP: forged HALT selector satisfied CpuChip"
    );
    false
}

fn find_real_row(trace: &ComponentTrace, opcode_selector: Column) -> usize {
    let selector = opcode_selector.offset();
    let padding = Column::IsPadding.offset();
    let rows = trace.original_trace[0].as_slice().len();
    (0..rows)
        .find(|&row| {
            trace.original_trace[selector].as_slice()[row] == BaseField::from(1u32)
                && trace.original_trace[padding].as_slice()[row] == BaseField::from(0u32)
        })
        .expect("dynamic-jump row")
}

fn one_step_jump_ind() -> SideNote {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 2; // jump_table[0] -> pc 3, emphatically not HALT.
    let code = vec![Opcode::JumpInd as u8, 0, 0, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![3],
        regs,
        vec![0; 4 * 1024 * 1024],
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let first = tracing.into_trace().remove(0);
    assert_eq!(first.opcode, Opcode::JumpInd);
    assert!(!first.exit);
    SideNote::new(vec![first], code, bitmask).with_jump_table(vec![3])
}

fn one_step_load_imm_jump_ind() -> SideNote {
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = 2;
    let code = vec![Opcode::LoadImmJumpInd as u8, 0x01, 0, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![3],
        regs,
        vec![0; 4 * 1024 * 1024],
        10_000,
        25,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _ = tracing.run();
    let first = tracing.into_trace().remove(0);
    assert_eq!(first.opcode, Opcode::LoadImmJumpInd);
    assert!(!first.exit);
    SideNote::new(vec![first], code, bitmask).with_jump_table(vec![3])
}

/// Forge a non-HALT dynamic-jump row into the algebraic shape that was
/// accepted before carry-bit constraints landed.
fn forge_halt_selector(
    trace: &mut ComponentTrace,
    row: usize,
    halt_selector: Column,
    addr: Column,
    carry: Column,
    input: Column,
    immediate: Column,
) {
    trace.original_trace[halt_selector.offset()].as_mut_slice()[row] = BaseField::from(1u32);
    let inv_256 = BaseField::from(256u32).inverse();
    let halt = 0xffff_0000u32.to_le_bytes();
    let mut carry_in = BaseField::from(0u32);
    let mut saw_non_bit = false;
    for (i, halt_byte) in halt.into_iter().enumerate() {
        let input_byte = trace.original_trace[input.offset() + i].as_slice()[row];
        let immediate_byte = trace.original_trace[immediate.offset() + i].as_slice()[row];
        let address_byte = BaseField::from(halt_byte as u32);
        let carry_value = (input_byte + immediate_byte + carry_in - address_byte) * inv_256;
        trace.original_trace[addr.offset() + i].as_mut_slice()[row] = address_byte;
        trace.original_trace[carry.offset() + i].as_mut_slice()[row] = carry_value;
        saw_non_bit |= carry_value != BaseField::from(0u32) && carry_value != BaseField::from(1u32);
        carry_in = carry_value;
    }
    assert!(saw_non_bit, "the forged chain must require a non-bit carry");

    // HALT's terminal convention keeps next_pc at pc. The side note has one
    // real row, so its logical successor is already padding.
    for i in 0..4 {
        let pc = trace.original_trace[Column::Pc.offset() + i].as_slice()[row];
        trace.original_trace[Column::NextPc.offset() + i].as_mut_slice()[row] = pc;
    }
}

#[test]
fn non_halt_jump_ind_cannot_forge_the_halt_selector() {
    let mut side_note = one_step_jump_ind();
    let chip = CpuChip;
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note);
    if !run_forgery_child(
        "ZKPVM_FORGE_HALT_JUMP_IND",
        "non_halt_jump_ind_cannot_forge_the_halt_selector",
    ) {
        return;
    }
    let row = find_real_row(&trace, Column::IsJumpInd);
    forge_halt_selector(
        &mut trace,
        row,
        Column::IsHaltJumpInd,
        Column::JumpIndAddr,
        Column::JumpIndCarry,
        Column::ValB,
        Column::ImmBytes,
    );
    assert_chip(&chip, &trace, &side_note);
}

#[test]
fn non_halt_load_imm_jump_ind_cannot_forge_the_halt_selector() {
    let mut side_note = one_step_load_imm_jump_ind();
    let chip = CpuChip;
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note);
    if !run_forgery_child(
        "ZKPVM_FORGE_HALT_LOAD_IMM_JUMP_IND",
        "non_halt_load_imm_jump_ind_cannot_forge_the_halt_selector",
    ) {
        return;
    }
    let row = find_real_row(&trace, Column::IsLoadImmJumpInd);
    forge_halt_selector(
        &mut trace,
        row,
        Column::IsHaltLoadImmJumpInd,
        Column::LoadImmJumpIndAddr,
        Column::LoadImmJumpIndCarry,
        Column::ValD,
        Column::ImmYBytes,
    );
    assert_chip(&chip, &trace, &side_note);
}
