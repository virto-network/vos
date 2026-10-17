#![cfg(feature = "debug-internals")]

//! Negative AIR gates for an instruction's operands: which register each
//! operand reads, whether it reads one, which register the result writes,
//! the immediate an operand takes, and the sub-operation a row applies.
//! Each is fixed by the instruction at the row's pc, so a row that changes
//! one, keeping its flag bytes canonical as ProgramMemory pins them, is
//! refused by CpuChip's own constraints.
//!
//! Every forgery is a malicious prover's edit of the finalized CpuChip
//! trace, consistent with every constraint that does not bind the column
//! it changes; the register ledger and the lookup tables follow whatever
//! the CPU's rows claim, as a forger would build them.

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::CpuChip;
use vos_pvm_proof::chips::cpu::Column as Cpu;
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::MachineProverComponent;
use vos_pvm_proof::trace::component::ComponentTrace;

/// φ1 = 100 and φ2 = 7, then one instruction of each shape:
///
/// ```text
///   Add64      φ3 = φ1 + φ2
///   LoadImm    φ4 = 42
///   And        φ5 = φ1 & φ2
///   CmovIz     φ6 = φ1 if φ2 = 0      (φ2 ≠ 0: no move)
///   DivU64     φ7 = φ1 / φ2
///   ShloL64    φ8 = φ1 << (φ2 mod 64)
///   ShloLImm64 φ9 = φ1 << 3
///   CmovIzImm  φ10 = 5 if φ2 = 0      (no move)
///   LoadImmJump φ11 = 9, to the next instruction
///   Trap
/// ```
fn side_note() -> SideNote {
    let instructions: [&[u8]; 10] = [
        &[Opcode::Add64 as u8, 0x21, 3],
        &[Opcode::LoadImm as u8, 4, 42],
        &[Opcode::And as u8, 0x21, 5],
        &[Opcode::CmovIz as u8, 0x21, 6],
        &[Opcode::DivU64 as u8, 0x21, 7],
        &[Opcode::ShloL64 as u8, 0x21, 8],
        &[Opcode::ShloLImm64 as u8, 0x19, 3],
        &[Opcode::CmovIzImm as u8, 0x2a, 5],
        &[Opcode::LoadImmJump as u8, 0x1b, 9, 4],
        &[Opcode::Trap as u8],
    ];
    let mut code = Vec::new();
    let mut bitmask = Vec::new();
    for instruction in instructions {
        bitmask.push(1);
        bitmask.extend(std::iter::repeat_n(0, instruction.len() - 1));
        code.extend_from_slice(instruction);
    }
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[1] = 100;
    registers[2] = 7;
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0; 1 << 16],
        10_000,
    );
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(tracer.run(), vos_pvm::ExitReason::Panic);
    let steps = tracer.into_trace();
    assert_eq!(steps.len(), instructions.len());
    assert_eq!(steps[1].regs_after[4], 42);
    assert_eq!(steps[5].regs_after[8], 100 << 7);
    assert_eq!(steps[6].regs_after[9], 800);
    assert_eq!(steps[8].regs_after[11], 9);
    SideNote::new(steps, code, bitmask).with_initial_regs(registers)
}

fn assert_chip<C: MachineProverComponent>(chip: &C, trace: &ComponentTrace, side_note: &SideNote) {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel.into());
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
}

/// Stwo's assertion evaluator panics before finalizing its LogupAtRow when a
/// constraint fails, whose Drop guard aborts a double panic: the forged
/// trace runs in a child process, and rejection is its failure. `true` in
/// the child, which goes on to the forgery.
fn in_child(test_name: &str) -> bool {
    const CHILD: &str = "VOS_OPERAND_GATE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg(test_name)
        .env(CHILD, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run the forged trace in a child process");
    assert!(
        !status.success(),
        "SOUNDNESS GAP: the forged trace satisfied CpuChip"
    );
    false
}

/// Where a trace of `log_size` keeps its logical row `row`: the trace
/// builder stores rows in the circle domain's bit-reversed order.
fn stored(log_size: u32, row: usize) -> usize {
    let rows: Vec<BaseField> = (0..1u32 << log_size).map(BaseField::from).collect();
    let order = vos_pvm_proof::trace::utils::finalize_columns(vec![rows]);
    order[0]
        .as_slice()
        .iter()
        .position(|&at| at == BaseField::from(row as u32))
        .expect("a row of the trace")
}

fn set_field(trace: &mut ComponentTrace, offset: usize, row: usize, value: BaseField) {
    let at = stored(trace.log_size, row);
    trace.original_trace[offset].as_mut_slice()[at] = value;
}

fn set(trace: &mut ComponentTrace, offset: usize, row: usize, value: u32) {
    set_field(trace, offset, row, BaseField::from(value));
}

fn get(trace: &ComponentTrace, offset: usize, row: usize) -> BaseField {
    trace.original_trace[offset].as_slice()[stored(trace.log_size, row)]
}

/// The row of the step at `opcode`.
fn row_of(trace: &ComponentTrace, opcode: Opcode) -> usize {
    (0..1usize << trace.log_size)
        .find(|&row| {
            get(trace, Cpu::Opcode.offset(), row) == BaseField::from(opcode as u32)
                && get(trace, Cpu::IsPadding.offset(), row) == BaseField::from(0u32)
        })
        .expect("the opcode's row")
}

/// Byte `i` of ValB as `value`, with the helper that multiplies it.
fn set_val_b(trace: &mut ComponentTrace, row: usize, i: usize, value: u32) {
    set(trace, Cpu::ValB.offset() + i, row, value);
    let lt = get(trace, Cpu::CmpLtFlag.offset(), row);
    set_field(
        trace,
        Cpu::CmpLtValBH.offset() + i,
        row,
        lt * BaseField::from(value),
    );
}

/// Byte `i` of ValD as `value`, non-zero as it was, with the helpers that
/// multiply it and its inverse.
fn set_val_d(trace: &mut ComponentTrace, row: usize, i: usize, value: u32) {
    assert_ne!(
        get(trace, Cpu::ValD.offset() + i, row),
        BaseField::from(0u32)
    );
    assert_ne!(value, 0);
    set(trace, Cpu::ValD.offset() + i, row, value);
    set_field(
        trace,
        Cpu::ValDByteInv.offset() + i,
        row,
        BaseField::from(value).inverse(),
    );
    let lt = get(trace, Cpu::CmpLtFlag.offset(), row);
    set_field(
        trace,
        Cpu::CmpLtValDH.offset() + i,
        row,
        lt * BaseField::from(value),
    );
}

fn set_result(trace: &mut ComponentTrace, row: usize, value: u64) {
    for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
        set(trace, Cpu::Result.offset() + i, row, byte as u32);
    }
}

/// Forge the row of the step at `opcode` with `edit`; CpuChip refuses it.
fn forge(test_name: &str, opcode: Opcode, edit: impl FnOnce(&mut ComponentTrace, usize)) {
    let mut side_note = side_note();
    let mut trace = CpuChip.generate_component_trace(&mut side_note);
    assert_chip(&CpuChip, &trace, &side_note);
    if !in_child(test_name) {
        return;
    }
    let row = row_of(&trace, opcode);
    edit(&mut trace, row);
    assert_chip(&CpuChip, &trace, &side_note);
}

/// `Add64 φ3 = φ1 + φ2` claiming its first operand is no register read:
/// the operand is then any value, here 0x40 for φ1's 100, and φ3 its sum.
#[test]
fn an_operand_cannot_skip_its_register_read() {
    forge(
        "an_operand_cannot_skip_its_register_read",
        Opcode::Add64,
        |trace, row| {
            for column in [Cpu::ValBIsReg, Cpu::ValBIsRegH, Cpu::ValBIsRegNotTruncH] {
                set(trace, column.offset(), row, 0);
            }
            set_val_b(trace, row, 0, 0x40);
            set_result(trace, row, 0x40 + 7);
        },
    );
}

/// `Add64 φ3 = φ1 + φ2` writing its sum to φ9.
#[test]
fn a_result_cannot_change_its_register() {
    forge(
        "a_result_cannot_change_its_register",
        Opcode::Add64,
        |trace, row| {
            set(trace, Cpu::ResultRegIdx.offset(), row, 9);
        },
    );
}

/// `Add64 φ3 = φ1 + φ2` reading its first operand from φ2, whose value
/// the ledger then returns.
#[test]
fn an_operand_cannot_change_its_register() {
    forge(
        "an_operand_cannot_change_its_register",
        Opcode::Add64,
        |trace, row| {
            set(trace, Cpu::ValBRegIdx.offset(), row, 2);
            set(trace, Cpu::RegValB.offset(), row, 7);
            set_val_b(trace, row, 0, 7);
            set_result(trace, row, 14);
        },
    );
}

/// `Add64 φ3 = φ1 + φ2` dropping its write: φ3 keeps its old value.
#[test]
fn a_result_cannot_skip_its_write() {
    forge(
        "a_result_cannot_skip_its_write",
        Opcode::Add64,
        |trace, row| {
            set(trace, Cpu::ResultIsReg.offset(), row, 0);
        },
    );
}

/// `LoadImm φ4 = 42` loading 0x99.
#[test]
fn an_immediate_operand_is_the_instruction_s() {
    forge(
        "an_immediate_operand_is_the_instruction_s",
        Opcode::LoadImm,
        |trace, row| {
            set_val_d(trace, row, 0, 0x99);
            set_result(trace, row, 0x99);
        },
    );
}

/// `And φ5 = φ1 & φ2` applied as an `Or`.
#[test]
fn a_sub_operation_is_the_instruction_s() {
    forge(
        "a_sub_operation_is_the_instruction_s",
        Opcode::And,
        |trace, row| {
            set(trace, Cpu::IsAnd.offset(), row, 0);
            set(trace, Cpu::IsOr.offset(), row, 1);
            set_result(trace, row, 100 | 7);
        },
    );
}

/// `CmovIz φ6 = φ1 if φ2 = 0`, with φ2 = 7, writing 0x55 to φ6.
#[test]
fn a_move_not_taken_writes_nothing() {
    forge(
        "a_move_not_taken_writes_nothing",
        Opcode::CmovIz,
        |trace, row| {
            set(trace, Cpu::ResultIsReg.offset(), row, 1);
            set_result(trace, row, 0x55);
        },
    );
}

/// `DivU64 φ7 = φ1 / φ2` returning the remainder, 2, for the quotient 14.
#[test]
fn a_division_cannot_return_its_remainder() {
    forge(
        "a_division_cannot_return_its_remainder",
        Opcode::DivU64,
        |trace, row| {
            set(trace, Cpu::DivRemOp.offset(), row, 2);
            set(trace, Cpu::GateDivH.offset(), row, 0);
            set(trace, Cpu::GateRemH.offset(), row, 2);
            set(trace, Cpu::DivActiveQuotH.offset(), row, 0);
            set(trace, Cpu::DivActiveRemH.offset(), row, 2);
            set_result(trace, row, 100 % 7);
        },
    );
}

/// `ShloL64 φ8 = φ1 << 7` shifting by 6: the shift amount's identity with
/// φ2 solved in the field, `7 = 6 + 64·q` for q = 1/64.
#[test]
fn a_register_shift_amount_is_the_register_s() {
    forge(
        "a_register_shift_amount_is_the_register_s",
        Opcode::ShloL64,
        |trace, row| {
            set(trace, Cpu::ShiftAmount.offset(), row, 6);
            for i in 0..Cpu::ShiftQuotient.size() {
                set(trace, Cpu::ShiftQuotient.offset() + i, row, 0);
            }
            set_field(
                trace,
                Cpu::ShiftQuotient.offset(),
                row,
                BaseField::from(64u32).inverse(),
            );
            set_val_d(trace, row, 0, 64);
            set_result(trace, row, 100 << 6);
        },
    );
}

/// `ShloLImm64 φ9 = φ1 << 3` shifting by 2.
#[test]
fn an_immediate_shift_amount_is_the_instruction_s() {
    forge(
        "an_immediate_shift_amount_is_the_instruction_s",
        Opcode::ShloLImm64,
        |trace, row| {
            set(trace, Cpu::ShiftAmount.offset(), row, 2);
            set_val_d(trace, row, 0, 4);
            set_result(trace, row, 100 << 2);
        },
    );
}

/// `CmovIzImm φ10 = 5 if φ2 = 0` dropping its immediate-operand swap, so
/// its moved value is no longer the immediate.
#[test]
fn an_operand_swap_is_the_instruction_s() {
    forge(
        "an_operand_swap_is_the_instruction_s",
        Opcode::CmovIzImm,
        |trace, row| {
            set(trace, Cpu::IsCmovImm.offset(), row, 0);
            set_val_b(trace, row, 0, 0x33);
        },
    );
}

/// `LoadImmJump φ11 = 9` loading 0x77.
#[test]
fn a_jump_s_load_is_its_immediate() {
    forge(
        "a_jump_s_load_is_its_immediate",
        Opcode::LoadImmJump,
        |trace, row| {
            set_result(trace, row, 0x77);
        },
    );
}
