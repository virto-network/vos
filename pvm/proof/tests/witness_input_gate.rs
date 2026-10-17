#![cfg(feature = "debug-internals")]

//! Negative AIR gates for the witness input: a malicious prover's tampered
//! CpuChip and WitnessInputChip traces, each checked against its chip's own
//! constraints. A witness-input row writes its count to φ7 alone, a count
//! below 2^24 that is non-zero exactly when the call hands bytes over, at a
//! destination below 2^32; the chip writes a call's bytes at consecutive
//! addresses from its destination, one fewer left a row, and no row outside
//! a call's chain.

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use vos_pvm_program::{CodeBlob, StandardProgram, build_standard_program};
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::cpu::Column as Cpu;
use vos_pvm_proof::chips::witness_input::Column as Witness;
use vos_pvm_proof::chips::{CpuChip, WitnessInputChip};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::MachineProverComponent;
use vos_pvm_proof::kernel::trace_kernel;
use vos_pvm_proof::trace::component::ComponentTrace;

const RW: u64 = 0x3_0000;

/// Two witness-input calls, of three and two bytes, each count stored,
/// then a halt with an empty output.
fn side_note() -> SideNote {
    let mut code = Vec::new();
    let mut starts = Vec::new();
    let mut emit = |bytes: &[u8]| {
        starts.push(code.len());
        code.extend_from_slice(bytes);
    };
    let load_imm =
        |register: u8, value: u64| [&[51, register][..], &(value as u32).to_le_bytes()].concat();
    for (index, (destination, capacity)) in [(RW + 0xffd, 3u64), (RW + 0x200, 4)]
        .into_iter()
        .enumerate()
    {
        emit(&load_imm(7, destination));
        emit(&load_imm(8, capacity));
        emit(&[10, 0x01, 0x04]);
        emit(&[&[62, 7][..], &(RW as u32 + 8 * index as u32).to_le_bytes()].concat());
    }
    emit(&load_imm(8, 0));
    emit(&[50, 0]);
    let mut bitmask = vec![0; code.len()];
    for start in starts {
        bitmask[start] = 1;
    }
    let blob = build_standard_program(&StandardProgram {
        ro_data: vec![1; 4096],
        rw_data: vec![],
        heap_pages: 4,
        stack_size: 4096,
        code: CodeBlob {
            jump_table: vec![],
            code,
            bitmask,
        },
    })
    .unwrap();
    trace_kernel(&blob, &[1, 2, 3, 4, 5], 1_000_000)
        .expect("halts")
        .side_note
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
    const CHILD: &str = "VOS_WITNESS_GATE_CHILD";
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
        "SOUNDNESS GAP: the forged trace satisfied its chip"
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

fn set(trace: &mut ComponentTrace, offset: usize, row: usize, value: u32) {
    let at = stored(trace.log_size, row);
    trace.original_trace[offset].as_mut_slice()[at] = BaseField::from(value);
}

fn get(trace: &ComponentTrace, offset: usize, row: usize) -> u32 {
    trace.original_trace[offset].as_slice()[stored(trace.log_size, row)].0
}

/// The first witness-input row of the CPU's trace that wrote bytes.
fn witness_row(trace: &ComponentTrace) -> usize {
    let rows = trace.original_trace[0].as_slice().len();
    (0..rows)
        .find(|&row| {
            get(trace, Cpu::IsWitnessEcall.offset(), row) == 1
                && get(trace, Cpu::WitnessNonEmpty.offset(), row) == 1
        })
        .expect("a witness-input row")
}

/// Forge the CPU's witness-input row with `edit`; its constraints refuse
/// it.
fn forge_cpu(test_name: &str, edit: impl FnOnce(&mut ComponentTrace, usize)) {
    let mut side_note = side_note();
    let chip = CpuChip;
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note);
    if !in_child(test_name) {
        return;
    }
    let row = witness_row(&trace);
    edit(&mut trace, row);
    assert_chip(&chip, &trace, &side_note);
}

/// Forge WitnessInputChip's trace with `edit`; its constraints refuse it.
fn forge_bytes(test_name: &str, edit: impl FnOnce(&mut ComponentTrace)) {
    let mut side_note = side_note();
    let chip = WitnessInputChip;
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note);
    if !in_child(test_name) {
        return;
    }
    edit(&mut trace);
    assert_chip(&chip, &trace, &side_note);
}

#[test]
fn the_count_goes_to_phi7_alone() {
    forge_cpu("the_count_goes_to_phi7_alone", |trace, row| {
        set(trace, Cpu::ResultRegIdx.offset(), row, 8);
    });
}

#[test]
fn the_count_is_written() {
    forge_cpu("the_count_is_written", |trace, row| {
        set(trace, Cpu::ResultIsReg.offset(), row, 0);
    });
}

#[test]
fn the_count_is_below_2_24() {
    forge_cpu("the_count_is_below_2_24", |trace, row| {
        set(trace, Cpu::Result.offset() + 3, row, 1);
    });
}

#[test]
fn the_destination_is_below_2_32() {
    forge_cpu("the_destination_is_below_2_32", |trace, row| {
        set(trace, Cpu::Phi10.offset() + 4, row, 1);
    });
}

#[test]
fn a_call_with_bytes_hands_them_over() {
    forge_cpu("a_call_with_bytes_hands_them_over", |trace, row| {
        set(trace, Cpu::WitnessNonEmpty.offset(), row, 0);
    });
}

#[test]
fn a_call_without_bytes_hands_none_over() {
    forge_cpu("a_call_without_bytes_hands_none_over", |trace, row| {
        for byte in 0..3 {
            set(trace, Cpu::Result.offset() + byte, row, 0);
        }
    });
}

/// A call's second byte written one address on, its carries re-solved:
/// the address chain refuses it.
#[test]
fn a_byte_skips_an_address() {
    forge_bytes("a_byte_skips_an_address", |trace| {
        let low = get(trace, Witness::Addr.offset(), 1);
        set(trace, Witness::Addr.offset(), 1, low + 1);
    });
}

/// The first call's count raised by one at its first byte: the chain no
/// longer counts down to its last.
#[test]
fn a_call_s_count_does_not_match_its_bytes() {
    forge_bytes("a_call_s_count_does_not_match_its_bytes", |trace| {
        let left = get(trace, Witness::Left.offset(), 0);
        set(trace, Witness::Left.offset(), 0, left + 1);
    });
}

/// A call's last byte claimed to go on: the next row starts the next call.
#[test]
fn a_call_runs_into_the_next() {
    forge_bytes("a_call_runs_into_the_next", |trace| {
        set(trace, Witness::IsLast.offset(), 2, 0);
        set(trace, Witness::Cont.offset(), 2, 1);
    });
}

/// A byte written past the last call, on a padding row, as though it went
/// on a call: no call's chain reaches it.
#[test]
fn a_byte_outside_every_call() {
    forge_bytes("a_byte_outside_every_call", |trace| {
        // Three bytes, then two: row 5 is the first padding row.
        for (column, value) in [
            (Witness::IsReal, 1),
            (Witness::IsLast, 1),
            (Witness::Follows, 1),
            (Witness::Left, 1),
        ] {
            set(trace, column.offset(), 5, value);
        }
    });
}

/// `Add64 φ2 = φ2 + φ1`, reading and writing φ2 at one timestamp, then a
/// trap.
fn add_in_place() -> SideNote {
    use vos_pvm::instruction::Opcode;
    let code = vec![Opcode::Add64 as u8, 0x12, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let mut registers = [0u64; vos_pvm::PVM_REGISTER_COUNT];
    registers[1] = 7;
    registers[2] = 5;
    let pvm = vos_pvm::interpreter::Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        vec![0; 1 << 16],
        10_000,
    );
    let mut tracer = vos_pvm_proof::core::tracing::TracingPvm::new(pvm);
    let _ = tracer.run();
    SideNote::new(tracer.into_trace(), code, bitmask).with_initial_regs(registers)
}

/// A step that reads and writes one register reads the value from before
/// it: the ledger's φ2 rows reordered so the step's write comes first and
/// its read returns the written 12, each value consistent with its
/// predecessor, are refused by the ordering, which sorts a register's
/// reads before its writes within a timestamp. (The witness input's φ7 is
/// such a register: read as the destination, written as the count.)
#[test]
fn a_read_cannot_follow_its_step_s_write() {
    use vos_pvm_proof::chips::RegisterMemoryChip;
    use vos_pvm_proof::chips::register_memory::Column as Ledger;
    let mut side_note = add_in_place();
    let chip = RegisterMemoryChip;
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note);
    if !in_child("a_read_cannot_follow_its_step_s_write") {
        return;
    }
    // φ2's rows: the initial write of 5, the step's read of 5, its write
    // of 12.
    let rows = 1usize << trace.log_size;
    let first = (0..rows)
        .find(|&row| {
            get(&trace, Ledger::RegAddr.offset(), row) == 2
                && get(&trace, Ledger::IsPadding.offset(), row) == 0
        })
        .expect("φ2's rows");
    let (read, write) = (first + 1, first + 2);
    assert_eq!(
        [read, write].map(|row| get(&trace, Ledger::IsWrite.offset(), row)),
        [0, 1]
    );
    for (row, is_write) in [(read, 1), (write, 0)] {
        set(&mut trace, Ledger::IsWrite.offset(), row, is_write);
        set(&mut trace, Ledger::Value.offset(), row, 12);
    }
    set(&mut trace, Ledger::PrevValue.offset(), read, 5);
    set(&mut trace, Ledger::PrevValue.offset(), write, 12);
    // The deltas as reordered: 2·1 + 0 from the initial write to the
    // step's write, then 2·0 − 1 to its read, which no bits decompose.
    let bits = |trace: &mut ComponentTrace, row: usize, delta: u32| {
        for bit in 0..28 {
            set(
                trace,
                Ledger::OrderBits.offset() + bit,
                row,
                (delta >> bit) & 1,
            );
        }
    };
    set(&mut trace, Ledger::OrderValH.offset(), first, 2);
    bits(&mut trace, first, 2);
    let at = stored(trace.log_size, read);
    trace.original_trace[Ledger::OrderValH.offset()].as_mut_slice()[at] =
        BaseField::from(0u32) - BaseField::from(1u32);
    bits(&mut trace, read, 0);
    assert_chip(&chip, &trace, &side_note);
}
