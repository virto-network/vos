#![cfg(feature = "debug-internals")]

//! Negative AIR gates for the memory ledger.
//!
//! Its order within a timestamp: a step that reads and writes one byte — a
//! precompile whose output overlaps its input, as BLAKE2b's state does —
//! reads the byte's value from before the step. A ledger that puts the write first, so that the read
//! returns the written value, is refused by MemoryChip's own constraints:
//! at one timestamp an address's reads come before its writes.
//!
//! Its pages: a page listed in MemoryPageChip is real on all its 32 rows,
//! so it produces its leaf, which the initial root authenticates; a page
//! real on some rows only, injecting its bytes without a leaf, is refused.

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::memory::Column as Ledger;
use vos_pvm_proof::chips::memory_page::Column as Page;
use vos_pvm_proof::chips::{MemoryChip, MemoryPageChip};
use vos_pvm_proof::core::tracing::{ECALL_BLAKE2B_COMPRESS, TracingPvm};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::MachineProverComponent;
use vos_pvm_proof::trace::component::ComponentTrace;

const H: u64 = 0x2_0000;

/// One BLAKE2b compression of the state at `H` with the zero block at
/// `H + 64`, written back to `H`, then a trap.
fn side_note() -> SideNote {
    let mut memory = vec![0u8; 0x3_0000];
    for (i, byte) in memory[H as usize..H as usize + 64].iter_mut().enumerate() {
        *byte = i as u8 + 1;
    }
    let mut code = vec![vos_pvm::instruction::Opcode::Ecalli as u8];
    code.extend_from_slice(&ECALL_BLAKE2B_COMPRESS.to_le_bytes());
    code.push(vos_pvm::instruction::Opcode::Trap as u8);
    let mut bitmask = vec![0; code.len()];
    bitmask[0] = 1;
    bitmask[code.len() - 1] = 1;
    let mut registers = [0u64; vos_pvm::PVM_REGISTER_COUNT];
    registers[7] = H;
    registers[8] = H + 64;
    registers[10] = 1;
    let pvm = vos_pvm::interpreter::Interpreter::new(
        code,
        bitmask,
        vec![],
        registers,
        memory.clone(),
        10_000,
    );
    let mut tracer = TracingPvm::new(pvm);
    let _ = tracer.run_with_precompiles();
    let mut side_note = tracer.into_side_note().with_memory(memory);
    vos_pvm_proof::prepare_side_note_for_verification(&mut side_note);
    side_note.ingest_memory_pages();
    side_note
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
    const CHILD: &str = "VOS_MEMORY_LEDGER_GATE_CHILD";
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
        "SOUNDNESS GAP: the forged ledger satisfied MemoryChip"
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

fn get_column(trace: &ComponentTrace, column: Ledger, row: usize) -> Vec<u32> {
    (0..column.size())
        .map(|i| get(trace, column.offset() + i, row))
        .collect()
}

fn order_delta(trace: &ComponentTrace, row: usize) -> u32 {
    (0..Ledger::OrderBits.size())
        .map(|bit| get(trace, Ledger::OrderBits.offset() + bit, row) << bit)
        .sum()
}

fn set_order_delta(trace: &mut ComponentTrace, row: usize, delta: u32) {
    for bit in 0..Ledger::OrderBits.size() {
        set(
            trace,
            Ledger::OrderBits.offset() + bit,
            row,
            (delta >> bit) & 1,
        );
    }
}

/// The compression's state byte at `H`, read then written at the call's
/// timestamp, reordered so the write comes first and the read returns the
/// written value. Each row's previous value follows its predecessor, and
/// the ordering witness is re-solved as the chip derives it: from the
/// timestamps alone, or from `2·ts + is_write`.
#[test]
fn a_read_cannot_follow_its_step_s_write() {
    let mut side_note = side_note();
    let chip = MemoryChip;
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note);
    if !in_child("a_read_cannot_follow_its_step_s_write") {
        return;
    }
    let read = (0..(1usize << trace.log_size) - 1)
        .find(|&row| {
            get(&trace, Ledger::IsPadding.offset(), row) == 0
                && get_column(&trace, Ledger::Address, row)
                    == get_column(&trace, Ledger::Address, row + 1)
                && get_column(&trace, Ledger::Timestamp, row)
                    == get_column(&trace, Ledger::Timestamp, row + 1)
                && get(&trace, Ledger::IsWrite.offset(), row) == 0
                && get(&trace, Ledger::IsWrite.offset(), row + 1) == 1
                && get(&trace, Ledger::Value.offset(), row)
                    != get(&trace, Ledger::Value.offset(), row + 1)
        })
        .expect("a byte read and written at one timestamp");
    let write = read + 1;
    let written = get(&trace, Ledger::Value.offset(), write);
    // The honest delta between the two is 0 by timestamps, 1 by keys.
    let keyed = order_delta(&trace, read) == 1;
    set(&mut trace, Ledger::IsWrite.offset(), read, 1);
    set(&mut trace, Ledger::Value.offset(), read, written);
    set(&mut trace, Ledger::IsWrite.offset(), write, 0);
    set(&mut trace, Ledger::PrevValue.offset(), write, written);
    if keyed {
        let before = order_delta(&trace, read - 1);
        set_order_delta(&mut trace, read - 1, before + 1);
    }
    assert_chip(&chip, &trace, &side_note);
}

/// The first listed page, real on its first 16 rows only: its rows still
/// inject their bytes, but its last block, padding, produces no leaf.
#[test]
fn a_page_is_real_on_all_its_rows() {
    let mut side_note = side_note();
    let chip = MemoryPageChip;
    let mut trace = chip.generate_component_trace(&mut side_note);
    assert_chip(&chip, &trace, &side_note);
    if !in_child("a_page_is_real_on_all_its_rows") {
        return;
    }
    assert_eq!(get(&trace, Page::IsReal.offset(), 31), 1);
    for row in 16..32 {
        for column in [
            Page::IsReal,
            Page::ChainGateH,
            Page::Block0GateH,
            Page::LastBlockGateH,
        ] {
            set(&mut trace, column.offset(), row, 0);
        }
    }
    assert_chip(&chip, &trace, &side_note);
}
