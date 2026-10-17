#![cfg(feature = "debug-internals")]

//! Negative AIR gates for the register ledger: every read returns the
//! latest earlier write of its register.
//!
//! The forgery: `φ2 = φ2 + φ1` writes 12 to φ2 at timestamp 1, and the step
//! at timestamp 2 reads φ2 as its stale 5. The honest ledger refuses the
//! read: it follows the write of 12. A forger places it elsewhere in the
//! ledger, filling every column as the chip's own trace does, and the
//! ledger must still refuse it.

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::RegisterMemoryChip;
use vos_pvm_proof::chips::register_memory::{
    Column as Ledger, RegEntry, build_entries_from_side_note,
};
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineComponent, MachineProverComponent};
use vos_pvm_proof::trace::builder::TraceBuilder;
use vos_pvm_proof::trace::component::ComponentTrace;

/// `φ2 = φ2 + φ1` (5 + 7 = 12), `φ3 = φ2 + φ2`, a trap; the second step
/// forged to read φ2 as 5 and write 10.
fn side_note() -> SideNote {
    let code = vec![
        Opcode::Add64 as u8,
        (1 << 4) | 2,
        2,
        Opcode::Add64 as u8,
        (2 << 4) | 2,
        3,
        Opcode::Trap as u8,
    ];
    let bitmask = vec![1, 0, 0, 1, 0, 0, 1];
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[1] = 7;
    registers[2] = 5;
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
    let mut steps = tracer.into_trace();
    assert_eq!(steps[0].regs_after[2], 12);
    steps[1].regs_before[2] = 5;
    steps[1].regs_after[3] = 10;
    steps[2].regs_before[3] = 10;
    steps[2].regs_after[3] = 10;
    SideNote::new(steps, code, bitmask).with_initial_regs(registers)
}

/// A row of the ledger: an entry, or padding.
#[derive(Clone)]
enum Row {
    Entry(RegEntry),
    Padding,
}

impl Row {
    fn entry(&self) -> Option<&RegEntry> {
        match self {
            Row::Entry(entry) => Some(entry),
            Row::Padding => None,
        }
    }
}

fn field(value: i64) -> BaseField {
    if value >= 0 {
        BaseField::from(value as u32)
    } else {
        -BaseField::from((-value) as u32)
    }
}

/// The ledger trace of `rows`, every column derived as the chip's own trace
/// fill derives it; a read with no same-register predecessor takes its own
/// value as its previous one, which nothing else binds.
fn ledger(rows: &[Row]) -> ComponentTrace {
    let n = rows.len();
    let log_size = n.trailing_zeros();
    assert_eq!(n, 1 << log_size);
    let mut trace = TraceBuilder::<Ledger>::new(log_size);
    let key = |entry: &RegEntry| 2 * entry.timestamp + u64::from(entry.is_write);
    for (row, slot) in rows.iter().enumerate() {
        let next = rows[(row + 1) % n].entry();
        let chain_start = next.is_some_and(|next| {
            rows[row]
                .entry()
                .is_none_or(|entry| entry.reg_addr != next.reg_addr)
        });
        trace.fill_columns(row, chain_start, Ledger::ChainStartH);
        let Row::Entry(entry) = slot else {
            trace.fill_columns(row, true, Ledger::IsPadding);
            let next_register = next.map_or(0, |next| i64::from(next.reg_addr));
            trace.fill_columns_base_field(row, &[field(next_register - 1)], Ledger::OrderValH);
            continue;
        };
        trace.fill_columns(row, entry.reg_addr, Ledger::RegAddr);
        trace.fill_columns(row, entry.value, Ledger::Value);
        trace.fill_columns(row, entry.timestamp, Ledger::Ts0);
        trace.fill_columns(row, entry.is_write, Ledger::IsWrite);
        let previous = row
            .checked_sub(1)
            .and_then(|previous| rows[previous].entry())
            .filter(|previous| previous.reg_addr == entry.reg_addr);
        let previous_value = match previous {
            Some(previous) => previous.value,
            None if !entry.is_write => entry.value,
            None => 0,
        };
        trace.fill_columns(row, previous_value, Ledger::PrevValue);
        let same = next.is_some_and(|next| next.reg_addr == entry.reg_addr);
        trace.fill_columns(row, same, Ledger::IsSameRegNext);
        trace.fill_columns(row, next.is_some(), Ledger::BothRealH);
        let (value, delta) = match next {
            Some(next) if same => {
                let delta = key(next) - key(entry);
                (field(delta as i64), delta)
            }
            Some(next) => {
                let delta = i64::from(next.reg_addr) - i64::from(entry.reg_addr) - 1;
                (
                    field(delta),
                    u64::try_from(delta).expect("registers ascend"),
                )
            }
            None => (field(-i64::from(entry.reg_addr) - 1), 0),
        };
        trace.fill_columns_base_field(row, &[value], Ledger::OrderValH);
        let bits: [BaseField; 28] =
            core::array::from_fn(|bit| BaseField::from(((delta >> bit) & 1) as u32));
        trace.fill_columns_base_field(row, &bits, Ledger::OrderBits);
    }
    let preprocessed = RegisterMemoryChip
        .generate_component_trace(&mut side_note())
        .preprocessed_trace;
    ComponentTrace {
        log_size,
        preprocessed_trace: preprocessed,
        original_trace: trace.finalize_bit_reversed().cols,
    }
}

fn assert_ledger(trace: &ComponentTrace, side_note: &SideNote) {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    RegisterMemoryChip.draw_lookup_elements(&mut lookup_elements, channel.into());
    let (interaction_trace, claimed_sum) =
        RegisterMemoryChip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    RegisterMemoryChip.debug_assert_constraints(
        trace,
        &interaction_trace,
        &lookup_elements,
        claimed_sum,
    );
}

/// Stwo's assertion evaluator aborts on a failed constraint: the forged
/// ledger runs in a child process, and refusal is its failure. `true` in
/// the child, which goes on to the forgery.
fn in_child(test_name: &str) -> bool {
    const CHILD: &str = "VOS_REGISTER_LEDGER_GATE_CHILD";
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
        .expect("run the forged ledger in a child process");
    assert!(
        !status.success(),
        "SOUNDNESS GAP: the forged ledger was accepted"
    );
    false
}

/// The honest ledger's entries, the stale reads apart.
fn entries() -> (Vec<RegEntry>, Vec<RegEntry>) {
    build_entries_from_side_note(&side_note())
        .into_iter()
        .partition(|entry| !(entry.reg_addr == 2 && entry.timestamp == 2))
}

fn padded(mut rows: Vec<Row>) -> Vec<Row> {
    rows.push(Row::Padding);
    rows.resize(rows.len().next_power_of_two().max(16), Row::Padding);
    rows
}

/// The refill is the chip's: the honest entries, refilled, satisfy it.
#[test]
fn the_refilled_honest_ledger_passes() {
    let mut side_note = side_note();
    side_note.steps[1].regs_before[2] = 12;
    side_note.steps[1].regs_after[3] = 24;
    side_note.steps[2].regs_before[3] = 24;
    side_note.steps[2].regs_after[3] = 24;
    let rows = build_entries_from_side_note(&side_note)
        .into_iter()
        .map(Row::Entry)
        .collect();
    assert_ledger(&ledger(&padded(rows)), &side_note);
}

/// The stale reads in their place in the sorted ledger, after the write of
/// 12: their previous value is the write's.
#[test]
fn a_read_returns_its_register_s_latest_write() {
    let side_note = side_note();
    let rows = build_entries_from_side_note(&side_note)
        .into_iter()
        .map(Row::Entry)
        .collect();
    let forged = ledger(&padded(rows));
    if !in_child("a_read_returns_its_register_s_latest_write") {
        return;
    }
    assert_ledger(&forged, &side_note);
}

/// The stale reads past a padding row, after the honest ledger: there no
/// predecessor binds their previous value.
#[test]
fn a_read_follows_its_register_s_writes() {
    let side_note = side_note();
    let (kept, stale) = entries();
    let mut rows: Vec<Row> = kept.into_iter().map(Row::Entry).collect();
    rows.push(Row::Padding);
    rows.extend(stale.into_iter().map(Row::Entry));
    let forged = ledger(&padded(rows));
    if !in_child("a_read_follows_its_register_s_writes") {
        return;
    }
    assert_ledger(&forged, &side_note);
}
