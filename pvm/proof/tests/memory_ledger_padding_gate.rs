#![cfg(feature = "debug-internals")]

//! Negative AIR gate for the memory ledger's padding flag.
//!
//! A ledger row consumes its tuple with multiplicity `−(1 − IsPadding)`. Were
//! `IsPadding` free, a row with `IsPadding = 2` would have multiplicity `+1`
//! and PRODUCE a tuple. Between two padding rows the group gates force that
//! tuple to be a ts=0 write with `is_closing = 1`, at any address and value:
//! a second ts=0 write of a byte the segment never writes, which a real row
//! then consumes, so the CPU's first load of that byte returns a forged
//! value instead of the entering image's (the exit image is forged to match).
//! MemoryChip's booleanity on `IsPadding` refuses the minting row.
//!
//! The ledger is refilled from explicit rows, every helper column derived as
//! the chip's own trace generation does, generalized to `IsPadding = 2`; a
//! control checks that the honest rows, refilled, satisfy the chip. The
//! minting row's `IsStart`, the previous padding row's `IsGroupStart`, is
//! then `−1`, so the booleanity of `IsStart` refuses it as well.

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use stwo::prover::backend::simd::column::BaseColumn;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm::{ExitReason, PVM_REGISTER_COUNT, PVM_ZONE_SIZE};
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::MemoryChip;
use vos_pvm_proof::chips::memory::Column as Ledger;
use vos_pvm_proof::core::tracing::TracingPvm;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineComponent, MachineProverComponent};
use vos_pvm_proof::page_merkle::PAGE_SIZE;
use vos_pvm_proof::trace::builder::TraceBuilder;
use vos_pvm_proof::trace::component::ComponentTrace;

/// The byte the program stores, in the middle of a page above the protected
/// low zone.
const A: u32 = PVM_ZONE_SIZE + 0x1800;
const V: u8 = 0x42;
/// The byte the program loads: never written, zero in the entering image.
const L: u32 = A + 8;
const V_FORGED: u8 = 0x99;

fn assert_chip(trace: &ComponentTrace, side_note: &SideNote) {
    let chip = MemoryChip;
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel.into());
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
}

/// `true` in the child, which goes on to the forgery; the parent asserts the
/// child failed.
fn in_child(test_name: &str) -> bool {
    const CHILD: &str = "VOS_MEMORY_LEDGER_PADDING_GATE_CHILD";
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
        "SOUNDNESS GAP: MemoryChip accepted the forgery of {test_name}"
    );
    false
}

/// `StoreIndU8 φ0 → [φ1]; LoadIndU8 [φ1 + 8] → φ2; Trap`.
fn side_note() -> SideNote {
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
    let mut regs = [0u64; PVM_REGISTER_COUNT];
    regs[0] = V as u64;
    regs[1] = A as u64;
    let memory = vec![0u8; 4 * 1024 * 1024];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        memory.clone(),
        10_000,
    );
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(tracer.run(), ExitReason::Panic);
    let steps = tracer.into_trace();
    assert_eq!(steps.len(), 3);
    let mut sn = SideNote::new(steps, code, bitmask).with_memory(memory);
    sn.ingest_memory_pages();
    sn
}

/// stored\[logical_row\]: the row's position in the bit-reversed storage order.
fn stored_index(log_size: u32) -> Vec<usize> {
    let rows: Vec<BaseField> = (0..1u32 << log_size).map(BaseField::from).collect();
    let order = vos_pvm_proof::trace::utils::finalize_columns(vec![rows]);
    let mut stored = vec![0usize; 1 << log_size];
    for (at, v) in order[0].as_slice().iter().enumerate() {
        stored[v.0 as usize] = at;
    }
    stored
}

#[derive(Clone, Debug, Default)]
struct Row {
    /// 0 real, 1 padding, 2 the forger's minting row (multiplicity +1).
    pad: u32,
    addr: u32,
    value: u32,
    ts: u64,
    is_write: bool,
    is_closing: bool,
}

fn read_rows(trace: &ComponentTrace) -> Vec<Row> {
    let stored = stored_index(trace.log_size);
    (0..1usize << trace.log_size)
        .map(|row| {
            let g = |col: Ledger, i: usize| {
                trace.original_trace[col.offset() + i].as_slice()[stored[row]].0
            };
            let pad = g(Ledger::IsPadding, 0);
            if pad != 0 {
                return Row {
                    pad,
                    ..Row::default()
                };
            }
            Row {
                pad,
                addr: (0..4).fold(0u32, |a, i| a | (g(Ledger::Address, i) << (8 * i))),
                value: g(Ledger::Value, 0),
                ts: (0..8).fold(0u64, |a, i| {
                    a | ((g(Ledger::Timestamp, i) as u64) << (8 * i))
                }),
                is_write: g(Ledger::IsWrite, 0) == 1,
                is_closing: g(Ledger::IsClosing, 0) == 1,
            }
        })
        .collect()
}

fn field(v: i64) -> BaseField {
    if v >= 0 {
        BaseField::from(v as u32)
    } else {
        -BaseField::from((-v) as u32)
    }
}

/// A MemoryChip main trace from explicit rows, each helper column derived as
/// the chip's trace generation does, for `pad ∈ {0, 1, 2}`.
fn fill_ledger(rows: &[Row], log_size: u32, sn: &SideNote) -> Vec<BaseColumn> {
    let n = rows.len();
    assert_eq!(n, 1usize << log_size);
    let mut trace = TraceBuilder::<Ledger>::new(log_size);
    let key = |r: &Row| 2 * r.ts + u64::from(r.is_write);
    for i in 0..n {
        let r = &rows[i];
        let nx = &rows[(i + 1) % n];
        let prev = &rows[(i + n - 1) % n];
        let same = r.pad == 0 && nx.pad == 0 && r.addr == nx.addr;
        let same_prev = prev.pad == 0 && r.pad == 0 && prev.addr == r.addr;
        let both_real = (1 - r.pad as i64) * (1 - nx.pad as i64);
        assert_ne!(
            both_real, -1,
            "row {i}: a real row may not abut a pad=2 row"
        );
        let hi_eq = (r.addr >> 16) == (nx.addr >> 16);
        let adv_lo = both_real == 1 && !same && hi_eq;
        let adv_hi = both_real == 1 && !same && !hi_eq;
        let delta: u64 = if same {
            key(nx).checked_sub(key(r)).expect("key order")
        } else if adv_lo {
            ((nx.addr & 0xffff) as i64 - (r.addr & 0xffff) as i64 - 1)
                .try_into()
                .expect("lo advance")
        } else if adv_hi {
            ((nx.addr >> 16) as i64 - (r.addr >> 16) as i64 - 1)
                .try_into()
                .expect("hi advance")
        } else {
            0
        };
        assert!(delta < (1u64 << 28));
        let prev_value = if same_prev { prev.value } else { r.value };
        if !r.is_write && r.pad != 1 {
            assert_eq!(prev_value, r.value, "row {i}: a read must chain");
        }
        trace.fill_columns_bytes(i, &r.addr.to_le_bytes(), Ledger::Address);
        trace.fill_columns(i, r.value as u8, Ledger::Value);
        trace.fill_columns(i, r.ts, Ledger::Timestamp);
        trace.fill_columns(i, r.is_write, Ledger::IsWrite);
        trace.fill_columns(i, prev_value as u8, Ledger::PrevValue);
        trace.fill_columns(i, same, Ledger::IsSameAddrNext);
        trace.fill_columns_base_field(i, &[field(r.pad as i64)], Ledger::IsPadding);
        trace.fill_columns(i, adv_lo, Ledger::AdvLoH);
        trace.fill_columns(i, adv_hi, Ledger::AdvHiH);
        let bits: [BaseField; 28] =
            core::array::from_fn(|b| BaseField::from(((delta >> b) & 1) as u32));
        trace.fill_columns_base_field(i, &bits, Ledger::OrderBits);
        trace.fill_columns(i, r.is_closing, Ledger::IsClosing);
        let group_start = (1 - nx.pad as i64) * (1 - same as i64);
        let group_end = (1 - r.pad as i64) * (1 - same as i64);
        trace.fill_columns_base_field(i, &[field(group_start)], Ledger::IsGroupStart);
        trace.fill_columns_base_field(i, &[field(group_end)], Ledger::IsGroupEnd);
        // The page's permission, held along the group, as the chip fills it;
        // `IsStart` is the previous row's `IsGroupStart`.
        let prev_same = prev.pad == 0 && r.pad == 0 && prev.addr == r.addr;
        let is_start = (1 - r.pad as i64) * (1 - prev_same as i64);
        let permission = if r.pad == 1 {
            0
        } else {
            sn.memory_layout.permission(r.addr / PAGE_SIZE as u32) as i64
        };
        let (readable, writable) = (permission >= 1, permission == 2);
        trace.fill_columns_base_field(i, &[field(is_start)], Ledger::IsStart);
        trace.fill_columns(i, readable, Ledger::Readable);
        trace.fill_columns(i, writable, Ledger::Writable);
        let permission_h = is_start * (readable as i64 + writable as i64);
        trace.fill_columns_base_field(i, &[field(permission_h)], Ledger::PermissionH);
    }
    trace.finalize_bit_reversed().cols
}

fn refilled(honest: &ComponentTrace, rows: &[Row], sn: &SideNote) -> ComponentTrace {
    ComponentTrace {
        log_size: honest.log_size,
        preprocessed_trace: honest.preprocessed_trace.clone(),
        original_trace: fill_ledger(rows, honest.log_size, sn),
    }
}

/// Control: the honest rows, refilled, satisfy MemoryChip.
#[test]
fn the_refilled_honest_ledger_passes() {
    let mut sn = side_note();
    let honest = MemoryChip.generate_component_trace(&mut sn);
    assert_chip(&honest, &sn);
    assert_chip(&refilled(&honest, &read_rows(&honest), &sn), &sn);
}

/// G2-2. A row with `IsPadding = 2`, between two padding rows, mints a ts=0
/// write of `V_FORGED` at `L`, consumed right after the page chip's own; the
/// CPU's load of `L` and the closing read then return `V_FORGED`.
#[test]
fn a_padding_flag_of_two_cannot_mint_a_write() {
    let mut sn = side_note();
    let honest = MemoryChip.generate_component_trace(&mut sn);
    assert_chip(&honest, &sn);
    if !in_child("a_padding_flag_of_two_cannot_mint_a_write") {
        return;
    }
    let load_ts = sn.steps[1].timestamp;
    let mut rows: Vec<Row> = read_rows(&honest)
        .into_iter()
        .filter(|r| r.pad == 0)
        .collect();
    let mut forged_reads = 0;
    for r in rows.iter_mut() {
        if r.addr == L && !r.is_write && (r.ts == load_ts || r.is_closing) {
            assert_eq!(r.value, 0, "L is untouched in the entering image");
            r.value = V_FORGED as u32;
            forged_reads += 1;
        }
    }
    assert_eq!(forged_reads, 2, "the step's load and the closing read");
    let first_write = rows
        .iter()
        .position(|r| r.addr == L && r.ts == 0)
        .expect("the page chip's ts=0 write at L");
    let minted = Row {
        pad: 0,
        addr: L,
        value: V_FORGED as u32,
        ts: 0,
        is_write: true,
        is_closing: true,
    };
    rows.insert(first_write + 1, minted.clone());
    rows.push(Row {
        pad: 1,
        ..Row::default()
    });
    rows.push(Row { pad: 2, ..minted });
    while rows.len() < (1usize << honest.log_size) {
        rows.push(Row {
            pad: 1,
            ..Row::default()
        });
    }
    assert_chip(&refilled(&honest, &rows, &sn), &sn);
}
