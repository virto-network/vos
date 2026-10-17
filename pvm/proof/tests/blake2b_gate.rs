#![cfg(feature = "debug-internals")]

//! Negative AIR gates for `Blake2bChip`, the precompile's ECALL-bound
//! compression chip.
//!
//! A compression is 96 rows. Its first row consumes the CPU's call tuple and
//! reads `h` and `m` from the memory ledger; its last row writes the digest
//! back to `h`. Nothing outside the chip relates those two rows, so the chip
//! itself must hold `IsReal` boolean and constant across the 96 rows, keep
//! real rows out of the trailing partial block that has no last row, and pin
//! every address it emits, on the row that emits it, to the call's pointer
//! plus the byte's offset, with byte limbs, not modulo p.
//!
//! Each test builds an honest trace, forges it the way a from-scratch prover
//! would, and asserts the chip's own constraints refuse it. Stwo's
//! assertion evaluator aborts on a double panic when a constraint fails
//! after a lookup was added, so each forgery runs in a child process and
//! refusal is that child's failure.

use stwo::core::fields::m31::BaseField;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::Blake2bChip;
use vos_pvm_proof::chips::blake2b::{Blake2bCall, Column};
use vos_pvm_proof::core::tracing::Blake2bMemOp;
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineComponent, MachineProverComponent};
use vos_pvm_proof::recursion_pcs::ProverChannel;
use vos_pvm_proof::trace::component::ComponentTrace;

const P: u32 = (1u32 << 31) - 1;
const H_PTR: u32 = 0x1000;
const M_PTR: u32 = 0x2000;

fn assert_chip(trace: &ComponentTrace, side_note: &SideNote) {
    let chip = Blake2bChip;
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut ProverChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel);
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
}

/// `true` in the child, which goes on to the forgery; the parent asserts the
/// child failed.
fn in_child(test_name: &str) -> bool {
    const CHILD: &str = "VOS_BLAKE2B_GATE_CHILD";
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
        "SOUNDNESS GAP: Blake2bChip accepted the forgery of {test_name}"
    );
    false
}

/// `calls` compressions of distinct states, each at its own call timestamp.
fn side_note(calls: usize) -> SideNote {
    side_note_at(calls, H_PTR, M_PTR)
}

fn side_note_at(calls: usize, h_ptr: u32, m_ptr: u32) -> SideNote {
    let mut sn = SideNote::new(Vec::new(), Vec::new(), Vec::new());
    for c in 0..calls {
        let h: [u64; 8] = core::array::from_fn(|i| (c * 8 + i + 1) as u64);
        let m = [9u64 + c as u64; 16];
        let out = vos_pvm_proof::chips::blake2b_compress(&h, &m, 0, true);
        sn.blake2b_calls.push(Blake2bCall {
            h,
            m,
            t: 0,
            f: true,
        });
        sn.blake2b_mem_ops.push(Blake2bMemOp {
            h_ptr,
            m_ptr,
            ts: 7 + c as u64,
            h_bytes: words_to_bytes(&h),
            m_bytes: words_to_bytes(&m),
            out_bytes: words_to_bytes(&out),
        });
    }
    sn
}

fn words_to_bytes<const N: usize>(words: &[u64]) -> [u8; N] {
    let mut bytes = [0u8; N];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// An honest trace, already checked to satisfy the chip.
fn honest(sn: &mut SideNote) -> ComponentTrace {
    let trace = Blake2bChip.generate_component_trace(sn);
    assert_chip(&trace, sn);
    trace
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

fn get(trace: &ComponentTrace, offset: usize, row: usize) -> u32 {
    trace.original_trace[offset].as_slice()[stored(trace.log_size, row)].0
}

/// Make logical row `row` a padding row as far as the gates see it.
fn unreal(trace: &mut ComponentTrace, row: usize) {
    for column in [
        Column::IsReal,
        Column::GateH,
        Column::InitGateH,
        Column::OutputGateH,
    ] {
        set(trace, column.offset(), row, 0);
    }
}

/// Copy every main column of logical row `from` onto row `to`.
fn copy_row(trace: &mut ComponentTrace, from: usize, to: usize) {
    let (from, to) = (stored(trace.log_size, from), stored(trace.log_size, to));
    for column in trace.original_trace.iter_mut() {
        let value = column.as_slice()[from];
        column.as_mut_slice()[to] = value;
    }
}

// ── Addresses ────────────────────────────────────────────────────────────

/// The address limb 2 of `h` byte `i`, which the digest's write reads on
/// row 95.
fn write_addr_b2(i: usize) -> usize {
    Column::HAddrB2.offset() + i
}

/// Claim address `addr` for `h` byte `i` on logical row `row`: limbs 1..3
/// directly, limb 0 through its carry, `c = (h_ptr[0] + i − addr[0]) / 256`
/// as a field element.
fn forge_h_addr(trace: &mut ComponentTrace, row: usize, i: usize, addr: u32) {
    let limbs = addr.to_le_bytes();
    let ptr0 = get(trace, Column::HPtr.offset(), row);
    let carry = (BaseField::from(ptr0 + i as u32) - BaseField::from(limbs[0] as u32))
        * BaseField::from(256u32).inverse();
    set_field(trace, Column::HAddrCarry.offset() + i, row, carry);
    for (k, column) in [Column::HAddrB1, Column::HAddrB2, Column::HAddrB3]
        .into_iter()
        .enumerate()
    {
        set(trace, column.offset() + i, row, limbs[k + 1] as u32);
    }
}

/// Move `h_ptr` to `ptr` on logical row `row`, with every address column
/// of that row filled consistently with it.
fn move_h_ptr(trace: &mut ComponentTrace, row: usize, ptr: u32) {
    let p = ptr.to_le_bytes();
    let inc = ((ptr >> 8) + 1).to_le_bytes();
    for k in 0..4 {
        set(trace, Column::HPtr.offset() + k, row, p[k] as u32);
    }
    for k in 0..3 {
        set(trace, Column::HPtrInc.offset() + k, row, inc[k] as u32);
    }
    let e0 = p[1] == 0xff;
    set(trace, Column::HPtrIncCarry.offset(), row, e0 as u32);
    set(
        trace,
        Column::HPtrIncCarry.offset() + 1,
        row,
        (e0 && p[2] == 0xff) as u32,
    );
    let upper = [Column::HAddrB1, Column::HAddrB2, Column::HAddrB3];
    for i in 0..64 {
        let carry = p[0] as usize + i >= 256;
        set(trace, Column::HAddrCarry.offset() + i, row, carry as u32);
        for k in 0..3 {
            let limb = if carry { inc[k] } else { p[k + 1] };
            set(trace, upper[k].offset() + i, row, limb as u32);
        }
    }
}

// ── Controls ─────────────────────────────────────────────────────────────

/// The harness refuses a wrong digest byte on an honest compression.
#[test]
fn a_wrong_digest_byte_is_refused() {
    let mut sn = side_note(1);
    let mut trace = honest(&mut sn);
    if !in_child("a_wrong_digest_byte_is_refused") {
        return;
    }
    let out = Column::Output.offset();
    let v = get(&trace, out, 95);
    set(&mut trace, out, 95, v ^ 1);
    assert_chip(&trace, &sn);
}

/// Honest pointers whose ranges carry out of limb 0, and out of limbs 1
/// and 2 of the increment (`h` crosses 0x0100_0000, `m` crosses 0x2_0000),
/// satisfy the chip.
#[test]
fn ranges_carrying_across_limbs_are_accepted() {
    let mut sn = side_note_at(1, 0x00FF_FFE0, 0x1_FFC0);
    honest(&mut sn);
}

/// A range wrapping 2^32 has no satisfying row: the runtime refuses such a
/// call, so the AIR proves no address of it.
#[test]
fn a_range_wrapping_2_32_is_unprovable() {
    if !in_child("a_range_wrapping_2_32_is_unprovable") {
        return;
    }
    let mut sn = side_note_at(1, 0xFFFF_FFF0, M_PTR);
    let trace = Blake2bChip.generate_component_trace(&mut sn);
    assert_chip(&trace, &sn);
}

// ── G4-1 / G4-6: IsReal ──────────────────────────────────────────────────

/// G4-1. `IsReal` lit on row 95 alone: no gate chains it to rows 0..94, so
/// its state, `H`, timestamp and write address are free, and it emits 64
/// writes of a forged digest at a forged address and timestamp.
#[test]
fn a_lone_last_row_cannot_write() {
    let mut sn = side_note(1);
    let mut trace = honest(&mut sn);
    if !in_child("a_lone_last_row_cannot_write") {
        return;
    }
    for row in 0..95 {
        unreal(&mut trace, row);
    }
    // Row 95 now writes values no other row pins: a forged address,
    // timestamp and `H`, with the digest and its AND witnesses recomputed
    // so the row is self-consistent.
    move_h_ptr(&mut trace, 95, 0x0DAD_BE40);
    set(&mut trace, Column::CallTs.offset(), 95, 99);
    let h_cols = [
        Column::H0,
        Column::H1,
        Column::H2,
        Column::H3,
        Column::H4,
        Column::H5,
        Column::H6,
        Column::H7,
    ];
    let v_cols = [
        Column::V0,
        Column::V1,
        Column::V2,
        Column::V3,
        Column::V4,
        Column::V5,
        Column::V6,
        Column::V7,
        Column::V8,
        Column::V9,
        Column::V10,
        Column::V11,
        Column::V12,
        Column::V13,
        Column::V14,
        Column::V15,
    ];
    // At row 95 the G-call touches slots 3, 4, 9 and 14.
    let v_after = |trace: &ComponentTrace, k: usize, b: usize| -> u32 {
        match k {
            3 => get(trace, Column::AOut.offset() + b, 95),
            4 => get(trace, Column::BOut.offset() + b, 95),
            9 => get(trace, Column::COut.offset() + b, 95),
            14 => get(trace, Column::DOut.offset() + b, 95),
            _ => get(trace, v_cols[k].offset() + b, 95),
        }
    };
    for w in 0..8 {
        for b in 0..8 {
            let h = 0xA5 ^ (w * 8 + b) as u32;
            let v1 = v_after(&trace, w, b);
            let v2 = v_after(&trace, w + 8, b);
            let xor1 = h ^ v1;
            set(&mut trace, h_cols[w].offset() + b, 95, h);
            set(&mut trace, Column::OutAnd1.offset() + w * 8 + b, 95, h & v1);
            set(
                &mut trace,
                Column::OutAnd2.offset() + w * 8 + b,
                95,
                xor1 & v2,
            );
            set(
                &mut trace,
                Column::Output.offset() + w * 8 + b,
                95,
                xor1 ^ v2,
            );
        }
    }
    assert_chip(&trace, &sn);
}

/// G4-1. `IsReal` lit on row 0 alone: the call is consumed and `h`, `m`
/// read, but the compression never reaches its writing row, so the
/// precompile leaves memory untouched.
#[test]
fn a_lone_first_row_cannot_drop_the_write() {
    let mut sn = side_note(1);
    let mut trace = honest(&mut sn);
    if !in_child("a_lone_first_row_cannot_drop_the_write") {
        return;
    }
    for row in 1..96 {
        unreal(&mut trace, row);
    }
    assert_chip(&trace, &sn);
}

/// G4-1. The trace's last 64 rows are a partial block with no row 95. A
/// compression placed there consumes its call and reads `h` and `m` but
/// never writes. The forgery keeps the cyclic wrap from the last row to
/// row 0 satisfied by making block 0 padding with the state the tail's last
/// row chains into.
#[test]
fn a_tail_block_cannot_consume_a_call() {
    let mut sn = side_note(2);
    let mut trace = honest(&mut sn);
    if !in_child("a_tail_block_cannot_consume_a_call") {
        return;
    }
    assert_eq!(trace.log_size, 8, "two compressions and a 64-row tail");
    // Call 0 moves to the tail: rows 192..256 take its rows 0..64.
    for row in 0..64 {
        copy_row(&mut trace, row, 192 + row);
    }
    // Row 0 takes the state row 255 chains into (call 0's row 64) as
    // padding; rows 1..96 become padding.
    copy_row(&mut trace, 64, 0);
    for row in 0..96 {
        unreal(&mut trace, row);
    }
    // Row 0's message selectors are round 0's, row 64's round 8's.
    let m0 = Column::M0.offset();
    let m1 = Column::M1.offset();
    for b in 0..8 {
        let mx = get(&trace, m0 + b, 0);
        let my = get(&trace, m1 + b, 0);
        set(&mut trace, Column::MxSlotSum.offset() + b, 0, mx);
        set(&mut trace, Column::MySlotSum.offset() + b, 0, my);
    }
    assert_chip(&trace, &sn);
}

/// G4-6. `IsReal = 2` with every gate doubled scales the block's lookups.
#[test]
fn is_real_two_is_refused() {
    let mut sn = side_note(1);
    let mut trace = honest(&mut sn);
    if !in_child("is_real_two_is_refused") {
        return;
    }
    for row in 0..96 {
        for column in [
            Column::IsReal,
            Column::GateH,
            Column::InitGateH,
            Column::OutputGateH,
        ] {
            let v = get(&trace, column.offset(), row);
            set(&mut trace, column.offset(), row, v * 2);
        }
    }
    assert_chip(&trace, &sn);
}

// ── G4-2: the write address ──────────────────────────────────────────────

/// G4-2. The digest's write address on row 95, the row that emits the
/// writes, moved 64 KiB up: the digest lands elsewhere and `h` keeps its
/// stale bytes.
#[test]
fn the_write_address_is_pinned_on_the_writing_row() {
    let mut sn = side_note(1);
    let mut trace = honest(&mut sn);
    if !in_child("the_write_address_is_pinned_on_the_writing_row") {
        return;
    }
    for i in 0..64 {
        let b2 = get(&trace, write_addr_b2(i), 95);
        set(&mut trace, write_addr_b2(i), 95, (b2 + 1) & 0xff);
    }
    assert_chip(&trace, &sn);
}

// ── G4-3: addresses are u32, not field elements ──────────────────────────

/// G4-3. `h_ptr + p` decomposes into four bytes whose base-256 sum equals
/// `h_ptr` modulo p: the read of `h[0]` and its write claimed there.
#[test]
fn an_address_aliased_by_p_is_refused() {
    let mut sn = side_note(1);
    let mut trace = honest(&mut sn);
    if !in_child("an_address_aliased_by_p_is_refused") {
        return;
    }
    let aliased = H_PTR.wrapping_add(P);
    assert_eq!(aliased, 0x8000_0FFF);
    forge_h_addr(&mut trace, 0, 0, aliased);
    forge_h_addr(&mut trace, 95, 0, aliased);
    assert_chip(&trace, &sn);
}
