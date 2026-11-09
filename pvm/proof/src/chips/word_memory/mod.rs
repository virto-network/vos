//! WordMemoryChip — the device's memory ledger a word a row
//! ([`crate::format::Memory::Word`]), in place of `MemoryChip`'s row a byte.
//!
//! A row is one word, its address a multiple of [`WORD_BYTES`], at one
//! `(timestamp, is_write)`: the word's bytes after it ([`Column::Value`])
//! and before it ([`Column::PrevValue`]), and the lanes it takes
//! ([`Column::Active`]), each lane `j` consuming the `MemoryAccess` byte
//! tuple of address `addr + j` exactly as `MemoryChip` consumes it. The
//! producers are unchanged: the CPU, the precompiles and the witness input
//! put the byte tuples they put for the byte ledger, at any width and
//! alignment; an access across a word's end is two rows, one a word.
//!
//! The rows are sorted by `(address, 2·timestamp + is_write)` as the byte
//! ledger's, a word's rows one group, every group
//! `[ts = 0 write, accesses…, closing read]`:
//! - **the group's ends** consume a word's `MemoryWord` tuples, all its bytes
//!   at once, which [`DeviceWordMemoryChip`] alone produces: its `ts = 0`
//!   write (the first touch, with the region's permission) and its closing
//!   read. Their address is the word's, a multiple of [`WORD_BYTES`] by
//!   that chip's bits, and every row of the group shares it, so a lane's
//!   byte address is `addr + j` with no carry, one word's lanes are
//!   another's never, and a byte is in one group alone;
//! - **a read** keeps every byte; **a write** keeps each byte it takes no
//!   lane of; the next row's previous bytes are this row's; so a lane reads
//!   the last byte written to it, or the first touch's, whatever the
//!   accesses' widths;
//! - **no lane** is taken on a group's ends or on padding, so every byte
//!   tuple is consumed inside a group, and **every inner row takes one**, so
//!   its timestamp is a producer's and the sort keys between two accesses
//!   cannot wrap the field through rows no access binds;
//! - **padding** comes after every real row (the preprocessed `IsLast`), so
//!   the real rows are one sorted run and a word one group, however many
//!   boundary rows name it.
//!
//! [`DeviceWordMemoryChip`]: crate::chips::DeviceWordMemoryChip

use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::device::WORD_BYTES;
use crate::framework::{BuiltInComponent, Logup};
use crate::lookups::{MemoryAccessLookupElements, MemoryWordLookupElements};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub mod boundary;
pub mod data;

pub use boundary::DeviceWordMemoryChip;
pub use data::DataWordTableChip;

#[derive(Clone, Copy)]
pub struct WordMemoryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The word's address (4 LE limbs), its first byte's.
    #[size = 4]
    #[mask_next_row]
    Address,
    /// The word's bytes after the row.
    #[size = 8]
    Value,
    /// The word's bytes before the row: the previous row's `Value` within a
    /// group.
    #[size = 8]
    #[mask_next_row]
    PrevValue,
    /// The access's timestamp (8 limbs).
    #[size = 8]
    #[mask_next_row]
    Timestamp,
    /// 1 = write, 0 = read.
    #[size = 1]
    #[mask_next_row]
    IsWrite,
    /// 1 on each lane whose byte tuple the row consumes.
    #[size = 8]
    Active,
    /// Bound boolean: the next row is real and the same word.
    #[size = 1]
    IsSameAddrNext,
    /// 1 on padding.
    #[size = 1]
    #[mask_next_row]
    IsPadding,
    /// Bound boolean: a real→real transition advancing the address in its
    /// low 16-bit half.
    #[size = 1]
    AdvLoH,
    /// Bound boolean: a real→real transition advancing the address in its
    /// high 16-bit half.
    #[size = 1]
    AdvHiH,
    /// The ordering delta's bits (`MemoryChip`'s `OrderBits`).
    #[size = 28]
    OrderBits,
    /// 1 on a group's closing read.
    #[size = 1]
    IsClosing,
    /// Bound helper: `is_real_next · (1 − IsSameAddrNext)`.
    #[size = 1]
    IsGroupStart,
    /// Bound helper: `is_real · (1 − IsSameAddrNext)`.
    #[size = 1]
    IsGroupEnd,
    /// 1 on a group's first row: the previous row's `IsGroupStart`.
    #[size = 1]
    #[mask_next_row]
    IsStart,
    /// The word's region is writable, constant along the group (every
    /// region a device run touches is readable).
    #[size = 1]
    #[mask_next_row]
    Writable,
    /// Bound helper `IsStart · (1 + Writable)`: the region's permission on
    /// a group's start, 0 on every other row.
    #[size = 1]
    PermissionH,
    /// The inverse of the lanes an inner row takes: proof that it takes one.
    #[size = 1]
    LaneInv,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "wmem"]
pub enum PreprocessedColumn {
    /// 1 on the last row, 0 elsewhere.
    #[size = 1]
    IsLast,
}

const _: () = assert!(WORD_BYTES == 8);

impl BuiltInComponent for WordMemoryChip {
    const LOGUP: Logup = Logup::Pairs;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (MemoryAccessLookupElements, MemoryWordLookupElements);

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        (bytes, words): &(MemoryAccessLookupElements, MemoryWordLookupElements),
    ) {
        let one = || E::F::one();
        let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = one() - is_pad[0].clone();
        let address = crate::trace::trace_eval!(trace_eval, Column::Address);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let prev = crate::trace::trace_eval!(trace_eval, Column::PrevValue);
        let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
        let is_write = crate::trace::trace_eval!(trace_eval, Column::IsWrite);
        let active = crate::trace::trace_eval!(trace_eval, Column::Active);
        let is_closing = crate::trace::trace_eval!(trace_eval, Column::IsClosing);
        let is_start = crate::trace::trace_eval!(trace_eval, Column::IsStart);

        for flag in [&is_closing[0], &is_write[0], &is_pad[0]]
            .into_iter()
            .chain(&active)
        {
            eval.add_constraint(flag.clone() * (flag.clone() - one()));
        }
        // A closing read is a real row's read.
        eval.add_constraint(is_closing[0].clone() * is_write[0].clone());
        eval.add_constraint(is_closing[0].clone() * is_pad[0].clone());

        // The lanes: taken on a group's inner rows alone, at least one on
        // each; a read keeps every byte, a byte no lane writes is kept, the
        // group's first row's free (its word tuple binds them).
        let ends = is_start[0].clone() + is_closing[0].clone() + is_pad[0].clone();
        let lane_inv = crate::trace::trace_eval!(trace_eval, Column::LaneInv);
        let taken = active
            .iter()
            .fold(E::F::zero(), |sum, lane| sum + lane.clone());
        eval.add_constraint((one() - ends.clone()) * (one() - lane_inv[0].clone() * taken));
        for lane in 0..WORD_BYTES {
            let kept = value[lane].clone() - prev[lane].clone();
            eval.add_constraint(ends.clone() * active[lane].clone());
            eval.add_constraint((one() - is_write[0].clone()) * kept.clone());
            eval.add_constraint((one() - active[lane].clone() - is_start[0].clone()) * kept);
        }

        // The sortedness gadget, `MemoryChip`'s: rows sorted by (address,
        // 2·ts + is_write), a word's rows one group; padding past the real
        // rows alone, a padding row followed by a real one only at the wrap.
        let is_pad_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsPadding);
        let is_last =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::IsLast);
        eval.add_constraint(
            is_pad[0].clone() * (one() - is_pad_next[0].clone()) * (one() - is_last[0].clone()),
        );
        let address_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Address);
        let timestamp_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Timestamp);
        let prev_next = crate::trace::trace_eval_next_row!(trace_eval, Column::PrevValue);
        let is_write_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsWrite);
        let is_same_addr = crate::trace::trace_eval!(trace_eval, Column::IsSameAddrNext);
        let adv_lo = crate::trace::trace_eval!(trace_eval, Column::AdvLoH);
        let adv_hi = crate::trace::trace_eval!(trace_eval, Column::AdvHiH);
        let order_bits = crate::trace::trace_eval!(trace_eval, Column::OrderBits);

        let b256 = E::F::from(BaseField::from(256u32));
        let half = |lo: &E::F, hi: &E::F| lo.clone() + hi.clone() * b256.clone();
        let lo_diff = half(&address_next[0], &address_next[1]) - half(&address[0], &address[1]);
        let hi_diff = half(&address_next[2], &address_next[3]) - half(&address[2], &address[3]);
        for flag in [&is_same_addr[0], &adv_lo[0], &adv_hi[0]] {
            eval.add_constraint(flag.clone() * (flag.clone() - one()));
        }
        eval.add_constraint(is_same_addr[0].clone() * is_pad[0].clone());
        eval.add_constraint(is_same_addr[0].clone() * is_pad_next[0].clone());
        eval.add_constraint(is_same_addr[0].clone() * hi_diff.clone());
        eval.add_constraint(is_same_addr[0].clone() * lo_diff.clone());
        eval.add_constraint(adv_lo[0].clone() * hi_diff.clone());
        let both_real = (one() - is_pad[0].clone()) * (one() - is_pad_next[0].clone());
        eval.add_constraint(
            is_same_addr[0].clone() + adv_lo[0].clone() + adv_hi[0].clone() - both_real,
        );
        let combine_ts = |limbs: &[E::F; 8]| -> E::F {
            let mut acc = E::F::zero();
            let mut pow = one();
            for limb in limbs {
                acc += limb.clone() * pow.clone();
                pow *= b256.clone();
            }
            acc
        };
        let two = E::F::from(BaseField::from(2u32));
        let key_diff = two.clone() * (combine_ts(&timestamp_next) - combine_ts(&timestamp))
            + is_write_next[0].clone()
            - is_write[0].clone();
        let order_delta = is_same_addr[0].clone() * key_diff
            + adv_lo[0].clone() * (lo_diff - one())
            + adv_hi[0].clone() * (hi_diff - one());
        let recomposed = crate::chips::ordering::recompose(eval, &order_bits, two);
        eval.add_constraint(recomposed - order_delta);

        // Within a group, the next row's previous bytes are this row's.
        for lane in 0..WORD_BYTES {
            eval.add_constraint(
                is_same_addr[0].clone() * (prev_next[lane].clone() - value[lane].clone()),
            );
        }

        // A group starts with a ts = 0 write and ends with a closing read.
        let is_group_start = crate::trace::trace_eval!(trace_eval, Column::IsGroupStart);
        let is_group_end = crate::trace::trace_eval!(trace_eval, Column::IsGroupEnd);
        let is_real_next = one() - is_pad_next[0].clone();
        eval.add_constraint(
            is_group_start[0].clone() - is_real_next * (one() - is_same_addr[0].clone()),
        );
        eval.add_constraint(
            is_group_end[0].clone() - is_real.clone() * (one() - is_same_addr[0].clone()),
        );
        for limb in &timestamp_next {
            eval.add_constraint(is_group_start[0].clone() * limb.clone());
        }
        eval.add_constraint(is_group_start[0].clone() * (one() - is_write_next[0].clone()));
        eval.add_constraint(is_group_end[0].clone() * (one() - is_closing[0].clone()));

        // The region's permission: held along the group, a write past the
        // start needing it writable.
        let is_start_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsStart);
        let writable = crate::trace::trace_eval!(trace_eval, Column::Writable);
        let writable_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Writable);
        let permission = crate::trace::trace_eval!(trace_eval, Column::PermissionH);
        for flag in [&is_start[0], &writable[0]] {
            eval.add_constraint(flag.clone() * (flag.clone() - one()));
        }
        eval.add_constraint(is_start_next[0].clone() - is_group_start[0].clone());
        eval.add_constraint(
            permission[0].clone() - is_start[0].clone() * (one() + writable[0].clone()),
        );
        eval.add_constraint(
            is_same_addr[0].clone() * (writable_next[0].clone() - writable[0].clone()),
        );
        eval.add_constraint(
            is_write[0].clone() * (one() - is_start[0].clone()) * (one() - writable[0].clone()),
        );

        // Each lane's byte tuple, `MemoryChip`'s: (addr + lane, byte, ts,
        // is_write, 0).
        for lane in 0..WORD_BYTES {
            let mut tuple: Vec<E::F> = Vec::with_capacity(15);
            tuple.push(address[0].clone() + E::F::from(BaseField::from(lane as u32)));
            tuple.extend_from_slice(&address[1..]);
            tuple.push(value[lane].clone());
            tuple.extend_from_slice(&timestamp);
            tuple.push(is_write[0].clone());
            tuple.push(E::F::zero());
            eval.add_to_relation(RelationEntry::new(
                bytes,
                (-active[lane].clone()).into(),
                &tuple,
            ));
        }
        // The word's tuple at the group's ends: (addr, bytes, ts, is_write,
        // is_closing + 2·permission).
        let mut tuple: Vec<E::F> = address.to_vec();
        tuple.extend_from_slice(&value);
        tuple.extend_from_slice(&timestamp);
        tuple.push(is_write[0].clone());
        tuple.push(is_closing[0].clone() + permission[0].clone() + permission[0].clone());
        eval.add_to_relation(RelationEntry::new(
            words,
            (-(is_start[0].clone() + is_closing[0].clone())).into(),
            &tuple,
        ));
    }
}

/// A row of the word ledger, as its trace is generated.
#[cfg(feature = "prover")]
#[derive(Clone, Debug)]
struct Row {
    address: u32,
    value: [u8; WORD_BYTES],
    timestamp: u64,
    is_write: bool,
    active: [bool; WORD_BYTES],
    is_closing: bool,
}

/// The word ledger's rows in their order: each touched word's group, its
/// `ts = 0` write, its accesses' rows by `(timestamp, is_write)`, one a
/// `(word, timestamp, is_write)` whose lanes each take one byte tuple, and
/// its closing read.
#[cfg(feature = "prover")]
fn rows(side_note: &SideNote) -> Vec<Row> {
    let run = super::device_memory::device_run(side_note);
    let closing_ts = crate::chips::register_memory_closing::closing_ts_for(side_note);
    let word_of = |address: u32| address & !(WORD_BYTES as u32 - 1);
    let mut entries = crate::chips::memory::access_entries(side_note);
    entries.sort_by_key(|entry| (word_of(entry.address), entry.timestamp, entry.is_write));
    let mut entries = entries.into_iter().peekable();
    let mut rows = Vec::new();
    for word in &run.words {
        let mut value = word.initial;
        let row = |timestamp, is_write, value, is_closing| Row {
            address: word.address,
            value,
            timestamp,
            is_write,
            active: [false; WORD_BYTES],
            is_closing,
        };
        rows.push(row(0, true, value, false));
        let accesses = rows.len();
        while let Some(entry) = entries.next_if(|entry| word_of(entry.address) == word.address) {
            let lane = (entry.address - word.address) as usize;
            let joins = rows.len() > accesses
                && rows.last().is_some_and(|last| {
                    (last.timestamp, last.is_write) == (entry.timestamp, entry.is_write)
                        && !last.active[lane]
                });
            if !joins {
                rows.push(row(entry.timestamp, entry.is_write, value, false));
            }
            let last = rows.last_mut().expect("the access's row");
            last.active[lane] = true;
            last.value[lane] = entry.value;
            value = last.value;
        }
        // The closing read's bytes are the boundary's: a run whose
        // accesses leave others breaks a constraint here, never a relation.
        rows.push(row(closing_ts, false, word.last, true));
    }
    rows
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for WordMemoryChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _: &SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let last = trace.num_rows() - 1;
        trace.fill_columns(last, true, PreprocessedColumn::IsLast);
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let rows = rows(side_note);
        let n = rows.len();
        // At least one padding row, so the cyclic wrap to row 0 is a group
        // start and the gadget never fires across it.
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(n + 1)
            .max(LOG_N_LANES)
            .max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();
        let run = super::device_memory::device_run(side_note);
        // The region's permission, 1 readable only, 2 writable, as
        // DeviceWordMemoryChip proves it; 0 off every region, which the AIR
        // refuses.
        let permission = |address: u32| match run.layout.region_of(address) {
            None => 0u8,
            Some(region) if crate::device::region::READABLE_ONLY[region] => 1,
            Some(_) => 2,
        };
        let same_next = |row: usize| row + 1 < n && rows[row + 1].address == rows[row].address;
        for (index, row) in rows.iter().enumerate() {
            let is_start = index == 0 || rows[index - 1].address != row.address;
            let prev = if is_start {
                [0; WORD_BYTES]
            } else {
                rows[index - 1].value
            };
            trace.fill_columns_bytes(index, &row.address.to_le_bytes(), Column::Address);
            trace.fill_columns_bytes(index, &row.value, Column::Value);
            trace.fill_columns_bytes(index, &prev, Column::PrevValue);
            trace.fill_columns(index, row.timestamp, Column::Timestamp);
            trace.fill_columns(index, row.is_write, Column::IsWrite);
            let active = row.active.map(|lane| BaseField::from(u32::from(lane)));
            trace.fill_columns_base_field(index, &active, Column::Active);
            trace.fill_columns(index, same_next(index), Column::IsSameAddrNext);
            trace.fill_columns(index, false, Column::IsPadding);
            trace.fill_columns(index, row.is_closing, Column::IsClosing);
            trace.fill_columns(index, is_start, Column::IsStart);
            let permission = permission(row.address);
            trace.fill_columns(index, permission == 2, Column::Writable);
            trace.fill_columns(
                index,
                if is_start { permission } else { 0 },
                Column::PermissionH,
            );
            let taken = row.active.iter().filter(|&&lane| lane).count() as u32;
            if taken > 0 {
                trace.fill_columns(index, BaseField::from(taken).inverse(), Column::LaneInv);
            }
        }
        for index in n..num_rows {
            trace.fill_columns(index, true, Column::IsPadding);
        }
        for index in 0..num_rows {
            let next = (index + 1) % num_rows;
            let (real, next_real) = (index < n, next < n);
            let same = real && same_next(index);
            let address = |row: usize| rows.get(row).map_or(0, |row| row.address);
            let hi_eq = address(index) >> 16 == address(next) >> 16;
            let adv_lo = real && next_real && !same && hi_eq;
            let adv_hi = real && next_real && !same && !hi_eq;
            trace.fill_columns(index, adv_lo, Column::AdvLoH);
            trace.fill_columns(index, adv_hi, Column::AdvHiH);
            trace.fill_columns(index, next_real && !same, Column::IsGroupStart);
            trace.fill_columns(index, real && !same, Column::IsGroupEnd);
            let key = |row: &Row| 2 * row.timestamp + u64::from(row.is_write);
            let delta: u64 = if same {
                key(&rows[next]) - key(&rows[index])
            } else if adv_lo {
                u64::from((address(next) & 0xffff) - (address(index) & 0xffff)) - 1
            } else if adv_hi {
                u64::from((address(next) >> 16) - (address(index) >> 16)) - 1
            } else {
                0
            };
            let bits = crate::chips::ordering::bits("word memory", delta);
            trace.fill_columns_base_field(index, &bits, Column::OrderBits);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: &ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        use stwo::prover::backend::simd::m31::PackedBaseField;

        let mut logup = LogupTraceBuilder::new(component_trace.log_size());
        let bytes: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let words: &MemoryWordLookupElements = lookup_elements.as_ref();
        let address = crate::trace::original_base_column!(component_trace, Column::Address);
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
        let timestamp = crate::trace::original_base_column!(component_trace, Column::Timestamp);
        let is_write = crate::trace::original_base_column!(component_trace, Column::IsWrite);
        let active = crate::trace::original_base_column!(component_trace, Column::Active);
        let is_closing = crate::trace::original_base_column!(component_trace, Column::IsClosing);
        let is_start = crate::trace::original_base_column!(component_trace, Column::IsStart);
        let permission = crate::trace::original_base_column!(component_trace, Column::PermissionH);

        for lane in 0..WORD_BYTES {
            let (address, value, timestamp, is_write) = (
                address.clone(),
                value.clone(),
                timestamp.clone(),
                is_write.clone(),
            );
            let offset = PackedBaseField::broadcast(BaseField::from(lane as u32));
            logup.add_to_relation_computed(
                bytes,
                [active[lane].clone()],
                |[active]| (-active).into(),
                15,
                move |v| {
                    let mut tuple = Vec::with_capacity(15);
                    tuple.push(address[0].at(v) + offset);
                    tuple.extend(address[1..].iter().map(|limb| limb.at(v)));
                    tuple.push(value[lane].at(v));
                    tuple.extend(timestamp.iter().map(|limb| limb.at(v)));
                    tuple.push(is_write[0].at(v));
                    tuple.push(PackedBaseField::zero());
                    tuple
                },
            );
        }
        logup.add_to_relation_computed(
            words,
            [is_start[0].clone(), is_closing[0].clone()],
            |[start, closing]| (-(start + closing)).into(),
            4 + WORD_BYTES + 8 + 2,
            move |v| {
                let mut tuple: Vec<PackedBaseField> =
                    address.iter().map(|limb| limb.at(v)).collect();
                tuple.extend(value.iter().map(|byte| byte.at(v)));
                tuple.extend(timestamp.iter().map(|limb| limb.at(v)));
                tuple.push(is_write[0].at(v));
                tuple.push(is_closing[0].at(v) + permission[0].at(v) + permission[0].at(v));
                tuple
            },
        );
        logup.finalize()
    }
}
