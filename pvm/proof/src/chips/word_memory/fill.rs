//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

/// A row of the word ledger, as its trace is generated.
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
fn rows(side_note: &SideNote) -> Vec<Row> {
    let run = crate::chips::device_run(side_note);
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
        let run = crate::chips::device_run(side_note);
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
