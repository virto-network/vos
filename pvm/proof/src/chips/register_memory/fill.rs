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

/// A single register-level ledger entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegEntry {
    pub reg_addr: u8,
    pub value: u64,
    pub timestamp: u64,
    pub is_write: bool,
}

impl BuiltInProverComponent for RegisterMemoryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        // The (reg, ts)-sorted single-entry ledger.
        let entries = build_entries_from_side_note(side_note);

        if entries.is_empty() {
            let log_size = LOG_N_LANES.max(min_log_size);
            let mut trace = TraceBuilder::<Column>::new(log_size);
            for row in 0..trace.num_rows() {
                trace.fill_columns(row, true, Column::IsPadding);
            }
            return trace.finalize_bit_reversed();
        }

        // One entry per row, sorted by (reg, ts): each row consumes one
        // access, which its place in its register's chain orders. A merged
        // row spanning several timestamps would need per-slot ordering and
        // a link to the next row, which the AIR has not
        // (docs/design/ledger-read-consistency.md, (D)).
        let num_rows_real = entries.len();
        let mut log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_rows_real);
        // Guarantee ≥ 1 padding row so the cyclic last→row-0 wraparound is always
        // a padding row (is_pad = 1 ⇒ both_real = 0): the sortedness gadget must
        // NOT fire across the wraparound (the last real reg → reg 0 would look
        // like a backwards key step).
        if (1usize << log_size) == num_rows_real {
            log_size += 1;
        }
        let log_size = log_size.max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        // Pass 1: base columns.  Track per-row (reg, ts, key_same) so the
        // ordering helpers (pass 2) can read the cyclic next row.
        let mut regs = vec![0u8; num_rows];
        let mut tss = vec![0u64; num_rows];
        let mut writes = vec![false; num_rows];
        let mut key_same = vec![false; num_rows];
        for (row, e) in entries.iter().enumerate() {
            trace.fill_columns(row, e.reg_addr, Column::RegAddr);
            trace.fill_columns(row, e.value, Column::Value);
            trace.fill_columns(row, e.timestamp, Column::Ts0);
            trace.fill_columns(row, e.is_write, Column::IsWrite);

            // prev_value = previous ledger row's value when same register; the
            // sortedness gadget binds the NEXT row's prev_value to this row's
            // value, so the honest filler must agree with that ordering.
            let prev_value: u64 = if row > 0 && entries[row - 1].reg_addr == e.reg_addr {
                entries[row - 1].value
            } else {
                0
            };
            trace.fill_columns(row, prev_value, Column::PrevValue);

            // key_same = next row real AND same register (a bound boolean).
            let same_reg_next = row + 1 < num_rows_real && entries[row + 1].reg_addr == e.reg_addr;
            trace.fill_columns(row, same_reg_next, Column::IsSameRegNext);
            trace.fill_columns(row, false, Column::IsPadding);

            regs[row] = e.reg_addr;
            tss[row] = e.timestamp;
            writes[row] = e.is_write;
            key_same[row] = same_reg_next;
        }
        for row in num_rows_real..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
            // regs/tss/key_same stay 0/false for padding rows.
        }

        // Pass 2: ordering helpers, reading the cyclic next = (row+1) % num_rows.
        //   BothRealH = both rows real.
        //   OrderValH = key_same·(2·ts_diff + is_write_diff)
        //               + (1−key_same)·(reg_diff−1)  [in field; may be negative
        //               on padding/wraparound rows, where BothRealH = 0 gates
        //               OrderDelta to 0].
        //   OrderDelta = BothRealH·OrderValH, 28-bit range-checked ≥ 0.
        let one = BaseField::from(1u32);
        for row in 0..num_rows {
            let next = (row + 1) % num_rows;
            let both_real = row < num_rows_real && next < num_rows_real;
            trace.fill_columns(row, both_real, Column::BothRealH);
            trace.fill_columns(
                row,
                next < num_rows_real && !key_same[row],
                Column::ChainStartH,
            );

            // Within a register, the key `2·ts + is_write`.
            let key = |row: usize| 2 * tss[row] + u64::from(writes[row]);
            let order_val_h: BaseField = if key_same[row] {
                BaseField::from((key(next) - key(row)) as u32)
            } else {
                BaseField::from(regs[next] as u32) - BaseField::from(regs[row] as u32) - one
            };
            trace.fill_columns_base_field(row, &[order_val_h], Column::OrderValH);

            let order_delta: u64 = if !both_real {
                0
            } else if key_same[row] {
                key(next) - key(row)
            } else {
                (regs[next] as u64) - (regs[row] as u64) - 1
            };
            let bits = super::super::ordering::bits("register", order_delta);
            trace.fill_columns_base_field(row, &bits, Column::OrderBits);
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
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let reg_lookup: &RegisterMemoryLookupElements = lookup_elements.as_ref();
        let is_pad = crate::trace::original_base_column!(component_trace, Column::IsPadding);
        let reg_addr = crate::trace::original_base_column!(component_trace, Column::RegAddr);
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
        let ts0 = crate::trace::original_base_column!(component_trace, Column::Ts0);
        let is_write = crate::trace::original_base_column!(component_trace, Column::IsWrite);

        // One emission per real row: (reg_addr[1], value[8], ts[8],
        // is_write[1]) = 18 limbs. EMISSION ORDER MUST MATCH the AIR side.
        let mut tuple: Vec<_> = Vec::with_capacity(18);
        tuple.push(reg_addr[0].clone());
        tuple.extend_from_slice(&value);
        tuple.extend_from_slice(&ts0);
        tuple.push(is_write[0].clone());
        logup.add_to_relation_with(
            reg_lookup,
            [is_pad[0].clone()],
            |[pad]| (-(PackedBaseField::one() - pad)).into(),
            &tuple,
        );

        logup.finalize()
    }
}

/// Build the (reg, ts)-sorted list of register-memory ledger entries that
/// `generate_main_trace_immut_min` fills, one per row; the gates build it too.
pub fn build_entries_from_side_note(side_note: &crate::side_note::SideNote) -> Vec<RegEntry> {
    let mut entries: Vec<RegEntry> = Vec::new();

    for (i, &val) in side_note.initial_regs.iter().enumerate() {
        entries.push(RegEntry {
            reg_addr: i as u8,
            value: val,
            timestamp: 0,
            is_write: true,
        });
    }

    for step in &side_note.steps {
        let acc = crate::chips::cpu::step_reg_accesses(step);
        if let Some((reg_idx, val)) = acc.val_b_read {
            entries.push(RegEntry {
                reg_addr: reg_idx,
                value: val,
                timestamp: step.timestamp,
                is_write: false,
            });
        }
        if let Some((reg_idx, val)) = acc.val_d_read {
            entries.push(RegEntry {
                reg_addr: reg_idx,
                value: val,
                timestamp: step.timestamp,
                is_write: false,
            });
        }
        if let Some((reg_idx, val)) = acc.val_a_read {
            entries.push(RegEntry {
                reg_addr: reg_idx,
                value: val,
                timestamp: step.timestamp,
                is_write: false,
            });
            entries.push(RegEntry {
                reg_addr: reg_idx,
                value: val,
                timestamp: step.timestamp,
                is_write: false,
            });
        }
        for &(reg_idx, val) in &acc.ecall_reads {
            entries.push(RegEntry {
                reg_addr: reg_idx,
                value: val,
                timestamp: step.timestamp,
                is_write: false,
            });
        }
        if let Some((reg_idx, val)) = acc.result_write {
            entries.push(RegEntry {
                reg_addr: reg_idx,
                value: val,
                timestamp: step.timestamp,
                is_write: true,
            });
        }
    }

    // Synthetic closing-read entries — one per register at
    // ts=closing_ts. Pair with `RegisterMemoryClosingChip`'s producer
    // emissions to consume them; read-consistency in this chip then
    // forces each row's value to equal the previous ledger row's
    // value (= the actual last write/initial value of that register),
    // pinning `side_note.final_regs` to the trace's true final state.
    //
    // No-op for empty traces (no steps ⇒ no closing chip producers
    // ⇒ no consumers needed) and for chip-isolated harnesses that
    // didn't add the closing chip to their component slice (would
    // emit unbalanced consumers and trip "claimed logup sum is not
    // zero"). Otherwise `closing_ts > step.timestamp` for every real
    // step, so the synthetic entries sort strictly after every real
    // access and the prev_value chain works.
    if side_note.closing_chip_active && !side_note.steps.is_empty() {
        let closing_ts = crate::chips::register_memory_closing::closing_ts_for(side_note);
        for (i, &val) in side_note.final_regs.iter().enumerate() {
            entries.push(RegEntry {
                reg_addr: i as u8,
                value: val,
                timestamp: closing_ts,
                is_write: false,
            });
        }
    }

    entries.sort_by_key(|e| (e.reg_addr, e.timestamp, e.is_write));
    entries
}
