#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
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
use crate::core::step::NUM_REGS;
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
use crate::{framework::BuiltInComponent, lookups::RegisterMemoryLookupElements};

/// RegisterMemoryChip: PVM register-file ledger, analogous to MemoryChip but
/// indexed by register number (0..NUM_REGS-1) and valued as full u64s.
///
/// The initial-state writes (ts=0, from SideNote.initial_regs) and the CpuChip
/// register-access emissions populate the ledger.  The ledger entries are
/// sorted by (reg_addr, timestamp, is_write) and the read-consistency
/// constraint fires when a read is preceded by a same-register entry (forcing
/// read value = previous value).  A step that reads and writes one register
/// reads it first: within a timestamp, reads sort before writes, so a read
/// returns the value before its step.
pub struct RegisterMemoryChip;

/// Ordering deltas must fit below this bit width. A same-register delta is
/// `2·ts_diff + is_write_diff`, so twenty-eight bits cover a register left
/// untouched for 2^27 steps, past the canonical actor-proof budget (<100M
/// steps), while staying far enough below the M31 modulus to reject a
/// field-wrapped negative as an alleged positive.
const ORDER_DELTA_BITS: usize = 28;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Register index.  `#[mask_next_row]` so the read-consistency /
    /// sortedness gadget can read the next ledger row's register.
    #[size = 1]
    #[mask_next_row]
    RegAddr,
    /// u64 value as 8 LE bytes.
    #[size = 8]
    Value,
    /// Timestamp (u64, 8 LE bytes).  Sort anchor — the row's position in
    /// the ledger is determined by `(RegAddr, Ts0)`, and each real row
    /// consumes one access.  `#[mask_next_row]` so the sortedness gadget can
    /// read the next row's timestamp.
    #[size = 8]
    #[mask_next_row]
    Ts0,
    /// 1 = write, 0 = read, a bit.  `#[mask_next_row]`: within a
    /// timestamp, the ordering gadget sorts a register's reads before its
    /// writes, and a register's first row is a write.
    #[size = 1]
    #[mask_next_row]
    IsWrite,
    /// Previous value at same register (u64, 8 bytes).  0 on the first entry
    /// per register.  `#[mask_next_row]` so a row can bind the *next* row's
    /// `prev_value` to this row's `value` (cross-row read-consistency).
    #[size = 8]
    #[mask_next_row]
    PrevValue,
    /// Bound boolean: 1 iff the next ledger row is real and accesses the same
    /// register. Pinned by the sortedness gadget (`IsSameRegNext · key_diff =
    /// 0` and the range-checked `OrderDelta`); it gates the cross-row
    /// `prev_value` value binding.
    #[size = 1]
    IsSameRegNext,
    /// 1 if padding row (beyond real ledger entries).  `#[mask_next_row]` so a
    /// row can tell whether its successor is real (the sortedness/value gadget
    /// only fires between two real rows).
    #[size = 1]
    #[mask_next_row]
    IsPadding,
    /// 28-bit little-endian decomposition of the per-transition ordering delta
    /// `OrderDelta = both_real · (IsSameRegNext·(2·ts_diff + is_write_diff) +
    /// (1−IsSameRegNext)·(reg_diff−1))`.  Each bit is constrained boolean and recomposed; this is
    /// a SELF-CONTAINED non-negativity range-check (no Range256 lookup — the
    /// consumer pass runs with an immutable `&SideNote` and cannot bump
    /// multiplicities).  28 bits covers every timestamp admitted by the
    /// canonical 100M-gas actor-proof budget and `reg_diff − 1 < NUM_REGS`.
    /// `2^28 < p/4`, so a field-wrapped negative (≈ p − small) cannot alias a
    /// valid positive in the admitted range.
    #[size = 28]
    OrderBits,
    /// Helper (degree flattening, so all constraints stay ≤ degree 2):
    /// `BothRealH = (1−IsPadding)·(1−IsPadding_next)` — 1 iff this row and its
    /// successor are both real.  Gates the ordering range-check off padding
    /// boundaries and the cyclic last→row-0 wraparound.
    #[size = 1]
    BothRealH,
    /// Helper (degree flattening): `OrderValH = IsSameRegNext·(2·ts_diff +
    /// is_write_diff) + (1−IsSameRegNext)·(reg_diff−1)`, the un-gated
    /// ordering value.  The range-checked OrderDelta is `BothRealH ·
    /// OrderValH`.
    #[size = 1]
    OrderValH,
    /// BOUND helper `ChainStartH = (1 − IsPadding_next)·(1 − IsSameRegNext)`:
    /// 1 iff the next row is real and starts its register's chain of
    /// same-register rows, which must be that register's `ts = 0` write.
    /// A register has one such write, so one chain: wherever padding
    /// interrupts the sortedness gadget, the rows after it start a chain
    /// with no write to start it.
    #[size = 1]
    ChainStartH,
    // Read-consistency uses an unconditional
    // `(1 - is_write) · (value[i] - prev_value[i]) = 0` per byte (no
    // gating helper column).  Padding rows have value=prev_value=0 so
    // 1·0=0 holds.
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "regmem"]
pub enum PreprocessedColumn {}

/// A single register-level ledger entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegEntry {
    pub reg_addr: u8,
    pub value: u64,
    pub timestamp: u64,
    pub is_write: bool,
}

impl BuiltInComponent for RegisterMemoryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = RegisterMemoryLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RegisterMemoryLookupElements,
    ) {
        let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();

        let reg_addr = crate::trace::trace_eval!(trace_eval, Column::RegAddr);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let ts0 = crate::trace::trace_eval!(trace_eval, Column::Ts0);
        let is_write = crate::trace::trace_eval!(trace_eval, Column::IsWrite);
        let prev_value = crate::trace::trace_eval!(trace_eval, Column::PrevValue);

        // IsPadding ∈ {0, 1}: a padding flag of 2 would make a row's
        // multiplicity `1 − IsPadding` a producer and BothRealH negative.
        eval.add_constraint(is_pad[0].clone() * (is_pad[0].clone() - E::F::one()));

        // IsWrite ∈ {0, 1}: the key `2·ts + is_write` takes it as a bit.
        eval.add_constraint(is_write[0].clone() * (is_write[0].clone() - E::F::one()));

        // Read consistency: a read's value is its prev_value, enforced
        // unconditionally per byte.
        let is_read = E::F::one() - is_write[0].clone();
        for i in 0..8 {
            eval.add_constraint(is_read.clone() * (value[i].clone() - prev_value[i].clone()));
        }

        // ── Cross-row read-consistency + (reg, ts) sortedness gadget ─────
        // The ledger is sorted by (RegAddr, Ts0).  These constraints pin that
        // ordering and bind each read to the immediately-preceding same-reg
        // row, closing the read-consistency soundness gap (see
        // docs/design/ledger-read-consistency.md).  All
        // constraints stay ≤ degree 2 (this chip can't raise
        // LOG_CONSTRAINT_DEGREE_BOUND), via the BothRealH / OrderValH helpers.
        let is_pad_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsPadding);
        let reg_addr_next = crate::trace::trace_eval_next_row!(trace_eval, Column::RegAddr);
        let ts0_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Ts0);
        let prev_value_next = crate::trace::trace_eval_next_row!(trace_eval, Column::PrevValue);
        let order_bits = crate::trace::trace_eval!(trace_eval, Column::OrderBits);
        let is_same_reg = crate::trace::trace_eval!(trace_eval, Column::IsSameRegNext);
        let both_real_h = crate::trace::trace_eval!(trace_eval, Column::BothRealH);
        let order_val_h = crate::trace::trace_eval!(trace_eval, Column::OrderValH);

        // `key_same` (= IsSameRegNext) is a bound boolean: it can be 1 only
        // when this row and its successor are both real and same-register.
        eval.add_constraint(is_same_reg[0].clone() * (is_same_reg[0].clone() - E::F::one()));
        eval.add_constraint(is_same_reg[0].clone() * is_pad[0].clone());
        eval.add_constraint(is_same_reg[0].clone() * is_pad_next[0].clone());
        let reg_diff = reg_addr_next[0].clone() - reg_addr[0].clone();
        eval.add_constraint(is_same_reg[0].clone() * reg_diff.clone());

        // BothRealH = (1−IsPadding)·(1−IsPadding_next): 1 iff both rows real.
        eval.add_constraint(
            both_real_h[0].clone()
                - (E::F::one() - is_pad[0].clone()) * (E::F::one() - is_pad_next[0].clone()),
        );

        // OrderValH = key_same·ts_diff + (1−key_same)·(reg_diff−1).
        let combine_ts = |bytes: &[E::F; 8]| -> E::F {
            let b256 = E::F::from(BaseField::from(256u32));
            let mut acc = E::F::zero();
            let mut pow = E::F::one();
            for b in bytes {
                acc += b.clone() * pow.clone();
                pow *= b256.clone();
            }
            acc
        };
        // Within one register the key is `2·ts + is_write`: timestamps
        // non-decreasing, and at one timestamp no read after a write. A step
        // that reads and writes a register (an ALU op whose destination is
        // a source, a witness input's φ7) then reads the value from before
        // it, never the one it writes.
        let is_write_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsWrite);
        let ts_diff = combine_ts(&ts0_next) - combine_ts(&ts0);
        let key_diff = ts_diff.clone() + ts_diff + is_write_next[0].clone() - is_write[0].clone();
        eval.add_constraint(
            order_val_h[0].clone()
                - (is_same_reg[0].clone() * key_diff
                    + (E::F::one() - is_same_reg[0].clone()) * (reg_diff - E::F::one())),
        );

        // OrderDelta = BothRealH · OrderValH, range-checked ≥ 0 via a 28-bit
        // decomposition (self-contained — no Range256 lookup, the consumer pass
        // runs with an immutable `&SideNote`; 28 bits < p/4 so a field-wrapped
        // negative cannot alias a valid small positive).  Then:
        //   key_same=1 ⇒ (ts, is_write) non-decreasing (2·ts_diff +
        //     is_write_diff ≥ 0), so a write never precedes a read at its ts.
        //   key_same=0, both real ⇒ reg strictly increases (reg_diff ≥ 1) ⇒
        //     registers are contiguous (no value-chain bleed) AND key_same is
        //     forced truthful (claiming 0 on equal regs yields −1, which has no
        //     28-bit decomposition).
        let two = E::F::from(BaseField::from(2u32));
        let mut recomposed = E::F::zero();
        let mut pow2 = E::F::one();
        for bit in &order_bits {
            eval.add_constraint(bit.clone() * (bit.clone() - E::F::one()));
            recomposed += bit.clone() * pow2.clone();
            pow2 *= two.clone();
        }
        eval.add_constraint(recomposed - both_real_h[0].clone() * order_val_h[0].clone());

        // Cross-row value binding: when the next row is the same register, its
        // prev_value must equal THIS row's value.  Combined with the per-byte
        // read-consistency above, this forces every read to return the
        // most-recent same-reg value (a real write or the initial state).
        for k in 0..8 {
            eval.add_constraint(
                is_same_reg[0].clone() * (prev_value_next[k].clone() - value[k].clone()),
            );
        }

        // ── Chains ──────────────────────────────────────────────────────
        // A register's rows form one chain, started by its ts = 0 write: a
        // row whose predecessor is not a same-register real row is a write
        // at ts 0, and the boundary chip produces one per register. So no
        // padding row can split a register's accesses into a second chain,
        // unordered against the first, whose reads take a previous value
        // nothing binds; the cyclic wrap from the trailing padding row makes
        // row 0 a chain's start too.
        let chain_start = crate::trace::trace_eval!(trace_eval, Column::ChainStartH);
        eval.add_constraint(
            chain_start[0].clone()
                - (E::F::one() - is_pad_next[0].clone()) * (E::F::one() - is_same_reg[0].clone()),
        );
        for limb in &ts0_next {
            eval.add_constraint(chain_start[0].clone() * limb.clone());
        }
        eval.add_constraint(chain_start[0].clone() * (E::F::one() - is_write_next[0].clone()));

        // ── Consumer emission ───────────────────────────────────────────
        // One access per real row: (reg_addr[1], value[8], ts[8],
        // is_write[1]). EMISSION ORDER MUST MATCH
        // `generate_interaction_trace` exactly.
        let mut tuple: Vec<E::F> = Vec::with_capacity(18);
        tuple.push(reg_addr[0].clone());
        tuple.extend_from_slice(&value);
        tuple.extend_from_slice(&ts0);
        // is_write is part of the tuple (binds read/write so a read can't
        // masquerade as a write to skip read-consistency).
        tuple.push(is_write[0].clone());
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real.clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
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
            assert!(
                order_delta < (1u64 << ORDER_DELTA_BITS),
                "register ordering delta {order_delta} exceeds the {ORDER_DELTA_BITS}-bit proof bound"
            );
            let bits: [BaseField; ORDER_DELTA_BITS] =
                core::array::from_fn(|b| BaseField::from(((order_delta >> b) & 1) as u32));
            trace.fill_columns_base_field(row, &bits, Column::OrderBits);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
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

/// Compile-time check that NUM_REGS fits in a single byte for RegAddr.
const _: [(); (NUM_REGS <= u8::MAX as usize) as usize - 1] = [];

/// Build the (reg, ts)-sorted list of register-memory ledger entries that
/// `generate_main_trace_immut_min` fills, one per row; the gates build it too.
#[cfg(feature = "prover")]
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
