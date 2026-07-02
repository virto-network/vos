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
/// sorted by (reg_addr, timestamp) and the read-consistency constraint fires
/// when a read is preceded by a same-register entry (forcing read value =
/// previous value).
pub struct RegisterMemoryChip;

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
    /// Slot 0 timestamp (u64, 8 LE bytes).  Sort anchor — the row's
    /// position in the ledger is determined by `(RegAddr, Ts0)`.  Slot 0
    /// is gated on `is_real = 1 - IsPadding`; on real rows, this slot
    /// always emits one consumer fraction.  `#[mask_next_row]` so the
    /// sortedness gadget can read the next row's timestamp.
    #[size = 8]
    #[mask_next_row]
    Ts0,
    /// Slot 1 timestamp.  Emits a consumer fraction iff `SlotReal1 = 1`.
    /// On unmerged rows (or writes), zero-fill.
    #[size = 8]
    Ts1,
    /// Slot 2 timestamp.  Emits iff `SlotReal2 = 1`.
    #[size = 8]
    Ts2,
    /// Slot 3 timestamp.  Emits iff `SlotReal3 = 1`.
    #[size = 8]
    Ts3,
    /// Booleans gating slots 1..=3 emissions.  Together with `is_real`
    /// (= slot-0 gate), the per-row multiplicity is
    /// `mult = is_real + SlotReal1 + SlotReal2 + SlotReal3 ∈ 0..=4`.
    /// Constraints enforce range + write-only-uses-slot-0 + padding-zero.
    #[size = 1]
    SlotReal1,
    #[size = 1]
    SlotReal2,
    #[size = 1]
    SlotReal3,
    /// 1 = write, 0 = read.
    #[size = 1]
    IsWrite,
    /// Previous value at same register (u64, 8 bytes).  0 on the first entry
    /// per register.  `#[mask_next_row]` so a row can bind the *next* row's
    /// `prev_value` to this row's `value` (cross-row read-consistency).
    #[size = 8]
    #[mask_next_row]
    PrevValue,
    /// BOUND boolean: 1 iff the next ledger row is real AND accesses the same
    /// register.  No longer a free witness — pinned by the sortedness gadget
    /// (`IsSameRegNext · key_diff = 0` and the range-checked `OrderDelta`), and
    /// it gates the cross-row `prev_value` value binding.
    #[size = 1]
    IsSameRegNext,
    /// 1 if padding row (beyond real ledger entries).  `#[mask_next_row]` so a
    /// row can tell whether its successor is real (the sortedness/value gadget
    /// only fires between two real rows).
    #[size = 1]
    #[mask_next_row]
    IsPadding,
    /// 24-bit little-endian decomposition of the per-transition ordering delta
    /// `OrderDelta = both_real · (IsSameRegNext·ts_diff + (1−IsSameRegNext)·
    /// (reg_diff−1))`.  Each bit is constrained boolean and recomposed; this is
    /// a SELF-CONTAINED non-negativity range-check (no Range256 lookup — the
    /// consumer pass runs with an immutable `&SideNote` and cannot bump
    /// multiplicities).  24 bits covers `ts_diff < 2^24` and `reg_diff − 1 <
    /// NUM_REGS`, and `2^24 ≪ p` so a field-wrapped negative (≈ p − small ≈
    /// 2^31, needing 31 bits) cannot alias a valid small positive.
    #[size = 24]
    OrderBits,
    /// Helper (degree flattening, so all constraints stay ≤ degree 2):
    /// `BothRealH = (1−IsPadding)·(1−IsPadding_next)` — 1 iff this row and its
    /// successor are both real.  Gates the ordering range-check off padding
    /// boundaries and the cyclic last→row-0 wraparound.
    #[size = 1]
    BothRealH,
    /// Helper (degree flattening): `OrderValH = IsSameRegNext·ts_diff +
    /// (1−IsSameRegNext)·(reg_diff−1)`, the un-gated ordering value.  The
    /// range-checked OrderDelta is `BothRealH · OrderValH`.
    #[size = 1]
    OrderValH,
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
        let ts1 = crate::trace::trace_eval!(trace_eval, Column::Ts1);
        let ts2 = crate::trace::trace_eval!(trace_eval, Column::Ts2);
        let ts3 = crate::trace::trace_eval!(trace_eval, Column::Ts3);
        let slot1 = crate::trace::trace_eval!(trace_eval, Column::SlotReal1);
        let slot2 = crate::trace::trace_eval!(trace_eval, Column::SlotReal2);
        let slot3 = crate::trace::trace_eval!(trace_eval, Column::SlotReal3);
        let is_write = crate::trace::trace_eval!(trace_eval, Column::IsWrite);
        let prev_value = crate::trace::trace_eval!(trace_eval, Column::PrevValue);

        // ── Slot-real flag invariants ────────────────────────────────
        // Each SlotReal_i ∈ {0, 1}: bool · (bool − 1) = 0.
        eval.add_constraint(slot1[0].clone() * (slot1[0].clone() - E::F::one()));
        eval.add_constraint(slot2[0].clone() * (slot2[0].clone() - E::F::one()));
        eval.add_constraint(slot3[0].clone() * (slot3[0].clone() - E::F::one()));
        // Padding rows have all extra slots inactive — otherwise a padding
        // row could spuriously emit consumer fractions and skew balance.
        eval.add_constraint(is_pad[0].clone() * slot1[0].clone());
        eval.add_constraint(is_pad[0].clone() * slot2[0].clone());
        eval.add_constraint(is_pad[0].clone() * slot3[0].clone());
        // Writes use only slot 0 (mult = 1 always — writes change the
        // value, breaking any merge run).  Combined with `is_real`
        // gating slot 0, this forces writes to multiplicity 1.
        eval.add_constraint(is_write[0].clone() * slot1[0].clone());
        eval.add_constraint(is_write[0].clone() * slot2[0].clone());
        eval.add_constraint(is_write[0].clone() * slot3[0].clone());

        // Read consistency: for a read (is_write=0) that follows a same-reg
        // entry, the byte-wise value must equal prev_value.  The merge
        // collapses only same-VALUE read runs, so a merged read row's value
        // matches the run's first slot's value and the prev-value lookup
        // against the previous ledger row works unchanged.  Enforced
        // unconditionally per byte.
        let is_read = E::F::one() - is_write[0].clone();
        for i in 0..8 {
            eval.add_constraint(is_read.clone() * (value[i].clone() - prev_value[i].clone()));
        }

        // ── Cross-row read-consistency + (reg, ts) sortedness gadget ─────
        // The ledger is sorted by (RegAddr, Ts0).  These constraints pin that
        // ordering and bind each read to the immediately-preceding same-reg
        // row, closing the read-consistency soundness gap (see
        // docs/plans/ledger-read-consistency.md).  All
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

        // `key_same` (= IsSameRegNext) is now a BOUND boolean: it can be 1 only
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
        let ts_diff = combine_ts(&ts0_next) - combine_ts(&ts0);
        eval.add_constraint(
            order_val_h[0].clone()
                - (is_same_reg[0].clone() * ts_diff
                    + (E::F::one() - is_same_reg[0].clone()) * (reg_diff - E::F::one())),
        );

        // OrderDelta = BothRealH · OrderValH, range-checked ≥ 0 via a 24-bit
        // decomposition (self-contained — no Range256 lookup, the consumer pass
        // runs with an immutable `&SideNote`; 24 bits ≪ p so a field-wrapped
        // negative cannot alias a valid small positive).  Then:
        //   key_same=1 ⇒ ts non-decreasing (ts_diff ≥ 0).
        //   key_same=0, both real ⇒ reg strictly increases (reg_diff ≥ 1) ⇒
        //     registers are contiguous (no value-chain bleed) AND key_same is
        //     forced truthful (claiming 0 on equal regs yields −1, which has no
        //     24-bit decomposition).
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

        // ── Per-slot consumer emissions ─────────────────────────────────
        // 4 fractions per row, paired by `finalize_logup_in_pairs`.
        // Slot 0 gate = is_real; slots 1..=3 gate = SlotReal_i.
        // Tuple shape unchanged: (reg_addr[1], value[8], ts[8]).
        // EMISSION ORDER MUST MATCH `generate_interaction_trace` exactly.
        let push_tuple = |dst: &mut Vec<E::F>, ts: &[E::F; 8]| {
            dst.push(reg_addr[0].clone());
            for col in &value {
                dst.push(col.clone());
            }
            for col in ts {
                dst.push(col.clone());
            }
            // is_write is part of the tuple (binds read/write so a read can't
            // masquerade as a write to skip read-consistency).
            dst.push(is_write[0].clone());
        };
        // Slot 0.
        let mut tuple0: Vec<E::F> = Vec::with_capacity(17);
        push_tuple(&mut tuple0, &ts0);
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real.clone()).into(),
            &tuple0,
        ));
        // Slot 1.
        let mut tuple1: Vec<E::F> = Vec::with_capacity(17);
        push_tuple(&mut tuple1, &ts1);
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-slot1[0].clone()).into(),
            &tuple1,
        ));
        // Slot 2.
        let mut tuple2: Vec<E::F> = Vec::with_capacity(17);
        push_tuple(&mut tuple2, &ts2);
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-slot2[0].clone()).into(),
            &tuple2,
        ));
        // Slot 3.
        let mut tuple3: Vec<E::F> = Vec::with_capacity(17);
        push_tuple(&mut tuple3, &ts3);
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-slot3[0].clone()).into(),
            &tuple3,
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RegisterMemoryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        // Build (reg, ts)-sorted single-entry ledger via the shared helper
        // that the analyzer and property tests also use — keeps the three
        // call sites byte-for-byte aligned.
        let entries = build_entries_from_side_note(side_note);

        if entries.is_empty() {
            let log_size = LOG_N_LANES;
            let mut trace = TraceBuilder::<Column>::new(log_size);
            for row in 0..trace.num_rows() {
                trace.fill_columns(row, true, Column::IsPadding);
            }
            return trace.finalize_bit_reversed();
        }

        // The read-run merge is DISABLED: the ledger carries one entry per
        // row, sorted by (reg, ts).  This keeps the sortedness argument that
        // pins read-consistency (below) auditable — a merged row spanning
        // multiple timestamps would need per-slot monotonicity + an
        // overlap-forbidding constraint.  `merge_entries` and its property
        // tests stay (uncalled) as documentation of the merge optimisation.
        // See docs/plans/ledger-read-consistency.md.
        let num_rows_real = entries.len();
        let mut log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_rows_real);
        // Guarantee ≥ 1 padding row so the cyclic last→row-0 wraparound is always
        // a padding row (is_pad = 1 ⇒ both_real = 0): the sortedness gadget must
        // NOT fire across the wraparound (the last real reg → reg 0 would look
        // like a backwards key step).
        if (1usize << log_size) == num_rows_real {
            log_size += 1;
        }
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        // Pass 1: base columns.  Track per-row (reg, ts, key_same) so the
        // ordering helpers (pass 2) can read the cyclic next row.
        let mut regs = vec![0u8; num_rows];
        let mut tss = vec![0u64; num_rows];
        let mut key_same = vec![false; num_rows];
        for (row, e) in entries.iter().enumerate() {
            trace.fill_columns(row, e.reg_addr, Column::RegAddr);
            trace.fill_columns(row, e.value, Column::Value);
            trace.fill_columns(row, e.timestamp, Column::Ts0);
            // Ts1..3 / SlotReal1..3 stay zero (merge disabled — one entry/row).
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
            key_same[row] = same_reg_next;
        }
        for row in num_rows_real..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
            // regs/tss/key_same stay 0/false for padding rows.
        }

        // Pass 2: ordering helpers, reading the cyclic next = (row+1) % num_rows.
        //   BothRealH = both rows real.
        //   OrderValH = key_same·ts_diff + (1−key_same)·(reg_diff−1)  [in field;
        //               may be negative on padding/wraparound rows, where
        //               BothRealH = 0 gates OrderDelta to 0].
        //   OrderDelta = BothRealH·OrderValH, 24-bit range-checked ≥ 0.
        let one = BaseField::from(1u32);
        for row in 0..num_rows {
            let next = (row + 1) % num_rows;
            let both_real = row < num_rows_real && next < num_rows_real;
            trace.fill_columns(row, both_real, Column::BothRealH);

            let order_val_h: BaseField = if key_same[row] {
                BaseField::from((tss[next] - tss[row]) as u32)
            } else {
                BaseField::from(regs[next] as u32) - BaseField::from(regs[row] as u32) - one
            };
            trace.fill_columns_base_field(row, &[order_val_h], Column::OrderValH);

            let order_delta: u64 = if !both_real {
                0
            } else if key_same[row] {
                tss[next] - tss[row]
            } else {
                (regs[next] as u64) - (regs[row] as u64) - 1
            };
            let bits: [BaseField; 24] =
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
        let ts1 = crate::trace::original_base_column!(component_trace, Column::Ts1);
        let ts2 = crate::trace::original_base_column!(component_trace, Column::Ts2);
        let ts3 = crate::trace::original_base_column!(component_trace, Column::Ts3);
        let slot1 = crate::trace::original_base_column!(component_trace, Column::SlotReal1);
        let slot2 = crate::trace::original_base_column!(component_trace, Column::SlotReal2);
        let slot3 = crate::trace::original_base_column!(component_trace, Column::SlotReal3);
        let is_write = crate::trace::original_base_column!(component_trace, Column::IsWrite);

        // 4 emissions per row (one per slot), paired by `add_constraints`'s
        // `finalize_logup_in_pairs`.  Tuple shape:
        //   (reg_addr[1], value[8], ts[8], is_write[1]) = 18 limbs.
        // Slot 0 gate = is_real = 1 - is_pad.
        // Slot i (i=1,2,3) gate = SlotReal_i.
        // EMISSION ORDER MUST MATCH the AIR side exactly.
        let mut tuple0: Vec<_> = Vec::with_capacity(18);
        tuple0.push(reg_addr[0].clone());
        tuple0.extend_from_slice(&value);
        tuple0.extend_from_slice(&ts0);
        tuple0.push(is_write[0].clone());
        logup.add_to_relation_with(
            reg_lookup,
            [is_pad[0].clone()],
            |[pad]| (-(PackedBaseField::one() - pad)).into(),
            &tuple0,
        );

        let mut tuple1: Vec<_> = Vec::with_capacity(18);
        tuple1.push(reg_addr[0].clone());
        tuple1.extend_from_slice(&value);
        tuple1.extend_from_slice(&ts1);
        tuple1.push(is_write[0].clone());
        logup.add_to_relation_with(reg_lookup, [slot1[0].clone()], |[s]| (-s).into(), &tuple1);

        let mut tuple2: Vec<_> = Vec::with_capacity(18);
        tuple2.push(reg_addr[0].clone());
        tuple2.extend_from_slice(&value);
        tuple2.extend_from_slice(&ts2);
        tuple2.push(is_write[0].clone());
        logup.add_to_relation_with(reg_lookup, [slot2[0].clone()], |[s]| (-s).into(), &tuple2);

        let mut tuple3: Vec<_> = Vec::with_capacity(18);
        tuple3.push(reg_addr[0].clone());
        tuple3.extend_from_slice(&value);
        tuple3.extend_from_slice(&ts3);
        tuple3.push(is_write[0].clone());
        logup.add_to_relation_with(reg_lookup, [slot3[0].clone()], |[s]| (-s).into(), &tuple3);

        logup.finalize()
    }
}

/// Compile-time check that NUM_REGS fits in a single byte for RegAddr.
const _: [(); (NUM_REGS <= u8::MAX as usize) as usize - 1] = [];

/// Dedup-feasibility report — counts how many entries in the (reg, ts)-sorted
/// register-memory ledger fall into runs of consecutive same-(reg, value) reads,
/// and what the resulting `log_size` would be if every such run were merged into
/// a single multiplicity-bearing row.  Used to decide whether a merged-row
/// chip-shrink pencils out before committing to the constraint redesign it needs.
#[derive(Debug, Default, Clone)]
pub struct RegisterDedupReport {
    /// Total ledger entries today (initial-state writes + every CpuChip read/write).
    pub total_entries: usize,
    /// Ledger entries after collapsing each run of consecutive same-(reg, value)
    /// reads into a single row.  Writes are always preserved.
    pub after_dedup: usize,
    /// `total_entries - after_dedup`.
    pub saved: usize,
    /// `ceil_log2_at_least_lanes(total_entries)` — what the chip uses today.
    pub current_log_size: u32,
    /// `ceil_log2_at_least_lanes(after_dedup)` — what the merge would deliver.
    pub after_dedup_log_size: u32,
    /// Number of runs collapsed (= number of merged rows in the dedup'd ledger).
    /// A "run" of length 1 is also counted: it folds into itself with multiplicity 1.
    pub run_count: usize,
    /// Length of the longest run encountered.  Bounds the multiplicity column width
    /// the merged chip would need to reserve.
    pub longest_run: usize,
    /// Histogram of run lengths: `(length, count)` sorted by length ascending.
    pub run_length_histogram: Vec<(usize, usize)>,
    /// Read entries (today's count, before dedup).
    pub total_reads: usize,
    /// Write entries (always preserved).
    pub total_writes: usize,
    /// After-dedup row count under a fixed per-row merge cap M.
    /// `cap_after_dedup[m] = m == 0` skipped; `cap_after_dedup[m]` for `m >= 1`
    /// is the row count when each run of length `L` is split into `ceil(L / m)`
    /// merged rows.  Use `m = 1` to recover `total_entries`.
    pub cap_after_dedup: Vec<(usize, usize, u32)>,
}

/// Build the (reg, ts)-sorted list of register-memory ledger entries that
/// `generate_main_trace_immut` would produce.  Shared between
/// `analyze_dedup`, `merge_entries` callers (incl. the property test
/// suite), and any future chip-side trace fill.  Centralising here means
/// the analyzer + soundness tests + chip cannot drift apart.
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
        if let Some((reg_idx, val)) = acc.result_write {
            entries.push(RegEntry {
                reg_addr: reg_idx,
                value: val,
                timestamp: step.timestamp,
                is_write: true,
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

    entries.sort_by_key(|e| (e.reg_addr, e.timestamp));
    entries
}

/// Build the same `entries: Vec<RegEntry>` `generate_main_trace_immut` would
/// produce, then walk it (sorted by reg+ts) counting dedup-able runs.
#[cfg(feature = "prover")]
pub fn analyze_dedup(side_note: &crate::side_note::SideNote) -> RegisterDedupReport {
    let entries = build_entries_from_side_note(side_note);
    let total_entries = entries.len();
    let total_reads = entries.iter().filter(|e| !e.is_write).count();
    let total_writes = total_entries - total_reads;

    if total_entries == 0 {
        return RegisterDedupReport::default();
    }

    let mut after_dedup = 0usize;
    let mut run_count = 0usize;
    let mut longest_run = 0usize;
    let mut histogram: std::collections::BTreeMap<usize, usize> = Default::default();

    let mut i = 0;
    while i < entries.len() {
        let head = &entries[i];
        let mut run_len = 1usize;
        if !head.is_write {
            let mut j = i + 1;
            while j < entries.len()
                && entries[j].reg_addr == head.reg_addr
                && !entries[j].is_write
                && entries[j].value == head.value
            {
                run_len += 1;
                j += 1;
            }
        }
        after_dedup += 1;
        run_count += 1;
        if run_len > longest_run {
            longest_run = run_len;
        }
        *histogram.entry(run_len).or_default() += 1;
        i += run_len;
    }

    let saved = total_entries - after_dedup;
    let current_log_size = crate::trace::utils::ceil_log2_at_least_lanes(total_entries);
    let after_dedup_log_size = crate::trace::utils::ceil_log2_at_least_lanes(after_dedup);

    let mut cap_after_dedup = Vec::new();
    for m in [1usize, 2, 3, 4, 5, 6, 8, 16] {
        let mut rows = 0usize;
        for (&len, &count) in &histogram {
            // For length-1 runs (which include writes), each run is exactly 1 row
            // regardless of m.  For len > m read-runs, split into ceil(len/m) rows.
            let rows_per_run = if len == 1 { 1 } else { (len + m - 1) / m };
            rows += rows_per_run * count;
        }
        let log = crate::trace::utils::ceil_log2_at_least_lanes(rows);
        cap_after_dedup.push((m, rows, log));
    }

    RegisterDedupReport {
        total_entries,
        after_dedup,
        saved,
        current_log_size,
        after_dedup_log_size,
        run_count,
        longest_run,
        run_length_histogram: histogram.into_iter().collect(),
        total_reads,
        total_writes,
        cap_after_dedup,
    }
}

// ── Merge helper ───────────────────────────────────────────────────────
//
// Soundness-sensitive: this is the backbone of the merged-row chip.  The
// merge function takes the (reg, ts)-sorted single-entry
// ledger and folds runs of consecutive same-(reg, value) reads into
// merged rows of up to `B5_MERGE_CAP` slots.  Writes are never merged
// (writes change the value, ending a run).  Runs of length > MERGE_CAP
// split into multiple adjacent merged rows.
//
// The merge must be DETERMINISTIC and INVERTIBLE: `unmerge_entries`
// re-derives the original entries by replaying each merged row's slots.
// `unmerge(merge(e)) == e` for any (reg, ts)-sorted `e`.  This invariant
// pins the merge rule before AIR constraint changes layer in.
//
// AIR constraint design notes (NOT yet wired into the chip): each merged
// row carries `Mult ∈ 0..=B5_MERGE_CAP`,
// `SlotReal_i = (Mult > i)`, and per-slot timestamp columns
// `TS_i[8]`.  Per-slot consumer emits `−SlotReal_i · (RegAddr, Value,
// TS_i)` to `RegisterMemoryLookupElements`.  Sort key remains
// `(RegAddr, TS_0)`; read-consistency unchanged.

/// Maximum number of unmerged entries collapsible into a single merged
/// ledger row.  Even (fits `finalize_logup_in_pairs` cleanly) and large
/// enough to fit log_size 15 with margin (canonical bench: 29,280 rows
/// at M=4 vs 32,768 cap at log=15).  M=3 also fits but with less
/// headroom and odd emission count.
pub const B5_MERGE_CAP: usize = 4;

/// A merged register-memory ledger row representing 1..=`B5_MERGE_CAP`
/// adjacent same-(reg, value) read entries OR a single non-mergeable
/// entry (write, or read at a (reg, value)-boundary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergedRegEntry {
    pub reg_addr: u8,
    pub value: u64,
    pub is_write: bool,
    /// Number of unmerged entries this row represents.  Always 1 for
    /// writes; 1..=`B5_MERGE_CAP` for reads.
    pub mult: u8,
    /// Timestamps of the merged entries, populated for `mult` slots
    /// from index 0.  Slots in `mult..` are zero (untouched).
    /// Strictly increasing across `0..mult` (inherited from input
    /// sort order).
    pub timestamps: [u64; B5_MERGE_CAP],
}

impl MergedRegEntry {
    /// Helper: construct a single-slot merged entry from a `RegEntry`.
    pub fn single(e: &RegEntry) -> Self {
        let mut timestamps = [0u64; B5_MERGE_CAP];
        timestamps[0] = e.timestamp;
        MergedRegEntry {
            reg_addr: e.reg_addr,
            value: e.value,
            is_write: e.is_write,
            mult: 1,
            timestamps,
        }
    }
}

/// Apply the merge rule to a (reg, ts)-sorted list of single-entry
/// register-memory ledger rows.  Consecutive same-(reg, value) reads are
/// folded up to `B5_MERGE_CAP` slots; runs of length > `B5_MERGE_CAP`
/// split into multiple adjacent merged rows.
///
/// Soundness invariant: `unmerge_entries(merge_entries(e)) == e` for any
/// `e` that is itself the output of `build_entries_from_side_note` (i.e.,
/// (reg, ts)-sorted).  Verified by the inline property test.
pub fn merge_entries(entries: &[RegEntry]) -> Vec<MergedRegEntry> {
    let mut merged = Vec::with_capacity(entries.len());
    let mut i = 0;
    while i < entries.len() {
        let head = &entries[i];
        if head.is_write {
            merged.push(MergedRegEntry::single(head));
            i += 1;
            continue;
        }
        let mut run_len = 1usize;
        while i + run_len < entries.len()
            && run_len < B5_MERGE_CAP
            && entries[i + run_len].reg_addr == head.reg_addr
            && !entries[i + run_len].is_write
            && entries[i + run_len].value == head.value
        {
            run_len += 1;
        }
        let mut timestamps = [0u64; B5_MERGE_CAP];
        for k in 0..run_len {
            timestamps[k] = entries[i + k].timestamp;
        }
        merged.push(MergedRegEntry {
            reg_addr: head.reg_addr,
            value: head.value,
            is_write: false,
            mult: run_len as u8,
            timestamps,
        });
        i += run_len;
    }
    merged
}

/// Inverse of `merge_entries`: expand each merged row to its constituent
/// single-entry rows in original sort order.
pub fn unmerge_entries(merged: &[MergedRegEntry]) -> Vec<RegEntry> {
    let mut out = Vec::with_capacity(merged.iter().map(|m| m.mult as usize).sum());
    for m in merged {
        for k in 0..m.mult as usize {
            out.push(RegEntry {
                reg_addr: m.reg_addr,
                value: m.value,
                timestamp: m.timestamps[k],
                is_write: m.is_write,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(reg: u8, val: u64, ts: u64) -> RegEntry {
        RegEntry {
            reg_addr: reg,
            value: val,
            timestamp: ts,
            is_write: false,
        }
    }
    fn w(reg: u8, val: u64, ts: u64) -> RegEntry {
        RegEntry {
            reg_addr: reg,
            value: val,
            timestamp: ts,
            is_write: true,
        }
    }

    #[test]
    fn merge_empty() {
        let merged = merge_entries(&[]);
        assert!(merged.is_empty());
    }

    #[test]
    fn merge_single_read() {
        let entries = vec![r(2, 0xABCD, 5)];
        let merged = merge_entries(&entries);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].mult, 1);
        assert_eq!(merged[0].timestamps[0], 5);
        assert_eq!(merged[0].timestamps[1..], [0; B5_MERGE_CAP - 1]);
    }

    #[test]
    fn merge_single_write() {
        let entries = vec![w(2, 0xABCD, 5)];
        let merged = merge_entries(&entries);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].mult, 1);
        assert!(merged[0].is_write);
    }

    #[test]
    fn merge_two_same_value_reads_folds() {
        let entries = vec![r(2, 0xABCD, 5), r(2, 0xABCD, 7)];
        let merged = merge_entries(&entries);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].mult, 2);
        assert_eq!(&merged[0].timestamps[..2], &[5, 7]);
    }

    #[test]
    fn merge_max_cap_folds() {
        let entries: Vec<_> = (0..B5_MERGE_CAP as u64)
            .map(|k| r(2, 0xABCD, k + 1))
            .collect();
        let merged = merge_entries(&entries);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].mult as usize, B5_MERGE_CAP);
    }

    #[test]
    fn merge_over_cap_splits() {
        // B5_MERGE_CAP + 1 same-value reads.
        let entries: Vec<_> = (0..(B5_MERGE_CAP as u64 + 1))
            .map(|k| r(2, 0xABCD, k + 1))
            .collect();
        let merged = merge_entries(&entries);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].mult as usize, B5_MERGE_CAP);
        assert_eq!(merged[1].mult, 1);
        assert_eq!(merged[1].timestamps[0], B5_MERGE_CAP as u64 + 1);
    }

    #[test]
    fn merge_does_not_cross_value_change() {
        // r2=A, r2=B (different values) → no merge.
        let entries = vec![r(2, 0xA, 1), r(2, 0xB, 2)];
        let merged = merge_entries(&entries);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].value, 0xA);
        assert_eq!(merged[1].value, 0xB);
    }

    #[test]
    fn merge_does_not_cross_register_boundary() {
        // r1=V, r2=V (same value, different reg) → no merge.
        let entries = vec![r(1, 0x0F, 1), r(2, 0x0F, 2)];
        let merged = merge_entries(&entries);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].reg_addr, 1);
        assert_eq!(merged[1].reg_addr, 2);
    }

    #[test]
    fn merge_does_not_cross_write() {
        // r2 read V, r2 write V, r2 read V.  The write is an interrupt:
        // the second read becomes its own merged row.
        let entries = vec![r(2, 0x0F, 1), w(2, 0x0F, 2), r(2, 0x0F, 3)];
        let merged = merge_entries(&entries);
        assert_eq!(merged.len(), 3);
        assert!(!merged[0].is_write);
        assert!(merged[1].is_write);
        assert!(!merged[2].is_write);
        assert_eq!(merged[0].mult, 1);
        assert_eq!(merged[1].mult, 1);
        assert_eq!(merged[2].mult, 1);
    }

    /// Soundness invariant: merge → unmerge is the identity for any input
    /// the chip would build.  The input must be (reg, ts)-sorted (which
    /// `build_entries_from_side_note` guarantees).
    #[test]
    fn roundtrip_handcrafted_sequences() {
        let cases: Vec<Vec<RegEntry>> = vec![
            vec![],
            vec![r(0, 0, 0)],
            vec![w(0, 100, 0), r(0, 100, 1), r(0, 100, 2), r(0, 100, 3)],
            vec![
                w(0, 100, 0),
                r(0, 100, 1),
                r(0, 100, 2),
                r(0, 100, 3),
                r(0, 100, 4),
            ],
            // Mixed sequence covering: writes, reads at multiple regs,
            // run that exceeds cap, value change, register change.
            {
                let mut v = vec![
                    w(0, 5, 0),
                    r(0, 5, 1),
                    r(0, 5, 2),
                    w(1, 7, 0),
                    r(1, 7, 3),
                    r(1, 7, 5),
                    r(1, 7, 7),
                    r(1, 7, 9),
                    r(1, 7, 11),
                    w(2, 9, 0),
                    r(2, 9, 4),
                    w(2, 11, 6),
                    r(2, 11, 8),
                ];
                v.sort_by_key(|e| (e.reg_addr, e.timestamp));
                v
            },
        ];
        for (idx, entries) in cases.iter().enumerate() {
            let merged = merge_entries(entries);
            let restored = unmerge_entries(&merged);
            assert_eq!(&restored, entries, "case #{idx} failed roundtrip");
        }
    }

    /// Verify the merge respects `B5_MERGE_CAP`: every output row's mult
    /// is 1..=B5_MERGE_CAP, and writes always have mult=1.
    #[test]
    fn merged_rows_obey_invariants() {
        // 1030-entry run (the longest from canonical bench) across cap.
        let mut entries: Vec<_> = (0..1030u64).map(|k| r(5, 0xCAFE, k + 1)).collect();
        entries.sort_by_key(|e| (e.reg_addr, e.timestamp));
        let merged = merge_entries(&entries);
        for m in &merged {
            assert!(m.mult >= 1, "mult must be >= 1");
            assert!(
                m.mult as usize <= B5_MERGE_CAP,
                "mult must be <= B5_MERGE_CAP"
            );
            if m.is_write {
                assert_eq!(m.mult, 1, "writes always have mult=1");
            }
            // Slots beyond mult must be zero (uninitialized witness).
            for k in m.mult as usize..B5_MERGE_CAP {
                assert_eq!(m.timestamps[k], 0, "padding slot {k} must be zero");
            }
            // Active slots must be strictly increasing.
            for k in 1..m.mult as usize {
                assert!(
                    m.timestamps[k] > m.timestamps[k - 1],
                    "slot timestamps must strictly increase"
                );
            }
        }
        // 1030 / 4 = 257.5 → 258 merged rows (last row has mult=2).
        assert_eq!(merged.len(), (1030 + B5_MERGE_CAP - 1) / B5_MERGE_CAP);
        let restored = unmerge_entries(&merged);
        assert_eq!(restored, entries);
    }

    /// Pseudo-random sweep — hand-rolled (no quickcheck dep needed).
    /// Generates 200 random step sequences and asserts the roundtrip
    /// invariant on each.
    #[test]
    fn roundtrip_random_sweep() {
        // Linear congruential generator for reproducibility without
        // pulling rand as a dev-dep.
        let mut state: u64 = 0xDEADBEEF_CAFEBABE;
        let mut next = || -> u64 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        for case in 0..200 {
            let n = (next() % 64) as usize + 1;
            let n_regs = (next() % 8) as u8 + 1;
            let n_values = (next() % 4) as u64 + 1;
            let mut entries: Vec<RegEntry> = Vec::with_capacity(n);
            for _ in 0..n {
                let reg = (next() % n_regs as u64) as u8;
                let value = next() % n_values;
                let timestamp = next() % 256;
                let is_write = next() % 4 == 0; // ~25% writes, 75% reads
                entries.push(RegEntry {
                    reg_addr: reg,
                    value,
                    timestamp,
                    is_write,
                });
            }
            entries.sort_by_key(|e| (e.reg_addr, e.timestamp));
            // Dedup duplicate (reg_addr, timestamp) pairs — the chip never
            // sees these from a real trace; sort is stable so we can dedup
            // by adjacency.
            entries.dedup_by(|a, b| a.reg_addr == b.reg_addr && a.timestamp == b.timestamp);

            let merged = merge_entries(&entries);
            let restored = unmerge_entries(&merged);
            assert_eq!(
                restored, entries,
                "case {case} (n={n}, regs={n_regs}, vals={n_values}) failed roundtrip"
            );
            for m in &merged {
                assert!(m.mult >= 1);
                assert!(m.mult as usize <= B5_MERGE_CAP);
                if m.is_write {
                    assert_eq!(m.mult, 1);
                }
                for k in 1..m.mult as usize {
                    assert!(
                        m.timestamps[k] > m.timestamps[k - 1],
                        "case {case}: slot timestamps must strictly increase"
                    );
                }
                for k in m.mult as usize..B5_MERGE_CAP {
                    assert_eq!(m.timestamps[k], 0);
                }
            }
        }
    }

    /// Cross-check: the cap-sweep numbers reported by `analyze_dedup`'s
    /// `cap_after_dedup` field for M = `B5_MERGE_CAP` must match
    /// `merge_entries(...)::len()`.  This is the consistency test
    /// between the analyzer's prediction and the merger's reality;
    /// future drift between them surfaces here.
    ///
    /// Uses synthetic entries (no actor blob needed) so it runs fast.
    #[test]
    fn merge_count_matches_cap_sweep() {
        // Construct a bench-like trace: 100 reads of (r2=V), interrupted
        // by one write halfway through, plus a tail of 50 more reads.
        let mut entries: Vec<RegEntry> = Vec::new();
        for k in 0..50u64 {
            entries.push(r(2, 0xABCD, k + 1));
        }
        entries.push(w(2, 0xABCD, 51));
        for k in 0..50u64 {
            entries.push(r(2, 0xABCD, k + 52));
        }
        entries.sort_by_key(|e| (e.reg_addr, e.timestamp));

        // Replicate analyze_dedup's cap-sweep math for M=B5_MERGE_CAP.
        // `alloc::` (not `std::`) so this verifier-meaningful test still
        // compiles in the no_std / no-prover build.
        let mut histogram: alloc::collections::BTreeMap<usize, usize> = Default::default();
        let mut i = 0;
        while i < entries.len() {
            let head = &entries[i];
            let mut run_len = 1usize;
            if !head.is_write {
                let mut j = i + 1;
                while j < entries.len()
                    && entries[j].reg_addr == head.reg_addr
                    && !entries[j].is_write
                    && entries[j].value == head.value
                {
                    run_len += 1;
                    j += 1;
                }
            }
            *histogram.entry(run_len).or_default() += 1;
            i += run_len;
        }
        let predicted: usize = histogram
            .iter()
            .map(|(&len, &count)| {
                let rows_per_run = if len == 1 {
                    1
                } else {
                    (len + B5_MERGE_CAP - 1) / B5_MERGE_CAP
                };
                rows_per_run * count
            })
            .sum();

        let merged = merge_entries(&entries);
        assert_eq!(
            merged.len(),
            predicted,
            "merger produced {} rows; cap-sweep predicted {predicted}",
            merged.len()
        );
    }
}
