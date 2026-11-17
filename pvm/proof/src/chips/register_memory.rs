use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::core::step::NUM_REGS;
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::RegisterMemoryLookupElements,
};

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
#[derive(Clone, Copy)]
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

impl BuiltInComponent for RegisterMemoryChip {
    const LOGUP: Logup = Logup::Single;
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
        // pvm/proof/docs/design/ledger-read-consistency.md).  All
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
        // The timestamps enter reduced mod p, so two accesses about 2^30
        // steps apart would alias; the chain's `ts = 0` start (below) keeps
        // a provable segment's accesses under 2^28, a soundness bound
        // (`crate::standalone::TIMESTAMP_BOUND`).
        let two = E::F::from(BaseField::from(2u32));
        let recomposed = super::ordering::recompose(eval, &order_bits, two.clone());
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
    }
}

/// Compile-time check that NUM_REGS fits in a single byte for RegAddr.
const _: [(); (NUM_REGS <= u8::MAX as usize) as usize - 1] = [];

#[cfg(feature = "prover")]
mod fill;
#[cfg(feature = "prover")]
pub use fill::{RegEntry, build_entries_from_side_note};
