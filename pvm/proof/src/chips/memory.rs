use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::MemoryAccessLookupElements,
};

/// MemoryChip: proves read/write consistency of RAM accesses.
///
/// Each row is one memory access (Load or Store). The trace is sorted by
/// (address, 2·timestamp + is_write): at one timestamp an address's reads
/// precede its writes. For consecutive accesses to the same address, reads
/// must return the value from the last write.
///
/// The AIR fixes no place for the padding, and the sortedness gadget does
/// not fire across a padding row, so the real rows may be several sorted
/// runs. Each run starts with a `ts = 0` write and every group ends with a
/// closing read, so an address is one group, its first touch the one
/// written, when its boundary produces its `ts = 0` write once: the page
/// boundary does (`MemoryPageChip`, a page once in the trie).
#[derive(Clone, Copy)]
pub struct MemoryChip;

/// Byte-level memory model: each row is a single byte access.
/// Multi-byte accesses are decomposed into N byte entries.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Byte address (4 limbs, u32).  `#[mask_next_row]` so the sortedness /
    /// read-consistency gadget can read the next ledger row's address.
    #[size = 4]
    #[mask_next_row]
    Address,
    /// Single byte value
    #[size = 1]
    Value,
    /// Timestamp of this access (8 limbs).  `#[mask_next_row]` for the
    /// same-address ts-monotonicity check.
    #[size = 8]
    #[mask_next_row]
    Timestamp,
    /// 1 = write, 0 = read.  `#[mask_next_row]` so the group-start constraint
    /// can require the first row of every address group to be a `ts=0` write.
    #[size = 1]
    #[mask_next_row]
    IsWrite,
    /// Previous byte value at same address.  `#[mask_next_row]` so a row can
    /// bind the *next* row's prev_value to this row's value (cross-row
    /// read-consistency).
    #[size = 1]
    #[mask_next_row]
    PrevValue,
    /// Bound boolean: 1 iff the next ledger row is real and accesses the same
    /// address. Pinned by the sortedness gadget; it gates the cross-row
    /// `prev_value` value binding.
    #[size = 1]
    IsSameAddrNext,
    /// 1 if padding row.  `#[mask_next_row]` so a row can tell whether its
    /// successor is real (the gadget only fires between two real rows).
    #[size = 1]
    #[mask_next_row]
    IsPadding,
    /// BOUND boolean: 1 iff this real→real transition advances the address via
    /// the LOW 16-bit half (hi halves equal, lo strictly increases).
    #[size = 1]
    AdvLoH,
    /// BOUND boolean: 1 iff this real→real transition advances the address via
    /// the HIGH 16-bit half (hi strictly increases).  Exactly one of
    /// {IsSameAddrNext, AdvLoH, AdvHiH} holds on a real→real transition.
    #[size = 1]
    AdvHiH,
    /// 28-bit little-endian decomposition of the per-transition ordering delta
    /// `OrderDelta = IsSameAddrNext·key_diff + AdvLoH·(lo_diff−1) +
    /// AdvHiH·(hi_diff−1)`, a SELF-CONTAINED non-negativity range-check (no
    /// Range256 lookup — the consumer pass runs with an immutable `&SideNote`).
    /// 28 bits covers twice every timestamp admitted by the canonical
    /// 100M-gas actor-proof budget plus the 16-bit half diffs. `2^28 < p/4`, so a
    /// field-wrapped negative cannot alias a valid small positive.
    #[size = 28]
    OrderBits,
    /// 1 iff this is a per-page closing read (the §2 boundary injection),
    /// produced only by MemoryPageChip; 0 for every step / precompile /
    /// ts=0-write entry.  Part of the logup tuple (so producers and consumer
    /// agree) and gates the group-end constraint.  `#[mask_next_row]`: an
    /// unreadable page's group goes from its start straight to its closing
    /// read.
    #[size = 1]
    #[mask_next_row]
    IsClosing,
    /// BOUND helper: `IsGroupStart = is_real_next · (1 − IsSameAddrNext)` — 1
    /// iff the NEXT ledger row begins a new address group (next row real and a
    /// different address, OR the cyclic padding→row-0 wrap).  Flattens the
    /// group-start gate to degree 1 so `IsGroupStart · ts_next` stays degree 2.
    #[size = 1]
    IsGroupStart,
    /// BOUND helper: `IsGroupEnd = is_real · (1 − IsSameAddrNext)` — 1 iff THIS
    /// real row ends its address group (next row is a different address or
    /// padding).  The group-end constraint forces such a row to be a closing
    /// read, so every accessed address lands in a listed page (design §2).
    #[size = 1]
    IsGroupEnd,
    /// 1 iff this real row starts its address group: the previous row's
    /// `IsGroupStart`.  `#[mask_next_row]` so that row can set it.
    #[size = 1]
    #[mask_next_row]
    IsStart,
    /// The address's page is readable (its permission 1 or 2), constant
    /// along the group.
    #[size = 1]
    #[mask_next_row]
    Readable,
    /// The address's page is writable (its permission 2), constant along
    /// the group.
    #[size = 1]
    #[mask_next_row]
    Writable,
    /// BOUND helper `IsStart · (Readable + Writable)`: the page's
    /// permission on its group's start, the ts=0 write MemoryPageChip
    /// produces with it, and 0 on every other row.
    #[size = 1]
    PermissionH,
    // Read-consistency uses an unconditional
    // `(1 - is_write) · (value - prev_value) = 0` constraint (no gating
    // helper column): padding rows have value=0 and prev_value=0, so the
    // stronger unconditional form holds.
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "mem"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for MemoryChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = MemoryAccessLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &MemoryAccessLookupElements,
    ) {
        let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();

        let address = crate::trace::trace_eval!(trace_eval, Column::Address);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
        let is_write = crate::trace::trace_eval!(trace_eval, Column::IsWrite);
        let is_closing = crate::trace::trace_eval!(trace_eval, Column::IsClosing);
        let prev_value = crate::trace::trace_eval!(trace_eval, Column::PrevValue);

        // IsClosing is a bound boolean (only MemoryPageChip ever sets it);
        // IsWrite and IsPadding are booleans too.
        for flag in [&is_closing, &is_write, &is_pad] {
            eval.add_constraint(flag[0].clone() * (flag[0].clone() - E::F::one()));
        }

        // Read consistency is unconditional: `(1 - is_write) · (value -
        // prev_value) = 0`.  On padding rows value=prev_value=0 so 1·0=0
        // holds.
        let is_read = E::F::one() - is_write[0].clone();
        eval.add_constraint(is_read * (value[0].clone() - prev_value[0].clone()));

        // ── Cross-row read-consistency + (addr, ts) sortedness gadget ────
        // The ledger is sorted by (Address, Timestamp).  These constraints pin
        // that ordering and bind each read to the immediately-preceding
        // same-address row (closing the read-consistency soundness gap).  All
        // constraints stay ≤ degree 2.  See docs/design/ledger-read-consistency.md.
        let is_pad_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsPadding);
        let address_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Address);
        let timestamp_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Timestamp);
        let prev_value_next = crate::trace::trace_eval_next_row!(trace_eval, Column::PrevValue);
        let is_same_addr = crate::trace::trace_eval!(trace_eval, Column::IsSameAddrNext);
        let adv_lo = crate::trace::trace_eval!(trace_eval, Column::AdvLoH);
        let adv_hi = crate::trace::trace_eval!(trace_eval, Column::AdvHiH);
        let order_bits = crate::trace::trace_eval!(trace_eval, Column::OrderBits);

        // 16-bit address halves (each < 2^16 < p, so the field diffs are exact —
        // a full u32 address would wrap the field).
        let b256 = E::F::from(BaseField::from(256u32));
        let a_lo = address[0].clone() + address[1].clone() * b256.clone();
        let a_hi = address[2].clone() + address[3].clone() * b256.clone();
        let a_lo_next = address_next[0].clone() + address_next[1].clone() * b256.clone();
        let a_hi_next = address_next[2].clone() + address_next[3].clone() * b256.clone();
        let lo_diff = a_lo_next - a_lo;
        let hi_diff = a_hi_next - a_hi;

        // Booleans.
        eval.add_constraint(is_same_addr[0].clone() * (is_same_addr[0].clone() - E::F::one()));
        eval.add_constraint(adv_lo[0].clone() * (adv_lo[0].clone() - E::F::one()));
        eval.add_constraint(adv_hi[0].clone() * (adv_hi[0].clone() - E::F::one()));

        // is_same_addr ⇒ both real, and addresses equal (both halves).
        eval.add_constraint(is_same_addr[0].clone() * is_pad[0].clone());
        eval.add_constraint(is_same_addr[0].clone() * is_pad_next[0].clone());
        eval.add_constraint(is_same_addr[0].clone() * hi_diff.clone());
        eval.add_constraint(is_same_addr[0].clone() * lo_diff.clone());
        // AdvLoH ⇒ hi halves equal (the advance is in the low half).
        eval.add_constraint(adv_lo[0].clone() * hi_diff.clone());
        // Exactly one of {same, lo-advance, hi-advance} on a real→real
        // transition; none on a padding boundary or the cyclic wraparound.
        let both_real = (E::F::one() - is_pad[0].clone()) * (E::F::one() - is_pad_next[0].clone());
        eval.add_constraint(
            is_same_addr[0].clone() + adv_lo[0].clone() + adv_hi[0].clone() - both_real,
        );

        // OrderDelta = same·key_diff + lo·(lo_diff−1) + hi·(hi_diff−1),
        // 28-bit range-checked ≥ 0, with key = 2·ts + is_write.  same=1 ⇒
        // the key is non-decreasing: ts is, and at one ts an address's reads
        // come before its writes, so a step that reads and writes one byte
        // (a precompile whose output overlaps its input) reads the value
        // from before it; lo=1 ⇒ lo strictly increases (hi equal) ⇒ addr↑;
        // hi=1 ⇒ hi strictly increases ⇒ addr↑.  0 on every non-real→real
        // transition (all three coeffs are 0 there). The timestamps enter
        // reduced mod p, so two accesses about 2^30 steps apart would alias;
        // each address's run starting at a `ts = 0` write keeps a provable
        // segment's accesses under 2^28, a soundness bound
        // (`crate::standalone::TIMESTAMP_BOUND`).
        let combine_ts = |bytes: &[E::F; 8]| -> E::F {
            let mut acc = E::F::zero();
            let mut pow = E::F::one();
            for b in bytes {
                acc += b.clone() * pow.clone();
                pow *= b256.clone();
            }
            acc
        };
        let is_write_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsWrite);
        let two = E::F::from(BaseField::from(2u32));
        let key_diff = two.clone() * (combine_ts(&timestamp_next) - combine_ts(&timestamp))
            + is_write_next[0].clone()
            - is_write[0].clone();
        let order_delta = is_same_addr[0].clone() * key_diff
            + adv_lo[0].clone() * (lo_diff - E::F::one())
            + adv_hi[0].clone() * (hi_diff - E::F::one());
        let recomposed = super::ordering::recompose(eval, &order_bits, two.clone());
        eval.add_constraint(recomposed - order_delta);

        // Cross-row value binding: same-address ⇒ the next row's prev_value
        // equals this row's value.  Combined with read-consistency, forces every
        // read to return the most-recent same-address write / initial byte.
        eval.add_constraint(
            is_same_addr[0].clone() * (prev_value_next[0].clone() - value[0].clone()),
        );

        // ── Per-page boundary group constraints (design §2) ──────────────
        // The per-page ledger injection (MemoryPageChip producers) puts a
        // `ts=0` boundary write and a closing read on EVERY byte of every
        // listed page.  After (addr, ts) sorting each address group is
        // `[ts=0 write, real accesses…, closing read]`.  These constraints
        // force that shape, so a prover cannot carry forged values across a
        // boundary by omitting a touched page: every accessed address must be
        // a listed page (else its group lacks the ts=0 write / closing read
        // producer → group-start violation or logup imbalance).
        let is_group_start = crate::trace::trace_eval!(trace_eval, Column::IsGroupStart);
        let is_group_end = crate::trace::trace_eval!(trace_eval, Column::IsGroupEnd);
        let is_real_next = E::F::one() - is_pad_next[0].clone();

        // Helper definitions (degree 2) — keep the gates below degree 2.
        //   IsGroupStart = is_real_next · (1 − IsSameAddrNext)
        //   IsGroupEnd   = is_real     · (1 − IsSameAddrNext)
        eval.add_constraint(
            is_group_start[0].clone()
                - is_real_next.clone() * (E::F::one() - is_same_addr[0].clone()),
        );
        eval.add_constraint(
            is_group_end[0].clone() - is_real.clone() * (E::F::one() - is_same_addr[0].clone()),
        );

        // Group start: the next row (first of a new address group) is a ts=0
        // write.  The trace generator's ≥1 padding row makes the cyclic
        // last→row-0 wrap a group start, so natural row 0 is covered; the AIR
        // does not require that row, and a trace with none is one cycle of
        // one address at one sort key, which no run's producers can fill.
        for limb in &timestamp_next {
            eval.add_constraint(is_group_start[0].clone() * limb.clone());
        }
        eval.add_constraint(is_group_start[0].clone() * (E::F::one() - is_write_next[0].clone()));

        // Group end: the last real row of every address group is a closing read.
        eval.add_constraint(is_group_end[0].clone() * (E::F::one() - is_closing[0].clone()));

        // ── Page permissions ──────────────────────────────────────────────
        // Every address group starts with its page's ts=0 write, which
        // MemoryPageChip produces carrying the page's proven permission
        // (`2·permission` in the tuple's last field; no other producer
        // emits ts = 0). The
        // group holds it, and every row after the start
        // obeys it: a write needs a writable page; an unreadable page's
        // start is followed by its closing read, so no step, BLAKE2b or
        // witness-input access lands in it.
        let is_start = crate::trace::trace_eval!(trace_eval, Column::IsStart);
        let is_start_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsStart);
        let readable = crate::trace::trace_eval!(trace_eval, Column::Readable);
        let readable_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Readable);
        let writable = crate::trace::trace_eval!(trace_eval, Column::Writable);
        let writable_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Writable);
        let is_closing_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsClosing);
        let permission = crate::trace::trace_eval!(trace_eval, Column::PermissionH);
        for flag in [&is_start, &readable, &writable] {
            eval.add_constraint(flag[0].clone() * (flag[0].clone() - E::F::one()));
        }
        eval.add_constraint(writable[0].clone() * (E::F::one() - readable[0].clone()));
        eval.add_constraint(is_start_next[0].clone() - is_group_start[0].clone());
        eval.add_constraint(
            permission[0].clone()
                - is_start[0].clone() * (readable[0].clone() + writable[0].clone()),
        );
        eval.add_constraint(
            is_same_addr[0].clone() * (readable_next[0].clone() - readable[0].clone()),
        );
        eval.add_constraint(
            is_same_addr[0].clone() * (writable_next[0].clone() - writable[0].clone()),
        );
        eval.add_constraint(
            is_same_addr[0].clone()
                * (E::F::one() - readable[0].clone())
                * (E::F::one() - is_closing_next[0].clone()),
        );
        eval.add_constraint(
            is_write[0].clone()
                * (E::F::one() - is_start[0].clone())
                * (E::F::one() - writable[0].clone()),
        );

        // Consumer lookup (negative multiplicity)
        // Byte-level tuple: (addr[4], value[1], timestamp[8], is_write[1],
        // is_closing + 2·permission[1])
        let mut tuple: Vec<E::F> = address.to_vec();
        tuple.push(value[0].clone());
        tuple.extend_from_slice(&timestamp);
        tuple.push(is_write[0].clone());
        tuple.push(is_closing[0].clone() + permission[0].clone() + permission[0].clone());

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real.clone()).into(),
            &tuple,
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
#[cfg(feature = "prover")]
pub(crate) use fill::access_entries;
