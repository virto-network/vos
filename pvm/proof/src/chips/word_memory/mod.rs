//! WordMemoryChip — the device's memory ledger a word a row, in place of
//! `MemoryChip`'s row a byte.
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
//! - **padding** comes after every real row and the last row is padding
//!   (the preprocessed `IsLast`), so the real rows are one sorted run and a
//!   word one group, however many boundary rows name it.
//!
//! [`DeviceWordMemoryChip`]: crate::chips::DeviceWordMemoryChip

use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::device::WORD_BYTES;
use crate::framework::{BuiltInComponent, Logup};
use crate::lookups::{MemoryAccessLookupElements, MemoryWordLookupElements};
use crate::trace::eval::TraceEval;

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
        // The last row is padding, which removes the all-real cyclic
        // ledger: every row one word at one sort key, with no group start.
        eval.add_constraint(is_last[0].clone() * is_real.clone());
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

#[cfg(feature = "prover")]
mod fill;
