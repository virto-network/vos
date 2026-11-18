//! WitnessInputChip: the bytes a kernel's witness-input calls write.
//!
//! A witness-input call (`ECALL_WITNESS_INPUT`, 0x401) writes the next
//! `count` bytes of the run's input at its destination φ7, and returns the
//! count in φ7. The bytes are free witness: what binds a run is where they
//! land. The CPU row of a call that wrote bytes produces one `WitnessCall`
//! tuple `(ts, destination, count)` (its own constraints pin the count to
//! φ7's write, below 2^24 and at most φ8, and the destination to φ7, below
//! 2^32). This chip turns each tuple into exactly `count` memory writes:
//!
//! - one row a byte, a call's rows contiguous, in address order;
//! - its first row (`IsFirst`) consumes the call's tuple, so its `Ts`, `Addr`
//!   and `Left` are the call's timestamp, destination and count;
//! - a row whose `Left` is not 1 (`Cont`) is followed by a real row of the
//!   same call: the same `Ts`, the next address (a carry chain with no
//!   carry out of the top byte, every byte range-checked, so no wrap past
//!   2^32) and `Left` one less;
//! - a row with `Left = 1` (`IsLast`) ends the call;
//! - a real row that does not start a call follows a `Cont` row (`Follows`),
//!   so no row writes outside a call's chain.
//!
//! So a chain runs from a call's first row through `count` rows, writing
//! `[destination, destination + count)` at the call's timestamp, and no row
//! writes anything else. `Left` decreases by one a row and a trace has far
//! fewer than `p` rows, so a chain cannot pass 1 and come back to it. Each
//! row produces its byte's memory write and range-checks the byte and its
//! address; the memory ledger orders it with the run's other accesses.

use crate::prelude::*;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::framework::BuiltInComponent;
use crate::lookups::{
    MemoryAccessLookupElements, Range256LookupElements, WitnessCallLookupElements,
};
use crate::trace::eval::TraceEval;

#[derive(Clone, Copy)]
pub struct WitnessInputChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// 1 on a byte's row, 0 on padding.
    #[size = 1]
    #[mask_next_row]
    IsReal,
    /// 1 on a call's first byte: it consumes the call's tuple.
    #[size = 1]
    #[mask_next_row]
    IsFirst,
    /// 1 on a call's last byte, where `Left = 1`.
    #[size = 1]
    IsLast,
    /// `IsReal · (1 − IsLast)`: the call goes on past this row.
    #[size = 1]
    Cont,
    /// `IsReal · (1 − IsFirst)`: this row goes on a call from the row
    /// before.
    #[size = 1]
    #[mask_next_row]
    Follows,
    /// The call's timestamp, 8 LE bytes.
    #[size = 8]
    #[mask_next_row]
    Ts,
    /// This byte's address, 4 LE bytes.
    #[size = 4]
    #[mask_next_row]
    Addr,
    /// The byte written.
    #[size = 1]
    Value,
    /// The call's bytes from this one on: its count on its first row.
    #[size = 1]
    #[mask_next_row]
    Left,
    /// The carries of `Addr + 1`, the next row's address.
    #[size = 3]
    Carry,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "witness_input"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for WitnessInputChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        WitnessCallLookupElements,
        MemoryAccessLookupElements,
        Range256LookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            WitnessCallLookupElements,
            MemoryAccessLookupElements,
            Range256LookupElements,
        ),
    ) {
        let (call_lookup, mem_lookup, range256_lookup) = lookup_elements;
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let is_first = crate::trace::trace_eval!(trace_eval, Column::IsFirst);
        let is_last = crate::trace::trace_eval!(trace_eval, Column::IsLast);
        let cont = crate::trace::trace_eval!(trace_eval, Column::Cont);
        let follows = crate::trace::trace_eval!(trace_eval, Column::Follows);
        let ts = crate::trace::trace_eval!(trace_eval, Column::Ts);
        let addr = crate::trace::trace_eval!(trace_eval, Column::Addr);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let left = crate::trace::trace_eval!(trace_eval, Column::Left);
        let carry = crate::trace::trace_eval!(trace_eval, Column::Carry);
        let is_real_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsReal);
        let is_first_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsFirst);
        let follows_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Follows);
        let ts_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Ts);
        let addr_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Addr);
        let left_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Left);

        let one = E::F::one();
        let f256 = E::F::from(BaseField::from(256u32));

        for flag in [&is_real, &is_first, &is_last] {
            eval.add_constraint(flag[0].clone() * (one.clone() - flag[0].clone()));
        }
        for bit in &carry {
            eval.add_constraint(bit.clone() * (one.clone() - bit.clone()));
        }
        // A first or last byte is a real one; a last byte has one left.
        eval.add_constraint(is_first[0].clone() * (one.clone() - is_real[0].clone()));
        eval.add_constraint(is_last[0].clone() * (one.clone() - is_real[0].clone()));
        eval.add_constraint(is_last[0].clone() * (left[0].clone() - one.clone()));
        eval.add_constraint(
            cont[0].clone() - is_real[0].clone() * (one.clone() - is_last[0].clone()),
        );
        eval.add_constraint(
            follows[0].clone() - is_real[0].clone() * (one.clone() - is_first[0].clone()),
        );

        // A call that goes on: the next row is its next byte, at its
        // timestamp, the next address, one fewer left.
        eval.add_constraint(cont[0].clone() * (one.clone() - is_real_next[0].clone()));
        eval.add_constraint(cont[0].clone() * is_first_next[0].clone());
        eval.add_constraint(
            cont[0].clone() * (left_next[0].clone() - left[0].clone() + one.clone()),
        );
        for i in 0..8 {
            eval.add_constraint(cont[0].clone() * (ts_next[i].clone() - ts[i].clone()));
        }
        eval.add_constraint(
            cont[0].clone()
                * (addr_next[0].clone() + f256.clone() * carry[0].clone()
                    - addr[0].clone()
                    - one.clone()),
        );
        for i in 1..3 {
            eval.add_constraint(
                cont[0].clone()
                    * (addr_next[i].clone() + f256.clone() * carry[i].clone()
                        - addr[i].clone()
                        - carry[i - 1].clone()),
            );
        }
        eval.add_constraint(
            cont[0].clone() * (addr_next[3].clone() - addr[3].clone() - carry[2].clone()),
        );
        // A row that goes on a call follows one that goes on.
        eval.add_constraint(follows_next[0].clone() * (one.clone() - cont[0].clone()));

        // Eight emissions, paired: the call's tuple twice on its first byte,
        // the byte's write, and five byte range checks.
        let mut call: Vec<E::F> = Vec::with_capacity(13);
        call.extend_from_slice(&ts);
        call.extend_from_slice(&addr);
        call.push(left[0].clone());
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                call_lookup,
                (-is_first[0].clone()).into(),
                &call,
            ));
        }
        let mut write: Vec<E::F> = Vec::with_capacity(15);
        write.extend_from_slice(&addr);
        write.push(value[0].clone());
        write.extend_from_slice(&ts);
        write.push(one.clone()); // is_write
        write.push(E::F::zero()); // is_closing
        eval.add_to_relation(RelationEntry::new(
            mem_lookup,
            is_real[0].clone().into(),
            &write,
        ));
        for byte in value.iter().chain(addr.iter()) {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real[0].clone().into(),
                core::slice::from_ref(byte),
            ));
        }
    }
}

#[cfg(feature = "prover")]
mod fill;
