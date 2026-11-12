#![cfg(feature = "debug-internals")]

//! Negative AIR gate for the word ledger's last row (`WordMemoryChip`).
//!
//! Padding lies past the real rows alone, so a word is one group; what
//! leaves no place for padding at all is a ledger whose every row is real.
//! Cyclically, such a ledger may be one word at one sort key on every row:
//! each row a read of the same bytes taking one lane, every row's
//! successor the same word (`IsSameAddrNext`), no group start, no closing
//! read and no ordering delta. Every constraint but the last row's holds on
//! it, so its rows consume lanes no group's ends bound. The last row is
//! padding (`IsLast · (1 − IsPadding) = 0`), which refuses it.
//!
//! The control: the same ledger against a preprocessed `IsLast` of no last
//! row satisfies every constraint, so the refusal is the last row's.

use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::WordMemoryChip;
use vos_pvm_proof::chips::word_memory::{Column, PreprocessedColumn};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineComponent, MachineProverComponent};
use vos_pvm_proof::trace::builder::TraceBuilder;
use vos_pvm_proof::trace::component::ComponentTrace;

const LOG_SIZE: u32 = 4;
/// The word, an aligned address, and its bytes.
const ADDRESS: u32 = 0x3_0008;
const VALUE: [u8; 8] = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];

/// The all-real cyclic ledger: every row a read of [`VALUE`] at
/// [`ADDRESS`] at timestamp 5, taking lane 0, the next row the same word.
fn all_real() -> Vec<stwo::prover::backend::simd::column::BaseColumn> {
    let mut trace = TraceBuilder::<Column>::new(LOG_SIZE);
    for row in 0..1 << LOG_SIZE {
        trace.fill_columns_bytes(row, &ADDRESS.to_le_bytes(), Column::Address);
        trace.fill_columns_bytes(row, &VALUE, Column::Value);
        trace.fill_columns_bytes(row, &VALUE, Column::PrevValue);
        trace.fill_columns(row, 5u64, Column::Timestamp);
        trace.fill_columns(row, false, Column::IsWrite);
        let mut active = [BaseField::from(0); 8];
        active[0] = BaseField::from(1);
        trace.fill_columns_base_field(row, &active, Column::Active);
        trace.fill_columns(row, true, Column::IsSameAddrNext);
        trace.fill_columns(row, false, Column::IsPadding);
        trace.fill_columns(row, true, Column::Writable);
        trace.fill_columns_base_field(row, &[BaseField::from(1)], Column::LaneInv);
    }
    trace.finalize_bit_reversed().cols
}

fn side_note() -> SideNote {
    SideNote::new(Vec::new(), Vec::new(), Vec::new())
}

/// The chip's constraints on `original` against `preprocessed`.
fn assert_ledger(
    preprocessed: Vec<stwo::prover::backend::simd::column::BaseColumn>,
    original: Vec<stwo::prover::backend::simd::column::BaseColumn>,
) {
    let trace = ComponentTrace {
        log_size: LOG_SIZE,
        preprocessed_trace: preprocessed,
        original_trace: original,
    };
    let side_note = side_note();
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sM31Channel::default();
    WordMemoryChip.draw_lookup_elements(&mut lookup_elements, channel.into());
    let (interaction_trace, claimed_sum) =
        WordMemoryChip.generate_interaction_trace(&trace, &side_note, &lookup_elements);
    WordMemoryChip.debug_assert_constraints(
        &trace,
        &interaction_trace,
        &lookup_elements,
        claimed_sum,
    );
}

/// Against an `IsLast` of no last row, the all-real ledger satisfies every
/// constraint: no other constraint refuses it.
#[test]
fn the_all_real_ledger_holds_every_other_constraint() {
    let none = TraceBuilder::<PreprocessedColumn>::new(LOG_SIZE)
        .finalize_bit_reversed()
        .cols;
    assert_ledger(none, all_real());
}

/// Against the chip's own `IsLast`, the all-real ledger is refused.
#[test]
fn an_all_real_ledger_is_refused() {
    let preprocessed = WordMemoryChip
        .generate_preprocessed_trace(LOG_SIZE, &side_note())
        .into_iter()
        .map(|evaluation| evaluation.values)
        .collect();
    if !in_child!("an_all_real_ledger_is_refused") {
        return;
    }
    assert_ledger(preprocessed, all_real());
}
