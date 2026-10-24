//! The instruction fetch and its flag bits.

use super::*;
use crate::chips::cpu::tuples::{FLAG_BYTES, PROGRAM_MEMORY};

/// The instruction's fetch from ProgramMemoryChip: two paired emissions of
/// [`PROGRAM_MEMORY`], multiplicity 1 on a real row.
pub(super) fn program_memory(
    logup: &mut LogupTraceBuilder,
    row: &RowTrace<'_>,
    lookup_elements: &AllLookupElements,
) {
    let prog_mem: &ProgramMemoryLookupElements = lookup_elements.as_ref();
    let tuple = super::lookups::columns(row, &PROGRAM_MEMORY);
    for _ in 0..2 {
        logup.add_to_relation_with(
            prog_mem,
            [row.is_padding[0].clone()],
            |[pad]| (PackedBaseField::one() - pad).into(),
            &tuple,
        );
    }
}

/// The flag bytes' bits: one ByteToBits lookup a byte of
/// [`FLAG_BYTES`], multiplicity 1 on every row, so a padding row's zero
/// bytes pin its flags.
pub(super) fn flag_bits(
    logup: &mut LogupTraceBuilder,
    row: &RowTrace<'_>,
    lookup_elements: &AllLookupElements,
) {
    let byte_to_bits: &ByteToBitsLookupElements = lookup_elements.as_ref();
    for (byte, bits) in FLAG_BYTES {
        let flag = |column: Column| row.column(column)[0].clone();
        let mut limbs = vec![vec![flag(byte)]];
        limbs.extend(
            bits.iter()
                .map(|flags| flags.iter().map(|&f| flag(f)).collect()),
        );
        logup.add_to_relation_computed(
            byte_to_bits,
            [row.is_padding[0].clone()],
            |[_]| PackedBaseField::one().into(),
            limbs.len(),
            move |i| {
                limbs
                    .iter()
                    .map(|flags| flags.iter().map(|flag| flag.at(i)).sum())
                    .collect()
            },
        );
    }
}
