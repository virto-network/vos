#![cfg(feature = "debug-internals")]

//! Each lookup table's preprocessed columns are its function, checked
//! against a definition written here apart from the chips': every row an
//! entry of the function, and every entry of its domain some row. The
//! preprocessed root commits these columns; a table generated wrong would be
//! committed and verified as written, so only this check holds a table to
//! what its lookups assume (a byte below 256, `a & b`, a byte's bits, `2^s`,
//! a byte's popcount and its leading and trailing zeros).

use std::collections::BTreeSet;

use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::{
    BitcountChip, BitwiseAndByteChip, BitwiseLookupChip, ByteToBitsChip, PopcountChip,
    PowerOfTwoChip, RangeMultiplicity256,
};
use vos_pvm_proof::harness::MachineProverComponent;

/// One addition, then a trap: every table at its own size.
fn side_note() -> SideNote {
    use vos_pvm::instruction::Opcode;
    let code = vec![Opcode::Add64 as u8, 0x10, 2, Opcode::Trap as u8];
    let bitmask = vec![1, 0, 0, 1];
    let pvm = vos_pvm::interpreter::Interpreter::new(
        code,
        bitmask,
        vec![],
        [0; vos_pvm::PVM_REGISTER_COUNT],
        vec![0; 1 << 16],
        10_000,
    );
    let mut tracer = vos_pvm_proof::core::tracing::TracingPvm::new(pvm);
    let _ = tracer.run();
    let mut side_note = tracer.into_side_note();
    vos_pvm_proof::prepare_side_note_for_verification(&mut side_note);
    side_note
}

/// `chip`'s preprocessed rows, each its columns' values in column order.
fn table<C: MachineProverComponent>(chip: &C) -> Vec<Vec<u32>> {
    let mut side_note = side_note();
    let trace = chip.generate_component_trace(&mut side_note);
    let columns = &trace.preprocessed_trace;
    assert!(!columns.is_empty(), "a table has preprocessed columns");
    (0..columns[0].as_slice().len())
        .map(|row| {
            columns
                .iter()
                .map(|column| column.as_slice()[row].0)
                .collect()
        })
        .collect()
}

/// Every row of `rows` satisfies `entry`, and `domain` distinct rows cover
/// the function's domain.
fn assert_table(name: &str, rows: &[Vec<u32>], domain: usize, entry: impl Fn(&[u32]) -> bool) {
    for (row, values) in rows.iter().enumerate() {
        assert!(
            entry(values),
            "{name}: row {row} {values:?} is no entry of the function"
        );
    }
    let distinct: BTreeSet<&Vec<u32>> = rows.iter().collect();
    assert_eq!(
        distinct.len(),
        domain,
        "{name}: every entry of the domain is a row"
    );
}

/// A little-endian byte limb vector's value.
fn bytes_value(limbs: &[u32]) -> Option<u64> {
    limbs.iter().rev().try_fold(0u64, |value, &limb| {
        (limb < 256).then(|| value.checked_mul(256).map(|v| v + u64::from(limb)))?
    })
}

#[test]
fn range256_is_every_byte() {
    use vos_pvm_proof::chips::range_multiplicity::PreprocessedColumn as P;
    assert_eq!(P::Value.offset(), 0);
    assert_table("range256", &table(&RangeMultiplicity256), 256, |row| {
        row[0] < 256
    });
}

#[test]
fn bitand_is_the_nibbles_and() {
    use vos_pvm_proof::chips::bitwise_lookup::PreprocessedColumn as P;
    let (a, b, and) = (P::A.offset(), P::B.offset(), P::AndResult.offset());
    assert_table("bitand", &table(&BitwiseLookupChip), 256, |row| {
        row[a] < 16 && row[b] < 16 && row[and] == row[a] & row[b]
    });
}

#[test]
fn bitandbyte_is_the_bytes_and() {
    use vos_pvm_proof::chips::bitwise_and_byte::PreprocessedColumn as P;
    let (a, b, and) = (P::A.offset(), P::B.offset(), P::AndResult.offset());
    assert_table("bitandbyte", &table(&BitwiseAndByteChip), 1 << 16, |row| {
        row[a] < 256 && row[b] < 256 && row[and] == row[a] & row[b]
    });
}

#[test]
fn byte_to_bits_is_each_byte_s_bits() {
    use vos_pvm_proof::chips::byte_to_bits::PreprocessedColumn as P;
    let byte = P::Byte.offset();
    let bits = [
        P::Bit0,
        P::Bit1,
        P::Bit2,
        P::Bit3,
        P::Bit4,
        P::Bit5,
        P::Bit6,
        P::Bit7,
    ]
    .map(P::offset);
    assert_table("byte_to_bits", &table(&ByteToBitsChip), 256, |row| {
        row[byte] < 256
            && bits
                .iter()
                .enumerate()
                .all(|(i, &bit)| row[bit] == (row[byte] >> i) & 1)
    });
}

#[test]
fn pow2_is_two_to_each_shift() {
    use vos_pvm_proof::chips::power_of_two::PreprocessedColumn as P;
    let shift = P::ShiftAmount.offset();
    let power = P::PowerVal.offset();
    let width = P::PowerVal.size();
    assert_table("pow2", &table(&PowerOfTwoChip), 64, |row| {
        row[shift] < 64 && bytes_value(&row[power..power + width]) == Some(1u64 << row[shift])
    });
}

#[test]
fn popcount_is_each_byte_s_ones() {
    use vos_pvm_proof::chips::popcount::PreprocessedColumn as P;
    let (byte, count) = (P::Byte.offset(), P::Popcount.offset());
    assert_table("popcount", &table(&PopcountChip), 256, |row| {
        row[byte] < 256 && row[count] == row[byte].count_ones()
    });
}

#[test]
fn bitcount_is_each_byte_s_zeros() {
    use vos_pvm_proof::chips::bitcount::PreprocessedColumn as P;
    let (byte, lz, tz) = (P::Byte.offset(), P::LzByte.offset(), P::TzByte.offset());
    assert_table("bitcount", &table(&BitcountChip), 256, |row| {
        row[byte] < 256
            && row[lz] == (row[byte] as u8).leading_zeros()
            && row[tz] == (row[byte] as u8).trailing_zeros()
    });
}
