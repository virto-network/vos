//! GP standard-program (SPI) blob emitter.
//!
//! Serializes the graypaper v0.7.2 *standard program* format — the blob
//! `vos_pvm::spi::parse_standard_program` consumes. This is the byte-for-byte
//! inverse of that parser and its `deblob_compact` code decoder:
//!
//! ```text
//!   program:  E₃(|o|) ‖ E₃(|w|) ‖ E₂(z) ‖ E₃(s) ‖ o ‖ w ‖ E₄(|c|) ‖ c
//!   c:        E(|j|) ‖ E₁(z_j) ‖ E(|code|) ‖ jump_table ‖ code ‖ packed_bitmask
//! ```
//!
//! where `o` = read-only data, `w` = read-write data, `z` = additional zeroed
//! heap pages, `s` = stack size in bytes, `z_j` = the jump-table entry width
//! in bytes, `Eₙ(·)` is a fixed-width little-endian integer, and `E(·)` is
//! the JAM natural (GP eq C.1). No metadata prefix is emitted — the result is
//! a bare program blob (`parse_standard_program` accepts both forms).

use crate::emitter::{jump_table_entry_size, pack_bitmask};

/// Encode a JAM natural (GP eq C.1) into 1–9 bytes, appending to `out`.
///
/// Mirrors `upstream_crypto::gp072_codec::encode_nat` (kept local so the
/// transpiler does not pull the crypto stack for ten lines of codec); the
/// exact inverse of `vos_pvm::spi::read_nat`, pinned by the tests below.
pub fn encode_nat(x: u64, out: &mut Vec<u8>) {
    // Smallest length class l in 0..=7 with x < 2^(7·(l+1)); 8 otherwise.
    let l = (0u8..8).find(|l| x < 1u64 << (7 * (u32::from(*l) + 1)));
    match l {
        Some(0) => out.push(x as u8),
        Some(l) => {
            // header = 2^8 − 2^(8−l) + ⌊x / 2^(8l)⌋, then l LE value bytes.
            out.push((256u64 - (256u64 >> l) + (x >> (8 * u32::from(l)))) as u8);
            out.extend_from_slice(&x.to_le_bytes()[..usize::from(l)]);
        }
        None => {
            out.push(0xFF);
            out.extend_from_slice(&x.to_le_bytes());
        }
    }
}

/// Serialize a GP standard-program (SPI) blob from its parts.
///
/// `ro_data`/`rw_data` are the initialization bytes of the read-only and
/// read-write regions **relative to their GP layout bases** (`Z_Z` and
/// `2·Z_Z + zone_round(|o|)` respectively — see `StandardProgram::layout`),
/// `heap_pages` is the zeroed heap page count beyond `rw_data`, `stack_size`
/// is the stack byte capacity, and `code`/`bitmask`/`jump_table` are the GP
/// instruction encoding exactly as the manifest emitter consumes them
/// (`bitmask` unpacked, one byte per code byte).
///
/// # Panics
///
/// Panics if a field exceeds its wire width (`|o|`, `|w|`, `s` ≥ 2²⁴ — they
/// are `E₃`-encoded) or if `code` and `bitmask` lengths differ. Callers that
/// cannot rule these out must check first (`link_elf_spi` does).
pub fn build_spi_blob(
    ro_data: &[u8],
    rw_data: &[u8],
    heap_pages: u16,
    stack_size: u32,
    code: &[u8],
    bitmask: &[u8],
    jump_table: &[u32],
) -> Vec<u8> {
    assert_eq!(
        code.len(),
        bitmask.len(),
        "code and bitmask must have same length"
    );
    assert!(ro_data.len() < 1 << 24, "ro_data exceeds E₃ width");
    assert!(rw_data.len() < 1 << 24, "rw_data exceeds E₃ width");
    assert!(stack_size < 1 << 24, "stack_size exceeds E₃ width");

    // Code sub-blob (deblob compact form):
    // E(|j|) ‖ E₁(z_j) ‖ E(|code|) ‖ jump_table ‖ code ‖ packed_bitmask.
    let entry_size = jump_table_entry_size(jump_table);
    let mut c = Vec::new();
    encode_nat(jump_table.len() as u64, &mut c);
    c.push(entry_size);
    encode_nat(code.len() as u64, &mut c);
    for &entry in jump_table {
        c.extend_from_slice(&entry.to_le_bytes()[..usize::from(entry_size)]);
    }
    c.extend_from_slice(code);
    c.extend_from_slice(&pack_bitmask(bitmask));

    // Program: E₃(|o|) ‖ E₃(|w|) ‖ E₂(z) ‖ E₃(s) ‖ o ‖ w ‖ E₄(|c|) ‖ c.
    let mut blob = Vec::with_capacity(15 + ro_data.len() + rw_data.len() + c.len());
    blob.extend_from_slice(&(ro_data.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&(rw_data.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&heap_pages.to_le_bytes());
    blob.extend_from_slice(&stack_size.to_le_bytes()[..3]);
    blob.extend_from_slice(ro_data);
    blob.extend_from_slice(rw_data);
    blob.extend_from_slice(
        &u32::try_from(c.len())
            .expect("code sub-blob fits E₄")
            .to_le_bytes(),
    );
    blob.extend_from_slice(&c);
    blob
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use vos_pvm::spi::{parse_standard_program, read_nat};

    #[test]
    fn encode_nat_matches_read_nat_at_class_boundaries() {
        // Every length-class boundary of GP eq C.1, both sides.
        let cases: Vec<u64> = (1..=7u32)
            .flat_map(|l| [(1u64 << (7 * l)) - 1, 1u64 << (7 * l)])
            .chain([0, 1, (1 << 56) - 1, 1 << 56, u64::MAX])
            .collect();
        for x in cases {
            let mut buf = Vec::new();
            encode_nat(x, &mut buf);
            assert_eq!(
                read_nat(&buf, 0),
                Some((x, buf.len())),
                "round-trip failed for {x}"
            );
        }
    }

    proptest! {
        #[test]
        fn encode_nat_round_trips_any_u64(x: u64) {
            let mut buf = Vec::new();
            encode_nat(x, &mut buf);
            prop_assert_eq!(read_nat(&buf, 0), Some((x, buf.len())));
        }
    }

    /// The emitter is the literal inverse of `parse_standard_program`: every
    /// header field, both data sections, and the deblobbed code survive a
    /// round-trip — including a jump table wide enough for 2-byte entries
    /// and a code section long enough for a multi-byte length nat.
    #[test]
    fn spi_blob_round_trips_through_javm_parser() {
        let ro: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let rw = [0xBBu8; 77];
        // 300 instructions (> 127 forces a 2-byte code-length nat), each a
        // 1-byte opcode: trap (0) / fallthrough (1).
        let code: Vec<u8> = (0..300).map(|i| (i % 2) as u8).collect();
        let bitmask = vec![1u8; code.len()];
        // Entries above 0xFF force entry_size = 2.
        let jump_table: Vec<u32> = (0..40).map(|i| 10 + i * 12).collect();
        assert_eq!(jump_table_entry_size(&jump_table), 2);

        let blob = build_spi_blob(&ro, &rw, 3, 8192, &code, &bitmask, &jump_table);
        let prog = parse_standard_program(&blob).expect("emitted blob parses");
        assert_eq!(prog.ro_data, ro);
        assert_eq!(prog.rw_data, rw);
        assert_eq!(prog.heap_pages, 3);
        assert_eq!(prog.stack_size, 8192);
        assert_eq!(prog.code.code, code);
        assert_eq!(prog.code.bitmask, bitmask);
        assert_eq!(prog.code.jump_table, jump_table);
    }

    /// Degenerate shape: no data, no jump table, minimal code.
    #[test]
    fn empty_sections_round_trip() {
        let blob = build_spi_blob(&[], &[], 0, 0, &[0], &[1], &[]);
        let prog = parse_standard_program(&blob).expect("parses");
        assert!(prog.ro_data.is_empty());
        assert!(prog.rw_data.is_empty());
        assert_eq!(prog.heap_pages, 0);
        assert_eq!(prog.stack_size, 0);
        assert_eq!(prog.code.code, [0]);
        assert!(prog.code.jump_table.is_empty());
    }
}
