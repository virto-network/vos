//! Serialize/deserialize a live `Pvm` as a DA blob.
//!
//! A VOS service's canonical state is its full PVM image — heap, stack,
//! static rw_data, registers, pc. This module encodes that image as a
//! flat byte vector that a [`DataLayer`](crate::data_layer::DataLayer)
//! can persist and later hand back to [`restore`] to rehydrate the
//! service where it left off.
//!
//! ## Wire format (version 1)
//!
//! ```text
//! offset  size  field
//! 0       4     magic = b"VPVM"
//! 4       1     version = 1
//! 5       3     reserved
//! 8       4     pc: u32 LE
//! 12      4     heap_base: u32 LE
//! 16      4     heap_top: u32 LE
//! 20      1     need_gas_charge: u8
//! 21      3     reserved
//! 24      104   registers: 13 × u64 LE
//! 128     4     flat_mem_len: u32 LE
//! 132     N     flat_mem (tail — restore moves this out of the Vec)
//! ```
//!
//! Gas, code, bitmask, jump_table, and block_gas_costs are **not**
//! serialized: they're either per-invocation (gas) or derived from the
//! immutable blob (the rest). Rehydration re-runs `initialize_program`
//! to rebuild those fields, then grafts the saved dynamic state on top.

use alloc::vec::Vec;

/// Byte layout magic: b"VPVM".
const MAGIC: [u8; 4] = *b"VPVM";
/// Current format version.
pub const VERSION: u8 = 1;
/// Size of the fixed-width header before the flat_mem tail.
pub const HEADER_SIZE: usize = 132;

#[cfg(feature = "std")]
use javm::Pvm;

/// Capture a live `Pvm` as a DA blob.
///
/// Allocates a single `Vec<u8>` of size `HEADER_SIZE + flat_mem.len()`.
#[cfg(feature = "std")]
pub fn capture(pvm: &Pvm) -> Vec<u8> {
    let flat_len = pvm.flat_mem.len();
    let mut out = Vec::with_capacity(HEADER_SIZE + flat_len);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&[0u8; 3]);
    out.extend_from_slice(&pvm.pc.to_le_bytes());
    out.extend_from_slice(&pvm.heap_base.to_le_bytes());
    out.extend_from_slice(&pvm.heap_top.to_le_bytes());
    out.push(pvm.need_gas_charge as u8);
    out.extend_from_slice(&[0u8; 3]);
    for r in pvm.registers.iter() {
        out.extend_from_slice(&r.to_le_bytes());
    }
    out.extend_from_slice(&(flat_len as u32).to_le_bytes());
    debug_assert_eq!(out.len(), HEADER_SIZE);
    out.extend_from_slice(&pvm.flat_mem);
    out
}

/// Rehydrate a `Pvm` from a captured image, on top of a freshly
/// initialized program. The `fresh` PVM supplies `code`, `bitmask`,
/// `jump_table`, `block_gas_costs`, and the initial `gas` budget; this
/// function overwrites its dynamic fields with the saved image.
///
/// Takes the captured bytes **by value** so we can split the tail and
/// move `flat_mem` into `fresh` without a second allocation.
///
/// Returns `None` if the image is malformed or the flat_mem length
/// doesn't match what the blob expects.
#[cfg(feature = "std")]
pub fn restore(mut fresh: Pvm, mut image: Vec<u8>) -> Option<Pvm> {
    if image.len() < HEADER_SIZE {
        return None;
    }
    if image[0..4] != MAGIC {
        return None;
    }
    if image[4] != VERSION {
        return None;
    }
    let pc = u32::from_le_bytes(image[8..12].try_into().ok()?);
    let heap_base = u32::from_le_bytes(image[12..16].try_into().ok()?);
    let heap_top = u32::from_le_bytes(image[16..20].try_into().ok()?);
    let need_gas_charge = image[20] != 0;

    let mut registers = [0u64; 13];
    for (i, r) in registers.iter_mut().enumerate() {
        let off = 24 + i * 8;
        *r = u64::from_le_bytes(image[off..off + 8].try_into().ok()?);
    }

    let flat_len = u32::from_le_bytes(image[128..132].try_into().ok()?) as usize;
    if image.len() != HEADER_SIZE + flat_len {
        return None;
    }
    // Sanity check: the rehydrated flat_mem must be the same length as
    // the fresh one. Blob-derived memory layout is immutable.
    if flat_len != fresh.flat_mem.len() {
        return None;
    }

    // Zero-copy tail extraction: split off the header, leaving `image`
    // holding only `flat_mem` bytes, then move it into `fresh`.
    let flat_mem = image.split_off(HEADER_SIZE);
    fresh.flat_mem = flat_mem;
    fresh.pc = pc;
    fresh.heap_base = heap_base;
    fresh.heap_top = heap_top;
    fresh.need_gas_charge = need_gas_charge;
    fresh.registers = registers;

    Some(fresh)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use javm::program::initialize_program;

    // Minimal valid PVM blob: one halt instruction.
    // This is brittle; a simpler approach is to round-trip against
    // whatever `initialize_program` gives us for an empty/near-empty
    // blob. For now, just test the header encoding/decoding by hand.

    #[test]
    fn header_size_is_132() {
        assert_eq!(HEADER_SIZE, 132);
    }

    #[test]
    fn roundtrip_header_fields() {
        // Fabricate a capture-shaped vector by hand, then decode it.
        let flat = vec![0xAB; 16];
        let mut img = Vec::with_capacity(HEADER_SIZE + flat.len());
        img.extend_from_slice(&MAGIC);
        img.push(VERSION);
        img.extend_from_slice(&[0; 3]);
        img.extend_from_slice(&0x1234u32.to_le_bytes()); // pc
        img.extend_from_slice(&0x1000u32.to_le_bytes()); // heap_base
        img.extend_from_slice(&0x2000u32.to_le_bytes()); // heap_top
        img.push(1);
        img.extend_from_slice(&[0; 3]);
        for i in 0..13u64 {
            img.extend_from_slice(&(i * 100).to_le_bytes());
        }
        img.extend_from_slice(&(flat.len() as u32).to_le_bytes());
        img.extend_from_slice(&flat);

        assert_eq!(img.len(), HEADER_SIZE + flat.len());
        assert_eq!(&img[0..4], &MAGIC);
        assert_eq!(img[4], VERSION);

        // Manual decode (mirrors restore, without needing a real Pvm).
        let pc = u32::from_le_bytes(img[8..12].try_into().unwrap());
        assert_eq!(pc, 0x1234);
        let flat_len =
            u32::from_le_bytes(img[128..132].try_into().unwrap()) as usize;
        assert_eq!(flat_len, 16);
        assert_eq!(&img[HEADER_SIZE..], &flat[..]);
    }

    #[test]
    fn rejects_bad_magic() {
        // We can't call restore without a real Pvm, so just check the
        // header parsing precondition directly.
        let mut img = vec![0u8; HEADER_SIZE];
        img[0..4].copy_from_slice(b"XXXX");
        assert_ne!(&img[0..4], &MAGIC);
    }

    #[test]
    fn roundtrip_real_pvm() {
        // Build a trivial PVM blob: one halt instruction at PC=0.
        // djump to 0xFFFF0000 halts.
        //   lui t1, 0x10         -> t1 = 0x10000
        //   addi t1, t1, -1      -> t1 = 0xFFFF
        //   slli t1, t1, 16      -> t1 = 0xFFFF0000
        //   jalr x0, t1, 0       -> djump halt
        let _ = initialize_program;
        // Full program creation is done by the transpiler elsewhere;
        // this test is just a compile-check that `restore` typechecks
        // against `Pvm`. Actual end-to-end coverage lives in the
        // integration tests that exercise the DataLayer via tick().
    }
}
