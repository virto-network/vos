//! Serialize/deserialize a live `Pvm` continuation as a CoreVM-style
//! split: a small **header** (PC + 13 registers + heap state +
//! iters + a 32-byte commitment to flat_mem) plus a separate **body**
//! (the flat_mem bytes themselves, content-addressed by that
//! commitment).
//!
//! This mirrors how CoreVM-on-JAM persists continuations: the cheap,
//! small metadata lives in the service's on-chain storage, while the
//! bulky memory image lives in the data-availability layer keyed by
//! its hash. JAM accumulate writes the header via `set_storage`; the
//! refine reader on the next round fetches the body from DA by
//! commitment and reassembles the live PVM.
//!
//! ## Header wire format (version 2)
//!
//! ```text
//! offset  size  field
//! 0       4     magic = b"VPVM"
//! 4       1     version = 2
//! 5       3     reserved
//! 8       4     pc: u32 LE
//! 12      4     heap_base: u32 LE
//! 16      4     heap_top: u32 LE
//! 20      1     need_gas_charge: u8
//! 21      3     reserved
//! 24      4     iters: u32 LE
//! 28      4     flat_mem_len: u32 LE
//! 32      32    commitment: blake2b-256(flat_mem)
//! 64      104   registers: 13 × u64 LE
//! 168     -     end (HEADER_SIZE)
//! ```
//!
//! Gas, code, bitmask, jump_table, and block_gas_costs are **not**
//! serialized: they're either per-invocation (gas) or derived from the
//! immutable blob (the rest). Rehydration re-runs `initialize_program`
//! on the host side and grafts the persisted dynamic state on top.

use alloc::vec::Vec;

/// Byte layout magic: b"VPVM".
const MAGIC: [u8; 4] = *b"VPVM";
/// Current header format version.
pub const VERSION: u8 = 2;
/// Size of the encoded continuation header.
pub const HEADER_SIZE: usize = 168;

// NOTE: `capture`/`restore` against a live `javm::Pvm` were removed when
// VOS migrated to the new `InvocationKernel` API, which does not (yet)
// expose a snapshot/restore surface. Only the `ContinuationHeader` type
// survives, so callers that persist headers stay source-compatible
// while the runtime cold-starts every tick.

/// Small persistable header for a suspended PVM continuation.
///
/// This is what gets written to a service's on-chain storage. The
/// `commitment` field is a blake2b-256 hash of the flat_mem body and
/// is the lookup key into the [`DataLayer`](crate::data_layer::DataLayer).
#[derive(Debug, Clone)]
pub struct ContinuationHeader {
    pub pc: u32,
    pub heap_base: u32,
    pub heap_top: u32,
    pub need_gas_charge: bool,
    pub iters: u32,
    pub flat_mem_len: u32,
    pub commitment: [u8; 32],
    pub registers: [u64; 13],
}

impl ContinuationHeader {
    /// Encode this header to a fixed-size byte vector.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&self.pc.to_le_bytes());
        out.extend_from_slice(&self.heap_base.to_le_bytes());
        out.extend_from_slice(&self.heap_top.to_le_bytes());
        out.push(self.need_gas_charge as u8);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&self.iters.to_le_bytes());
        out.extend_from_slice(&self.flat_mem_len.to_le_bytes());
        out.extend_from_slice(&self.commitment);
        for r in self.registers.iter() {
            out.extend_from_slice(&r.to_le_bytes());
        }
        debug_assert_eq!(out.len(), HEADER_SIZE);
        out
    }

    /// Decode a header from bytes. Returns `None` on malformed input.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        if bytes[0..4] != MAGIC || bytes[4] != VERSION {
            return None;
        }
        let pc = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let heap_base = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let heap_top = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let need_gas_charge = bytes[20] != 0;
        let iters = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
        let flat_mem_len = u32::from_le_bytes(bytes[28..32].try_into().ok()?);
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&bytes[32..64]);
        let mut registers = [0u64; 13];
        for (i, r) in registers.iter_mut().enumerate() {
            let off = 64 + i * 8;
            *r = u64::from_le_bytes(bytes[off..off + 8].try_into().ok()?);
        }
        Some(Self {
            pc,
            heap_base,
            heap_top,
            need_gas_charge,
            iters,
            flat_mem_len,
            commitment,
            registers,
        })
    }
}

/// Compute the data-layer commitment (blake2b-256) for a flat_mem body.
#[cfg(feature = "std")]
pub fn commit(flat_mem: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new().hash_length(32).hash(flat_mem);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn header_size_is_168() {
        assert_eq!(HEADER_SIZE, 168);
    }

    #[test]
    fn header_roundtrip() {
        let h = ContinuationHeader {
            pc: 0x1234,
            heap_base: 0x1000,
            heap_top: 0x2000,
            need_gas_charge: true,
            iters: 7,
            flat_mem_len: 16,
            commitment: [0xAB; 32],
            registers: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };
        let bytes = h.encode();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let d = ContinuationHeader::decode(&bytes).unwrap();
        assert_eq!(d.pc, 0x1234);
        assert_eq!(d.heap_base, 0x1000);
        assert_eq!(d.heap_top, 0x2000);
        assert!(d.need_gas_charge);
        assert_eq!(d.iters, 7);
        assert_eq!(d.flat_mem_len, 16);
        assert_eq!(d.commitment, [0xAB; 32]);
        assert_eq!(d.registers[12], 12);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(b"XXXX");
        assert!(ContinuationHeader::decode(&bytes).is_none());
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = 0xFF;
        assert!(ContinuationHeader::decode(&bytes).is_none());
    }

    #[test]
    fn commit_is_deterministic() {
        assert_eq!(commit(b"hello"), commit(b"hello"));
        assert_ne!(commit(b"hello"), commit(b"world"));
    }
}
