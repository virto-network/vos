//! Durable JAVM kernel continuation envelope.
//!
//! The small header lives in service storage. Its content-addressed body is
//! the canonical `javm::snapshot::KernelSnapshot` wire, including exact PCs,
//! registers, gas, capabilities, nested call stack, scheduler state, and
//! memory blocks. The runtime never reconstructs a continuation from a flat
//! memory image or starts it at PC 0.
//!
//! ## Header wire format (version 3)
//!
//! ```text
//! offset  size  field
//! 0       4     magic = b"VKS2"
//! 4       1     version = 3
//! 5       3     reserved
//! 8       4     snapshot_len: u32 LE
//! 12      32    commitment: blake2b-256(snapshot wire)
//! 44      32    VOS execution-semantics ID
//! 76      -     end (HEADER_SIZE)
//! ```

use alloc::vec::Vec;

/// Byte layout magic: b"VKS2".
const MAGIC: [u8; 4] = *b"VKS2";
/// Current header format version.
pub const VERSION: u8 = 3;
/// Size of the encoded continuation header.
pub const HEADER_SIZE: usize = 76;

/// Small persistable header for an exact suspended kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationHeader {
    pub snapshot_len: u32,
    pub commitment: [u8; 32],
    pub execution_semantics: [u8; 32],
}

impl ContinuationHeader {
    /// Encode this header to a fixed-size byte vector.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&self.snapshot_len.to_le_bytes());
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.execution_semantics);
        debug_assert_eq!(out.len(), HEADER_SIZE);
        out
    }

    /// Decode a header from bytes. Returns `None` on malformed input.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HEADER_SIZE {
            return None;
        }
        if bytes[0..4] != MAGIC || bytes[4] != VERSION || bytes[5..8] != [0; 3] {
            return None;
        }
        let snapshot_len = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&bytes[12..44]);
        let mut execution_semantics = [0u8; 32];
        execution_semantics.copy_from_slice(&bytes[44..76]);
        Some(Self {
            snapshot_len,
            commitment,
            execution_semantics,
        })
    }
}

/// Compute the data-layer commitment (blake2b-256) for a snapshot body.
#[cfg(feature = "std")]
pub fn commit(body: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new().hash_length(32).hash(body);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn header_size_is_76() {
        assert_eq!(HEADER_SIZE, 76);
    }

    #[test]
    fn header_roundtrip() {
        let h = ContinuationHeader {
            snapshot_len: 16,
            commitment: [0xAB; 32],
            execution_semantics: [0xCD; 32],
        };
        let bytes = h.encode();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let d = ContinuationHeader::decode(&bytes).unwrap();
        assert_eq!(d.snapshot_len, 16);
        assert_eq!(d.commitment, [0xAB; 32]);
        assert_eq!(d.execution_semantics, [0xCD; 32]);
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
    fn rejects_trailing_bytes_and_nonzero_reserved_bytes() {
        let mut bytes = ContinuationHeader {
            snapshot_len: 0,
            commitment: [0; 32],
            execution_semantics: [0; 32],
        }
        .encode();
        bytes.push(0);
        assert!(ContinuationHeader::decode(&bytes).is_none());
        bytes.pop();
        bytes[5] = 1;
        assert!(ContinuationHeader::decode(&bytes).is_none());
    }

    #[test]
    fn commit_is_deterministic() {
        assert_eq!(commit(b"hello"), commit(b"hello"));
        assert_ne!(commit(b"hello"), commit(b"world"));
    }
}
