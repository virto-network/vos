//! A kernel's io-hash: what its proof binds of a statement, the kernel's
//! public arguments, its output and the roots it read.
//!
//! `io_hash = BLAKE2b-256(IO_HASH_DOMAIN ‖ public_args ‖ output ‖ roots)`,
//! each field in its SCALE encoding: a byte vector a compact length then its
//! bytes, the roots a compact count then each [`RootRead`] as its fields
//! encode, a byte for its kind, the space's 32 bytes, the window as eight
//! little-endian bytes and the root's 32. So a venue that decodes a
//! statement re-encodes its fields to the same bytes.
//!
//! A kernel computes it through the BLAKE2b precompile and leaves it in
//! φ9..φ12 at its halt, eight little-endian bytes a register; a venue
//! recomputes it from the statement and compares.

use crate::blake2b::Blake2b256;

/// The io-hash's domain, absorbed first.
pub const IO_HASH_DOMAIN: &[u8] = b"vos/io/v1";

/// A root a kernel read: of what kind, whose space, as of which window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootRead {
    pub kind: u8,
    pub space: [u8; 32],
    pub window: u64,
    pub root: [u8; 32],
}

/// The io-hash of a kernel's run: `public_args` and `output` as the
/// kernel's statement carries them, `roots` the roots it read, in order.
pub fn compute_io_hash(public_args: &[u8], output: &[u8], roots: &[RootRead]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(IO_HASH_DOMAIN);
    for bytes in [public_args, output] {
        hasher.update(compact(bytes.len() as u64).as_slice());
        hasher.update(bytes);
    }
    hasher.update(compact(roots.len() as u64).as_slice());
    for root in roots {
        hasher.update(&[root.kind]);
        hasher.update(&root.space);
        hasher.update(&root.window.to_le_bytes());
        hasher.update(&root.root);
    }
    hasher.finalize()
}

/// A length's SCALE compact encoding, at most nine bytes.
struct Compact {
    bytes: [u8; 9],
    len: usize,
}

impl Compact {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn compact(value: u64) -> Compact {
    let mut bytes = [0u8; 9];
    let len = match value {
        0..=0x3f => {
            bytes[0] = (value as u8) << 2;
            1
        }
        0x40..=0x3fff => {
            bytes[..2].copy_from_slice(&(((value as u16) << 2) | 1).to_le_bytes());
            2
        }
        0x4000..=0x3fff_ffff => {
            bytes[..4].copy_from_slice(&(((value as u32) << 2) | 2).to_le_bytes());
            4
        }
        _ => {
            let width = 8 - value.leading_zeros() as usize / 8;
            bytes[0] = (((width - 4) as u8) << 2) | 3;
            bytes[1..=width].copy_from_slice(&value.to_le_bytes()[..width]);
            width + 1
        }
    };
    Compact { bytes, len }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SCALE's own vectors for the compact encoding's four modes.
    #[test]
    fn lengths_encode_as_scale_compacts() {
        let cases: [(u64, &[u8]); 8] = [
            (0, &[0x00]),
            (1, &[0x04]),
            (63, &[0xfc]),
            (64, &[0x01, 0x01]),
            (16_383, &[0xfd, 0xff]),
            (16_384, &[0x02, 0x00, 0x01, 0x00]),
            (1_073_741_823, &[0xfe, 0xff, 0xff, 0xff]),
            (1_073_741_824, &[0x03, 0x00, 0x00, 0x00, 0x40]),
        ];
        for (value, expected) in cases {
            assert_eq!(compact(value).as_slice(), expected, "{value}");
        }
        assert_eq!(
            compact(u64::MAX).as_slice(),
            [0x13, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    /// The io-hash is BLAKE2b-256 of its domain and the three fields'
    /// encodings, and tells every field, and where one ends, apart.
    #[test]
    fn the_io_hash_is_blake2b_of_the_encoded_fields() {
        use blake2::digest::{Digest, consts::U32};
        let root = RootRead {
            kind: 1,
            space: [0xa1; 32],
            window: 0x0102_0304_0506_0708,
            root: [0xb2; 32],
        };
        let mut encoded = alloc::vec::Vec::new();
        encoded.extend_from_slice(b"vos/io/v1");
        encoded.extend_from_slice(&[3 << 2, 1, 2, 3]);
        encoded.extend_from_slice(&[0]);
        encoded.extend_from_slice(&[1 << 2, 1]);
        encoded.extend_from_slice(&root.space);
        encoded.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        encoded.extend_from_slice(&root.root);
        let expected: [u8; 32] = blake2::Blake2b::<U32>::digest(&encoded).into();
        assert_eq!(compute_io_hash(&[1, 2, 3], &[], &[root]), expected);

        let hashes = [
            compute_io_hash(&[], &[], &[]),
            compute_io_hash(&[1], &[], &[]),
            compute_io_hash(&[], &[1], &[]),
            compute_io_hash(&[1, 2], &[], &[]),
            compute_io_hash(&[1], &[2], &[]),
            compute_io_hash(&[], &[], &[root]),
        ];
        for (index, hash) in hashes.iter().enumerate() {
            assert!(!hashes[..index].contains(hash), "{index}");
        }
    }
}
