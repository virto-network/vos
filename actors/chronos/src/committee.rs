//! Wire codec for the voter list passed to [`crate::Chronos::set_committee`].

use alloc::vec::Vec;

/// Upper bound on committee size and per-voter id length, so a malformed
/// [`encode_committee`] blob can never drive an unbounded allocation. A voter
/// id is a `peer_id` multihash (tens of bytes); 256 is comfortably generous.
pub const MAX_COMMITTEE: usize = 1024;
const MAX_VOTER_ID_LEN: usize = 256;

/// Wire codec for the voter list passed to [`crate::Chronos::set_committee`]. A
/// handler parameter must map to a [`vos::Value`] variant and there is no
/// `Vec<Vec<u8>>` variant, so the variable-length `peer_id` list is flattened
/// into one length-prefixed blob: a `u16` count, then per voter a `u16` length
/// and that many bytes, all little-endian. Exported so the feeder encodes
/// identically.
pub fn encode_committee(voters: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(voters.len() as u16).to_le_bytes());
    for v in voters {
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

/// Inverse of [`encode_committee`]. Returns `None` on a malformed blob: a bad
/// length prefix, trailing garbage, an over-long voter id, or more than
/// [`MAX_COMMITTEE`] entries.
pub fn decode_committee(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut p = 0usize;
    let count = u16::from_le_bytes(bytes.get(p..p + 2)?.try_into().ok()?) as usize;
    p += 2;
    if count > MAX_COMMITTEE {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u16::from_le_bytes(bytes.get(p..p + 2)?.try_into().ok()?) as usize;
        p += 2;
        if len > MAX_VOTER_ID_LEN {
            return None;
        }
        out.push(bytes.get(p..p + len)?.to_vec());
        p += len;
    }
    if p != bytes.len() {
        return None; // trailing garbage
    }
    Some(out)
}
