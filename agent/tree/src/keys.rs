//! Key transforms, scan bounds, and the bit arithmetic of paths.

use alloc::vec::Vec;

use crate::Hash;
use crate::hash::{Hasher, TAG_KEY};

/// `key` escaped: each `0x00` becomes `0x00 0xFF`, and `0x00 0x00` ends it.
///
/// No escaped key prefixes another: `0x00 0x00` never occurs inside an
/// escaped body, and no body ends in a lone `0x00`. Escaping keeps byte
/// order: at the first differing byte nonzero bytes compare as they did,
/// `0x00 0xFF` sorts below any nonzero byte, and a key that prefixes another
/// continues with `0x00 0x00`, below both continuations of the longer one.
pub fn escape(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 2);
    escape_into(key, &mut out);
    out
}

/// Append `key` escaped to `out`.
pub fn escape_into(key: &[u8], out: &mut Vec<u8>) {
    for &byte in key {
        out.push(byte);
        if byte == 0 {
            out.push(0xFF);
        }
    }
    out.extend_from_slice(&[0, 0]);
}

/// The escaped key at the front of `bytes`: the raw key and the bytes its
/// escaped form takes, or `None` if `bytes` does not start with one.
pub fn unescape(bytes: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut key = Vec::new();
    let mut at = 0;
    loop {
        match *bytes.get(at)? {
            0 => match *bytes.get(at + 1)? {
                0xFF => {
                    key.push(0);
                    at += 2;
                }
                0 => return Some((key, at + 2)),
                _ => return None,
            },
            byte => {
                key.push(byte);
                at += 1;
            }
        }
    }
}

/// The ordered transform: a table scans in key order.
pub fn ordered(key: &[u8]) -> Vec<u8> {
    escape(key)
}

/// The hashed transform, `H128(key) ‖ escape(key)`: paths stay about
/// log₂ n deep whatever keys clients choose, and the raw key stays in the
/// row key for a scan to return.
pub fn hashed<H: Hasher>(hasher: &H, key: &[u8]) -> Vec<u8> {
    let digest = hasher.hash(TAG_KEY, &[key]);
    let mut out = Vec::with_capacity(16 + key.len() + 2);
    out.extend_from_slice(&digest[..16]);
    escape_into(key, &mut out);
    out
}

/// The private transform, `H(key)`: a shared path hides its neighbours' keys,
/// and the table does not iterate.
pub fn private<H: Hasher>(hasher: &H, key: &[u8]) -> Hash {
    hasher.hash(TAG_KEY, &[key])
}

/// The least byte string past every key that starts with `prefix`: its last
/// byte below `0xFF` incremented, the bytes after it dropped. `None` when
/// there is none, and a scan of the prefix runs to the tree's right edge.
pub fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let last = prefix.iter().rposition(|&byte| byte != 0xFF)?;
    let mut end = prefix[..=last].to_vec();
    end[last] += 1;
    Some(end)
}

/// The least byte string above `key`, `key ‖ 0x00`: a bounded scan's range
/// ends there, just past the last row it returned.
pub fn after(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 1);
    out.extend_from_slice(key);
    out.push(0);
    out
}

/// Bit `level` of `key`, 0 past its end.
pub(crate) fn bit(key: &[u8], level: u16) -> usize {
    let level = usize::from(level);
    key.get(level / 8)
        .map_or(0, |byte| usize::from((byte >> (7 - level % 8)) & 1))
}

/// The first bit at which `a` and `b` differ, or `None` if one is a prefix
/// of the other.
pub(crate) fn first_difference(a: &[u8], b: &[u8]) -> Option<u16> {
    let at = a.iter().zip(b).position(|(x, y)| x != y)?;
    let level = at * 8 + (a[at] ^ b[at]).leading_zeros() as usize;
    Some(level as u16)
}

/// The first `level` bits of `key` in whole bytes, the bits past `level`
/// zero: the place of a branch at `level` over `key`.
pub(crate) fn prefix_of(key: &[u8], level: u16) -> Vec<u8> {
    let level = usize::from(level);
    let mut prefix = key[..level.div_ceil(8)].to_vec();
    if !level.is_multiple_of(8) {
        *prefix.last_mut().expect("a partial byte") &= 0xFF << (8 - level % 8);
    }
    prefix
}

/// Where a bound lies against the keys of a subtree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    /// Below every key in it.
    Below,
    /// Above every key in it.
    Above,
    /// Sharing their first `level` bits, with more bits of its own: the
    /// bound's bit at `level` decides further.
    Within,
}

/// Where `bound` lies against the keys of the subtree of a branch at
/// `level` with `prefix`.
pub(crate) fn side(bound: &[u8], prefix: &[u8], level: u16) -> Side {
    let level = usize::from(level);
    let shared = level.min(bound.len() * 8);
    for at in 0..shared.div_ceil(8) {
        let bits = (shared - at * 8).min(8);
        let differ = (bound[at] ^ prefix[at]) & (0xFF << (8 - bits));
        if differ != 0 {
            let level = (at * 8 + differ.leading_zeros() as usize) as u16;
            return if bit(bound, level) == 1 {
                Side::Above
            } else {
                Side::Below
            };
        }
    }
    if bound.len() * 8 <= level {
        // A proper prefix of every key in the subtree.
        Side::Below
    } else {
        Side::Within
    }
}
