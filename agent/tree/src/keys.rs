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
///
/// On the PVM every load costs as much, a byte's as a word's, and a small
/// copy as much as many: runs of nonzero bytes are copied whole, zeros are
/// read eight at a time where a whole aligned word holds them, and the
/// buffer is zero-filled, so a zero needs only its `0xFF` stored.
pub fn escape_into(key: &[u8], out: &mut Vec<u8>) {
    let Some(first) = first_zero(key) else {
        out.reserve(key.len() + 2);
        out.extend_from_slice(key);
        out.extend_from_slice(&[0, 0]);
        return;
    };
    let start = out.len();
    out.resize(start + first + 2 * (key.len() - first) + 2, 0);
    let buffer = &mut out[start..];
    let mut written = 0;
    let mut rest = key;
    while !rest.is_empty() {
        let run = first_zero(rest).unwrap_or(rest.len());
        buffer[written..written + run].copy_from_slice(&rest[..run]);
        written += run;
        rest = &rest[run..];
        loop {
            if aligned_word(rest) == Some(0) {
                for pair in buffer[written..written + 16].chunks_exact_mut(2) {
                    pair[1] = 0xFF;
                }
                written += 16;
                rest = &rest[8..];
            } else if let Some((&0, after)) = rest.split_first() {
                buffer[written + 1] = 0xFF;
                written += 2;
                rest = after;
            } else {
                break;
            }
        }
    }
    out.truncate(start + written + 2);
}

/// The escaped key at the front of `bytes`: the raw key and the bytes its
/// escaped form takes, or `None` if `bytes` does not start with one.
pub fn unescape(bytes: &[u8]) -> Option<(Vec<u8>, usize)> {
    // Zero-filled, so an escaped zero needs no store; each byte of the key
    // takes at least one of `bytes`.
    let mut key = alloc::vec![0; bytes.len()];
    let mut written = 0;
    let mut at = 0;
    loop {
        if *bytes.get(at)? != 0 {
            let run = first_zero(&bytes[at..])?;
            key[written..written + run].copy_from_slice(&bytes[at..at + run]);
            written += run;
            at += run;
        } else if aligned_word(&bytes[at..]) == Some(ESCAPED_ZEROS) {
            // Four escaped zeros at once.
            written += 4;
            at += 8;
        } else {
            match *bytes.get(at + 1)? {
                0xFF => {
                    written += 1;
                    at += 2;
                }
                0 => {
                    key.truncate(written);
                    return Some((key, at + 2));
                }
                _ => return None,
            }
        }
    }
}

/// Four escaped zero bytes, as a word reads them.
const ESCAPED_ZEROS: u64 = u64::from_ne_bytes([0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF]);

/// The first eight bytes of `bytes` as a word, when they are aligned as one.
fn aligned_word(bytes: &[u8]) -> Option<u64> {
    let aligned = bytes.as_ptr().cast::<u64>().is_aligned();
    // SAFETY: eight bytes from an address aligned for a `u64`, which every
    // bit pattern is.
    (aligned && bytes.len() >= 8).then(|| unsafe { bytes.as_ptr().cast::<u64>().read() })
}

/// The first zero byte of `bytes`, read a word at a time where the words
/// are aligned: on the PVM a byte's load costs as much as a word's. A zero
/// at the very front is the callers' to take without it.
fn first_zero(bytes: &[u8]) -> Option<usize> {
    const LOW: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    // SAFETY: every bit pattern is a `u64`.
    let (head, words, _) = unsafe { bytes.align_to::<u64>() };
    if let Some(at) = head.iter().position(|&byte| byte == 0) {
        return Some(at);
    }
    // A word holds a zero byte exactly when this sets one of its high bits.
    let clear = words
        .iter()
        .position(|&word| word.wrapping_sub(LOW) & !word & HIGH != 0)
        .unwrap_or(words.len());
    let from = head.len() + clear * 8;
    bytes[from..]
        .iter()
        .position(|&byte| byte == 0)
        .map(|at| from + at)
}

/// The ordered transform: a table scans in key order.
pub fn ordered(key: &[u8]) -> Vec<u8> {
    escape(key)
}

/// The hashed transform, `H128(key) ‖ escape(key)`: paths stay about
/// log₂ n deep whatever keys clients choose, and the raw key stays in the
/// row key for a scan to return.
pub fn hashed<H: Hasher>(hasher: &H, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + key.len() + 2);
    hashed_into(hasher, key, &mut out);
    out
}

/// Append `key` under the hashed transform to `out`.
pub fn hashed_into<H: Hasher>(hasher: &H, key: &[u8], out: &mut Vec<u8>) {
    let digest = hasher.hash(TAG_KEY, &[key]);
    out.extend_from_slice(&digest[..16]);
    escape_into(key, out);
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
