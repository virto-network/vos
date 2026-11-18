//! The key transforms and scan bounds.

use proptest::prelude::*;
use vos_tree::keys::{after, escape, hashed, ordered, prefix_end, private, unescape};

use crate::common::{H, raw_key};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Escaping keeps the raw keys' byte order, no escaped key prefixes
    /// another, and it decodes back.
    #[test]
    fn escape_keeps_order_and_is_prefix_free(a in raw_key(), b in raw_key()) {
        let (x, y) = (escape(&a), escape(&b));
        prop_assert_eq!(x.cmp(&y), a.cmp(&b));
        if a != b {
            prop_assert!(!x.starts_with(&y) && !y.starts_with(&x));
        }
        prop_assert_eq!(unescape(&x), Some((a.clone(), x.len())));
        let mut tail = x.clone();
        tail.extend_from_slice(&y);
        prop_assert_eq!(unescape(&tail), Some((a.clone(), x.len())), "a row key's tail");
        prop_assert_eq!(ordered(&a), x);
    }

    /// The hashed transform keeps the raw key after the hash, so a scan
    /// returns it, and stays prefix-free.
    #[test]
    fn hashed_keys_carry_their_raw_key(a in raw_key(), b in raw_key()) {
        let (x, y) = (hashed(&H, &a), hashed(&H, &b));
        prop_assert_eq!(&x[..16], &private(&H, &a)[..16]);
        prop_assert_eq!(unescape(&x[16..]), Some((a.clone(), x.len() - 16)));
        if a != b {
            prop_assert!(!x.starts_with(&y) && !y.starts_with(&x));
        }
    }

    /// A key starts with a prefix exactly when it lies in
    /// `[prefix, prefix_end(prefix))`, and `after(key)` is the least string
    /// above it.
    #[test]
    fn scan_bounds(prefix in raw_key(), key in raw_key(), other in raw_key()) {
        let inside = key.as_slice() >= prefix.as_slice()
            && prefix_end(&prefix).is_none_or(|end| key < end);
        prop_assert_eq!(key.starts_with(&prefix), inside);
        let next = after(&key);
        prop_assert!(key < next);
        prop_assert!(other <= key || other >= next);
    }
}

/// Escaping a byte at a time, as the format defines it.
fn plain_escape(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &byte in key {
        out.push(byte);
        if byte == 0 {
            out.push(0xFF);
        }
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// Keys of up to 64 bytes, mostly zeros, and a buffer offset that puts them
/// at every alignment.
fn zero_heavy() -> impl Strategy<Value = (Vec<u8>, usize)> {
    let byte = prop_oneof![4 => Just(0u8), 1 => Just(0xFF), 1 => any::<u8>()];
    (prop::collection::vec(byte, 0..=64), 0usize..8)
}

/// `key` at `offset` bytes into a buffer.
fn placed(key: &[u8], offset: usize) -> Vec<u8> {
    [&vec![7u8; offset][..], key].concat()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// The word-at-a-time escape and unescape agree with a byte loop at
    /// every alignment, and keep order, prefix-freedom and the round trip.
    #[test]
    fn escape_agrees_with_a_byte_loop((a, at) in zero_heavy(), (b, bt) in zero_heavy()) {
        let (x_buffer, y_buffer) = (placed(&a, at), placed(&b, bt));
        let (x, y) = (escape(&x_buffer[at..]), escape(&y_buffer[bt..]));
        prop_assert_eq!(&x, &plain_escape(&a));
        prop_assert_eq!(x.cmp(&y), a.cmp(&b));
        if a != b {
            prop_assert!(!x.starts_with(&y) && !y.starts_with(&x));
        }
        let mut tail = placed(&x, bt);
        tail.extend_from_slice(&y);
        prop_assert_eq!(unescape(&tail[bt..]), Some((a.clone(), x.len())));
        prop_assert_eq!(unescape(&x[..x.len() - 1]), None, "cut short");
    }
}

#[test]
fn prefix_end_drops_trailing_ff() {
    assert_eq!(prefix_end(b"a/"), Some(b"a0".to_vec()));
    assert_eq!(prefix_end(&[0x01, 0xFF, 0xFF]), Some(vec![0x02]));
    assert_eq!(prefix_end(&[0xFF, 0xFF]), None);
    assert_eq!(prefix_end(&[]), None);
}

#[test]
fn unescape_refuses_what_escape_never_writes() {
    assert_eq!(unescape(&[0x61, 0x00]), None, "a lone 0x00 at the end");
    assert_eq!(
        unescape(&[0x61, 0x00, 0x01]),
        None,
        "0x00 before another byte"
    );
    assert_eq!(unescape(&[0x61]), None, "no terminator");
}
