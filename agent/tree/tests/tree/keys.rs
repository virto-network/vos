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
