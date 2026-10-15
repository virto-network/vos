//! Clients' signatures, checked against keys kept decompressed.

use std::sync::LazyLock;

use ed25519_dalek::{Signature, VerifyingKey};
use vos_wire::defaults;
use vos_wire::ingress::{Call, call_message};

pub(crate) fn verify(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    verify_in(&KEYS, key, message, signature)
}

/// The keys signature checks decompressed: decompressing one is about a
/// tenth of a check. One cache for the whole node, every agent's sessions
/// and every executor, sized to one agent's live sessions: with many busy
/// agents it overflows, and a key evicted is decompressed again. Only keys
/// that decompress are kept.
static KEYS: LazyLock<Keys> = LazyLock::new(|| kept_keys(defaults::MAX_SESSIONS as usize));

type Keys = quick_cache::sync::Cache<[u8; 32], VerifyingKey>;

fn kept_keys(capacity: usize) -> Keys {
    quick_cache::sync::Cache::new(capacity)
}

fn verify_in(keys: &Keys, key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    verifying_key_in(keys, key).is_some_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// `bytes` decompressed, kept or now; none if they are no key.
fn verifying_key_in(keys: &Keys, bytes: &[u8; 32]) -> Option<VerifyingKey> {
    if let Some(key) = keys.get(bytes) {
        return Some(key);
    }
    let key = VerifyingKey::from_bytes(bytes).ok()?;
    keys.insert(*bytes, key);
    Some(key)
}

/// Whether `call` is signed by its session's key, for the agent whose
/// identity is `identity`.
pub(crate) fn signed(identity: &[u8; 32], call: &Call) -> bool {
    let message = call_message(
        identity,
        &call.session,
        call.sequence,
        call.instance,
        call.method,
        &call.arguments,
    );
    verify(&call.session.key, &message, &call.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// A kept key checks as a fresh one does: the right signature passes,
    /// and a wrong one fails, before and after it is kept.
    #[test]
    fn a_kept_key_checks_as_a_fresh_one() {
        let signing = SigningKey::from_bytes(&[3; 32]);
        let key = signing.verifying_key().to_bytes();
        let signature = signing.sign(b"a message").to_bytes();
        let mut wrong = signature;
        wrong[0] ^= 1;
        for _ in 0..2 {
            assert!(verify(&key, b"a message", &signature));
            assert!(!verify(&key, b"a message", &wrong));
            assert!(!verify(&key, b"another message", &signature));
        }
    }

    /// A check uses the key kept for its bytes: kept under other bytes,
    /// another key's signature passes for them, which only the cache does.
    #[test]
    fn a_check_uses_the_key_kept_for_its_bytes() {
        let keys = kept_keys(8);
        let signing = SigningKey::from_bytes(&[4; 32]);
        let other = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
        let signature = signing.sign(b"a message").to_bytes();
        assert!(!verify_in(&keys, &other, b"a message", &signature));
        keys.insert(other, signing.verifying_key());
        assert!(verify_in(&keys, &other, b"a message", &signature));
    }

    /// Bytes that are no key fail every time, and are not kept.
    #[test]
    fn bytes_that_are_no_key_are_not_kept() {
        let none = (0..=u8::MAX)
            .map(|byte| [byte; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("bytes that do not decompress");
        let keys = kept_keys(8);
        for _ in 0..2 {
            assert!(verifying_key_in(&keys, &none).is_none());
        }
        assert!(keys.get(&none).is_none());
        assert!(!verify(&none, b"a message", &[0; 64]));
    }

    /// The kept keys stay within their bound.
    #[test]
    fn the_kept_keys_stay_within_their_bound() {
        let keys = kept_keys(8);
        for seed in 0..100u8 {
            let key = SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes();
            assert!(verifying_key_in(&keys, &key).is_some());
        }
        assert!(keys.len() <= 8, "{} kept", keys.len());
    }
}
