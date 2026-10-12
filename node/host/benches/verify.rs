//! What a signature check costs (slice 3, step 3.10): ed25519 with the
//! key decompressed on every check, as the node's ingress does, and with
//! it decompressed once, kept; `verify_strict` both ways, and `verify`
//! beside them. Run it pinned, e.g. `taskset -c 0` (a P-core) and
//! `taskset -c 12` (an E-core) on the reference laptop.
//!
//! `cargo bench -p vos-node --bench verify`.

use std::time::Instant;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const ROUNDS: u32 = 20_000;

fn time(name: &str, mut check: impl FnMut() -> bool) {
    // Warm up, then time.
    for _ in 0..1_000 {
        assert!(check());
    }
    let started = Instant::now();
    for _ in 0..ROUNDS {
        assert!(check());
    }
    let each = started.elapsed() / ROUNDS;
    println!("{name}: {:.1} µs a check", each.as_secs_f64() * 1e6);
}

fn main() {
    if std::env::args().any(|arg| arg == "--list") {
        return;
    }
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let message = vec![42u8; 200];
    let signature = key.sign(&message).to_bytes();
    time("decompressed each time, strict", || {
        VerifyingKey::from_bytes(&public).is_ok_and(|key| {
            key.verify_strict(&message, &Signature::from_bytes(&signature))
                .is_ok()
        })
    });
    let kept = VerifyingKey::from_bytes(&public).unwrap();
    time("decompressed once, strict", || {
        kept.verify_strict(&message, &Signature::from_bytes(&signature))
            .is_ok()
    });
    time("decompressed once, not strict", || {
        ed25519_dalek::Verifier::verify(&kept, &message, &Signature::from_bytes(&signature)).is_ok()
    });
}
