//! What a signature check costs: ed25519's strict check with the key
//! decompressed at every check, and with it decompressed once and kept;
//! and a key's decompression alone. The variants alternate in short blocks
//! and each reports its median block, so neither meets the core in another
//! state. Run it pinned to a core whose sibling is idle, e.g. `taskset -c 1`
//! on the reference laptop.
//!
//! `cargo bench -p vos-node --bench verify`.

use std::time::Instant;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// One way to check a signature.
type Check<'a> = Box<dyn FnMut() -> bool + 'a>;

const BLOCK: u32 = 2_000;
const BLOCKS: usize = 25;

/// Microseconds each of `BLOCK` calls of `check` takes, once.
fn block(check: &mut dyn FnMut() -> bool) -> f64 {
    let started = Instant::now();
    for _ in 0..BLOCK {
        assert!(check());
    }
    started.elapsed().as_secs_f64() * 1e6 / f64::from(BLOCK)
}

fn main() {
    if std::env::args().any(|arg| arg == "--list") {
        return;
    }
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let message = vec![42u8; 200];
    let signature = key.sign(&message).to_bytes();
    let kept = VerifyingKey::from_bytes(&public).unwrap();
    let mut variants: Vec<(&str, Check)> = vec![
        (
            "strict, the key decompressed each time",
            Box::new(|| {
                VerifyingKey::from_bytes(&public).is_ok_and(|key| {
                    key.verify_strict(&message, &Signature::from_bytes(&signature))
                        .is_ok()
                })
            }),
        ),
        (
            "strict, the key kept",
            Box::new(|| {
                kept.verify_strict(&message, &Signature::from_bytes(&signature))
                    .is_ok()
            }),
        ),
        (
            "a key's decompression alone",
            Box::new(|| VerifyingKey::from_bytes(&public).is_ok()),
        ),
    ];
    // Warm up, then alternate.
    for (_, check) in &mut variants {
        block(check.as_mut());
    }
    let mut times: Vec<Vec<f64>> = vec![Vec::new(); variants.len()];
    for _ in 0..BLOCKS {
        for (at, (_, check)) in variants.iter_mut().enumerate() {
            times[at].push(block(check.as_mut()));
        }
    }
    for ((name, _), times) in variants.iter().zip(&mut times) {
        times.sort_by(f64::total_cmp);
        println!(
            "{name}: {:.1} µs (blocks from {:.1} to {:.1})",
            times[times.len() / 2],
            times[0],
            times[times.len() - 1]
        );
    }
}
