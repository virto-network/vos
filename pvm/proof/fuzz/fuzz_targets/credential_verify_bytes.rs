//! Fuzz target: arbitrary bytes through the final verifier's
//! `credential::verify_bytes`, the call ingress makes on an executor: the
//! input's first byte picks the statement's kind, the next its public
//! words (four little-endian bytes each), the rest is the proof. Seeded
//! with an honest proof of each kind (`recair`'s `credential_ingress
//! --seeds`).
//!
//! Properties: **no panic, no abort**, and **one encoding:** a proof
//! accepted is read whole and re-encodes to its bytes, so no two byte
//! strings carry one accepted proof.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vos_pvm_final_verifier::credential::{self, CredentialKind};

fuzz_target!(|data: &[u8]| {
    let Some((&kind, rest)) = data.split_first() else {
        return;
    };
    let kind = match kind & 1 {
        0 => CredentialKind::Auth,
        _ => CredentialKind::Owner,
    };
    let count = kind.public_words();
    if rest.len() < 4 * count {
        return;
    }
    let (words, proof) = rest.split_at(4 * count);
    let words: Vec<u32> = words
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect();
    if credential::verify_bytes(kind, &words, proof).is_ok() {
        let decoded = credential::decode(proof).expect("an accepted proof decodes");
        assert_eq!(credential::encode(&decoded).as_deref(), Some(proof));
    }
});
