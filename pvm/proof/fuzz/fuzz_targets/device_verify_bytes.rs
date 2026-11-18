//! Fuzz target: arbitrary bytes through the device verifier
//! (`vos_pvm_device::Verifier::verify`), the call ingress makes on
//! an executor: the input's first 32 bytes the io-hash, the rest the
//! proof, under one small kernel's program. Seeded with an honest proof of
//! it (`cargo run --example seed`).
//!
//! Properties: **no panic, no abort**, and **one encoding:** a proof
//! accepted is read whole and re-encodes to its bytes, so no two byte
//! strings carry one accepted proof.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use vos_pvm_device::{decode, encode, Verifier, FORMAT};

#[path = "device_program.rs"]
mod device_program;

fn verifier() -> &'static Verifier {
    static VERIFIER: OnceLock<Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| device_program::program().verifier())
}

fuzz_target!(|data: &[u8]| {
    let Some((io, proof)) = data.split_first_chunk::<32>() else {
        return;
    };
    if verifier().verify(io, proof).is_ok() {
        let decoded = decode(&FORMAT, proof).expect("an accepted proof decodes");
        assert_eq!(encode(&FORMAT, &decoded).as_deref(), Some(proof));
    }
});
