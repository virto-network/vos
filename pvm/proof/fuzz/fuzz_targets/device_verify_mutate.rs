//! Fuzz target: the golden device proof (`device_golden`, format 47, of
//! `device_verify_bytes`' kernel) mutated by its structure, its 8-bit
//! interaction PoW ground again over the mutated commitments (at most a
//! few thousand nonces, about 256 on average), then verified by the
//! verifier ingress calls (`vos_pvm_device::Verifier::verify`); and its
//! bytes mutated after, verified as they are.
//!
//! The input is a list of mutations (`mutation::Mutation`, as
//! `final_verifier_mutate`'s): on the decoded proof, a vector of any of its
//! trees, columns, witnesses or layers grown, shrunk or emptied, a value
//! set to anything (a noncanonical limb among them), a hash, a nonce, a
//! claimed sum or a configuration field changed; on the encoding, byte
//! flips, insertions, removals and truncations. Ground again, a mutated
//! proof passes the pre-check and reaches the decode whole, the shape
//! checks, the device components' evaluation at the out-of-domain point,
//! the logup sums and the STARK's Merkle and FRI checks.
//!
//! Property: **no panic, no abort**, and **nothing accepted but the
//! golden's one encoding.**
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo fuzz run device_verify_mutate -- -max_total_time=300
//! ```

#![no_main]

mod device_golden;
mod device_program;
mod mutation;

use libfuzzer_sys::fuzz_target;
use mutation::{apply_bytes, apply_device, Mutation};
use vos_pvm_device::{encode, FORMAT};

fuzz_target!(|mutations: Vec<Mutation>| {
    let golden = device_golden::golden();
    let mut proof = golden.decode();
    for mutation in &mutations {
        apply_device(&mut proof, mutation);
    }
    if let Some((bytes, verdict)) = golden.ground(&proof) {
        if verdict.is_ok() {
            assert!(
                bytes == golden.proof,
                "an accepted proof that is not the golden one"
            );
        }
    }
    let mut bytes = encode(&FORMAT, &proof).unwrap_or_else(|| golden.proof.clone());
    for mutation in &mutations {
        apply_bytes(&mut bytes, mutation);
    }
    if golden.verifier.verify(&golden.io, &bytes).is_ok() {
        assert!(
            bytes == golden.proof,
            "accepted bytes that are not the golden's"
        );
    }
});
