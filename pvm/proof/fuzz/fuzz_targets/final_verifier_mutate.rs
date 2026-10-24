//! Fuzz target: the golden wraps, formats 28 and 39, mutated by their bytes
//! and by their structure, then verified against their public words, each
//! under its format (`vos_pvm_final_verifier::{unmasked, masked}::verify`,
//! and the bytes through `vos_pvm_final_verifier::verify`).
//!
//! The input is a list of mutations ([`Mutation`], `arbitrary`): byte flips,
//! insertions, removals and truncations of the encoding; and, on the
//! decoded proof, a vector of any of its trees, columns, witnesses or
//! layers grown, shrunk or emptied, a value set to anything (a noncanonical
//! limb among them), a hash changed, a nonce, a configuration field, a log
//! size or the format set.
//!
//! Property: **no panic, no abort**, and **a mutated proof that verifies is
//! the golden one** by value (`golden::Golden::assert_is_golden`): the
//! mutations that cancel out, or rewrite a postcard varint longer. The
//! shape checks stand before every Stwo call that would index the proof;
//! this target is what holds them to that.
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo fuzz run final_verifier_mutate -- -max_total_time=600
//! ```

#![no_main]

mod golden;
mod mutation;

use libfuzzer_sys::fuzz_target;
use mutation::{apply, apply_bytes, Mutation};
use vos_pvm_final_verifier::WrapProof;

fuzz_target!(|mutations: Vec<Mutation>| {
    for golden in golden::goldens() {
        let mut proof: WrapProof = golden.decode(&golden.proof).expect("decodes");
        for mutation in &mutations {
            apply(&mut proof, mutation);
        }
        if golden.verify(proof.clone()).is_ok() {
            golden.assert_is_golden(&proof);
        }
        let mut bytes = golden
            .encode(&proof)
            .unwrap_or_else(|| golden.proof.clone());
        for mutation in &mutations {
            apply_bytes(&mut bytes, mutation);
        }
        if golden.verify_bytes(&bytes) {
            golden.assert_is_golden(&golden.decode(&bytes).expect("decodes"));
        }
    }
});
