//! Fuzz target: arbitrary bytes as a wrap proof, against the golden wrap's
//! public words (`vos_pvm_final_verifier::verify_bytes`).
//!
//! Property: **no panic, no abort**, and **nothing accepted but the golden
//! wrap:** bytes that verify decode to it, their re-encoding its bytes
//! (`golden::Golden::assert_is_golden`). Seed the corpus with the golden
//! wrap so the fuzzer starts from a proof that decodes:
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo run --example seed
//! cargo fuzz run final_verifier_bytes -- -max_total_time=600 -max_len=262145
//! ```

#![no_main]

mod golden;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let golden = golden::golden();
    if vos_pvm_final_verifier::verify_bytes(data, &golden.words).is_ok() {
        golden.assert_is_golden(&vos_pvm_final_verifier::decode(data).expect("decodes"));
    }
});
