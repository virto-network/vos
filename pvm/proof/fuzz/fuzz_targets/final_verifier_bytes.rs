//! Fuzz target: arbitrary bytes as a wrap proof of `format::WRAP` and of format
//! 39, each against its golden wrap's public words, dispatched by the
//! format as a venue dispatches (`vos_pvm_final_verifier::verify`).
//!
//! Property: **no panic, no abort**, and **nothing accepted but a golden
//! wrap:** bytes that verify decode to it, their re-encoding its bytes
//! (`golden::Golden::assert_is_golden`; under 39's fixed layout, the bytes
//! themselves). Seed the corpus with the golden wraps so the fuzzer starts
//! from proofs that decode:
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
    for golden in golden::goldens() {
        if golden.verify_bytes(data) {
            golden.assert_is_golden(&golden.decode(data).expect("decodes"));
        }
    }
});
