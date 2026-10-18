//! Fuzz target: arbitrary bytes as a wrap proof, against the golden wrap's
//! public words (`vos_final_verifier::verify_bytes`).
//!
//! Property: **no panic, no abort.** Whatever the bytes, the verifier
//! returns a verdict: a refusal for anything but the golden wrap's
//! encodings. Seed the corpus with the golden wrap so the fuzzer starts
//! from a proof that decodes:
//!
//! ```text
//! cd pvm/proof
//! mkdir -p fuzz/corpus/final_verifier_bytes
//! cp fixtures/wrap*.proof fuzz/corpus/final_verifier_bytes/
//! cargo fuzz run final_verifier_bytes -- -max_total_time=600 -max_len=262145
//! ```

#![no_main]

mod golden;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let golden = golden::golden();
    if let Ok(statement) = vos_final_verifier::verify_bytes(data, &golden.words) {
        assert_eq!(statement.words(), golden.words);
    }
});
