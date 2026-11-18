//! Fuzz target: `format::MASKED_WRAP`'s fixed layout, read past its header.
//! The input is the bytes after the header (the format and its ten words,
//! which the decode pins word for word): the target puts
//! `format::MASKED_WRAP`'s header before them, so every byte the fuzzer
//! chooses lands in the counts, limbs and hashes the decode bounds. The
//! input is also read whole, header and all.
//!
//! Properties: **no panic, no abort**, and
//! - **one encoding:** bytes that decode re-encode to themselves
//!   (`masked::encode`);
//! - **nothing accepted but a golden wrap:** bytes that verify against a
//!   golden's words are that golden's (`golden::Golden::assert_is_golden`).
//!
//! The decode refuses most inputs within a few counts, so a run reads
//! millions; seed the corpus with `format::MASKED_WRAP`'s goldens past
//! their header (`examples/seed.rs`) so mutations start from proofs that
//! decode:
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo run --example seed
//! cargo fuzz run masked_bytes -- -max_total_time=300 -max_len=262144
//! ```

#![no_main]

mod golden;

use libfuzzer_sys::fuzz_target;
use vos_pvm_final_verifier::masked;

fuzz_target!(|data: &[u8]| {
    let golden = golden::goldens()
        .iter()
        .find(|golden| golden.format == masked::FORMAT)
        .expect("a golden of format 39");
    let mut bytes = golden.proof[..golden::MASKED_HEADER].to_vec();
    bytes.extend_from_slice(data);
    for bytes in [&bytes[..], data] {
        let Ok(proof) = masked::decode(bytes) else {
            continue;
        };
        assert_eq!(
            masked::encode(&proof).as_deref(),
            Some(bytes),
            "one encoding"
        );
        for golden in golden::goldens()
            .iter()
            .filter(|golden| golden.format == masked::FORMAT)
        {
            if golden.verify(proof.clone()).is_ok() {
                golden.assert_is_golden(&proof);
            }
        }
    }
});
