//! Fuzz target: `format::MASKED_WRAP`'s goldens reshaped within the
//! layout's bounds, where Stwo's PCS reads them. The parts the transcript
//! binds before the queries (the header, the commitments, the claimed sums,
//! the sampled values, the nonces, FRI's commitments and last layer) stay
//! the golden's, so every proof this makes passes the replay and its proof
//! of work and reaches `verify_values`' Merkle checks, the DEEP quotients'
//! answers and FRI's decommitments. What the queries open is made anew,
//! each part kept or rewritten by the input: each tree's queried values
//! (one count a tree, up to a query each, any limbs, a noncanonical one
//! among them) and its Merkle witness (up to a sibling a query a level),
//! and each FRI layer's witness values and hashes, within their bounds.
//!
//! Byte flips and the mutation target rarely get this far: a changed
//! commitment or sampled value is refused by the transcript first.
//!
//! Property: **no panic, no abort**, and **a proof that verifies is the
//! golden one** (`golden::Golden::assert_is_golden`); and the proof's fixed
//! layout, when it holds the proof, verifies as the proof does.
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo fuzz run masked_shape -- -max_total_time=300
//! ```

#![no_main]

mod golden;
mod shape;

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use vos_pvm_final_verifier::masked;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let goldens: Vec<_> = golden::goldens()
        .iter()
        .filter(|golden| golden.format == masked::FORMAT)
        .collect();
    let Ok(at) = u.choose_index(goldens.len()) else {
        return;
    };
    let golden = goldens[at];
    let mut proof = golden.decode(&golden.proof).expect("decodes");
    if shape::reshape(&mut u, &mut proof).is_err() {
        return;
    }
    let accepted = golden.verify(proof.clone());
    if accepted {
        golden.assert_is_golden(&proof);
    }
    if let Some(bytes) = golden.encode(&proof) {
        assert_eq!(
            golden.verify_bytes(&bytes),
            accepted,
            "the bytes as the proof"
        );
    }
});
