//! Fuzz target: arbitrary bytes as a work item of the JAM statements
//! service and its first extrinsic (`service::split`), through its refine
//! (`vos_statement_service::refine::refine`: the item's decode, a
//! registration's, an anchor's or a control's signature, a statement's
//! decode and checks and its proof's verification), its verdict encoded and
//! read back by `Verdict::decode_prefix`, as accumulate reads it; and the
//! bytes themselves read as a verdict. Seeded with the fixtures' statements
//! and their proofs and with registrations, anchors and controls of the
//! anchor's golden vectors (`cargo run --example seed`).
//!
//! Properties: **no panic, no abort**, a verdict **read back as it was
//! written**, whole, and **one encoding:** bytes read as a verdict are that
//! verdict's encoding.

#![no_main]

mod service;

use libfuzzer_sys::fuzz_target;
use vos_statement_service::verdict::Verdict;

fuzz_target!(|data: &[u8]| {
    let verdict = service::verdict(data);
    let bytes = verdict.encode();
    let (read, len) = Verdict::decode_prefix(&bytes).expect("a verdict reads back");
    assert_eq!(read, verdict, "the verdict read back");
    assert_eq!(len, bytes.len(), "the verdict read whole");
    if let Ok((read, len)) = Verdict::decode_prefix(data) {
        assert_eq!(read.encode(), data[..len], "a verdict's one encoding");
    }
});
