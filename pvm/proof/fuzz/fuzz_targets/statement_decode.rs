//! Fuzz target: arbitrary bytes through `vos-statement`'s decoders and the
//! venue's check: `Statement::decode`, `Input::decode_prefix` and
//! `judge_bytes`.
//!
//! Properties: **no panic, no abort**, and
//! - **one encoding:** a statement that decodes re-encodes to the bytes, and
//!   an input to the prefix it took;
//! - **an acceptance is the venue's rules held:** the format one the venue
//!   accepts and the build links, the statement's program the pin, a
//!   venue-bound statement's `public_args` the venue's id first, a rootless
//!   statement of no space and a rooted one's roots all of its space and
//!   anchored, the id unseen and the statement's own; and the proof a
//!   golden wrap of its format by value (`golden::Golden::assert_is_golden`),
//!   its statement that golden's.
//!
//! Seed the corpus with the fixtures' judgements and their statements
//! (`examples/seed.rs`), so the fuzzer starts from inputs that decode and a
//! proof that verifies:
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo run --example seed
//! cargo fuzz run statement_decode -- -max_total_time=600 -max_len=262144
//! ```

#![no_main]

mod golden;

use libfuzzer_sys::fuzz_target;
use vos_statement::model::{judge_bytes, Input};
use vos_statement::{SpaceId, Statement, Venue, LINKED};

fuzz_target!(|data: &[u8]| {
    if let Ok(statement) = Statement::decode(data) {
        assert_eq!(statement.encode(), data, "one encoding");
    }
    let decoded = Input::decode_prefix(data);
    if let Ok((input, used)) = &decoded {
        assert_eq!(input.encode(), data[..*used], "one encoding");
    }
    let verdict = judge_bytes(data);
    let Ok(id) = verdict else {
        return;
    };
    let (input, used) = decoded.expect("an accepted input decodes");
    let statement = &input.statement;
    assert!(LINKED.contains(&statement.format));
    assert!(input.policy.accepts(statement.format));
    assert_eq!(statement.program, input.pin.program);
    if input.pin.venue_bound {
        assert_eq!(statement.public_args[..32], input.policy.id().0);
    }
    if statement.roots.is_empty() {
        assert_eq!(statement.space, SpaceId::NONE);
    }
    for root in &statement.roots {
        assert_eq!(root.space, statement.space);
        assert!(input.policy.anchored(root));
    }
    assert_eq!(id, statement.id());
    assert!(!input.policy.seen(&id));

    let words = vos_statement::vos_pvm_final_verifier::Statement {
        program: statement.program.0,
        io_hash: statement.io_hash(),
    }
    .words();
    let golden = golden::goldens()
        .iter()
        .find(|golden| golden.format == statement.format && golden.words == words)
        .expect("the golden statement");
    let proof = golden.decode(&data[used..]).expect("decodes");
    golden.assert_is_golden(&proof);
});
