//! Fuzz target: arbitrary bytes through `vos-statement`'s decoders and the
//! venue's check: `Statement::decode`, `Input::decode_prefix` and
//! `judge_bytes`.
//!
//! Properties: **no panic, no abort**, and
//! - **one encoding:** a statement that decodes re-encodes to the bytes, and
//!   an input to the prefix it took;
//! - **an acceptance is the venue's rules held:** the format 28, the
//!   statement's program the pin, a rootless statement of no space and a
//!   rooted one's roots all of its space and anchored, the id unseen and
//!   the statement's own; and the proof the golden wrap by value
//!   (`golden::Golden::assert_is_golden`), its statement the golden one.
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
use vos_statement::{SpaceId, Statement, Venue, FORMAT};

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
    assert_eq!(statement.format, FORMAT);
    assert_eq!(statement.program, input.program);
    if statement.roots.is_empty() {
        assert_eq!(statement.space, SpaceId::NONE);
    }
    for root in &statement.roots {
        assert_eq!(root.space, statement.space);
        assert!(input.policy.anchored(root));
    }
    assert_eq!(id, statement.id());
    assert!(!input.policy.seen(&id));

    let golden = golden::golden();
    let proof = vos_statement::vos_final_verifier::decode(&data[used..]).expect("decodes");
    golden.assert_is_golden(&proof);
    let words = vos_statement::vos_final_verifier::Statement {
        program: statement.program.0,
        io_hash: statement.io_hash(),
    }
    .words();
    assert_eq!(words, golden.words, "the golden statement");
});
