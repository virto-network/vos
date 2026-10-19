//! Seeds the corpora of the targets that start from the golden fixtures
//! (`pvm/proof/fixtures`): `final_verifier_bytes` with the three wraps and
//! the format-39 golden (`vos-pvm-recair`'s masked wrap tests write it),
//! `statement_decode` with every fixture's judgement (its input, then its
//! proof) and its statement alone.
//!
//! ```text
//! cargo test -p vos-pvm-recair --test recursion masked
//! cd pvm/proof/fuzz
//! cargo run --example seed
//! ```

use std::path::Path;

use vos_statement::fixtures;

fn main() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let write = |target: &str, name: &str, bytes: &[u8]| {
        let directory = corpus.join(target);
        std::fs::create_dir_all(&directory).expect("the corpus' directory");
        std::fs::write(directory.join(name), bytes).expect("writes");
    };
    let directory = fixtures::directory();
    for name in ["wrap.proof", "wrap-prefix.proof", "wrap-midway.proof"] {
        let bytes = std::fs::read(directory.join(name)).expect("the wrap");
        write("final_verifier_bytes", name, &bytes);
    }
    let masked =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../target/tmp/wrap/one-segment-39.proof");
    let bytes = std::fs::read(&masked).unwrap_or_else(|error| {
        panic!(
            "{} ({error}): run `cargo test -p vos-pvm-recair --test recursion masked` first",
            masked.display()
        )
    });
    write("final_verifier_bytes", "wrap-39.proof", &bytes);
    let all = fixtures::load(&directory);
    for fixture in &all {
        let name = fixture.name.replace([' ', ','], "-");
        write(
            "statement_decode",
            &format!("{name}.judgement"),
            &fixture.bytes(),
        );
        write(
            "statement_decode",
            &format!("{name}.statement"),
            &fixture.input.statement.encode(),
        );
    }
    println!("{} fixtures seeded under {}", all.len(), corpus.display());
}
