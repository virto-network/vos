//! Seeds the corpora of the targets that start from the golden fixtures
//! (`pvm/proof/fixtures`): `final_verifier_bytes` with the wraps,
//! `statement_decode` with every fixture's judgement (its input, then its
//! proof) and its statement alone.
//!
//! ```text
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
    for name in [
        "wrap.proof",
        "wrap-rootless.proof",
        "wrap-prefix.proof",
        "wrap-midway.proof",
        "wrap-28.proof",
    ] {
        let bytes = std::fs::read(directory.join(name)).expect("the wrap");
        write("final_verifier_bytes", name, &bytes);
    }
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
