//! Seeds the corpora of the targets that start from the golden fixtures
//! (`pvm/proof/fixtures`): `final_verifier_bytes` with every wrap there,
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
    let mut wraps = 0;
    for entry in std::fs::read_dir(&directory).expect("the fixtures' directory") {
        let path = entry.expect("an entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name.starts_with("wrap") && name.ends_with(".proof") {
            let bytes = std::fs::read(&path).expect("the wrap");
            write("final_verifier_bytes", name, &bytes);
            wraps += 1;
        }
    }
    assert!(wraps > 0, "no wrap under {}", directory.display());
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
