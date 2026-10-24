//! Seeds the corpora of the targets that start from the golden fixtures
//! (`pvm/proof/fixtures`) and vectors: `final_verifier_bytes` with every
//! wrap there, `masked_bytes` with `format::MASKED_WRAP`'s past their header,
//! `statement_decode` with every fixture's judgement (its input, then its
//! proof) and its statement alone, and `anchor_decode` with `vos-anchor`'s
//! golden vectors, their geneses, an anchor and a migration of each.
//!
//! Those four corpora are cleared first: a masked fixture regenerated is
//! another honest proof of the same words, so a proof of an earlier
//! fixture left in a corpus verifies, and the targets' oracle (every
//! accepted proof the golden one) refuses it.
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo run --example seed
//! ```

use std::path::Path;

use vos_anchor::vectors;
use vos_anchor::{Anchor, Migrate, RootKind, VenueId};
use vos_statement::fixtures;

/// `format::MASKED_WRAP`'s header in its fixed layout: the format and ten
/// words.
const MASKED_HEADER: usize = 4 * 11;

fn main() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    for target in [
        "final_verifier_bytes",
        "masked_bytes",
        "statement_decode",
        "anchor_decode",
    ] {
        match std::fs::remove_dir_all(corpus.join(target)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                panic!("clears the {target} corpus: {error}")
            }
            _ => {}
        }
    }
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
            if bytes.starts_with(&39u32.to_le_bytes()) {
                write("masked_bytes", name, &bytes[MASKED_HEADER..]);
            }
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
    for (at, golden) in vectors::golden().iter().enumerate() {
        let vector = &golden.vector;
        let digests = vector.digests();
        write("anchor_decode", &format!("vector-{at}"), &vector.encode());
        write(
            "anchor_decode",
            &format!("genesis-{at}"),
            &vector.genesis.encode(),
        );
        let anchor = Anchor {
            space: digests.space,
            window: vector.window,
            kind: RootKind::Space,
            root: digests.space_root,
            signer: vector.genesis.nodes.first().map_or([0; 32], |node| node.1),
            signature: [0x5a; 64],
        };
        write("anchor_decode", &format!("anchor-{at}"), &anchor.encode());
        let migrate = Migrate {
            space: digests.space,
            from: vector.venue,
            to: VenueId::jam(&vector.jam_genesis, vector.service),
            from_window: vector.window,
        };
        write("anchor_decode", &format!("migrate-{at}"), &migrate.encode());
    }
    println!("{} fixtures seeded under {}", all.len(), corpus.display());
}
