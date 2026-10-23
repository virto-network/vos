//! The tests' wrap files (`target/tmp/wrap/`), a carrier of the prover's
//! output: each a final wrap of format 28 or 39 that verifies against its
//! public words, its format, its words or its judgement's input, and
//! nothing else, so no segment, leaf or fold proof is ever written there;
//! and a production kernel's wrap is masked, format 28 the test circuits'
//! alone. Run by `just test-proof` after the suites that write them, which
//! leave some: an empty directory fails.

use std::collections::BTreeMap;
use std::path::Path;

use vos_pvm_final_verifier::{PUBLIC_WORDS, masked, unmasked};
use vos_pvm_proof::constants;

#[test]
fn the_wrap_directory_holds_final_wraps_alone() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join("wrap");
    let entries = std::fs::read_dir(&directory).expect("the suites' wrap files");
    let mut wraps: BTreeMap<String, BTreeMap<String, Vec<u8>>> = BTreeMap::new();
    for entry in entries {
        let path = entry.unwrap().path();
        let (Some(stem), Some(extension)) = (path.file_stem(), path.extension()) else {
            panic!("{} is no wrap's file", path.display());
        };
        let extension = extension.to_string_lossy().into_owned();
        assert!(
            ["proof", "format", "words", "input"].contains(&extension.as_str()),
            "{} is no wrap's file",
            path.display()
        );
        wraps
            .entry(stem.to_string_lossy().into_owned())
            .or_default()
            .insert(extension, std::fs::read(&path).unwrap());
    }
    let mut statements = BTreeMap::new();
    for (name, files) in &wraps {
        let format = u32::from_le_bytes(files["format"][..].try_into().expect("a format"));
        assert!(
            [masked::FORMAT, unmasked::FORMAT].contains(&format),
            "{name}: format {format}"
        );
        let words: Vec<u32> = files["words"]
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect();
        let words: [u32; PUBLIC_WORDS] = words.try_into().expect("the public words");
        let statement = vos_pvm_final_verifier::verify(
            format,
            &[masked::FORMAT, unmasked::FORMAT],
            &files["proof"],
            &words,
        )
        .unwrap_or_else(|error| panic!("{name}: not a final wrap: {error:?}"));
        statements.insert(name, (format, statement.program));
    }
    // Format 28 wraps a test circuit alone: the kernels' predicate, or a
    // circuit wrapped under 39 beside it, as the recursion suite's
    // one-segment run is.
    let masked: Vec<[u32; 8]> = statements
        .values()
        .filter(|(format, _)| *format == masked::FORMAT)
        .map(|(_, program)| *program)
        .collect();
    for (name, (format, program)) in &statements {
        assert!(
            *format == masked::FORMAT
                || (!PRODUCTION.contains(program)
                    && (*program == constants::PREDICATE_PROGRAM || masked.contains(program))),
            "{name}: format 28 of no test circuit, program {program:?}"
        );
    }
    assert!(
        !wraps.is_empty(),
        "no wrap files: run after the suites that write them"
    );
}

/// The production kernels' program ids: their wraps are masked.
const PRODUCTION: [[u32; 8]; 2] = [constants::WINDOW_PROGRAM, constants::BALANCE_PROGRAM];
