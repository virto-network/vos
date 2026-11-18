//! The tests' wrap files (`target/tmp/wrap/`), a carrier of the prover's
//! output: each a final wrap of `format::MASKED_WRAP` that verifies against
//! its public words, its format, its words or its judgement's input, and
//! nothing else, so no segment, leaf or fold proof is ever written there.
//! The writers are this binary's masked wraps and `vos-kernel-tests`' wraps
//! (`../common/wrap_files.rs`). Run by `just test-proof` after the suites
//! that write them, which leave some: an empty directory fails. Every other
//! run of this binary skips it (`--skip wrap_files::`), since it would race
//! its writers.

use std::collections::BTreeMap;

use vos_pvm_final_verifier::{PUBLIC_WORDS, masked};

#[test]
fn the_wrap_directory_holds_final_wraps_alone() {
    let directory = crate::common::wrap_files::directory();
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
    for (name, files) in &wraps {
        let format = u32::from_le_bytes(files["format"][..].try_into().expect("a format"));
        assert_eq!(format, masked::FORMAT, "{name}: format {format}");
        let words: Vec<u32> = files["words"]
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect();
        let words: [u32; PUBLIC_WORDS] = words.try_into().expect("the public words");
        vos_pvm_final_verifier::verify(format, &[masked::FORMAT], &files["proof"], &words)
            .unwrap_or_else(|error| panic!("{name}: not a final wrap: {error:?}"));
    }
    assert!(
        !wraps.is_empty(),
        "no wrap files: run after the suites that write them"
    );
}
