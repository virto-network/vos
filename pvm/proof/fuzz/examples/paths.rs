//! Lists what each input of the checked-in corpus (`replay/<target>/`)
//! reaches: the verdict its target's verifier, decoder or venue gives it,
//! counted by verdict a target. `prove_verify_roundtrip`'s inputs are
//! programs, counted alone.
//!
//! With `--each`, it prints a line `<target>\t<input>\t<verdict>` for
//! each verdict of each input instead: what a corpus is pruned by.
//!
//! With `--expect <file>` (`just fuzz-reach`, `reach.txt`), it fails
//! unless every verdict the file lists for a target, a line
//! `<target>\t<verdict>`, is reached by one of its inputs at least: a
//! corpus that drifts off a check stops guarding it, and the gate says so.
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo run --release --example paths [-- --expect reach.txt]
//! ```

#[path = "../fuzz_targets/device_program.rs"]
mod device_program;
#[path = "../fuzz_targets/golden.rs"]
mod golden;
#[path = "../fuzz_targets/mutation.rs"]
mod mutation;
#[path = "../fuzz_targets/shape.rs"]
mod shape;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use arbitrary::{Arbitrary, Unstructured};
use vos_anchor::vectors::Vector;
use vos_anchor::{Anchor, SpaceGenesis};
use vos_pvm_final_verifier::{masked, Error, LINKED};
use vos_statement::model::judge_bytes;

/// A verifier's verdict, its variant and what it names.
fn verdict<T>(result: Result<T, Error>) -> String {
    match result {
        Ok(_) => "accepted".into(),
        Err(Error::Stark(error)) => format!("Stark({error})"),
        Err(error) => format!("{error:?}"),
    }
}

fn decoded<T, E: std::fmt::Debug>(name: &str, result: Result<T, E>) -> String {
    match result {
        Ok(_) => format!("{name}: decodes"),
        Err(error) => format!("{name}: {error:?}"),
    }
}

/// `device_verify_bytes`' program's verifier, made once.
fn device_verifier() -> &'static vos_pvm_device::Verifier {
    static VERIFIER: OnceLock<vos_pvm_device::Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| device_program::program().verifier())
}

/// The verdicts `bytes` reaches as `target`'s input.
fn paths(target: &str, bytes: &[u8]) -> Vec<String> {
    let goldens = golden::goldens();
    let masked = || {
        goldens
            .iter()
            .filter(|golden| golden.format == masked::FORMAT)
    };
    match target {
        "final_verifier_bytes" => goldens
            .iter()
            .map(|golden| {
                let result =
                    vos_pvm_final_verifier::verify(golden.format, LINKED, bytes, &golden.words);
                format!("{}: {}", golden.format, verdict(result))
            })
            .collect(),
        "masked_bytes" => {
            let golden = masked().next().expect("a golden of format 39");
            let mut prefixed = golden.proof[..golden::MASKED_HEADER].to_vec();
            prefixed.extend_from_slice(bytes);
            [("after the header", &prefixed[..]), ("whole", bytes)]
                .into_iter()
                .map(|(how, bytes)| {
                    let result = vos_pvm_final_verifier::verify(
                        masked::FORMAT,
                        LINKED,
                        bytes,
                        &golden.words,
                    );
                    format!("{how}: {}", verdict(result))
                })
                .collect()
        }
        "masked_shape" => {
            let mut u = Unstructured::new(bytes);
            let goldens: Vec<_> = masked().collect();
            let Ok(at) = u.choose_index(goldens.len()) else {
                return vec!["no golden chosen".into()];
            };
            let golden = goldens[at];
            let mut proof = golden.decode(&golden.proof).expect("decodes");
            if shape::reshape(&mut u, &mut proof).is_err() {
                return vec!["not reshaped".into()];
            }
            vec![verdict(masked::verify(proof, &golden.words))]
        }
        "final_verifier_mutate" => {
            let Ok(mutations) =
                Vec::<mutation::Mutation>::arbitrary_take_rest(Unstructured::new(bytes))
            else {
                return vec!["no mutations".into()];
            };
            goldens
                .iter()
                .map(|golden| {
                    let mut proof = golden.decode(&golden.proof).expect("decodes");
                    for mutation in &mutations {
                        mutation::apply(&mut proof, mutation);
                    }
                    format!("{}: {}", golden.format, verdict(golden.verify(proof)))
                })
                .collect()
        }
        "statement_decode" => vec![match judge_bytes(bytes) {
            Ok(_) => "accepted".into(),
            Err(refusal) => format!("{refusal:?}"),
        }],
        "device_verify_bytes" => vec![match bytes.split_first_chunk::<32>() {
            None => "shorter than an io-hash".into(),
            Some((io, proof)) => match device_verifier().verify(io, proof) {
                Ok(()) => "accepted".into(),
                Err(refusal) => format!("{refusal:?}"),
            },
        }],
        "anchor_decode" => vec![
            decoded("genesis", SpaceGenesis::decode(bytes)),
            decoded("anchor", Anchor::decode(bytes)),
            decoded("vector", Vector::decode(bytes)),
        ],
        _ => vec!["a program".into()],
    }
}

/// The verdicts `file` lists, by target: each line `<target>\t<verdict>`,
/// blank lines and `#` comments skipped.
fn expected(file: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(file).expect("the expected verdicts");
    let mut expected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (target, verdict) = line
            .split_once('\t')
            .expect("a line `<target>\\t<verdict>`");
        expected
            .entry(target.to_owned())
            .or_default()
            .insert(verdict.to_owned());
    }
    expected
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (expect, each) = match arguments.as_slice() {
        [] => (None, false),
        [flag] if flag == "--each" => (None, true),
        [flag, file] if flag == "--expect" => (Some(expected(Path::new(file))), false),
        _ => panic!("usage: paths [--each | --expect <file>]"),
    };
    let mut reached: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let replay = Path::new(env!("CARGO_MANIFEST_DIR")).join("replay");
    let mut targets: Vec<_> = std::fs::read_dir(&replay)
        .expect("the replay corpus")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    targets.sort();
    for directory in targets {
        let target = directory
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a target's name")
            .to_owned();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut inputs = 0;
        for entry in std::fs::read_dir(&directory).expect("the target's corpus") {
            let file = entry.expect("an entry").path();
            let bytes = std::fs::read(&file).expect("an input");
            inputs += 1;
            for path in paths(&target, &bytes) {
                if each {
                    let name = file.file_name().and_then(|name| name.to_str());
                    println!("{target}\t{}\t{path}", name.unwrap_or_default());
                }
                *counts.entry(path).or_default() += 1;
            }
        }
        println!("{target}: {inputs} inputs");
        for (path, count) in &counts {
            println!("  {count:>5}  {path}");
        }
        reached.insert(target, counts.into_keys().collect());
    }
    let Some(expect) = expect else {
        return;
    };
    let missing: Vec<String> = expect
        .iter()
        .flat_map(|(target, verdicts)| {
            let reached = reached.get(target);
            verdicts
                .iter()
                .filter(move |verdict| !reached.is_some_and(|reached| reached.contains(*verdict)))
                .map(move |verdict| format!("{target}: {verdict}"))
        })
        .collect();
    for line in &missing {
        eprintln!("not reached: {line}");
    }
    assert!(
        missing.is_empty(),
        "the replay corpus does not reach {} expected verdicts",
        missing.len()
    );
    println!("every expected verdict reached");
}
