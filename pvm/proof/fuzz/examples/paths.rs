//! Lists what each input of the checked-in corpus (`replay/<target>/`)
//! reaches: the verdict its target's verifier, decoder or venue gives it,
//! counted by verdict a target. `prove_verify_roundtrip`'s inputs are
//! programs, counted alone.
//!
//! ```text
//! cd pvm/proof/fuzz
//! cargo run --release --example paths
//! ```

#[path = "../fuzz_targets/golden.rs"]
mod golden;
#[path = "../fuzz_targets/mutation.rs"]
mod mutation;
#[path = "../fuzz_targets/shape.rs"]
mod shape;

use std::collections::BTreeMap;
use std::path::Path;

use arbitrary::{Arbitrary, Unstructured};
use vos_anchor::vectors::Vector;
use vos_anchor::{Anchor, Migrate, SpaceGenesis};
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
                    let result = match golden.format {
                        masked::FORMAT => masked::verify(proof, &golden.words),
                        _ => vos_pvm_final_verifier::unmasked::verify(proof, &golden.words),
                    };
                    format!("{}: {}", golden.format, verdict(result))
                })
                .collect()
        }
        "statement_decode" => vec![match judge_bytes(bytes) {
            Ok(_) => "accepted".into(),
            Err(refusal) => format!("{refusal:?}"),
        }],
        "anchor_decode" => vec![
            decoded("genesis", SpaceGenesis::decode(bytes)),
            decoded("anchor", Anchor::decode(bytes)),
            decoded("migrate", Migrate::decode(bytes)),
            decoded("vector", Vector::decode(bytes)),
        ],
        _ => vec!["a program".into()],
    }
}

fn main() {
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
            let bytes = std::fs::read(entry.expect("an entry").path()).expect("an input");
            inputs += 1;
            for path in paths(&target, &bytes) {
                *counts.entry(path).or_default() += 1;
            }
        }
        println!("{target}: {inputs} inputs");
        for (path, count) in counts {
            println!("  {count:>5}  {path}");
        }
    }
}
