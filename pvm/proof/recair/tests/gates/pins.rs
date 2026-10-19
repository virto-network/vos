//! Only checked wirings are pinned: a circuit's preprocessed columns
//! (`trace::preprocessed_columns`) and its hash
//! (`vos_pvm_recair_air::circuit_hash`, however it is named at the call)
//! are computed nowhere in the workspace's sources but `recair`'s
//! `prove.rs` (the fold's in-AIR child hash aside), whose
//! `preprocessed_root_on` runs `Circuit::check_wiring` first, and the
//! gates' forger. A second yield, which the relation alone balances
//! (`multiplicities`), is refused because of it.

use std::path::{Path, PathBuf};

/// The `.rs` files under `dir`, past `target`, `.git` and the spikes.
fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(name.as_ref(), "target" | ".git" | "spikes" | ".worktrees") {
                sources(&path, found);
            }
        } else if name.ends_with(".rs") {
            found.push(path);
        }
    }
}

/// Whether `source` names `needle` as a whole identifier: Stwo's
/// `new_with_preprocessed_columns(` is another function.
fn calls(source: &str, needle: &str) -> bool {
    source.match_indices(needle).any(|(at, _)| {
        !source[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

#[test]
fn only_checked_wirings_are_committed() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.join("../../..");
    let mut found = Vec::new();
    sources(&workspace, &mut found);
    assert!(found.len() > 100, "the workspace's sources");
    let allowed = [
        "pvm/proof/recair/src/prove.rs",
        "pvm/proof/recair/src/trace.rs",
        "pvm/proof/recair-air/src/lib.rs",
        // The in-AIR child hash: a fold's gates over a child's root wires.
        "pvm/proof/recair/src/fold/child.rs",
        "pvm/proof/recair/src/fold/mod.rs",
        "pvm/proof/recair/tests/gates/forge.rs",
        // The generic masked prover's `p2`-only set, its wiring checked.
        "pvm/proof/recair/tests/circuit/masked_prover.rs",
        // The masking's soundness gates: a circuit turned so that a chained
        // row is row 0, which the wiring check refuses, to test the wrap row.
        "pvm/proof/recair/tests/circuit/masked_gates.rs",
        "pvm/proof/recair/tests/gates/pins.rs",
    ];
    let mut callers = Vec::new();
    for path in &found {
        let relative = path
            .strip_prefix(&workspace)
            .expect("under the workspace")
            .to_string_lossy()
            .replace('\\', "/");
        if allowed.contains(&relative.as_str()) {
            continue;
        }
        let source = std::fs::read_to_string(path).unwrap_or_default();
        for needle in ["preprocessed_columns(", "circuit_hash("] {
            if calls(&source, needle) {
                callers.push(format!("{relative}: {needle}"));
            }
        }
    }
    assert!(callers.is_empty(), "{callers:?}");
}
