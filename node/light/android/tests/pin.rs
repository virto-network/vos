// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! s4 is pinned at one revision: every manifest and lockfile of VOS that
//! names s4 names the same one, so the facility, the gateway and the demo
//! (and the AAR, which compiles against the facility's s4 checkout) agree
//! on the contract. `just pin-s4 <rev>` moves them together.

use std::collections::BTreeSet;
use std::path::Path;

const S4: &str = "codeberg.org/Virto/s4";

/// Every s4 revision `text` names: a manifest's `rev = "…"` beside s4's
/// URL, a lockfile's `?rev=…#…` source.
fn revisions(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines().filter(|line| line.contains(S4)) {
        let rev = line
            .split_once("rev = \"")
            .map(|(_, rest)| rest)
            .or_else(|| line.split_once("?rev=").map(|(_, rest)| rest));
        let rev = rev.expect("an s4 line names its revision");
        found.push(rev.chars().take_while(char::is_ascii_hexdigit).collect());
        if let Some((_, resolved)) = line.split_once('#') {
            found.push(
                resolved
                    .chars()
                    .take_while(char::is_ascii_hexdigit)
                    .collect(),
            );
        }
    }
    found
}

#[test]
fn every_s4_revision_named_is_one() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let files = [
        "Cargo.toml",
        "Cargo.lock",
        "node/light/android/Cargo.toml",
        "node/light/android/Cargo.lock",
        "node/gateway/demo/Cargo.toml",
        "node/gateway/demo/Cargo.lock",
    ];
    let mut all = BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(root.join(file)).unwrap();
        let found = revisions(&text);
        assert!(!found.is_empty(), "{file} names no s4 revision");
        all.extend(found.into_iter().map(|rev| (rev, file)));
    }
    let revs: BTreeSet<&String> = all.iter().map(|(rev, _)| rev).collect();
    assert_eq!(
        revs.len(),
        1,
        "s4 is named at more than one revision: {all:?}"
    );
    assert_eq!(revs.first().unwrap().len(), 40, "a full commit id");
}
