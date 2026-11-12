// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The release artifacts the facility embeds are the ones this tree's
//! guests make: a guest that moved fails here until `just
//! facility-release` writes them anew.

#[path = "common/release.rs"]
mod release;

#[test]
fn the_embedded_artifacts_are_this_trees() {
    let directory = release::directory();
    let stale: Vec<&str> = release::artifacts()
        .into_iter()
        .filter(|(name, bytes)| std::fs::read(directory.join(name)).ok().as_ref() != Some(bytes))
        .map(|(name, _)| name)
        .collect();
    assert!(
        stale.is_empty(),
        "{stale:?} are not this tree's guests': `just facility-release`"
    );
}
