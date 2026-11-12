// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `just facility-release`: the facility's release artifacts written
//! anew into `release/` from this tree's guests, each printed with its
//! size.

#[path = "../tests/common/release.rs"]
mod release;

fn main() {
    let directory = release::directory();
    for (name, bytes) in release::artifacts() {
        let path = directory.join(name);
        std::fs::write(&path, &bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        println!("{} {}", path.display(), bytes.len());
    }
}
