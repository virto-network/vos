// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility's release artifacts (`release/`), as this tree's guests
//! make them (`just build-programs`): the stock kernels' (`auth.device`, `owner.device`,
//! from the credential actor), the default agent's program, linked
//! (`agent.program`), and the light node's local actors' packages
//! (`credential-book.package`, `device-book.package`). `just
//! facility-release` writes them; the `release` test holds the embedded
//! ones to them.

use vos_abi::Encode as _;
use vos_testkit::programs;

/// Each artifact's file name and bytes.
pub fn artifacts() -> Vec<(&'static str, Vec<u8>)> {
    let read = |path: std::path::PathBuf| {
        std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    };
    let credentials = read(programs::program_elf("vos-credentials"));
    let device = |method: &str| {
        vos_light::release::device(&credentials, method)
            .unwrap()
            .encode()
    };
    let package = |elf| vos_light::release::package(&read(elf), 1).unwrap().encode();
    vec![
        ("auth.device", device("auth")),
        ("owner.device", device("owner")),
        (
            "agent.program",
            vos_light::release::agent(&read(programs::program_elf("vos-agent"))).unwrap(),
        ),
        (
            "credential-book.package",
            package(programs::program_elf("vos-credential-book")),
        ),
        (
            "device-book.package",
            package(programs::program_elf("vos-device-book")),
        ),
    ]
}

/// The release directory.
pub fn directory() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("release")
}
