// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility's own interface's AIDL (the AAR's `src/main/aidl`) declares
//! every parcelable and enum of `personal::contract` as its type is, and
//! nothing else; what the screens' Java holds of the facility's (a label's
//! bound, the kit's forms and its word list) is the facility's.

use std::path::Path;

use vos_facility::personal::contract::{AIDL, REGISTRY};

#[test]
fn the_aidl_declares_every_parcelable_as_its_type() {
    let failures = s4_credential_contract::parcel::check(Path::new(AIDL), REGISTRY);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The screens trim a label to the contract's bound, written in Java too.
#[test]
fn the_screens_label_bound_is_the_contracts() {
    let words = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("aar/src/main/java/team/virto/vos/personal/Words.java"),
    )
    .unwrap();
    let declared = format!(
        "MAX_LABEL = {};",
        vos_facility::personal::contract::MAX_LABEL
    );
    assert!(
        words.contains(&declared),
        "Words.java does not declare {declared}"
    );
}

fn java(class: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("aar/src/main/java/team/virto/vos/personal")
            .join(class),
    )
    .unwrap()
}

/// The screens know a kit's forms by the facility's titles, and check its
/// words against the kit's own list, BIP39's English, as the kit reads it.
#[test]
fn the_screens_kit_words_are_the_kits() {
    let words = java("KitWords.java");
    for (constant, title) in [
        ("ENTER", vos_facility::personal::ENTER_PHRASE),
        ("CHECK", vos_facility::personal::CHECK_PHRASE),
    ] {
        let declared = format!("{constant} = \"{title}\";");
        assert!(
            words.contains(&declared),
            "KitWords.java does not declare {declared}"
        );
    }
    let list = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("aar/src/main/resources/team/virto/vos/personal/kit-words.txt"),
    )
    .unwrap();
    let list: Vec<&str> = list.lines().collect();
    assert_eq!(list, bip39::Language::English.word_list().to_vec());
}
