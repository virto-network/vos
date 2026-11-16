// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility's own interface's AIDL (the AAR's `src/main/aidl`) declares
//! every parcelable and enum of `personal::contract` as its type is, and
//! nothing else.

use std::path::Path;

use vos_facility::personal::contract::{AIDL, REGISTRY};

#[test]
fn the_aidl_declares_every_parcelable_as_its_type() {
    let failures = s4_credential_contract::parcel::check(Path::new(AIDL), REGISTRY);
    assert!(failures.is_empty(), "{failures:#?}");
}
