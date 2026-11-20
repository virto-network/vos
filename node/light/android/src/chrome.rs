// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The client's trusted chrome, as the facility asks it: a form drawn by the
//! client, which no server document can draw over or answer. Every text in a
//! form is the facility's, from what enrollment pinned and the request's
//! checked arguments; what the facility proves is read back from the user's
//! answer, never from the server's pre-fill.

pub use s4_credential_contract::{Answer, Field, Form};

use crate::source::BoxFuture;

/// The trusted chrome the client lends the facility.
pub trait Chrome: Send + Sync {
    fn confirm(&self, form: Form) -> BoxFuture<'_, Answer>;

    /// What the operation is doing while the user waits, in words: shown
    /// beside it, never answered. Nothing where the client shows none.
    fn progress(&self, _text: &str) {}
}

/// The first bytes of a digest in hex, as the chrome names it.
pub fn short(bytes: &[u8; 32]) -> String {
    format!("{}…", hex::encode(&bytes[..8]))
}
