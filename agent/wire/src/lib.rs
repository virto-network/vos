//! The node's formats and the stock actors' messages: a refine's batch
//! ([`batch`]), the apply of its result ([`apply`]), a work package
//! ([`package`]), a node's ingress ([`ingress`]) and its peers' messages
//! ([`peer`]); and the messages of the credential actor ([`credentials`]),
//! the personal agent ([`personal`]), the homes ([`homes`]) and the books
//! ([`books`]). The actor ABI they are built on is `vos-abi`'s.
//!
//! Everything here is SCALE-coded with the workspace codec, the encoding JAM
//! uses.

#![no_std]

extern crate alloc;

pub mod apply;
pub mod batch;
pub mod books;
pub mod credentials;
pub mod homes;
pub mod ingress;
pub mod package;
pub mod peer;
pub mod personal;

/// When a session's row in the due index is due: sessions are filed by the
/// bucket of their last activity, so one sweep collects many.
pub mod expiry;

/// The node's and the agent's defaults. Each is a constant, cheap to change.
pub mod defaults;
