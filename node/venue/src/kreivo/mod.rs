//! Kreivo's spaces pallet (`docs/design/spaces-pallet.md`): the node's
//! client of it, [`KreivoVenue`], in two layers, [`calls`] (the pinned call
//! bytes, storage keys and event decoding) and a [`Transport`] (sign and
//! send a call, follow it to inclusion, read events and raw storage); and
//! `mock`, a plain-Rust model of the pallet (feature `mock`, and this
//! crate's tests), the chain the client's tests run against, and the
//! conformance vectors G1–G18 it generates, which Kreivo's pallet must
//! pass. The transport over a live Kreivo node is not here: it implements
//! [`Transport`] (`spaces-pallet.md`, the node-side client).

pub mod calls;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
pub mod transport;
mod venue;

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod tests;

pub use transport::{Sender, Transport};
pub use venue::{Alert, Connect, KreivoVenue, Options};
