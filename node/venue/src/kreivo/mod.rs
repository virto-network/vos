//! Kreivo's spaces pallet (`docs/design/spaces-pallet.md`): the node's
//! client of it, [`KreivoVenue`], in two layers, [`calls`] (the pinned
//! call bytes, storage keys and event decoding) and a [`Transport`] (sign
//! and send a call, follow it to inclusion, read events and raw storage);
//! `chain`, the transport over a Kreivo node's RPC (feature `kreivo`);
//! and `mock`, a plain-Rust model of the pallet (feature `mock`, and this
//! crate's tests), the chain the client's tests run against, and the
//! conformance vectors G1–G18 it generates, which the Kreivo teammate's
//! pallet must pass.
//!
//! A production node does not select Kreivo ([`selectable`]) until the
//! teammate's pallet passes the vectors in its own runtime and the end to
//! end run on a Kreivo dev chain (`slice-6-on-chain.md`, M3b's deferred
//! gates 1 and 2): no space anchors on a chain whose pallet has not met
//! them.

pub mod calls;
#[cfg(feature = "kreivo")]
pub mod chain;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
pub mod transport;
mod venue;

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod tests;

pub use transport::{Sender, Transport};
pub use venue::{Alert, KreivoVenue, Options};

/// A node's Kreivo account key (decision 12): the 32-byte mini secret of
/// an sr25519 key, made by the node and kept in its store beside its node
/// key and its anchor keys, never one of them. The controller registers
/// its account as one of the space's authorities, paired with the node's
/// anchor key; it holds no balance, the space's sovereign account pays.
/// Never shown: its `Debug` names it only, and it is zeroed when dropped.
pub struct AccountSeed([u8; 32]);

impl AccountSeed {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    /// The secret, to make the key from.
    pub fn secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for AccountSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountSeed(..)")
    }
}

impl Drop for AccountSeed {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: a byte of the seed, which this owns.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

/// What a node's build is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Build {
    /// Tests and development: built with debug assertions.
    Dev,
    /// A production node.
    Production,
}

impl Build {
    /// This build's.
    pub fn current() -> Self {
        if cfg!(debug_assertions) {
            Self::Dev
        } else {
            Self::Production
        }
    }
}

/// Whether a node built for `build` may select Kreivo as its space's
/// venue: in tests and development only, until Kreivo's pallet meets the
/// conformance vectors in its runtime and the end to end run.
pub fn selectable(build: Build) -> Result<(), String> {
    match build {
        Build::Dev => Ok(()),
        Build::Production => Err("the `kreivo` venue is not selectable in a production node \
             until Kreivo's spaces pallet passes the conformance vectors in its runtime and the \
             end to end run on a Kreivo dev chain"
            .into()),
    }
}
