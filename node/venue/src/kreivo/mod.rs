//! Kreivo's spaces pallet (`docs/design/spaces-pallet.md`) as VOS models
//! it: [`mock`], a plain-Rust model of the pallet's storage, calls, events,
//! errors, deposits and fees, and the conformance vectors G1–G18 it
//! generates, which the Kreivo teammate's pallet must pass.

pub mod mock;

mod conformance;
