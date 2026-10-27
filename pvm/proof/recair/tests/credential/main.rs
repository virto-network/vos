//! The credential AIR (`docs/design/proving.md` §8, pin I): the auth, owner
//! and membership-and-payment circuits on the recursion AIR's `p2` and
//! `qm31`, held to `vos_wire::credentials`' reference word for word; proved
//! masked under format 44 on the Blake2s-M31 channel and verified by the
//! final verifier; their soundness, forgery and leakage gates.

#[path = "../common/mod.rs"]
mod common;

mod gates;
mod leakage;
mod prove;
mod reference;
mod support;
