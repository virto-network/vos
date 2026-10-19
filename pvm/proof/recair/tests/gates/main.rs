//! The recursion AIR's forgery gates (`recursion-air.md` §1, §11's R12;
//! `proving.md` A.3): a malicious prover per gate ([`forge`]), which skips
//! the honest prover's checks, and the verifier's refusal of its proof,
//! named.
//!
//! - [`p2_modes`]: a row computed by another mode's rule, a sponge or a
//!   transcript chained across rows wrongly, a Merkle step over another
//!   child or in the swapped order;
//! - [`multiplicities`]: the `Gate` relation's signed multiplicities, a use
//!   carrying another value than its yield, a yield consumed once more than
//!   it counts, a negative multiplicity (a second yield), a public use added
//!   or dropped;
//! - [`one_of`]: `assert_one_of`'s choice outside its set, in a small
//!   circuit, in the fold and in the wrap;
//! - [`lanes`]: a message wire's lanes its absorbing row leaves unread, free
//!   to the prover, which the static check refuses any circuit to read;
//! - [`boundary_bytes`]: a leaf's boundary byte of 256 or more where the
//!   leaf does not range-check it;
//! - [`pins`]: no circuit is committed but through the static check.

#[path = "../common/mod.rs"]
mod common;

mod forge;

mod boundary_bytes;
mod lanes;
mod multiplicities;
mod one_of;
mod p2_modes;
mod pins;
