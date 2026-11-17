//! The venue as a JAM refine program (`--features pvm-guest`, built by
//! `just check-no-std` for the PVM target): it verifies a final proof the
//! way a JAM service would, or judges a statement with it as a venue does,
//! and reports its gas by phase.
//!
//! It links `format::MASKED_WRAP` (`src/bin/guest`).
//!
//! Input, as a JAM work item gives it:
//! - work item 0's payload (`fetch`, kind 13), at most 16 KiB: a mode byte,
//!   then
//!   - 0: the proof's format (a little-endian `u32`, one this build links:
//!     `vos_pvm_final_verifier::LINKED`) and the 24 public words (each a
//!     little-endian `u32`), which the proof is verified against;
//!   - 1: a judgement's input (`vos_statement::model::Input`): the program
//!     id the venue pinned, its state (its time, its formats, spaces,
//!     anchors and `Seen` entries) and the statement. The program id and
//!     the state come in the payload only for the test harness; a real
//!     service reads them from its own state, never from what a work item
//!     carries;
//!
//!   then the proof's Blake2b-256 hash and its length (`u32`,
//!   little-endian); any other mode is refused as a bad payload, so the
//!   program accepts nothing without a proof;
//! - the proof, in its format's encoding, as a preimage of the running
//!   service, read by `historical_lookup`: only once a judgement's checks
//!   before the proof pass, and only when its length is at most
//!   `vos_pvm_final_verifier::MAX_PROOF_BYTES`, refused before any
//!   allocation or lookup otherwise.
//!
//! Output (φ7 address, φ8 length): `Report`, every field a little-endian
//! `u64`: the verdict, the gas left at each phase, the heap's figures, a
//! refusal's text, a judgement's code and accepted statement id, and 160
//! bytes of zeros.
//! Blake2b-256 is computed in software: JAM serves no hash.

#![no_std]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
#![no_main]

extern crate alloc;

mod guest;
