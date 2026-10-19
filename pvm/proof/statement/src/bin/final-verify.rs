//! The venue as a JAM refine program (`--features pvm-guest`, built by
//! `just check-no-std` for the PVM target): it verifies a final proof the
//! way a JAM service would, or judges a statement with it as a venue does,
//! and reports its gas by phase.
//!
//! Two builds of it (`src/bin/guest`): `final-verify.elf`, the production
//! venue's, linking format 39 alone, which refuses to build under
//! `test-formats`; and `final-verify-test.elf` (`--features
//! pvm-guest,test-formats`, `src/bin/final-verify-test.rs`), linking format
//! 28 beside it, for the test policy's fixtures.
//!
//! Input, as a JAM work item gives it:
//! - work item 0's payload (`fetch`, kind 13), at most 16 KiB: a mode byte,
//!   then
//!   - 0: the proof's format (a little-endian `u32`, one this build links:
//!     `vos_pvm_final_verifier::LINKED`) and the 24 public words (each a
//!     little-endian `u32`), which the proof is verified against;
//!   - 1: a judgement's input (`vos_statement::model::Input`): what the
//!     venue pinned (the program id, venue-bound or not), its state (its
//!     id, its time, its formats, spaces, anchors and `Seen` entries) and
//!     the statement. The pin and the state come in the payload only for
//!     the test harness; a real service reads them from its own state,
//!     never from what a work item carries;
//!
//!   then the proof's Blake2b-256 hash and its length (`u32`,
//!   little-endian);
//!   - 2: a golden vector of `vos-anchor` (`vos_anchor::vectors::Vector`'s
//!     encoding), and nothing after it: its digests are computed, and no
//!     proof is read;
//! - the proof, in its format's encoding, as a preimage of the running
//!   service, read by `historical_lookup`: only once a judgement's checks
//!   before the proof pass, and only when its length is at most
//!   `vos_pvm_final_verifier::MAX_PROOF_BYTES`, refused before any
//!   allocation or lookup otherwise.
//!
//! Output (φ7 address, φ8 length): `Report`, every field a little-endian
//! `u64`: the verdict, the gas left at each phase, the heap's figures, a
//! refusal's text, a judgement's code and accepted statement id, and a
//! vector's digests.
//! Blake2b-256 is computed in software: JAM serves no hash.

#![no_std]
#![no_main]

extern crate alloc;

#[cfg(feature = "test-formats")]
compile_error!("final-verify links format 39 alone: build final-verify-test under test-formats");

mod guest;
