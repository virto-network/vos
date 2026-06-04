//! Composite SMT state-root.
//!
//! The algorithm and the three leaf encoders that used to live here
//! were extracted into `cipher_clerk::state_root` (ungated, no_std,
//! alloc-free) so the canonical encoding lives next to the types it
//! commits to. This module is now a thin re-export keeping the
//! actor-local `crate::smt::compute_state_root` name stable for the
//! call sites in `lib.rs` / `view.rs`.
//!
//! Byte-equality against `cipher_clerk::helpers::MemLedger::root` is
//! pinned in cipher-clerk's `state_root_mem_ledger` integration test
//! (the pin that used to live in this crate's `tests.rs`).

pub(crate) use cipher_clerk::state_root::composite_state_root as compute_state_root;
