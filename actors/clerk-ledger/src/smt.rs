//! Composite SMT state-root — the from-scratch reference.
//!
//! The algorithm and the leaf encoders live in
//! `cipher_clerk::state_root` (ungated, no_std, alloc-free) so the
//! canonical encoding lives next to the types it commits to. The
//! actor itself no longer rebuilds the root — the committed maps
//! maintain the six sub-SMT roots incrementally and `composite_root`
//! folds them in O(1) — so the full rebuild survives only as the
//! parity reference the unit tests compare the incremental root
//! against, byte for byte.
//!
//! Byte-equality against `cipher_clerk::helpers::MemLedger::root` is
//! pinned in cipher-clerk's `state_root_mem_ledger` integration test.

#[cfg(test)]
pub(crate) use cipher_clerk::state_root::composite_state_root as compute_state_root;
