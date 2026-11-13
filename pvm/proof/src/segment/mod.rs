//! Trace segmentation: slice a fully-traced `SideNote` into bounded
//! step-range segments that prove independently in bounded memory.
//!
//! A single proof's peak memory scales with the trace's largest chip
//! `log_size`; a kernel's run is cut into segments of its shape's classes
//! ([`crate::prove_kernel`]), each proved on its own, and a run's segments
//! chain: each one's `final_state` is the next's `initial_state`
//! ([`crate::proof::check_continuity`]; a leaf binds it in-circuit).
//!
//! Each segment's verification binds those fields to the committed boundary
//! columns (`boundary_binding`):
//!   - pc/timestamp columns are pinned to the trace by CpuChip's
//!     program-execution chaining;
//!   - register columns are pinned to the trace by the register ledger's
//!     read-consistency (a cross-row `prev_value` binding, a `(reg, ts)`
//!     sortedness gadget and an `is_write` limb; gate:
//!     `tests/gates/ledger_readconsistency_gate.rs`);
//!   - `memory_root` is the page-Merkle root the boundary multiproof binds
//!     in-circuit (`Memory{Page,Merkle,RootBoundary}Chip`).

/// Split `[0, total)` into consecutive `[a, b)` ranges of at most
/// `max_steps` steps each (the last may be shorter). Panics if
/// `max_steps == 0`. Returns an empty vec when `total == 0`.
pub fn segment_bounds(total: usize, max_steps: usize) -> alloc::vec::Vec<(usize, usize)> {
    assert!(max_steps > 0, "max_steps must be non-zero");
    let mut bounds = alloc::vec::Vec::new();
    let mut a = 0;
    while a < total {
        let b = (a + max_steps).min(total);
        bounds.push((a, b));
        a = b;
    }
    bounds
}

#[cfg(feature = "prover")]
mod bounds;
#[cfg(feature = "prover")]
mod cursor;
#[cfg(feature = "prover")]
mod window;

#[cfg(feature = "prover")]
pub use bounds::segment_bounds_budgeted;
#[cfg(feature = "prover")]
pub use cursor::SegmentCursor;
#[cfg(feature = "prover")]
pub use window::segment_side_note;
#[cfg(feature = "prover")]
pub(crate) use window::{replay_sparse_writes, replay_writes};

#[cfg(all(test, feature = "prover"))]
mod tests;
