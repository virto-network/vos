//! The carrier audit: the bytes of every carrier a run produced, searched
//! for what must never leave the prover role (`proving.md` A.5).
//!
//! A run knows what it must not show: the segment, leaf and fold proofs it
//! built, the rows it served, the plain hashes of its private arguments,
//! its step counts, its memory roots and its registers past the io-hash's
//! φ9..φ12. [`Needles`] holds them, from the prover's internals
//! (`vos_node_prover::Internals`) and each statement's record; [`Audit`]
//! holds the carriers, each as it [`Reach`]es: out of the role (a venue's
//! call, a log line, a client's answer, a node that does not replicate the
//! agent) or within the agent's replicas (its log, its blobs, the frames
//! between them). Every needle is searched in every carrier that leaves;
//! the proofs, memory roots and register files, which no carrier may hold,
//! in those that stay too.
//!
//! - [`needles`]: the needles and the forms each is searched in;
//! - [`audit`]: the carriers and the search;
//! - [`capture`]: what takes a run's carriers: a venue's client
//!   ([`Tapped`]), the process's logs ([`Logs`]) and standard error
//!   ([`Stderr`]), a node's disk and its store.

pub mod audit;
pub mod capture;
pub mod needles;

pub use audit::{Audit, Carrier, Finding};
pub use capture::{
    DEBUG_ENVIRONMENT, Logs, Stderr, Tapped, anchor_carriers, directory, store, submission_carriers,
};
pub use needles::{DEBUG_OUTPUTS, DISTINCT, Needle, Needles, SHORTEST};

/// What a needle is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A segment, leaf or fold proof: its trees' roots, its encoding, the
    /// digests its output states.
    NodeProof,
    /// A served row: its value, its salt, the cut's roots and paths; or a
    /// private argument.
    ServedRow,
    /// A plain or domain-prefixed hash of the private arguments or of the
    /// served rows.
    PrivateHash,
    /// A step count: a segment's, a boundary's index, the run's, the gas a
    /// re-run has left.
    StepCount,
    /// A memory root, or the commitment of an image.
    MemoryRoot,
    /// A register past φ9..φ12, or the file φ0..φ8.
    Register,
    /// A debug output's own text, which only `debug-internals` builds
    /// print: each instruction a run steps through, the recompiler's
    /// registers, a trace's rows.
    DebugOutput,
}

impl Kind {
    /// Whether no carrier at all may hold it, the role's own included.
    fn nowhere(self) -> bool {
        matches!(self, Self::NodeProof | Self::MemoryRoot)
    }
}

/// How far a carrier reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Out of the prover role: a venue, a log, a client, a node that does
    /// not replicate the agent.
    Leaves,
    /// Within the agent's replicas, which hold its rows and run its
    /// kernels.
    Role,
}

/// `mutex`, held, whether or not a holder panicked.
fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests;
