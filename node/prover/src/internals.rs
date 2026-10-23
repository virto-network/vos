//! What a statement's proof is built from that must never leave the prover
//! role: the segment, leaf and fold proofs, the run's step counts, its
//! memory roots and its registers past the io-hash's φ9..φ12. A carrier
//! audit searches every carrier that leaves the role for them.

/// A segment, leaf or fold proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeProof {
    /// What it proves, e.g. `segment 0`, `leaf 2`, `fold 1`.
    pub name: String,
    /// Its trees' roots.
    pub roots: Vec<[u8; 32]>,
    /// Its serde form, as postcard lays it out.
    pub encoding: Vec<u8>,
    /// The digests its output states, of its boundaries' states: none for a
    /// segment.
    pub digests: Vec<[u8; 32]>,
}

/// The internals of one statement's proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Internals {
    pub proofs: Vec<NodeProof>,
    /// Each boundary's step index, then each segment's steps.
    pub steps: Vec<u64>,
    /// The run's steps, every segment's summed: what the gas its re-run
    /// left shows.
    pub run_steps: u64,
    /// Each boundary's memory root and the commitment of its image; never
    /// the kernel's image root, which its install's record publishes.
    pub memory_roots: Vec<[u8; 32]>,
    /// Each boundary's registers, φ0..φ12 (φ9..φ12, the io-hash, public).
    pub registers: Vec<[u64; 13]>,
}

impl Internals {
    /// The registers whose values are private: φ0..φ8.
    pub const PRIVATE_REGISTERS: core::ops::Range<usize> = 0..9;
}
