//! Program-identity commitment.
//!
//! In zkpvm, a proof's preprocessed-trace Merkle root IS the program
//! commitment.  No separate computation is needed — the prover commits to
//! it as part of `prove`, and the verifier checks it via
//! `verify_standalone(proof, expected_commitment)`.
//!
//! Workflow:
//!   1. Run the prover once on representative input:
//!      `let proof = prove(&mut side_note)?`
//!   2. Extract the program hash:
//!      `let hash = program_commitment_of_proof(&proof)`
//!      (also accessible as `proof.stark_proof.commitments[0]`)
//!   3. Publish (hash, proof.log_sizes) as the program identity record.
//!   4. For every later proof of the same program, verify with:
//!      `verify_standalone(later_proof, hash)`
//!      The verifier rejects unless `later_proof.log_sizes == proof.log_sizes`
//!      AND its preprocessed commitment matches `hash`.
//!
//! Why this works: ProgramMemoryChip's preprocessed columns
//! include every PC's decoded instruction tuple plus the
//! 20 category flags; two programs with different bytecode necessarily
//! produce different ProgramMemoryChip preprocessed columns, and
//! therefore different Merkle roots.  The other chips' preprocessed
//! tables (BitwiseLookupChip, RangeMultiplicity256, PowerOfTwoChip,
//! Blake2bChip schedule) contribute fixed-per-log_size constants.
//!
//! Limitation we accept: the commitment depends on `proof.log_sizes` and
//! thus on the execution shape (number of steps, ECALLs, memory ops).
//! Two proofs of the same program at different log_sizes produce
//! different commitments.  A chain operator sets canonical log_sizes
//! by running the prover at sufficient capacity, then refuses smaller
//! proofs.  Future work could fix log_sizes to per-chip maxima at
//! compile time so the commitment is purely program-derived.

use crate::Proof;

/// Program-identity hash type — the preprocessed-trace Merkle root, in the
/// per-build PCS hash (Blake2s by default; `P2Hash` under `poseidon2-channel`).
pub type ProgramCommitment = crate::recursion_pcs::ProverMerkleHash;

/// Extract the program-commitment Merkle root from a proof.
///
/// Equivalent to `proof.stark_proof.commitments[0]`, but expressed as a
/// named API so callers don't reach into the StarkProof internals.
///
/// Use this once at program-deploy time:
///   ```ignore
///   let proof = zkpvm::prove(&mut side_note)?;
///   let id_hash = zkpvm::program_commitment_of_proof(&proof);
///   let id_log_sizes = proof.log_sizes.clone();
///   // publish (id_hash, id_log_sizes) on-chain or alongside the program.
///   ```
pub fn program_commitment_of_proof(proof: &Proof) -> ProgramCommitment {
    proof.stark_proof.commitments[0]
}

/// Convenience: hex-encoded program commitment.
pub fn program_commitment_hex(proof: &Proof) -> alloc::string::String {
    use alloc::string::ToString;
    program_commitment_of_proof(proof).to_string()
}
