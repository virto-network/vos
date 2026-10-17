//! Program-identity commitment.
//!
//! In vos-pvm-proof, a proof's preprocessed-trace Merkle root IS the program
//! commitment.  No separate computation is needed — the prover commits to
//! it as part of `prove`, and the verifier checks it via
//! `verify_standalone(proof, expected_commitment)`.
//!
//! Workflow:
//!   1. Run the prover once on representative input:
//!      `let proof = prove(&mut side_note)?`
//!   2. Extract the program hash:
//!      `let hash = program_commitment_of_proof(&proof)`
//!      (also accessible as `proof.preprocessed_commitment()`)
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
//! The commitment depends on `proof.log_sizes`: two proofs of the same
//! program at different log sizes commit differently.  A kernel's shape
//! ([`crate::shape`]) fixes every log size per class of segment from its
//! code, so each class's commitment is the program's alone,
//! computed before any run (`program_commitment_for_shape`).

use crate::Proof;

/// Program-identity hash type — the preprocessed-trace Merkle root, in the
/// hash of the proof's format.
pub type ProgramCommitment = crate::pcs::Commitment;

/// Extract the program-commitment Merkle root from a proof.
///
/// Equivalent to `proof.preprocessed_commitment()` on a proof the prover
/// made.
///
/// # Panics
///
/// On a proof without a preprocessed tree, which the prover never makes.
///
/// Use this once at program-deploy time:
///   ```no_run
///   # fn deploy(side_note: &mut vos_pvm_proof::SideNote) {
///   let proof = vos_pvm_proof::prove(side_note).expect("prove");
///   let id_hash = vos_pvm_proof::program_commitment_of_proof(&proof);
///   let id_log_sizes = proof.log_sizes.clone();
///   // publish (id_hash, id_log_sizes) on-chain or alongside the program.
///   # }
///   ```
pub fn program_commitment_of_proof(proof: &Proof) -> ProgramCommitment {
    proof
        .preprocessed_commitment()
        .expect("a proof the prover made has a preprocessed tree")
}

/// Convenience: hex-encoded program commitment.
pub fn program_commitment_hex(proof: &Proof) -> alloc::string::String {
    use alloc::string::ToString;
    program_commitment_of_proof(proof).to_string()
}
