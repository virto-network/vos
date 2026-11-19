//! The native verifier of a segment proof (format 41), from the proof and
//! its program's preprocessed root alone, no trace.
//!
//! [`verify_standalone`] is the reference a leaf circuit is held to: the
//! recursion's in-AIR verifier (`vos-pvm-recair`'s leaf) replays the checks
//! it makes (`docs/design/proving.md` A.1), and the recursion's tests hold
//! the leaf to it, but for the boundary timestamps' bound
//! ([`TIMESTAMP_BOUND`]), which the leaf takes from the fold chain instead.
//! Its checks are written once, in `vos_pvm_proof::standalone`, which the
//! prover-side `vos_pvm_proof::verify` runs too; this crate names them
//! without the prover. No production path calls it: a node verifies a
//! kernel's segments inside its leaves, and a venue the wrap alone.
//! [`verify_kernel_segment`] and [`verify_kernel_chain`] add a kernel's
//! shape and entry, its program id's preimage.
//!
//! **No production build links this crate.** It is the reference the
//! leaf is tested against and the compile check of `vos-pvm-proof`'s
//! verifier-only configuration (`just check-no-std`); nodes and venues
//! verify through the leaf, the wrap and the device verifier instead
//! (`../AUDIT.md`).
//!
//! `no_std`: `vos-pvm-proof` without its `prover` feature pulls no `vos_pvm`
//! and no rayon, and builds for `wasm32-unknown-unknown`.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

use alloc::{format, vec::Vec};
use stwo::core::verifier::VerificationError;

// The proof type, and the format registry `verify_standalone` admits a
// proof's number from.
pub use vos_pvm_proof::Proof;
pub use vos_pvm_proof::format;
pub use vos_pvm_proof::program_id::{
    ENTRY_TIMESTAMP, HALT_PC, KernelEntry, KernelProgram, LeafCircuits, ProgramId,
};
pub use vos_pvm_proof::shape::{ClassShape, KernelShape};

/// Verification hash type — the preprocessed-trace Merkle root, in the hash
/// of the proof's format.
pub use vos_pvm_proof::pcs::Commitment as CommitmentHash;

/// The per-component log size cap `verify_standalone` applies, the
/// protocol's.
pub use vos_pvm_proof::proof::MAX_PROOF_LOG_SIZE as DEFAULT_MAX_LOG_SIZE;

/// The segment verifier from a proof and its program's preprocessed root,
/// its security counts, and the bound on its boundary timestamps: one copy
/// of the checks, `vos-pvm-proof`'s, which its prover-side `verify` runs
/// too.
pub use vos_pvm_proof::standalone::{TIMESTAMP_BOUND, proof_security_bits, verify_standalone};

/// The class of a segment of a kernel's run, from its structure alone: its
/// format the kernel's, its chips exactly the shape's, more or fewer
/// refused, its log sizes exactly one class's.
fn kernel_segment_class(
    proof: &Proof,
    program: &KernelProgram,
) -> Result<usize, VerificationError> {
    if proof.format_version != program.format {
        return Err(VerificationError::InvalidStructure(format!(
            "the proof's format {} is not its kernel's, {}",
            proof.format_version, program.format
        )));
    }
    program
        .shape
        .class_of(proof.component_mask, &proof.log_sizes)
        .map_err(VerificationError::from)
}

/// Verify a segment of a kernel's run against its program, the preimage of
/// its program id ([`vos_pvm_proof::program_id`]): its format, its chips
/// exactly the shape's, more or fewer refused, its log sizes exactly one
/// class's, then [`verify_standalone`] against that class's preprocessed
/// root. The shape is checked before any cryptographic work, so a proof of
/// another shape costs its structure alone. Returns the segment's class.
pub fn verify_kernel_segment(
    proof: Proof,
    program: &KernelProgram,
) -> Result<usize, VerificationError> {
    program.check()?;
    let class = kernel_segment_class(&proof, program)?;
    verify_standalone(proof, program.preprocessed_roots[class])?;
    Ok(class)
}

/// Verify a whole run of a kernel, a chain of its segments, against its
/// program and its entry ([`KernelEntry::of`] the kernel's blob): the first
/// segment starts where the loader starts the kernel, at its entry pc, at
/// timestamp 1, with the loader's registers and the kernel's image root;
/// each continues the one before; the last ends at the halt; and each is a
/// segment of the kernel ([`verify_kernel_segment`]). Every structural
/// check runs before any cryptographic one, and verifying a proof consumes
/// it, so the chain is taken whole. Returns the run's final
/// registers: its output's address and length in φ7 and φ8, its io-hash
/// in φ9 to φ12.
pub fn verify_kernel_chain(
    proofs: Vec<Proof>,
    program: &KernelProgram,
    entry: &KernelEntry,
) -> Result<[u64; 13], VerificationError> {
    let refuse = |reason: &str| {
        Err(VerificationError::InvalidStructure(format!(
            "verify_kernel_chain: {reason}"
        )))
    };
    let (Some(first), Some(last)) = (proofs.first(), proofs.last()) else {
        return refuse("empty proof chain");
    };
    program.check()?;
    let start = &first.initial_state;
    if start.timestamp != ENTRY_TIMESTAMP {
        return refuse("the first segment does not start at the run's first timestamp");
    }
    if start.pc != entry.pc {
        return refuse("the first segment does not start at the kernel's entry");
    }
    if start.registers != entry.registers {
        return refuse("the first segment does not start with the loader's registers");
    }
    if start.memory_root != program.image_root {
        return refuse("the first segment does not start at the kernel's image root");
    }
    if last.final_state.pc != HALT_PC {
        return refuse("the last segment does not end at the halt");
    }
    vos_pvm_proof::proof::check_continuity(&proofs)?;
    let classes = proofs
        .iter()
        .map(|proof| kernel_segment_class(proof, program))
        .collect::<Result<Vec<_>, _>>()?;
    let registers = last.final_state.registers;
    for (proof, class) in proofs.into_iter().zip(classes) {
        verify_standalone(proof, program.preprocessed_roots[class])?;
    }
    Ok(registers)
}
