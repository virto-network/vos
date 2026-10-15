//! Proof closure for standard nested Refine execution.
//!
//! The PVM AIR proves one program at a time. A standard Refine invocation is
//! not one program: the outer runtime stops at calls 9 through 14, the host
//! mutates the outer machine and its inner-machine dictionary, and call 13
//! runs a separately installed program. Consequently this module represents
//! the closure as ordered, independently verifiable machine-slice proofs plus
//! an authenticated boundary transcript.
//!
//! Soundness is deliberately reflected in the API. Child STARKs prove the
//! interpreter slices. [`RefineBundleVerification::ReplayRequired`] means
//! those proofs and the transcript authenticate successfully, but does *not*
//! bind the separately recorded native machine-state hashes and exit reasons
//! to those proofs or prove calls 9 through 14 in AIR. Prover-enabled hosts
//! close those remaining boundaries with
//! [`verify_refine_bundle_replayed`], which replays `RefineContext` from the
//! exact outer program, arguments, and gas and compares every typed boundary.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::Proof;

mod encode;

use encode::{
    commitment_bytes, put_exit, put_machine_id, put_refine_host_boundary, put_segment_state,
    put_u32, put_u64,
};

/// Wire shape of the boundary bundle itself and the encoding of the machine
/// states its boundaries commit to.
///
/// 4 — machine-state permission commitments hash the map's maximal runs
///     instead of one byte per page.
pub const REFINE_BUNDLE_FORMAT_VERSION: u32 = 4;
/// Post-decode protocol ceiling for independently proven machine slices.
///
/// An inner machine's precompile call ends its slice at a host exit, and its
/// agent serves it in a slice of its own, so each served call costs two: a
/// proven refine holds about 500 BLAKE2b compressions of its machines.
/// Proving attestable methods (slice 5) inherits that bound.
pub const MAX_REFINE_PROOF_SLICES: usize = 1_024;
/// A handled outer host call can contribute at most one boundary per slice.
pub const MAX_REFINE_HOST_BOUNDARIES: usize = MAX_REFINE_PROOF_SLICES;
/// The component mask is `u32`, so no proof shape can name more components.
pub const MAX_REFINE_CHILD_COMPONENTS: usize = u32::BITS as usize;
/// Stwo's canonical tree count: preprocessed, main, interaction, composition.
pub const REFINE_CHILD_COMMITMENT_COUNT: usize = crate::proof::PROOF_COMMITMENT_TREE_COUNT;
/// Aggregate post-decode heap payload accepted across all child proofs.
/// Production transports use the recursively bounded codec in
/// [`crate::refine_codec`], never direct Serde decoding.
pub const MAX_REFINE_CHILD_PROOF_BYTES: usize = 512 * 1024 * 1024;

/// Collision-resistant identity of exact canonical program artifact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RefineProgramId(pub [u8; 32]);

/// Derive the exact canonical-program artifact identity used by Refine
/// bundles. Length-prefixing prevents concatenation ambiguity.
pub fn refine_program_id(program: &[u8]) -> RefineProgramId {
    let mut bytes = Vec::with_capacity(40 + program.len());
    bytes.extend_from_slice(b"vos/pvm/refine-program/v1\0");
    bytes.extend_from_slice(&(program.len() as u64).to_le_bytes());
    bytes.extend_from_slice(program);
    RefineProgramId(crate::page_merkle::blake2b256(&bytes))
}

/// Commitment to the exact Refine invocation argument bytes.
pub fn refine_arguments_commitment(arguments: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(40 + arguments.len());
    bytes.extend_from_slice(b"vos/pvm/refine-arguments/v1\0");
    bytes.extend_from_slice(&(arguments.len() as u64).to_le_bytes());
    bytes.extend_from_slice(arguments);
    crate::page_merkle::blake2b256(&bytes)
}

/// Exact machine identity within one Refine invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RefineMachineId {
    Outer {
        program: RefineProgramId,
    },
    Inner {
        slot: u32,
        generation: u64,
        program: RefineProgramId,
    },
}

impl RefineMachineId {
    pub fn program(self) -> RefineProgramId {
        match self {
            Self::Outer { program } | Self::Inner { program, .. } => program,
        }
    }
}

/// Canonical, runtime-independent encoding of a PVM exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefineSliceExit {
    Halt,
    Panic,
    OutOfGas,
    PageFault(u32),
    HostCall(u64),
}

/// Authenticated before/after boundary for one standard host operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefineHostBoundary {
    /// Host operation, exactly one of 9..=14.
    pub call: u8,
    /// Number of completed slices at the Before event.
    pub slices_before: u32,
    /// Number of completed slices at the After event. Only INVOKE (13) may
    /// place an inner slice in this half-open interval.
    pub slices_after: u32,
    /// Commitment to the complete outer machine + inner dictionary before
    /// dispatch (program identities, architectural state, permissions and
    /// sparse non-zero pages).
    pub state_before: [u8; 32],
    /// Equivalent commitment after dispatch.
    pub state_after: [u8; 32],
    /// Exact outer register file supplying this host operation's inputs.
    pub registers_before: [u64; 13],
    /// Exact outer register file carrying its result/status.
    pub registers_after: [u64; 13],
}

/// One independently proven machine slice.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefineProofSlice {
    pub order: u32,
    pub identity: RefineMachineId,
    pub entry_state: [u8; 32],
    /// State exposed by `MachineExit`. This can differ from the STARK row's
    /// final PC when the host has just acknowledged an inner host exit.
    pub observed_exit_state: [u8; 32],
    pub exit: RefineSliceExit,
    pub proof: Proof,
}

/// Prove/verify-capable closure of one nested Refine invocation.
///
/// # Untrusted decoding
///
/// The derived Serde representation is an in-memory interchange shape only.
/// Untrusted material must enter through
/// [`crate::decode_refine_proof_bundle`], which rejects the complete input
/// against the authenticated runtime ceiling and charges every nested Stwo
/// allocation before reserve. [`refine_bundle_cardinality_is_valid`] remains
/// the final post-decode structural preflight.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefineProofBundle {
    pub format_version: u32,
    pub outer_program: RefineProgramId,
    /// Commitment to the exact invocation argument bytes.
    pub arguments_commitment: [u8; 32],
    /// Exact invocation gas budget.
    pub gas_limit: u64,
    pub slices: Vec<RefineProofSlice>,
    pub host_boundaries: Vec<RefineHostBoundary>,
    pub result: RefineSliceExit,
    /// Hash of every field above that selects execution identity or proof
    /// shape, including child proof format/program commitment/log sizes and
    /// exact slice/boundary order.
    pub transcript_commitment: [u8; 32],
}

/// Successful structural/cryptographic verification disposition.
///
/// This intentionally has no `Valid` variant. Child proofs do not bind every
/// native state/exit transcript field, and calls 9..=14 are outside their AIR;
/// exact deterministic replay is required for end-to-end acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefineBundleVerification {
    ReplayRequired { transcript_commitment: [u8; 32] },
}

/// Allocation-free preflight for every collection whose length is encoded in
/// the Refine transcript or cloned/iterated by the verifier.
pub fn refine_bundle_cardinality_is_valid(bundle: &RefineProofBundle) -> bool {
    if bundle.slices.is_empty()
        || bundle.slices.len() > MAX_REFINE_PROOF_SLICES
        || bundle.host_boundaries.len() > MAX_REFINE_HOST_BOUNDARIES
        || bundle.host_boundaries.len() > bundle.slices.len()
    {
        return false;
    }
    let mut child_bytes = 0usize;
    for slice in &bundle.slices {
        if slice.proof.log_sizes.len() > MAX_REFINE_CHILD_COMPONENTS
            || slice.proof.claimed_sums.len() > MAX_REFINE_CHILD_COMPONENTS
            || slice.proof.num_components > MAX_REFINE_CHILD_COMPONENTS
            || slice.proof.stark_proof.commitments.len() != REFINE_CHILD_COMMITMENT_COUNT
        {
            return false;
        }
        let Ok(bytes) = crate::proof::preflight_proof_structure_readonly(
            &slice.proof,
            crate::proof::MAX_PROOF_LOG_SIZE,
        ) else {
            return false;
        };
        let Some(total) = child_bytes.checked_add(bytes) else {
            return false;
        };
        if total > MAX_REFINE_CHILD_PROOF_BYTES {
            return false;
        }
        child_bytes = total;
    }
    true
}

/// Recompute the canonical outer transcript commitment.
///
/// This authenticates ordered machine identities, public native-state
/// boundary witnesses, complete child statement metadata/roots, and host-call
/// boundaries. It is not a substitute for the child STARK transcript: replay
/// acceptance separately regenerates and compares each exact main-trace root,
/// then verifies that child's format-domain-bound STARK.
pub fn refine_bundle_commitment(bundle: &RefineProofBundle) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"vos/pvm/refine-proof-bundle/v2\0");
    put_u32(&mut bytes, bundle.format_version);
    bytes.extend_from_slice(&bundle.outer_program.0);
    bytes.extend_from_slice(&bundle.arguments_commitment);
    put_u64(&mut bytes, bundle.gas_limit);
    put_exit(&mut bytes, bundle.result);
    put_u32(&mut bytes, bundle.slices.len() as u32);
    for slice in &bundle.slices {
        put_u32(&mut bytes, slice.order);
        put_machine_id(&mut bytes, slice.identity);
        bytes.extend_from_slice(&slice.entry_state);
        bytes.extend_from_slice(&slice.observed_exit_state);
        put_exit(&mut bytes, slice.exit);

        let proof = &slice.proof;
        put_u32(&mut bytes, proof.format_version);
        put_u32(&mut bytes, proof.component_mask);
        put_u64(&mut bytes, proof.num_components as u64);
        put_u32(&mut bytes, proof.log_sizes.len() as u32);
        for &size in &proof.log_sizes {
            put_u32(&mut bytes, size);
        }
        put_u32(&mut bytes, proof.claimed_sums.len() as u32);
        for sum in &proof.claimed_sums {
            for limb in sum.to_m31_array() {
                put_u32(&mut bytes, limb.0);
            }
        }
        put_u32(&mut bytes, proof.pcs_config.pow_bits);
        put_u32(&mut bytes, proof.pcs_config.fri_config.log_blowup_factor);
        put_u32(
            &mut bytes,
            proof.pcs_config.fri_config.log_last_layer_degree_bound,
        );
        put_u64(&mut bytes, proof.pcs_config.fri_config.n_queries as u64);
        put_u32(&mut bytes, proof.pcs_config.fri_config.fold_step);
        match proof.pcs_config.lifting_log_size {
            None => bytes.push(0),
            Some(lifting_log_size) => {
                bytes.push(1);
                put_u32(&mut bytes, lifting_log_size);
            }
        }
        put_segment_state(&mut bytes, &proof.initial_state);
        put_segment_state(&mut bytes, &proof.final_state);
        put_u32(&mut bytes, proof.stark_proof.commitments.len() as u32);
        for commitment in proof.stark_proof.commitments.iter() {
            bytes.extend_from_slice(&commitment_bytes(commitment));
        }
    }
    put_u32(&mut bytes, bundle.host_boundaries.len() as u32);
    for boundary in &bundle.host_boundaries {
        bytes.push(boundary.call);
        put_u32(&mut bytes, boundary.slices_before);
        put_u32(&mut bytes, boundary.slices_after);
        bytes.extend_from_slice(&boundary.state_before);
        bytes.extend_from_slice(&boundary.state_after);
        for &register in &boundary.registers_before {
            put_u64(&mut bytes, register);
        }
        for &register in &boundary.registers_after {
            put_u64(&mut bytes, register);
        }
    }
    crate::page_merkle::blake2b256(&bytes)
}

#[derive(Clone, Copy)]
struct RefineExecutionSlice {
    order: u32,
    identity: RefineMachineId,
    entry_state: [u8; 32],
    observed_exit_state: [u8; 32],
    exit: RefineSliceExit,
}

/// Commitment to the exact nested execution transcript, independent of the
/// proof system's serialization and Fiat-Shamir payload.
///
/// A tentative executor can commit this value before proof production. A
/// verifier recomputes the same value from the public proof bundle after it
/// has checked every child proof and replayed all native Refine boundaries.
/// Keeping this separate from [`refine_bundle_commitment`] avoids a circular
/// dependency between the statement (which names the trace) and proof bytes
/// produced for that statement.
pub fn refine_bundle_execution_commitment(bundle: &RefineProofBundle) -> [u8; 32] {
    refine_execution_commitment(
        bundle.outer_program,
        bundle.arguments_commitment,
        bundle.gas_limit,
        bundle.result,
        bundle.slices.len(),
        bundle.slices.iter().map(|slice| RefineExecutionSlice {
            order: slice.order,
            identity: slice.identity,
            entry_state: slice.entry_state,
            observed_exit_state: slice.observed_exit_state,
            exit: slice.exit,
        }),
        &bundle.host_boundaries,
    )
}

/// Read the public-I/O hash from the proved terminal outer-machine halt.
///
/// This helper performs only the local terminal-shape check. Callers handling
/// untrusted material must first use the bounded Refine codec and must accept
/// this value only after complete child-proof verification and deterministic
/// native-boundary replay. The final registers are bound by the PVM AIR; the
/// standard runtime places its exact work/transition commitment in a2..a5.
pub fn refine_bundle_terminal_public_io(bundle: &RefineProofBundle) -> Option<[u8; 32]> {
    let terminal = bundle.slices.last()?;
    if bundle.result != RefineSliceExit::Halt
        || terminal.exit != RefineSliceExit::Halt
        || !matches!(terminal.identity, RefineMachineId::Outer { program } if program == bundle.outer_program)
    {
        return None;
    }
    Some(terminal.proof.public_io_hash())
}

fn refine_execution_commitment(
    outer_program: RefineProgramId,
    arguments_commitment: [u8; 32],
    gas_limit: u64,
    result: RefineSliceExit,
    slice_count: usize,
    slices: impl IntoIterator<Item = RefineExecutionSlice>,
    host_boundaries: &[RefineHostBoundary],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"vos/pvm/refine-execution-transcript/v2\0");
    bytes.extend_from_slice(&outer_program.0);
    bytes.extend_from_slice(&arguments_commitment);
    put_u64(&mut bytes, gas_limit);
    put_exit(&mut bytes, result);
    put_u32(&mut bytes, slice_count as u32);
    for slice in slices {
        put_u32(&mut bytes, slice.order);
        put_machine_id(&mut bytes, slice.identity);
        bytes.extend_from_slice(&slice.entry_state);
        bytes.extend_from_slice(&slice.observed_exit_state);
        put_exit(&mut bytes, slice.exit);
    }
    put_u32(&mut bytes, host_boundaries.len() as u32);
    for boundary in host_boundaries {
        put_refine_host_boundary(&mut bytes, boundary);
    }
    crate::page_merkle::blake2b256(&bytes)
}

#[cfg(feature = "prover")]
mod prover;

#[cfg(feature = "prover")]
pub use prover::{
    RefineObservedRun, RefineTraceBundle, RefineTraceError, RefineTraceSlice, prove_refine,
    refine_trace_execution_commitment, trace_refine, trace_refine_observed,
    trace_refine_with_output, verify_refine_bundle_replayed,
};

#[cfg(all(test, feature = "prover"))]
mod tests;
