use alloc::string::{String, ToString};

use vos_pvm::Gas;

use crate::SideNote;
use crate::prove::ProvingError;

use super::collector::{exit_kind, run_refine_collector};
use super::*;

/// Directly observed (not re-executed) witness for one machine slice.
pub struct RefineTraceSlice {
    pub order: u32,
    pub identity: RefineMachineId,
    pub entry_state: [u8; 32],
    pub observed_exit_state: [u8; 32],
    pub exit: RefineSliceExit,
    pub side_note: SideNote,
}

/// Traced closure produced by the sole `RefineContext` interpreter run.
pub struct RefineTraceBundle {
    pub outer_program: RefineProgramId,
    pub arguments_commitment: [u8; 32],
    pub gas_limit: u64,
    pub slices: Vec<RefineTraceSlice>,
    pub host_boundaries: Vec<RefineHostBoundary>,
    pub result: RefineSliceExit,
}

/// Exact output and public-I/O registers captured with one observed trace.
///
/// Construction succeeds only for a normal halt whose complete output
/// window is readable and no larger than the caller's ceiling. The trace,
/// bytes, and register commitment therefore always describe the same sole
/// interpreter run; a caller cannot accidentally pair a proved trace with
/// output recovered by a second execution.
pub struct RefineObservedRun {
    pub trace: RefineTraceBundle,
    pub output: Vec<u8>,
    pub public_io: [u8; 32],
}

#[derive(Debug)]
pub enum RefineTraceError {
    Load(vos_pvm::refine::RefineError),
    Observation(String),
    OutputUnavailable,
    Prove(ProvingError),
    ReplayMismatch(&'static str),
    Verify(String),
}

impl core::fmt::Display for RefineTraceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Load(error) => write!(formatter, "cannot load Refine program: {error}"),
            Self::Observation(error) => {
                write!(formatter, "invalid Refine observation: {error}")
            }
            Self::OutputUnavailable => formatter.write_str(
                "Refine did not halt with a readable output inside the configured ceiling",
            ),
            Self::Prove(error) => write!(formatter, "cannot prove Refine slice: {error}"),
            Self::ReplayMismatch(field) => {
                write!(formatter, "Refine replay differs at {field}")
            }
            Self::Verify(error) => write!(formatter, "Refine child proof failed: {error}"),
        }
    }
}

impl std::error::Error for RefineTraceError {}

impl From<vos_pvm::refine::RefineError> for RefineTraceError {
    fn from(error: vos_pvm::refine::RefineError) -> Self {
        Self::Load(error)
    }
}

/// Execute and trace a complete standard Refine invocation once.
///
/// `MemoryModel::Sparse` is forced even on 64-bit hosts. Every witness row
/// comes from `InstructionObservation` emitted by that sole execution.
pub fn trace_refine(
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
) -> Result<RefineTraceBundle, RefineTraceError> {
    let outer_id = refine_program_id(outer_program);
    let (collector, invocation) = run_refine_collector(outer_program, args, gas)?;
    Ok(RefineTraceBundle {
        outer_program: outer_id,
        arguments_commitment: refine_arguments_commitment(args),
        gas_limit: gas,
        slices: collector.slices,
        host_boundaries: collector.boundaries,
        result: exit_kind(&invocation.exit),
    })
}

/// Execute and trace one complete standard Refine invocation, returning
/// the exact halted output from that same observed run.
///
/// The guest-controlled output length is rejected before allocation when
/// it exceeds `maximum_output_bytes`.
///
/// `None` means the invocation did not reach a normal halt with a fully
/// readable, bounded output window. Callers must reject it when a
/// canonical output is required; no second unobserved execution is needed
/// to recover the tentative transition.
pub fn trace_refine_with_output(
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
    maximum_output_bytes: usize,
) -> Result<(RefineTraceBundle, Option<Vec<u8>>), RefineTraceError> {
    let outer_id = refine_program_id(outer_program);
    let (collector, invocation) = run_refine_collector(outer_program, args, gas)?;
    let output = invocation.output_bounded(maximum_output_bytes);
    Ok((
        RefineTraceBundle {
            outer_program: outer_id,
            arguments_commitment: refine_arguments_commitment(args),
            gas_limit: gas,
            slices: collector.slices,
            host_boundaries: collector.boundaries,
            result: exit_kind(&invocation.exit),
        },
        output,
    ))
}

/// Execute and trace one complete standard Refine invocation exactly
/// once, requiring its bounded halted output and public-I/O registers.
///
/// This is the production preparation seam for a tentative transition.
/// Output length and readability are validated by
/// [`vos_pvm::refine::Invocation::output_bounded`] before allocation.
pub fn trace_refine_observed(
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
    maximum_output_bytes: usize,
) -> Result<RefineObservedRun, RefineTraceError> {
    let outer_id = refine_program_id(outer_program);
    let (collector, invocation) = run_refine_collector(outer_program, args, gas)?;
    let output = invocation
        .output_bounded(maximum_output_bytes)
        .ok_or(RefineTraceError::OutputUnavailable)?;
    let public_io = crate::proof::public_io_hash_from_registers(&invocation.registers);
    Ok(RefineObservedRun {
        trace: RefineTraceBundle {
            outer_program: outer_id,
            arguments_commitment: refine_arguments_commitment(args),
            gas_limit: gas,
            slices: collector.slices,
            host_boundaries: collector.boundaries,
            result: exit_kind(&invocation.exit),
        },
        output,
        public_io,
    })
}

/// Pre-proof commitment to the exact execution metadata observed in a
/// [`RefineTraceBundle`]. This equals
/// [`refine_bundle_execution_commitment`] for the proof produced from the
/// trace.
pub fn refine_trace_execution_commitment(trace: &RefineTraceBundle) -> [u8; 32] {
    refine_execution_commitment(
        trace.outer_program,
        trace.arguments_commitment,
        trace.gas_limit,
        trace.result,
        trace.slices.len(),
        trace.slices.iter().map(|slice| RefineExecutionSlice {
            order: slice.order,
            identity: slice.identity,
            entry_state: slice.entry_state,
            observed_exit_state: slice.observed_exit_state,
            exit: slice.exit,
        }),
        &trace.host_boundaries,
    )
}

/// Prove every directly observed machine slice and authenticate the
/// complete boundary transcript.
pub fn prove_refine(trace: RefineTraceBundle) -> Result<RefineProofBundle, RefineTraceError> {
    if trace.slices.is_empty()
        || trace.slices.len() > MAX_REFINE_PROOF_SLICES
        || trace.host_boundaries.len() > MAX_REFINE_HOST_BOUNDARIES
        || trace.host_boundaries.len() > trace.slices.len()
    {
        return Err(RefineTraceError::Observation(
            "Refine closure cardinality is noncanonical".to_string(),
        ));
    }
    let mut slices = Vec::with_capacity(trace.slices.len());
    let mut child_proof_bytes = 0usize;
    for mut slice in trace.slices {
        let proof = crate::prove(&mut slice.side_note).map_err(RefineTraceError::Prove)?;
        if proof.log_sizes.len() > MAX_REFINE_CHILD_COMPONENTS
            || proof.claimed_sums.len() > MAX_REFINE_CHILD_COMPONENTS
            || proof.num_components > MAX_REFINE_CHILD_COMPONENTS
            || proof.stark_proof.commitment_count() != REFINE_CHILD_COMMITMENT_COUNT
        {
            return Err(RefineTraceError::Observation(format!(
                "Refine child proof cardinality is noncanonical: logs={}, sums={}, components={}, commitments={}",
                proof.log_sizes.len(),
                proof.claimed_sums.len(),
                proof.num_components,
                proof.stark_proof.commitment_count(),
            )));
        }
        let proof_bytes = crate::proof::proof_owned_bytes(&proof).ok_or_else(|| {
            RefineTraceError::Observation(
                "Refine child proof exceeds the per-proof payload bound".to_string(),
            )
        })?;
        child_proof_bytes = child_proof_bytes
            .checked_add(proof_bytes)
            .filter(|&total| total <= MAX_REFINE_CHILD_PROOF_BYTES)
            .ok_or_else(|| {
                RefineTraceError::Observation(
                    "Refine child-proof aggregate payload limit exceeded".to_string(),
                )
            })?;
        slices.push(RefineProofSlice {
            order: slice.order,
            identity: slice.identity,
            entry_state: slice.entry_state,
            observed_exit_state: slice.observed_exit_state,
            exit: slice.exit,
            proof,
        });
    }
    let mut bundle = RefineProofBundle {
        format_version: REFINE_BUNDLE_FORMAT_VERSION,
        outer_program: trace.outer_program,
        arguments_commitment: trace.arguments_commitment,
        gas_limit: trace.gas_limit,
        slices,
        host_boundaries: trace.host_boundaries,
        result: trace.result,
        transcript_commitment: [0; 32],
    };
    bundle.transcript_commitment = refine_bundle_commitment(&bundle);
    Ok(bundle)
}

/// Close the native-host semantic boundary by replaying exact committed
/// inputs and verifying every child proof against the newly observed
/// program/slice side note.
pub fn verify_refine_bundle_replayed(
    bundle: &RefineProofBundle,
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
) -> Result<(), RefineTraceError> {
    if !refine_bundle_cardinality_is_valid(bundle) {
        return Err(RefineTraceError::ReplayMismatch("bundle cardinality"));
    }
    if bundle.format_version != REFINE_BUNDLE_FORMAT_VERSION {
        return Err(RefineTraceError::ReplayMismatch("bundle format version"));
    }
    if refine_program_id(outer_program) != bundle.outer_program {
        return Err(RefineTraceError::ReplayMismatch("outer program identity"));
    }
    if refine_arguments_commitment(args) != bundle.arguments_commitment || gas != bundle.gas_limit {
        return Err(RefineTraceError::ReplayMismatch("arguments/gas"));
    }
    if refine_bundle_commitment(bundle) != bundle.transcript_commitment {
        return Err(RefineTraceError::ReplayMismatch("transcript commitment"));
    }
    // Reject hostile PCS amplification before deterministic replay or any
    // prover-side commitment constructor. The final child verifier repeats
    // these policy checks after exact trace binding.
    for slice in &bundle.slices {
        crate::proof::check_min_security(&slice.proof.pcs_config)
            .map_err(|_| RefineTraceError::ReplayMismatch("child PCS security"))?;
        if slice.proof.pcs_config.fri_config.log_blowup_factor
            > crate::proof::MAX_RECOMMIT_LOG_BLOWUP
        {
            return Err(RefineTraceError::ReplayMismatch(
                "child PCS recommitment amplification",
            ));
        }
    }
    let trace = trace_refine(outer_program, args, gas)?;
    if trace.outer_program != bundle.outer_program {
        return Err(RefineTraceError::ReplayMismatch("outer program"));
    }
    if trace.arguments_commitment != bundle.arguments_commitment
        || trace.gas_limit != bundle.gas_limit
    {
        return Err(RefineTraceError::ReplayMismatch("invocation inputs"));
    }
    if trace.host_boundaries != bundle.host_boundaries {
        return Err(RefineTraceError::ReplayMismatch("host boundaries"));
    }
    if trace.result != bundle.result || trace.slices.len() != bundle.slices.len() {
        return Err(RefineTraceError::ReplayMismatch("slice/result shape"));
    }
    for (observed, proven) in trace.slices.iter().zip(&bundle.slices) {
        if observed.order != proven.order
            || observed.identity != proven.identity
            || observed.entry_state != proven.entry_state
            || observed.observed_exit_state != proven.observed_exit_state
            || observed.exit != proven.exit
        {
            return Err(RefineTraceError::ReplayMismatch("machine slice"));
        }
    }
    for (mut observed, proven) in trace.slices.into_iter().zip(&bundle.slices) {
        let mut child = proven.proof.clone();
        let format =
            crate::proof::preflight_proof_structure(&mut child, crate::DEFAULT_MAX_LOG_SIZE)
                .map_err(|_| RefineTraceError::ReplayMismatch("child proof structure"))?;
        let target = crate::prove::Target {
            format,
            config: child.pcs_config,
        };
        let binding = crate::prove::replay_trace_binding(&mut observed.side_note, target)
            .map_err(RefineTraceError::Prove)?;
        if child.component_mask != binding.component_mask
            || child.num_components != binding.log_sizes.len()
            || child.log_sizes != binding.log_sizes
            || child.stark_proof.commitment(0) != Some(binding.preprocessed_commitment)
            || child.stark_proof.commitment(1) != Some(binding.main_commitment)
            || child.initial_state != binding.initial_state
            || child.final_state != binding.final_state
        {
            return Err(RefineTraceError::ReplayMismatch(
                "child proof does not bind exact replay trace",
            ));
        }
        crate::verify(child, &observed.side_note)
            .map_err(|error| RefineTraceError::Verify(error.to_string()))?;
    }
    Ok(())
}
