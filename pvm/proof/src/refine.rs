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

/// Wire shape of the boundary bundle itself.
pub const REFINE_BUNDLE_FORMAT_VERSION: u32 = 1;
/// Post-decode protocol ceiling for independently proven machine slices.
pub const MAX_REFINE_PROOF_SLICES: usize = 1_024;
/// A handled outer host call can contribute at most one boundary per slice.
pub const MAX_REFINE_HOST_BOUNDARIES: usize = MAX_REFINE_PROOF_SLICES;
/// The component mask is `u32`, so no proof shape can name more components.
pub const MAX_REFINE_CHILD_COMPONENTS: usize = u32::BITS as usize;
/// Stwo's canonical tree count: preprocessed, main, interaction, composition.
pub const REFINE_CHILD_COMMITMENT_COUNT: usize = 4;

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
    Trap,
    Ecall,
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
/// The derived Serde representation is an in-memory interchange shape, not a
/// bounded wire decoder. A transport MUST reject serialized input above its
/// configured aggregate proof-byte ceiling before deserializing this type.
/// [`refine_bundle_cardinality_is_valid`] is a second, post-decode shape check;
/// it cannot prevent allocations already requested by a Serde decoder.
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
    !bundle.slices.is_empty()
        && bundle.slices.len() <= MAX_REFINE_PROOF_SLICES
        && bundle.host_boundaries.len() <= MAX_REFINE_HOST_BOUNDARIES
        && bundle.host_boundaries.len() <= bundle.slices.len()
        && bundle.slices.iter().all(|slice| {
            slice.proof.log_sizes.len() <= MAX_REFINE_CHILD_COMPONENTS
                && slice.proof.claimed_sums.len() <= MAX_REFINE_CHILD_COMPONENTS
                && slice.proof.num_components <= MAX_REFINE_CHILD_COMPONENTS
                && slice.proof.stark_proof.commitments.len() == REFINE_CHILD_COMMITMENT_COUNT
        })
}

/// Recompute the canonical transcript commitment.
pub fn refine_bundle_commitment(bundle: &RefineProofBundle) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"vos/pvm/refine-proof-bundle/v1\0");
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
        put_u32(&mut bytes, proof.log_sizes.len() as u32);
        for &size in &proof.log_sizes {
            put_u32(&mut bytes, size);
        }
        put_u32(&mut bytes, proof.pcs_config.pow_bits);
        put_u32(&mut bytes, proof.pcs_config.fri_config.log_blowup_factor);
        put_u32(
            &mut bytes,
            proof.pcs_config.fri_config.log_last_layer_degree_bound,
        );
        put_u64(&mut bytes, proof.pcs_config.fri_config.n_queries as u64);
        put_u32(&mut bytes, proof.pcs_config.fri_config.fold_step);
        put_u32(
            &mut bytes,
            proof.pcs_config.lifting_log_size.unwrap_or(u32::MAX),
        );
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

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_machine_id(bytes: &mut Vec<u8>, identity: RefineMachineId) {
    match identity {
        RefineMachineId::Outer { program } => {
            bytes.push(0);
            bytes.extend_from_slice(&program.0);
        }
        RefineMachineId::Inner {
            slot,
            generation,
            program,
        } => {
            bytes.push(1);
            put_u32(bytes, slot);
            put_u64(bytes, generation);
            bytes.extend_from_slice(&program.0);
        }
    }
}

fn put_exit(bytes: &mut Vec<u8>, exit: RefineSliceExit) {
    match exit {
        RefineSliceExit::Halt => bytes.push(0),
        RefineSliceExit::Panic => bytes.push(1),
        RefineSliceExit::Trap => bytes.push(2),
        RefineSliceExit::Ecall => bytes.push(3),
        RefineSliceExit::OutOfGas => bytes.push(4),
        RefineSliceExit::PageFault(address) => {
            bytes.push(5);
            put_u32(bytes, address);
        }
        RefineSliceExit::HostCall(call) => {
            bytes.push(6);
            put_u64(bytes, call);
        }
    }
}

fn put_segment_state(bytes: &mut Vec<u8>, state: &crate::SegmentState) {
    put_u32(bytes, state.pc);
    put_u64(bytes, state.timestamp);
    for &register in &state.registers {
        put_u64(bytes, register);
    }
    bytes.extend_from_slice(&state.memory_commitment);
    bytes.extend_from_slice(&state.memory_root);
}

#[cfg(not(feature = "poseidon2-channel"))]
fn commitment_bytes(commitment: &crate::recursion_pcs::ProverMerkleHash) -> [u8; 32] {
    commitment.0
}

#[cfg(feature = "poseidon2-channel")]
fn commitment_bytes(commitment: &crate::recursion_pcs::ProverMerkleHash) -> [u8; 32] {
    commitment.to_bytes()
}

#[cfg(feature = "prover")]
mod prover {
    use alloc::collections::BTreeMap;
    use alloc::string::{String, ToString};

    use stwo::prover::ProvingError;
    use vos_pvm::args;
    use vos_pvm::inner::InnerMachineIdentity;
    use vos_pvm::instruction::Opcode;
    use vos_pvm::interpreter::{InstructionObservation, Interpreter};
    use vos_pvm::refine::MemoryModel;
    use vos_pvm::refine_host::{
        RefineContext, RefineHostPhase, RefineMachineIdentity, RefineObservation,
    };
    use vos_pvm::{ExitReason, Gas, PVM_REGISTER_COUNT};

    use crate::core::step::PvmStep;
    use crate::core::tracing::{
        compute_skip, decode_branch_target, decode_imm_y, decode_immediate, decode_mem_access,
        decode_reg_indices,
    };
    use crate::{SideNote, prepare_side_note_for_verification};

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

    #[derive(Debug)]
    pub enum RefineTraceError {
        Load(vos_pvm::refine::RefineError),
        Observation(String),
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

    struct ActiveSlice {
        identity: RefineMachineId,
        entry_state: [u8; 32],
        initial_memory: crate::SparseMemoryImage,
        code: Vec<u8>,
        bitmask: Vec<u8>,
        jump_table: Vec<u32>,
        initial_regs: [u64; PVM_REGISTER_COUNT],
        last_regs: [u64; PVM_REGISTER_COUNT],
        next_timestamp: u64,
        steps: Vec<PvmStep>,
    }

    struct PendingBoundary {
        call: u8,
        slices_before: u32,
        state_before: [u8; 32],
        registers_before: [u64; 13],
    }

    struct Collector {
        outer_program: RefineProgramId,
        active: Option<ActiveSlice>,
        slices: Vec<RefineTraceSlice>,
        boundaries: Vec<RefineHostBoundary>,
        pending_boundary: Option<PendingBoundary>,
        timestamps: BTreeMap<RefineMachineIdentity, u64>,
        inner_programs: BTreeMap<InnerMachineIdentity, RefineProgramId>,
        error: Option<String>,
    }

    impl Collector {
        fn new(outer_program: RefineProgramId) -> Self {
            Self {
                outer_program,
                active: None,
                slices: Vec::new(),
                boundaries: Vec::new(),
                pending_boundary: None,
                timestamps: BTreeMap::new(),
                inner_programs: BTreeMap::new(),
                error: None,
            }
        }

        fn fail(&mut self, message: impl Into<String>) {
            if self.error.is_none() {
                self.error = Some(message.into());
            }
        }

        fn update_programs(&mut self, inner: &vos_pvm::inner::InnerMachines) {
            for view in inner.views() {
                self.inner_programs
                    .entry(view.identity)
                    .or_insert_with(|| refine_program_id(view.program));
            }
        }

        fn machine_id(&self, identity: RefineMachineIdentity) -> Option<RefineMachineId> {
            match identity {
                RefineMachineIdentity::Outer => Some(RefineMachineId::Outer {
                    program: self.outer_program,
                }),
                RefineMachineIdentity::Inner(identity) => {
                    self.inner_programs.get(&identity).copied().map(|program| {
                        RefineMachineId::Inner {
                            slot: identity.slot,
                            generation: identity.generation,
                            program,
                        }
                    })
                }
            }
        }

        fn observe(&mut self, event: RefineObservation<'_>) {
            if self.error.is_some() {
                return;
            }
            match event {
                RefineObservation::MachineEnter { identity, machine } => {
                    if self.active.is_some() {
                        self.fail("machine entered while another slice is active");
                        return;
                    }
                    if !machine.memory().is_sparse() {
                        self.fail("Refine proof tracing requires sparse memory");
                        return;
                    }
                    let Some(bundle_identity) = self.machine_id(identity) else {
                        self.fail("inner machine entered without an installed program identity");
                        return;
                    };
                    let timestamp = self.timestamps.get(&identity).copied().unwrap_or(1);
                    self.active = Some(ActiveSlice {
                        identity: bundle_identity,
                        entry_state: machine_state_commitment(machine, bundle_identity.program()),
                        initial_memory: machine.memory().nonzero_page_image().into(),
                        code: machine.code.clone(),
                        bitmask: machine.bitmask.clone(),
                        jump_table: machine.jump_table.clone(),
                        initial_regs: machine.registers,
                        last_regs: machine.registers,
                        next_timestamp: timestamp,
                        steps: Vec::new(),
                    });
                }
                RefineObservation::Instruction {
                    identity,
                    instruction,
                } => {
                    let Some(expected) = self.machine_id(identity) else {
                        self.fail("instruction has no machine program identity");
                        return;
                    };
                    let Some(active) = self.active.as_mut() else {
                        self.fail("instruction observed outside a machine slice");
                        return;
                    };
                    if active.identity != expected {
                        self.fail("instruction machine identity differs from active slice");
                        return;
                    }
                    match observed_step(active, &instruction) {
                        Ok(step) => {
                            active.last_regs = step.regs_after;
                            active.next_timestamp += 1;
                            active.steps.push(step);
                        }
                        Err(error) => self.fail(error),
                    }
                }
                RefineObservation::MachineExit {
                    identity,
                    exit,
                    machine,
                } => {
                    let Some(expected) = self.machine_id(identity) else {
                        self.fail("machine exit has no program identity");
                        return;
                    };
                    let Some(active) = self.active.take() else {
                        self.fail("machine exited without an active slice");
                        return;
                    };
                    if active.identity != expected || active.steps.is_empty() {
                        self.fail("machine exit identity/trace does not match active slice");
                        return;
                    }
                    if self.slices.len() >= MAX_REFINE_PROOF_SLICES {
                        self.fail("Refine machine-slice limit exceeded");
                        return;
                    }
                    self.timestamps.insert(identity, active.next_timestamp);
                    let side_note = SideNote::new(active.steps, active.code, active.bitmask)
                        .with_isa_mode(vos_pvm::IsaMode::Conformance)
                        .with_jump_table(active.jump_table)
                        .with_initial_regs(active.initial_regs)
                        .with_sparse_memory(active.initial_memory);
                    self.slices.push(RefineTraceSlice {
                        order: self.slices.len() as u32,
                        identity: active.identity,
                        entry_state: active.entry_state,
                        observed_exit_state: machine_state_commitment(
                            machine,
                            active.identity.program(),
                        ),
                        exit: exit_kind(&exit),
                        side_note,
                    });
                }
                RefineObservation::HostCall {
                    phase,
                    id,
                    outer,
                    inner,
                } => {
                    self.update_programs(inner);
                    let Ok(call) = u8::try_from(id) else {
                        self.fail("host boundary identifier exceeds u8");
                        return;
                    };
                    if !(9..=14).contains(&call) {
                        self.fail("observed non-standard Refine host boundary");
                        return;
                    }
                    let Some(state) = context_state_commitment(
                        outer.interpreter(),
                        self.outer_program,
                        inner,
                        &self.inner_programs,
                    ) else {
                        self.fail("inner dictionary has no cached program identity");
                        return;
                    };
                    match phase {
                        RefineHostPhase::Before => {
                            if self.boundaries.len() >= MAX_REFINE_HOST_BOUNDARIES {
                                self.fail("Refine host-boundary limit exceeded");
                                return;
                            }
                            if self.pending_boundary.is_some() {
                                self.fail("nested Before host boundary");
                                return;
                            }
                            self.pending_boundary = Some(PendingBoundary {
                                call,
                                slices_before: self.slices.len() as u32,
                                state_before: state,
                                registers_before: *outer.registers(),
                            });
                        }
                        RefineHostPhase::After => {
                            let Some(before) = self.pending_boundary.take() else {
                                self.fail("After host boundary without Before");
                                return;
                            };
                            if before.call != call {
                                self.fail("host Before/After identifiers differ");
                                return;
                            }
                            self.boundaries.push(RefineHostBoundary {
                                call,
                                slices_before: before.slices_before,
                                slices_after: self.slices.len() as u32,
                                state_before: before.state_before,
                                state_after: state,
                                registers_before: before.registers_before,
                                registers_after: *outer.registers(),
                            });
                        }
                    }
                }
            }
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
        let context = RefineContext::load_with(outer_program, args, gas, MemoryModel::Sparse)?;
        let mut collector = Collector::new(outer_id);
        let invocation = context.run_observed(|event| collector.observe(event));
        if let Some(error) = collector.error {
            return Err(RefineTraceError::Observation(error));
        }
        if collector.active.is_some() || collector.pending_boundary.is_some() {
            return Err(RefineTraceError::Observation(
                "unterminated machine or host boundary".to_string(),
            ));
        }
        Ok(RefineTraceBundle {
            outer_program: outer_id,
            arguments_commitment: refine_arguments_commitment(args),
            gas_limit: gas,
            slices: collector.slices,
            host_boundaries: collector.boundaries,
            result: exit_kind(&invocation.exit),
        })
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
        for mut slice in trace.slices {
            let proof = crate::prove(&mut slice.side_note).map_err(RefineTraceError::Prove)?;
            if proof.log_sizes.len() > MAX_REFINE_CHILD_COMPONENTS
                || proof.claimed_sums.len() > MAX_REFINE_CHILD_COMPONENTS
                || proof.num_components > MAX_REFINE_CHILD_COMPONENTS
                || proof.stark_proof.commitments.len() != REFINE_CHILD_COMMITMENT_COUNT
            {
                return Err(RefineTraceError::Observation(format!(
                    "Refine child proof cardinality is noncanonical: logs={}, sums={}, components={}, commitments={}",
                    proof.log_sizes.len(),
                    proof.claimed_sums.len(),
                    proof.num_components,
                    proof.stark_proof.commitments.len(),
                )));
            }
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
        if refine_arguments_commitment(args) != bundle.arguments_commitment
            || gas != bundle.gas_limit
        {
            return Err(RefineTraceError::ReplayMismatch("arguments/gas"));
        }
        if refine_bundle_commitment(bundle) != bundle.transcript_commitment {
            return Err(RefineTraceError::ReplayMismatch("transcript commitment"));
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
            prepare_side_note_for_verification(&mut observed.side_note);
            crate::verify(proven.proof.clone(), &observed.side_note)
                .map_err(|error| RefineTraceError::Verify(error.to_string()))?;
        }
        Ok(())
    }

    fn observed_step(
        active: &ActiveSlice,
        observation: &InstructionObservation<'_>,
    ) -> Result<PvmStep, String> {
        let machine = observation.machine_after;
        if machine.code != active.code
            || machine.bitmask != active.bitmask
            || machine.jump_table != active.jump_table
            || observation.registers_before != active.last_regs
            || machine.isa_mode() != vos_pvm::IsaMode::Conformance
        {
            return Err(
                "instruction observation changed static program/profile or continuity".to_string(),
            );
        }
        let opcode_byte = active
            .code
            .get(observation.pc_before as usize)
            .copied()
            .unwrap_or(0);
        if opcode_byte != observation.opcode_byte {
            return Err("instruction observation opcode differs from program".to_string());
        }
        let opcode = Opcode::from_byte_in_mode(opcode_byte, vos_pvm::IsaMode::Conformance)
            .unwrap_or(Opcode::Trap);
        let skip_len = compute_skip(&active.bitmask, observation.pc_before as usize);
        let decoded = args::decode_args(
            &active.code,
            observation.pc_before as usize,
            skip_len as usize,
            opcode.category(),
        );
        let (reg_a, reg_b, reg_d) = decode_reg_indices(opcode, &decoded);
        let regs_after = machine.registers;
        let changed: Vec<usize> = (0..PVM_REGISTER_COUNT)
            .filter(|&index| observation.registers_before[index] != regs_after[index])
            .collect();
        if changed.len() > 1 {
            return Err("one instruction changed more than one register".to_string());
        }
        let gas_charged = if observation.need_gas_charge_before {
            observation
                .gas_before
                .checked_sub(machine.gas)
                .ok_or_else(|| "instruction increased gas".to_string())?
        } else {
            0
        };
        let sequential_next_pc = observation.pc_before.wrapping_add(1).wrapping_add(skip_len);
        let exited = observation.exit.is_some();
        let (mem_read, mem_write) = if exited {
            (None, None)
        } else {
            decode_mem_access(opcode, &decoded, &observation.registers_before, &regs_after)
        };
        Ok(PvmStep {
            timestamp: active.next_timestamp,
            pc: observation.pc_before,
            opcode,
            skip_len,
            regs_before: observation.registers_before,
            regs_after,
            reg_write: changed.first().copied(),
            reg_a,
            reg_b,
            reg_d,
            imm: decode_immediate(&decoded),
            imm_y: decode_imm_y(&decoded),
            branch_target: decode_branch_target(&decoded),
            branch_taken: !exited && machine.pc != sequential_next_pc,
            mem_read,
            mem_write,
            gas_after: machine.gas,
            gas_charged,
            next_pc: machine.pc,
            host_call_acknowledged: false,
            exit: exited,
        })
    }

    fn machine_state_commitment(machine: &Interpreter, program: RefineProgramId) -> [u8; 32] {
        let image = machine.memory().nonzero_page_image();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"vos/pvm/refine-machine-state/v1\0");
        // Collector hashes each exact canonical program blob once per
        // installed identity. The ID transitively binds decoded code,
        // bitmask, and jump table without re-hashing MiB-scale static bytes at
        // every native host boundary.
        bytes.extend_from_slice(&program.0);
        bytes.push(match machine.isa_mode() {
            vos_pvm::IsaMode::Conformance => 0,
            vos_pvm::IsaMode::Jar => 1,
        });
        bytes.push(match machine.gas_model() {
            vos_pvm::GasModel::BlockPipeline => 0,
            vos_pvm::GasModel::PerInstruction => 1,
        });
        put_u32(&mut bytes, machine.pc);
        put_u64(&mut bytes, machine.gas);
        for &register in &machine.registers {
            put_u64(&mut bytes, register);
        }
        put_u32(&mut bytes, machine.heap_base);
        put_u32(&mut bytes, machine.heap_top);
        put_u32(&mut bytes, machine.max_heap_pages);
        bytes.push(machine.mem_cycles);
        bytes.push(machine.gas_charged as u8);
        bytes.push(machine.need_gas_charge as u8);
        match machine.pending_host_call() {
            Some(call) => {
                bytes.push(1);
                put_u64(&mut bytes, call.id);
                put_u32(&mut bytes, call.cause_pc);
                put_u32(&mut bytes, call.resume_pc);
            }
            None => bytes.push(0),
        }
        put_u64(&mut bytes, image.span());
        put_u32(&mut bytes, image.pages().len() as u32);
        for page in image.pages() {
            put_u32(&mut bytes, page.page_index);
            bytes.extend_from_slice(&page.bytes);
        }
        put_u64(&mut bytes, machine.memory().page_perms().len() as u64);
        bytes.extend_from_slice(machine.memory().page_perms());
        crate::page_merkle::blake2b256(&bytes)
    }

    fn context_state_commitment(
        outer: &Interpreter,
        outer_program: RefineProgramId,
        inner: &vos_pvm::inner::InnerMachines,
        inner_programs: &BTreeMap<InnerMachineIdentity, RefineProgramId>,
    ) -> Option<[u8; 32]> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"vos/pvm/refine-context-state/v1\0");
        bytes.extend_from_slice(&machine_state_commitment(outer, outer_program));
        put_u32(&mut bytes, inner.len() as u32);
        for view in inner.views() {
            let program = inner_programs.get(&view.identity)?;
            put_u32(&mut bytes, view.identity.slot);
            put_u64(&mut bytes, view.identity.generation);
            bytes.extend_from_slice(&program.0);
            put_u32(&mut bytes, view.initial_pc);
            match view.machine {
                Some(machine) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&machine_state_commitment(machine, *program));
                }
                None => bytes.push(0),
            }
        }
        Some(crate::page_merkle::blake2b256(&bytes))
    }

    fn exit_kind(exit: &ExitReason) -> RefineSliceExit {
        match exit {
            ExitReason::Halt => RefineSliceExit::Halt,
            ExitReason::Panic => RefineSliceExit::Panic,
            ExitReason::Trap => RefineSliceExit::Trap,
            ExitReason::Ecall => RefineSliceExit::Ecall,
            ExitReason::OutOfGas => RefineSliceExit::OutOfGas,
            ExitReason::PageFault(address) => RefineSliceExit::PageFault(*address),
            ExitReason::HostCall(call) => RefineSliceExit::HostCall(*call),
        }
    }
}

#[cfg(feature = "prover")]
pub use prover::{
    RefineTraceBundle, RefineTraceError, RefineTraceSlice, prove_refine, trace_refine,
    verify_refine_bundle_replayed,
};

#[cfg(all(test, feature = "prover"))]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn standard_program_with_rw(code: &[u8], starts: &[usize], rw_data: &[u8]) -> Vec<u8> {
        let mut packed = vec![0u8; code.len().div_ceil(8)];
        for &index in starts {
            packed[index / 8] |= 1 << (index % 8);
        }
        let mut code_blob = vec![0, 1, code.len() as u8];
        code_blob.extend_from_slice(code);
        code_blob.extend_from_slice(&packed);

        let mut blob = Vec::new();
        blob.extend_from_slice(&[0; 3]);
        blob.extend_from_slice(&(rw_data.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&4096u32.to_le_bytes()[..3]);
        blob.extend_from_slice(rw_data);
        blob.extend_from_slice(&(code_blob.len() as u32).to_le_bytes());
        blob.extend_from_slice(&code_blob);
        blob
    }

    fn inner_program() -> Vec<u8> {
        // host(42), then trap.
        vec![0, 1, 3, 10, 42, 0, 0b0000_0101]
    }

    fn nested_fixture() -> (Vec<u8>, Vec<u8>, u64) {
        const RW_BASE: u32 = 2 * vos_pvm::PVM_ZONE_SIZE;
        let mut frame = [0u8; 112];
        frame[..8].copy_from_slice(&100_000u64.to_le_bytes());
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        // machine(args), r8 <- RW_BASE, invoke(machine 0, frame), halt.
        let code = [10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0];
        (
            standard_program_with_rw(&code, &[0, 2, 7, 9], &frame),
            inner_program(),
            1_000_000,
        )
    }

    #[test]
    fn direct_observation_builds_canonical_nested_sparse_slices() {
        let (outer, arguments, gas) = nested_fixture();
        let trace = trace_refine(&outer, &arguments, gas).expect("trace nested Refine");

        assert_eq!(trace.outer_program, refine_program_id(&outer));
        assert_eq!(
            trace.arguments_commitment,
            refine_arguments_commitment(&arguments)
        );
        assert_eq!(trace.gas_limit, gas);
        assert_eq!(trace.slices.len(), 4);
        assert_eq!(trace.host_boundaries.len(), 2);
        assert_eq!(
            trace
                .slices
                .iter()
                .map(|slice| slice.order)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert!(matches!(
            trace.slices[0].identity,
            RefineMachineId::Outer { program } if program == refine_program_id(&outer)
        ));
        assert!(matches!(
            trace.slices[2].identity,
            RefineMachineId::Inner { slot: 0, generation: 0, program }
                if program == refine_program_id(&arguments)
        ));
        assert_eq!(
            trace
                .host_boundaries
                .iter()
                .map(|boundary| (boundary.call, boundary.slices_before, boundary.slices_after))
                .collect::<Vec<_>>(),
            [(9, 1, 1), (13, 2, 3)]
        );
        assert_ne!(
            trace.host_boundaries[1].state_before,
            trace.host_boundaries[1].state_after
        );
        assert_ne!(
            trace.host_boundaries[1].registers_before,
            trace.host_boundaries[1].registers_after
        );

        for slice in &trace.slices {
            assert!(slice.side_note.initial_memory.is_empty());
            let image = slice
                .side_note
                .sparse_initial_memory
                .as_ref()
                .expect("Refine slices use sparse memory");
            // The standard layout reserves guard space near the top of the
            // 32-bit address space, so its mapped span is just under 4 GiB.
            // What matters here is that the witness stays page-sparse rather
            // than materialising that multi-GiB logical image.
            assert!(image.span() > 4_000_000_000);
            assert!(image.pages().len() < 16);
        }
        assert_eq!(trace.slices[0].side_note.steps[0].timestamp, 1);
        assert_eq!(trace.slices[1].side_note.steps[0].timestamp, 2);
        assert_eq!(trace.slices[2].side_note.steps[0].timestamp, 1);
        assert_eq!(trace.slices[3].side_note.steps[0].timestamp, 4);
    }

    #[test]
    fn input_identity_binds_exact_bytes_and_gas() {
        let (outer, arguments, gas) = nested_fixture();
        let trace = trace_refine(&outer, &arguments, gas).unwrap();
        let mut changed = arguments.clone();
        changed[4] ^= 1;
        assert_ne!(
            trace.arguments_commitment,
            refine_arguments_commitment(&changed)
        );
        assert_ne!(trace.outer_program, refine_program_id(&arguments));
        assert_ne!(gas, gas + 1);
    }

    #[test]
    fn observation_records_every_standard_host_boundary() {
        const RW_BASE: u32 = 2 * vos_pvm::PVM_ZONE_SIZE;
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        // Calls 9..12 can safely report errors from their zero/unknown inputs.
        // Point INVOKE at a writable frame, then call 13 and 14 and halt.
        let code = [
            10, 9, 10, 10, 10, 11, 10, 12, 51, 8, b0, b1, b2, 10, 13, 10, 14, 50, 0,
        ];
        let outer = standard_program_with_rw(&code, &[0, 2, 4, 6, 8, 13, 15, 17], &[0; 112]);
        let trace = trace_refine(&outer, &[], 1_000_000).unwrap();

        assert_eq!(
            trace
                .host_boundaries
                .iter()
                .map(|boundary| boundary.call)
                .collect::<Vec<_>>(),
            [9, 10, 11, 12, 13, 14]
        );
        assert_eq!(trace.slices.len(), 7);
        for (index, boundary) in trace.host_boundaries.iter().enumerate() {
            assert_eq!(boundary.slices_before, index as u32 + 1);
            assert_eq!(boundary.slices_after, boundary.slices_before);
        }
        assert_eq!(trace.result, RefineSliceExit::Halt);
    }

    #[test]
    fn prove_preflights_slice_cardinality_without_proving() {
        let identity = RefineMachineId::Outer {
            program: RefineProgramId([0; 32]),
        };
        let slices = (0..=MAX_REFINE_PROOF_SLICES)
            .map(|order| RefineTraceSlice {
                order: order as u32,
                identity,
                entry_state: [0; 32],
                observed_exit_state: [0; 32],
                exit: RefineSliceExit::Halt,
                side_note: crate::SideNote::new(Vec::new(), Vec::new(), Vec::new()),
            })
            .collect();
        let trace = RefineTraceBundle {
            outer_program: identity.program(),
            arguments_commitment: [0; 32],
            gas_limit: 0,
            slices,
            host_boundaries: Vec::new(),
            result: RefineSliceExit::Halt,
        };
        assert!(matches!(
            prove_refine(trace),
            Err(RefineTraceError::Observation(message))
                if message.contains("cardinality")
        ));
    }

    #[test]
    fn proof_generation_numbers_reject_both_previous_formats() {
        #[cfg(not(feature = "poseidon2-channel"))]
        assert_eq!(crate::PROOF_FORMAT_VERSION, 18);
        #[cfg(feature = "poseidon2-channel")]
        assert_eq!(crate::PROOF_FORMAT_VERSION, 19);
        assert_ne!(crate::PROOF_FORMAT_VERSION, 16);
        assert_ne!(crate::PROOF_FORMAT_VERSION, 17);
    }

    #[test]
    fn transcript_integers_have_one_canonical_little_endian_encoding() {
        let mut encoded = Vec::new();
        put_u32(&mut encoded, 0x7856_3412);
        put_u64(&mut encoded, 0xf0de_bc9a_7856_3412);
        assert_eq!(
            encoded,
            [
                0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            ]
        );
    }
}
