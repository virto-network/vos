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
pub const REFINE_BUNDLE_FORMAT_VERSION: u32 = 2;
/// Post-decode protocol ceiling for independently proven machine slices.
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
    bytes.extend_from_slice(b"vos/pvm/refine-execution-transcript/v1\0");
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

fn put_refine_host_boundary(bytes: &mut Vec<u8>, boundary: &RefineHostBoundary) {
    bytes.push(boundary.call);
    put_u32(bytes, boundary.slices_before);
    put_u32(bytes, boundary.slices_after);
    bytes.extend_from_slice(&boundary.state_before);
    bytes.extend_from_slice(&boundary.state_after);
    for &register in &boundary.registers_before {
        put_u64(bytes, register);
    }
    for &register in &boundary.registers_after {
        put_u64(bytes, register);
    }
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
    use alloc::sync::Arc;

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

    use crate::SideNote;
    use crate::core::step::PvmStep;
    use crate::core::tracing::{
        compute_skip, decode_branch_target, decode_imm_y, decode_immediate, decode_mem_access,
        decode_reg_indices,
    };

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

    struct ActiveSlice {
        identity: RefineMachineId,
        entry_state: [u8; 32],
        initial_memory: crate::SparseMemoryImage,
        code: Arc<[u8]>,
        bitmask: Arc<[u8]>,
        jump_table: Arc<[u32]>,
        program_location: ProgramLocation,
        initial_regs: [u64; PVM_REGISTER_COUNT],
        last_regs: [u64; PVM_REGISTER_COUNT],
        next_timestamp: u64,
        steps: Vec<PvmStep>,
    }

    #[derive(Clone)]
    struct ProgramStatic {
        code: Arc<[u8]>,
        bitmask: Arc<[u8]>,
        jump_table: Arc<[u32]>,
    }

    #[derive(Clone, Copy)]
    struct CachedInnerProgram {
        id: RefineProgramId,
        allocation: (usize, usize),
    }

    /// Cheap continuity token for interpreter-owned immutable program data.
    /// RefineContext never mutates these vectors after loading; comparing
    /// their allocations and lengths on every observation avoids an
    /// O(instructions × program-size) byte comparison. Executed opcodes and
    /// decoded semantics are still checked against the shared snapshot.
    #[derive(Clone, Copy)]
    struct ProgramLocation {
        code: (usize, usize),
        bitmask: (usize, usize),
        jump_table: (usize, usize),
    }

    impl ProgramLocation {
        fn of(machine: &Interpreter) -> Self {
            Self {
                code: (machine.code.as_ptr() as usize, machine.code.len()),
                bitmask: (machine.bitmask.as_ptr() as usize, machine.bitmask.len()),
                jump_table: (
                    machine.jump_table.as_ptr() as usize,
                    machine.jump_table.len(),
                ),
            }
        }

        fn matches(self, machine: &Interpreter) -> bool {
            self.code == (machine.code.as_ptr() as usize, machine.code.len())
                && self.bitmask == (machine.bitmask.as_ptr() as usize, machine.bitmask.len())
                && self.jump_table
                    == (
                        machine.jump_table.as_ptr() as usize,
                        machine.jump_table.len(),
                    )
        }
    }

    struct MachineStateCache {
        value_revision: u64,
        value_commitment: [u8; 32],
        value_image: crate::SparseMemoryImage,
        permission_revision: u64,
        permission_commitment: [u8; 32],
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
        inner_programs: BTreeMap<InnerMachineIdentity, CachedInnerProgram>,
        program_statics: BTreeMap<RefineProgramId, ProgramStatic>,
        machine_state_cache: BTreeMap<RefineMachineId, MachineStateCache>,
        #[cfg(test)]
        full_value_scans: usize,
        #[cfg(test)]
        full_permission_scans: usize,
        #[cfg(test)]
        static_program_copies: usize,
        #[cfg(test)]
        program_identity_hashes: usize,
        #[cfg(test)]
        static_location_checks: usize,
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
                program_statics: BTreeMap::new(),
                machine_state_cache: BTreeMap::new(),
                #[cfg(test)]
                full_value_scans: 0,
                #[cfg(test)]
                full_permission_scans: 0,
                #[cfg(test)]
                static_program_copies: 0,
                #[cfg(test)]
                program_identity_hashes: 0,
                #[cfg(test)]
                static_location_checks: 0,
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
                let allocation = (view.program.as_ptr() as usize, view.program.len());
                match self.inner_programs.get(&view.identity) {
                    Some(cached) if cached.allocation != allocation => {
                        self.fail("an installed inner program changed allocation or length");
                        return;
                    }
                    Some(_) => {}
                    None => {
                        self.inner_programs.insert(
                            view.identity,
                            CachedInnerProgram {
                                id: refine_program_id(view.program),
                                allocation,
                            },
                        );
                        #[cfg(test)]
                        {
                            self.program_identity_hashes += 1;
                        }
                    }
                }
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
                            program: program.id,
                        }
                    })
                }
            }
        }

        fn program_static(
            &mut self,
            identity: RefineMachineId,
            machine: &Interpreter,
        ) -> ProgramStatic {
            self.program_statics
                .entry(identity.program())
                .or_insert_with(|| {
                    #[cfg(test)]
                    {
                        self.static_program_copies += 1;
                    }
                    ProgramStatic {
                        code: Arc::from(machine.code.as_slice()),
                        bitmask: Arc::from(machine.bitmask.as_slice()),
                        jump_table: Arc::from(machine.jump_table.as_slice()),
                    }
                })
                .clone()
        }

        fn update_machine_cache(&mut self, identity: RefineMachineId, machine: &Interpreter) {
            let memory = machine.memory();
            let value_revision = memory.value_revision();
            let permission_revision = memory.permissions_revision();
            let value_changed = self
                .machine_state_cache
                .get(&identity)
                .is_none_or(|cache| cache.value_revision != value_revision);
            let permissions_changed = self
                .machine_state_cache
                .get(&identity)
                .is_none_or(|cache| cache.permission_revision != permission_revision);

            if value_changed {
                let image: crate::SparseMemoryImage = memory.nonzero_page_image().into();
                let value_commitment = sparse_value_commitment(&image);
                #[cfg(test)]
                {
                    self.full_value_scans += 1;
                }
                match self.machine_state_cache.get_mut(&identity) {
                    Some(cache) => {
                        cache.value_revision = value_revision;
                        cache.value_commitment = value_commitment;
                        cache.value_image = image;
                    }
                    None => {
                        let permission_commitment = permission_commitment(memory.page_perms());
                        #[cfg(test)]
                        {
                            self.full_permission_scans += 1;
                        }
                        self.machine_state_cache.insert(
                            identity,
                            MachineStateCache {
                                value_revision,
                                value_commitment,
                                value_image: image,
                                permission_revision,
                                permission_commitment,
                            },
                        );
                        return;
                    }
                }
            }

            if permissions_changed {
                let commitment = permission_commitment(memory.page_perms());
                #[cfg(test)]
                {
                    self.full_permission_scans += 1;
                }
                let cache = self
                    .machine_state_cache
                    .get_mut(&identity)
                    .expect("value cache is installed above");
                cache.permission_revision = permission_revision;
                cache.permission_commitment = commitment;
            }
        }

        fn machine_state_commitment(
            &mut self,
            identity: RefineMachineId,
            machine: &Interpreter,
        ) -> [u8; 32] {
            self.update_machine_cache(identity, machine);
            let cache = self
                .machine_state_cache
                .get(&identity)
                .expect("machine cache was installed above");
            architectural_state_commitment(
                machine,
                identity.program(),
                cache.value_commitment,
                cache.permission_commitment,
            )
        }

        fn memory_image(
            &mut self,
            identity: RefineMachineId,
            machine: &Interpreter,
        ) -> crate::SparseMemoryImage {
            self.update_machine_cache(identity, machine);
            self.machine_state_cache
                .get(&identity)
                .expect("machine cache was installed above")
                .value_image
                .clone()
        }

        fn context_state_commitment(
            &mut self,
            outer: &Interpreter,
            inner: &vos_pvm::inner::InnerMachines,
        ) -> Option<[u8; 32]> {
            let outer_identity = RefineMachineId::Outer {
                program: self.outer_program,
            };
            let outer_commitment = self.machine_state_commitment(outer_identity, outer);
            let views = inner.views().collect::<Vec<_>>();
            let mut machine_commitments = Vec::with_capacity(views.len());
            for view in &views {
                let program = self.inner_programs.get(&view.identity)?.id;
                let identity = RefineMachineId::Inner {
                    slot: view.identity.slot,
                    generation: view.identity.generation,
                    program,
                };
                let commitment = view
                    .machine
                    .map(|machine| self.machine_state_commitment(identity, machine));
                machine_commitments.push((view.identity, program, view.initial_pc, commitment));
            }

            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"vos/pvm/refine-context-state/v2\0");
            bytes.extend_from_slice(&outer_commitment);
            put_u64(&mut bytes, inner.next_generation());
            put_u32(&mut bytes, machine_commitments.len() as u32);
            for (identity, program, initial_pc, commitment) in machine_commitments {
                put_u32(&mut bytes, identity.slot);
                put_u64(&mut bytes, identity.generation);
                bytes.extend_from_slice(&program.0);
                put_u32(&mut bytes, initial_pc);
                match commitment {
                    Some(commitment) => {
                        bytes.push(1);
                        bytes.extend_from_slice(&commitment);
                    }
                    None => bytes.push(0),
                }
            }
            Some(crate::page_merkle::blake2b256(&bytes))
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
                    let program = self.program_static(bundle_identity, machine);
                    let timestamp = self.timestamps.get(&identity).copied().unwrap_or(1);
                    let entry_state = self.machine_state_commitment(bundle_identity, machine);
                    let initial_memory = self.memory_image(bundle_identity, machine);
                    self.active = Some(ActiveSlice {
                        identity: bundle_identity,
                        entry_state,
                        initial_memory,
                        code: program.code,
                        bitmask: program.bitmask,
                        jump_table: program.jump_table,
                        program_location: ProgramLocation::of(machine),
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
                    #[cfg(test)]
                    {
                        self.static_location_checks += 1;
                    }
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
                    if active.identity != expected
                        || active.steps.is_empty()
                        || !active.program_location.matches(machine)
                    {
                        self.fail("machine exit identity/trace does not match active slice");
                        return;
                    }
                    if self.slices.len() >= MAX_REFINE_PROOF_SLICES {
                        self.fail("Refine machine-slice limit exceeded");
                        return;
                    }
                    self.timestamps.insert(identity, active.next_timestamp);
                    let side_note = SideNote::new_shared(active.steps, active.code, active.bitmask)
                        .with_isa_mode(vos_pvm::IsaMode::Conformance)
                        .with_shared_jump_table(active.jump_table)
                        .with_initial_regs(active.initial_regs)
                        .with_sparse_memory(active.initial_memory);
                    let observed_exit_state =
                        self.machine_state_commitment(active.identity, machine);
                    self.slices.push(RefineTraceSlice {
                        order: self.slices.len() as u32,
                        identity: active.identity,
                        entry_state: active.entry_state,
                        observed_exit_state,
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
                    if self.error.is_some() {
                        return;
                    }
                    let Ok(call) = u8::try_from(id) else {
                        self.fail("host boundary identifier exceeds u8");
                        return;
                    };
                    if !(9..=14).contains(&call) {
                        self.fail("observed non-standard Refine host boundary");
                        return;
                    }
                    let Some(state) = self.context_state_commitment(outer.interpreter(), inner)
                    else {
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

    #[cfg(test)]
    #[derive(Clone, Copy, Debug)]
    pub(super) struct CollectorMetrics {
        pub full_value_scans: usize,
        pub full_permission_scans: usize,
        pub static_program_copies: usize,
        pub program_identity_hashes: usize,
        pub static_location_checks: usize,
    }

    fn run_refine_collector(
        outer_program: &[u8],
        args: &[u8],
        gas: Gas,
    ) -> Result<(Collector, vos_pvm::refine::Invocation), RefineTraceError> {
        let outer_id = refine_program_id(outer_program);
        let context = RefineContext::load_with(outer_program, args, gas, MemoryModel::Sparse)?;
        let mut collector = Collector::new(outer_id);
        let invocation = context.run_observed(|event| collector.observe(event));
        if let Some(error) = collector.error.take() {
            return Err(RefineTraceError::Observation(error));
        }
        if collector.active.is_some() || collector.pending_boundary.is_some() {
            return Err(RefineTraceError::Observation(
                "unterminated machine or host boundary".to_string(),
            ));
        }
        Ok((collector, invocation))
    }

    #[cfg(test)]
    pub(super) fn collector_metrics_for(
        outer_program: &[u8],
        args: &[u8],
        gas: Gas,
    ) -> Result<CollectorMetrics, RefineTraceError> {
        let (collector, _) = run_refine_collector(outer_program, args, gas)?;
        Ok(CollectorMetrics {
            full_value_scans: collector.full_value_scans,
            full_permission_scans: collector.full_permission_scans,
            static_program_copies: collector.static_program_copies,
            program_identity_hashes: collector.program_identity_hashes,
            static_location_checks: collector.static_location_checks,
        })
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
        if refine_arguments_commitment(args) != bundle.arguments_commitment
            || gas != bundle.gas_limit
        {
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
            crate::proof::preflight_proof_structure(&mut child, crate::DEFAULT_MAX_LOG_SIZE)
                .map_err(|_| RefineTraceError::ReplayMismatch("child proof structure"))?;
            let binding =
                crate::prove::replay_trace_binding(&mut observed.side_note, child.pcs_config)
                    .map_err(RefineTraceError::Prove)?;
            let commitments = &child.stark_proof.commitments;
            if child.component_mask != binding.component_mask
                || child.num_components != binding.log_sizes.len()
                || child.log_sizes != binding.log_sizes
                || commitments.first().copied() != Some(binding.preprocessed_commitment)
                || commitments.get(1).copied() != Some(binding.main_commitment)
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

    fn observed_step(
        active: &ActiveSlice,
        observation: &InstructionObservation<'_>,
    ) -> Result<PvmStep, String> {
        let machine = observation.machine_after;
        if !active.program_location.matches(machine)
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

    fn sparse_value_commitment(image: &crate::SparseMemoryImage) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"vos/pvm/refine-memory-values/v1\0");
        put_u64(&mut bytes, image.span());
        put_u32(&mut bytes, image.pages().len() as u32);
        for page in image.pages() {
            put_u32(&mut bytes, page.page_index);
            bytes.extend_from_slice(&page.bytes);
        }
        crate::page_merkle::blake2b256(&bytes)
    }

    fn permission_commitment(permissions: &[u8]) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"vos/pvm/refine-memory-permissions/v1\0");
        put_u64(&mut bytes, permissions.len() as u64);
        bytes.extend_from_slice(permissions);
        crate::page_merkle::blake2b256(&bytes)
    }

    fn architectural_state_commitment(
        machine: &Interpreter,
        program: RefineProgramId,
        value_commitment: [u8; 32],
        permission_commitment: [u8; 32],
    ) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"vos/pvm/refine-machine-state/v2\0");
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
        bytes.extend_from_slice(&value_commitment);
        bytes.extend_from_slice(&permission_commitment);
        crate::page_merkle::blake2b256(&bytes)
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

    #[cfg(test)]
    mod cache_tests {
        use super::*;
        use vos_pvm::interpreter::Memory;

        fn machine() -> Interpreter {
            Interpreter::with_memory(
                vec![50, 0],
                vec![1, 0],
                Vec::new(),
                [0; PVM_REGISTER_COUNT],
                Memory::sparse(vos_pvm::PVM_PAGE_SIZE as u64),
                10_000,
                25,
            )
        }

        #[test]
        fn unchanged_63_machine_1024_boundary_scan_cost_is_revision_bounded() {
            let program = RefineProgramId([7; 32]);
            let mut collector = Collector::new(program);
            let mut machines = (0..63).map(|_| machine()).collect::<Vec<_>>();

            for boundary in 0..1_024 {
                for (slot, machine) in machines.iter().enumerate() {
                    let identity = RefineMachineId::Inner {
                        slot: slot as u32,
                        generation: slot as u64,
                        program,
                    };
                    let commitment = collector.machine_state_commitment(identity, machine);
                    if boundary == 0 {
                        assert_ne!(commitment, [0; 32]);
                    }
                }
            }
            assert_eq!(collector.full_value_scans, 63);
            assert_eq!(collector.full_permission_scans, 63);

            machines[0].memory_mut().write_u8(0, 1).unwrap();
            let identity = RefineMachineId::Inner {
                slot: 0,
                generation: 0,
                program,
            };
            collector.machine_state_commitment(identity, &machines[0]);
            assert_eq!(collector.full_value_scans, 64);
            assert_eq!(collector.full_permission_scans, 63);

            assert!(
                machines[0]
                    .memory_mut()
                    .set_page_range(0, 1, vos_pvm::interpreter::PERM_NONE)
            );
            collector.machine_state_commitment(identity, &machines[0]);
            assert_eq!(collector.full_value_scans, 64);
            assert_eq!(collector.full_permission_scans, 64);
        }

        #[test]
        fn context_commitment_binds_next_generation_with_no_live_slots() {
            let program = RefineProgramId([9; 32]);
            let outer = machine();
            let mut collector = Collector::new(program);
            let empty = vos_pvm::inner::InnerMachines::new();
            let before = collector
                .context_state_commitment(&outer, &empty)
                .expect("empty context commits");

            let mut cycled = vos_pvm::inner::InnerMachines::new();
            let id = cycled
                .create(&[0, 1, 3, 10, 42, 0, 0b0000_0101], 0)
                .expect("valid compact program");
            cycled.expunge(id).expect("live slot expunges");
            assert!(cycled.is_empty());
            assert_eq!(cycled.next_generation(), 1);
            let after = collector
                .context_state_commitment(&outer, &cycled)
                .expect("cycled empty context commits");
            assert_ne!(before, after);
        }
    }
}

#[cfg(feature = "prover")]
pub use prover::{
    RefineObservedRun, RefineTraceBundle, RefineTraceError, RefineTraceSlice, prove_refine,
    refine_trace_execution_commitment, trace_refine, trace_refine_observed,
    trace_refine_with_output, verify_refine_bundle_replayed,
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
        assert!(alloc::sync::Arc::ptr_eq(
            &trace.slices[0].side_note.code,
            &trace.slices[1].side_note.code,
        ));
        assert!(alloc::sync::Arc::ptr_eq(
            &trace.slices[1].side_note.code,
            &trace.slices[3].side_note.code,
        ));

        let metrics = prover::collector_metrics_for(&outer, &arguments, gas).unwrap();
        assert_eq!(metrics.static_program_copies, 2);
        assert_eq!(metrics.program_identity_hashes, 1);
        assert_eq!(
            metrics.static_location_checks,
            trace
                .slices
                .iter()
                .map(|slice| slice.side_note.steps.len())
                .sum::<usize>()
        );
        // Outer memory is scanned once; the inner is scanned at entry and
        // once more after its invocation mutates the invoke frame.
        assert_eq!(metrics.full_value_scans, 3);
        assert_eq!(metrics.full_permission_scans, 2);
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
    fn observed_trace_returns_the_exact_same_run_output() {
        const RW_BASE: u32 = 2 * vos_pvm::PVM_ZONE_SIZE;
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        // a0 <- RW_BASE, a1 <- 3, a2..a5 <- 1..=4, halt.
        let code = [
            51, 7, b0, b1, b2, 51, 8, 3, 0, 0, 51, 9, 1, 0, 0, 51, 10, 2, 0, 0, 51, 11, 3, 0, 0,
            51, 12, 4, 0, 0, 50, 0,
        ];
        let outer = standard_program_with_rw(&code, &[0, 5, 10, 15, 20, 25, 30], b"out");

        let observed = trace_refine_observed(&outer, b"args", 1_000_000, 3).unwrap();
        let mut expected_public_io = [0u8; 32];
        for (index, word) in [1u64, 2, 3, 4].iter().enumerate() {
            expected_public_io[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(observed.trace.result, RefineSliceExit::Halt);
        assert_eq!(observed.output, b"out");
        assert_eq!(observed.public_io, expected_public_io);
        assert!(matches!(
            trace_refine_observed(&outer, b"args", 1_000_000, 2),
            Err(RefineTraceError::OutputUnavailable)
        ));

        let (trace, output) = trace_refine_with_output(&outer, b"args", 1_000_000, 3).unwrap();

        assert_eq!(trace.result, RefineSliceExit::Halt);
        assert_eq!(output.as_deref(), Some(b"out".as_slice()));
        assert_ne!(refine_trace_execution_commitment(&trace), [0; 32]);

        let (bounded_trace, bounded_output) =
            trace_refine_with_output(&outer, b"args", 1_000_000, 2).unwrap();
        assert_eq!(bounded_output, None);
        assert_eq!(
            refine_trace_execution_commitment(&bounded_trace),
            refine_trace_execution_commitment(&trace),
            "the allocation ceiling must not change the observed execution",
        );
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
    fn proof_generation_numbers_reject_previous_formats() {
        #[cfg(not(feature = "poseidon2-channel"))]
        assert_eq!(crate::PROOF_FORMAT_VERSION, 20);
        #[cfg(feature = "poseidon2-channel")]
        assert_eq!(crate::PROOF_FORMAT_VERSION, 21);
        for previous in 16..=19 {
            assert_ne!(crate::PROOF_FORMAT_VERSION, previous);
        }
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
