//! Stable actor-execution contract of an agent runtime.
//!
//! The node supplies authenticated work and exact content-addressed program
//! availability. The runtime owns actor lookup, lane selection, inner-machine
//! host calls, and the next opaque runtime state.

use alloc::vec::Vec;

use super::{MethodMode, StateLane};
use crate::service::wire::Encoder;
#[cfg(feature = "pvm")]
use crate::service::wire::ServiceWire;
use crate::service::{
    ActorId, BlobRef, CapabilityId, DeploymentId, Hash, InvocationId, Origin, PrincipalId,
    ProgramId, ServiceIdentity,
};

/// Maximum dynamic request passed to an application actor. This matches the
/// actor lifecycle's ordinary transfer window and leaves room in the compact
/// guest heap for decoded arguments and state.
pub const MAX_EXECUTION_MESSAGE_BYTES: usize = 8 * 1024;
/// Maximum typed reply retained by the runtime.
pub const MAX_EXECUTION_REPLY_BYTES: usize = 8 * 1024;
/// Maximum encoded size of one lane. The stricter aggregate bound below is
/// what makes a three-lane invocation fit the application actor's 256-KiB
/// heap while input, decoded fields, and output coexist.
pub const MAX_EXECUTION_STATE_BYTES: usize = 48 * 1024;
/// Maximum sum of the linear, merge, and local lane images visible to one
/// invocation.
pub const MAX_EXECUTION_STATE_TOTAL_BYTES: usize = 48 * 1024;
/// Maximum aggregate content-addressed availability supplied to one call.
pub const MAX_EXECUTION_AVAILABILITY_BYTES: usize = 48 * 1024;
/// Maximum application PVM accepted by the bundled runtime. Parsing a PVM
/// materializes its data, code, bitmask, and compact-code form concurrently,
/// so this is intentionally much smaller than a generic service wire.
pub const MAX_EXECUTION_PROGRAM_BYTES: usize = 1280 * 1024;
/// Maximum instruction gas which an untrusted caller may assign to one actor
/// invocation. The host adds its separately configured runtime-management
/// budget around this value; actor-selected gas itself is never unbounded.
pub const MAX_EXECUTION_GAS: u64 = 1_000_000_000;
/// Maximum canonical signed method-policy artifact supplied to one call.
/// This is separate from actor availability because it is deployment
/// provenance, not caller-selected input.
pub const MAX_EXECUTION_POLICY_BYTES: usize = 64 * 1024;
/// Maximum opaque runtime image accepted by the bundled 32-MiB agent-runtime
/// guest. The runtime contract signs this ceiling and the wire decoder
/// enforces it before allocation.
/// Execution temporarily owns the decoded image, its runtime representation,
/// a snapshot, and the encoded successor in addition to the actor PVM.
pub const MAX_RUNTIME_STATE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EXECUTION_BLOBS: usize = 4;
#[cfg(feature = "pvm")]
const ACTOR_DISPATCH_CONTROL_CAPACITY: usize = 512;
const MAX_EXECUTION_HOST_CALLS: usize = 4 * 1024;
const MAX_EXECUTION_FETCH_CALLS: usize = 16;
const MAX_EXECUTION_FETCH_BYTES: usize = 64 * 1024;
const MAX_EXECUTION_BLAKE2B_COMPRESS_CALLS: usize = 1024;
const MAX_EXECUTION_DEBUG_BYTES: usize = 16 * 1024;

#[cfg(feature = "pvm")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ActorStateLanes {
    pub linear: Option<Vec<u8>>,
    pub merge: Option<Vec<u8>>,
    pub local: Option<Vec<u8>>,
}

#[cfg(feature = "pvm")]
impl ActorStateLanes {
    pub fn get(&self, lane: StateLane) -> Option<&[u8]> {
        match lane {
            StateLane::Linear => self.linear.as_deref(),
            StateLane::Merge => self.merge.as_deref(),
            StateLane::Local => self.local.as_deref(),
        }
    }

    pub fn take(&mut self, lane: StateLane) -> Option<Vec<u8>> {
        match lane {
            StateLane::Linear => self.linear.take(),
            StateLane::Merge => self.merge.take(),
            StateLane::Local => self.local.take(),
        }
    }

    pub fn encoded_len(&self) -> Option<usize> {
        execution_state_size([
            self.linear.as_deref(),
            self.merge.as_deref(),
            self.local.as_deref(),
        ])
    }

    /// Build the only lane image an actor running in `mode` is allowed to
    /// observe. The complete preimage stays inside the outer runtime so a
    /// hand-written actor PVM cannot learn a hidden lane merely by ignoring
    /// the generated Rust lane views.
    pub fn visible_for(&self, mode: super::MethodMode) -> Self {
        let visible =
            |lane, value: &Option<Vec<u8>>| mode.can_read(lane).then(|| value.clone()).flatten();
        Self {
            linear: visible(StateLane::Linear, &self.linear),
            merge: visible(StateLane::Merge, &self.merge),
            local: visible(StateLane::Local, &self.local),
        }
    }
}

/// Checked aggregate size for a set of optional lane images.
#[cfg(feature = "pvm")]
pub(crate) fn execution_state_size<'a>(
    lanes: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> Option<usize> {
    lanes
        .into_iter()
        .flatten()
        .try_fold(0usize, |total, lane| total.checked_add(lane.len()))
}

/// One content-addressed preimage made available to the runtime invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeBlob {
    pub reference: BlobRef,
    pub bytes: Vec<u8>,
}

/// Hard allocation ceiling while decoding one untrusted inner-machine image.
/// The enclosing runtime applies its (possibly smaller) signed state limit to
/// the complete encoded continuation before committing it.
pub const MAX_PORTABLE_MACHINE_MEMORY_BYTES: usize = MAX_RUNTIME_STATE_BYTES;
pub const MAX_PORTABLE_MACHINE_REGIONS: usize = 2;

/// One complete mutable region in a portable inner-machine snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableMemoryRegion {
    pub base: u32,
    pub bytes: Vec<u8>,
}

/// Runtime-independent state needed to recreate one standard inner machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableMachineSnapshot {
    pub pc: u32,
    pub gas_remaining: u64,
    pub registers: [u64; vos_pvm_program::REGISTER_COUNT],
    pub memory: Vec<PortableMemoryRegion>,
}

impl PortableMachineSnapshot {
    /// Validate bounds independent of a program. Restore additionally checks
    /// exact region bases and lengths against the authenticated program.
    pub fn is_valid(&self) -> bool {
        if self.memory.len() > MAX_PORTABLE_MACHINE_REGIONS {
            return false;
        }
        let mut total = 0usize;
        let mut previous_end = None;
        for region in &self.memory {
            if region.bytes.is_empty()
                || region.base % vos_pvm_program::PAGE_SIZE != 0
                || region.bytes.len() % vos_pvm_program::PAGE_SIZE as usize != 0
            {
                return false;
            }
            let Ok(len) = u32::try_from(region.bytes.len()) else {
                return false;
            };
            let Some(end) = region.base.checked_add(len) else {
                return false;
            };
            if previous_end.is_some_and(|previous| region.base < previous) {
                return false;
            }
            previous_end = Some(end);
            let Some(next) = total.checked_add(region.bytes.len()) else {
                return false;
            };
            if next > MAX_PORTABLE_MACHINE_MEMORY_BYTES {
                return false;
            }
            total = next;
        }
        true
    }

    pub fn memory_bytes(&self) -> usize {
        self.memory.iter().map(|region| region.bytes.len()).sum()
    }
}

/// Caller context signed into an [`ActorInvocationReceipt`](super::authority::ActorInvocationReceipt).
/// Public actor message bytes never carry these fields; the runtime guest
/// verifies the receipt before using them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorInvocationAuth {
    pub origin: Origin,
    /// Authority-authenticated application principal. Transport subjects and
    /// causal actor/service identities remain in `origin`; neither is a
    /// substitute for this authorization identity.
    pub principal: Option<PrincipalId>,
    pub origin_service: Option<ServiceIdentity>,
    pub space_role: Option<u8>,
    pub actor_role: Option<u8>,
    pub capability: Option<CapabilityId>,
}

impl ActorInvocationAuth {
    pub const fn anonymous() -> Self {
        Self {
            origin: Origin::Anonymous,
            principal: None,
            origin_service: None,
            space_role: None,
            actor_role: None,
            capability: None,
        }
    }

    pub fn validate(&self) -> bool {
        let claims_are_empty =
            self.space_role.is_none() && self.actor_role.is_none() && self.capability.is_none();
        let origin_valid = match self.origin {
            // Anonymous is an absence of authenticated authority, not merely
            // a caller label. Never let it carry host-trusted assertions.
            Origin::Anonymous => {
                self.principal.is_none() && self.origin_service.is_none() && claims_are_empty
            }
            // System work may carry one exact platform capability, but has no
            // principal or actor against which a role grant could be bound.
            Origin::System => {
                self.origin_service.is_none()
                    && self.principal.is_none()
                    && self.space_role.is_none()
                    && self.actor_role.is_none()
            }
            Origin::Member(subject) => {
                subject != crate::service::SubjectId::ZERO
                    && self
                        .principal
                        .is_some_and(|principal| principal != PrincipalId::ZERO)
                    && self.origin_service.is_none()
            }
            Origin::Actor(actor) => {
                actor != ActorId::ZERO
                    && self
                        .principal
                        .is_some_and(|principal| principal != PrincipalId::ZERO)
                    && self.origin_service.as_ref().is_some_and(|service| {
                        service.space != crate::service::SpaceId::ZERO
                            && service.root_service != crate::service::RootServiceId::ZERO
                            && service.deployment != DeploymentId::ZERO
                            && service.service_program != ProgramId::ZERO
                            && service.platform == crate::service::PLATFORM_ID
                            && service.execution_semantics == crate::service::EXECUTION_SEMANTICS_ID
                            && service.gas_schedule.is_valid()
                    })
            }
        };
        origin_valid
            && self
                .space_role
                .is_none_or(|role| crate::SpaceRole::from_u8(role).is_some())
            && self.actor_role != Some(u8::MAX)
            && self
                .capability
                .is_none_or(|capability| capability != CapabilityId::ZERO)
    }
}

impl Default for ActorInvocationAuth {
    fn default() -> Self {
        Self::anonymous()
    }
}

/// Authenticated actor work delivered to one agent runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorInvocation {
    pub invocation: InvocationId,
    pub actor: ActorId,
    /// Immutable identity of the exact install targeted by this work.
    /// Removing and reinstalling the same ActorId changes this value, so an
    /// authorization issued for the retired install cannot reach its
    /// replacement even when deployment and program are reused.
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub mode: MethodMode,
    pub auth: ActorInvocationAuth,
    pub message: Vec<u8>,
    pub availability: Vec<RuntimeBlob>,
    pub gas: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ActorExecutionStatus {
    Done = 0,
    Forbidden = 1,
    Panicked = 2,
    OutOfGas = 3,
    /// The actor committed one cooperative slice. Its exact machine
    /// continuation is runtime-owned state, not reply payload supplied by the
    /// caller.
    Yielded = 4,
}

/// Durable state observation which produced one exact actor reply.
///
/// Missing lanes are represented explicitly. Merge state uses a canonical
/// content frontier because the standard Local adapter has no causal DAG;
/// replicated adapters may map their canonical frontier to the same hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActorObservation {
    pub linear_revision: Option<u64>,
    pub merge_frontier: Option<Hash>,
    pub local_revision: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorExecutionReply {
    pub invocation: InvocationId,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub deployment: DeploymentId,
    pub mode: MethodMode,
    pub lane: Option<StateLane>,
    pub status: ActorExecutionStatus,
    pub reply: Vec<u8>,
    pub gas_remaining: u64,
    pub observation: ActorObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorExecutionError {
    NotCreated,
    NotFound,
    StaleIncarnation,
    Suspended,
    StaleDeployment,
    WrongProgram,
    UnsupportedMethod,
    /// The agent profile or runtime capabilities do not expose the durable
    /// component which owns this invocation mode's exact result.
    UnsupportedResultStorage,
    MissingState,
    InvalidAvailability,
    InvalidInput,
    InvalidActorOutput,
    DivergentInvocation,
    ResultCapacity,
    InvalidAuthorization,
    AuthorityExpired,
    AuthoritySlotRegressed,
    /// A valid continuation exists, but another continuation in the same
    /// physical component precedes it in the deterministic FIFO.
    ContinuationNotReady,
    UnsupportedHostCall(u64),
}

impl ActorExecutionError {
    /// Whether an authenticated, fresh, structurally admitted invocation must
    /// retain this deterministic rejection as an exact external outcome.
    ///
    /// The caller is still responsible for proving that the error arose after
    /// admission. In particular, [`Self::InvalidInput`] is durable only at the
    /// trusted runtime boundary; malformed host input is rejected before this
    /// classification is consulted.
    pub const fn is_durable_exact_outcome(self) -> bool {
        matches!(
            self,
            Self::NotFound
                | Self::StaleIncarnation
                | Self::Suspended
                | Self::StaleDeployment
                | Self::WrongProgram
                | Self::UnsupportedMethod
                | Self::InvalidInput
                | Self::InvalidActorOutput
                | Self::UnsupportedHostCall(_)
        )
    }
}

/// Complete runtime execution call. `state` is opaque to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeExecutionCall {
    pub state: super::wire::RuntimeState,
    pub invocation: ActorInvocation,
    /// Complete authority evidence verified again by the runtime guest.
    pub authority: super::authority::ActorInvocationReceipt,
    /// Canonical logical slot selected by the host/replication transition.
    pub observed_slot: u64,
    /// Exact-result recovery when the historical actor package has already
    /// been retired after an upgrade. This mode may only recover a guest-owned
    /// disposition; it can never execute unseen work.
    pub recovery_only: bool,
    /// Exact content-addressed program resolved by the host from its durable
    /// package catalog. It is intentionally absent from [`ActorInvocation`]
    /// so callers cannot select executable bytes.
    pub actor_pvm: Vec<u8>,
    /// Exact signed execution schema staged from the actor deployment.
    pub actor_schema: RuntimeBlob,
    /// Exact signed method policies staged from the same deployment. Package
    /// signature verification happens at lifecycle admission; the runtime
    /// authenticates these bytes against the guest-owned reference and
    /// enforces the selected method before entering application code.
    pub actor_policies: RuntimeBlob,
    /// Exact canonical constructor-argument object selected by the installed
    /// directory entry. Absence and present-empty remain distinct; const fields
    /// are reconstructed by the constructor and are not serialized here.
    pub installation_data: Option<RuntimeBlob>,
}

/// Complete deterministic runtime execution result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeExecutionReturn {
    pub state: super::wire::RuntimeState,
    pub result: Result<ActorExecutionReply, ActorExecutionError>,
}

impl ActorInvocation {
    /// Stable identity of every execution-significant caller field. Program
    /// bytes are excluded because the host resolves them by `program` from
    /// its authenticated catalog.
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(&self.invocation.0);
        encoder.fixed(&self.actor.0);
        encoder.fixed(&self.incarnation.0);
        encoder.fixed(&self.deployment.0);
        encoder.fixed(&self.program.0);
        encoder.u8(match self.mode {
            super::MethodMode::Query => 0,
            super::MethodMode::LinearizableQuery => 1,
            super::MethodMode::LocalQuery => 2,
            super::MethodMode::Linear => 3,
            super::MethodMode::Merge => 4,
            super::MethodMode::Local => 5,
        });
        crate::service::encode_origin(&mut encoder, self.auth.origin);
        encoder.option(&self.auth.principal, |encoder, principal| {
            encoder.fixed(&principal.0)
        });
        encoder.option(&self.auth.origin_service, crate::service::encode_service);
        encoder.option(&self.auth.space_role, |encoder, role| encoder.u8(*role));
        encoder.option(&self.auth.actor_role, |encoder, role| encoder.u8(*role));
        encoder.option(&self.auth.capability, |encoder, capability| {
            encoder.fixed(&capability.0)
        });
        encoder.bytes(&self.message);
        encoder.list(&self.availability, |encoder, blob| {
            encoder.fixed(&blob.reference.hash.0);
            encoder.u64(blob.reference.len);
            encoder.bytes(&blob.bytes);
        });
        encoder.u64(self.gas);
        Hash::digest(b"vos/agent/invocation", &[&bytes])
    }

    /// Message signed by the configured agent authority. It is deliberately
    /// distinct from the durable retry commitment so a receipt for one
    /// protocol cannot be replayed in the other.
    pub fn authorization_message(&self) -> Hash {
        Hash::digest(
            b"vos/agent/invocation-authorization",
            &[&self.commitment().0],
        )
    }

    pub fn validate(&self) -> Result<(), ActorExecutionError> {
        let availability_bytes = self
            .availability
            .iter()
            .try_fold(0usize, |total, blob| total.checked_add(blob.bytes.len()));
        if self.invocation == InvocationId::ZERO
            || self.actor == ActorId::ZERO
            || self.incarnation == Hash::ZERO
            || self.deployment == DeploymentId::ZERO
            || self.program == ProgramId::ZERO
            || self.gas == 0
            || self.gas > MAX_EXECUTION_GAS
            || !self.auth.validate()
            || self.message.is_empty()
            || self.message.len() > MAX_EXECUTION_MESSAGE_BYTES
            || self.availability.len() > MAX_EXECUTION_BLOBS
            || self
                .availability
                .windows(2)
                .any(|pair| pair[0].reference.hash >= pair[1].reference.hash)
            || self.availability.iter().any(|blob| {
                blob.bytes.len() > MAX_EXECUTION_STATE_BYTES || !blob.reference.matches(&blob.bytes)
            })
            || availability_bytes.is_none_or(|bytes| bytes > MAX_EXECUTION_AVAILABILITY_BYTES)
        {
            return Err(ActorExecutionError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ActorHostBudget {
    pub(crate) calls: u32,
    pub(crate) fetch_calls: u32,
    pub(crate) fetch_bytes: u32,
    pub(crate) blake2b_compressions: u32,
    pub(crate) debug_bytes: u32,
}

impl ActorHostBudget {
    #[cfg(feature = "pvm")]
    fn charge(total: &mut u32, amount: usize, maximum: usize) -> bool {
        let Ok(amount) = u32::try_from(amount) else {
            return false;
        };
        let Some(next) = total
            .checked_add(amount)
            .filter(|next| *next as usize <= maximum)
        else {
            return false;
        };
        *total = next;
        true
    }

    #[cfg(feature = "pvm")]
    fn host_call(&mut self) -> bool {
        Self::charge(&mut self.calls, 1, MAX_EXECUTION_HOST_CALLS)
    }

    #[cfg(feature = "pvm")]
    fn fetch(&mut self, bytes: usize) -> bool {
        Self::charge(&mut self.fetch_calls, 1, MAX_EXECUTION_FETCH_CALLS)
            && Self::charge(&mut self.fetch_bytes, bytes, MAX_EXECUTION_FETCH_BYTES)
    }

    #[cfg(feature = "agent-runtime")]
    fn blake2b_compression(&mut self) -> bool {
        Self::charge(
            &mut self.blake2b_compressions,
            1,
            MAX_EXECUTION_BLAKE2B_COMPRESS_CALLS,
        )
    }

    #[cfg(feature = "pvm")]
    fn debug(&mut self, bytes: usize) -> bool {
        Self::charge(&mut self.debug_bytes, bytes, MAX_EXECUTION_DEBUG_BYTES)
    }

    pub(crate) fn validate(self) -> bool {
        self.calls as usize <= MAX_EXECUTION_HOST_CALLS
            && self.fetch_calls as usize <= MAX_EXECUTION_FETCH_CALLS
            && self.fetch_bytes as usize <= MAX_EXECUTION_FETCH_BYTES
            && self.blake2b_compressions as usize <= MAX_EXECUTION_BLAKE2B_COMPRESS_CALLS
            && self.debug_bytes as usize <= MAX_EXECUTION_DEBUG_BYTES
    }

    fn includes(self, earlier: Self) -> bool {
        self.calls >= earlier.calls
            && self.fetch_calls >= earlier.fetch_calls
            && self.fetch_bytes >= earlier.fetch_bytes
            && self.blake2b_compressions >= earlier.blake2b_compressions
            && self.debug_bytes >= earlier.debug_bytes
    }
}

/// Exact portable state captured at an actor SUSPEND exit. The fetch cursor
/// and native-work counters are part of the continuation: resetting either on
/// resume would make restart behavior diverge or permit budget bypass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActorMachineContinuation {
    pub(crate) machine: PortableMachineSnapshot,
    pub(crate) fetch_index: u8,
    pub(crate) host_budget: ActorHostBudget,
}

impl ActorMachineContinuation {
    pub(crate) fn validate(&self) -> bool {
        self.fetch_index <= 5 && self.host_budget.validate() && self.machine.is_valid()
    }
}

#[cfg(feature = "pvm")]
fn charge_yield_finalizer(
    continuation: &mut ActorMachineContinuation,
    gas_remaining: u64,
    host_budget: ActorHostBudget,
) -> Result<(), ActorExecutionError> {
    if gas_remaining > continuation.machine.gas_remaining
        || !host_budget.includes(continuation.host_budget)
        || !host_budget.validate()
    {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    continuation.machine.gas_remaining = gas_remaining;
    continuation.host_budget = host_budget;
    Ok(())
}

#[cfg(feature = "pvm")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ActorRunOutcome {
    Completed {
        reply: ActorExecutionReply,
        state: ActorStateLanes,
    },
    Yielded {
        reply: ActorExecutionReply,
        state: ActorStateLanes,
        continuation: ActorMachineContinuation,
    },
}

#[cfg(feature = "pvm")]
pub(crate) fn run_inner_actor(
    invocation: &ActorInvocation,
    actor_pvm: &[u8],
    installation_data: Option<&[u8]>,
    actor_state: &ActorStateLanes,
    continuation: Option<ActorMachineContinuation>,
) -> Result<ActorRunOutcome, ActorExecutionError> {
    use super::machine::{ActorMachine, InnerExit};
    use crate::abi::{error, hostcall};

    if actor_state
        .encoded_len()
        .is_none_or(|len| len > MAX_EXECUTION_STATE_TOTAL_BYTES)
    {
        return Err(ActorExecutionError::InvalidInput);
    }
    let encode_lane = |lane: Option<&[u8]>| {
        let mut item = Vec::with_capacity(lane.map_or(1, |bytes| bytes.len() + 1));
        match lane {
            None => item.push(0),
            Some(bytes) => {
                item.push(1);
                item.extend_from_slice(bytes);
            }
        }
        item
    };
    let linear = encode_lane(actor_state.linear.as_deref());
    let merge = encode_lane(actor_state.merge.as_deref());
    let local = encode_lane(actor_state.local.as_deref());
    let control = super::wire::ActorDispatchControl {
        invocation: invocation.invocation,
        actor: invocation.actor,
        mode: invocation.mode,
        auth: invocation.auth.clone(),
    }
    .encode();
    if control.len() > ACTOR_DISPATCH_CONTROL_CAPACITY {
        return Err(ActorExecutionError::InvalidInput);
    }
    let fetch = [
        linear.as_slice(),
        merge.as_slice(),
        local.as_slice(),
        control.as_slice(),
        invocation.message.as_slice(),
    ];
    let mut actor_args =
        Vec::with_capacity(installation_data.map_or(1, |bytes| bytes.len().saturating_add(1)));
    match installation_data {
        None => actor_args.push(0),
        Some(bytes) => {
            if bytes.len() > super::MAX_INSTALLATION_DATA_BYTES {
                return Err(ActorExecutionError::InvalidInput);
            }
            actor_args.push(1);
            actor_args.extend_from_slice(bytes);
        }
    }
    let (mut machine, mut gas, mut fetch_index, mut host_budget) = match continuation {
        Some(continuation) => {
            if !continuation.validate() {
                return Err(ActorExecutionError::InvalidInput);
            }
            let mut machine = ActorMachine::restore(actor_pvm, &actor_args, &continuation.machine)
                .map_err(|_| ActorExecutionError::InvalidAvailability)?;
            // Agent SUSPEND is a private inner-actor ABI exit. Zero finalized
            // the fork which emitted the yielded lane image; one resumes the
            // captured successor without a service checkpoint token.
            machine.registers_mut()[7] = 1;
            machine.registers_mut()[8] = 0;
            (
                machine,
                continuation.machine.gas_remaining,
                continuation.fetch_index as usize,
                continuation.host_budget,
            )
        }
        None => (
            ActorMachine::load(actor_pvm, &actor_args)
                .map_err(|_| ActorExecutionError::InvalidInput)?,
            invocation.gas,
            0,
            ActorHostBudget::default(),
        ),
    };
    let mut yielded_continuation: Option<ActorMachineContinuation> = None;

    loop {
        match machine.resume(gas) {
            InnerExit::Halt => {
                let registers = *machine.registers();
                let address = u32::try_from(registers[7])
                    .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                let len = usize::try_from(registers[8])
                    .ok()
                    .filter(|len| {
                        *len <= MAX_EXECUTION_STATE_TOTAL_BYTES + MAX_EXECUTION_REPLY_BYTES + 13
                    })
                    .ok_or(ActorExecutionError::InvalidActorOutput)?;
                let mut output = alloc::vec![0u8; len];
                machine
                    .read(address, &mut output)
                    .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                let (mut reply, state) =
                    decode_actor_output(invocation, machine.gas_remaining(), output)?;
                return match (reply.status, yielded_continuation.take()) {
                    (ActorExecutionStatus::Yielded, Some(mut continuation)) => {
                        // Memory/PC/registers remain the exact pre-result
                        // snapshot, while gas and native work performed by
                        // the disposable finalization fork are charged to the
                        // continuation. Repeated yields therefore cannot make
                        // state serialization or output construction free.
                        charge_yield_finalizer(
                            &mut continuation,
                            machine.gas_remaining(),
                            host_budget,
                        )?;
                        reply.gas_remaining = machine.gas_remaining();
                        Ok(ActorRunOutcome::Yielded {
                            reply,
                            state,
                            continuation,
                        })
                    }
                    (ActorExecutionStatus::Yielded, None) | (_, Some(_)) => {
                        Err(ActorExecutionError::InvalidActorOutput)
                    }
                    (_, None) => Ok(ActorRunOutcome::Completed { reply, state }),
                };
            }
            InnerExit::Panic | InnerExit::Fault(_) => {
                return Ok(ActorRunOutcome::Completed {
                    reply: terminal_reply(
                        invocation,
                        ActorExecutionStatus::Panicked,
                        machine.gas_remaining(),
                    ),
                    state: actor_state.clone(),
                });
            }
            InnerExit::OutOfGas => {
                return Ok(ActorRunOutcome::Completed {
                    reply: terminal_reply(invocation, ActorExecutionStatus::OutOfGas, 0),
                    state: actor_state.clone(),
                });
            }
            InnerExit::InvalidResult(_) => return Err(ActorExecutionError::InvalidActorOutput),
            InnerExit::Host(id) => {
                gas = machine.gas_remaining();
                // PVM instruction gas bounds guest computation, but host
                // operations perform native work outside that schedule. Keep
                // a second deterministic per-invocation work budget so a
                // cheap ECALL loop cannot monopolize the agent thread.
                if !host_budget.host_call() {
                    return Ok(ActorRunOutcome::Completed {
                        reply: terminal_reply(invocation, ActorExecutionStatus::OutOfGas, 0),
                        state: actor_state.clone(),
                    });
                }
                let registers = *machine.registers();
                if id == u64::from(hostcall::SUSPEND) {
                    if yielded_continuation.is_some() {
                        return Err(ActorExecutionError::InvalidActorOutput);
                    }
                    let snapshot = machine
                        .capture()
                        .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                    let continuation = ActorMachineContinuation {
                        machine: snapshot,
                        fetch_index: u8::try_from(fetch_index)
                            .map_err(|_| ActorExecutionError::InvalidActorOutput)?,
                        host_budget,
                    };
                    let mut finalizer =
                        ActorMachine::restore(actor_pvm, &actor_args, &continuation.machine)
                            .map_err(|_| ActorExecutionError::InvalidActorOutput)?;
                    finalizer.registers_mut()[7] = 0;
                    finalizer.registers_mut()[8] = 0;
                    gas = continuation.machine.gas_remaining;
                    yielded_continuation = Some(continuation);
                    machine = finalizer;
                    continue;
                }
                let (result0, result1) = match id {
                    value if value == u64::from(hostcall::GAS) => (gas, 0),
                    value if value == u64::from(hostcall::FETCH) => {
                        let address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let capacity = usize::try_from(registers[8])
                            .ok()
                            .filter(|len| *len <= MAX_EXECUTION_STATE_BYTES + 1)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        if let Some(item) = fetch.get(fetch_index) {
                            let copied = item.len().min(capacity);
                            if !host_budget.fetch(copied) {
                                return Ok(ActorRunOutcome::Completed {
                                    reply: terminal_reply(
                                        invocation,
                                        ActorExecutionStatus::OutOfGas,
                                        0,
                                    ),
                                    state: actor_state.clone(),
                                });
                            }
                            machine
                                .write(address, &item[..copied])
                                .map_err(|_| ActorExecutionError::InvalidInput)?;
                            if item.len() <= capacity {
                                fetch_index += 1;
                            }
                            (item.len() as u64, 0)
                        } else {
                            (0, 0)
                        }
                    }
                    // The standard loader maps the program-declared heap up
                    // front. This call is therefore an accounting seam, not
                    // permission to mutate pages outside that declaration.
                    value if value == u64::from(hostcall::GROW_HEAP) => (error::HOST_OK, 0),
                    #[cfg(feature = "agent-runtime")]
                    value if value == u64::from(crate::crypto::ECALL_BLAKE2B_COMPRESS) => {
                        if !host_budget.blake2b_compression() {
                            return Ok(ActorRunOutcome::Completed {
                                reply: terminal_reply(
                                    invocation,
                                    ActorExecutionStatus::OutOfGas,
                                    0,
                                ),
                                state: actor_state.clone(),
                            });
                        }
                        let h_address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let m_address = u32::try_from(registers[8])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let mut h = [0u8; 64];
                        let mut block = [0u8; 128];
                        machine
                            .read(h_address, &mut h)
                            .and_then(|()| machine.read(m_address, &mut block))
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        crate::crypto::blake2b::host_compress_block(
                            &mut h,
                            &block,
                            registers[9] as u128,
                            registers[10] != 0,
                        );
                        machine
                            .write(h_address, &h)
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        // Crypto precompiles are memory transforms. Preserve
                        // their argument registers exactly like tracing does;
                        // actor code reads the digest through `h_address`.
                        (registers[7], registers[8])
                    }
                    // Guest diagnostics never cross the deterministic runtime
                    // boundary. Validate the readable window, then discard it.
                    value if value == u64::from(hostcall::DEBUG_WRITE) => {
                        let address = u32::try_from(registers[7])
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        let len = usize::try_from(registers[8])
                            .ok()
                            .filter(|len| *len <= 8 * 1024)
                            .ok_or(ActorExecutionError::InvalidInput)?;
                        if !host_budget.debug(len) {
                            return Ok(ActorRunOutcome::Completed {
                                reply: terminal_reply(
                                    invocation,
                                    ActorExecutionStatus::OutOfGas,
                                    0,
                                ),
                                state: actor_state.clone(),
                            });
                        }
                        let mut discarded = alloc::vec![0u8; len];
                        machine
                            .read(address, &mut discarded)
                            .map_err(|_| ActorExecutionError::InvalidInput)?;
                        (len as u64, 0)
                    }
                    other => return Err(ActorExecutionError::UnsupportedHostCall(other)),
                };
                let registers = machine.registers_mut();
                registers[7] = result0;
                registers[8] = result1;
            }
        }
    }
}

#[cfg(feature = "pvm")]
fn terminal_reply(
    invocation: &ActorInvocation,
    status: ActorExecutionStatus,
    gas_remaining: u64,
) -> ActorExecutionReply {
    ActorExecutionReply {
        invocation: invocation.invocation,
        actor: invocation.actor,
        incarnation: invocation.incarnation,
        deployment: invocation.deployment,
        mode: invocation.mode,
        lane: invocation.mode.write_lane(),
        status,
        reply: Vec::new(),
        gas_remaining,
        observation: ActorObservation::default(),
    }
}

#[cfg(feature = "pvm")]
fn decode_actor_output(
    invocation: &ActorInvocation,
    gas_remaining: u64,
    output: Vec<u8>,
) -> Result<(ActorExecutionReply, ActorStateLanes), ActorExecutionError> {
    if output.len() < 13 {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    let linear_len = u32::from_le_bytes(
        output[1..5]
            .try_into()
            .expect("the output length was checked above"),
    ) as usize;
    let merge_len = u32::from_le_bytes(output[5..9].try_into().unwrap()) as usize;
    let local_len = u32::from_le_bytes(output[9..13].try_into().unwrap()) as usize;
    if linear_len > MAX_EXECUTION_STATE_BYTES
        || merge_len > MAX_EXECUTION_STATE_BYTES
        || local_len > MAX_EXECUTION_STATE_BYTES
    {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    let linear_end = 13usize
        .checked_add(linear_len)
        .filter(|end| *end <= output.len())
        .ok_or(ActorExecutionError::InvalidActorOutput)?;
    let merge_end = linear_end
        .checked_add(merge_len)
        .filter(|end| *end <= output.len())
        .ok_or(ActorExecutionError::InvalidActorOutput)?;
    let local_end = merge_end
        .checked_add(local_len)
        .filter(|end| *end <= output.len())
        .ok_or(ActorExecutionError::InvalidActorOutput)?;
    if linear_len
        .checked_add(merge_len)
        .and_then(|len| len.checked_add(local_len))
        .is_none_or(|len| len > MAX_EXECUTION_STATE_TOTAL_BYTES)
    {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    if output.len() - local_end > MAX_EXECUTION_REPLY_BYTES {
        return Err(ActorExecutionError::InvalidActorOutput);
    }
    let status = match output[0] {
        crate::actors::STATUS_DONE => ActorExecutionStatus::Done,
        crate::actors::STATUS_FORBIDDEN => ActorExecutionStatus::Forbidden,
        crate::actors::STATUS_PANICKED => ActorExecutionStatus::Panicked,
        crate::actors::STATUS_OOG => ActorExecutionStatus::OutOfGas,
        crate::actors::STATUS_YIELDED => ActorExecutionStatus::Yielded,
        _ => return Err(ActorExecutionError::InvalidActorOutput),
    };
    let next_state = ActorStateLanes {
        linear: Some(output[13..linear_end].to_vec()),
        merge: Some(output[linear_end..merge_end].to_vec()),
        local: Some(output[merge_end..local_end].to_vec()),
    };
    let reply = output[local_end..].to_vec();
    Ok((
        ActorExecutionReply {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            mode: invocation.mode,
            lane: invocation.mode.write_lane(),
            status,
            reply,
            gas_remaining,
            observation: ActorObservation::default(),
        },
        next_state,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> ActorInvocation {
        ActorInvocation {
            invocation: InvocationId([1; 32]),
            actor: ActorId([2; 32]),
            incarnation: Hash([5; 32]),
            deployment: DeploymentId([3; 32]),
            program: ProgramId([4; 32]),
            mode: MethodMode::Linear,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 1,
        }
    }

    fn source_service() -> ServiceIdentity {
        ServiceIdentity {
            space: crate::service::SpaceId([0x11; 32]),
            root_service: crate::service::RootServiceId([0x12; 32]),
            deployment: DeploymentId([0x13; 32]),
            service_program: ProgramId([0x14; 32]),
            platform: crate::service::PLATFORM_ID,
            execution_semantics: crate::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: crate::service::GasSchedule::new(1, 1),
        }
    }

    #[test]
    fn anonymous_auth_cannot_smuggle_authenticated_claims() {
        assert!(ActorInvocationAuth::anonymous().validate());

        let mut auth = ActorInvocationAuth::anonymous();
        auth.origin_service = Some(source_service());
        assert!(!auth.validate());

        let mut auth = ActorInvocationAuth::anonymous();
        auth.space_role = Some(crate::SpaceRole::Member.as_u8());
        assert!(!auth.validate());

        let mut auth = ActorInvocationAuth::anonymous();
        auth.actor_role = Some(1);
        assert!(!auth.validate());

        let mut auth = ActorInvocationAuth::anonymous();
        auth.capability = Some(CapabilityId::named("actor.write"));
        assert!(!auth.validate());
    }

    #[test]
    fn authenticated_origin_shapes_are_canonical() {
        let capability = CapabilityId::named("actor.write");
        assert!(
            ActorInvocationAuth {
                origin: Origin::System,
                principal: None,
                origin_service: None,
                space_role: None,
                actor_role: None,
                capability: Some(capability),
            }
            .validate()
        );
        assert!(
            !ActorInvocationAuth {
                origin: Origin::System,
                principal: None,
                origin_service: None,
                space_role: Some(crate::SpaceRole::Member.as_u8()),
                actor_role: None,
                capability: None,
            }
            .validate()
        );
        assert!(
            !ActorInvocationAuth {
                origin: Origin::Member(crate::service::SubjectId::ZERO),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: None,
                space_role: None,
                actor_role: None,
                capability: None,
            }
            .validate()
        );
        assert!(
            ActorInvocationAuth {
                origin: Origin::Member(crate::service::SubjectId([0x21; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: None,
                space_role: Some(crate::SpaceRole::Member.as_u8()),
                actor_role: Some(1),
                capability: None,
            }
            .validate()
        );
        assert!(
            !ActorInvocationAuth {
                origin: Origin::Member(crate::service::SubjectId([0x21; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: Some(source_service()),
                space_role: None,
                actor_role: None,
                capability: None,
            }
            .validate()
        );
        assert!(
            !ActorInvocationAuth {
                origin: Origin::Actor(ActorId([0x22; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: None,
                space_role: None,
                actor_role: None,
                capability: None,
            }
            .validate()
        );
        assert!(
            ActorInvocationAuth {
                origin: Origin::Actor(ActorId([0x22; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: Some(source_service()),
                space_role: None,
                actor_role: Some(1),
                capability: None,
            }
            .validate()
        );

        let mut malformed_service = source_service();
        malformed_service.platform = Hash::ZERO;
        assert!(
            !ActorInvocationAuth {
                origin: Origin::Actor(ActorId([0x22; 32])),
                principal: Some(crate::service::PrincipalId([0x31; 32])),
                origin_service: Some(malformed_service),
                space_role: None,
                actor_role: None,
                capability: None,
            }
            .validate()
        );
    }

    #[test]
    fn authorization_commitment_binds_principal_roles_and_complete_actor_source() {
        let capability = CapabilityId::named("actor.write");
        let mut member = invocation();
        member.auth = ActorInvocationAuth {
            origin: Origin::Member(crate::service::SubjectId([0x21; 32])),
            principal: Some(crate::service::PrincipalId([0x31; 32])),
            origin_service: None,
            space_role: Some(crate::SpaceRole::Member.as_u8()),
            actor_role: Some(3),
            capability: Some(capability),
        };
        let member_authorization = member.authorization_message();

        let mut forged_member = member.clone();
        forged_member.auth.origin = Origin::Member(crate::service::SubjectId([0x22; 32]));
        assert_ne!(forged_member.authorization_message(), member_authorization);
        let mut forged_role = member;
        forged_role.auth.actor_role = Some(4);
        assert_ne!(forged_role.authorization_message(), member_authorization);

        let mut actor = invocation();
        actor.auth = ActorInvocationAuth {
            origin: Origin::Actor(ActorId([0x31; 32])),
            principal: Some(crate::service::PrincipalId([0x32; 32])),
            origin_service: Some(source_service()),
            space_role: None,
            actor_role: Some(2),
            capability: None,
        };
        let actor_authorization = actor.authorization_message();

        // Reusing the same ActorId from another root is not authenticated as
        // the original caller: the complete source identity is committed.
        let mut forged_source = actor;
        forged_source
            .auth
            .origin_service
            .as_mut()
            .unwrap()
            .root_service = crate::service::RootServiceId([0x41; 32]);
        assert_ne!(forged_source.authorization_message(), actor_authorization);
    }

    #[test]
    fn invocation_gas_is_explicitly_bounded() {
        let mut invocation = invocation();
        invocation.gas = MAX_EXECUTION_GAS;
        assert_eq!(invocation.validate(), Ok(()));
        invocation.gas = MAX_EXECUTION_GAS + 1;
        assert_eq!(
            invocation.validate(),
            Err(ActorExecutionError::InvalidInput)
        );
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn native_host_work_has_independent_quotas() {
        let mut budget = ActorHostBudget {
            calls: u32::try_from(MAX_EXECUTION_HOST_CALLS - 1).unwrap(),
            fetch_calls: u32::try_from(MAX_EXECUTION_FETCH_CALLS - 1).unwrap(),
            fetch_bytes: u32::try_from(MAX_EXECUTION_FETCH_BYTES - 1).unwrap(),
            blake2b_compressions: u32::try_from(MAX_EXECUTION_BLAKE2B_COMPRESS_CALLS - 1).unwrap(),
            debug_bytes: u32::try_from(MAX_EXECUTION_DEBUG_BYTES - 1).unwrap(),
        };
        assert!(budget.host_call());
        assert!(!budget.host_call());
        assert!(budget.fetch(1));
        assert!(!budget.fetch(0));
        #[cfg(feature = "agent-runtime")]
        {
            assert!(budget.blake2b_compression());
            assert!(!budget.blake2b_compression());
        }
        assert!(budget.debug(1));
        assert!(!budget.debug(1));
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn repeated_yield_finalizers_cannot_replenish_gas_or_native_work_budget() {
        let mut continuation = ActorMachineContinuation {
            machine: PortableMachineSnapshot {
                pc: 2,
                gas_remaining: 1_000,
                registers: [0; vos_pvm_program::REGISTER_COUNT],
                memory: Vec::new(),
            },
            fetch_index: 5,
            host_budget: ActorHostBudget {
                calls: 2,
                fetch_calls: 1,
                fetch_bytes: 9,
                blake2b_compressions: 0,
                debug_bytes: 3,
            },
        };
        charge_yield_finalizer(
            &mut continuation,
            800,
            ActorHostBudget {
                calls: 4,
                fetch_calls: 1,
                fetch_bytes: 9,
                blake2b_compressions: 0,
                debug_bytes: 7,
            },
        )
        .unwrap();
        charge_yield_finalizer(
            &mut continuation,
            600,
            ActorHostBudget {
                calls: 7,
                fetch_calls: 2,
                fetch_bytes: 20,
                blake2b_compressions: 1,
                debug_bytes: 7,
            },
        )
        .unwrap();
        assert_eq!(continuation.machine.gas_remaining, 600);
        assert_eq!(continuation.host_budget.calls, 7);
        assert_eq!(continuation.host_budget.fetch_bytes, 20);

        let charged = continuation.clone();
        assert_eq!(
            charge_yield_finalizer(
                &mut continuation,
                601,
                ActorHostBudget {
                    calls: 7,
                    fetch_calls: 2,
                    fetch_bytes: 20,
                    blake2b_compressions: 1,
                    debug_bytes: 7,
                },
            ),
            Err(ActorExecutionError::InvalidActorOutput)
        );
        assert_eq!(continuation, charged);
        assert_eq!(
            charge_yield_finalizer(
                &mut continuation,
                500,
                ActorHostBudget {
                    calls: 6,
                    fetch_calls: 2,
                    fetch_bytes: 20,
                    blake2b_compressions: 1,
                    debug_bytes: 7,
                },
            ),
            Err(ActorExecutionError::InvalidActorOutput)
        );
        assert_eq!(continuation, charged);
    }

    #[test]
    fn availability_enforces_the_aggregate_guest_budget() {
        let mut invocation = invocation();
        invocation.availability = [
            vec![1; MAX_EXECUTION_AVAILABILITY_BYTES / 2],
            vec![2; MAX_EXECUTION_AVAILABILITY_BYTES / 2],
        ]
        .into_iter()
        .map(|bytes| RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        })
        .collect();
        invocation
            .availability
            .sort_unstable_by_key(|blob| blob.reference.hash);
        assert_eq!(invocation.validate(), Ok(()));

        let bytes = vec![3];
        invocation.availability.push(RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        invocation
            .availability
            .sort_unstable_by_key(|blob| blob.reference.hash);
        assert_eq!(
            invocation.validate(),
            Err(ActorExecutionError::InvalidInput)
        );
    }

    #[test]
    fn exact_outcome_error_classification_is_exhaustive() {
        for error in [
            ActorExecutionError::NotFound,
            ActorExecutionError::StaleIncarnation,
            ActorExecutionError::Suspended,
            ActorExecutionError::StaleDeployment,
            ActorExecutionError::WrongProgram,
            ActorExecutionError::UnsupportedMethod,
            ActorExecutionError::InvalidInput,
            ActorExecutionError::InvalidActorOutput,
            ActorExecutionError::UnsupportedHostCall(u64::MAX),
        ] {
            assert!(error.is_durable_exact_outcome(), "{error:?}");
        }
        for error in [
            ActorExecutionError::NotCreated,
            ActorExecutionError::UnsupportedResultStorage,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::DivergentInvocation,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::InvalidAuthorization,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
            ActorExecutionError::ContinuationNotReady,
        ] {
            assert!(!error.is_durable_exact_outcome(), "{error:?}");
        }
    }

    #[cfg(feature = "pvm")]
    fn actor_output(lanes: [usize; 3], reply: usize) -> Vec<u8> {
        let mut output = vec![0; 13 + lanes.iter().sum::<usize>() + reply];
        output[0] = crate::actors::STATUS_DONE;
        output[1..5].copy_from_slice(&(lanes[0] as u32).to_le_bytes());
        output[5..9].copy_from_slice(&(lanes[1] as u32).to_le_bytes());
        output[9..13].copy_from_slice(&(lanes[2] as u32).to_le_bytes());
        output
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn actor_output_accepts_exact_aggregate_state_and_reply_limits() {
        let lane = MAX_EXECUTION_STATE_TOTAL_BYTES / 3;
        let remainder = MAX_EXECUTION_STATE_TOTAL_BYTES - lane * 2;
        let output = actor_output([lane, lane, remainder], MAX_EXECUTION_REPLY_BYTES);
        assert!(decode_actor_output(&invocation(), 1, output).is_ok());
    }

    #[cfg(feature = "pvm")]
    #[test]
    fn actor_output_rejects_aggregate_state_overflow() {
        let lane = MAX_EXECUTION_STATE_TOTAL_BYTES / 3;
        let remainder = MAX_EXECUTION_STATE_TOTAL_BYTES - lane * 2 + 1;
        let output = actor_output([lane, lane, remainder], 0);
        assert_eq!(
            decode_actor_output(&invocation(), 1, output),
            Err(ActorExecutionError::InvalidActorOutput)
        );
    }
}
