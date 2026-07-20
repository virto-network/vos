use alloc::collections::BTreeSet;
use alloc::string::String;
#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

use super::identity::*;
use super::wire::{DecodeError, Decoder, Encoder, V2Wire};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIdentityV2 {
    pub space: SpaceId,
    pub root_service: RootServiceId,
    pub deployment: DeploymentId,
    pub service_program: ProgramId,
    pub service_abi: u16,
    pub execution_semantics: Hash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConsistencyModeV2 {
    Ephemeral = 0,
    Local = 1,
    Raft = 2,
    Crdt = 3,
}

impl ConsistencyModeV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match decoder.u8()? {
            0 => Ok(Self::Ephemeral),
            1 => Ok(Self::Local),
            2 => Ok(Self::Raft),
            3 => Ok(Self::Crdt),
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistencyBaseV2 {
    Linear { revision: u64, state_root: Hash },
    Crdt { heads: Vec<Hash> },
}

impl ConsistencyBaseV2 {
    pub fn mode_compatible(&self, mode: ConsistencyModeV2) -> bool {
        matches!(
            (self, mode),
            (
                Self::Linear { .. },
                ConsistencyModeV2::Ephemeral | ConsistencyModeV2::Local | ConsistencyModeV2::Raft
            ) | (Self::Crdt { .. }, ConsistencyModeV2::Crdt)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationEvidenceV2 {
    /// Method policy explicitly allows anonymous invocation.
    Public,
    /// Opaque credential disclosed to ordinary authorization validation and
    /// the generated policy it must satisfy. Attested private roles use
    /// [`Self::PrivateCredential`] instead.
    Credential {
        policy: Hash,
        credential_commitment: Hash,
        bytes: Vec<u8>,
    },
    /// Private attestation witness. Refine/proving receives the preimage as an
    /// imported blob, while work and statement wires expose only this content
    /// reference, the credential commitment, and the generated policy.
    PrivateCredential {
        policy: Hash,
        credential_commitment: Hash,
        witness: BlobRefV2,
    },
    /// Authenticated platform operation. This never bypasses the method's
    /// generated policy.
    SystemCapability {
        capability: SystemCapabilityId,
        authenticator: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRefV2 {
    pub hash: Hash,
    pub len: u64,
}

impl BlobRefV2 {
    /// Construct a content reference for bytes imported into or exported from
    /// a VOS v2 service invocation.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self {
            hash: Hash::digest(b"vos/blob/v2", &[bytes]),
            len: bytes.len() as u64,
        }
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.len == bytes.len() as u64 && *self == Self::of_bytes(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedActorV2 {
    pub actor: ActorId,
    pub program: ProgramId,
    /// First canonical state materialization for this actor at the work base.
    /// Linear work has exactly this state. CRDT work may additionally import
    /// concurrent frontier states which the actor PVM merges before dispatch.
    pub state: BlobRefV2,
    pub causal_states: Vec<BlobRefV2>,
    pub continuation: Option<BlobRefV2>,
}

/// Canonical code supplied to Refine. An ELF, JIT image, or proving artifact
/// is never accepted here: `pvm` is the exact executable/proof identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedProgramV2 {
    pub program: ProgramId,
    pub pvm: Vec<u8>,
}

/// Content-addressed bytes supplied to Refine for one declared blob reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedBlobV2 {
    pub reference: BlobRefV2,
    pub bytes: Vec<u8>,
}

/// Complete immutable import set for one Refine execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefineImportsV2 {
    pub programs: Vec<ImportedProgramV2>,
    pub blobs: Vec<ImportedBlobV2>,
}

/// Input placed in the invocation-owned IPC DATA capability before the
/// generic service CALLs an actor VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorSliceInputV2 {
    pub actor: ActorId,
    /// Stable identity allocated by the generic service for this complete
    /// execution slice. Present only for an explicitly CRDT service.
    pub change: Option<ChangeId>,
    pub state: Vec<u8>,
    /// Additional canonical CRDT frontier materializations. The generated
    /// actor merger folds these into `state` before the message is observed.
    pub causal_states: Vec<Vec<u8>>,
    /// Canonical generated actor-message bytes.
    pub message: Vec<u8>,
    pub origin: Origin,
}

/// Actor-produced result returned through the same IPC DATA capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorSliceOutputV2 {
    pub actor: ActorId,
    pub writes: Vec<ActorWriteV2>,
    /// Concrete field operations emitted by one `#[actor(crdt)]` execution
    /// slice. Ordinary actors always leave this empty.
    pub crdt_operations: Vec<CrdtOperationV2>,
    /// Canonical archived actor state after applying `crdt_operations` to the
    /// imported causal materialization. This is transported as a candidate
    /// blob; Refine never persists it directly.
    pub crdt_materialization: Option<Vec<u8>>,
    /// Cross-root calls emitted by this slice. The owning service derives each
    /// stable `CallId` from the work invocation and `await_ordinal`.
    pub outbox: Vec<ActorCallRequestV2>,
    pub reply: Vec<u8>,
    pub yielded: bool,
    pub forbidden: bool,
    /// Present after a restored continuation or when this slice creates a new
    /// durable checkpoint. The generic service uses it to bind the transition
    /// to the current base and atomically replace/delete continuation state.
    pub checkpoint: Option<CheckpointTokenV2>,
}

/// Pure host-to-guest handoff written only after JAR captured the exact
/// pre-result machine snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointTokenV2 {
    pub input: WorkInputIdV2,
    pub base: ConsistencyBaseV2,
    /// Current CRDT frontier height supplied with resumed work. The outer
    /// service VM is part of the exact snapshot and still holds its
    /// pre-suspension envelope, so the injected token carries the consensus
    /// inputs needed for the next transition without replaying that VM.
    pub base_causal_height: Option<u64>,
    pub expected: Option<Hash>,
    pub replacement: Option<BlobRefV2>,
    pub pending_call: Option<CallId>,
}

/// Actor-to-scheduler portion of a durable cross-root call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorCallRequestV2 {
    pub await_ordinal: u64,
    pub to: ActorId,
    pub payload: Vec<u8>,
    pub authorization: AuthorizationEvidenceV2,
    pub deadline_timeslot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkEnvelopeV2 {
    pub service: ServiceIdentityV2,
    /// Stable identity of the complete workflow across durable awaits.
    pub invocation: InvocationId,
    /// Zero-based execution slice within `invocation`. Each committed await
    /// advances this value, so retries deduplicate without conflating later
    /// checkpoints with the first transition.
    pub workflow_step: u64,
    /// Authenticated JAM logical timeslot at which this work item is
    /// scheduled. Durable deadlines are compared only to this consensus input,
    /// never to a wall clock.
    pub logical_timeslot: u64,
    pub target: ActorId,
    pub target_program: ProgramId,
    pub method: String,
    pub arguments: Vec<u8>,
    pub origin: Origin,
    pub authorization: AuthorizationEvidenceV2,
    pub causal_parent: Option<InvocationId>,
    pub parent_call: Option<CallId>,
    /// Present only when restoring a continuation waiting on a committed
    /// cross-root result. The reply is injected at the captured protocol-call
    /// boundary; it is never treated as a fresh handler argument.
    pub awaited_reply: Option<AccumulatedReplyV2>,
    pub consistency: ConsistencyModeV2,
    pub base: ConsistencyBaseV2,
    /// Maximum causal height among `base` heads. Present only for CRDT work;
    /// Accumulate recomputes it from committed parent nodes before accepting
    /// the child change.
    pub base_causal_height: Option<u64>,
    pub imported_actors: Vec<ImportedActorV2>,
    pub imported_blobs: Vec<BlobRefV2>,
    pub proof_requested: bool,
}

impl WorkEnvelopeV2 {
    pub const fn input_id(&self) -> WorkInputIdV2 {
        WorkInputIdV2 {
            invocation: self.invocation,
            workflow_step: self.workflow_step,
        }
    }

    /// Consensus identity of the complete work input, including origin,
    /// authorization evidence, consistency base, and every import reference.
    pub fn hash(&self) -> Hash {
        Hash::digest(b"vos/work/v2", &[&self.encode()])
    }

    /// Stable identity shared by every slice of one suspended workflow.
    /// Volatile scheduling inputs (step, timeslot, arguments, consistency
    /// frontier, and imported state) are deliberately excluded; service,
    /// actor/program, method, caller, authorization, and consistency mode are
    /// not allowed to change while an exact continuation is live.
    pub fn workflow_identity(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        encode_service(&mut e, &self.service);
        e.fixed(&self.invocation.0);
        e.fixed(&self.target.0);
        e.fixed(&self.target_program.0);
        e.string(&self.method);
        encode_origin(&mut e, self.origin);
        encode_auth(&mut e, &self.authorization);
        e.option(&self.causal_parent, |e, id| e.fixed(&id.0));
        e.option(&self.parent_call, |e, id| e.fixed(&id.0));
        e.u8(self.consistency as u8);
        e.bool(self.proof_requested);
        Hash::digest(b"vos/workflow/v2", &[&bytes])
    }
}

/// Exactly-once identity of one consumable workflow slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkInputIdV2 {
    pub invocation: InvocationId,
    pub workflow_step: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorWriteV2 {
    pub actor: ActorId,
    pub key: Vec<u8>,
    /// `None` deletes the row. The actor itself is never represented by a
    /// magic storage key.
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtOperationV2 {
    pub actor: ActorId,
    /// Generated stable field tag, independent of the field's source order.
    pub field: Hash,
    pub ordinal: u32,
    pub id: OperationId,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtMaterializationV2 {
    pub actor: ActorId,
    pub state: BlobRefV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationChangeV2 {
    pub actor: ActorId,
    pub expected: Option<Hash>,
    pub replacement: Option<BlobRefV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRecordV2 {
    pub call_id: CallId,
    pub caller_invocation: InvocationId,
    pub await_ordinal: u64,
    pub from: ActorId,
    pub to: ActorId,
    pub parent: Option<CallId>,
    pub payload: Vec<u8>,
    pub authorization: AuthorizationEvidenceV2,
    pub deadline_timeslot: Option<u64>,
}

impl MessageRecordV2 {
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        encode_message(&mut Encoder(&mut bytes), self);
        Hash::digest(b"vos/message/v2", &[&bytes])
    }

    /// Commitment carried by the source accumulation receipt. Delivery sends
    /// the complete canonical outbox, allowing destination Accumulate to
    /// authenticate membership without trusting native transport state.
    pub fn outbox_commitment(messages: &[Self]) -> Option<Hash> {
        if messages.is_empty() {
            return None;
        }
        let mut bytes = Vec::new();
        Encoder(&mut bytes).list(messages, encode_message);
        Some(Hash::digest(b"vos/outbox/v2", &[&bytes]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyRecordV2 {
    pub call_id: CallId,
    pub producer: ActorId,
    pub result: Vec<u8>,
}

impl ReplyRecordV2 {
    pub fn commitment(&self) -> Hash {
        let mut bytes = Vec::new();
        encode_reply(&mut Encoder(&mut bytes), self);
        Hash::digest(b"vos/reply/v2", &[&bytes])
    }
}

/// A reply released by another service only after its Accumulate commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulatedReplyV2 {
    pub reply: ReplyRecordV2,
    pub receipt: AccumulationReceiptV2,
}

/// Payload injected into the exact suspended protocol-call buffer after the
/// awaited result's accumulation receipt has been admitted as work input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwaitResumeV2 {
    pub checkpoint: CheckpointTokenV2,
    pub reply: ReplyRecordV2,
}

/// Exact public input passed to the platform's accumulation-receipt verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptVerificationRequestV2 {
    pub receipt: AccumulationReceiptV2,
}

impl ReceiptVerificationRequestV2 {
    pub fn hash(&self) -> Hash {
        Hash::digest(b"vos/receipt-verification/v2", &[&self.encode()])
    }
}

/// Fixed-schema workflow operations merged alongside application CRDT fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowOperationV2 {
    Consumed(WorkInputIdV2),
    Continuation(ContinuationChangeV2),
    Inbox(MessageRecordV2),
    Outbox(MessageRecordV2),
    Reply(ReplyRecordV2),
}

/// One atomic CRDT DAG payload for an entire actor execution slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtChangeV2 {
    pub id: ChangeId,
    pub causal_dependencies: Vec<Hash>,
    pub causal_height: u64,
    pub operations: Vec<CrdtOperationV2>,
    pub workflow: Vec<WorkflowOperationV2>,
    pub materializations: Vec<CrdtMaterializationV2>,
}

impl CrdtChangeV2 {
    pub fn derive_id(work: &WorkEnvelopeV2) -> Option<ChangeId> {
        let ConsistencyBaseV2::Crdt { heads } = &work.base else {
            return None;
        };
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        e.fixed(&work.service.root_service.0);
        e.fixed(&work.service.deployment.0);
        e.fixed(&work.target.0);
        e.fixed(&work.invocation.0);
        e.u64(work.workflow_step);
        e.list(heads, |e, head| e.fixed(&head.0));
        Some(ChangeId(
            Hash::digest(b"vos/crdt-change-id/v2", &[&bytes]).0,
        ))
    }

    pub fn derive_delivery_id(
        service: &ServiceIdentityV2,
        call: CallId,
        heads: &[Hash],
    ) -> ChangeId {
        let mut bytes = Vec::new();
        let mut e = Encoder(&mut bytes);
        e.fixed(&service.root_service.0);
        e.fixed(&service.deployment.0);
        e.fixed(&call.0);
        e.list(heads, |e, head| e.fixed(&head.0));
        ChangeId(Hash::digest(b"vos/crdt-delivery-id/v2", &[&bytes]).0)
    }

    pub fn cid(&self) -> Hash {
        Hash::digest(b"vos/crdt-dag-node/v2", &[&self.encode()])
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GasAccountingV2 {
    pub refine_used: u64,
    pub proof_used: u64,
    pub accumulate_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofCommitmentV2 {
    pub statement: Hash,
    pub trace: Hash,
    pub proof_blob: BlobRefV2,
    pub statement_version: u16,
}

/// Exact public inputs passed from guest Accumulate to the configured proof
/// verifier capability. Proof bytes remain content addressed and are read by
/// the host from `proof_blob`; the guest never trusts a host-supplied claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofVerificationRequestV2 {
    pub actor_program: ProgramId,
    pub execution_semantics: Hash,
    pub statement: Hash,
    pub trace: Hash,
    pub proof_blob: BlobRefV2,
}

impl ProofVerificationRequestV2 {
    pub fn hash(&self) -> Hash {
        Hash::digest(b"vos/proof-verification/v2", &[&self.encode()])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionV2 {
    pub service: ServiceIdentityV2,
    pub consumed_input: WorkInputIdV2,
    pub target_program: ProgramId,
    pub base: ConsistencyBaseV2,
    pub writes: Vec<ActorWriteV2>,
    pub crdt_change: Option<CrdtChangeV2>,
    pub continuations: Vec<ContinuationChangeV2>,
    pub inbox: Vec<MessageRecordV2>,
    pub outbox: Vec<MessageRecordV2>,
    pub reply: Option<ReplyRecordV2>,
    pub exported_blobs: Vec<BlobRefV2>,
    pub gas: GasAccountingV2,
    pub proof: Option<ProofCommitmentV2>,
}

impl TransitionV2 {
    /// Hash of the complete transport value, including an attached proof.
    /// This is useful for blob/cache identity but is deliberately not the
    /// value accepted by an accumulation receipt.
    pub fn hash(&self) -> Hash {
        let encoded = self.encode();
        Hash::digest(b"vos/transition-wire/v2", &[&encoded])
    }

    /// Consensus commitment to the actor execution before proof attachment.
    ///
    /// An attestation proves a statement containing the predicted accumulation
    /// receipt. The receipt therefore cannot commit to proof bytes which are
    /// generated from that same statement. Accumulate accepts this projection,
    /// while independently requiring and validating the proof for attested
    /// methods.
    pub fn commitment(&self) -> Hash {
        let mut candidate = self.clone();
        candidate.proof = None;
        Hash::digest(b"vos/transition/v2", &[&candidate.encode()])
    }

    pub fn workflow_operations(&self) -> Vec<WorkflowOperationV2> {
        let mut operations = Vec::with_capacity(
            1 + self.continuations.len()
                + self.inbox.len()
                + self.outbox.len()
                + usize::from(self.reply.is_some()),
        );
        operations.push(WorkflowOperationV2::Consumed(self.consumed_input));
        operations.extend(
            self.continuations
                .iter()
                .cloned()
                .map(WorkflowOperationV2::Continuation),
        );
        operations.extend(self.inbox.iter().cloned().map(WorkflowOperationV2::Inbox));
        operations.extend(self.outbox.iter().cloned().map(WorkflowOperationV2::Outbox));
        operations.extend(self.reply.iter().cloned().map(WorkflowOperationV2::Reply));
        operations.sort_by_key(workflow_operation_bytes);
        operations
    }
}

/// Pure physical Refine output. Candidate blob bytes are carried alongside
/// the transition instead of being written through a protocol capability;
/// Accumulate must independently validate and stage them before commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefineOutputV2 {
    pub transition: TransitionV2,
    pub candidate_blobs: Vec<ImportedBlobV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulationReceiptV2 {
    pub service: ServiceIdentityV2,
    pub accepted_transition: Hash,
    /// Direct commitment to the reply released after this commit. This lets a
    /// caller validate a transported result without importing the full source
    /// transition; `accepted_transition` continues to bind every other effect.
    pub reply_commitment: Option<Hash>,
    /// Commitment to the complete canonical outbox released after this
    /// transition committed. Cross-root delivery supplies those exact records
    /// and a finalized receipt to destination Accumulate.
    pub outbox_commitment: Option<Hash>,
    pub resulting_state_root: Option<Hash>,
    pub resulting_crdt_heads: Vec<Hash>,
    pub sequence: u64,
    pub checkpoint: u64,
    pub consistency: ConsistencyModeV2,
}

/// Generated policy bound to one actor method at service installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodPolicyV2 {
    pub method: String,
    pub schema: Hash,
    pub policy: Hash,
    pub public: bool,
    pub attested: bool,
}

/// One canonical actor installed into the root actor tree owned by a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorGenesisV2 {
    pub actor: ActorId,
    /// Stable name within the parent's owned namespace. The one root actor's
    /// name is unique in the service root namespace.
    pub name: String,
    /// `None` identifies the single root actor; every child names an actor in
    /// the same genesis tree.
    pub parent: Option<ActorId>,
    pub program: ProgramId,
    pub initial_state: BlobRefV2,
    pub crdt: bool,
    pub methods: Vec<MethodPolicyV2>,
}

/// Clean-break initialization accepted only by an empty v2 service store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceGenesisV2 {
    pub service: ServiceIdentityV2,
    pub consistency: ConsistencyModeV2,
    pub actors: Vec<ActorGenesisV2>,
    pub authorization: AuthorizationEvidenceV2,
}

/// Complete input required by guest-owned Accumulate to validate a Refine
/// result. The host does not supply a journal or a native apply plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulationEnvelopeV2 {
    pub work: WorkEnvelopeV2,
    pub transition: TransitionV2,
    /// Candidate content-addressed bytes produced by Refine or its exact JAR
    /// snapshot boundary. They remain unobservable unless this Accumulate
    /// transaction commits.
    pub provided_blobs: Vec<ImportedBlobV2>,
}

/// Authenticated cross-root admission input. The destination service guest,
/// not the native transport, validates the finalized source receipt and
/// atomically creates the durable inbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryEnvelopeV2 {
    pub service: ServiceIdentityV2,
    pub logical_timeslot: u64,
    pub base: ConsistencyBaseV2,
    pub base_causal_height: Option<u64>,
    pub message: MessageRecordV2,
    pub source_outbox: Vec<MessageRecordV2>,
    pub source_receipt: AccumulationReceiptV2,
    /// Workflow-only causal node for CRDT services. Linear services require
    /// this to be absent.
    pub crdt_change: Option<CrdtChangeV2>,
}

impl DeliveryEnvelopeV2 {
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/delivery/v2", &[&self.encode()])
    }
}

/// Physical IC-5 request. Every service-state mutation, including external
/// message admission, passes through one of these guest-owned operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulateRequestV2 {
    Install(ServiceGenesisV2),
    Apply(AccumulationEnvelopeV2),
    PrepareAttested(AccumulationEnvelopeV2),
    Deliver(DeliveryEnvelopeV2),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishedEffectsV2 {
    pub reply: Option<ReplyRecordV2>,
    pub outbox: Vec<MessageRecordV2>,
    pub exported_blobs: Vec<BlobRefV2>,
    pub proof: Option<ProofCommitmentV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstallReceiptV2 {
    pub service: ServiceIdentityV2,
    pub consistency: ConsistencyModeV2,
    pub resulting_state_root: Option<Hash>,
    pub resulting_crdt_heads: Vec<Hash>,
}

/// Stable rejection codes returned without committing guest storage writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulationRejectionV2 {
    StoreAlreadyInitialized,
    StoreUninitialized,
    WrongService,
    WrongAbi,
    WrongExecutionSemantics,
    WrongProgram,
    InvalidConsistency,
    Unauthorized,
    MissingBlob(Hash),
    MissingProof,
    ProofUnavailable,
    InvalidProof,
    StaleLinearWork {
        expected_revision: u64,
        actual_revision: u64,
    },
    StaleStateRoot,
    MissingCausalDependency(Hash),
    TransitionInputMismatch,
    TransitionBaseMismatch,
    DivergentDuplicate,
    InvalidWorkflowTransition,
    ContinuationConflict(ActorId),
    MessageCycle,
    StorageFull,
    SequenceOverflow,
    NonCanonical,
    ReceiptUnavailable,
    InvalidReceipt,
}

impl AccumulationRejectionV2 {
    /// A retry can succeed without changing the submitted logical operation.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::StaleLinearWork { .. }
                | Self::StaleStateRoot
                | Self::MissingBlob(_)
                | Self::MissingCausalDependency(_)
                | Self::ContinuationConflict(_)
                | Self::StorageFull
                | Self::ProofUnavailable
                | Self::ReceiptUnavailable
        )
    }
}

/// Guest output. Only `Installed` and `Accepted` authorize the local driver to
/// commit its isolated transaction; `Prepared` and `Rejected` are read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulationResultV2 {
    Installed(ServiceInstallReceiptV2),
    Accepted {
        receipt: AccumulationReceiptV2,
        published: PublishedEffectsV2,
        duplicate: bool,
    },
    Prepared(AccumulationReceiptV2),
    Rejected(AccumulationRejectionV2),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefineError {
    WrongAbi,
    WrongExecutionSemantics,
    MissingImport(Hash),
    InvalidImport(Hash),
    NonCanonicalImports,
    InvalidConsistency,
    Execution(Vec<u8>),
}

impl core::fmt::Display for RefineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "refine failed: {self:?}")
    }
}

impl core::error::Error for RefineError {}

impl RefineImportsV2 {
    /// Verify that Refine has every byte named by the work envelope and that
    /// no imported code/blob can masquerade under a different content ID.
    pub fn validate_for(&self, work: &WorkEnvelopeV2) -> Result<(), RefineError> {
        if work.service.service_abi != super::ABI_VERSION {
            return Err(RefineError::WrongAbi);
        }
        if work.service.execution_semantics != super::EXECUTION_SEMANTICS_ID {
            return Err(RefineError::WrongExecutionSemantics);
        }
        if !work.base.mode_compatible(work.consistency) {
            return Err(RefineError::InvalidConsistency);
        }

        if self
            .programs
            .windows(2)
            .any(|pair| pair[0].program >= pair[1].program)
            || self
                .blobs
                .windows(2)
                .any(|pair| pair[0].reference.hash >= pair[1].reference.hash)
        {
            return Err(RefineError::NonCanonicalImports);
        }
        for imported in &self.programs {
            if imported.pvm.is_empty() || ProgramId::of_pvm(&imported.pvm) != imported.program {
                return Err(RefineError::InvalidImport(Hash(imported.program.0)));
            }
        }
        for imported in &self.blobs {
            if !imported.reference.matches(&imported.bytes) {
                return Err(RefineError::InvalidImport(imported.reference.hash));
            }
        }

        let target = work
            .imported_actors
            .iter()
            .find(|actor| actor.actor == work.target)
            .ok_or(RefineError::MissingImport(Hash(work.target.0)))?;
        if target.program != work.target_program {
            return Err(RefineError::InvalidImport(Hash(target.program.0)));
        }

        for actor in &work.imported_actors {
            if self
                .programs
                .binary_search_by_key(&actor.program, |program| program.program)
                .is_err()
            {
                return Err(RefineError::MissingImport(Hash(actor.program.0)));
            }
            self.require_blob(&actor.state)?;
            for state in &actor.causal_states {
                self.require_blob(state)?;
            }
            if let Some(continuation) = &actor.continuation {
                self.require_blob(continuation)?;
            }
        }
        for reference in &work.imported_blobs {
            self.require_blob(reference)?;
        }
        Ok(())
    }

    fn require_blob(&self, reference: &BlobRefV2) -> Result<(), RefineError> {
        let imported = self
            .blobs
            .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
            .ok()
            .map(|index| &self.blobs[index])
            .ok_or(RefineError::MissingImport(reference.hash))?;
        if imported.reference != *reference {
            return Err(RefineError::InvalidImport(reference.hash));
        }
        Ok(())
    }
}

impl V2Wire for WorkEnvelopeV2 {
    const MAGIC: [u8; 4] = *b"VWK2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.invocation.0);
        e.u64(self.workflow_step);
        e.u64(self.logical_timeslot);
        e.fixed(&self.target.0);
        e.fixed(&self.target_program.0);
        e.string(&self.method);
        e.bytes(&self.arguments);
        encode_origin(&mut e, self.origin);
        encode_auth(&mut e, &self.authorization);
        e.option(&self.causal_parent, |e, id| e.fixed(&id.0));
        e.option(&self.parent_call, |e, id| e.fixed(&id.0));
        e.option(&self.awaited_reply, |e, reply| e.bytes(&reply.encode()));
        e.u8(self.consistency as u8);
        encode_base(&mut e, &self.base);
        e.option(&self.base_causal_height, |e, height| e.u64(*height));
        e.list(&self.imported_actors, encode_imported_actor);
        e.list(&self.imported_blobs, encode_blob_ref);
        e.bool(self.proof_requested);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let service = decode_service(d)?;
        let invocation = InvocationId(d.fixed()?);
        let workflow_step = d.u64()?;
        let logical_timeslot = d.u64()?;
        let target = ActorId(d.fixed()?);
        let target_program = ProgramId(d.fixed()?);
        let method = d.string()?;
        if method.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        let arguments = d.bytes()?;
        let origin = decode_origin(d)?;
        let authorization = decode_auth(d)?;
        let causal_parent = d.option(|d| d.fixed().map(InvocationId))?;
        let parent_call = d.option(|d| d.fixed().map(CallId))?;
        let awaited_reply = d.option(|d| AccumulatedReplyV2::decode(&d.bytes()?))?;
        if awaited_reply.is_some() && workflow_step == 0 {
            return Err(DecodeError::NonCanonical);
        }
        let consistency = ConsistencyModeV2::decode(d)?;
        let base = decode_base(d)?;
        if !base.mode_compatible(consistency) {
            return Err(DecodeError::NonCanonical);
        }
        let base_causal_height = d.option(Decoder::u64)?;
        match (&base, base_causal_height) {
            (ConsistencyBaseV2::Linear { .. }, None) => {}
            (ConsistencyBaseV2::Crdt { heads }, Some(0)) if heads.is_empty() => {}
            (ConsistencyBaseV2::Crdt { heads }, Some(height))
                if !heads.is_empty() && height != 0 => {}
            _ => return Err(DecodeError::NonCanonical),
        }
        let imported_actors = d.list(decode_imported_actor)?;
        let imported_blobs = d.list(decode_blob_ref)?;
        let proof_requested = d.bool()?;
        ensure_sorted_unique(&imported_actors, |actor| actor.actor.0)?;
        ensure_sorted_unique(&imported_blobs, |b| b.hash.0)?;
        if let AuthorizationEvidenceV2::PrivateCredential { witness, .. } = &authorization {
            let present = imported_blobs
                .binary_search_by_key(&witness.hash, |blob| blob.hash)
                .ok()
                .is_some_and(|index| imported_blobs[index] == *witness);
            if !proof_requested || !present {
                return Err(DecodeError::NonCanonical);
            }
        }
        for actor in &imported_actors {
            ensure_sorted_unique(&actor.causal_states, |state| state.hash.0)?;
            if actor
                .causal_states
                .iter()
                .any(|state| state.hash == actor.state.hash)
                || actor
                    .causal_states
                    .first()
                    .is_some_and(|state| state.hash <= actor.state.hash)
                || (consistency != ConsistencyModeV2::Crdt && !actor.causal_states.is_empty())
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        Ok(Self {
            service,
            invocation,
            workflow_step,
            logical_timeslot,
            target,
            target_program,
            method,
            arguments,
            origin,
            authorization,
            causal_parent,
            parent_call,
            awaited_reply,
            consistency,
            base,
            base_causal_height,
            imported_actors,
            imported_blobs,
            proof_requested,
        })
    }
}

impl V2Wire for RefineImportsV2 {
    const MAGIC: [u8; 4] = *b"VRI2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.list(&self.programs, |e, program| {
            e.fixed(&program.program.0);
            e.bytes(&program.pvm);
        });
        e.list(&self.blobs, |e, blob| {
            encode_blob_ref(e, &blob.reference);
            e.bytes(&blob.bytes);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            programs: d.list(|d| {
                Ok(ImportedProgramV2 {
                    program: ProgramId(d.fixed()?),
                    pvm: d.bytes()?,
                })
            })?,
            blobs: d.list(|d| {
                Ok(ImportedBlobV2 {
                    reference: decode_blob_ref(d)?,
                    bytes: d.bytes()?,
                })
            })?,
        };
        ensure_sorted_unique(&value.programs, |program| program.program.0)?;
        ensure_sorted_unique(&value.blobs, |blob| blob.reference.hash.0)?;
        for program in &value.programs {
            if program.pvm.is_empty() || ProgramId::of_pvm(&program.pvm) != program.program {
                return Err(DecodeError::NonCanonical);
            }
        }
        if value
            .blobs
            .iter()
            .any(|blob| !blob.reference.matches(&blob.bytes))
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for ActorSliceInputV2 {
    const MAGIC: [u8; 4] = *b"VSI2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.actor.0);
        e.option(&self.change, |e, change| e.fixed(&change.0));
        e.bytes(&self.state);
        e.list(&self.causal_states, |e, state| e.bytes(state));
        e.bytes(&self.message);
        encode_origin(&mut e, self.origin);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor: ActorId(d.fixed()?),
            change: d.option(|d| d.fixed().map(ChangeId))?,
            state: d.bytes()?,
            causal_states: d.list(Decoder::bytes)?,
            message: d.bytes()?,
            origin: decode_origin(d)?,
        };
        if value.change.is_none() && !value.causal_states.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for ActorSliceOutputV2 {
    const MAGIC: [u8; 4] = *b"VSO2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.actor.0);
        e.list(&self.writes, encode_write);
        e.list(&self.crdt_operations, encode_crdt_op);
        e.option(&self.crdt_materialization, |e, state| e.bytes(state));
        e.list(&self.outbox, encode_actor_call);
        e.bytes(&self.reply);
        e.bool(self.yielded);
        e.bool(self.forbidden);
        e.option(&self.checkpoint, encode_checkpoint_token);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor: ActorId(d.fixed()?),
            writes: d.list(decode_write)?,
            crdt_operations: d.list(decode_crdt_op)?,
            crdt_materialization: d.option(Decoder::bytes)?,
            outbox: d.list(decode_actor_call)?,
            reply: d.bytes()?,
            yielded: d.bool()?,
            forbidden: d.bool()?,
            checkpoint: d.option(decode_checkpoint_token)?,
        };
        if value.writes.iter().any(|write| write.actor != value.actor)
            || value
                .crdt_operations
                .iter()
                .any(|operation| operation.actor != value.actor || operation.payload.is_empty())
            || value
                .crdt_operations
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || value
                .outbox
                .windows(2)
                .any(|pair| pair[0].await_ordinal >= pair[1].await_ordinal)
            || value.outbox.iter().any(|call| call.payload.is_empty())
            || (!value.crdt_operations.is_empty() && value.crdt_materialization.is_none())
            || (value.yielded
                && value
                    .checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.replacement.as_ref())
                    .is_none())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for CheckpointTokenV2 {
    const MAGIC: [u8; 4] = *b"VCP2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        encode_checkpoint_token(&mut Encoder(out), self);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_checkpoint_token(d)
    }
}

impl V2Wire for AwaitResumeV2 {
    const MAGIC: [u8; 4] = *b"VRS2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_checkpoint_token(&mut e, &self.checkpoint);
        encode_reply(&mut e, &self.reply);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            checkpoint: decode_checkpoint_token(d)?,
            reply: decode_reply(d)?,
        };
        if value.checkpoint.pending_call != Some(value.reply.call_id) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for TransitionV2 {
    const MAGIC: [u8; 4] = *b"VTR2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.consumed_input.invocation.0);
        e.u64(self.consumed_input.workflow_step);
        e.fixed(&self.target_program.0);
        encode_base(&mut e, &self.base);
        e.list(&self.writes, encode_write);
        e.option(&self.crdt_change, |e, change| e.bytes(&change.encode()));
        e.list(&self.continuations, encode_continuation_change);
        e.list(&self.inbox, encode_message);
        e.list(&self.outbox, encode_message);
        e.option(&self.reply, encode_reply);
        e.list(&self.exported_blobs, encode_blob_ref);
        e.u64(self.gas.refine_used);
        e.u64(self.gas.proof_used);
        e.u64(self.gas.accumulate_used);
        e.option(&self.proof, encode_proof);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let result = Self {
            service: decode_service(d)?,
            consumed_input: WorkInputIdV2 {
                invocation: InvocationId(d.fixed()?),
                workflow_step: d.u64()?,
            },
            target_program: ProgramId(d.fixed()?),
            base: decode_base(d)?,
            writes: d.list(decode_write)?,
            crdt_change: d.option(|d| CrdtChangeV2::decode(&d.bytes()?))?,
            continuations: d.list(decode_continuation_change)?,
            inbox: d.list(decode_message)?,
            outbox: d.list(decode_message)?,
            reply: d.option(decode_reply)?,
            exported_blobs: d.list(decode_blob_ref)?,
            gas: GasAccountingV2 {
                refine_used: d.u64()?,
                proof_used: d.u64()?,
                accumulate_used: d.u64()?,
            },
            proof: d.option(decode_proof)?,
        };
        ensure_sorted_unique(&result.exported_blobs, |b| b.hash.0)?;
        Ok(result)
    }
}

impl V2Wire for RefineOutputV2 {
    const MAGIC: [u8; 4] = *b"VRO2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.bytes(&self.transition.encode());
        e.list(&self.candidate_blobs, |e, blob| {
            encode_blob_ref(e, &blob.reference);
            e.bytes(&blob.bytes);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            transition: TransitionV2::decode(&d.bytes()?)?,
            candidate_blobs: d.list(|d| {
                Ok(ImportedBlobV2 {
                    reference: decode_blob_ref(d)?,
                    bytes: d.bytes()?,
                })
            })?,
        };
        validate_candidate_blobs(&value.transition, &value.candidate_blobs)?;
        Ok(value)
    }
}

impl V2Wire for CrdtChangeV2 {
    const MAGIC: [u8; 4] = *b"VCG2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.id.0);
        e.list(&self.causal_dependencies, |e, dependency| {
            e.fixed(&dependency.0)
        });
        e.u64(self.causal_height);
        e.list(&self.operations, encode_crdt_op);
        e.list(&self.workflow, encode_workflow_operation);
        e.list(&self.materializations, |e, materialization| {
            e.fixed(&materialization.actor.0);
            encode_blob_ref(e, &materialization.state);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            id: ChangeId(d.fixed()?),
            causal_dependencies: d.list(|d| d.fixed().map(Hash))?,
            causal_height: d.u64()?,
            operations: d.list(decode_crdt_op)?,
            workflow: d.list(decode_workflow_operation)?,
            materializations: d.list(|d| {
                Ok(CrdtMaterializationV2 {
                    actor: ActorId(d.fixed()?),
                    state: decode_blob_ref(d)?,
                })
            })?,
        };
        ensure_sorted_unique(&value.causal_dependencies, |hash| hash.0)?;
        ensure_sorted_unique(&value.operations, |operation| operation.id.0)?;
        ensure_sorted_unique(&value.materializations, |materialization| {
            materialization.actor.0
        })?;
        if value.causal_height == 0
            || value.operations.iter().any(|operation| {
                operation.payload.is_empty()
                    || operation.id
                        != value
                            .id
                            .operation(operation.actor, operation.field, operation.ordinal)
            })
            || value.workflow.windows(2).any(|pair| {
                workflow_operation_bytes(&pair[0]) >= workflow_operation_bytes(&pair[1])
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for BlobRefV2 {
    const MAGIC: [u8; 4] = *b"VBR2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        encode_blob_ref(&mut Encoder(out), self);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_blob_ref(d)
    }
}

impl V2Wire for MethodPolicyV2 {
    const MAGIC: [u8; 4] = *b"VMP2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.string(&self.method);
        e.fixed(&self.schema.0);
        e.fixed(&self.policy.0);
        e.bool(self.public);
        e.bool(self.attested);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            method: d.string()?,
            schema: Hash(d.fixed()?),
            policy: Hash(d.fixed()?),
            public: d.bool()?,
            attested: d.bool()?,
        };
        if value.method.is_empty() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for ActorGenesisV2 {
    const MAGIC: [u8; 4] = *b"VAG2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        encode_actor_genesis(&mut Encoder(out), self);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_actor_genesis(d)
    }
}

impl V2Wire for MessageRecordV2 {
    const MAGIC: [u8; 4] = *b"VMR2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        encode_message(&mut Encoder(out), self);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_message(d)
    }
}

impl V2Wire for AccumulatedReplyV2 {
    const MAGIC: [u8; 4] = *b"VRP2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_reply(&mut e, &self.reply);
        e.bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            reply: decode_reply(d)?,
            receipt: AccumulationReceiptV2::decode(&d.bytes()?)?,
        };
        if value.receipt.reply_commitment != Some(value.reply.commitment()) {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for AccumulationReceiptV2 {
    const MAGIC: [u8; 4] = *b"VAR2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.accepted_transition.0);
        e.option(&self.reply_commitment, |e, hash| e.fixed(&hash.0));
        e.option(&self.outbox_commitment, |e, hash| e.fixed(&hash.0));
        e.option(&self.resulting_state_root, |e, h| e.fixed(&h.0));
        e.list(&self.resulting_crdt_heads, |e, h| e.fixed(&h.0));
        e.u64(self.sequence);
        e.u64(self.checkpoint);
        e.u8(self.consistency as u8);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            accepted_transition: Hash(d.fixed()?),
            reply_commitment: d.option(|d| d.fixed().map(Hash))?,
            outbox_commitment: d.option(|d| d.fixed().map(Hash))?,
            resulting_state_root: d.option(|d| d.fixed().map(Hash))?,
            resulting_crdt_heads: d.list(|d| d.fixed().map(Hash))?,
            sequence: d.u64()?,
            checkpoint: d.u64()?,
            consistency: ConsistencyModeV2::decode(d)?,
        };
        ensure_sorted_unique(&value.resulting_crdt_heads, |h| h.0)?;
        validate_result_commitment(
            value.consistency,
            value.resulting_state_root,
            &value.resulting_crdt_heads,
        )?;
        Ok(value)
    }
}

impl V2Wire for ReceiptVerificationRequestV2 {
    const MAGIC: [u8; 4] = *b"VRV2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        Encoder(out).bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            receipt: AccumulationReceiptV2::decode(&d.bytes()?)?,
        })
    }
}

impl V2Wire for ProofVerificationRequestV2 {
    const MAGIC: [u8; 4] = *b"VPV2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.actor_program.0);
        e.fixed(&self.execution_semantics.0);
        e.fixed(&self.statement.0);
        e.fixed(&self.trace.0);
        encode_blob_ref(&mut e, &self.proof_blob);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor_program: ProgramId(d.fixed()?),
            execution_semantics: Hash(d.fixed()?),
            statement: Hash(d.fixed()?),
            trace: Hash(d.fixed()?),
            proof_blob: decode_blob_ref(d)?,
        };
        if value.statement == Hash::ZERO || value.trace == Hash::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for ServiceGenesisV2 {
    const MAGIC: [u8; 4] = *b"VGN2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.u8(self.consistency as u8);
        e.list(&self.actors, encode_actor_genesis);
        encode_auth(&mut e, &self.authorization);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            consistency: ConsistencyModeV2::decode(d)?,
            actors: d.list(decode_actor_genesis)?,
            authorization: decode_auth(d)?,
        };
        validate_genesis(&value)?;
        Ok(value)
    }
}

impl V2Wire for AccumulationEnvelopeV2 {
    const MAGIC: [u8; 4] = *b"VAE2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.bytes(&self.work.encode());
        e.bytes(&self.transition.encode());
        e.list(&self.provided_blobs, |e, blob| {
            encode_blob_ref(e, &blob.reference);
            e.bytes(&blob.bytes);
        });
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            work: WorkEnvelopeV2::decode(&d.bytes()?)?,
            transition: TransitionV2::decode(&d.bytes()?)?,
            provided_blobs: d.list(|d| {
                Ok(ImportedBlobV2 {
                    reference: decode_blob_ref(d)?,
                    bytes: d.bytes()?,
                })
            })?,
        };
        validate_accumulation_envelope(&value)?;
        Ok(value)
    }
}

impl V2Wire for DeliveryEnvelopeV2 {
    const MAGIC: [u8; 4] = *b"VDL2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.u64(self.logical_timeslot);
        encode_base(&mut e, &self.base);
        e.option(&self.base_causal_height, |e, height| e.u64(*height));
        encode_message(&mut e, &self.message);
        e.list(&self.source_outbox, encode_message);
        e.bytes(&self.source_receipt.encode());
        e.option(&self.crdt_change, |e, change| e.bytes(&change.encode()));
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            logical_timeslot: d.u64()?,
            base: decode_base(d)?,
            base_causal_height: d.option(Decoder::u64)?,
            message: decode_message(d)?,
            source_outbox: d.list(decode_message)?,
            source_receipt: AccumulationReceiptV2::decode(&d.bytes()?)?,
            crdt_change: d.option(|d| CrdtChangeV2::decode(&d.bytes()?))?,
        };
        ensure_sorted_unique(&value.source_outbox, |message| message.call_id.0)?;
        if value
            .source_outbox
            .binary_search_by_key(&value.message.call_id, |message| message.call_id)
            .ok()
            .is_none_or(|index| value.source_outbox[index] != value.message)
            || value.source_receipt.outbox_commitment
                != MessageRecordV2::outbox_commitment(&value.source_outbox)
        {
            return Err(DecodeError::NonCanonical);
        }
        match (&value.base, value.base_causal_height, &value.crdt_change) {
            (ConsistencyBaseV2::Linear { .. }, None, None) => {}
            (ConsistencyBaseV2::Crdt { heads }, Some(height), Some(change))
                if change.id
                    == CrdtChangeV2::derive_delivery_id(
                        &value.service,
                        value.message.call_id,
                        heads,
                    )
                    && change.causal_dependencies == *heads
                    && height.checked_add(1) == Some(change.causal_height)
                    && change.operations.is_empty()
                    && change.materializations.is_empty()
                    && change.workflow == [WorkflowOperationV2::Inbox(value.message.clone())] => {}
            _ => return Err(DecodeError::NonCanonical),
        }
        Ok(value)
    }
}

impl V2Wire for AccumulateRequestV2 {
    const MAGIC: [u8; 4] = *b"VAC2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        match self {
            Self::Install(genesis) => {
                e.u8(0);
                e.bytes(&genesis.encode());
            }
            Self::Apply(envelope) => {
                e.u8(1);
                e.bytes(&envelope.encode());
            }
            Self::PrepareAttested(envelope) => {
                e.u8(2);
                e.bytes(&envelope.encode());
            }
            Self::Deliver(envelope) => {
                e.u8(3);
                e.bytes(&envelope.encode());
            }
        }
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.u8()? {
            0 => Ok(Self::Install(ServiceGenesisV2::decode(&d.bytes()?)?)),
            1 => Ok(Self::Apply(AccumulationEnvelopeV2::decode(&d.bytes()?)?)),
            2 => Ok(Self::PrepareAttested(AccumulationEnvelopeV2::decode(
                &d.bytes()?,
            )?)),
            3 => Ok(Self::Deliver(DeliveryEnvelopeV2::decode(&d.bytes()?)?)),
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

impl V2Wire for PublishedEffectsV2 {
    const MAGIC: [u8; 4] = *b"VEF2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.option(&self.reply, encode_reply);
        e.list(&self.outbox, encode_message);
        e.list(&self.exported_blobs, encode_blob_ref);
        e.option(&self.proof, encode_proof);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            reply: d.option(decode_reply)?,
            outbox: d.list(decode_message)?,
            exported_blobs: d.list(decode_blob_ref)?,
            proof: d.option(decode_proof)?,
        };
        ensure_sorted_unique(&value.outbox, |message| message.call_id.0)?;
        ensure_sorted_unique(&value.exported_blobs, |blob| blob.hash.0)?;
        Ok(value)
    }
}

impl V2Wire for AccumulationResultV2 {
    const MAGIC: [u8; 4] = *b"VAO2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        match self {
            Self::Installed(receipt) => {
                e.u8(0);
                encode_install_receipt(&mut e, receipt);
            }
            Self::Accepted {
                receipt,
                published,
                duplicate,
            } => {
                e.u8(1);
                e.bytes(&receipt.encode());
                e.bytes(&published.encode());
                e.bool(*duplicate);
            }
            Self::Prepared(receipt) => {
                e.u8(2);
                e.bytes(&receipt.encode());
            }
            Self::Rejected(rejection) => {
                e.u8(3);
                encode_rejection(&mut e, rejection);
            }
        }
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.u8()? {
            0 => Ok(Self::Installed(decode_install_receipt(d)?)),
            1 => {
                let receipt = AccumulationReceiptV2::decode(&d.bytes()?)?;
                let published = PublishedEffectsV2::decode(&d.bytes()?)?;
                let duplicate = d.bool()?;
                if duplicate && published != PublishedEffectsV2::default() {
                    return Err(DecodeError::NonCanonical);
                }
                if !duplicate
                    && (published.reply.as_ref().map(ReplyRecordV2::commitment)
                        != receipt.reply_commitment
                        || MessageRecordV2::outbox_commitment(&published.outbox)
                            != receipt.outbox_commitment)
                {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::Accepted {
                    receipt,
                    published,
                    duplicate,
                })
            }
            2 => Ok(Self::Prepared(AccumulationReceiptV2::decode(&d.bytes()?)?)),
            3 => Ok(Self::Rejected(decode_rejection(d)?)),
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

fn encode_actor_genesis(e: &mut Encoder<'_>, value: &ActorGenesisV2) {
    e.fixed(&value.actor.0);
    e.string(&value.name);
    e.option(&value.parent, |e, parent| e.fixed(&parent.0));
    e.fixed(&value.program.0);
    encode_blob_ref(e, &value.initial_state);
    e.bool(value.crdt);
    e.list(&value.methods, |e, method| {
        e.string(&method.method);
        e.fixed(&method.schema.0);
        e.fixed(&method.policy.0);
        e.bool(method.public);
        e.bool(method.attested);
    });
}

fn decode_actor_genesis(d: &mut Decoder<'_>) -> Result<ActorGenesisV2, DecodeError> {
    let value = ActorGenesisV2 {
        actor: ActorId(d.fixed()?),
        name: d.string()?,
        parent: d.option(|d| d.fixed().map(ActorId))?,
        program: ProgramId(d.fixed()?),
        initial_state: decode_blob_ref(d)?,
        crdt: d.bool()?,
        methods: d.list(|d| {
            Ok(MethodPolicyV2 {
                method: d.string()?,
                schema: Hash(d.fixed()?),
                policy: Hash(d.fixed()?),
                public: d.bool()?,
                attested: d.bool()?,
            })
        })?,
    };
    if value.name.is_empty()
        || value.methods.iter().any(|method| method.method.is_empty())
        || value
            .methods
            .windows(2)
            .any(|pair| pair[0].method >= pair[1].method)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn validate_genesis(value: &ServiceGenesisV2) -> Result<(), DecodeError> {
    if value.actors.is_empty() {
        return Err(DecodeError::NonCanonical);
    }
    ensure_sorted_unique(&value.actors, |actor| actor.actor.0)?;
    let roots: Vec<_> = value
        .actors
        .iter()
        .filter(|actor| actor.parent.is_none())
        .map(|actor| actor.actor)
        .collect();
    if roots.len() != 1 {
        return Err(DecodeError::NonCanonical);
    }
    let root = roots[0];
    let known: BTreeSet<_> = value.actors.iter().map(|actor| actor.actor).collect();
    let mut names = BTreeSet::new();
    for actor in &value.actors {
        if value.consistency == ConsistencyModeV2::Crdt && !actor.crdt {
            return Err(DecodeError::NonCanonical);
        }
        if actor.name.is_empty()
            || !names.insert((actor.parent, actor.name.as_str()))
            || actor.parent == Some(actor.actor)
            || actor.parent.is_some_and(|parent| !known.contains(&parent))
        {
            return Err(DecodeError::NonCanonical);
        }
        let mut cursor = actor.actor;
        for _ in 0..value.actors.len() {
            if cursor == root {
                break;
            }
            let parent = value
                .actors
                .iter()
                .find(|candidate| candidate.actor == cursor)
                .and_then(|candidate| candidate.parent)
                .ok_or(DecodeError::NonCanonical)?;
            cursor = parent;
        }
        if cursor != root {
            return Err(DecodeError::NonCanonical);
        }
    }
    match &value.authorization {
        AuthorizationEvidenceV2::SystemCapability { authenticator, .. }
            if !authenticator.is_empty() =>
        {
            Ok(())
        }
        _ => Err(DecodeError::NonCanonical),
    }
}

fn validate_accumulation_envelope(value: &AccumulationEnvelopeV2) -> Result<(), DecodeError> {
    if value.work.service != value.transition.service
        || value.work.input_id() != value.transition.consumed_input
        || value.work.target_program != value.transition.target_program
        || value.work.base != value.transition.base
        || !value.work.base.mode_compatible(value.work.consistency)
    {
        return Err(DecodeError::NonCanonical);
    }
    match (&value.work.base, &value.transition.crdt_change) {
        (ConsistencyBaseV2::Crdt { heads }, Some(change))
            if value.work.consistency == ConsistencyModeV2::Crdt
                && value.transition.writes.is_empty()
                && Some(change.id) == CrdtChangeV2::derive_id(&value.work)
                && change.causal_dependencies.as_slice() == heads.as_slice()
                && value
                    .work
                    .base_causal_height
                    .and_then(|height| height.checked_add(1))
                    == Some(change.causal_height)
                && change.workflow == value.transition.workflow_operations() =>
        {
            Ok(())
        }
        (ConsistencyBaseV2::Linear { .. }, None)
            if value.work.consistency != ConsistencyModeV2::Crdt =>
        {
            Ok(())
        }
        _ => Err(DecodeError::NonCanonical),
    }?;
    validate_candidate_blobs(&value.transition, &value.provided_blobs)?;
    Ok(())
}

fn validate_candidate_blobs(
    transition: &TransitionV2,
    candidates: &[ImportedBlobV2],
) -> Result<(), DecodeError> {
    ensure_sorted_unique(candidates, |blob| blob.reference.hash.0)?;
    for candidate in candidates {
        if !candidate.reference.matches(&candidate.bytes)
            || !transition_blob_references(transition)
                .any(|reference| reference == &candidate.reference)
        {
            return Err(DecodeError::NonCanonical);
        }
    }
    Ok(())
}

fn transition_blob_references(transition: &TransitionV2) -> impl Iterator<Item = &BlobRefV2> {
    transition
        .exported_blobs
        .iter()
        .chain(
            transition
                .continuations
                .iter()
                .filter_map(|change| change.replacement.as_ref()),
        )
        .chain(
            transition
                .crdt_change
                .iter()
                .flat_map(|change| change.materializations.iter())
                .map(|materialization| &materialization.state),
        )
        .chain(transition.proof.iter().map(|proof| &proof.proof_blob))
}

fn encode_install_receipt(e: &mut Encoder<'_>, value: &ServiceInstallReceiptV2) {
    encode_service(e, &value.service);
    e.u8(value.consistency as u8);
    e.option(&value.resulting_state_root, |e, root| e.fixed(&root.0));
    e.list(&value.resulting_crdt_heads, |e, head| e.fixed(&head.0));
}

fn decode_install_receipt(d: &mut Decoder<'_>) -> Result<ServiceInstallReceiptV2, DecodeError> {
    let value = ServiceInstallReceiptV2 {
        service: decode_service(d)?,
        consistency: ConsistencyModeV2::decode(d)?,
        resulting_state_root: d.option(|d| d.fixed().map(Hash))?,
        resulting_crdt_heads: d.list(|d| d.fixed().map(Hash))?,
    };
    ensure_sorted_unique(&value.resulting_crdt_heads, |head| head.0)?;
    validate_result_commitment(
        value.consistency,
        value.resulting_state_root,
        &value.resulting_crdt_heads,
    )?;
    Ok(value)
}

fn validate_result_commitment(
    consistency: ConsistencyModeV2,
    state_root: Option<Hash>,
    crdt_heads: &[Hash],
) -> Result<(), DecodeError> {
    let valid = match consistency {
        ConsistencyModeV2::Crdt => state_root.is_none(),
        ConsistencyModeV2::Ephemeral | ConsistencyModeV2::Local | ConsistencyModeV2::Raft => {
            state_root.is_some() && crdt_heads.is_empty()
        }
    };
    valid.then_some(()).ok_or(DecodeError::NonCanonical)
}

fn encode_rejection(e: &mut Encoder<'_>, value: &AccumulationRejectionV2) {
    use AccumulationRejectionV2 as R;
    match value {
        R::StoreAlreadyInitialized => e.u8(0),
        R::StoreUninitialized => e.u8(1),
        R::WrongService => e.u8(2),
        R::WrongAbi => e.u8(3),
        R::WrongExecutionSemantics => e.u8(4),
        R::WrongProgram => e.u8(5),
        R::InvalidConsistency => e.u8(6),
        R::Unauthorized => e.u8(7),
        R::MissingBlob(hash) => {
            e.u8(8);
            e.fixed(&hash.0);
        }
        R::MissingProof => e.u8(9),
        R::ProofUnavailable => e.u8(10),
        R::InvalidProof => e.u8(11),
        R::StaleLinearWork {
            expected_revision,
            actual_revision,
        } => {
            e.u8(12);
            e.u64(*expected_revision);
            e.u64(*actual_revision);
        }
        R::StaleStateRoot => e.u8(13),
        R::MissingCausalDependency(hash) => {
            e.u8(14);
            e.fixed(&hash.0);
        }
        R::TransitionInputMismatch => e.u8(15),
        R::TransitionBaseMismatch => e.u8(16),
        R::DivergentDuplicate => e.u8(17),
        R::InvalidWorkflowTransition => e.u8(18),
        R::ContinuationConflict(actor) => {
            e.u8(19);
            e.fixed(&actor.0);
        }
        R::MessageCycle => e.u8(20),
        R::StorageFull => e.u8(21),
        R::SequenceOverflow => e.u8(22),
        R::NonCanonical => e.u8(23),
        R::ReceiptUnavailable => e.u8(24),
        R::InvalidReceipt => e.u8(25),
    }
}

fn decode_rejection(d: &mut Decoder<'_>) -> Result<AccumulationRejectionV2, DecodeError> {
    use AccumulationRejectionV2 as R;
    match d.u8()? {
        0 => Ok(R::StoreAlreadyInitialized),
        1 => Ok(R::StoreUninitialized),
        2 => Ok(R::WrongService),
        3 => Ok(R::WrongAbi),
        4 => Ok(R::WrongExecutionSemantics),
        5 => Ok(R::WrongProgram),
        6 => Ok(R::InvalidConsistency),
        7 => Ok(R::Unauthorized),
        8 => Ok(R::MissingBlob(Hash(d.fixed()?))),
        9 => Ok(R::MissingProof),
        10 => Ok(R::ProofUnavailable),
        11 => Ok(R::InvalidProof),
        12 => Ok(R::StaleLinearWork {
            expected_revision: d.u64()?,
            actual_revision: d.u64()?,
        }),
        13 => Ok(R::StaleStateRoot),
        14 => Ok(R::MissingCausalDependency(Hash(d.fixed()?))),
        15 => Ok(R::TransitionInputMismatch),
        16 => Ok(R::TransitionBaseMismatch),
        17 => Ok(R::DivergentDuplicate),
        18 => Ok(R::InvalidWorkflowTransition),
        19 => Ok(R::ContinuationConflict(ActorId(d.fixed()?))),
        20 => Ok(R::MessageCycle),
        21 => Ok(R::StorageFull),
        22 => Ok(R::SequenceOverflow),
        23 => Ok(R::NonCanonical),
        24 => Ok(R::ReceiptUnavailable),
        25 => Ok(R::InvalidReceipt),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_service(e: &mut Encoder<'_>, value: &ServiceIdentityV2) {
    e.fixed(&value.space.0);
    e.fixed(&value.root_service.0);
    e.fixed(&value.deployment.0);
    e.fixed(&value.service_program.0);
    e.u16(value.service_abi);
    e.fixed(&value.execution_semantics.0);
}

fn decode_service(d: &mut Decoder<'_>) -> Result<ServiceIdentityV2, DecodeError> {
    let value = ServiceIdentityV2 {
        space: SpaceId(d.fixed()?),
        root_service: RootServiceId(d.fixed()?),
        deployment: DeploymentId(d.fixed()?),
        service_program: ProgramId(d.fixed()?),
        service_abi: d.u16()?,
        execution_semantics: Hash(d.fixed()?),
    };
    if value.service_abi != super::ABI_VERSION {
        return Err(DecodeError::InvalidVersion);
    }
    Ok(value)
}

fn encode_base(e: &mut Encoder<'_>, value: &ConsistencyBaseV2) {
    match value {
        ConsistencyBaseV2::Linear {
            revision,
            state_root,
        } => {
            e.u8(0);
            e.u64(*revision);
            e.fixed(&state_root.0);
        }
        ConsistencyBaseV2::Crdt { heads } => {
            e.u8(1);
            e.list(heads, |e, h| e.fixed(&h.0));
        }
    }
}

fn decode_base(d: &mut Decoder<'_>) -> Result<ConsistencyBaseV2, DecodeError> {
    match d.u8()? {
        0 => Ok(ConsistencyBaseV2::Linear {
            revision: d.u64()?,
            state_root: Hash(d.fixed()?),
        }),
        1 => {
            let heads = d.list(|d| d.fixed().map(Hash))?;
            ensure_sorted_unique(&heads, |h| h.0)?;
            Ok(ConsistencyBaseV2::Crdt { heads })
        }
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_origin(e: &mut Encoder<'_>, value: Origin) {
    match value {
        Origin::Anonymous => e.u8(0),
        Origin::Member(id) => {
            e.u8(1);
            e.fixed(&id.0);
        }
        Origin::Actor(id) => {
            e.u8(2);
            e.fixed(&id.0);
        }
        Origin::System => e.u8(3),
    }
}

fn decode_origin(d: &mut Decoder<'_>) -> Result<Origin, DecodeError> {
    match d.u8()? {
        0 => Ok(Origin::Anonymous),
        1 => Ok(Origin::Member(SubjectId(d.fixed()?))),
        2 => Ok(Origin::Actor(ActorId(d.fixed()?))),
        3 => Ok(Origin::System),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_auth(e: &mut Encoder<'_>, value: &AuthorizationEvidenceV2) {
    match value {
        AuthorizationEvidenceV2::Public => e.u8(0),
        AuthorizationEvidenceV2::Credential {
            policy,
            credential_commitment,
            bytes,
        } => {
            e.u8(1);
            e.fixed(&policy.0);
            e.fixed(&credential_commitment.0);
            e.bytes(bytes);
        }
        AuthorizationEvidenceV2::SystemCapability {
            capability,
            authenticator,
        } => {
            e.u8(2);
            e.fixed(&capability.0);
            e.bytes(authenticator);
        }
        AuthorizationEvidenceV2::PrivateCredential {
            policy,
            credential_commitment,
            witness,
        } => {
            e.u8(3);
            e.fixed(&policy.0);
            e.fixed(&credential_commitment.0);
            encode_blob_ref(e, witness);
        }
    }
}

fn decode_auth(d: &mut Decoder<'_>) -> Result<AuthorizationEvidenceV2, DecodeError> {
    match d.u8()? {
        0 => Ok(AuthorizationEvidenceV2::Public),
        1 => Ok(AuthorizationEvidenceV2::Credential {
            policy: Hash(d.fixed()?),
            credential_commitment: Hash(d.fixed()?),
            bytes: d.bytes()?,
        }),
        2 => Ok(AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId(d.fixed()?),
            authenticator: d.bytes()?,
        }),
        3 => Ok(AuthorizationEvidenceV2::PrivateCredential {
            policy: Hash(d.fixed()?),
            credential_commitment: Hash(d.fixed()?),
            witness: decode_blob_ref(d)?,
        }),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_blob_ref(e: &mut Encoder<'_>, value: &BlobRefV2) {
    e.fixed(&value.hash.0);
    e.u64(value.len);
}

fn decode_blob_ref(d: &mut Decoder<'_>) -> Result<BlobRefV2, DecodeError> {
    Ok(BlobRefV2 {
        hash: Hash(d.fixed()?),
        len: d.u64()?,
    })
}

fn encode_imported_actor(e: &mut Encoder<'_>, value: &ImportedActorV2) {
    e.fixed(&value.actor.0);
    e.fixed(&value.program.0);
    encode_blob_ref(e, &value.state);
    e.list(&value.causal_states, encode_blob_ref);
    e.option(&value.continuation, encode_blob_ref);
}

fn decode_imported_actor(d: &mut Decoder<'_>) -> Result<ImportedActorV2, DecodeError> {
    Ok(ImportedActorV2 {
        actor: ActorId(d.fixed()?),
        program: ProgramId(d.fixed()?),
        state: decode_blob_ref(d)?,
        causal_states: d.list(decode_blob_ref)?,
        continuation: d.option(decode_blob_ref)?,
    })
}

fn encode_write(e: &mut Encoder<'_>, value: &ActorWriteV2) {
    e.fixed(&value.actor.0);
    e.bytes(&value.key);
    e.option(&value.value, |e, value| e.bytes(value));
}

fn decode_write(d: &mut Decoder<'_>) -> Result<ActorWriteV2, DecodeError> {
    let value = ActorWriteV2 {
        actor: ActorId(d.fixed()?),
        key: d.bytes()?,
        value: d.option(Decoder::bytes)?,
    };
    if value.key.is_empty() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_crdt_op(e: &mut Encoder<'_>, value: &CrdtOperationV2) {
    e.fixed(&value.actor.0);
    e.fixed(&value.field.0);
    e.u32(value.ordinal);
    e.fixed(&value.id.0);
    e.bytes(&value.payload);
}

fn decode_crdt_op(d: &mut Decoder<'_>) -> Result<CrdtOperationV2, DecodeError> {
    Ok(CrdtOperationV2 {
        actor: ActorId(d.fixed()?),
        field: Hash(d.fixed()?),
        ordinal: d.u32()?,
        id: OperationId(d.fixed()?),
        payload: d.bytes()?,
    })
}

fn encode_workflow_operation(e: &mut Encoder<'_>, value: &WorkflowOperationV2) {
    match value {
        WorkflowOperationV2::Consumed(input) => {
            e.u8(0);
            e.fixed(&input.invocation.0);
            e.u64(input.workflow_step);
        }
        WorkflowOperationV2::Continuation(change) => {
            e.u8(1);
            encode_continuation_change(e, change);
        }
        WorkflowOperationV2::Inbox(message) => {
            e.u8(2);
            encode_message(e, message);
        }
        WorkflowOperationV2::Outbox(message) => {
            e.u8(3);
            encode_message(e, message);
        }
        WorkflowOperationV2::Reply(reply) => {
            e.u8(4);
            encode_reply(e, reply);
        }
    }
}

fn decode_workflow_operation(d: &mut Decoder<'_>) -> Result<WorkflowOperationV2, DecodeError> {
    match d.u8()? {
        0 => Ok(WorkflowOperationV2::Consumed(WorkInputIdV2 {
            invocation: InvocationId(d.fixed()?),
            workflow_step: d.u64()?,
        })),
        1 => Ok(WorkflowOperationV2::Continuation(
            decode_continuation_change(d)?,
        )),
        2 => Ok(WorkflowOperationV2::Inbox(decode_message(d)?)),
        3 => Ok(WorkflowOperationV2::Outbox(decode_message(d)?)),
        4 => Ok(WorkflowOperationV2::Reply(decode_reply(d)?)),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn workflow_operation_bytes(value: &WorkflowOperationV2) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_workflow_operation(&mut Encoder(&mut bytes), value);
    bytes
}

fn encode_continuation_change(e: &mut Encoder<'_>, value: &ContinuationChangeV2) {
    e.fixed(&value.actor.0);
    e.option(&value.expected, |e, h| e.fixed(&h.0));
    e.option(&value.replacement, encode_blob_ref);
}

fn encode_checkpoint_token(e: &mut Encoder<'_>, value: &CheckpointTokenV2) {
    e.fixed(&value.input.invocation.0);
    e.u64(value.input.workflow_step);
    encode_base(e, &value.base);
    e.option(&value.base_causal_height, |e, height| e.u64(*height));
    e.option(&value.expected, |e, hash| e.fixed(&hash.0));
    e.option(&value.replacement, encode_blob_ref);
    e.option(&value.pending_call, |e, call| e.fixed(&call.0));
}

fn decode_checkpoint_token(d: &mut Decoder<'_>) -> Result<CheckpointTokenV2, DecodeError> {
    let value = CheckpointTokenV2 {
        input: WorkInputIdV2 {
            invocation: InvocationId(d.fixed()?),
            workflow_step: d.u64()?,
        },
        base: decode_base(d)?,
        base_causal_height: d.option(Decoder::u64)?,
        expected: d.option(|d| d.fixed().map(Hash))?,
        replacement: d.option(decode_blob_ref)?,
        pending_call: d.option(|d| d.fixed().map(CallId))?,
    };
    if matches!(value.base, ConsistencyBaseV2::Linear { .. }) != value.base_causal_height.is_none()
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_actor_call(e: &mut Encoder<'_>, value: &ActorCallRequestV2) {
    e.u64(value.await_ordinal);
    e.fixed(&value.to.0);
    e.bytes(&value.payload);
    encode_auth(e, &value.authorization);
    e.option(&value.deadline_timeslot, |e, value| e.u64(*value));
}

fn decode_actor_call(d: &mut Decoder<'_>) -> Result<ActorCallRequestV2, DecodeError> {
    Ok(ActorCallRequestV2 {
        await_ordinal: d.u64()?,
        to: ActorId(d.fixed()?),
        payload: d.bytes()?,
        authorization: decode_auth(d)?,
        deadline_timeslot: d.option(Decoder::u64)?,
    })
}

fn decode_continuation_change(d: &mut Decoder<'_>) -> Result<ContinuationChangeV2, DecodeError> {
    Ok(ContinuationChangeV2 {
        actor: ActorId(d.fixed()?),
        expected: d.option(|d| d.fixed().map(Hash))?,
        replacement: d.option(decode_blob_ref)?,
    })
}

fn encode_message(e: &mut Encoder<'_>, value: &MessageRecordV2) {
    e.fixed(&value.call_id.0);
    e.fixed(&value.caller_invocation.0);
    e.u64(value.await_ordinal);
    e.fixed(&value.from.0);
    e.fixed(&value.to.0);
    e.option(&value.parent, |e, id| e.fixed(&id.0));
    e.bytes(&value.payload);
    encode_auth(e, &value.authorization);
    e.option(&value.deadline_timeslot, |e, value| e.u64(*value));
}

fn decode_message(d: &mut Decoder<'_>) -> Result<MessageRecordV2, DecodeError> {
    let value = MessageRecordV2 {
        call_id: CallId(d.fixed()?),
        caller_invocation: InvocationId(d.fixed()?),
        await_ordinal: d.u64()?,
        from: ActorId(d.fixed()?),
        to: ActorId(d.fixed()?),
        parent: d.option(|d| d.fixed().map(CallId))?,
        payload: d.bytes()?,
        authorization: decode_auth(d)?,
        deadline_timeslot: d.option(Decoder::u64)?,
    };
    if value.payload.is_empty()
        || value.call_id != value.caller_invocation.call_id(value.await_ordinal)
    {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_reply(e: &mut Encoder<'_>, value: &ReplyRecordV2) {
    e.fixed(&value.call_id.0);
    e.fixed(&value.producer.0);
    e.bytes(&value.result);
}

fn decode_reply(d: &mut Decoder<'_>) -> Result<ReplyRecordV2, DecodeError> {
    Ok(ReplyRecordV2 {
        call_id: CallId(d.fixed()?),
        producer: ActorId(d.fixed()?),
        result: d.bytes()?,
    })
}

fn encode_proof(e: &mut Encoder<'_>, value: &ProofCommitmentV2) {
    e.fixed(&value.statement.0);
    e.fixed(&value.trace.0);
    encode_blob_ref(e, &value.proof_blob);
    e.u16(value.statement_version);
}

fn decode_proof(d: &mut Decoder<'_>) -> Result<ProofCommitmentV2, DecodeError> {
    let value = ProofCommitmentV2 {
        statement: Hash(d.fixed()?),
        trace: Hash(d.fixed()?),
        proof_blob: decode_blob_ref(d)?,
        statement_version: d.u16()?,
    };
    if value.statement_version != super::ATTESTATION_STATEMENT_VERSION
        || value.statement == Hash::ZERO
        || value.trace == Hash::ZERO
    {
        return Err(DecodeError::InvalidVersion);
    }
    Ok(value)
}

fn ensure_sorted_unique<T>(values: &[T], key: impl Fn(&T) -> [u8; 32]) -> Result<(), DecodeError> {
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> ServiceIdentityV2 {
        ServiceIdentityV2 {
            space: SpaceId([0; 32]),
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: super::super::ABI_VERSION,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        }
    }

    fn work() -> WorkEnvelopeV2 {
        WorkEnvelopeV2 {
            service: service(),
            invocation: InvocationId([4; 32]),
            workflow_step: 0,
            logical_timeslot: 5,
            target: ActorId([5; 32]),
            target_program: ProgramId([6; 32]),
            method: "increment".into(),
            arguments: vec![1, 2],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            awaited_reply: None,
            consistency: ConsistencyModeV2::Local,
            base: ConsistencyBaseV2::Linear {
                revision: 7,
                state_root: Hash([8; 32]),
            },
            base_causal_height: None,
            imported_actors: vec![],
            imported_blobs: vec![],
            proof_requested: false,
        }
    }

    #[test]
    fn work_wire_is_strict_and_deterministic() {
        let value = work();
        let bytes = value.encode();
        assert_eq!(bytes, value.encode());
        assert_eq!(WorkEnvelopeV2::decode(&bytes).unwrap(), value);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            WorkEnvelopeV2::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );
        let mut old = bytes;
        old[4..6].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            WorkEnvelopeV2::decode(&old),
            Err(DecodeError::InvalidVersion)
        );
    }

    #[test]
    fn refine_imports_bind_all_program_and_blob_bytes() {
        let pvm = b"canonical-actor-pvm".to_vec();
        let program = ProgramId::of_pvm(&pvm);
        let state_bytes = b"actor-state".to_vec();
        let state = BlobRefV2::of_bytes(&state_bytes);
        let extra_bytes = b"schema-or-credential".to_vec();
        let extra = BlobRefV2::of_bytes(&extra_bytes);

        let mut work = work();
        work.target_program = program;
        work.imported_actors = vec![ImportedActorV2 {
            actor: work.target,
            program,
            state: state.clone(),
            causal_states: vec![],
            continuation: None,
        }];
        work.imported_blobs = vec![extra.clone()];

        let mut blobs = vec![
            ImportedBlobV2 {
                reference: state,
                bytes: state_bytes,
            },
            ImportedBlobV2 {
                reference: extra,
                bytes: extra_bytes,
            },
        ];
        blobs.sort_by_key(|blob| blob.reference.hash);
        let imports = RefineImportsV2 {
            programs: vec![ImportedProgramV2 { program, pvm }],
            blobs,
        };
        imports.validate_for(&work).unwrap();
        let encoded = imports.encode();
        assert_eq!(RefineImportsV2::decode(&encoded).unwrap(), imports);

        let mut missing = imports.clone();
        missing
            .blobs
            .retain(|blob| blob.reference != work.imported_blobs[0]);
        assert_eq!(
            missing.validate_for(&work),
            Err(RefineError::MissingImport(work.imported_blobs[0].hash))
        );

        let mut tampered = imports;
        tampered.programs[0].pvm.push(0);
        assert_eq!(
            tampered.validate_for(&work),
            Err(RefineError::InvalidImport(Hash(program.0)))
        );
    }

    #[test]
    fn actor_slice_wires_round_trip_and_bind_writes_to_the_actor() {
        let input = ActorSliceInputV2 {
            actor: ActorId([21; 32]),
            change: Some(ChangeId([23; 32])),
            state: b"before".to_vec(),
            causal_states: vec![b"concurrent".to_vec()],
            message: b"message".to_vec(),
            origin: Origin::Actor(ActorId([22; 32])),
        };
        assert_eq!(ActorSliceInputV2::decode(&input.encode()).unwrap(), input);

        let output = ActorSliceOutputV2 {
            actor: ActorId([21; 32]),
            writes: vec![ActorWriteV2 {
                actor: ActorId([21; 32]),
                key: b"state".to_vec(),
                value: Some(b"after".to_vec()),
            }],
            crdt_operations: vec![],
            crdt_materialization: None,
            outbox: vec![ActorCallRequestV2 {
                await_ordinal: 0,
                to: ActorId([27; 32]),
                payload: b"peer request".to_vec(),
                authorization: AuthorizationEvidenceV2::Public,
                deadline_timeslot: Some(30),
            }],
            reply: b"ok".to_vec(),
            yielded: false,
            forbidden: false,
            checkpoint: None,
        };
        assert_eq!(
            ActorSliceOutputV2::decode(&output.encode()).unwrap(),
            output
        );

        let mut cross_actor_write = output;
        cross_actor_write.writes[0].actor = ActorId([23; 32]);
        assert_eq!(
            ActorSliceOutputV2::decode(&cross_actor_write.encode()),
            Err(DecodeError::NonCanonical)
        );

        let replacement = BlobRefV2::of_bytes(b"kernel snapshot");
        let checkpoint = CheckpointTokenV2 {
            input: WorkInputIdV2 {
                invocation: InvocationId([24; 32]),
                workflow_step: 3,
            },
            base: ConsistencyBaseV2::Linear {
                revision: 3,
                state_root: Hash([25; 32]),
            },
            base_causal_height: None,
            expected: Some(Hash([26; 32])),
            replacement: Some(replacement),
            pending_call: Some(InvocationId([24; 32]).call_id(3)),
        };
        assert_eq!(
            CheckpointTokenV2::decode(&checkpoint.encode()).unwrap(),
            checkpoint
        );

        let mut invalid_yield = ActorSliceOutputV2 {
            actor: ActorId([21; 32]),
            writes: vec![],
            crdt_operations: vec![],
            crdt_materialization: None,
            outbox: vec![],
            reply: vec![],
            yielded: true,
            forbidden: false,
            checkpoint: None,
        };
        assert_eq!(
            ActorSliceOutputV2::decode(&invalid_yield.encode()),
            Err(DecodeError::NonCanonical)
        );
        invalid_yield.checkpoint = Some(checkpoint.clone());
        assert_eq!(
            ActorSliceOutputV2::decode(&invalid_yield.encode()).unwrap(),
            invalid_yield
        );

        let resume = AwaitResumeV2 {
            checkpoint: CheckpointTokenV2 {
                replacement: None,
                ..checkpoint.clone()
            },
            reply: ReplyRecordV2 {
                call_id: checkpoint.pending_call.unwrap(),
                producer: ActorId([28; 32]),
                result: b"committed reply".to_vec(),
            },
        };
        assert_eq!(AwaitResumeV2::decode(&resume.encode()).unwrap(), resume);
        let mut mismatched = resume;
        mismatched.reply.call_id = InvocationId([29; 32]).call_id(3);
        assert_eq!(
            AwaitResumeV2::decode(&mismatched.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn transition_commitment_binds_execution_but_not_attached_proof() {
        let base = TransitionV2 {
            service: service(),
            consumed_input: WorkInputIdV2 {
                invocation: InvocationId([9; 32]),
                workflow_step: 0,
            },
            target_program: ProgramId([10; 32]),
            base: ConsistencyBaseV2::Linear {
                revision: 0,
                state_root: Hash::ZERO,
            },
            writes: vec![],
            crdt_change: None,
            continuations: vec![],
            inbox: vec![],
            outbox: vec![],
            reply: None,
            exported_blobs: vec![],
            gas: GasAccountingV2::default(),
            proof: None,
        };
        let mut changed = base.clone();
        changed.reply = Some(ReplyRecordV2 {
            call_id: CallId([11; 32]),
            producer: ActorId([12; 32]),
            result: b"ok".to_vec(),
        });
        assert_ne!(base.hash(), changed.hash());
        assert_ne!(base.commitment(), changed.commitment());

        let mut proved = changed.clone();
        proved.proof = Some(ProofCommitmentV2 {
            statement: Hash([14; 32]),
            trace: Hash([13; 32]),
            proof_blob: BlobRefV2::of_bytes(b"proof"),
            statement_version: super::super::ATTESTATION_STATEMENT_VERSION,
        });
        assert_ne!(proved.hash(), changed.hash());
        assert_eq!(proved.commitment(), changed.commitment());
        assert_eq!(TransitionV2::decode(&changed.encode()).unwrap(), changed);
    }

    #[test]
    fn durable_message_binds_call_identity_and_authorization() {
        let caller_invocation = InvocationId([71; 32]);
        let message = MessageRecordV2 {
            call_id: caller_invocation.call_id(3),
            caller_invocation,
            await_ordinal: 3,
            from: ActorId([72; 32]),
            to: ActorId([73; 32]),
            parent: Some(CallId([74; 32])),
            payload: b"message".to_vec(),
            authorization: AuthorizationEvidenceV2::Credential {
                policy: Hash([75; 32]),
                credential_commitment: Hash([76; 32]),
                bytes: vec![77],
            },
            deadline_timeslot: Some(78),
        };
        assert_eq!(MessageRecordV2::decode(&message.encode()).unwrap(), message);

        let mut wrong_ordinal = message;
        wrong_ordinal.await_ordinal = 4;
        assert_eq!(
            MessageRecordV2::decode(&wrong_ordinal.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn accumulate_request_wires_bind_install_and_apply_inputs() {
        let genesis = ServiceGenesisV2 {
            service: service(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![
                ActorGenesisV2 {
                    actor: ActorId([5; 32]),
                    name: "root".into(),
                    parent: None,
                    program: ProgramId([6; 32]),
                    initial_state: BlobRefV2::of_bytes(b"root-state"),
                    crdt: false,
                    methods: vec![MethodPolicyV2 {
                        method: "increment".into(),
                        schema: Hash([7; 32]),
                        policy: Hash([8; 32]),
                        public: true,
                        attested: false,
                    }],
                },
                ActorGenesisV2 {
                    actor: ActorId([9; 32]),
                    name: "child".into(),
                    parent: Some(ActorId([5; 32])),
                    program: ProgramId([10; 32]),
                    initial_state: BlobRefV2::of_bytes(b"child-state"),
                    crdt: false,
                    methods: vec![],
                },
            ],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: SystemCapabilityId([11; 32]),
                authenticator: b"platform-authenticator".to_vec(),
            },
        };
        let install = AccumulateRequestV2::Install(genesis);
        assert_eq!(
            AccumulateRequestV2::decode(&install.encode()).unwrap(),
            install
        );

        let work = work();
        let artifact = ImportedBlobV2 {
            reference: BlobRefV2::of_bytes(b"candidate artifact"),
            bytes: b"candidate artifact".to_vec(),
        };
        let transition = TransitionV2 {
            service: work.service.clone(),
            consumed_input: work.input_id(),
            target_program: work.target_program,
            base: work.base.clone(),
            writes: vec![],
            crdt_change: None,
            continuations: vec![],
            inbox: vec![],
            outbox: vec![],
            reply: None,
            exported_blobs: vec![artifact.reference.clone()],
            gas: GasAccountingV2::default(),
            proof: None,
        };
        let refined = RefineOutputV2 {
            transition: transition.clone(),
            candidate_blobs: vec![artifact.clone()],
        };
        assert_eq!(RefineOutputV2::decode(&refined.encode()).unwrap(), refined);
        let apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work,
            transition,
            provided_blobs: vec![artifact],
        });
        assert_eq!(AccumulateRequestV2::decode(&apply.encode()).unwrap(), apply);

        let caller_invocation = InvocationId([20; 32]);
        let message = MessageRecordV2 {
            call_id: caller_invocation.call_id(0),
            caller_invocation,
            await_ordinal: 0,
            from: ActorId([21; 32]),
            to: ActorId([5; 32]),
            parent: None,
            payload: vec![1],
            authorization: AuthorizationEvidenceV2::Public,
            deadline_timeslot: Some(9),
        };
        let source_outbox = vec![message.clone()];
        let mut source_service = service();
        source_service.root_service = RootServiceId([22; 32]);
        let delivery = AccumulateRequestV2::Deliver(DeliveryEnvelopeV2 {
            service: service(),
            logical_timeslot: 8,
            base: ConsistencyBaseV2::Linear {
                revision: 7,
                state_root: Hash([8; 32]),
            },
            base_causal_height: None,
            message,
            source_outbox: source_outbox.clone(),
            source_receipt: AccumulationReceiptV2 {
                service: source_service,
                accepted_transition: Hash([23; 32]),
                reply_commitment: None,
                outbox_commitment: MessageRecordV2::outbox_commitment(&source_outbox),
                resulting_state_root: Some(Hash([24; 32])),
                resulting_crdt_heads: vec![],
                sequence: 1,
                checkpoint: 0,
                consistency: ConsistencyModeV2::Local,
            },
            crdt_change: None,
        });
        assert_eq!(
            AccumulateRequestV2::decode(&delivery.encode()).unwrap(),
            delivery
        );

        let AccumulateRequestV2::Apply(mut divergent) = apply else {
            unreachable!()
        };
        divergent.transition.consumed_input.workflow_step += 1;
        assert_eq!(
            AccumulationEnvelopeV2::decode(&divergent.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut unexpected = divergent;
        unexpected.transition.consumed_input = unexpected.work.input_id();
        unexpected.provided_blobs[0] = ImportedBlobV2 {
            reference: BlobRefV2::of_bytes(b"not referenced"),
            bytes: b"not referenced".to_vec(),
        };
        assert_eq!(
            AccumulationEnvelopeV2::decode(&unexpected.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn genesis_rejects_cycles_and_plain_actors_in_crdt_services() {
        let mut genesis = ServiceGenesisV2 {
            service: service(),
            consistency: ConsistencyModeV2::Crdt,
            actors: vec![ActorGenesisV2 {
                actor: ActorId([5; 32]),
                name: "root".into(),
                parent: None,
                program: ProgramId([6; 32]),
                initial_state: BlobRefV2::of_bytes(b"state"),
                crdt: false,
                methods: vec![],
            }],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: SystemCapabilityId([7; 32]),
                authenticator: vec![1],
            },
        };
        assert_eq!(
            ServiceGenesisV2::decode(&genesis.encode()),
            Err(DecodeError::NonCanonical)
        );

        genesis.consistency = ConsistencyModeV2::Local;
        genesis.actors[0].parent = None;
        let mut first_child = genesis.actors[0].clone();
        first_child.actor = ActorId([8; 32]);
        first_child.name = "child".into();
        first_child.parent = Some(genesis.actors[0].actor);
        let mut second_child = first_child.clone();
        second_child.actor = ActorId([9; 32]);
        genesis.actors.extend([first_child, second_child]);
        assert_eq!(
            ServiceGenesisV2::decode(&genesis.encode()),
            Err(DecodeError::NonCanonical),
            "siblings cannot share one durable directory name"
        );

        genesis.actors.truncate(1);
        genesis.actors[0].parent = Some(genesis.actors[0].actor);
        assert_eq!(
            ServiceGenesisV2::decode(&genesis.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn accumulation_results_are_commit_decisions_on_the_wire() {
        let receipt = AccumulationReceiptV2 {
            service: service(),
            accepted_transition: Hash([12; 32]),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: Some(Hash([13; 32])),
            resulting_crdt_heads: vec![],
            sequence: 4,
            checkpoint: 2,
            consistency: ConsistencyModeV2::Local,
        };
        let accepted = AccumulationResultV2::Accepted {
            receipt: receipt.clone(),
            published: PublishedEffectsV2::default(),
            duplicate: false,
        };
        assert_eq!(
            AccumulationResultV2::decode(&accepted.encode()).unwrap(),
            accepted
        );

        let reply = ReplyRecordV2 {
            call_id: CallId([14; 32]),
            producer: ActorId([15; 32]),
            result: b"committed reply".to_vec(),
        };
        let mut reply_receipt = receipt.clone();
        reply_receipt.reply_commitment = Some(reply.commitment());
        let with_reply = AccumulationResultV2::Accepted {
            receipt: reply_receipt,
            published: PublishedEffectsV2 {
                reply: Some(reply.clone()),
                ..PublishedEffectsV2::default()
            },
            duplicate: false,
        };
        assert_eq!(
            AccumulationResultV2::decode(&with_reply.encode()).unwrap(),
            with_reply
        );
        let mismatched = AccumulationResultV2::Accepted {
            receipt: receipt.clone(),
            published: PublishedEffectsV2 {
                reply: Some(reply),
                ..PublishedEffectsV2::default()
            },
            duplicate: false,
        };
        assert_eq!(
            AccumulationResultV2::decode(&mismatched.encode()),
            Err(DecodeError::NonCanonical)
        );

        let duplicate = AccumulationResultV2::Accepted {
            receipt,
            published: PublishedEffectsV2::default(),
            duplicate: true,
        };
        assert_eq!(
            AccumulationResultV2::decode(&duplicate.encode()).unwrap(),
            duplicate
        );

        let rejection = AccumulationResultV2::Rejected(AccumulationRejectionV2::StaleLinearWork {
            expected_revision: 3,
            actual_revision: 4,
        });
        assert_eq!(
            AccumulationResultV2::decode(&rejection.encode()).unwrap(),
            rejection
        );
        assert!(AccumulationRejectionV2::StaleStateRoot.is_retryable());
        assert!(!AccumulationRejectionV2::DivergentDuplicate.is_retryable());
    }

    #[test]
    fn one_crdt_change_binds_the_complete_execution_slice() {
        let mut work = work();
        work.consistency = ConsistencyModeV2::Crdt;
        work.base = ConsistencyBaseV2::Crdt {
            heads: vec![Hash([31; 32])],
        };
        work.base_causal_height = Some(3);
        let change_id = CrdtChangeV2::derive_id(&work).unwrap();
        let field = Hash([32; 32]);
        let transition = TransitionV2 {
            service: work.service.clone(),
            consumed_input: work.input_id(),
            target_program: work.target_program,
            base: work.base.clone(),
            writes: vec![],
            crdt_change: Some(CrdtChangeV2 {
                id: change_id,
                causal_dependencies: vec![Hash([31; 32])],
                causal_height: 4,
                operations: vec![CrdtOperationV2 {
                    actor: work.target,
                    field,
                    ordinal: 0,
                    id: change_id.operation(work.target, field, 0),
                    payload: b"counter +1".to_vec(),
                }],
                workflow: vec![WorkflowOperationV2::Consumed(work.input_id())],
                materializations: vec![CrdtMaterializationV2 {
                    actor: work.target,
                    state: BlobRefV2::of_bytes(b"materialized-state"),
                }],
            }),
            continuations: vec![],
            inbox: vec![],
            outbox: vec![],
            reply: None,
            exported_blobs: vec![],
            gas: GasAccountingV2::default(),
            proof: None,
        };
        let envelope = AccumulationEnvelopeV2 {
            work,
            transition,
            provided_blobs: vec![],
        };
        assert_eq!(
            AccumulationEnvelopeV2::decode(&envelope.encode()).unwrap(),
            envelope
        );

        let mut bad_id = envelope.clone();
        bad_id.transition.crdt_change.as_mut().unwrap().operations[0].id = OperationId([99; 32]);
        assert_eq!(
            AccumulationEnvelopeV2::decode(&bad_id.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut missing_workflow_reply = envelope;
        missing_workflow_reply.transition.reply = Some(ReplyRecordV2 {
            call_id: CallId([44; 32]),
            producer: ActorId([45; 32]),
            result: b"done".to_vec(),
        });
        assert_eq!(
            AccumulationEnvelopeV2::decode(&missing_workflow_reply.encode()),
            Err(DecodeError::NonCanonical)
        );
    }
}
