//! Clean-break guest-owned service storage schema.
//!
//! The header is the mutable root anchor and is deliberately not a leaf in
//! the application state tree. Deduplication and receipt rows are likewise
//! consensus service storage, but excluded from the application root to avoid
//! making a receipt commit to itself.

use alloc::string::String;
use alloc::vec::Vec;

use super::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use super::{
    AccumulatedReply, AccumulationReceipt, ActorId, AuthorizationEvidence, CallId, ConsistencyMode,
    CrdtChange, DeploymentId, DirectIngress, Hash, InvocationId, ProgramId, PublishedEffects,
    ServiceIdentity, WorkEnvelope, WorkInputId,
};

/// Physical keys used directly in the service account. They are outside
/// every actor's logical keyspace and never exposed through application APIs.
const HEADER_STORAGE_KEY: &[u8] = b"\0vos/service/header";
const DEDUP_STORAGE_PREFIX: &[u8] = b"\0vos/service/dedup/";
const RECEIPT_STORAGE_PREFIX: &[u8] = b"\0vos/service/receipt/";
const PUBLICATION_STORAGE_PREFIX: &[u8] = b"\0vos/service/publication/";
const PUBLICATION_ACK_STORAGE_PREFIX: &[u8] = b"\0vos/service/publication-ack/";
const ROLE_ASSERTION_ELIGIBILITY_STORAGE_PREFIX: &[u8] = b"\0vos/service/role-assertion/";
const DELIVERY_STORAGE_PREFIX: &[u8] = b"\0vos/service/delivery/";
const INGRESS_STORAGE_PREFIX: &[u8] = b"\0vos/service/ingress/";
const REPLY_ADMISSION_STORAGE_PREFIX: &[u8] = b"\0vos/service/reply-admission/";
const CALL_EXPIRATION_STORAGE_PREFIX: &[u8] = b"\0vos/service/call-expiration/";
const PENDING_CALL_DEADLINE_STORAGE_PREFIX: &[u8] = b"\0vos/service/pending-deadline/";
const ACTOR_UPGRADE_STORAGE_PREFIX: &[u8] = b"\0vos/service/actor-upgrade/";
const CRDT_NODE_STORAGE_PREFIX: &[u8] = b"\0vos/service/crdt-node/";
const CRDT_NODE_RECEIPT_STORAGE_PREFIX: &[u8] = b"\0vos/service/crdt-node-receipt/";
const CRDT_CHANGE_STORAGE_PREFIX: &[u8] = b"\0vos/service/crdt-change/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreHeader {
    pub service: ServiceIdentity,
    pub consistency: ConsistencyMode,
    /// Root of the guest-owned service metadata/workflow tree. It exists for
    /// every consistency mode; CRDT receipts expose causal heads instead.
    pub service_root: Hash,
    /// Exact current revision for Ephemeral, Local, and Raft. CRDT services
    /// derive receipt sequence from causal height and keep this at zero.
    pub revision: u64,
    pub state_root: Option<Hash>,
    pub crdt_heads: Vec<Hash>,
    /// Greatest trusted logical timeslot committed through this service
    /// image. Native schedulers restore their node-wide allocator above this
    /// floor before admitting new work, so process restart and wall-clock
    /// rollback cannot backdate a later invocation.
    pub admission_timeslot_high_water: u64,
}

impl StoreHeader {
    pub fn current(service: ServiceIdentity, consistency: ConsistencyMode) -> Self {
        Self {
            service,
            consistency,
            service_root: super::state_tree::empty_state_root(),
            revision: 0,
            state_root: (consistency != ConsistencyMode::Crdt)
                .then(super::state_tree::empty_state_root),
            crdt_heads: Vec::new(),
            admission_timeslot_high_water: 0,
        }
    }

    pub fn open(bytes: &[u8]) -> Result<Self, StoreOpenError> {
        if bytes.get(..4) != Some(&Self::MAGIC) {
            return Err(StoreOpenError::UnknownStore);
        }
        let header = Self::decode(bytes).map_err(StoreOpenError::InvalidHeader)?;
        if header.service.platform != super::PLATFORM_ID
            || header.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
            || !header.service.gas_schedule.is_valid()
        {
            return Err(StoreOpenError::IncompatibleSemantics);
        }
        Ok(header)
    }

    pub fn open_for(bytes: &[u8], expected: &ServiceIdentity) -> Result<Self, StoreOpenError> {
        let header = Self::open(bytes)?;
        if &header.service != expected {
            return Err(StoreOpenError::WrongService);
        }
        Ok(header)
    }
}

impl ServiceWire for StoreHeader {
    const MAGIC: [u8; 4] = *b"VSTR";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.u8(self.consistency as u8);
        e.fixed(&self.service_root.0);
        e.u64(self.revision);
        e.option(&self.state_root, |e, root| e.fixed(&root.0));
        e.list(&self.crdt_heads, |e, head| e.fixed(&head.0));
        e.u64(self.admission_timeslot_high_water);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            service: decode_service(d)?,
            consistency: decode_consistency(d)?,
            service_root: Hash(d.fixed()?),
            revision: d.u64()?,
            state_root: d.option(|d| d.fixed().map(Hash))?,
            crdt_heads: d.list(|d| d.fixed().map(Hash))?,
            admission_timeslot_high_water: d.u64()?,
        };
        ensure_hashes_sorted(&value.crdt_heads)?;
        let valid_commitment = match value.consistency {
            ConsistencyMode::Crdt => value.state_root.is_none() && value.revision == 0,
            ConsistencyMode::Ephemeral | ConsistencyMode::Local | ConsistencyMode::Raft => {
                value.state_root == Some(value.service_root) && value.crdt_heads.is_empty()
            }
        };
        if !valid_commitment {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

/// Logical rows covered by the guest-owned application state root. The full
/// encoded logical key is stored in each leaf; its digest only chooses a tree
/// position.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum StateKey {
    /// Canonical, sorted membership of the complete root actor tree.
    ActorDirectory,
    /// Canonical install-time bindings to actors owned by other root trees.
    ExternalActorDirectory,
    /// Immutable platform authority whose finalized replies may satisfy
    /// generated space-role policies for this root tree.
    RoleAuthority,
    ActorDescriptor(ActorId),
    MethodPolicy {
        actor: ActorId,
        method: String,
    },
    ActorRow {
        actor: ActorId,
        key: Vec<u8>,
    },
    Continuation(ActorId),
    Inbox(CallId),
    Outbox(CallId),
    Workflow(InvocationId),
    CrdtMaterialization(ActorId),
    /// Number of destination-authorized delivery rows which still pin this
    /// actor's installed deployment and program. Linear upgrades remain busy
    /// until the corresponding inbox slices consume those rows.
    PendingAuthorizedInbox(ActorId),
}

impl ServiceWire for StateKey {
    const MAGIC: [u8; 4] = *b"VSKW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        match self {
            Self::ActorDirectory => {
                e.u8(9);
            }
            Self::ExternalActorDirectory => {
                e.u8(10);
            }
            Self::RoleAuthority => {
                e.u8(11);
            }
            Self::ActorDescriptor(actor) => {
                e.u8(0);
                e.fixed(&actor.0);
            }
            Self::MethodPolicy { actor, method } => {
                e.u8(1);
                e.fixed(&actor.0);
                e.string(method);
            }
            Self::ActorRow { actor, key } => {
                e.u8(2);
                e.fixed(&actor.0);
                e.bytes(key);
            }
            Self::Continuation(actor) => {
                e.u8(3);
                e.fixed(&actor.0);
            }
            Self::Inbox(call) => {
                e.u8(4);
                e.fixed(&call.0);
            }
            Self::Outbox(call) => {
                e.u8(5);
                e.fixed(&call.0);
            }
            Self::Workflow(invocation) => {
                e.u8(6);
                e.fixed(&invocation.0);
            }
            Self::CrdtMaterialization(actor) => {
                e.u8(7);
                e.fixed(&actor.0);
            }
            Self::PendingAuthorizedInbox(actor) => {
                e.u8(8);
                e.fixed(&actor.0);
            }
        }
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.u8()? {
            0 => Ok(Self::ActorDescriptor(ActorId(d.fixed()?))),
            1 => {
                let actor = ActorId(d.fixed()?);
                let method = d.string()?;
                if method.is_empty() {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::MethodPolicy { actor, method })
            }
            2 => {
                let actor = ActorId(d.fixed()?);
                let key = d.bytes()?;
                if key.is_empty() {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::ActorRow { actor, key })
            }
            3 => Ok(Self::Continuation(ActorId(d.fixed()?))),
            4 => Ok(Self::Inbox(CallId(d.fixed()?))),
            5 => Ok(Self::Outbox(CallId(d.fixed()?))),
            6 => Ok(Self::Workflow(InvocationId(d.fixed()?))),
            7 => Ok(Self::CrdtMaterialization(ActorId(d.fixed()?))),
            8 => Ok(Self::PendingAuthorizedInbox(ActorId(d.fixed()?))),
            9 => Ok(Self::ActorDirectory),
            10 => Ok(Self::ExternalActorDirectory),
            11 => Ok(Self::RoleAuthority),
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupRecord {
    pub input: WorkInputId,
    pub work_hash: Hash,
    pub transition_commitment: Hash,
    pub receipt: AccumulationReceipt,
}

/// Physical exactly-once record for an accepted actor upgrade. It is kept
/// outside the service tree because its receipt commits to the resulting tree
/// root. The actor descriptor and generated policies remain inside the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorUpgradeRecord {
    pub upgrade: Hash,
    pub actor: ActorId,
    pub previous_deployment: DeploymentId,
    pub previous_program: ProgramId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub receipt: AccumulationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressRecord {
    pub ingress: DirectIngress,
    /// Set atomically with the initial actor slice. The original admission is
    /// retained as the permanent invocation deduplication identity.
    pub consumed: bool,
    /// Exact guest receipt for the admission node. CRDT peers verify this
    /// before importing the queued invocation through SyncCrdt.
    pub receipt: AccumulationReceipt,
}

impl IngressRecord {
    pub(crate) fn encode_admitted(
        ingress: &DirectIngress,
        consumed: bool,
        receipt: &AccumulationReceipt,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        out.extend_from_slice(&super::PLATFORM_ID.0);
        let mut e = Encoder(&mut out);
        e.bytes(&ingress.encode_admitted());
        e.bool(consumed);
        e.bytes(&receipt.encode());
        out
    }

    pub(crate) fn encode_materialized(
        ingress: &super::CrdtIngress,
        change: &super::CrdtChange,
        consumed: bool,
        receipt: &AccumulationReceipt,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        out.extend_from_slice(&super::PLATFORM_ID.0);
        let mut e = Encoder(&mut out);
        e.bytes(&DirectIngress::encode_materialized(ingress, change));
        e.bool(consumed);
        e.bytes(&receipt.encode());
        out
    }

    /// Flip the canonical consumed flag in an already-decoded record without
    /// rebuilding its nested CRDT change and receipt. Callers must first run
    /// [`ServiceWire::decode`] over the same bytes; this helper only preserves that
    /// authenticated wire while changing the one atomic lifecycle bit.
    pub(crate) fn mark_consumed_in_place(bytes: &mut [u8]) -> Result<(), DecodeError> {
        if bytes.get(..4) != Some(&Self::MAGIC) || bytes.get(4..36) != Some(&super::PLATFORM_ID.0) {
            return Err(DecodeError::NonCanonical);
        }
        let ingress_len = u32::from_le_bytes(
            bytes
                .get(36..40)
                .ok_or(DecodeError::Truncated)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        ) as usize;
        let consumed = 40usize
            .checked_add(ingress_len)
            .ok_or(DecodeError::LimitExceeded)?;
        let flag = bytes.get_mut(consumed).ok_or(DecodeError::Truncated)?;
        if *flag != 0 {
            return Err(DecodeError::NonCanonical);
        }
        *flag = 1;
        Ok(())
    }
}

/// Recoverable effects created by one committed actor slice. The host may
/// expose them only after the surrounding service transaction commits, then
/// removes the row through guest Accumulate acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRecord {
    pub input: WorkInputId,
    pub receipt: AccumulationReceipt,
    pub published: PublishedEffects,
}

/// Permanent local suppression marker for external effects already accepted
/// by their consumers. CRDT rematerialization may reconstruct a publication
/// from causal history after its transient row was removed; this marker keeps
/// that replica from publishing the same logical effects forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationAckRecord {
    pub input: WorkInputId,
    pub transport_commitment: Hash,
}

/// Guest-owned proof that one exact transition produced only the atomic reply
/// shape accepted as a platform role assertion. Unlike the publication row,
/// this record survives acknowledgement so recovery cannot forget a
/// suspension, artifact, proof, attestation, or other external side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssertionEligibility {
    pub input: WorkInputId,
    pub transition_commitment: Hash,
    pub reply_commitment: Hash,
}

impl PublicationRecord {
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/publication/service", &[&self.encode()])
    }
}

impl ServiceWire for PublicationAckRecord {
    const MAGIC: [u8; 4] = *b"VPAW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_input(&mut e, self.input);
        e.fixed(&self.transport_commitment.0);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            input: decode_input(d)?,
            transport_commitment: Hash(d.fixed()?),
        };
        if value.input.invocation == InvocationId::ZERO || value.transport_commitment == Hash::ZERO
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

/// Permanent delivery identity plus restart-drain state for one finalized
/// cross-root message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRecord {
    pub call_id: CallId,
    pub logical_timeslot: u64,
    pub consumed: bool,
    /// Deadline of a terminal inbox retirement. A delivered call is either
    /// consumed by actor execution or retired, never both.
    pub retired_at: Option<u64>,
    /// Exact guest-authorized evidence survives inbox retirement so a lost
    /// source acknowledgement can still be classified as the same delivery.
    pub authorization: AuthorizationEvidence,
    pub retry_identity: Hash,
    pub delivery_commitment: Hash,
    pub receipt: AccumulationReceipt,
}

/// Permanent identity of one finalized reply consumed at an exact await
/// boundary. This lets transport recover from a lost acknowledgement even
/// after the workflow has advanced to a later await.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyAdmissionRecord {
    pub call_id: CallId,
    pub input: WorkInputId,
    pub awaited_reply: AccumulatedReply,
    pub work_hash: Hash,
}

/// Enumerable guest-owned index for one deadline-bearing suspended call.
/// The authoritative message and workflow remain in the state tree; this row
/// only makes their identity rediscoverable after a process restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCallDeadline {
    pub call_id: CallId,
    pub caller_invocation: InvocationId,
    pub deadline_timeslot: u64,
}

/// Non-recursive workflow row covered by the service tree. Receipts live in
/// the physical bookkeeping namespace because including their resulting root
/// in this row would make the commitment circular.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowCheckpoint {
    pub input: WorkInputId,
    /// Stable service/actor/caller binding shared by all continuation slices.
    pub workflow_identity: Hash,
    /// Exact last admitted work. This is durable scheduler state, not a replay
    /// instruction: the next slice reconstructs current base/state imports
    /// from service storage while retaining stable workflow inputs.
    pub resume_work: WorkEnvelope,
    pub work_hash: Hash,
    /// Linear transitions store their proof-independent execution commitment.
    /// CRDT checkpoints store
    /// the causal node CID so the row can be rebuilt from the DAG without the
    /// outer transition wire.
    pub transition_hash: Hash,
}

impl ServiceWire for WorkflowCheckpoint {
    const MAGIC: [u8; 4] = *b"VWFW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        Self::encode_materialized_body(
            out,
            self.input,
            self.workflow_identity,
            &self.resume_work,
            self.work_hash,
            self.transition_hash,
        );
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            input: decode_input(d)?,
            workflow_identity: Hash(d.fixed()?),
            resume_work: WorkEnvelope::decode(&d.bytes()?)?,
            work_hash: Hash(d.fixed()?),
            transition_hash: Hash(d.fixed()?),
        };
        if value.input != value.resume_work.input_id()
            || value.workflow_identity != value.resume_work.workflow_identity()
            || value.work_hash != value.resume_work.hash()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl WorkflowCheckpoint {
    fn encode_materialized_body(
        out: &mut Vec<u8>,
        input: WorkInputId,
        workflow_identity: Hash,
        resume_work: &WorkEnvelope,
        work_hash: Hash,
        transition_hash: Hash,
    ) {
        let mut e = Encoder(out);
        encode_input(&mut e, input);
        e.fixed(&workflow_identity.0);
        // Write the length-prefixed nested work directly into the final row.
        // A separate temporary duplicates the largest workflow owner and can
        // exhaust the bounded service guest while an exact continuation is
        // committed.
        let length_offset = e.0.len();
        e.u32(0);
        let resume_offset = e.0.len();
        e.0.extend_from_slice(&WorkEnvelope::MAGIC);
        e.0.extend_from_slice(&super::PLATFORM_ID.0);
        resume_work.encode_body(e.0);
        let resume_len = e.0.len() - resume_offset;
        let resume_len =
            u32::try_from(resume_len).expect("workflow wire is bounded by ServiceWire");
        e.0[length_offset..length_offset + 4].copy_from_slice(&resume_len.to_le_bytes());
        e.fixed(&work_hash.0);
        e.fixed(&transition_hash.0);
    }

    /// Encode a causal materialization directly from the authenticated DAG
    /// work without first cloning its complete nested resume envelope.
    pub(crate) fn encode_materialized(
        input: WorkInputId,
        workflow_identity: Hash,
        resume_work: &WorkEnvelope,
        work_hash: Hash,
        transition_hash: Hash,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        out.extend_from_slice(&super::PLATFORM_ID.0);
        Self::encode_materialized_body(
            &mut out,
            input,
            workflow_identity,
            resume_work,
            work_hash,
            transition_hash,
        );
        out
    }

    /// Stable inputs which must survive every exact continuation slice. The
    /// timeslot, step, arguments, consistency base, awaited reply, and actor
    /// state imports are intentionally reconstructed for the next execution.
    pub fn matches_resume_work(&self, work: &WorkEnvelope) -> bool {
        self.workflow_identity == work.workflow_identity()
            && self.resume_work.imported_blobs == work.imported_blobs
    }
}

impl ServiceWire for DedupRecord {
    const MAGIC: [u8; 4] = *b"VDDW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_input(&mut e, self.input);
        e.fixed(&self.work_hash.0);
        e.fixed(&self.transition_commitment.0);
        e.bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            input: decode_input(d)?,
            work_hash: Hash(d.fixed()?),
            transition_commitment: Hash(d.fixed()?),
            receipt: AccumulationReceipt::decode(&d.bytes()?)?,
        };
        if value.receipt.accepted_transition != value.transition_commitment
            || value.receipt.checkpoint != value.input.workflow_step
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for PublicationRecord {
    const MAGIC: [u8; 4] = *b"VPBW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_input(&mut e, self.input);
        e.bytes(&self.receipt.encode());
        e.bytes(&self.published.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            input: decode_input(d)?,
            receipt: AccumulationReceipt::decode(&d.bytes()?)?,
            published: PublishedEffects::decode(&d.bytes()?)?,
        };
        if value.input.invocation == InvocationId::ZERO
            || value.receipt.checkpoint != value.input.workflow_step
            || value.published == PublishedEffects::default()
            || value.receipt.reply_commitment
                != value
                    .published
                    .reply
                    .as_ref()
                    .map(super::ReplyRecord::commitment)
            || value.receipt.outbox_commitment
                != super::MessageRecord::outbox_commitment(&value.published.outbox)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for RoleAssertionEligibility {
    const MAGIC: [u8; 4] = *b"VREW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_input(&mut e, self.input);
        e.fixed(&self.transition_commitment.0);
        e.fixed(&self.reply_commitment.0);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            input: decode_input(d)?,
            transition_commitment: Hash(d.fixed()?),
            reply_commitment: Hash(d.fixed()?),
        };
        if value.input.invocation == InvocationId::ZERO || value.input.workflow_step != 0 {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for ActorUpgradeRecord {
    const MAGIC: [u8; 4] = *b"VURW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.upgrade.0);
        e.fixed(&self.actor.0);
        e.fixed(&self.previous_deployment.0);
        e.fixed(&self.previous_program.0);
        e.fixed(&self.deployment.0);
        e.fixed(&self.program.0);
        e.bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            upgrade: Hash(d.fixed()?),
            actor: ActorId(d.fixed()?),
            previous_deployment: DeploymentId(d.fixed()?),
            previous_program: ProgramId(d.fixed()?),
            deployment: DeploymentId(d.fixed()?),
            program: ProgramId(d.fixed()?),
            receipt: AccumulationReceipt::decode(&d.bytes()?)?,
        };
        if value.previous_deployment == value.deployment
            || value.receipt.accepted_transition != value.upgrade
            || value.receipt.reply_commitment.is_some()
            || value.receipt.outbox_commitment.is_some()
            || value.receipt.resulting_state_root.is_none()
            || !value.receipt.resulting_crdt_heads.is_empty()
            || value.receipt.consistency == ConsistencyMode::Crdt
            || value.receipt.checkpoint != 0
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for DeliveryRecord {
    const MAGIC: [u8; 4] = *b"VDRW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.call_id.0);
        e.u64(self.logical_timeslot);
        e.bool(self.consumed);
        e.option(&self.retired_at, |e, retired_at| e.u64(*retired_at));
        super::contracts::encode_auth(&mut e, &self.authorization);
        e.fixed(&self.retry_identity.0);
        e.fixed(&self.delivery_commitment.0);
        e.bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            call_id: CallId(d.fixed()?),
            logical_timeslot: d.u64()?,
            consumed: d.bool()?,
            retired_at: d.option(Decoder::u64)?,
            authorization: super::contracts::decode_auth(d)?,
            retry_identity: Hash(d.fixed()?),
            delivery_commitment: Hash(d.fixed()?),
            receipt: AccumulationReceipt::decode(&d.bytes()?)?,
        };
        if value.call_id == CallId::ZERO
            || value.retry_identity == Hash::ZERO
            || value.receipt.accepted_transition != value.delivery_commitment
            || value.receipt.reply_commitment.is_some()
            || value.receipt.outbox_commitment.is_some()
            || value.receipt.checkpoint != 0
            || (value.consumed && value.retired_at.is_some())
            || value.retired_at == Some(0)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for IngressRecord {
    const MAGIC: [u8; 4] = *b"VIRW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.bytes(&self.ingress.encode());
        e.bool(self.consumed);
        e.bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            ingress: DirectIngress::decode(&d.bytes()?)?,
            consumed: d.bool()?,
            receipt: AccumulationReceipt::decode(&d.bytes()?)?,
        };
        let accepted_transition = value.ingress.crdt_change.as_ref().map_or_else(
            || value.ingress.commitment(),
            CrdtChange::receipt_commitment,
        );
        if value.receipt.service != value.ingress.service
            || value.receipt.accepted_transition != accepted_transition
            || value.receipt.checkpoint != 0
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for ReplyAdmissionRecord {
    const MAGIC: [u8; 4] = *b"VRDW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.call_id.0);
        encode_input(&mut e, self.input);
        e.bytes(&self.awaited_reply.encode());
        e.fixed(&self.work_hash.0);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            call_id: CallId(d.fixed()?),
            input: decode_input(d)?,
            awaited_reply: AccumulatedReply::decode(&d.bytes()?)?,
            work_hash: Hash(d.fixed()?),
        };
        if value.call_id == CallId::ZERO
            || value.input.invocation == InvocationId::ZERO
            || value.input.workflow_step == 0
            || value.awaited_reply.reply.call_id != value.call_id
            || value.work_hash == Hash::ZERO
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl ServiceWire for PendingCallDeadline {
    const MAGIC: [u8; 4] = *b"VPDW";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.call_id.0);
        e.fixed(&self.caller_invocation.0);
        e.u64(self.deadline_timeslot);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            call_id: CallId(d.fixed()?),
            caller_invocation: InvocationId(d.fixed()?),
            deadline_timeslot: d.u64()?,
        };
        if value.call_id == CallId::ZERO || value.caller_invocation == InvocationId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

pub const fn header_storage_key() -> &'static [u8] {
    HEADER_STORAGE_KEY
}

pub fn dedup_storage_key(input: WorkInputId) -> Vec<u8> {
    input_storage_key(DEDUP_STORAGE_PREFIX, input)
}

pub fn receipt_storage_key(input: WorkInputId) -> Vec<u8> {
    input_storage_key(RECEIPT_STORAGE_PREFIX, input)
}

pub fn publication_storage_key(input: WorkInputId) -> Vec<u8> {
    input_storage_key(PUBLICATION_STORAGE_PREFIX, input)
}

pub fn publication_ack_storage_key(input: WorkInputId) -> Vec<u8> {
    input_storage_key(PUBLICATION_ACK_STORAGE_PREFIX, input)
}

pub fn role_assertion_eligibility_storage_key(input: WorkInputId) -> Vec<u8> {
    input_storage_key(ROLE_ASSERTION_ELIGIBILITY_STORAGE_PREFIX, input)
}

#[cfg(feature = "std")]
pub(crate) const fn publication_storage_prefix() -> &'static [u8] {
    PUBLICATION_STORAGE_PREFIX
}

pub fn delivery_storage_key(call: CallId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DELIVERY_STORAGE_PREFIX.len() + call.0.len());
    key.extend_from_slice(DELIVERY_STORAGE_PREFIX);
    key.extend_from_slice(&call.0);
    key
}

pub fn reply_admission_storage_key(call: CallId) -> Vec<u8> {
    let mut key = Vec::with_capacity(REPLY_ADMISSION_STORAGE_PREFIX.len() + call.0.len());
    key.extend_from_slice(REPLY_ADMISSION_STORAGE_PREFIX);
    key.extend_from_slice(&call.0);
    key
}

#[cfg(feature = "std")]
pub(crate) const fn reply_admission_storage_prefix() -> &'static [u8] {
    REPLY_ADMISSION_STORAGE_PREFIX
}

/// Guest-owned durable timeout outcome used to reconstruct an exact resume
/// after process restart or CRDT synchronization.
pub fn call_expiration_storage_key(call: CallId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CALL_EXPIRATION_STORAGE_PREFIX.len() + call.0.len());
    key.extend_from_slice(CALL_EXPIRATION_STORAGE_PREFIX);
    key.extend_from_slice(&call.0);
    key
}

#[cfg(feature = "std")]
pub(crate) const fn call_expiration_storage_prefix() -> &'static [u8] {
    CALL_EXPIRATION_STORAGE_PREFIX
}

pub fn pending_call_deadline_storage_key(call: CallId) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_CALL_DEADLINE_STORAGE_PREFIX.len() + call.0.len());
    key.extend_from_slice(PENDING_CALL_DEADLINE_STORAGE_PREFIX);
    key.extend_from_slice(&call.0);
    key
}

pub fn actor_upgrade_storage_key(upgrade: Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(ACTOR_UPGRADE_STORAGE_PREFIX.len() + upgrade.0.len());
    key.extend_from_slice(ACTOR_UPGRADE_STORAGE_PREFIX);
    key.extend_from_slice(&upgrade.0);
    key
}

#[cfg(feature = "std")]
pub(crate) const fn actor_upgrade_storage_prefix() -> &'static [u8] {
    ACTOR_UPGRADE_STORAGE_PREFIX
}

#[cfg(feature = "std")]
pub(crate) const fn pending_call_deadline_storage_prefix() -> &'static [u8] {
    PENDING_CALL_DEADLINE_STORAGE_PREFIX
}

#[cfg(feature = "std")]
pub(crate) const fn delivery_storage_prefix() -> &'static [u8] {
    DELIVERY_STORAGE_PREFIX
}

pub fn ingress_storage_key(invocation: InvocationId) -> Vec<u8> {
    let mut key = Vec::with_capacity(INGRESS_STORAGE_PREFIX.len() + invocation.0.len());
    key.extend_from_slice(INGRESS_STORAGE_PREFIX);
    key.extend_from_slice(&invocation.0);
    key
}

#[cfg(feature = "std")]
pub(crate) const fn ingress_storage_prefix() -> &'static [u8] {
    INGRESS_STORAGE_PREFIX
}

pub fn crdt_node_storage_key(cid: Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(CRDT_NODE_STORAGE_PREFIX.len() + cid.0.len());
    key.extend_from_slice(CRDT_NODE_STORAGE_PREFIX);
    key.extend_from_slice(&cid.0);
    key
}

pub fn crdt_node_receipt_storage_key(cid: Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(CRDT_NODE_RECEIPT_STORAGE_PREFIX.len() + cid.0.len());
    key.extend_from_slice(CRDT_NODE_RECEIPT_STORAGE_PREFIX);
    key.extend_from_slice(&cid.0);
    key
}

pub fn crdt_change_storage_key(change: super::ChangeId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CRDT_CHANGE_STORAGE_PREFIX.len() + change.0.len());
    key.extend_from_slice(CRDT_CHANGE_STORAGE_PREFIX);
    key.extend_from_slice(&change.0);
    key
}

fn input_storage_key(prefix: &[u8], input: WorkInputId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + input.invocation.0.len() + 8);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&input.invocation.0);
    key.extend_from_slice(&input.workflow_step.to_le_bytes());
    key
}

fn encode_input(e: &mut Encoder<'_>, input: WorkInputId) {
    e.fixed(&input.invocation.0);
    e.u64(input.workflow_step);
}

fn decode_input(d: &mut Decoder<'_>) -> Result<WorkInputId, DecodeError> {
    Ok(WorkInputId {
        invocation: InvocationId(d.fixed()?),
        workflow_step: d.u64()?,
    })
}

fn encode_service(e: &mut Encoder<'_>, service: &ServiceIdentity) {
    e.fixed(&service.space.0);
    e.fixed(&service.root_service.0);
    e.fixed(&service.deployment.0);
    e.fixed(&service.service_program.0);
    e.fixed(&service.platform.0);
    e.fixed(&service.execution_semantics.0);
    e.u64(service.gas_schedule.refine);
    e.u64(service.gas_schedule.accumulate);
}

fn decode_service(d: &mut Decoder<'_>) -> Result<ServiceIdentity, DecodeError> {
    Ok(ServiceIdentity {
        space: super::SpaceId(d.fixed()?),
        root_service: super::RootServiceId(d.fixed()?),
        deployment: super::DeploymentId(d.fixed()?),
        service_program: super::ProgramId(d.fixed()?),
        platform: Hash(d.fixed()?),
        execution_semantics: Hash(d.fixed()?),
        gas_schedule: super::GasSchedule::new(d.u64()?, d.u64()?),
    })
}

fn decode_consistency(d: &mut Decoder<'_>) -> Result<ConsistencyMode, DecodeError> {
    match d.u8()? {
        0 => Ok(ConsistencyMode::Ephemeral),
        1 => Ok(ConsistencyMode::Local),
        2 => Ok(ConsistencyMode::Raft),
        3 => Ok(ConsistencyMode::Crdt),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn ensure_hashes_sorted(values: &[Hash]) -> Result<(), DecodeError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOpenError {
    UnknownStore,
    InvalidHeader(DecodeError),
    IncompatibleSemantics,
    WrongService,
}

impl core::fmt::Display for StoreOpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownStore => f.write_str(
                "store does not belong to this platform; reset it and reinstall the signed package",
            ),
            Self::InvalidHeader(error) => write!(f, "invalid VOS service store header: {error}"),
            Self::IncompatibleSemantics => {
                f.write_str("store execution semantics do not match this runtime; reinstall")
            }
            Self::WrongService => {
                f.write_str("store belongs to a different VOS service or deployment; reinstall")
            }
        }
    }
}

impl core::error::Error for StoreOpenError {}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::service::{
        ChangeId, DeploymentId, EXECUTION_SEMANTICS_ID, MessageRecord, PLATFORM_ID, ProgramId,
        RootServiceId, empty_state_root,
    };

    fn service(byte: u8) -> ServiceIdentity {
        ServiceIdentity {
            space: crate::service::SpaceId([0; 32]),
            root_service: RootServiceId([byte; 32]),
            deployment: DeploymentId([byte.wrapping_add(1); 32]),
            service_program: ProgramId([byte.wrapping_add(2); 32]),
            platform: PLATFORM_ID,
            execution_semantics: EXECUTION_SEMANTICS_ID,
            gas_schedule: super::super::GasSchedule::new(1_000_000_000, 5_000_000_000),
        }
    }

    #[test]
    fn foreign_store_gets_actionable_clean_break_error() {
        let error = StoreHeader::open(b"foreign-state").unwrap_err();
        assert_eq!(error, StoreOpenError::UnknownStore);
        let message = error.to_string();
        assert!(message.contains("reset"));
        assert!(message.contains("reinstall"));
    }

    #[test]
    fn current_linear_and_crdt_headers_round_trip() {
        let mut linear = StoreHeader::current(service(7), ConsistencyMode::Local);
        linear.admission_timeslot_high_water = 42;
        assert_eq!(StoreHeader::open(&linear.encode()).unwrap(), linear);
        assert!(linear.state_root.is_some());
        assert_eq!(linear.service_root, linear.state_root.unwrap());

        let crdt = StoreHeader::current(service(9), ConsistencyMode::Crdt);
        assert_eq!(StoreHeader::open(&crdt.encode()).unwrap(), crdt);
        assert_eq!(crdt.state_root, None);
        assert_eq!(crdt.revision, 0);
        assert_eq!(crdt.admission_timeslot_high_water, 0);
        assert_eq!(crdt.service_root, empty_state_root());
    }

    #[test]
    fn store_header_is_bound_to_service_identity() {
        let header = StoreHeader::current(service(1), ConsistencyMode::Raft);
        assert_eq!(
            StoreHeader::open_for(&header.encode(), &service(2)),
            Err(StoreOpenError::WrongService)
        );
    }

    #[test]
    fn logical_state_keys_are_strict_and_domain_separated() {
        let actor = ActorId([3; 32]);
        let row = StateKey::ActorRow {
            actor,
            key: b"state".to_vec(),
        };
        let policy = StateKey::MethodPolicy {
            actor,
            method: "increment".into(),
        };
        assert_eq!(StateKey::decode(&row.encode()).unwrap(), row);
        assert_eq!(StateKey::decode(&policy.encode()).unwrap(), policy);
        assert_eq!(
            StateKey::decode(&StateKey::RoleAuthority.encode()).unwrap(),
            StateKey::RoleAuthority
        );
        assert_ne!(row.encode(), policy.encode());

        let invalid = StateKey::ActorRow { actor, key: vec![] };
        assert_eq!(
            StateKey::decode(&invalid.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn physical_bookkeeping_keys_cannot_alias() {
        let input = WorkInputId {
            invocation: InvocationId([4; 32]),
            workflow_step: 5,
        };
        let dedup = dedup_storage_key(input);
        let receipt = receipt_storage_key(input);
        let publication = publication_storage_key(input);
        let publication_ack = publication_ack_storage_key(input);
        let role_assertion = role_assertion_eligibility_storage_key(input);
        let delivery = delivery_storage_key(CallId([4; 32]));
        let ingress = ingress_storage_key(input.invocation);
        let reply_admission = reply_admission_storage_key(CallId([4; 32]));
        let expiration = call_expiration_storage_key(CallId([4; 32]));
        let deadline = pending_call_deadline_storage_key(CallId([4; 32]));
        let upgrade = actor_upgrade_storage_key(Hash([8; 32]));
        assert_ne!(dedup, receipt);
        assert_ne!(dedup, publication);
        assert_ne!(receipt, publication);
        assert_ne!(publication_ack, publication);
        assert_ne!(publication_ack, receipt);
        assert_ne!(role_assertion, receipt);
        assert_ne!(role_assertion, publication);
        assert_ne!(delivery, publication);
        assert_ne!(reply_admission, delivery);
        assert_ne!(reply_admission, publication);
        assert_ne!(expiration, deadline);
        assert_ne!(expiration, reply_admission);
        assert_ne!(deadline, delivery);
        assert_ne!(upgrade, receipt);
        assert_ne!(upgrade, publication);
        assert_ne!(ingress, delivery);
        assert_ne!(ingress, publication);
        assert_ne!(dedup.as_slice(), header_storage_key());
        assert_ne!(crdt_node_storage_key(Hash([6; 32])), receipt);
        assert_ne!(
            crdt_node_receipt_storage_key(Hash([6; 32])),
            crdt_node_storage_key(Hash([6; 32]))
        );
        assert_ne!(
            crdt_change_storage_key(ChangeId([6; 32])),
            crdt_node_storage_key(Hash([6; 32]))
        );
    }

    #[test]
    fn dedup_record_binds_transition_and_workflow_checkpoint() {
        let input = WorkInputId {
            invocation: InvocationId([10; 32]),
            workflow_step: 3,
        };
        let record = DedupRecord {
            input,
            work_hash: Hash([11; 32]),
            transition_commitment: Hash([12; 32]),
            receipt: AccumulationReceipt {
                service: service(13),
                accepted_transition: Hash([12; 32]),
                reply_commitment: None,
                outbox_commitment: None,
                resulting_state_root: Some(Hash([14; 32])),
                resulting_crdt_heads: vec![],
                sequence: 9,
                checkpoint: 3,
                consistency: ConsistencyMode::Local,
            },
        };
        assert_eq!(DedupRecord::decode(&record.encode()).unwrap(), record);

        let mut divergent = record;
        divergent.receipt.checkpoint = 4;
        assert_eq!(
            DedupRecord::decode(&divergent.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn publication_and_delivery_rows_bind_committed_transport_state() {
        let input = WorkInputId {
            invocation: InvocationId([20; 32]),
            workflow_step: 2,
        };
        let caller_invocation = InvocationId([21; 32]);
        let message = MessageRecord {
            call_id: caller_invocation.call_id(0),
            caller_invocation,
            await_ordinal: 0,
            from_service: service(24),
            from: ActorId([22; 32]),
            to_service: service(23),
            to: ActorId([23; 32]),
            parent: None,
            payload: vec![1],
            authorization: super::super::AuthorizationEvidence::Public,
            proof_requested: false,
            deadline_timeslot: Some(30),
        };
        let published = PublishedEffects {
            outbox: vec![message.clone()],
            ..PublishedEffects::default()
        };
        let receipt = AccumulationReceipt {
            service: service(24),
            accepted_transition: Hash([25; 32]),
            reply_commitment: None,
            outbox_commitment: MessageRecord::outbox_commitment(&published.outbox),
            resulting_state_root: Some(Hash([26; 32])),
            resulting_crdt_heads: vec![],
            sequence: 4,
            checkpoint: input.workflow_step,
            consistency: ConsistencyMode::Local,
        };
        let publication = PublicationRecord {
            input,
            receipt: receipt.clone(),
            published,
        };
        assert_eq!(
            PublicationRecord::decode(&publication.encode()).unwrap(),
            publication
        );
        let acknowledgement = PublicationAckRecord {
            input,
            transport_commitment: publication.published.transport_commitment(),
        };
        assert_eq!(
            PublicationAckRecord::decode(&acknowledgement.encode()).unwrap(),
            acknowledgement
        );
        let mut bad_publication = publication;
        bad_publication.published.outbox[0].payload.push(0);
        assert_eq!(
            PublicationRecord::decode(&bad_publication.encode()),
            Err(DecodeError::NonCanonical)
        );

        let delivery = DeliveryRecord {
            call_id: message.call_id,
            logical_timeslot: 7,
            consumed: false,
            retired_at: None,
            authorization: message.authorization.clone(),
            retry_identity: Hash([27; 32]),
            delivery_commitment: Hash([28; 32]),
            receipt: AccumulationReceipt {
                service: service(29),
                accepted_transition: Hash([28; 32]),
                reply_commitment: None,
                outbox_commitment: None,
                resulting_state_root: Some(Hash([30; 32])),
                resulting_crdt_heads: vec![],
                sequence: 5,
                checkpoint: 0,
                consistency: ConsistencyMode::Local,
            },
        };
        assert_eq!(
            DeliveryRecord::decode(&delivery.encode()).unwrap(),
            delivery
        );
        let mut retired_delivery = delivery.clone();
        retired_delivery.retired_at = Some(19);
        assert_eq!(
            DeliveryRecord::decode(&retired_delivery.encode()).unwrap(),
            retired_delivery
        );
        let mut impossible_delivery = delivery.clone();
        impossible_delivery.consumed = true;
        impossible_delivery.retired_at = Some(19);
        assert_eq!(
            DeliveryRecord::decode(&impossible_delivery.encode()),
            Err(DecodeError::NonCanonical)
        );
        let mut bad_delivery = delivery;
        bad_delivery.receipt.accepted_transition = Hash([31; 32]);
        assert_eq!(
            DeliveryRecord::decode(&bad_delivery.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn ingress_record_round_trips() {
        let ingress = IngressRecord {
            ingress: DirectIngress {
                service: service(18),
                invocation: InvocationId([19; 32]),
                logical_timeslot: 11,
                target: ActorId([20; 32]),
                method: "value".into(),
                arguments: vec![1],
                private_arguments: None,
                origin: super::super::Origin::Anonymous,
                authorization: super::super::AuthorizationEvidence::Public,
                imported_blobs: vec![],
                proof_requested: false,
                base: super::super::ConsistencyBase::Linear {
                    revision: 10,
                    state_root: Hash([18; 32]),
                },
                base_causal_height: None,
                crdt_change: None,
            },
            consumed: false,
            receipt: AccumulationReceipt {
                service: service(18),
                accepted_transition: Hash::ZERO,
                reply_commitment: None,
                outbox_commitment: None,
                resulting_state_root: Some(Hash([18; 32])),
                resulting_crdt_heads: vec![],
                sequence: 10,
                checkpoint: 0,
                consistency: ConsistencyMode::Local,
            },
        };
        let mut ingress = ingress;
        ingress.receipt.accepted_transition = ingress.ingress.commitment();
        assert_eq!(IngressRecord::decode(&ingress.encode()).unwrap(), ingress);

        let mut consumed = ingress.encode();
        IngressRecord::mark_consumed_in_place(&mut consumed).unwrap();
        let decoded = IngressRecord::decode(&consumed).unwrap();
        assert!(decoded.consumed);
        assert_eq!(decoded.ingress, ingress.ingress);
        assert_eq!(decoded.receipt, ingress.receipt);
        assert_eq!(
            IngressRecord::mark_consumed_in_place(&mut consumed),
            Err(DecodeError::NonCanonical),
            "the atomic lifecycle bit cannot be consumed twice",
        );
    }

    #[test]
    fn reply_admission_binds_call_input_reply_and_work() {
        let caller_invocation = InvocationId([40; 32]);
        let call = caller_invocation.call_id(3);
        let reply = super::super::ReplyRecord {
            call_id: call,
            producer: ActorId([41; 32]),
            result: vec![42],
        };
        let mut remote = service(43);
        remote.root_service = RootServiceId([44; 32]);
        let record = ReplyAdmissionRecord {
            call_id: call,
            input: WorkInputId {
                invocation: caller_invocation,
                workflow_step: 2,
            },
            awaited_reply: AccumulatedReply {
                receipt: AccumulationReceipt {
                    service: remote,
                    accepted_transition: Hash([45; 32]),
                    reply_commitment: Some(reply.commitment()),
                    outbox_commitment: None,
                    resulting_state_root: Some(Hash([46; 32])),
                    resulting_crdt_heads: vec![],
                    sequence: 3,
                    checkpoint: 0,
                    consistency: ConsistencyMode::Local,
                },
                reply,
                attestation: None,
            },
            work_hash: Hash([47; 32]),
        };
        assert_eq!(
            ReplyAdmissionRecord::decode(&record.encode()).unwrap(),
            record
        );

        let mut step_zero = record;
        step_zero.input.workflow_step = 0;
        assert_eq!(
            ReplyAdmissionRecord::decode(&step_zero.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn pending_deadline_row_binds_its_restart_identity() {
        let invocation = InvocationId([50; 32]);
        let deadline = PendingCallDeadline {
            call_id: invocation.call_id(2),
            caller_invocation: invocation,
            deadline_timeslot: 99,
        };
        assert_eq!(
            PendingCallDeadline::decode(&deadline.encode()).unwrap(),
            deadline
        );

        let mut invalid = deadline;
        invalid.call_id = CallId::ZERO;
        assert_eq!(
            PendingCallDeadline::decode(&invalid.encode()),
            Err(DecodeError::NonCanonical)
        );
    }
}
