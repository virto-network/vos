//! Clean-break guest-owned service storage schema.
//!
//! The header is the mutable root anchor and is deliberately not a leaf in
//! the application state tree. Deduplication and receipt rows are likewise
//! consensus service storage, but excluded from the application root to avoid
//! making a receipt commit to itself.

use alloc::string::String;
use alloc::vec::Vec;

use super::wire::{DecodeError, Decoder, Encoder, V2Wire};
use super::{
    AccumulationReceiptV2, ActorId, CallId, ConsistencyModeV2, DirectIngressV2, Hash, InvocationId,
    PublishedEffectsV2, ReplyRecordV2, ServiceIdentityV2, WorkEnvelopeV2, WorkInputIdV2,
};

pub const SERVICE_STORE_SCHEMA_VERSION: u16 = 8;

/// Physical keys used directly in the JAM service account. They are outside
/// every actor's logical keyspace and never exposed through application APIs.
const HEADER_STORAGE_KEY: &[u8] = b"\0vos/v2/header";
const DEDUP_STORAGE_PREFIX: &[u8] = b"\0vos/v2/dedup/";
const RECEIPT_STORAGE_PREFIX: &[u8] = b"\0vos/v2/receipt/";
const PUBLICATION_STORAGE_PREFIX: &[u8] = b"\0vos/v2/publication/";
const ATTESTATION_ARCHIVE_STORAGE_PREFIX: &[u8] = b"\0vos/v2/attestation-archive/";
const DELIVERY_STORAGE_PREFIX: &[u8] = b"\0vos/v2/delivery/";
const INGRESS_STORAGE_PREFIX: &[u8] = b"\0vos/v2/ingress/";
const CRDT_NODE_STORAGE_PREFIX: &[u8] = b"\0vos/v2/crdt-node/";
const CRDT_NODE_RECEIPT_STORAGE_PREFIX: &[u8] = b"\0vos/v2/crdt-node-receipt/";
const CRDT_CHANGE_STORAGE_PREFIX: &[u8] = b"\0vos/v2/crdt-change/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreHeaderV2 {
    pub schema_version: u16,
    pub service: ServiceIdentityV2,
    pub consistency: ConsistencyModeV2,
    /// Root of the guest-owned service metadata/workflow tree. It exists for
    /// every consistency mode; CRDT receipts expose causal heads instead.
    pub service_root: Hash,
    /// Exact current revision for Ephemeral, Local, and Raft. CRDT services
    /// derive receipt sequence from causal height and keep this at zero.
    pub revision: u64,
    pub state_root: Option<Hash>,
    pub crdt_heads: Vec<Hash>,
    pub snapshot_version: u16,
}

impl StoreHeaderV2 {
    pub fn current(service: ServiceIdentityV2, consistency: ConsistencyModeV2) -> Self {
        Self {
            schema_version: SERVICE_STORE_SCHEMA_VERSION,
            service,
            consistency,
            service_root: super::state_tree::empty_state_root(),
            revision: 0,
            state_root: (consistency != ConsistencyModeV2::Crdt)
                .then(super::state_tree::empty_state_root),
            crdt_heads: Vec::new(),
            snapshot_version: super::SNAPSHOT_VERSION,
        }
    }

    pub fn open(bytes: &[u8]) -> Result<Self, StoreOpenError> {
        if bytes.get(..4) != Some(&Self::MAGIC) {
            return Err(StoreOpenError::LegacyStore);
        }
        let header = Self::decode(bytes).map_err(StoreOpenError::InvalidHeader)?;
        if header.schema_version != SERVICE_STORE_SCHEMA_VERSION
            || header.service.service_abi != super::ABI_VERSION
            || header.service.execution_semantics != super::EXECUTION_SEMANTICS_ID
            || header.snapshot_version != super::SNAPSHOT_VERSION
        {
            return Err(StoreOpenError::IncompatibleSemantics);
        }
        Ok(header)
    }

    pub fn open_for(bytes: &[u8], expected: &ServiceIdentityV2) -> Result<Self, StoreOpenError> {
        let header = Self::open(bytes)?;
        if &header.service != expected {
            return Err(StoreOpenError::WrongService);
        }
        Ok(header)
    }
}

impl V2Wire for StoreHeaderV2 {
    const MAGIC: [u8; 4] = *b"VST2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.u16(self.schema_version);
        encode_service(&mut e, &self.service);
        e.u8(self.consistency as u8);
        e.fixed(&self.service_root.0);
        e.u64(self.revision);
        e.option(&self.state_root, |e, root| e.fixed(&root.0));
        e.list(&self.crdt_heads, |e, head| e.fixed(&head.0));
        e.u16(self.snapshot_version);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            schema_version: d.u16()?,
            service: decode_service(d)?,
            consistency: decode_consistency(d)?,
            service_root: Hash(d.fixed()?),
            revision: d.u64()?,
            state_root: d.option(|d| d.fixed().map(Hash))?,
            crdt_heads: d.list(|d| d.fixed().map(Hash))?,
            snapshot_version: d.u16()?,
        };
        ensure_hashes_sorted(&value.crdt_heads)?;
        let valid_commitment = match value.consistency {
            ConsistencyModeV2::Crdt => value.state_root.is_none() && value.revision == 0,
            ConsistencyModeV2::Ephemeral | ConsistencyModeV2::Local | ConsistencyModeV2::Raft => {
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
pub enum StateKeyV2 {
    /// Canonical, sorted membership of the complete root actor tree.
    ActorDirectory,
    /// Canonical install-time bindings to actors owned by other root trees.
    ExternalActorDirectory,
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
    /// Once-only verifier admission. Its value is the exact canonical proof
    /// obligation accepted atomically with the authorized actor effects.
    AttestationReplay {
        actor: ActorId,
        invocation: InvocationId,
    },
    CrdtMaterialization(ActorId),
    ActorName {
        parent: Option<ActorId>,
        name: String,
    },
}

impl V2Wire for StateKeyV2 {
    const MAGIC: [u8; 4] = *b"VSK2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        match self {
            Self::ActorDirectory => {
                e.u8(9);
            }
            Self::ExternalActorDirectory => {
                e.u8(10);
            }
            Self::AttestationReplay { actor, invocation } => {
                e.u8(11);
                e.fixed(&actor.0);
                e.fixed(&invocation.0);
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
            Self::ActorName { parent, name } => {
                e.u8(8);
                e.option(parent, |e, parent| e.fixed(&parent.0));
                e.string(name);
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
            8 => {
                let parent = d.option(|d| d.fixed().map(ActorId))?;
                let name = d.string()?;
                if name.is_empty() {
                    return Err(DecodeError::NonCanonical);
                }
                Ok(Self::ActorName { parent, name })
            }
            9 => Ok(Self::ActorDirectory),
            10 => Ok(Self::ExternalActorDirectory),
            11 => Ok(Self::AttestationReplay {
                actor: ActorId(d.fixed()?),
                invocation: InvocationId(d.fixed()?),
            }),
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupRecordV2 {
    pub input: WorkInputIdV2,
    pub work_hash: Hash,
    pub transition_commitment: Hash,
    pub receipt: AccumulationReceiptV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRecordV2 {
    pub call_id: CallId,
    /// Exact consensus timeslot at which the inbox row was admitted. Hosts
    /// use the next logical timeslot when draining this row after restart.
    pub logical_timeslot: u64,
    /// Set by the same guest Accumulate transaction that consumes the inbox
    /// row. The finalized delivery identity remains for duplicate ACK replay.
    pub consumed: bool,
    pub retry_identity: Hash,
    pub delivery_commitment: Hash,
    pub receipt: AccumulationReceiptV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressRecordV2 {
    pub ingress: DirectIngressV2,
    /// Set atomically with the initial actor slice. The original admission is
    /// retained as the permanent invocation deduplication identity.
    pub consumed: bool,
    /// Exact guest receipt for the admission node. CRDT peers verify this
    /// before importing the queued invocation through SyncCrdt.
    pub receipt: AccumulationReceiptV2,
}

/// Recoverable effects created by one committed actor slice. The host may
/// expose these bytes only after the surrounding service transaction commits,
/// then removes the row through guest Accumulate acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRecordV2 {
    pub input: WorkInputIdV2,
    pub receipt: AccumulationReceiptV2,
    pub published: PublishedEffectsV2,
}

impl PublicationRecordV2 {
    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/publication/v2", &[&self.encode()])
    }
}

/// Non-recursive workflow row covered by the service tree. Receipts live in
/// the physical bookkeeping namespace because including their resulting root
/// in this row would make the commitment circular.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowCheckpointV2 {
    pub input: WorkInputIdV2,
    /// Stable service/actor/caller binding shared by all continuation slices.
    pub workflow_identity: Hash,
    /// Exact last admitted work. This is durable scheduler state, not a replay
    /// instruction: the next slice reconstructs current base/state imports
    /// from service storage while retaining the stable method, caller,
    /// authorization, arguments, and application blob references here.
    pub resume_work: WorkEnvelopeV2,
    pub work_hash: Hash,
    pub transition_commitment: Hash,
    /// Canonical completed reply retained after its transient publication is
    /// acknowledged, so an exact invocation retry can recover the result.
    pub reply: Option<ReplyRecordV2>,
}

impl V2Wire for WorkflowCheckpointV2 {
    const MAGIC: [u8; 4] = *b"VWF2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_input(&mut e, self.input);
        e.fixed(&self.workflow_identity.0);
        e.bytes(&self.resume_work.encode());
        e.fixed(&self.work_hash.0);
        e.fixed(&self.transition_commitment.0);
        e.option(&self.reply, |e, reply| e.bytes(&reply.encode()));
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            input: decode_input(d)?,
            workflow_identity: Hash(d.fixed()?),
            resume_work: WorkEnvelopeV2::decode(&d.bytes()?)?,
            work_hash: Hash(d.fixed()?),
            transition_commitment: Hash(d.fixed()?),
            reply: d.option(|d| ReplyRecordV2::decode(&d.bytes()?))?,
        };
        if value.input != value.resume_work.input_id()
            || value.workflow_identity != value.resume_work.workflow_identity()
            || value.work_hash != value.resume_work.hash()
            || value.reply.as_ref().is_some_and(|reply| {
                reply.producer != value.resume_work.target
                    || reply.call_id
                        != value
                            .resume_work
                            .parent_call
                            .unwrap_or_else(|| value.resume_work.invocation.root_reply_id())
            })
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl WorkflowCheckpointV2 {
    /// Stable inputs which must survive every exact continuation slice. The
    /// timeslot, step, consistency base, awaited reply, and imported actor
    /// state are intentionally rebuilt for the next scheduled execution.
    pub fn matches_resume_work(&self, work: &WorkEnvelopeV2) -> bool {
        self.workflow_identity == work.workflow_identity()
            && self.resume_work.arguments == work.arguments
            && self.resume_work.imported_blobs == work.imported_blobs
    }
}

impl V2Wire for DedupRecordV2 {
    const MAGIC: [u8; 4] = *b"VDD2";

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
            receipt: AccumulationReceiptV2::decode(&d.bytes()?)?,
        };
        if value.receipt.accepted_transition != value.transition_commitment
            || value.receipt.checkpoint != value.input.workflow_step
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for DeliveryRecordV2 {
    const MAGIC: [u8; 4] = *b"VDR2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.call_id.0);
        e.u64(self.logical_timeslot);
        e.bool(self.consumed);
        e.fixed(&self.retry_identity.0);
        e.fixed(&self.delivery_commitment.0);
        e.bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            call_id: CallId(d.fixed()?),
            logical_timeslot: d.u64()?,
            consumed: d.bool()?,
            retry_identity: Hash(d.fixed()?),
            delivery_commitment: Hash(d.fixed()?),
            receipt: AccumulationReceiptV2::decode(&d.bytes()?)?,
        };
        if value.retry_identity == Hash::ZERO
            || value.receipt.accepted_transition != value.delivery_commitment
            || value.receipt.reply_commitment.is_some()
            || value.receipt.outbox_commitment.is_some()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for IngressRecordV2 {
    const MAGIC: [u8; 4] = *b"VIR2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.bytes(&self.ingress.encode());
        e.bool(self.consumed);
        e.bytes(&self.receipt.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            ingress: DirectIngressV2::decode(&d.bytes()?)?,
            consumed: d.bool()?,
            receipt: AccumulationReceiptV2::decode(&d.bytes()?)?,
        };
        if value.receipt.service != value.ingress.service
            || value.receipt.accepted_transition != value.ingress.commitment()
            || value.receipt.checkpoint != 0
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

impl V2Wire for PublicationRecordV2 {
    const MAGIC: [u8; 4] = *b"VPB2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_input(&mut e, self.input);
        e.bytes(&self.receipt.encode());
        e.bytes(&self.published.encode());
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            input: decode_input(d)?,
            receipt: AccumulationReceiptV2::decode(&d.bytes()?)?,
            published: PublishedEffectsV2::decode(&d.bytes()?)?,
        };
        if value.published == PublishedEffectsV2::default()
            || value.receipt.checkpoint != value.input.workflow_step
            || value
                .published
                .reply
                .as_ref()
                .map(super::ReplyRecordV2::commitment)
                != value.receipt.reply_commitment
            || super::MessageRecordV2::outbox_commitment(&value.published.outbox)
                != value.receipt.outbox_commitment
            || !value
                .published
                .attestation_matches_receipt(&value.receipt)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(value)
    }
}

pub const fn header_storage_key() -> &'static [u8] {
    HEADER_STORAGE_KEY
}

pub fn dedup_storage_key(input: WorkInputIdV2) -> Vec<u8> {
    input_storage_key(DEDUP_STORAGE_PREFIX, input)
}

pub fn receipt_storage_key(input: WorkInputIdV2) -> Vec<u8> {
    input_storage_key(RECEIPT_STORAGE_PREFIX, input)
}

pub fn publication_storage_key(input: WorkInputIdV2) -> Vec<u8> {
    input_storage_key(PUBLICATION_STORAGE_PREFIX, input)
}

pub fn attestation_archive_storage_key(input: WorkInputIdV2) -> Vec<u8> {
    input_storage_key(ATTESTATION_ARCHIVE_STORAGE_PREFIX, input)
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

fn input_storage_key(prefix: &[u8], input: WorkInputIdV2) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + input.invocation.0.len() + 8);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&input.invocation.0);
    key.extend_from_slice(&input.workflow_step.to_le_bytes());
    key
}

fn encode_input(e: &mut Encoder<'_>, input: WorkInputIdV2) {
    e.fixed(&input.invocation.0);
    e.u64(input.workflow_step);
}

fn decode_input(d: &mut Decoder<'_>) -> Result<WorkInputIdV2, DecodeError> {
    Ok(WorkInputIdV2 {
        invocation: InvocationId(d.fixed()?),
        workflow_step: d.u64()?,
    })
}

fn encode_service(e: &mut Encoder<'_>, service: &ServiceIdentityV2) {
    e.fixed(&service.space.0);
    e.fixed(&service.root_service.0);
    e.fixed(&service.deployment.0);
    e.fixed(&service.service_program.0);
    e.u16(service.service_abi);
    e.fixed(&service.execution_semantics.0);
}

fn decode_service(d: &mut Decoder<'_>) -> Result<ServiceIdentityV2, DecodeError> {
    Ok(ServiceIdentityV2 {
        space: super::SpaceId(d.fixed()?),
        root_service: super::RootServiceId(d.fixed()?),
        deployment: super::DeploymentId(d.fixed()?),
        service_program: super::ProgramId(d.fixed()?),
        service_abi: d.u16()?,
        execution_semantics: Hash(d.fixed()?),
    })
}

fn decode_consistency(d: &mut Decoder<'_>) -> Result<ConsistencyModeV2, DecodeError> {
    match d.u8()? {
        0 => Ok(ConsistencyModeV2::Ephemeral),
        1 => Ok(ConsistencyModeV2::Local),
        2 => Ok(ConsistencyModeV2::Raft),
        3 => Ok(ConsistencyModeV2::Crdt),
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
    LegacyStore,
    InvalidHeader(DecodeError),
    IncompatibleSemantics,
    WrongService,
}

impl core::fmt::Display for StoreOpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LegacyStore => f.write_str(
                "this is a VOS v1 store; runtime v2 cannot migrate it—export any needed data, \
                 reset the store, and reinstall the signed .vos package",
            ),
            Self::InvalidHeader(error) => write!(f, "invalid VOS v2 store header: {error}"),
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
    use crate::v2::{
        ABI_VERSION, ChangeId, DeploymentId, EXECUTION_SEMANTICS_ID, ProgramId, ReplyRecordV2,
        RootServiceId, empty_state_root,
    };

    fn service(byte: u8) -> ServiceIdentityV2 {
        ServiceIdentityV2 {
            space: crate::v2::SpaceId([0; 32]),
            root_service: RootServiceId([byte; 32]),
            deployment: DeploymentId([byte.wrapping_add(1); 32]),
            service_program: ProgramId([byte.wrapping_add(2); 32]),
            service_abi: ABI_VERSION,
            execution_semantics: EXECUTION_SEMANTICS_ID,
        }
    }

    #[test]
    fn v1_store_gets_actionable_clean_break_error() {
        let error = StoreHeaderV2::open(b"legacy-state").unwrap_err();
        assert_eq!(error, StoreOpenError::LegacyStore);
        let message = error.to_string();
        assert!(message.contains("reset"));
        assert!(message.contains("reinstall"));
    }

    #[test]
    fn current_linear_and_crdt_headers_round_trip() {
        let linear = StoreHeaderV2::current(service(7), ConsistencyModeV2::Local);
        assert_eq!(StoreHeaderV2::open(&linear.encode()).unwrap(), linear);
        assert!(linear.state_root.is_some());
        assert_eq!(linear.service_root, linear.state_root.unwrap());

        let crdt = StoreHeaderV2::current(service(9), ConsistencyModeV2::Crdt);
        assert_eq!(StoreHeaderV2::open(&crdt.encode()).unwrap(), crdt);
        assert_eq!(crdt.state_root, None);
        assert_eq!(crdt.revision, 0);
        assert_eq!(crdt.service_root, empty_state_root());
    }

    #[test]
    fn store_header_is_bound_to_service_identity() {
        let header = StoreHeaderV2::current(service(1), ConsistencyModeV2::Raft);
        assert_eq!(
            StoreHeaderV2::open_for(&header.encode(), &service(2)),
            Err(StoreOpenError::WrongService)
        );
    }

    #[test]
    fn logical_state_keys_are_strict_and_domain_separated() {
        let actor = ActorId([3; 32]);
        let row = StateKeyV2::ActorRow {
            actor,
            key: b"state".to_vec(),
        };
        let policy = StateKeyV2::MethodPolicy {
            actor,
            method: "increment".into(),
        };
        let name = StateKeyV2::ActorName {
            parent: Some(actor),
            name: "child".into(),
        };
        assert_eq!(StateKeyV2::decode(&row.encode()).unwrap(), row);
        assert_eq!(StateKeyV2::decode(&policy.encode()).unwrap(), policy);
        assert_eq!(StateKeyV2::decode(&name.encode()).unwrap(), name);
        assert_ne!(row.encode(), policy.encode());
        assert_ne!(row.encode(), name.encode());

        let invalid = StateKeyV2::ActorRow { actor, key: vec![] };
        assert_eq!(
            StateKeyV2::decode(&invalid.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn physical_bookkeeping_keys_cannot_alias() {
        let input = WorkInputIdV2 {
            invocation: InvocationId([4; 32]),
            workflow_step: 5,
        };
        let dedup = dedup_storage_key(input);
        let receipt = receipt_storage_key(input);
        let publication = publication_storage_key(input);
        let attestation = attestation_archive_storage_key(input);
        let delivery = delivery_storage_key(CallId([7; 32]));
        let ingress = ingress_storage_key(input.invocation);
        assert_ne!(dedup, receipt);
        assert_ne!(publication, receipt);
        assert_ne!(publication, dedup);
        assert_ne!(attestation, publication);
        assert_ne!(attestation, receipt);
        assert_ne!(attestation, dedup);
        assert_ne!(delivery, receipt);
        assert_ne!(delivery, dedup);
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
        let input = WorkInputIdV2 {
            invocation: InvocationId([10; 32]),
            workflow_step: 3,
        };
        let record = DedupRecordV2 {
            input,
            work_hash: Hash([11; 32]),
            transition_commitment: Hash([12; 32]),
            receipt: AccumulationReceiptV2 {
                service: service(13),
                accepted_transition: Hash([12; 32]),
                reply_commitment: None,
                outbox_commitment: None,
                resulting_state_root: Some(Hash([14; 32])),
                resulting_crdt_heads: vec![],
                sequence: 9,
                checkpoint: 3,
                consistency: ConsistencyModeV2::Local,
            },
        };
        assert_eq!(DedupRecordV2::decode(&record.encode()).unwrap(), record);

        let mut divergent = record;
        divergent.receipt.checkpoint = 4;
        assert_eq!(
            DedupRecordV2::decode(&divergent.encode()),
            Err(DecodeError::NonCanonical)
        );

        let delivery = DeliveryRecordV2 {
            call_id: CallId([15; 32]),
            logical_timeslot: 9,
            consumed: false,
            retry_identity: Hash([14; 32]),
            delivery_commitment: Hash([16; 32]),
            receipt: AccumulationReceiptV2 {
                service: service(17),
                accepted_transition: Hash([16; 32]),
                reply_commitment: None,
                outbox_commitment: None,
                resulting_state_root: Some(Hash([18; 32])),
                resulting_crdt_heads: vec![],
                sequence: 10,
                checkpoint: 0,
                consistency: ConsistencyModeV2::Local,
            },
        };
        assert_eq!(
            DeliveryRecordV2::decode(&delivery.encode()).unwrap(),
            delivery
        );

        let ingress = IngressRecordV2 {
            ingress: DirectIngressV2 {
                service: service(18),
                invocation: InvocationId([19; 32]),
                logical_timeslot: 11,
                target: ActorId([20; 32]),
                method: "value".into(),
                arguments: vec![1],
                origin: super::super::Origin::Anonymous,
                authorization: super::super::AuthorizationEvidenceV2::Public,
                imported_blobs: vec![],
                proof_requested: false,
                base: super::super::ConsistencyBaseV2::Linear {
                    revision: 10,
                    state_root: Hash([18; 32]),
                },
                base_causal_height: None,
                crdt_change: None,
            },
            consumed: false,
            receipt: AccumulationReceiptV2 {
                service: service(18),
                accepted_transition: Hash::ZERO,
                reply_commitment: None,
                outbox_commitment: None,
                resulting_state_root: Some(Hash([18; 32])),
                resulting_crdt_heads: vec![],
                sequence: 10,
                checkpoint: 0,
                consistency: ConsistencyModeV2::Local,
            },
        };
        let mut ingress = ingress;
        ingress.receipt.accepted_transition = ingress.ingress.commitment();
        assert_eq!(IngressRecordV2::decode(&ingress.encode()).unwrap(), ingress);

        let reply = ReplyRecordV2 {
            call_id: CallId([21; 32]),
            producer: ActorId([22; 32]),
            result: b"committed reply".to_vec(),
        };
        let publication = PublicationRecordV2 {
            input,
            receipt: AccumulationReceiptV2 {
                service: service(21),
                accepted_transition: Hash([22; 32]),
                reply_commitment: Some(reply.commitment()),
                outbox_commitment: None,
                resulting_state_root: Some(Hash([23; 32])),
                resulting_crdt_heads: vec![],
                sequence: 11,
                checkpoint: input.workflow_step,
                consistency: ConsistencyModeV2::Local,
            },
            published: PublishedEffectsV2 {
                reply: Some(reply),
                ..PublishedEffectsV2::default()
            },
        };
        assert_eq!(
            PublicationRecordV2::decode(&publication.encode()).unwrap(),
            publication
        );
    }
}
