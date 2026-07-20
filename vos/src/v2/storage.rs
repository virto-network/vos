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
    AccumulationReceiptV2, ActorId, CallId, ConsistencyModeV2, Hash, InvocationId,
    ServiceIdentityV2, WorkEnvelopeV2, WorkInputIdV2,
};

pub const SERVICE_STORE_SCHEMA_VERSION: u16 = 2;

/// Physical keys used directly in the JAM service account. They are outside
/// every actor's logical keyspace and never exposed through application APIs.
const HEADER_STORAGE_KEY: &[u8] = b"\0vos/v2/header";
const DEDUP_STORAGE_PREFIX: &[u8] = b"\0vos/v2/dedup/";
const RECEIPT_STORAGE_PREFIX: &[u8] = b"\0vos/v2/receipt/";
const CRDT_NODE_STORAGE_PREFIX: &[u8] = b"\0vos/v2/crdt-node/";
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
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            input: decode_input(d)?,
            workflow_identity: Hash(d.fixed()?),
            resume_work: WorkEnvelopeV2::decode(&d.bytes()?)?,
            work_hash: Hash(d.fixed()?),
            transition_commitment: Hash(d.fixed()?),
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

pub const fn header_storage_key() -> &'static [u8] {
    HEADER_STORAGE_KEY
}

pub fn dedup_storage_key(input: WorkInputIdV2) -> Vec<u8> {
    input_storage_key(DEDUP_STORAGE_PREFIX, input)
}

pub fn receipt_storage_key(input: WorkInputIdV2) -> Vec<u8> {
    input_storage_key(RECEIPT_STORAGE_PREFIX, input)
}

pub fn crdt_node_storage_key(cid: Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(CRDT_NODE_STORAGE_PREFIX.len() + cid.0.len());
    key.extend_from_slice(CRDT_NODE_STORAGE_PREFIX);
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
        ABI_VERSION, ChangeId, DeploymentId, EXECUTION_SEMANTICS_ID, ProgramId, RootServiceId,
        empty_state_root,
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
        assert_ne!(dedup, receipt);
        assert_ne!(dedup.as_slice(), header_storage_key());
        assert_ne!(crdt_node_storage_key(Hash([6; 32])), receipt);
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
    }
}
