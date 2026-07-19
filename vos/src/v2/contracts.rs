use alloc::string::String;
#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

use super::identity::*;
use super::wire::{DecodeError, Decoder, Encoder, V2Wire};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIdentityV2 {
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
    /// Opaque credential and the generated policy it must satisfy. For an
    /// attested method the credential is supplied to the prover privately;
    /// only its commitment appears here.
    Credential {
        policy: Hash,
        credential_commitment: Hash,
        bytes: Vec<u8>,
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
    pub state: BlobRefV2,
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
    pub state: Vec<u8>,
    /// Canonical generated actor-message bytes.
    pub message: Vec<u8>,
    pub origin: Origin,
}

/// Actor-produced result returned through the same IPC DATA capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorSliceOutputV2 {
    pub actor: ActorId,
    pub writes: Vec<ActorWriteV2>,
    pub reply: Vec<u8>,
    pub yielded: bool,
    pub forbidden: bool,
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
    pub target: ActorId,
    pub target_program: ProgramId,
    pub method: String,
    pub arguments: Vec<u8>,
    pub origin: Origin,
    pub authorization: AuthorizationEvidenceV2,
    pub causal_parent: Option<InvocationId>,
    pub parent_call: Option<CallId>,
    pub consistency: ConsistencyModeV2,
    pub base: ConsistencyBaseV2,
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
    pub id: OperationId,
    pub causal_dependencies: Vec<Hash>,
    pub payload: Vec<u8>,
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
    pub from: ActorId,
    pub to: ActorId,
    pub parent: Option<CallId>,
    pub payload: Vec<u8>,
    pub deadline_timeslot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyRecordV2 {
    pub call_id: CallId,
    pub producer: ActorId,
    pub result: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GasAccountingV2 {
    pub refine_used: u64,
    pub proof_used: u64,
    pub accumulate_used: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofCommitmentV2 {
    pub trace: Hash,
    pub proof_blob: BlobRefV2,
    pub statement_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionV2 {
    pub service: ServiceIdentityV2,
    pub consumed_input: WorkInputIdV2,
    pub target_program: ProgramId,
    pub base: ConsistencyBaseV2,
    pub writes: Vec<ActorWriteV2>,
    pub crdt_operations: Vec<CrdtOperationV2>,
    pub resulting_crdt_heads: Vec<Hash>,
    pub continuations: Vec<ContinuationChangeV2>,
    pub inbox: Vec<MessageRecordV2>,
    pub outbox: Vec<MessageRecordV2>,
    pub reply: Option<ReplyRecordV2>,
    pub exported_blobs: Vec<BlobRefV2>,
    pub gas: GasAccountingV2,
    pub proof: Option<ProofCommitmentV2>,
}

impl TransitionV2 {
    pub fn hash(&self) -> Hash {
        let encoded = self.encode();
        Hash::digest(b"vos/transition/v2", &[&encoded])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccumulationReceiptV2 {
    pub service: ServiceIdentityV2,
    pub accepted_transition: Hash,
    pub resulting_state_root: Option<Hash>,
    pub resulting_crdt_heads: Vec<Hash>,
    pub sequence: u64,
    pub checkpoint: u64,
    pub consistency: ConsistencyModeV2,
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

/// Pure logical Refine implementation. It has no receiver and receives no
/// mutable service store; all code, state, credentials, continuations, and
/// blobs must be present in `work`/`imports`.
///
/// Making Refine an associated operation is deliberate: a service cannot
/// smuggle invocation-to-invocation state through a refiner instance. The
/// production service still enforces determinism at the PVM boundary, but the
/// Rust conformance surface does not make stateful Refine implementations look
/// valid in the first place.
pub trait Refine {
    fn refine(
        work: &WorkEnvelopeV2,
        imports: &RefineImportsV2,
    ) -> Result<TransitionV2, RefineError>;
}

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
        e.fixed(&self.target.0);
        e.fixed(&self.target_program.0);
        e.string(&self.method);
        e.bytes(&self.arguments);
        encode_origin(&mut e, self.origin);
        encode_auth(&mut e, &self.authorization);
        e.option(&self.causal_parent, |e, id| e.fixed(&id.0));
        e.option(&self.parent_call, |e, id| e.fixed(&id.0));
        e.u8(self.consistency as u8);
        encode_base(&mut e, &self.base);
        e.list(&self.imported_actors, encode_imported_actor);
        e.list(&self.imported_blobs, encode_blob_ref);
        e.bool(self.proof_requested);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let service = decode_service(d)?;
        let invocation = InvocationId(d.fixed()?);
        let workflow_step = d.u64()?;
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
        let consistency = ConsistencyModeV2::decode(d)?;
        let base = decode_base(d)?;
        if !base.mode_compatible(consistency) {
            return Err(DecodeError::NonCanonical);
        }
        let imported_actors = d.list(decode_imported_actor)?;
        let imported_blobs = d.list(decode_blob_ref)?;
        let proof_requested = d.bool()?;
        ensure_sorted_unique(&imported_actors, |actor| actor.actor.0)?;
        ensure_sorted_unique(&imported_blobs, |b| b.hash.0)?;
        Ok(Self {
            service,
            invocation,
            workflow_step,
            target,
            target_program,
            method,
            arguments,
            origin,
            authorization,
            causal_parent,
            parent_call,
            consistency,
            base,
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
        e.bytes(&self.state);
        e.bytes(&self.message);
        encode_origin(&mut e, self.origin);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            actor: ActorId(d.fixed()?),
            state: d.bytes()?,
            message: d.bytes()?,
            origin: decode_origin(d)?,
        })
    }
}

impl V2Wire for ActorSliceOutputV2 {
    const MAGIC: [u8; 4] = *b"VSO2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        e.fixed(&self.actor.0);
        e.list(&self.writes, encode_write);
        e.bytes(&self.reply);
        e.bool(self.yielded);
        e.bool(self.forbidden);
    }

    fn decode_body(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor: ActorId(d.fixed()?),
            writes: d.list(decode_write)?,
            reply: d.bytes()?,
            yielded: d.bool()?,
            forbidden: d.bool()?,
        };
        if value.writes.iter().any(|write| write.actor != value.actor) {
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
        e.list(&self.crdt_operations, encode_crdt_op);
        e.list(&self.resulting_crdt_heads, |e, h| e.fixed(&h.0));
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
            crdt_operations: d.list(decode_crdt_op)?,
            resulting_crdt_heads: d.list(|d| d.fixed().map(Hash))?,
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
        ensure_sorted_unique(&result.resulting_crdt_heads, |h| h.0)?;
        ensure_sorted_unique(&result.exported_blobs, |b| b.hash.0)?;
        Ok(result)
    }
}

impl V2Wire for AccumulationReceiptV2 {
    const MAGIC: [u8; 4] = *b"VAR2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut e = Encoder(out);
        encode_service(&mut e, &self.service);
        e.fixed(&self.accepted_transition.0);
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
            resulting_state_root: d.option(|d| d.fixed().map(Hash))?,
            resulting_crdt_heads: d.list(|d| d.fixed().map(Hash))?,
            sequence: d.u64()?,
            checkpoint: d.u64()?,
            consistency: ConsistencyModeV2::decode(d)?,
        };
        ensure_sorted_unique(&value.resulting_crdt_heads, |h| h.0)?;
        Ok(value)
    }
}

fn encode_service(e: &mut Encoder<'_>, value: &ServiceIdentityV2) {
    e.fixed(&value.root_service.0);
    e.fixed(&value.deployment.0);
    e.fixed(&value.service_program.0);
    e.u16(value.service_abi);
    e.fixed(&value.execution_semantics.0);
}

fn decode_service(d: &mut Decoder<'_>) -> Result<ServiceIdentityV2, DecodeError> {
    let value = ServiceIdentityV2 {
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
    e.option(&value.continuation, encode_blob_ref);
}

fn decode_imported_actor(d: &mut Decoder<'_>) -> Result<ImportedActorV2, DecodeError> {
    Ok(ImportedActorV2 {
        actor: ActorId(d.fixed()?),
        program: ProgramId(d.fixed()?),
        state: decode_blob_ref(d)?,
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
    e.fixed(&value.id.0);
    e.list(&value.causal_dependencies, |e, h| e.fixed(&h.0));
    e.bytes(&value.payload);
}

fn decode_crdt_op(d: &mut Decoder<'_>) -> Result<CrdtOperationV2, DecodeError> {
    let value = CrdtOperationV2 {
        actor: ActorId(d.fixed()?),
        id: OperationId(d.fixed()?),
        causal_dependencies: d.list(|d| d.fixed().map(Hash))?,
        payload: d.bytes()?,
    };
    ensure_sorted_unique(&value.causal_dependencies, |h| h.0)?;
    Ok(value)
}

fn encode_continuation_change(e: &mut Encoder<'_>, value: &ContinuationChangeV2) {
    e.fixed(&value.actor.0);
    e.option(&value.expected, |e, h| e.fixed(&h.0));
    e.option(&value.replacement, encode_blob_ref);
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
    e.fixed(&value.from.0);
    e.fixed(&value.to.0);
    e.option(&value.parent, |e, id| e.fixed(&id.0));
    e.bytes(&value.payload);
    e.option(&value.deadline_timeslot, |e, value| e.u64(*value));
}

fn decode_message(d: &mut Decoder<'_>) -> Result<MessageRecordV2, DecodeError> {
    Ok(MessageRecordV2 {
        call_id: CallId(d.fixed()?),
        from: ActorId(d.fixed()?),
        to: ActorId(d.fixed()?),
        parent: d.option(|d| d.fixed().map(CallId))?,
        payload: d.bytes()?,
        deadline_timeslot: d.option(Decoder::u64)?,
    })
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
    e.fixed(&value.trace.0);
    encode_blob_ref(e, &value.proof_blob);
    e.u16(value.statement_version);
}

fn decode_proof(d: &mut Decoder<'_>) -> Result<ProofCommitmentV2, DecodeError> {
    let value = ProofCommitmentV2 {
        trace: Hash(d.fixed()?),
        proof_blob: decode_blob_ref(d)?,
        statement_version: d.u16()?,
    };
    if value.statement_version != super::ATTESTATION_STATEMENT_VERSION {
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
            target: ActorId([5; 32]),
            target_program: ProgramId([6; 32]),
            method: "increment".into(),
            arguments: vec![1, 2],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            consistency: ConsistencyModeV2::Local,
            base: ConsistencyBaseV2::Linear {
                revision: 7,
                state_root: Hash([8; 32]),
            },
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
        missing.blobs.retain(|blob| blob.reference != work.imported_blobs[0]);
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
            state: b"before".to_vec(),
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
            reply: b"ok".to_vec(),
            yielded: false,
            forbidden: false,
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
    }

    #[test]
    fn transition_hash_excludes_nothing() {
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
            crdt_operations: vec![],
            resulting_crdt_heads: vec![],
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
        assert_eq!(TransitionV2::decode(&changed.encode()).unwrap(), changed);
    }
}
