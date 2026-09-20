//! Public proof statements for outer-runtime plus inner-actor execution.
//!
//! A shipped record contains only commitments and a content-addressed proof.
//! Producer-private witness material is represented by a deliberately
//! non-wire type and must stay in an operator-owned sidecar.

use alloc::string::String;
use alloc::vec::Vec;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::wire::{CanonicalWire, WireError};
use crate::{
    ActorId, AgentId, BlobRef, DeploymentId, Hash, InvocationId, InvocationResultStorage,
    MethodMode, ProducerId, ProgramId, SpaceId, StateLane,
};

pub const MAX_PROOF_METHOD_BYTES: usize = 128;
pub const PROOF_PUBLIC_KEY_BYTES: usize = 32;
pub const PROOF_SIGNATURE_BYTES: usize = 64;
pub const MAX_TRANSITION_PROOF_RECORD_BYTES: usize = 4 * 1024;
/// Canonical public proof chunks use the same per-object ceiling as every
/// other authenticated catalog artifact.
pub const TRANSITION_PROOF_MATERIAL_CHUNK_BYTES: u64 = crate::MAX_CATALOG_ARTIFACT_BYTES;
/// The global proof-material ceiling is an exact multiple of the chunk size,
/// but keep the formula correct if either protocol constant changes later.
pub const MAX_TRANSITION_PROOF_MATERIAL_CHUNKS: usize = crate::MAX_TRANSITION_PROOF_MATERIAL_BYTES
    .div_ceil(TRANSITION_PROOF_MATERIAL_CHUNK_BYTES)
    as usize;
pub const MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES: usize = 1_024;

/// Stable identity of one exact invocation transition.
///
/// A logical invocation may yield and later resume more than once. Its
/// [`InvocationId`] therefore identifies the workflow, while `execution`
/// commits to both the canonical work and the exact predecessor lane roots.
/// Exact retries retain both values and resolve to the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransitionProofKey {
    pub invocation: InvocationId,
    pub execution: Hash,
}

impl TransitionProofKey {
    pub fn validate(self) -> bool {
        self.invocation != InvocationId::ZERO && self.execution != Hash::ZERO
    }
}

/// Canonical content-addressed root for one proof system's public material.
///
/// A bounded proof backend sets [`TransitionProofRecord::proof`] to the
/// encoded manifest rather than an unbounded monolithic proof. `material`
/// names the exact concatenation of `chunks`; it is a synthetic aggregate
/// reference and need not itself be stored as one CAS object. Every non-final
/// chunk is exactly
/// [`TRANSITION_PROOF_MATERIAL_CHUNK_BYTES`] bytes, making the representation
/// unique rather than allowing one proof to be rechunked under many roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionProofMaterialManifest {
    pub material: BlobRef,
    pub chunks: Vec<BlobRef>,
}

impl TransitionProofMaterialManifest {
    pub fn for_material(material: &[u8]) -> Result<Self, WireError> {
        let material_len = u64::try_from(material.len()).map_err(|_| WireError::LimitExceeded)?;
        if material_len == 0 {
            return Err(WireError::InvalidValue);
        }
        if material_len > crate::MAX_TRANSITION_PROOF_MATERIAL_BYTES {
            return Err(WireError::LimitExceeded);
        }
        let chunk_bytes = usize::try_from(TRANSITION_PROOF_MATERIAL_CHUNK_BYTES)
            .map_err(|_| WireError::LimitExceeded)?;
        let value = Self {
            material: BlobRef::of_bytes(material),
            chunks: material
                .chunks(chunk_bytes)
                .map(BlobRef::of_bytes)
                .collect(),
        };
        value
            .validate()
            .then_some(value)
            .ok_or(WireError::InvalidValue)
    }

    pub fn validate(&self) -> bool {
        if self.material.hash == Hash::ZERO
            || self.material.len == 0
            || self.material.len > crate::MAX_TRANSITION_PROOF_MATERIAL_BYTES
        {
            return false;
        }
        let expected_chunks = self
            .material
            .len
            .div_ceil(TRANSITION_PROOF_MATERIAL_CHUNK_BYTES);
        if usize::try_from(expected_chunks).ok() != Some(self.chunks.len())
            || self.chunks.is_empty()
            || self.chunks.len() > MAX_TRANSITION_PROOF_MATERIAL_CHUNKS
        {
            return false;
        }
        self.chunks.iter().enumerate().all(|(index, chunk)| {
            let Some(offset) = (index as u64).checked_mul(TRANSITION_PROOF_MATERIAL_CHUNK_BYTES)
            else {
                return false;
            };
            let expected = self
                .material
                .len
                .saturating_sub(offset)
                .min(TRANSITION_PROOF_MATERIAL_CHUNK_BYTES);
            chunk.hash != Hash::ZERO && chunk.len == expected && expected != 0
        })
    }

    /// Verify the aggregate identity and every canonical chunk without
    /// trusting a caller-supplied manifest constructor.
    pub fn matches_material(&self, material: &[u8]) -> bool {
        if !self.validate() || !self.material.matches(material) {
            return false;
        }
        let Ok(chunk_bytes) = usize::try_from(TRANSITION_PROOF_MATERIAL_CHUNK_BYTES) else {
            return false;
        };
        self.chunks
            .iter()
            .zip(material.chunks(chunk_bytes))
            .all(|(reference, bytes)| reference.matches(bytes))
    }

    /// Validate an authenticated runtime ceiling before a resolver fetches
    /// any chunk and return the only aggregate allocation size it may use.
    pub fn bounded_material_len(&self, maximum: u64) -> Result<usize, WireError> {
        if !self.validate() {
            return Err(WireError::InvalidValue);
        }
        if maximum == 0
            || maximum > crate::MAX_TRANSITION_PROOF_MATERIAL_BYTES
            || self.material.len > maximum
        {
            return Err(WireError::LimitExceeded);
        }
        usize::try_from(self.material.len).map_err(|_| WireError::LimitExceeded)
    }

    /// Reassemble exact ordered chunks beneath a caller's authenticated
    /// runtime-policy ceiling. Missing, additional, reordered, or substituted
    /// chunks are rejected before the aggregate is returned.
    pub fn assemble_bounded<'a, I>(&self, chunks: I, maximum: u64) -> Result<Vec<u8>, WireError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let material_len = self.bounded_material_len(maximum)?;
        let mut material = Vec::new();
        material
            .try_reserve_exact(material_len)
            .map_err(|_| WireError::LimitExceeded)?;
        let mut supplied = chunks.into_iter();
        for reference in &self.chunks {
            let bytes = supplied.next().ok_or(WireError::InvalidValue)?;
            if !reference.matches(bytes) {
                return Err(WireError::InvalidValue);
            }
            material.extend_from_slice(bytes);
        }
        if supplied.next().is_some() || !self.material.matches(&material) {
            return Err(WireError::InvalidValue);
        }
        Ok(material)
    }
}

impl CanonicalWire for TransitionProofMaterialManifest {
    const MAGIC: [u8; 4] = *b"APM1";
    const MAX_ENCODED_BYTES: usize = MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_blob(encoder, &self.material);
        encoder.list(&self.chunks, encode_blob);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            material: decode_blob(decoder)?,
            chunks: decoder.list_bounded(MAX_TRANSITION_PROOF_MATERIAL_CHUNKS, decode_blob)?,
        };
        value
            .validate()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

/// State roots observed by one runtime transition. Control is always present;
/// an absent state-lane root means the agent has not provisioned that lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofLaneRoots {
    pub control: Hash,
    pub linear: Option<Hash>,
    pub merge: Option<Hash>,
    pub local: Option<Hash>,
}

impl ProofLaneRoots {
    pub fn validate(&self) -> bool {
        self.control != Hash::ZERO
            && self.linear != Some(Hash::ZERO)
            && self.merge != Some(Hash::ZERO)
            && self.local != Some(Hash::ZERO)
    }

    pub const fn lane(self, lane: StateLane) -> Option<Hash> {
        match lane {
            StateLane::Linear => self.linear,
            StateLane::Merge => self.merge,
            StateLane::Local => self.local,
        }
    }

    fn same_shape(self, other: Self) -> bool {
        self.linear.is_some() == other.linear.is_some()
            && self.merge.is_some() == other.merge.is_some()
            && self.local.is_some() == other.local.is_some()
    }
}

/// Complete execution identity. The runtime and actor deployments are both
/// explicit: a proof for the same actor program under a different outer
/// runtime is a different statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionProofSubject {
    pub space: SpaceId,
    pub agent: AgentId,
    pub runtime_deployment: DeploymentId,
    pub runtime_program: ProgramId,
    /// Exact authenticated runtime package carrying the program and contract.
    pub runtime_package: BlobRef,
    pub actor: ActorId,
    pub incarnation: Hash,
    pub actor_deployment: DeploymentId,
    pub actor_program: ProgramId,
    pub invocation: InvocationId,
    pub method: String,
    pub mode: MethodMode,
}

impl TransitionProofSubject {
    pub fn validate(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != AgentId::ZERO
            && self.runtime_deployment != DeploymentId::ZERO
            && self.runtime_program != ProgramId::ZERO
            && self.runtime_package.hash != Hash::ZERO
            && self.runtime_package.len != 0
            && self.runtime_package.len <= crate::MAX_CATALOG_ARTIFACT_BYTES
            && self.actor != ActorId::ZERO
            && self.incarnation != Hash::ZERO
            && self.actor_deployment != DeploymentId::ZERO
            && self.actor_program != ProgramId::ZERO
            && self.invocation != InvocationId::ZERO
            && !self.method.is_empty()
            && self.method.len() <= MAX_PROOF_METHOD_BYTES
    }
}

/// Verifier-facing statement proven by a concrete proof system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionProofStatement {
    pub subject: TransitionProofSubject,
    pub before: ProofLaneRoots,
    pub after: ProofLaneRoots,
    /// Domain-separated digest of the exact canonical RuntimeWork bytes.
    pub work: Hash,
    /// Domain-separated digest of the exact canonical RuntimeTransition bytes.
    pub transition: Hash,
    /// Proof-independent execution commitment for the complete nested standard
    /// Refine trace. A verifier recomputes it from the proof bundle only after
    /// verifying every child proof and deterministically replaying the native
    /// boundaries. It is not a commitment to serialized proof bytes, a
    /// producer-private witness, or a legacy service attestation.
    pub refine_trace: Hash,
    /// Public I/O commitment carried by the physical proof.
    pub public_io: Hash,
    /// Identity of the proof system/verifier parameters.
    pub proof_system: Hash,
}

impl TransitionProofStatement {
    pub fn validate(&self) -> bool {
        if !self.subject.validate()
            || !self.before.validate()
            || !self.after.validate()
            || !self.before.same_shape(self.after)
            || self.work == Hash::ZERO
            || self.transition == Hash::ZERO
            || self.refine_trace == Hash::ZERO
            || self.public_io == Hash::ZERO
            || self.proof_system == Hash::ZERO
        {
            return false;
        }

        let storage = self.subject.mode.result_storage();
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            let before = self.before.lane(lane);
            let after = self.after.lane(lane);
            if storage == InvocationResultStorage::Lane(lane) {
                if before.is_none() || after.is_none() {
                    return false;
                }
            } else if before != after {
                // Queries and immutable lane snapshots cannot alter a state
                // component merely because a proof record names it.
                return false;
            }
        }
        if storage != InvocationResultStorage::Control && self.before.control != self.after.control
        {
            return false;
        }
        true
    }

    /// Exact retry/publication key for this transition slice.
    pub fn key(&self) -> TransitionProofKey {
        TransitionProofKey {
            invocation: self.subject.invocation,
            execution: Self::execution_commitment(self.work, self.before),
        }
    }

    /// Commitment identifying one execution of canonical work from exact
    /// predecessor lane roots.
    pub fn execution_commitment(work: Hash, before: ProofLaneRoots) -> Hash {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(work.as_bytes());
        encode_roots(&mut encoder, before);
        Hash::digest(b"vos/agent/proof/runtime-execution/v1", &[&bytes])
    }

    pub fn commitment(&self) -> Result<Hash, WireError> {
        Ok(Hash::digest(
            b"vos/agent/transition-proof-statement",
            &[&self.encode()?],
        ))
    }

    pub fn work_commitment(canonical_work: &[u8]) -> Hash {
        Hash::digest(b"vos/agent/proof/runtime-work", &[canonical_work])
    }

    pub fn transition_commitment(canonical_transition: &[u8]) -> Hash {
        Hash::digest(
            b"vos/agent/proof/runtime-transition",
            &[canonical_transition],
        )
    }

    /// Match every public execution binding while independently recomputing
    /// the commitments of the exact canonical work and transition bytes.
    /// Shared followers can use this without the producer-private witness.
    #[allow(clippy::too_many_arguments)]
    pub fn matches_execution(
        &self,
        subject: &TransitionProofSubject,
        before: ProofLaneRoots,
        after: ProofLaneRoots,
        canonical_work: &[u8],
        canonical_transition: &[u8],
        refine_trace: Hash,
        public_io: Hash,
        proof_system: Hash,
    ) -> bool {
        self.validate()
            && &self.subject == subject
            && self.before == before
            && self.after == after
            && self.work == Self::work_commitment(canonical_work)
            && self.transition == Self::transition_commitment(canonical_transition)
            && self.refine_trace == refine_trace
            && self.public_io == public_io
            && self.proof_system == proof_system
    }
}

impl CanonicalWire for TransitionProofStatement {
    // Generation 4 gives the derived transition key predecessor-state
    // semantics. Prior statement generations are not upgraded implicitly.
    const MAGIC: [u8; 4] = *b"APS4";
    const MAX_ENCODED_BYTES: usize = 1_024;

    fn validate_wire(&self) -> bool {
        self.validate()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_statement(encoder, self);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decode_statement(decoder)
    }
}

/// Public, content-addressed proof record. The proof bytes are supplied to a
/// verifier explicitly and are never confused with the producer signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionProofRecord {
    pub statement: TransitionProofStatement,
    pub proof: BlobRef,
    pub producer: ProducerId,
    pub producer_public_key: [u8; PROOF_PUBLIC_KEY_BYTES],
    pub producer_signature: [u8; PROOF_SIGNATURE_BYTES],
}

impl TransitionProofRecord {
    fn validate_unsigned_shape(&self) -> bool {
        self.statement.validate()
            && self.proof.hash != Hash::ZERO
            && self.proof.len != 0
            && self.proof.len <= MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES as u64
            && self.producer != ProducerId::ZERO
            && self.producer_public_key != [0; PROOF_PUBLIC_KEY_BYTES]
            && ProducerId::of_public_key(&self.producer_public_key) == self.producer
    }

    pub fn validate_shape(&self) -> bool {
        self.validate_unsigned_shape() && self.producer_signature != [0; PROOF_SIGNATURE_BYTES]
    }

    /// Exact bytes signed by the proof producer. Signature bytes themselves
    /// are excluded; all statement fields and the proof content identity are
    /// included.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WireError> {
        // Signature producers need these bytes before the signature exists.
        if !self.validate_unsigned_shape() {
            return Err(WireError::InvalidValue);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"vos/agent/transition-proof-record/v4");
        bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
        let statement = self.statement.encode()?;
        let mut encoder = Encoder(&mut bytes);
        encoder.bytes(&statement);
        encode_blob(&mut encoder, &self.proof);
        encoder.fixed(self.producer.as_bytes());
        encoder.0.extend_from_slice(&self.producer_public_key);
        Ok(bytes)
    }

    pub fn commitment(&self) -> Result<Hash, WireError> {
        Ok(Hash::digest(
            b"vos/agent/transition-proof-record",
            &[&self.signing_bytes()?, &self.producer_signature],
        ))
    }

    /// Canonical commitment of one verified transition publication.
    ///
    /// This is the durable journal identity for the exact retry key,
    /// transition, signed proof record, and before/after lane roots. It does
    /// not itself assert that verification occurred; only the verifier-owned
    /// publication capability may authorize persistence. Once persisted, a
    /// no-std replay reader can recompute this value from the canonical proof
    /// record and reject substituted journal metadata.
    pub fn verified_publication_commitment(&self) -> Result<Hash, WireError> {
        if !self.validate_shape() {
            return Err(WireError::InvalidValue);
        }
        let proof_record = self.commitment()?;
        let key = self.statement.key();
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.fixed(key.invocation.as_bytes());
        encoder.fixed(key.execution.as_bytes());
        encoder.fixed(self.statement.transition.as_bytes());
        encoder.fixed(proof_record.as_bytes());
        encode_roots(&mut encoder, self.statement.before);
        encode_roots(&mut encoder, self.statement.after);
        Ok(Hash::digest(
            b"vos/agent/verified-transition-publication/v3",
            &[&bytes],
        ))
    }

    /// Verify the signed manifest root and the exact bounded proof material it
    /// names. Callers must fetch and canonically assemble the manifest chunks
    /// before entering this method; physical verifiers never receive manifest
    /// bytes in place of a proof.
    pub fn verify<V: TransitionProofVerifier>(
        &self,
        manifest_bytes: &[u8],
        proof_material: &[u8],
        verifier: &V,
    ) -> Result<(), ProofRecordError> {
        self.verify_material_and_producer(manifest_bytes, proof_material, verifier)?;
        if !verifier.verify_transition(&self.statement, proof_material) {
            return Err(ProofRecordError::InvalidProof);
        }
        Ok(())
    }

    fn verify_material_and_producer<V: TransitionProofVerifier>(
        &self,
        manifest_bytes: &[u8],
        proof_material: &[u8],
        verifier: &V,
    ) -> Result<(), ProofRecordError> {
        if !self.validate_shape() {
            return Err(ProofRecordError::InvalidRecord);
        }
        if !self.proof.matches(manifest_bytes) {
            return Err(ProofRecordError::WrongProof);
        }
        let manifest = TransitionProofMaterialManifest::decode(manifest_bytes)
            .map_err(|_| ProofRecordError::WrongProof)?;
        if !manifest.matches_material(proof_material) {
            return Err(ProofRecordError::WrongProof);
        }
        let signing_bytes = self
            .signing_bytes()
            .map_err(|_| ProofRecordError::InvalidRecord)?;
        if !verifier.verify_producer(
            &self.producer_public_key,
            &signing_bytes,
            &self.producer_signature,
        ) {
            return Err(ProofRecordError::InvalidProducerSignature);
        }
        Ok(())
    }

    /// Verify both the public proof record and its exact clean Agent
    /// execution binding. This is the follower-facing verification path: it
    /// needs canonical work, canonical transition, and public proof bytes,
    /// but never the producer-private witness. `before` and `after` are
    /// expected roots: an authoritative replay/materialization caller must
    /// recompute both independently rather than copying them from
    /// `self.statement`. Physical proof verification does not authenticate a
    /// journal's choice of state roots on its own.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_exact<V: TransitionProofVerifier>(
        &self,
        manifest_bytes: &[u8],
        proof_material: &[u8],
        subject: &TransitionProofSubject,
        before: ProofLaneRoots,
        after: ProofLaneRoots,
        canonical_work: &[u8],
        canonical_transition: &[u8],
        refine_trace: Hash,
        public_io: Hash,
        proof_system: Hash,
        producer: ProducerId,
        verifier: &V,
    ) -> Result<(), ProofRecordError> {
        if !self.statement.matches_execution(
            subject,
            before,
            after,
            canonical_work,
            canonical_transition,
            refine_trace,
            public_io,
            proof_system,
        ) {
            return Err(ProofRecordError::WrongStatement);
        }
        if self.producer != producer {
            return Err(ProofRecordError::WrongProducer);
        }
        self.verify_material_and_producer(manifest_bytes, proof_material, verifier)?;
        if !verifier.verify_transition_exact(
            &self.statement,
            canonical_work,
            canonical_transition,
            proof_material,
        ) {
            return Err(ProofRecordError::InvalidProof);
        }
        Ok(())
    }
}

impl CanonicalWire for TransitionProofRecord {
    // Generation 4 signs the predecessor-bound execution-key semantics.
    // No predecessor record is upgraded implicitly.
    const MAGIC: [u8; 4] = *b"APR4";
    const MAX_ENCODED_BYTES: usize = MAX_TRANSITION_PROOF_RECORD_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_shape()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_statement(encoder, &self.statement);
        encode_blob(encoder, &self.proof);
        encoder.fixed(self.producer.as_bytes());
        encoder.0.extend_from_slice(&self.producer_public_key);
        encoder.0.extend_from_slice(&self.producer_signature);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            statement: decode_statement(decoder)?,
            proof: decode_blob(decoder)?,
            producer: ProducerId(decoder.fixed()?),
            producer_public_key: decoder
                .take(PROOF_PUBLIC_KEY_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
            producer_signature: decoder
                .take(PROOF_SIGNATURE_BYTES)?
                .try_into()
                .map_err(|_| DecodeError::Truncated)?,
        };
        value
            .validate_shape()
            .then_some(value)
            .ok_or(DecodeError::NonCanonical)
    }
}

/// Independent verifier for one public transition-proof record.
///
/// `verify_transition` receives assembled material whose manifest and chunk
/// identities were already checked by [`TransitionProofRecord::verify`]. It
/// must validate that complete physical proof for the
/// statement's exact `proof_system`. For the standard nested Refine backend,
/// accepting child proofs alone is insufficient: verification must perform
/// the required deterministic boundary replay and bind its transcript
/// commitment to `statement.refine_trace`, as well as the statement's public
/// I/O and state roots.
pub trait TransitionProofVerifier {
    fn verify_producer(
        &self,
        public_key: &[u8; PROOF_PUBLIC_KEY_BYTES],
        message: &[u8],
        signature: &[u8; PROOF_SIGNATURE_BYTES],
    ) -> bool;

    fn verify_transition(
        &self,
        statement: &TransitionProofStatement,
        proof_material: &[u8],
    ) -> bool;

    /// Verify a physical proof against the exact canonical execution bytes.
    ///
    /// The default preserves verifier compatibility while allowing physical
    /// backends to bind proof inputs and terminal public I/O without trying
    /// to invert the statement's commitments. Production Refine verifiers
    /// override this method; callers which only have a statement must remain
    /// fail-closed for such a verifier.
    fn verify_transition_exact(
        &self,
        statement: &TransitionProofStatement,
        _canonical_work: &[u8],
        _canonical_transition: &[u8],
        proof_material: &[u8],
    ) -> bool {
        self.verify_transition(statement, proof_material)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofRecordError {
    InvalidRecord,
    WrongStatement,
    WrongProducer,
    WrongProof,
    InvalidProducerSignature,
    InvalidProof,
}

/// Producer-only material. It deliberately has no [`CanonicalWire`]
/// implementation and is not a field of [`TransitionProofRecord`]. Hosts keep
/// it in an access-controlled sidecar and erase it after proof production or
/// retention expiry.
#[derive(PartialEq, Eq)]
pub struct ProducerPrivateWitness {
    pub statement: Hash,
    pub bytes: Vec<u8>,
}

impl core::fmt::Debug for ProducerPrivateWitness {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProducerPrivateWitness")
            .field("statement", &self.statement)
            .field(
                "bytes",
                &format_args!("<redacted:{} bytes>", self.bytes.len()),
            )
            .finish()
    }
}

fn encode_optional_hash(encoder: &mut Encoder<'_>, value: Option<Hash>) {
    encoder.option(&value, |encoder, value| encoder.fixed(value.as_bytes()));
}

fn decode_optional_hash(decoder: &mut Decoder<'_>) -> Result<Option<Hash>, DecodeError> {
    let value = decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?;
    if value == Some(Hash::ZERO) {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

fn encode_roots(encoder: &mut Encoder<'_>, roots: ProofLaneRoots) {
    encoder.fixed(roots.control.as_bytes());
    encode_optional_hash(encoder, roots.linear);
    encode_optional_hash(encoder, roots.merge);
    encode_optional_hash(encoder, roots.local);
}

fn decode_roots(decoder: &mut Decoder<'_>) -> Result<ProofLaneRoots, DecodeError> {
    let roots = ProofLaneRoots {
        control: Hash(decoder.fixed()?),
        linear: decode_optional_hash(decoder)?,
        merge: decode_optional_hash(decoder)?,
        local: decode_optional_hash(decoder)?,
    };
    roots
        .validate()
        .then_some(roots)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_mode(encoder: &mut Encoder<'_>, mode: MethodMode) {
    encoder.u8(mode as u8);
}

fn decode_mode(decoder: &mut Decoder<'_>) -> Result<MethodMode, DecodeError> {
    match decoder.u8()? {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::LocalQuery),
        3 => Ok(MethodMode::Linear),
        4 => Ok(MethodMode::Merge),
        5 => Ok(MethodMode::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

fn encode_subject(encoder: &mut Encoder<'_>, subject: &TransitionProofSubject) {
    encoder.fixed(subject.space.as_bytes());
    encoder.fixed(subject.agent.as_bytes());
    encoder.fixed(subject.runtime_deployment.as_bytes());
    encoder.fixed(subject.runtime_program.as_bytes());
    encode_blob(encoder, &subject.runtime_package);
    encoder.fixed(subject.actor.as_bytes());
    encoder.fixed(subject.incarnation.as_bytes());
    encoder.fixed(subject.actor_deployment.as_bytes());
    encoder.fixed(subject.actor_program.as_bytes());
    encoder.fixed(subject.invocation.as_bytes());
    encoder.string(&subject.method);
    encode_mode(encoder, subject.mode);
}

fn decode_subject(decoder: &mut Decoder<'_>) -> Result<TransitionProofSubject, DecodeError> {
    let subject = TransitionProofSubject {
        space: SpaceId(decoder.fixed()?),
        agent: AgentId(decoder.fixed()?),
        runtime_deployment: DeploymentId(decoder.fixed()?),
        runtime_program: ProgramId(decoder.fixed()?),
        runtime_package: decode_blob(decoder)?,
        actor: ActorId(decoder.fixed()?),
        incarnation: Hash(decoder.fixed()?),
        actor_deployment: DeploymentId(decoder.fixed()?),
        actor_program: ProgramId(decoder.fixed()?),
        invocation: InvocationId(decoder.fixed()?),
        method: decoder.string_bounded(MAX_PROOF_METHOD_BYTES)?,
        mode: decode_mode(decoder)?,
    };
    subject
        .validate()
        .then_some(subject)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_statement(encoder: &mut Encoder<'_>, statement: &TransitionProofStatement) {
    encode_subject(encoder, &statement.subject);
    encode_roots(encoder, statement.before);
    encode_roots(encoder, statement.after);
    encoder.fixed(statement.work.as_bytes());
    encoder.fixed(statement.transition.as_bytes());
    encoder.fixed(statement.refine_trace.as_bytes());
    encoder.fixed(statement.public_io.as_bytes());
    encoder.fixed(statement.proof_system.as_bytes());
}

fn decode_statement(decoder: &mut Decoder<'_>) -> Result<TransitionProofStatement, DecodeError> {
    let statement = TransitionProofStatement {
        subject: decode_subject(decoder)?,
        before: decode_roots(decoder)?,
        after: decode_roots(decoder)?,
        work: Hash(decoder.fixed()?),
        transition: Hash(decoder.fixed()?),
        refine_trace: Hash(decoder.fixed()?),
        public_io: Hash(decoder.fixed()?),
        proof_system: Hash(decoder.fixed()?),
    };
    statement
        .validate()
        .then_some(statement)
        .ok_or(DecodeError::NonCanonical)
}

fn encode_blob(encoder: &mut Encoder<'_>, blob: &BlobRef) {
    encoder.fixed(blob.hash.as_bytes());
    encoder.u64(blob.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn proof_material_manifest_round_trips_and_binds_exact_bytes() {
        let material = b"serialized nested Refine proof";
        let manifest = TransitionProofMaterialManifest::for_material(material).unwrap();
        assert_eq!(manifest.material, BlobRef::of_bytes(material));
        assert_eq!(manifest.chunks, vec![BlobRef::of_bytes(material)]);
        assert!(manifest.matches_material(material));
        assert!(!manifest.matches_material(b"substituted nested Refine proof"));
        assert_eq!(
            manifest
                .assemble_bounded([material.as_slice()], material.len() as u64)
                .unwrap(),
            material
        );
        assert_eq!(
            manifest.assemble_bounded(core::iter::empty(), material.len() as u64),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            manifest.assemble_bounded(
                [material.as_slice(), b"extra".as_slice()],
                material.len() as u64,
            ),
            Err(WireError::InvalidValue)
        );
        assert_eq!(
            manifest.assemble_bounded([material.as_slice()], material.len() as u64 - 1),
            Err(WireError::LimitExceeded)
        );

        let encoded = manifest.encode().unwrap();
        assert!(encoded.len() <= MAX_TRANSITION_PROOF_MATERIAL_MANIFEST_BYTES);
        assert_eq!(
            TransitionProofMaterialManifest::decode(&encoded),
            Ok(manifest)
        );
    }

    #[test]
    fn proof_material_manifest_requires_one_canonical_chunking() {
        let chunk = TRANSITION_PROOF_MATERIAL_CHUNK_BYTES;
        let valid = TransitionProofMaterialManifest {
            material: BlobRef {
                hash: Hash([1; 32]),
                len: chunk + 1,
            },
            chunks: vec![
                BlobRef {
                    hash: Hash([2; 32]),
                    len: chunk,
                },
                BlobRef {
                    hash: Hash([3; 32]),
                    len: 1,
                },
            ],
        };
        assert!(valid.validate());

        let mut short_first = valid.clone();
        short_first.chunks[0].len -= 1;
        assert!(!short_first.validate());
        let mut joined = valid.clone();
        joined.chunks = vec![BlobRef {
            hash: Hash([4; 32]),
            len: chunk + 1,
        }];
        assert!(!joined.validate());
        let mut empty_final = valid;
        empty_final.material.len = chunk;
        assert!(!empty_final.validate());

        let maximum = TransitionProofMaterialManifest {
            material: BlobRef {
                hash: Hash([5; 32]),
                len: crate::MAX_TRANSITION_PROOF_MATERIAL_BYTES,
            },
            chunks: (0..MAX_TRANSITION_PROOF_MATERIAL_CHUNKS)
                .map(|index| BlobRef {
                    hash: Hash([index as u8 + 1; 32]),
                    len: chunk,
                })
                .collect(),
        };
        assert!(maximum.validate());
    }

    #[test]
    fn proof_material_manifest_assembles_real_boundary_chunks_exactly() {
        let chunk = TRANSITION_PROOF_MATERIAL_CHUNK_BYTES as usize;
        let mut material = vec![0x5a; chunk + 1];
        material[chunk] = 0x6b;
        let manifest = TransitionProofMaterialManifest::for_material(&material).unwrap();
        assert_eq!(manifest.chunks.len(), 2);
        assert_eq!(manifest.chunks[0].len, chunk as u64);
        assert_eq!(manifest.chunks[1].len, 1);
        assert_eq!(
            manifest
                .assemble_bounded(
                    [&material[..chunk], &material[chunk..]],
                    material.len() as u64,
                )
                .unwrap(),
            material,
        );
        assert_eq!(
            manifest.assemble_bounded(
                [&material[chunk..], &material[..chunk]],
                material.len() as u64,
            ),
            Err(WireError::InvalidValue),
        );
        assert_eq!(
            TransitionProofMaterialManifest::for_material(&material[..chunk])
                .unwrap()
                .chunks
                .len(),
            1,
            "an exact 8 MiB boundary has no empty trailing chunk",
        );
    }

    #[test]
    fn proof_material_manifest_rejects_empty_oversized_and_hostile_lists() {
        assert_eq!(
            TransitionProofMaterialManifest::for_material(&[]),
            Err(WireError::InvalidValue)
        );
        let oversized = TransitionProofMaterialManifest {
            material: BlobRef {
                hash: Hash([1; 32]),
                len: crate::MAX_TRANSITION_PROOF_MATERIAL_BYTES + 1,
            },
            chunks: vec![BlobRef {
                hash: Hash([2; 32]),
                len: TRANSITION_PROOF_MATERIAL_CHUNK_BYTES,
            }],
        };
        assert!(!oversized.validate());

        let mut encoded = TransitionProofMaterialManifest::for_material(b"proof")
            .unwrap()
            .encode()
            .unwrap();
        let list_length_offset = 4 + 32 + 32 + 8;
        encoded[list_length_offset..list_length_offset + 4]
            .copy_from_slice(&((MAX_TRANSITION_PROOF_MATERIAL_CHUNKS + 1) as u32).to_le_bytes());
        assert!(matches!(
            TransitionProofMaterialManifest::decode(&encoded),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        ));

        let mut zero_chunk = TransitionProofMaterialManifest::for_material(b"proof")
            .unwrap()
            .encode()
            .unwrap();
        let first_chunk_hash = list_length_offset + 4;
        zero_chunk[first_chunk_hash..first_chunk_hash + 32].fill(0);
        assert!(TransitionProofMaterialManifest::decode(&zero_chunk).is_err());

        let mut truncated = TransitionProofMaterialManifest::for_material(b"proof")
            .unwrap()
            .encode()
            .unwrap();
        truncated.pop();
        assert_eq!(
            TransitionProofMaterialManifest::decode(&truncated),
            Err(WireError::Decode(DecodeError::Truncated))
        );
    }

    #[test]
    fn proof_material_manifest_rejects_noncanonical_envelopes() {
        let manifest = TransitionProofMaterialManifest::for_material(b"proof").unwrap();
        let mut wrong_magic = manifest.encode().unwrap();
        wrong_magic[0..4].copy_from_slice(b"APM0");
        assert!(TransitionProofMaterialManifest::decode(&wrong_magic).is_err());

        let mut trailing = manifest.encode().unwrap();
        trailing.push(0);
        assert_eq!(
            TransitionProofMaterialManifest::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );
    }

    fn roots(linear: u8, merge: u8, local: u8) -> ProofLaneRoots {
        ProofLaneRoots {
            control: Hash([1; 32]),
            linear: Some(Hash([linear; 32])),
            merge: Some(Hash([merge; 32])),
            local: Some(Hash([local; 32])),
        }
    }

    fn statement() -> TransitionProofStatement {
        TransitionProofStatement {
            subject: TransitionProofSubject {
                space: SpaceId([2; 32]),
                agent: AgentId([3; 32]),
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_package: BlobRef::of_bytes(b"signed runtime package"),
                actor: ActorId([6; 32]),
                incarnation: Hash([7; 32]),
                actor_deployment: DeploymentId([8; 32]),
                actor_program: ProgramId([9; 32]),
                invocation: InvocationId([10; 32]),
                method: "increment".to_string(),
                mode: MethodMode::Linear,
            },
            before: roots(11, 12, 13),
            after: roots(14, 12, 13),
            work: TransitionProofStatement::work_commitment(b"canonical work"),
            transition: TransitionProofStatement::transition_commitment(b"canonical transition"),
            refine_trace: Hash([20; 32]),
            public_io: Hash([15; 32]),
            proof_system: Hash([16; 32]),
        }
    }

    fn proof_manifest(proof_material: &[u8]) -> Vec<u8> {
        TransitionProofMaterialManifest::for_material(proof_material)
            .unwrap()
            .encode()
            .unwrap()
    }

    fn record(proof_material: &[u8]) -> TransitionProofRecord {
        let public_key = [17; 32];
        let manifest = proof_manifest(proof_material);
        TransitionProofRecord {
            statement: statement(),
            proof: BlobRef::of_bytes(&manifest),
            producer: ProducerId::of_public_key(&public_key),
            producer_public_key: public_key,
            producer_signature: [18; 64],
        }
    }

    struct AcceptExact;

    impl TransitionProofVerifier for AcceptExact {
        fn verify_producer(
            &self,
            _public_key: &[u8; 32],
            message: &[u8],
            signature: &[u8; 64],
        ) -> bool {
            message.starts_with(b"vos/agent/transition-proof-record/v4") && *signature == [18; 64]
        }

        fn verify_transition(
            &self,
            statement: &TransitionProofStatement,
            proof_bytes: &[u8],
        ) -> bool {
            statement.proof_system == Hash([16; 32]) && proof_bytes == b"physical proof"
        }
    }

    struct ExactOnly;

    impl TransitionProofVerifier for ExactOnly {
        fn verify_producer(
            &self,
            _public_key: &[u8; 32],
            message: &[u8],
            signature: &[u8; 64],
        ) -> bool {
            message.starts_with(b"vos/agent/transition-proof-record/v4") && *signature == [18; 64]
        }

        fn verify_transition(
            &self,
            _statement: &TransitionProofStatement,
            _proof_bytes: &[u8],
        ) -> bool {
            false
        }

        fn verify_transition_exact(
            &self,
            statement: &TransitionProofStatement,
            canonical_work: &[u8],
            canonical_transition: &[u8],
            proof_bytes: &[u8],
        ) -> bool {
            statement.proof_system == Hash([16; 32])
                && canonical_work == b"canonical work"
                && canonical_transition == b"canonical transition"
                && proof_bytes == b"physical proof"
        }
    }

    #[test]
    fn statement_binds_outer_runtime_inner_actor_method_lanes_and_transition() {
        let statement = statement();
        assert!(statement.validate());
        let bytes = statement.encode().unwrap();
        assert_eq!(TransitionProofStatement::decode(&bytes).unwrap(), statement);

        let commitment = statement.commitment().unwrap();
        let mut changed = statement.clone();
        changed.subject.runtime_program = ProgramId([99; 32]);
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut changed = statement.clone();
        changed.subject.runtime_package = BlobRef::of_bytes(b"substituted runtime package");
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut changed = statement.clone();
        changed.subject.method = "decrement".to_string();
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut changed = statement.clone();
        changed.after.linear = Some(Hash([98; 32]));
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut changed = statement.clone();
        changed.transition = Hash([97; 32]);
        assert_ne!(changed.commitment().unwrap(), commitment);
        let mut changed = statement;
        changed.refine_trace = Hash([96; 32]);
        assert_ne!(changed.commitment().unwrap(), commitment);
    }

    #[test]
    fn execution_key_is_stable_and_binds_work_and_before_roots_only() {
        let statement = statement();
        let key = statement.key();
        assert_eq!(key.invocation, statement.subject.invocation);
        assert_eq!(
            key.execution,
            Hash([
                0xc5, 0x68, 0x34, 0x4e, 0x58, 0x28, 0xb8, 0x6f, 0x8f, 0x7a, 0xd6, 0xdf, 0xce, 0xcc,
                0xd5, 0xb3, 0xf4, 0x79, 0x1a, 0x50, 0xc2, 0x80, 0x13, 0x28, 0xe7, 0x59, 0xfd, 0x34,
                0xec, 0xd6, 0xd2, 0x90,
            ])
        );
        let reopened = TransitionProofStatement::decode(&statement.encode().unwrap()).unwrap();
        assert_eq!(reopened.work, statement.work);
        assert_eq!(reopened.before, statement.before);
        assert_eq!(reopened.key(), key);

        let mut changed = statement.clone();
        changed.work = Hash([22; 32]);
        assert_ne!(changed.key(), key);

        let mut changed = statement.clone();
        changed.before.linear = Some(Hash([23; 32]));
        assert_ne!(changed.key(), key);

        let mut changed = statement.clone();
        changed.before.linear = None;
        assert_ne!(changed.key(), key);

        let mut changed = statement;
        changed.after.linear = Some(Hash([24; 32]));
        assert_eq!(changed.key(), key);
    }

    #[test]
    fn statement_rejects_mutation_outside_the_declared_lane() {
        let mut invalid = statement();
        invalid.after.merge = Some(Hash([90; 32]));
        assert!(!invalid.validate());

        invalid = statement();
        invalid.subject.mode = MethodMode::Query;
        assert!(!invalid.validate());

        invalid = statement();
        invalid.after.control = Hash([89; 32]);
        assert!(!invalid.validate());

        let mut linearizable_query = statement();
        linearizable_query.subject.mode = MethodMode::LinearizableQuery;
        assert!(linearizable_query.validate());

        invalid = statement();
        invalid.before.linear = None;
        invalid.after.linear = None;
        assert!(!invalid.validate());
    }

    #[test]
    fn public_record_round_trips_verifies_and_contains_no_private_witness() {
        let sentinel = b"PRIVATE-WITNESS-SENTINEL-7a31";
        let witness = ProducerPrivateWitness {
            statement: statement().commitment().unwrap(),
            bytes: sentinel.to_vec(),
        };
        let record = record(b"physical proof");
        let manifest = proof_manifest(b"physical proof");
        let encoded = record.encode().unwrap();
        assert_eq!(TransitionProofRecord::decode(&encoded).unwrap(), record);
        assert!(
            record
                .verify(&manifest, b"physical proof", &AcceptExact)
                .is_ok()
        );
        assert!(
            !encoded
                .windows(sentinel.len())
                .any(|window| window == sentinel)
        );
        assert_eq!(witness.bytes, sentinel);
    }

    #[test]
    fn verified_publication_commitment_is_stable_and_binds_every_journal_field() {
        let record = record(b"physical proof");
        let commitment = record.verified_publication_commitment().unwrap();
        assert_eq!(
            commitment.0,
            [
                0x58, 0xc8, 0xc3, 0xcb, 0xd1, 0xd6, 0xbf, 0xb4, 0x74, 0x04, 0xc5, 0x94, 0x55, 0x19, 0x23, 0x5a,
                0x48, 0x90, 0x10, 0x6d, 0xa1, 0x6d, 0x5e, 0x66, 0x17, 0xee, 0x0b, 0x90, 0x7a, 0x15, 0xb9, 0x8e,
            ]
        );

        let mut changed = record.clone();
        changed.statement.subject.invocation = InvocationId([21; 32]);
        assert_ne!(
            changed.verified_publication_commitment().unwrap(),
            commitment
        );
        let mut changed = record.clone();
        changed.statement.work = Hash([22; 32]);
        assert_ne!(
            changed.verified_publication_commitment().unwrap(),
            commitment
        );
        let mut changed = record.clone();
        changed.statement.transition = Hash([23; 32]);
        assert_ne!(
            changed.verified_publication_commitment().unwrap(),
            commitment
        );
        let mut changed = record.clone();
        changed.producer_signature[0] ^= 1;
        assert_ne!(
            changed.verified_publication_commitment().unwrap(),
            commitment
        );
        let mut changed = record.clone();
        changed.statement.before.linear = Some(Hash([24; 32]));
        assert_ne!(
            changed.verified_publication_commitment().unwrap(),
            commitment
        );
        let mut changed = record;
        changed.statement.after.linear = Some(Hash([25; 32]));
        assert_ne!(
            changed.verified_publication_commitment().unwrap(),
            commitment
        );

        changed.producer_signature = [0; PROOF_SIGNATURE_BYTES];
        assert_eq!(
            changed.verified_publication_commitment(),
            Err(WireError::InvalidValue)
        );
    }

    #[test]
    fn signing_bytes_are_available_before_a_signature_exists() {
        let mut unsigned = record(b"physical proof");
        unsigned.producer_signature = [0; PROOF_SIGNATURE_BYTES];
        assert!(!unsigned.validate_shape());
        assert!(unsigned.signing_bytes().is_ok());
        assert_eq!(unsigned.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn proof_content_producer_signature_and_backend_fail_independently() {
        let record = record(b"physical proof");
        let manifest = proof_manifest(b"physical proof");
        assert_eq!(
            record.verify(b"wrong manifest", b"physical proof", &AcceptExact),
            Err(ProofRecordError::WrongProof)
        );
        assert_eq!(
            record.verify(&manifest, b"wrong proof", &AcceptExact),
            Err(ProofRecordError::WrongProof)
        );
        let mut wrong_signature = record.clone();
        wrong_signature.producer_signature[0] ^= 1;
        assert_eq!(
            wrong_signature.verify(&manifest, b"physical proof", &AcceptExact),
            Err(ProofRecordError::InvalidProducerSignature)
        );
        let mut wrong_system = record;
        wrong_system.statement.proof_system = Hash([19; 32]);
        assert_eq!(
            wrong_system.verify(&manifest, b"physical proof", &AcceptExact),
            Err(ProofRecordError::InvalidProof)
        );
    }

    #[test]
    fn follower_exact_verification_rejects_every_external_binding_substitution() {
        let record = record(b"physical proof");
        let manifest = proof_manifest(b"physical proof");
        let statement = &record.statement;
        let verify = |subject: &TransitionProofSubject,
                      before: ProofLaneRoots,
                      after: ProofLaneRoots,
                      work: &[u8],
                      transition: &[u8],
                      refine_trace: Hash,
                      public_io: Hash,
                      proof_system: Hash,
                      producer: ProducerId| {
            record.verify_exact(
                &manifest,
                b"physical proof",
                subject,
                before,
                after,
                work,
                transition,
                refine_trace,
                public_io,
                proof_system,
                producer,
                &ExactOnly,
            )
        };
        assert!(
            verify(
                &statement.subject,
                statement.before,
                statement.after,
                b"canonical work",
                b"canonical transition",
                statement.refine_trace,
                statement.public_io,
                statement.proof_system,
                record.producer,
            )
            .is_ok()
        );

        let mut wrong_subject = statement.subject.clone();
        wrong_subject.actor = ActorId([99; 32]);
        let cases = [
            verify(
                &wrong_subject,
                statement.before,
                statement.after,
                b"canonical work",
                b"canonical transition",
                statement.refine_trace,
                statement.public_io,
                statement.proof_system,
                record.producer,
            ),
            verify(
                &statement.subject,
                roots(99, 12, 13),
                statement.after,
                b"canonical work",
                b"canonical transition",
                statement.refine_trace,
                statement.public_io,
                statement.proof_system,
                record.producer,
            ),
            verify(
                &statement.subject,
                statement.before,
                statement.after,
                b"substituted work",
                b"canonical transition",
                statement.refine_trace,
                statement.public_io,
                statement.proof_system,
                record.producer,
            ),
            verify(
                &statement.subject,
                statement.before,
                statement.after,
                b"canonical work",
                b"substituted transition",
                statement.refine_trace,
                statement.public_io,
                statement.proof_system,
                record.producer,
            ),
            verify(
                &statement.subject,
                statement.before,
                statement.after,
                b"canonical work",
                b"canonical transition",
                Hash([98; 32]),
                statement.public_io,
                statement.proof_system,
                record.producer,
            ),
            verify(
                &statement.subject,
                statement.before,
                statement.after,
                b"canonical work",
                b"canonical transition",
                statement.refine_trace,
                Hash([97; 32]),
                statement.proof_system,
                record.producer,
            ),
            verify(
                &statement.subject,
                statement.before,
                statement.after,
                b"canonical work",
                b"canonical transition",
                statement.refine_trace,
                statement.public_io,
                Hash([96; 32]),
                record.producer,
            ),
        ];
        assert!(
            cases
                .into_iter()
                .all(|result| result == Err(ProofRecordError::WrongStatement))
        );
        assert_eq!(
            verify(
                &statement.subject,
                statement.before,
                statement.after,
                b"canonical work",
                b"canonical transition",
                statement.refine_trace,
                statement.public_io,
                statement.proof_system,
                ProducerId([95; 32]),
            ),
            Err(ProofRecordError::WrongProducer)
        );
    }

    #[test]
    fn proof_wire_rejects_trailing_unknown_and_previous_generation_headers() {
        let record = record(b"physical proof");
        let mut trailing = record.encode().unwrap();
        trailing.push(0);
        assert!(matches!(
            TransitionProofRecord::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        ));

        for magic in [*b"APRF", *b"PRF1", *b"APR2", *b"APR3"] {
            let mut old = record.encode().unwrap();
            old[..4].copy_from_slice(&magic);
            assert!(matches!(
                TransitionProofRecord::decode(&old),
                Err(WireError::Decode(DecodeError::InvalidTag))
            ));
        }

        let mut unknown_mode = record.statement.encode().unwrap();
        // Header + nine fixed identities + runtime package ref + method.
        let mode = 4 + 32 + 9 * 32 + 32 + 8 + 4 + record.statement.subject.method.len();
        unknown_mode[mode] = 0xff;
        assert!(matches!(
            TransitionProofStatement::decode(&unknown_mode),
            Err(WireError::Decode(DecodeError::InvalidTag))
        ));

        // The pre-Refine layout is not normalized into the current
        // statement. There is one clean wire shape and no compatibility
        // decoder which could silently reinterpret public I/O as a trace.
        let statement = statement();
        let mut previous_layout = Vec::new();
        previous_layout.extend_from_slice(b"APS2");
        previous_layout.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(&mut previous_layout);
        encoder.fixed(statement.subject.space.as_bytes());
        encoder.fixed(statement.subject.agent.as_bytes());
        encoder.fixed(statement.subject.runtime_deployment.as_bytes());
        encoder.fixed(statement.subject.runtime_program.as_bytes());
        encoder.fixed(statement.subject.actor.as_bytes());
        encoder.fixed(statement.subject.incarnation.as_bytes());
        encoder.fixed(statement.subject.actor_deployment.as_bytes());
        encoder.fixed(statement.subject.actor_program.as_bytes());
        encoder.fixed(statement.subject.invocation.as_bytes());
        encoder.string(&statement.subject.method);
        encode_mode(&mut encoder, statement.subject.mode);
        encode_roots(&mut encoder, statement.before);
        encode_roots(&mut encoder, statement.after);
        encoder.fixed(statement.work.as_bytes());
        encoder.fixed(statement.transition.as_bytes());
        encoder.fixed(statement.public_io.as_bytes());
        encoder.fixed(statement.proof_system.as_bytes());
        assert!(matches!(
            TransitionProofStatement::decode(&previous_layout),
            Err(WireError::Decode(DecodeError::InvalidTag))
        ));

        let mut previous_statement_magic = statement.encode().unwrap();
        previous_statement_magic[..4].copy_from_slice(b"APS3");
        assert!(matches!(
            TransitionProofStatement::decode(&previous_statement_magic),
            Err(WireError::Decode(DecodeError::InvalidTag))
        ));

        let mut previous_signing_domain = record.signing_bytes().unwrap();
        previous_signing_domain[b"vos/agent/transition-proof-record/v".len()] = b'3';
        assert!(!AcceptExact.verify_producer(
            &record.producer_public_key,
            &previous_signing_domain,
            &record.producer_signature,
        ));
    }

    #[test]
    fn invalid_producer_and_zero_roots_are_noncanonical() {
        let mut invalid = record(b"physical proof");
        invalid.producer = ProducerId([55; 32]);
        assert_eq!(invalid.encode(), Err(WireError::InvalidValue));

        let mut invalid = statement();
        invalid.before.control = Hash::ZERO;
        assert_eq!(invalid.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn method_and_record_bounds_apply_before_encoding() {
        let mut invalid = statement();
        invalid.subject.method = "x".repeat(MAX_PROOF_METHOD_BYTES + 1);
        assert_eq!(invalid.encode(), Err(WireError::InvalidValue));

        let mut invalid = record(b"physical proof");
        invalid.proof.len = crate::MAX_CATALOG_ARTIFACT_BYTES + 1;
        assert_eq!(invalid.encode(), Err(WireError::InvalidValue));
    }
}
