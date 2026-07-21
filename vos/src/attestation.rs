//! Portable v3 attestations and the verifier-only path.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::v2::wire::{Decoder, Encoder};
use crate::v2::{
    AccumulationReceiptV2, ActorId, DecodeError, DeploymentId, Hash, InvocationId, MethodPolicyV2,
    ProducerId, ProgramId, ProofVerificationRequestV2, RefineImportsV2, SpaceId, TransitionV2,
    V2Wire, WorkEnvelopeV2,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateCommitmentV3 {
    Linear(Hash),
    Crdt(Vec<Hash>),
}

/// Consensus-visible statement proved by an attested actor method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationStatementV3 {
    pub statement_version: u16,
    pub space: SpaceId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub actor_program: ProgramId,
    pub method: String,
    pub schema: Hash,
    pub invocation: InvocationId,
    pub before: StateCommitmentV3,
    pub after: StateCommitmentV3,
    pub claim_commitment: Hash,
    pub input_commitment: Hash,
    pub authorization_policy: Hash,
    pub accumulation_receipt: AccumulationReceiptV2,
}

/// Canonical public inputs returned by guest-owned attestation preparation.
///
/// The host passes this value to the proof producer unchanged. In particular,
/// it must not reconstruct the method policy or predicted receipt outside the
/// service guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPreparationV2 {
    pub receipt: AccumulationReceiptV2,
    pub statement: AttestationStatementV3,
}

impl AttestationPreparationV2 {
    pub fn for_transition(
        work: &WorkEnvelopeV2,
        transition: &TransitionV2,
        policy: &MethodPolicyV2,
        receipt: AccumulationReceiptV2,
    ) -> Result<Self, AttestationError> {
        let statement =
            AttestationStatementV3::for_transition(work, transition, policy, receipt.clone())?;
        Ok(Self { receipt, statement })
    }

    pub fn validate(&self) -> Result<(), AttestationError> {
        self.statement.validate()?;
        if self.statement.accumulation_receipt != self.receipt {
            return Err(AttestationError::ReceiptMismatch);
        }
        Ok(())
    }

    /// Check the public inputs against the exact live Refine execution that a
    /// proof producer will deterministically replay.
    pub fn validate_for_execution(
        &self,
        work: &WorkEnvelopeV2,
        transition: &TransitionV2,
    ) -> Result<(), AttestationError> {
        self.validate()?;
        let statement = &self.statement;
        let receipt = &self.receipt;
        let reply = transition
            .reply
            .as_ref()
            .filter(|reply| reply.producer == work.target)
            .ok_or(AttestationError::InvalidStatement)?;
        let authorization_input = authorization_input(&work.authorization);
        if transition.proof.is_some()
            || work.service != transition.service
            || work.service != receipt.service
            || work.input_id() != transition.consumed_input
            || work.base != transition.base
            || work.target_program != transition.target_program
            || receipt.accepted_transition != transition.commitment()
            || statement.space != work.service.space
            || statement.actor != work.target
            || statement.deployment != work.service.deployment
            || statement.actor_program != work.target_program
            || statement.method != work.method
            || statement.invocation != work.invocation
            || statement.claim_commitment
                != Hash::digest(b"vos/attestation-claim/v3", &[&reply.result])
            || statement.input_commitment
                != Hash::digest(
                    b"vos/attestation-input/v3",
                    &[&work.arguments, &authorization_input.0],
                )
        {
            return Err(AttestationError::InvalidStatement);
        }
        Ok(())
    }
}

impl V2Wire for AttestationPreparationV2 {
    const MAGIC: [u8; 4] = *b"VAP2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.bytes(&self.receipt.encode());
        encoder.bytes(&self.statement.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            receipt: AccumulationReceiptV2::decode(&decoder.bytes()?)?,
            statement: AttestationStatementV3::decode(&decoder.bytes()?)?,
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

impl AttestationStatementV3 {
    /// Construct the one canonical statement for a prepared actor transition.
    /// Both the prover and guest Accumulate use this function, preventing a
    /// host from substituting different public inputs at proof time.
    pub fn for_transition(
        work: &WorkEnvelopeV2,
        transition: &TransitionV2,
        policy: &MethodPolicyV2,
        receipt: AccumulationReceiptV2,
    ) -> Result<Self, AttestationError> {
        if work.service != transition.service
            || work.service != receipt.service
            || work.target_program != transition.target_program
            || work.input_id() != transition.consumed_input
            || work.base != transition.base
            || work.method != policy.method
            || receipt.accepted_transition != transition.commitment()
            || receipt.checkpoint != work.workflow_step
            || receipt.consistency != work.consistency
        {
            return Err(AttestationError::InvalidStatement);
        }
        let reply = transition
            .reply
            .as_ref()
            .filter(|reply| reply.producer == work.target)
            .ok_or(AttestationError::InvalidStatement)?;
        let before = match &work.base {
            crate::v2::ConsistencyBaseV2::Linear { state_root, .. } => {
                StateCommitmentV3::Linear(*state_root)
            }
            crate::v2::ConsistencyBaseV2::Crdt { heads } => StateCommitmentV3::Crdt(heads.clone()),
        };
        let after = match receipt.consistency {
            crate::v2::ConsistencyModeV2::Crdt => {
                StateCommitmentV3::Crdt(receipt.resulting_crdt_heads.clone())
            }
            _ => StateCommitmentV3::Linear(
                receipt
                    .resulting_state_root
                    .ok_or(AttestationError::InvalidStatement)?,
            ),
        };
        let authorization_input = authorization_input(&work.authorization);
        let value = Self {
            statement_version: crate::v2::ATTESTATION_STATEMENT_VERSION,
            space: work.service.space,
            actor: work.target,
            deployment: work.service.deployment,
            actor_program: work.target_program,
            method: work.method.clone(),
            schema: policy.schema,
            invocation: work.invocation,
            before,
            after,
            claim_commitment: Hash::digest(b"vos/attestation-claim/v3", &[&reply.result]),
            input_commitment: Hash::digest(
                b"vos/attestation-input/v3",
                &[&work.arguments, &authorization_input.0],
            ),
            authorization_policy: policy.policy,
            accumulation_receipt: receipt,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(b"vos/attestation-statement/v3", &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.statement_version != crate::v2::ATTESTATION_STATEMENT_VERSION {
            return Err(AttestationError::WrongStatementVersion);
        }
        if self.method.is_empty()
            || self.accumulation_receipt.service.service_abi != crate::v2::ABI_VERSION
            || self.accumulation_receipt.service.execution_semantics
                != crate::v2::EXECUTION_SEMANTICS_ID
        {
            return Err(AttestationError::InvalidStatement);
        }
        if self.space != self.accumulation_receipt.service.space
            || self.deployment != self.accumulation_receipt.service.deployment
            || self.accumulation_receipt.accepted_transition == Hash::ZERO
        {
            return Err(AttestationError::ReceiptMismatch);
        }
        match (&self.before, &self.after) {
            (StateCommitmentV3::Linear(_), StateCommitmentV3::Linear(after))
                if self.accumulation_receipt.consistency != crate::v2::ConsistencyModeV2::Crdt
                    && self.accumulation_receipt.resulting_state_root == Some(*after)
                    && self.accumulation_receipt.resulting_crdt_heads.is_empty() =>
            {
                Ok(())
            }
            (StateCommitmentV3::Crdt(before), StateCommitmentV3::Crdt(after))
                if self.accumulation_receipt.consistency == crate::v2::ConsistencyModeV2::Crdt
                    && self.accumulation_receipt.resulting_state_root.is_none()
                    && self.accumulation_receipt.resulting_crdt_heads == *after
                    && hashes_are_canonical(before)
                    && hashes_are_canonical(after) =>
            {
                Ok(())
            }
            _ => Err(AttestationError::StateCommitmentMismatch),
        }
    }
}

fn authorization_input(authorization: &crate::v2::AuthorizationEvidenceV2) -> Hash {
    match authorization {
        crate::v2::AuthorizationEvidenceV2::Public => Hash::ZERO,
        crate::v2::AuthorizationEvidenceV2::Credential {
            credential_commitment,
            ..
        }
        | crate::v2::AuthorizationEvidenceV2::PrivateCredential {
            credential_commitment,
            ..
        } => *credential_commitment,
        crate::v2::AuthorizationEvidenceV2::SystemCapability { capability, .. } => {
            Hash(capability.0)
        }
    }
}

/// Exact replay input handed to the configured proof producer. It includes
/// the protocol-pinned service scheduler, all canonical actor PVMs and blobs,
/// the live work input/output, and the guest-derived public statement.
pub struct AttestationProofRequestV2<'a> {
    pub canonical_service_pvm: &'a [u8],
    pub work: &'a WorkEnvelopeV2,
    pub imports: &'a RefineImportsV2,
    pub transition: &'a TransitionV2,
    pub preparation: &'a AttestationPreparationV2,
}

impl AttestationProofRequestV2<'_> {
    pub fn validate(&self) -> Result<(), AttestationError> {
        if ProgramId::of_pvm(self.canonical_service_pvm) != self.work.service.service_program
            || self.imports.validate_for(self.work).is_err()
        {
            return Err(AttestationError::InvalidStatement);
        }
        self.preparation
            .validate_for_execution(self.work, self.transition)
    }
}

/// Trace and proof bytes produced from one exact canonical replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducedAttestationProofV2 {
    pub trace: Hash,
    pub proof: Vec<u8>,
}

impl ProducedAttestationProofV2 {
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.trace == Hash::ZERO
            || self.proof.is_empty()
            || self.proof.len() > crate::v2::MAX_ATTESTATION_PROOF_BYTES
        {
            return Err(AttestationError::InvalidProof);
        }
        Ok(())
    }
}

/// Canonical actor-PVM proof engine. Implementations may trace the live run or
/// deterministically replay the exact request; they may not substitute an
/// attestation-only program.
pub trait AttestationProofProducerV2 {
    type Error;

    fn prove(
        &mut self,
        request: &AttestationProofRequestV2<'_>,
    ) -> Result<ProducedAttestationProofV2, Self::Error>;
}

/// Host cache/verifier seam used after proof generation and before Apply.
/// Making proof bytes available is not a service-state commit and never
/// publishes an application attestation package.
pub trait AttestationProofHostV2 {
    fn make_proof_available(&mut self, request: &ProofVerificationRequestV2, proof: &[u8]) -> bool;
}

impl V2Wire for AttestationStatementV3 {
    const MAGIC: [u8; 4] = *b"VOSA";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.u16(self.statement_version);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.actor.0);
        encoder.fixed(&self.deployment.0);
        encoder.fixed(&self.actor_program.0);
        encoder.string(&self.method);
        encoder.fixed(&self.schema.0);
        encoder.fixed(&self.invocation.0);
        encode_state(&mut encoder, &self.before);
        encode_state(&mut encoder, &self.after);
        encoder.fixed(&self.claim_commitment.0);
        encoder.fixed(&self.input_commitment.0);
        encoder.fixed(&self.authorization_policy.0);
        encoder.bytes(&self.accumulation_receipt.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            statement_version: decoder.u16()?,
            space: SpaceId(decoder.fixed()?),
            actor: ActorId(decoder.fixed()?),
            deployment: DeploymentId(decoder.fixed()?),
            actor_program: ProgramId(decoder.fixed()?),
            method: decoder.string()?,
            schema: Hash(decoder.fixed()?),
            invocation: InvocationId(decoder.fixed()?),
            before: decode_state(decoder)?,
            after: decode_state(decoder)?,
            claim_commitment: Hash(decoder.fixed()?),
            input_commitment: Hash(decoder.fixed()?),
            authorization_policy: Hash(decoder.fixed()?),
            accumulation_receipt: AccumulationReceiptV2::decode(&decoder.bytes()?)?,
        };
        value.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(value)
    }
}

fn hashes_are_canonical(values: &[Hash]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_state(encoder: &mut Encoder<'_>, state: &StateCommitmentV3) {
    match state {
        StateCommitmentV3::Linear(root) => {
            encoder.u8(0);
            encoder.fixed(&root.0);
        }
        StateCommitmentV3::Crdt(heads) => {
            encoder.u8(1);
            encoder.list(heads, |encoder, head| encoder.fixed(&head.0));
        }
    }
}

fn decode_state(decoder: &mut Decoder<'_>) -> Result<StateCommitmentV3, DecodeError> {
    match decoder.u8()? {
        0 => Ok(StateCommitmentV3::Linear(Hash(decoder.fixed()?))),
        1 => Ok(StateCommitmentV3::Crdt(
            decoder.list(|decoder| decoder.fixed().map(Hash))?,
        )),
        _ => Err(DecodeError::InvalidTag),
    }
}

/// Application proof package. `M` is the generated method marker. There is
/// deliberately no `claim()` accessor; previews are explicitly unverified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation<T, M> {
    producer_name: String,
    producer: ProducerId,
    statement: AttestationStatementV3,
    trace: Hash,
    preview: T,
    proof: Vec<u8>,
    _method: PhantomData<M>,
}

/// Generated binding between an attested method marker, its return type, and
/// the exact actor reply wire committed by `TransitionV2`.
pub trait AttestedMethod<T> {
    const METHOD: &'static str;

    fn claim_wire(claim: &T) -> Vec<u8>;

    fn decode_claim_wire(wire: &[u8]) -> Option<T>;
}

impl<T, M> Attestation<T, M> {
    #[doc(hidden)]
    pub fn __from_runtime(
        producer_name: String,
        producer: ProducerId,
        statement: AttestationStatementV3,
        trace: Hash,
        preview: T,
        proof: Vec<u8>,
    ) -> Result<Self, AttestationError>
    where
        M: AttestedMethod<T>,
    {
        let package = Self {
            producer_name,
            producer,
            statement,
            trace,
            preview,
            proof,
            _method: PhantomData,
        };
        package.statement.validate()?;
        if package.trace == Hash::ZERO
            || package.proof.is_empty()
            || package.proof.len() > crate::v2::MAX_ATTESTATION_PROOF_BYTES
        {
            return Err(AttestationError::InvalidProof);
        }
        if package.statement.method != M::METHOD {
            return Err(AttestationError::WrongMethod);
        }
        if Hash::digest(
            b"vos/attestation-claim/v3",
            &[&M::claim_wire(&package.preview)],
        ) != package.statement.claim_commitment
        {
            return Err(AttestationError::ClaimCommitmentMismatch);
        }
        Ok(package)
    }

    /// UI/transport preview. Never use it for authorization or state changes.
    pub fn unverified_preview(&self) -> &T {
        &self.preview
    }

    pub fn statement(&self) -> &AttestationStatementV3 {
        &self.statement
    }

    pub fn producer(&self) -> ProducerId {
        self.producer
    }

    /// Strict portable application package. The preview is encoded with the
    /// exact generated actor-reply codec, not a second generic serializer.
    pub fn to_portable_bytes(&self) -> Vec<u8>
    where
        M: AttestedMethod<T>,
    {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"VAT3");
        bytes.extend_from_slice(&crate::v2::ABI_VERSION.to_le_bytes());
        let mut encoder = Encoder(&mut bytes);
        encoder.string(&self.producer_name);
        encoder.fixed(&self.producer.0);
        encoder.bytes(&self.statement.encode());
        encoder.fixed(&self.trace.0);
        encoder.bytes(&M::claim_wire(&self.preview));
        encoder.bytes(&self.proof);
        bytes
    }

    pub fn from_portable_bytes(bytes: &[u8]) -> Result<Self, AttestationError>
    where
        M: AttestedMethod<T>,
    {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4).map_err(invalid_package)? != b"VAT3"
            || decoder.u16().map_err(invalid_package)? != crate::v2::ABI_VERSION
        {
            return Err(AttestationError::InvalidStatement);
        }
        let producer_name = decoder.string().map_err(invalid_package)?;
        let producer = ProducerId(decoder.fixed().map_err(invalid_package)?);
        let statement = AttestationStatementV3::decode(&decoder.bytes().map_err(invalid_package)?)
            .map_err(invalid_package)?;
        let trace = Hash(decoder.fixed().map_err(invalid_package)?);
        let preview = M::decode_claim_wire(&decoder.bytes().map_err(invalid_package)?)
            .ok_or(AttestationError::ClaimCommitmentMismatch)?;
        let proof = decoder.bytes().map_err(invalid_package)?;
        if !decoder.exhausted() {
            return Err(AttestationError::InvalidStatement);
        }
        Self::__from_runtime(producer_name, producer, statement, trace, preview, proof)
    }
}

fn invalid_package(_: DecodeError) -> AttestationError {
    AttestationError::InvalidStatement
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> core::ops::Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationError {
    CannotSuspend,
    WrongStatementVersion,
    InvalidStatement,
    WrongProducer,
    WrongMethod,
    ClaimCommitmentMismatch,
    ReceiptMismatch,
    StateCommitmentMismatch,
    InvalidProof,
    Replay,
}

impl core::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "attestation failed: {self:?}")
    }
}

impl core::error::Error for AttestationError {}

/// Proof engine seam. Implementations verify the canonical actor PVM proof
/// against the exact statement and execution-semantics identity.
pub trait ProofVerifier {
    fn verify(
        &self,
        actor_program: ProgramId,
        execution_semantics: Hash,
        statement: Hash,
        proof: &[u8],
    ) -> bool;
}

impl<F> ProofVerifier for F
where
    F: Fn(ProgramId, Hash, Hash, &[u8]) -> bool,
{
    fn verify(
        &self,
        actor_program: ProgramId,
        execution_semantics: Hash,
        statement: Hash,
        proof: &[u8],
    ) -> bool {
        self(actor_program, execution_semantics, statement, proof)
    }
}

#[derive(Debug, Default)]
pub struct AttestationReplayGuard {
    seen: BTreeSet<(ActorId, InvocationId)>,
}

/// Durable replay seam used by the verifier path. Deployment adapters must
/// make this admission atomic with any state change authorized by the claim.
pub trait AttestationReplayStore {
    fn admit_once(&mut self, actor: ActorId, invocation: InvocationId) -> bool;
}

impl AttestationReplayStore for AttestationReplayGuard {
    fn admit_once(&mut self, actor: ActorId, invocation: InvocationId) -> bool {
        self.seen.insert((actor, invocation))
    }
}

/// Authenticated registry result for the producer name supplied to
/// [`VerifyAttestationBuilder::from`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationSource {
    pub actor: ActorId,
    pub producer: ProducerId,
}

pub trait AttestationSourceResolver {
    fn resolve_attestation_source(&self, name: &str) -> Option<AttestationSource>;
}

impl<F> AttestationSourceResolver for F
where
    F: Fn(&str) -> Option<AttestationSource>,
{
    fn resolve_attestation_source(&self, name: &str) -> Option<AttestationSource> {
        self(name)
    }
}

/// Verify an already-produced package. This path never invokes the producer.
pub fn verify_once<T, M: AttestedMethod<T>>(
    package: Attestation<T, M>,
    expected_producer_name: &str,
    expected_actor: ActorId,
    expected_producer: ProducerId,
    replay: &mut impl AttestationReplayStore,
    verifier: &impl ProofVerifier,
) -> Result<Verified<T>, AttestationError> {
    if package.producer_name != expected_producer_name
        || package.statement.actor != expected_actor
        || package.producer != expected_producer
    {
        return Err(AttestationError::WrongProducer);
    }
    package.statement.validate()?;
    if package.statement.method != M::METHOD {
        return Err(AttestationError::WrongMethod);
    }
    if Hash::digest(
        b"vos/attestation-claim/v3",
        &[&M::claim_wire(&package.preview)],
    ) != package.statement.claim_commitment
    {
        return Err(AttestationError::ClaimCommitmentMismatch);
    }
    if !verifier.verify(
        package.statement.actor_program,
        package
            .statement
            .accumulation_receipt
            .service
            .execution_semantics,
        package.statement.commitment(),
        &package.proof,
    ) {
        return Err(AttestationError::InvalidProof);
    }
    if !replay.admit_once(package.statement.actor, package.statement.invocation) {
        return Err(AttestationError::Replay);
    }
    Ok(Verified(package.preview))
}

/// Verifier-side dependencies. It deliberately contains no proof producer or
/// invocation capability: verification cannot execute the source actor.
pub struct VerificationContext<'a, R, V, S> {
    resolver: &'a R,
    verifier: &'a V,
    replay: &'a mut S,
}

impl<'a, R, V, S> VerificationContext<'a, R, V, S> {
    pub fn new(resolver: &'a R, verifier: &'a V, replay: &'a mut S) -> Self {
        Self {
            resolver,
            verifier,
            replay,
        }
    }

    pub fn verify<T, M>(
        &mut self,
        package: Attestation<T, M>,
    ) -> VerifyAttestationBuilder<'_, T, M, R, V, S> {
        VerifyAttestationBuilder {
            package,
            resolver: self.resolver,
            verifier: self.verifier,
            replay: self.replay,
        }
    }
}

/// First verifier-builder state. Calling `from` is mandatory before the
/// once-only verification operation becomes available.
pub struct VerifyAttestationBuilder<'a, T, M, R, V, S> {
    package: Attestation<T, M>,
    resolver: &'a R,
    verifier: &'a V,
    replay: &'a mut S,
}

impl<'a, T, M, R, V, S> VerifyAttestationBuilder<'a, T, M, R, V, S> {
    pub fn from(
        self,
        producer_name: impl Into<String>,
    ) -> VerifyAttestationFrom<'a, T, M, R, V, S> {
        VerifyAttestationFrom {
            package: self.package,
            producer_name: producer_name.into(),
            resolver: self.resolver,
            verifier: self.verifier,
            replay: self.replay,
        }
    }
}

/// Builder state with an authenticated producer name ready to resolve.
pub struct VerifyAttestationFrom<'a, T, M, R, V, S> {
    package: Attestation<T, M>,
    producer_name: String,
    resolver: &'a R,
    verifier: &'a V,
    replay: &'a mut S,
}

impl<T, M, R, V, S> VerifyAttestationFrom<'_, T, M, R, V, S>
where
    M: AttestedMethod<T>,
    R: AttestationSourceResolver,
    V: ProofVerifier,
    S: AttestationReplayStore,
{
    pub async fn once(self) -> Result<Verified<T>, AttestationError> {
        let source = self
            .resolver
            .resolve_attestation_source(&self.producer_name)
            .ok_or(AttestationError::WrongProducer)?;
        verify_once(
            self.package,
            &self.producer_name,
            source.actor,
            source.producer,
            self.replay,
            self.verifier,
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use crate::Encode;
    use crate::v2::{ConsistencyModeV2, RootServiceId, ServiceIdentityV2};

    use super::*;

    enum Method {}

    impl AttestedMethod<u64> for Method {
        const METHOD: &'static str = "is_adult";

        fn claim_wire(claim: &u64) -> Vec<u8> {
            crate::value::Value::U64(*claim).encode()
        }

        fn decode_claim_wire(wire: &[u8]) -> Option<u64> {
            <crate::value::Value as crate::Decode>::try_decode(wire)?.as_u64()
        }
    }

    enum OtherMethod {}

    impl AttestedMethod<u64> for OtherMethod {
        const METHOD: &'static str = "other_method";

        fn claim_wire(claim: &u64) -> Vec<u8> {
            Method::claim_wire(claim)
        }

        fn decode_claim_wire(wire: &[u8]) -> Option<u64> {
            Method::decode_claim_wire(wire)
        }
    }

    fn package(claim: u64) -> Attestation<u64, Method> {
        let deployment = DeploymentId([3; 32]);
        let receipt = AccumulationReceiptV2 {
            service: ServiceIdentityV2 {
                space: SpaceId([6; 32]),
                root_service: RootServiceId([1; 32]),
                deployment,
                service_program: ProgramId([2; 32]),
                service_abi: crate::v2::ABI_VERSION,
                execution_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
            },
            accepted_transition: Hash([4; 32]),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: Some(Hash([5; 32])),
            resulting_crdt_heads: vec![],
            sequence: 1,
            checkpoint: 1,
            consistency: ConsistencyModeV2::Local,
        };
        let statement = AttestationStatementV3 {
            statement_version: crate::v2::ATTESTATION_STATEMENT_VERSION,
            space: SpaceId([6; 32]),
            actor: ActorId([7; 32]),
            deployment,
            actor_program: ProgramId([8; 32]),
            method: "is_adult".to_string(),
            schema: Hash([9; 32]),
            invocation: InvocationId([10; 32]),
            before: StateCommitmentV3::Linear(Hash([11; 32])),
            after: StateCommitmentV3::Linear(Hash([5; 32])),
            claim_commitment: Hash::digest(
                b"vos/attestation-claim/v3",
                &[&Method::claim_wire(&claim)],
            ),
            input_commitment: Hash([13; 32]),
            authorization_policy: Hash([14; 32]),
            accumulation_receipt: receipt,
        };
        Attestation::__from_runtime(
            "private-age".to_string(),
            ProducerId([15; 32]),
            statement,
            Hash([16; 32]),
            claim,
            vec![1],
        )
        .unwrap()
    }

    #[test]
    fn verification_is_separate_tamper_evident_and_once_only() {
        let verifier = |_: ProgramId, _: Hash, _: Hash, proof: &[u8]| proof == [1];
        let mut replay = AttestationReplayGuard::default();
        assert_eq!(
            verify_once(
                package(21),
                "private-age",
                ActorId([7; 32]),
                ProducerId([15; 32]),
                &mut replay,
                &verifier,
            )
            .unwrap()
            .into_inner(),
            21,
        );
        assert_eq!(
            verify_once(
                package(21),
                "private-age",
                ActorId([7; 32]),
                ProducerId([15; 32]),
                &mut replay,
                &verifier,
            ),
            Err(AttestationError::Replay),
        );

        let mut tampered = package(21);
        tampered.preview = 20;
        assert_eq!(
            verify_once(
                tampered,
                "private-age",
                ActorId([7; 32]),
                ProducerId([15; 32]),
                &mut AttestationReplayGuard::default(),
                &verifier,
            ),
            Err(AttestationError::ClaimCommitmentMismatch),
        );

        assert_eq!(
            verify_once(
                package(22),
                "private-age",
                ActorId([7; 32]),
                ProducerId([99; 32]),
                &mut AttestationReplayGuard::default(),
                &verifier,
            ),
            Err(AttestationError::WrongProducer),
        );

        let mut wrong_state = package(23);
        wrong_state.statement.after = StateCommitmentV3::Linear(Hash([99; 32]));
        assert_eq!(
            verify_once(
                wrong_state,
                "private-age",
                ActorId([7; 32]),
                ProducerId([15; 32]),
                &mut AttestationReplayGuard::default(),
                &verifier,
            ),
            Err(AttestationError::StateCommitmentMismatch),
        );
    }

    #[test]
    fn verifier_builder_resolves_the_source_and_never_needs_a_producer() {
        let resolver = |name: &str| {
            (name == "private-age").then_some(AttestationSource {
                actor: ActorId([7; 32]),
                producer: ProducerId([15; 32]),
            })
        };
        let verifier = |_: ProgramId, _: Hash, _: Hash, proof: &[u8]| proof == [1];
        let mut replay = AttestationReplayGuard::default();
        let mut context = VerificationContext::new(&resolver, &verifier, &mut replay);

        let claim =
            crate::block_on(context.verify(package(25)).from("private-age").once()).unwrap();
        assert_eq!(claim.into_inner(), 25);

        assert_eq!(
            crate::block_on(context.verify(package(25)).from("private-age").once(),),
            Err(AttestationError::Replay),
        );

        let mut fresh_replay = AttestationReplayGuard::default();
        let mut fresh_context = VerificationContext::new(&resolver, &verifier, &mut fresh_replay);
        assert_eq!(
            crate::block_on(fresh_context.verify(package(26)).from("unknown-age").once(),),
            Err(AttestationError::WrongProducer),
        );
    }

    #[test]
    fn runtime_constructor_rejects_the_wrong_generated_method_marker() {
        let package = package(24);
        assert!(matches!(
            Attestation::<u64, OtherMethod>::__from_runtime(
                "private-age".to_string(),
                package.producer,
                package.statement,
                package.trace,
                package.preview,
                package.proof,
            ),
            Err(AttestationError::WrongMethod)
        ));
    }

    #[test]
    fn portable_package_round_trips_and_rejects_trailing_or_tampered_claims() {
        let package = package(27);
        let bytes = package.to_portable_bytes();
        let decoded = Attestation::<u64, Method>::from_portable_bytes(&bytes).unwrap();
        assert_eq!(decoded.unverified_preview(), &27);
        assert_eq!(decoded.statement(), package.statement());
        assert_eq!(decoded.trace, package.trace);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            Attestation::<u64, Method>::from_portable_bytes(&trailing),
            Err(AttestationError::InvalidStatement)
        ));

        let mut tampered = bytes;
        let claim_position = tampered
            .windows(Method::claim_wire(&27).len())
            .position(|window| window == Method::claim_wire(&27))
            .unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert_ne!(claim_position, tampered.len() - 1, "proof was tampered");
        assert!(
            Attestation::<u64, Method>::from_portable_bytes(&tampered).is_ok(),
            "proof bytes are opaque until verification"
        );

        let mut claim_tampered = package.to_portable_bytes();
        let claim_wire = Method::claim_wire(&27);
        let claim_position = claim_tampered
            .windows(claim_wire.len())
            .position(|window| window == claim_wire)
            .unwrap();
        claim_tampered[claim_position + claim_wire.len() - 1] ^= 1;
        assert!(matches!(
            Attestation::<u64, Method>::from_portable_bytes(&claim_tampered),
            Err(AttestationError::ClaimCommitmentMismatch)
        ));
    }

    #[test]
    fn preparation_wire_binds_the_guest_receipt_to_the_statement() {
        let package = package(21);
        let preparation = AttestationPreparationV2 {
            receipt: package.statement.accumulation_receipt.clone(),
            statement: package.statement.clone(),
        };
        assert_eq!(
            AttestationPreparationV2::decode(&preparation.encode()).unwrap(),
            preparation
        );

        let mut mismatched = preparation;
        mismatched.receipt.sequence += 1;
        assert_eq!(
            AttestationPreparationV2::decode(&mismatched.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn produced_proofs_must_fit_the_durable_actor_resume_window() {
        let proof = ProducedAttestationProofV2 {
            trace: Hash([1; 32]),
            proof: vec![0; crate::v2::MAX_ATTESTATION_PROOF_BYTES + 1],
        };
        assert_eq!(proof.validate(), Err(AttestationError::InvalidProof));

        let package = package(21);
        assert!(matches!(
            Attestation::<u64, Method>::__from_runtime(
                package.producer_name,
                package.producer,
                package.statement,
                Hash::ZERO,
                package.preview,
                package.proof,
            ),
            Err(AttestationError::InvalidProof)
        ));
    }
}
