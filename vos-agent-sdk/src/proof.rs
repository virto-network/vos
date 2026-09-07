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
    ActorId, AgentId, BlobRef, DeploymentId, Hash, InvocationId, MethodMode, ProducerId, ProgramId,
    SpaceId, StateLane,
};

pub const MAX_PROOF_METHOD_BYTES: usize = 128;
pub const PROOF_PUBLIC_KEY_BYTES: usize = 32;
pub const PROOF_SIGNATURE_BYTES: usize = 64;
pub const MAX_TRANSITION_PROOF_RECORD_BYTES: usize = 4 * 1024;

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
    /// Commitment of the complete nested standard Refine trace. This is the
    /// transcript commitment authenticated by the physical proof, not a
    /// producer-private witness or a legacy service attestation.
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

        let writable = self.subject.mode.write_lane();
        for lane in [StateLane::Linear, StateLane::Merge, StateLane::Local] {
            let before = self.before.lane(lane);
            let after = self.after.lane(lane);
            if Some(lane) == writable {
                if before.is_none() || after.is_none() {
                    return false;
                }
            } else if before != after {
                // Queries and immutable lane snapshots cannot alter a state
                // component merely because a proof record names it.
                return false;
            }
        }
        true
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
    // Generation 2 adds the nested Refine transcript commitment. The old
    // unversioned APST shape is deliberately not decoded as this statement.
    const MAGIC: [u8; 4] = *b"APS2";
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
            && self.proof.len <= crate::MAX_CATALOG_ARTIFACT_BYTES
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
        bytes.extend_from_slice(b"vos/agent/transition-proof-record/v2");
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

    pub fn verify<V: TransitionProofVerifier>(
        &self,
        proof_bytes: &[u8],
        verifier: &V,
    ) -> Result<(), ProofRecordError> {
        if !self.validate_shape() {
            return Err(ProofRecordError::InvalidRecord);
        }
        if !self.proof.matches(proof_bytes) {
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
        if !verifier.verify_transition(&self.statement, proof_bytes) {
            return Err(ProofRecordError::InvalidProof);
        }
        Ok(())
    }

    /// Verify both the public proof record and its exact clean Agent
    /// execution binding. This is the follower-facing verification path: it
    /// needs canonical work, canonical transition, and public proof bytes,
    /// but never the producer-private witness.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_exact<V: TransitionProofVerifier>(
        &self,
        proof_bytes: &[u8],
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
        self.verify(proof_bytes, verifier)
    }
}

impl CanonicalWire for TransitionProofRecord {
    // Generation 2 signs a statement that commits the complete nested
    // Refine transcript. No legacy record is upgraded implicitly.
    const MAGIC: [u8; 4] = *b"APR2";
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
/// `verify_transition` must validate the complete physical proof for the
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

    fn verify_transition(&self, statement: &TransitionProofStatement, proof_bytes: &[u8]) -> bool;
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

    fn record(proof_bytes: &[u8]) -> TransitionProofRecord {
        let public_key = [17; 32];
        TransitionProofRecord {
            statement: statement(),
            proof: BlobRef::of_bytes(proof_bytes),
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
            message.starts_with(b"vos/agent/transition-proof-record/v2") && *signature == [18; 64]
        }

        fn verify_transition(
            &self,
            statement: &TransitionProofStatement,
            proof_bytes: &[u8],
        ) -> bool {
            statement.proof_system == Hash([16; 32]) && proof_bytes == b"physical proof"
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
    fn statement_rejects_mutation_outside_the_declared_lane() {
        let mut invalid = statement();
        invalid.after.merge = Some(Hash([90; 32]));
        assert!(!invalid.validate());

        invalid = statement();
        invalid.subject.mode = MethodMode::Query;
        assert!(!invalid.validate());

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
        let encoded = record.encode().unwrap();
        assert_eq!(TransitionProofRecord::decode(&encoded).unwrap(), record);
        assert!(record.verify(b"physical proof", &AcceptExact).is_ok());
        assert!(
            !encoded
                .windows(sentinel.len())
                .any(|window| window == sentinel)
        );
        assert_eq!(witness.bytes, sentinel);
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
        assert_eq!(
            record.verify(b"wrong proof", &AcceptExact),
            Err(ProofRecordError::WrongProof)
        );
        let mut wrong_signature = record.clone();
        wrong_signature.producer_signature[0] ^= 1;
        assert_eq!(
            wrong_signature.verify(b"physical proof", &AcceptExact),
            Err(ProofRecordError::InvalidProducerSignature)
        );
        let mut wrong_system = record;
        wrong_system.statement.proof_system = Hash([19; 32]);
        assert_eq!(
            wrong_system.verify(b"physical proof", &AcceptExact),
            Err(ProofRecordError::InvalidProof)
        );
    }

    #[test]
    fn follower_exact_verification_rejects_every_external_binding_substitution() {
        let record = record(b"physical proof");
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
                &AcceptExact,
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

        for magic in [*b"APRF", *b"PRF1"] {
            let mut old = record.encode().unwrap();
            old[..4].copy_from_slice(&magic);
            assert!(matches!(
                TransitionProofRecord::decode(&old),
                Err(WireError::Decode(DecodeError::InvalidTag))
            ));
        }

        let mut unknown_mode = record.statement.encode().unwrap();
        // Header + nine fixed identities + method length + method bytes.
        let mode = 4 + 32 + 9 * 32 + 4 + record.statement.subject.method.len();
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
        previous_layout.extend_from_slice(b"APST");
        previous_layout.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(&mut previous_layout);
        encode_subject(&mut encoder, &statement.subject);
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

        let mut previous_signing_domain = record.signing_bytes().unwrap();
        previous_signing_domain[b"vos/agent/transition-proof-record/v".len()] = b'1';
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
