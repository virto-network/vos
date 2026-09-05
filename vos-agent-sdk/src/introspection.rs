//! Canonical signed-closure metadata for AgentActor introspection.
//!
//! AAI1 contains only operator-facing documentation and dispatch hints. The
//! executable method ABI and authorization contract remain owned by AMP2, and
//! state/mode declarations remain owned by AAS1. This artifact binds both by
//! exact content reference and is accepted only after all three complete
//! method surfaces agree.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::method_policy::{
    ActorMethodPolicyArtifact, AttestationRequirement, MAX_METHOD_POLICY_ENCODED_BYTES,
    MAX_METHOD_POLICY_NAME_BYTES,
};
use crate::wire::{CanonicalWire, WireError};
use crate::{BlobRef, Hash};

/// The only accepted clean-generation introspection wire magic.
pub const ACTOR_INTROSPECTION_MAGIC: [u8; 4] = *b"AAI1";
pub const MAX_INTROSPECTION_METHODS: usize = crate::schema::MAX_METHODS;
pub const MAX_ACTOR_DOCUMENTATION_BYTES: usize = 4 * 1024;
pub const MAX_METHOD_DOCUMENTATION_BYTES: usize = 4 * 1024;
pub const MAX_ACTOR_INTROSPECTION_ENCODED_BYTES: usize =
    crate::MAX_RUNTIME_EXECUTION_ARTIFACT_BYTES;
/// Exact return type required by the asynchronous job dispatcher.
pub const JOB_RETURN_TYPE_IDENTITY: &str = "u64";

/// Whether the generated CLI may expose a method as a subcommand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CliExposure {
    Hidden = 0,
    Exposed = 1,
}

/// Client-side dispatch contract for one method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MethodDispatch {
    /// The method reply is the result.
    Sync = 0,
    /// The method starts a job and returns its canonical `u64` identifier.
    Job = 1,
}

/// Signed operator-facing metadata for one exact AMP2 method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorMethodIntrospection {
    pub name: String,
    /// First documentation paragraph; empty means undocumented.
    pub doc: String,
    pub cli_exposure: CliExposure,
    /// Zero selects the caller's default timeout.
    pub timeout_ms: u32,
    pub dispatch: MethodDispatch,
}

impl ActorMethodIntrospection {
    pub fn validate(&self) -> Result<(), IntrospectionError> {
        if self.name.is_empty() || self.name.len() > MAX_METHOD_POLICY_NAME_BYTES {
            return Err(IntrospectionError::InvalidMethod);
        }
        if self.doc.len() > MAX_METHOD_DOCUMENTATION_BYTES {
            return Err(IntrospectionError::LimitExceeded);
        }
        Ok(())
    }
}

/// Complete AAI1 artifact inserted into an Actor package's signed closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorIntrospectionArtifact {
    /// Exact AAS1 bytes described by this artifact.
    pub actor_schema: BlobRef,
    /// Exact AMP2 bytes described by this artifact.
    pub method_policy: BlobRef,
    /// First documentation paragraph; empty means undocumented.
    pub actor_doc: String,
    /// Strict UTF-8 byte/name order, complete for the referenced AMP2 table.
    pub methods: Vec<ActorMethodIntrospection>,
}

impl ActorIntrospectionArtifact {
    pub fn validate(&self) -> Result<(), IntrospectionError> {
        if !valid_reference(&self.actor_schema, crate::schema::MAX_ENCODED_BYTES)
            || !valid_reference(&self.method_policy, MAX_METHOD_POLICY_ENCODED_BYTES)
        {
            return Err(IntrospectionError::InvalidArtifact);
        }
        if self.actor_doc.len() > MAX_ACTOR_DOCUMENTATION_BYTES
            || self.methods.len() > MAX_INTROSPECTION_METHODS
        {
            return Err(IntrospectionError::LimitExceeded);
        }
        for method in &self.methods {
            method.validate()?;
        }
        if self
            .methods
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(IntrospectionError::MethodOrder);
        }
        if self
            .encoded_len()
            .is_none_or(|length| length > MAX_ACTOR_INTROSPECTION_ENCODED_BYTES)
        {
            return Err(IntrospectionError::LimitExceeded);
        }
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        // CanonicalWire magic/ABI, two BlobRefs, actor-doc framing and list
        // count. Each row has two framed strings, two tags, and one timeout.
        let mut length = (4usize + crate::RUNTIME_ABI_ID.0.len())
            .checked_add(2 * (32 + 8))?
            .checked_add(4)?
            .checked_add(self.actor_doc.len())?
            .checked_add(4)?;
        for method in &self.methods {
            length = length
                .checked_add(4)?
                .checked_add(method.name.len())?
                .checked_add(4)?
                .checked_add(method.doc.len())?
                .checked_add(1 + 4 + 1)?;
        }
        Some(length)
    }

    pub fn method(&self, name: &str) -> Option<&ActorMethodIntrospection> {
        self.methods
            .binary_search_by(|method| method.name.as_str().cmp(name))
            .ok()
            .and_then(|position| self.methods.get(position))
    }

    /// Authenticate and decode the exact referenced AAS1 and AMP2 bytes, then
    /// require this artifact to describe their complete method set.
    pub fn validate_against_artifact_bytes(
        &self,
        actor_schema_bytes: &[u8],
        method_policy_bytes: &[u8],
    ) -> Result<(), IntrospectionError> {
        self.validate()?;
        if !self.actor_schema.matches(actor_schema_bytes)
            || !self.method_policy.matches(method_policy_bytes)
        {
            return Err(IntrospectionError::ArtifactMismatch);
        }
        let actor_schema = crate::schema::decode(actor_schema_bytes)
            .map_err(|_| IntrospectionError::InvalidSchema)?;
        let method_policy = ActorMethodPolicyArtifact::decode(method_policy_bytes)
            .map_err(|_| IntrospectionError::InvalidMethodPolicy)?;
        method_policy
            .validate_against_schema_bytes(actor_schema_bytes)
            .map_err(|_| IntrospectionError::InvalidMethodPolicy)?;
        if actor_schema.methods.len() != self.methods.len()
            || method_policy.methods.len() != self.methods.len()
        {
            return Err(IntrospectionError::MethodSetMismatch);
        }
        for (introspection, policy) in self.methods.iter().zip(&method_policy.methods) {
            if introspection.name != policy.name {
                return Err(IntrospectionError::MethodSetMismatch);
            }
            if introspection.dispatch == MethodDispatch::Job
                && (policy.return_type_identity != JOB_RETURN_TYPE_IDENTITY
                    || policy.attestation != AttestationRequirement::None)
            {
                return Err(IntrospectionError::InvalidJob);
            }
        }
        Ok(())
    }

    /// Content identity for the later VOS2 exact-closure integration.
    pub fn artifact_ref(&self) -> Result<BlobRef, WireError> {
        Ok(BlobRef::of_bytes(&self.encode()?))
    }
}

impl CanonicalWire for ActorIntrospectionArtifact {
    const MAGIC: [u8; 4] = ACTOR_INTROSPECTION_MAGIC;
    const MAX_ENCODED_BYTES: usize = MAX_ACTOR_INTROSPECTION_ENCODED_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_blob(encoder, &self.actor_schema);
        encode_blob(encoder, &self.method_policy);
        encoder.string(&self.actor_doc);
        encoder.list(&self.methods, encode_method);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor_schema: decode_blob(decoder)?,
            method_policy: decode_blob(decoder)?,
            actor_doc: decoder.string_bounded(MAX_ACTOR_DOCUMENTATION_BYTES)?,
            methods: decoder.list_bounded(MAX_INTROSPECTION_METHODS, decode_method)?,
        };
        value.validate().map_err(|error| match error {
            IntrospectionError::LimitExceeded => DecodeError::LimitExceeded,
            _ => DecodeError::NonCanonical,
        })?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntrospectionError {
    InvalidArtifact,
    InvalidMethod,
    MethodOrder,
    ArtifactMismatch,
    InvalidSchema,
    InvalidMethodPolicy,
    MethodSetMismatch,
    InvalidJob,
    LimitExceeded,
}

impl fmt::Display for IntrospectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact => formatter.write_str("invalid actor introspection artifact"),
            Self::InvalidMethod => formatter.write_str("invalid actor introspection method"),
            Self::MethodOrder => formatter.write_str("noncanonical introspection method order"),
            Self::ArtifactMismatch => {
                formatter.write_str("introspection artifact content reference mismatch")
            }
            Self::InvalidSchema => formatter.write_str("invalid referenced AgentActor schema"),
            Self::InvalidMethodPolicy => {
                formatter.write_str("invalid referenced actor method policy")
            }
            Self::MethodSetMismatch => {
                formatter.write_str("introspection methods do not match actor policy")
            }
            Self::InvalidJob => formatter.write_str("invalid actor job dispatch contract"),
            Self::LimitExceeded => formatter.write_str("actor introspection limit exceeded"),
        }
    }
}

impl core::error::Error for IntrospectionError {}

fn valid_reference(reference: &BlobRef, maximum: usize) -> bool {
    reference.hash != Hash::ZERO && reference.len != 0 && reference.len <= maximum as u64
}

fn encode_blob(encoder: &mut Encoder<'_>, value: &BlobRef) {
    encoder.fixed(value.hash.as_bytes());
    encoder.u64(value.len);
}

fn decode_blob(decoder: &mut Decoder<'_>) -> Result<BlobRef, DecodeError> {
    Ok(BlobRef {
        hash: Hash(decoder.fixed()?),
        len: decoder.u64()?,
    })
}

fn encode_method(encoder: &mut Encoder<'_>, method: &ActorMethodIntrospection) {
    encoder.string(&method.name);
    encoder.string(&method.doc);
    encoder.u8(method.cli_exposure as u8);
    encoder.u32(method.timeout_ms);
    encoder.u8(method.dispatch as u8);
}

fn decode_method(decoder: &mut Decoder<'_>) -> Result<ActorMethodIntrospection, DecodeError> {
    Ok(ActorMethodIntrospection {
        name: decoder.string_bounded(MAX_METHOD_POLICY_NAME_BYTES)?,
        doc: decoder.string_bounded(MAX_METHOD_DOCUMENTATION_BYTES)?,
        cli_exposure: match decoder.u8()? {
            0 => CliExposure::Hidden,
            1 => CliExposure::Exposed,
            _ => return Err(DecodeError::InvalidTag),
        },
        timeout_ms: decoder.u32()?,
        dispatch: match decoder.u8()? {
            0 => MethodDispatch::Sync,
            1 => MethodDispatch::Job,
            _ => return Err(DecodeError::InvalidTag),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_policy::{
        ActorMethodPolicy, AuthorizationPolicySelector, IdempotencyRequirement, MethodArgument,
    };
    use crate::schema::{ParsedMethod, ParsedSchema};
    use crate::{CapabilityId, MethodMode};

    fn artifacts() -> (Vec<u8>, Vec<u8>) {
        let schema = ParsedSchema {
            fields: Vec::new(),
            methods: alloc::vec![
                ParsedMethod {
                    source_index: 0,
                    name: "write".into(),
                    mode: MethodMode::Merge,
                    explicit: true,
                },
                ParsedMethod {
                    source_index: 1,
                    name: "read".into(),
                    mode: MethodMode::Query,
                    explicit: false,
                },
            ],
        }
        .encode()
        .unwrap();
        let policy = ActorMethodPolicyArtifact {
            actor_schema: BlobRef::of_bytes(&schema),
            methods: alloc::vec![
                ActorMethodPolicy {
                    name: "read".into(),
                    mode: MethodMode::Query,
                    arguments: Vec::new(),
                    return_type_identity: "bool".into(),
                    authorization_policy: AuthorizationPolicySelector::Public,
                    idempotency: IdempotencyRequirement::NotRequired,
                    attestation: AttestationRequirement::Required {
                        proof_system: Hash([21; 32]),
                    },
                },
                ActorMethodPolicy {
                    name: "write".into(),
                    mode: MethodMode::Merge,
                    arguments: alloc::vec![MethodArgument {
                        name: "value".into(),
                        type_identity: "u64".into(),
                    }],
                    return_type_identity: JOB_RETURN_TYPE_IDENTITY.into(),
                    authorization_policy: AuthorizationPolicySelector::Capability(CapabilityId(
                        [22; 32]
                    )),
                    idempotency: IdempotencyRequirement::Required,
                    attestation: AttestationRequirement::None,
                },
            ],
        }
        .encode()
        .unwrap();
        (schema, policy)
    }

    fn artifact_for(schema: &[u8], policy: &[u8]) -> ActorIntrospectionArtifact {
        ActorIntrospectionArtifact {
            actor_schema: BlobRef::of_bytes(schema),
            method_policy: BlobRef::of_bytes(policy),
            actor_doc: "A durable counter.".into(),
            methods: alloc::vec![
                ActorMethodIntrospection {
                    name: "read".into(),
                    doc: "Read the counter.".into(),
                    cli_exposure: CliExposure::Exposed,
                    timeout_ms: 0,
                    dispatch: MethodDispatch::Sync,
                },
                ActorMethodIntrospection {
                    name: "write".into(),
                    doc: "Start a counter update.".into(),
                    cli_exposure: CliExposure::Hidden,
                    timeout_ms: 120_000,
                    dispatch: MethodDispatch::Job,
                },
            ],
        }
    }

    fn sample() -> (ActorIntrospectionArtifact, Vec<u8>, Vec<u8>) {
        let (schema, policy) = artifacts();
        (artifact_for(&schema, &policy), schema, policy)
    }

    fn encode_unchecked(artifact: &ActorIntrospectionArtifact) -> Vec<u8> {
        let mut bytes = ACTOR_INTROSPECTION_MAGIC.to_vec();
        bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(&mut bytes);
        encode_blob(&mut encoder, &artifact.actor_schema);
        encode_blob(&mut encoder, &artifact.method_policy);
        encoder.string(&artifact.actor_doc);
        encoder.list(&artifact.methods, encode_method);
        bytes
    }

    struct FirstMethodOffsets {
        actor_doc_length: usize,
        method_count: usize,
        method_name_length: usize,
        method_doc_length: usize,
        cli: usize,
        dispatch: usize,
    }

    fn first_method_offsets(artifact: &ActorIntrospectionArtifact) -> FirstMethodOffsets {
        let actor_doc_length = 4 + crate::RUNTIME_ABI_ID.0.len() + 2 * (32 + 8);
        let method_count = actor_doc_length + 4 + artifact.actor_doc.len();
        let method_name_length = method_count + 4;
        let method = &artifact.methods[0];
        let method_doc_length = method_name_length + 4 + method.name.len();
        let cli = method_doc_length + 4 + method.doc.len();
        FirstMethodOffsets {
            actor_doc_length,
            method_count,
            method_name_length,
            method_doc_length,
            cli,
            dispatch: cli + 1 + 4,
        }
    }

    #[test]
    fn canonical_round_trip_lookup_and_exact_cross_binding() {
        let (artifact, schema, policy) = sample();
        artifact
            .validate_against_artifact_bytes(&schema, &policy)
            .unwrap();
        let encoded = artifact.encode().unwrap();
        assert_eq!(artifact.encoded_len(), Some(encoded.len()));
        assert_eq!(
            ActorIntrospectionArtifact::decode(&encoded).unwrap(),
            artifact
        );
        assert_eq!(
            artifact.artifact_ref().unwrap(),
            BlobRef::of_bytes(&encoded)
        );
        assert_eq!(artifact.method("read").unwrap().timeout_ms, 0);
        assert!(artifact.method("missing").is_none());
    }

    #[test]
    fn empty_actor_has_one_canonical_introspection_table() {
        let schema = ParsedSchema {
            fields: Vec::new(),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let policy = ActorMethodPolicyArtifact {
            actor_schema: BlobRef::of_bytes(&schema),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let empty_artifact = ActorIntrospectionArtifact {
            actor_schema: BlobRef::of_bytes(&schema),
            method_policy: BlobRef::of_bytes(&policy),
            actor_doc: String::new(),
            methods: Vec::new(),
        };
        empty_artifact
            .validate_against_artifact_bytes(&schema, &policy)
            .unwrap();
        let encoded = empty_artifact.encode().unwrap();
        assert_eq!(
            ActorIntrospectionArtifact::decode(&encoded).unwrap(),
            empty_artifact
        );

        let (_, nonempty_schema, nonempty_policy) = sample();
        let mismatch = ActorIntrospectionArtifact {
            actor_schema: BlobRef::of_bytes(&nonempty_schema),
            method_policy: BlobRef::of_bytes(&nonempty_policy),
            actor_doc: String::new(),
            methods: Vec::new(),
        };
        assert_eq!(
            mismatch.validate_against_artifact_bytes(&nonempty_schema, &nonempty_policy),
            Err(IntrospectionError::MethodSetMismatch)
        );
    }

    #[test]
    fn job_dispatch_requires_u64_return_and_forbids_attestation() {
        let (schema, policy) = artifacts();
        let mut decoded = ActorMethodPolicyArtifact::decode(&policy).unwrap();
        decoded.methods[1].return_type_identity = "u32".into();
        let wrong_return = decoded.encode().unwrap();
        let artifact = artifact_for(&schema, &wrong_return);
        assert_eq!(
            artifact.validate_against_artifact_bytes(&schema, &wrong_return),
            Err(IntrospectionError::InvalidJob)
        );

        let mut decoded = ActorMethodPolicyArtifact::decode(&policy).unwrap();
        decoded.methods[1].attestation = AttestationRequirement::Required {
            proof_system: Hash([31; 32]),
        };
        let attested = decoded.encode().unwrap();
        let artifact = artifact_for(&schema, &attested);
        assert_eq!(
            artifact.validate_against_artifact_bytes(&schema, &attested),
            Err(IntrospectionError::InvalidJob)
        );

        let mut sync = artifact_for(&schema, &attested);
        sync.methods[1].dispatch = MethodDispatch::Sync;
        sync.validate_against_artifact_bytes(&schema, &attested)
            .unwrap();
    }

    #[test]
    fn exact_references_and_complete_method_set_reject_substitution() {
        let (mut artifact, schema, policy) = sample();
        let mut substituted_schema = schema.clone();
        substituted_schema[0] ^= 1;
        assert_eq!(
            artifact.validate_against_artifact_bytes(&substituted_schema, &policy),
            Err(IntrospectionError::ArtifactMismatch)
        );
        let mut substituted_policy = policy.clone();
        substituted_policy[0] ^= 1;
        assert_eq!(
            artifact.validate_against_artifact_bytes(&schema, &substituted_policy),
            Err(IntrospectionError::ArtifactMismatch)
        );

        artifact.methods.pop();
        assert_eq!(
            artifact.validate_against_artifact_bytes(&schema, &policy),
            Err(IntrospectionError::MethodSetMismatch)
        );
        let (mut artifact, schema, policy) = sample();
        artifact.methods[1].name = "wrong".into();
        assert_eq!(
            artifact.validate_against_artifact_bytes(&schema, &policy),
            Err(IntrospectionError::MethodSetMismatch)
        );
    }

    #[test]
    fn wire_rejects_old_unknown_trailing_and_noncanonical_order() {
        let (artifact, _, _) = sample();
        let encoded = artifact.encode().unwrap();
        let offsets = first_method_offsets(&artifact);

        let mut old = encoded.clone();
        old[..4].copy_from_slice(b"AAI0");
        assert!(matches!(
            ActorIntrospectionArtifact::decode(&old),
            Err(WireError::Decode(DecodeError::InvalidTag))
        ));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            ActorIntrospectionArtifact::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        ));

        for position in [offsets.cli, offsets.dispatch] {
            let mut unknown = encoded.clone();
            unknown[position] = 0xff;
            assert!(matches!(
                ActorIntrospectionArtifact::decode(&unknown),
                Err(WireError::Decode(DecodeError::InvalidTag))
            ));
        }

        let (mut unsorted, _, _) = sample();
        unsorted.methods.swap(0, 1);
        assert_eq!(unsorted.validate(), Err(IntrospectionError::MethodOrder));
        assert!(matches!(
            ActorIntrospectionArtifact::decode(&encode_unchecked(&unsorted)),
            Err(WireError::Decode(DecodeError::NonCanonical))
        ));
        let (mut duplicate, _, _) = sample();
        duplicate.methods[1].name = duplicate.methods[0].name.clone();
        assert_eq!(duplicate.validate(), Err(IntrospectionError::MethodOrder));
        assert!(matches!(
            ActorIntrospectionArtifact::decode(&encode_unchecked(&duplicate)),
            Err(WireError::Decode(DecodeError::NonCanonical))
        ));
    }

    #[test]
    fn decoder_preflights_every_length_count_and_aggregate_bound() {
        let (artifact, _, _) = sample();
        let encoded = artifact.encode().unwrap();
        let offsets = first_method_offsets(&artifact);

        for (position, maximum) in [
            (offsets.actor_doc_length, MAX_ACTOR_DOCUMENTATION_BYTES),
            (offsets.method_name_length, MAX_METHOD_POLICY_NAME_BYTES),
            (offsets.method_doc_length, MAX_METHOD_DOCUMENTATION_BYTES),
        ] {
            let mut hostile = encoded.clone();
            hostile[position..position + 4].copy_from_slice(&((maximum + 1) as u32).to_le_bytes());
            assert!(matches!(
                ActorIntrospectionArtifact::decode(&hostile),
                Err(WireError::Decode(DecodeError::LimitExceeded))
            ));
        }

        let mut hostile_count = encoded;
        hostile_count[offsets.method_count..offsets.method_count + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            ActorIntrospectionArtifact::decode(&hostile_count),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        ));

        let oversized = alloc::vec![0; MAX_ACTOR_INTROSPECTION_ENCODED_BYTES + 1];
        assert_eq!(
            ActorIntrospectionArtifact::decode(&oversized),
            Err(WireError::LimitExceeded)
        );

        let (mut aggregate, _, _) = sample();
        aggregate.methods = (0..MAX_INTROSPECTION_METHODS)
            .map(|index| ActorMethodIntrospection {
                name: alloc::format!("{index:03}"),
                doc: "d".repeat(MAX_METHOD_DOCUMENTATION_BYTES),
                cli_exposure: CliExposure::Hidden,
                timeout_ms: 0,
                dispatch: MethodDispatch::Sync,
            })
            .collect();
        assert_eq!(aggregate.validate(), Err(IntrospectionError::LimitExceeded));
        assert_eq!(aggregate.encode(), Err(WireError::InvalidValue));
    }

    #[test]
    fn invalid_references_and_individual_strings_fail_closed() {
        let (mut artifact, _, _) = sample();
        artifact.actor_schema.hash = Hash::ZERO;
        assert_eq!(
            artifact.validate(),
            Err(IntrospectionError::InvalidArtifact)
        );

        let (mut artifact, _, _) = sample();
        artifact.method_policy.len = 0;
        assert_eq!(
            artifact.validate(),
            Err(IntrospectionError::InvalidArtifact)
        );

        let (mut artifact, _, _) = sample();
        artifact.actor_schema.len = crate::schema::MAX_ENCODED_BYTES as u64 + 1;
        assert_eq!(
            artifact.validate(),
            Err(IntrospectionError::InvalidArtifact)
        );

        let (mut artifact, _, _) = sample();
        artifact.method_policy.len = MAX_METHOD_POLICY_ENCODED_BYTES as u64 + 1;
        assert_eq!(
            artifact.validate(),
            Err(IntrospectionError::InvalidArtifact)
        );

        let (mut artifact, _, _) = sample();
        artifact.actor_doc = "a".repeat(MAX_ACTOR_DOCUMENTATION_BYTES + 1);
        assert_eq!(artifact.validate(), Err(IntrospectionError::LimitExceeded));

        let (mut artifact, _, _) = sample();
        artifact.methods[0].name.clear();
        assert_eq!(artifact.validate(), Err(IntrospectionError::InvalidMethod));

        let (mut artifact, _, _) = sample();
        artifact.methods[0].doc = "d".repeat(MAX_METHOD_DOCUMENTATION_BYTES + 1);
        assert_eq!(artifact.validate(), Err(IntrospectionError::LimitExceeded));
    }
}
