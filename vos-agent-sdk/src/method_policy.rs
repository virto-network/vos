//! Canonical per-method execution and authorization policy for AgentActors.
//!
//! The AAS1 actor schema owns state layout and the declaration-ordered method
//! names/modes. This artifact binds that exact schema by content reference and
//! adds the method contract which an agent runtime enforces before dispatch.
//! Entries are name-ordered for deterministic lookup; validation requires the
//! same complete name/mode set as the referenced AAS1 schema.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::schema::{self, ParsedSchema};
use crate::wire::{CanonicalWire, WireError};
use crate::{BlobRef, Hash, MethodMode};

/// The only accepted clean-generation method-policy wire magic.
pub const METHOD_POLICY_MAGIC: [u8; 4] = *b"AMP1";
pub const MAX_METHOD_POLICIES: usize = schema::MAX_METHODS;
pub const MAX_METHOD_POLICY_NAME_BYTES: usize = schema::MAX_NAME_BYTES;
/// Matches the runtime's separately bounded deployment-artifact window.
pub const MAX_METHOD_POLICY_ENCODED_BYTES: usize = crate::MAX_RUNTIME_EXECUTION_ARTIFACT_BYTES;

/// Whether ingress must provide a stable idempotency identity for this
/// method. There is deliberately no optional state without executor meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IdempotencyRequirement {
    NotRequired = 0,
    Required = 1,
}

impl IdempotencyRequirement {
    pub const fn for_mode(mode: MethodMode) -> Self {
        match mode {
            MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::LocalQuery => {
                Self::NotRequired
            }
            MethodMode::Linear | MethodMode::Merge | MethodMode::Local => Self::Required,
        }
    }

    pub const fn is_valid_for(self, mode: MethodMode) -> bool {
        matches!(
            (self, Self::for_mode(mode)),
            (Self::NotRequired, Self::NotRequired) | (Self::Required, Self::Required)
        )
    }
}

/// Proof-bearing attestation required before a transition may be committed.
/// The proof-system identity is matched to
/// [`crate::proof::TransitionProofStatement::proof_system`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationRequirement {
    None,
    Required { proof_system: Hash },
}

impl AttestationRequirement {
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required { .. })
    }

    const fn is_valid(self) -> bool {
        match self {
            Self::None => true,
            Self::Required { proof_system } => !hash_is_zero(proof_system),
        }
    }
}

/// Complete signed contract for one actor method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorMethodPolicy {
    pub name: String,
    pub mode: MethodMode,
    /// Identity of the canonical complete argument schema.
    pub argument_schema: Hash,
    /// Identity of the canonical return schema.
    pub return_schema: Hash,
    /// Exact policy expected in an invocation authority selector.
    pub authorization_policy: Hash,
    pub idempotency: IdempotencyRequirement,
    pub attestation: AttestationRequirement,
}

impl ActorMethodPolicy {
    pub fn validate(&self) -> bool {
        !self.name.is_empty()
            && self.name.len() <= MAX_METHOD_POLICY_NAME_BYTES
            && self.argument_schema != Hash::ZERO
            && self.return_schema != Hash::ZERO
            && self.authorization_policy != Hash::ZERO
            && self.idempotency.is_valid_for(self.mode)
            && self.attestation.is_valid()
    }
}

/// Exact method-policy artifact named by an Actor package manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorMethodPolicyArtifact {
    /// Exact AAS1 preimage whose method surface this artifact completes.
    pub actor_schema: BlobRef,
    /// Strict UTF-8 byte/name order, with no duplicate names.
    pub methods: Vec<ActorMethodPolicy>,
}

impl ActorMethodPolicyArtifact {
    pub fn validate(&self) -> Result<(), MethodPolicyError> {
        if self.actor_schema.hash == Hash::ZERO
            || self.actor_schema.len == 0
            || self.actor_schema.len > schema::MAX_ENCODED_BYTES as u64
            || self.methods.is_empty()
        {
            return Err(MethodPolicyError::InvalidArtifact);
        }
        if self.methods.len() > MAX_METHOD_POLICIES {
            return Err(MethodPolicyError::LimitExceeded);
        }
        if self.methods.iter().any(|method| !method.validate()) {
            return Err(MethodPolicyError::InvalidMethod);
        }
        if self
            .methods
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(MethodPolicyError::MethodOrder);
        }
        if self
            .encoded_len()
            .is_none_or(|length| length > MAX_METHOD_POLICY_ENCODED_BYTES)
        {
            return Err(MethodPolicyError::LimitExceeded);
        }
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        let mut length = 4usize
            .checked_add(crate::RUNTIME_ABI_ID.0.len())?
            .checked_add(32 + 8 + 4)?;
        for method in &self.methods {
            // name framing, mode, three identities, idempotency and
            // attestation tag; a required attestation adds its proof system.
            let fixed = 4usize + 1 + 3 * 32 + 1 + 1;
            length = length.checked_add(fixed)?.checked_add(method.name.len())?;
            if method.attestation.is_required() {
                length = length.checked_add(32)?;
            }
        }
        Some(length)
    }

    pub fn method(&self, name: &str) -> Option<&ActorMethodPolicy> {
        self.methods
            .binary_search_by(|method| method.name.as_str().cmp(name))
            .ok()
            .and_then(|position| self.methods.get(position))
    }

    pub fn requires_attestation(&self) -> bool {
        self.methods
            .iter()
            .any(|method| method.attestation.is_required())
    }

    /// Require this policy to describe exactly the same method names and
    /// modes as a validated AAS1 schema. AAS1 source order and the policy's
    /// name order are intentionally independent canonical projections.
    pub fn validate_against_schema(
        &self,
        actor_schema: &ParsedSchema,
    ) -> Result<(), MethodPolicyError> {
        self.validate()?;
        actor_schema
            .validate()
            .map_err(|_| MethodPolicyError::InvalidSchema)?;
        if self.methods.len() != actor_schema.methods.len() {
            return Err(MethodPolicyError::SchemaMismatch);
        }
        for schema_method in &actor_schema.methods {
            let policy = self
                .method(&schema_method.name)
                .ok_or(MethodPolicyError::SchemaMismatch)?;
            if policy.mode != schema_method.mode {
                return Err(MethodPolicyError::SchemaMismatch);
            }
        }
        Ok(())
    }

    /// Authenticate and decode the exact referenced AAS1 bytes before
    /// comparing its complete method surface.
    pub fn validate_against_schema_bytes(
        &self,
        actor_schema: &[u8],
    ) -> Result<(), MethodPolicyError> {
        if !self.actor_schema.matches(actor_schema) {
            return Err(MethodPolicyError::SchemaMismatch);
        }
        let parsed = schema::decode(actor_schema).map_err(|_| MethodPolicyError::InvalidSchema)?;
        self.validate_against_schema(&parsed)
    }

    /// Content identity inserted into an Actor package's exact closure.
    pub fn artifact_ref(&self) -> Result<BlobRef, WireError> {
        Ok(BlobRef::of_bytes(&self.encode()?))
    }
}

impl CanonicalWire for ActorMethodPolicyArtifact {
    const MAGIC: [u8; 4] = METHOD_POLICY_MAGIC;
    const MAX_ENCODED_BYTES: usize = MAX_METHOD_POLICY_ENCODED_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate().is_ok()
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_blob(encoder, &self.actor_schema);
        encoder.list(&self.methods, encode_method);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = Self {
            actor_schema: decode_blob(decoder)?,
            methods: decoder.list_bounded(MAX_METHOD_POLICIES, decode_method)?,
        };
        value.validate().map_err(|error| match error {
            MethodPolicyError::LimitExceeded => DecodeError::LimitExceeded,
            MethodPolicyError::MethodOrder => DecodeError::NonCanonical,
            _ => DecodeError::NonCanonical,
        })?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodPolicyError {
    InvalidArtifact,
    InvalidMethod,
    MethodOrder,
    InvalidSchema,
    SchemaMismatch,
    LimitExceeded,
}

impl fmt::Display for MethodPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact => formatter.write_str("invalid actor method-policy artifact"),
            Self::InvalidMethod => formatter.write_str("invalid actor method policy"),
            Self::MethodOrder => formatter.write_str("noncanonical actor method-policy order"),
            Self::InvalidSchema => formatter.write_str("invalid referenced AgentActor schema"),
            Self::SchemaMismatch => {
                formatter.write_str("method policy does not match AgentActor schema")
            }
            Self::LimitExceeded => formatter.write_str("actor method-policy limit exceeded"),
        }
    }
}

impl core::error::Error for MethodPolicyError {}

const fn hash_is_zero(value: Hash) -> bool {
    let mut index = 0usize;
    while index < value.0.len() {
        if value.0[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
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

fn encode_method(encoder: &mut Encoder<'_>, method: &ActorMethodPolicy) {
    encoder.string(&method.name);
    encoder.u8(method.mode as u8);
    encoder.fixed(method.argument_schema.as_bytes());
    encoder.fixed(method.return_schema.as_bytes());
    encoder.fixed(method.authorization_policy.as_bytes());
    encoder.u8(method.idempotency as u8);
    match method.attestation {
        AttestationRequirement::None => encoder.u8(0),
        AttestationRequirement::Required { proof_system } => {
            encoder.u8(1);
            encoder.fixed(proof_system.as_bytes());
        }
    }
}

fn decode_method(decoder: &mut Decoder<'_>) -> Result<ActorMethodPolicy, DecodeError> {
    Ok(ActorMethodPolicy {
        name: decoder.string_bounded(MAX_METHOD_POLICY_NAME_BYTES)?,
        mode: decode_mode(decoder.u8()?)?,
        argument_schema: Hash(decoder.fixed()?),
        return_schema: Hash(decoder.fixed()?),
        authorization_policy: Hash(decoder.fixed()?),
        idempotency: match decoder.u8()? {
            0 => IdempotencyRequirement::NotRequired,
            1 => IdempotencyRequirement::Required,
            _ => return Err(DecodeError::InvalidTag),
        },
        attestation: match decoder.u8()? {
            0 => AttestationRequirement::None,
            1 => AttestationRequirement::Required {
                proof_system: Hash(decoder.fixed()?),
            },
            _ => return Err(DecodeError::InvalidTag),
        },
    })
}

fn decode_mode(value: u8) -> Result<MethodMode, DecodeError> {
    match value {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::LocalQuery),
        3 => Ok(MethodMode::Linear),
        4 => Ok(MethodMode::Merge),
        5 => Ok(MethodMode::Local),
        _ => Err(DecodeError::InvalidTag),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ParsedMethod, ParsedSchema};

    fn schema() -> (ParsedSchema, Vec<u8>) {
        let parsed = ParsedSchema {
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
        };
        let bytes = parsed.encode().unwrap();
        (parsed, bytes)
    }

    fn method(name: &str, mode: MethodMode, seed: u8) -> ActorMethodPolicy {
        ActorMethodPolicy {
            name: name.into(),
            mode,
            argument_schema: Hash([seed; 32]),
            return_schema: Hash([seed.wrapping_add(1); 32]),
            authorization_policy: Hash([seed.wrapping_add(2); 32]),
            idempotency: IdempotencyRequirement::for_mode(mode),
            attestation: AttestationRequirement::None,
        }
    }

    fn policy_artifact() -> (ActorMethodPolicyArtifact, Vec<u8>) {
        let (_, schema) = schema();
        (
            ActorMethodPolicyArtifact {
                actor_schema: BlobRef::of_bytes(&schema),
                methods: alloc::vec![
                    method("read", MethodMode::Query, 1),
                    method("write", MethodMode::Merge, 4),
                ],
            },
            schema,
        )
    }

    fn encode_unchecked(artifact: &ActorMethodPolicyArtifact) -> Vec<u8> {
        let mut bytes = METHOD_POLICY_MAGIC.to_vec();
        bytes.extend_from_slice(crate::RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(&mut bytes);
        encode_blob(&mut encoder, &artifact.actor_schema);
        encoder.list(&artifact.methods, encode_method);
        bytes
    }

    #[test]
    fn canonical_round_trip_lookup_and_schema_cross_binding() {
        let (artifact, schema_bytes) = policy_artifact();
        artifact
            .validate_against_schema_bytes(&schema_bytes)
            .unwrap();
        let encoded = artifact.encode().unwrap();
        assert_eq!(artifact.encoded_len(), Some(encoded.len()));
        assert_eq!(
            ActorMethodPolicyArtifact::decode(&encoded).unwrap(),
            artifact
        );
        assert_eq!(
            artifact.artifact_ref().unwrap(),
            BlobRef::of_bytes(&encoded)
        );
        assert_eq!(artifact.method("read").unwrap().mode, MethodMode::Query);
        assert!(artifact.method("missing").is_none());
        assert!(!artifact.requires_attestation());
    }

    #[test]
    fn idempotency_is_fixed_by_method_mode() {
        for mode in [
            MethodMode::Query,
            MethodMode::LinearizableQuery,
            MethodMode::LocalQuery,
        ] {
            assert_eq!(
                IdempotencyRequirement::for_mode(mode),
                IdempotencyRequirement::NotRequired
            );
        }
        for mode in [MethodMode::Linear, MethodMode::Merge, MethodMode::Local] {
            assert_eq!(
                IdempotencyRequirement::for_mode(mode),
                IdempotencyRequirement::Required
            );
        }
        let (mut artifact, _) = policy_artifact();
        artifact.methods[0].idempotency = IdempotencyRequirement::Required;
        assert_eq!(artifact.validate(), Err(MethodPolicyError::InvalidMethod));
        artifact.methods[0].idempotency = IdempotencyRequirement::NotRequired;
        artifact.methods[1].idempotency = IdempotencyRequirement::NotRequired;
        assert_eq!(artifact.validate(), Err(MethodPolicyError::InvalidMethod));
    }

    #[test]
    fn attestation_requires_an_exact_nonzero_proof_system() {
        let (mut artifact, _) = policy_artifact();
        artifact.methods[1].attestation = AttestationRequirement::Required {
            proof_system: Hash([9; 32]),
        };
        assert!(artifact.validate().is_ok());
        assert!(artifact.requires_attestation());
        artifact.methods[1].attestation = AttestationRequirement::Required {
            proof_system: Hash::ZERO,
        };
        assert_eq!(artifact.validate(), Err(MethodPolicyError::InvalidMethod));
    }

    #[test]
    fn duplicate_order_and_schema_substitution_fail_closed() {
        let (mut unsorted, schema_bytes) = policy_artifact();
        unsorted.methods.swap(0, 1);
        assert_eq!(unsorted.validate(), Err(MethodPolicyError::MethodOrder));
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&encode_unchecked(&unsorted)),
            Err(WireError::Decode(DecodeError::NonCanonical))
        ));

        let (mut duplicate, _) = policy_artifact();
        duplicate.methods[1].name = duplicate.methods[0].name.clone();
        assert_eq!(duplicate.validate(), Err(MethodPolicyError::MethodOrder));
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&encode_unchecked(&duplicate)),
            Err(WireError::Decode(DecodeError::NonCanonical))
        ));

        let (mut artifact, _) = policy_artifact();
        artifact.actor_schema.hash.0[0] ^= 1;
        assert_eq!(
            artifact.validate_against_schema_bytes(&schema_bytes),
            Err(MethodPolicyError::SchemaMismatch)
        );

        let (mut artifact, _) = policy_artifact();
        artifact.methods[1].mode = MethodMode::Linear;
        artifact.methods[1].idempotency = IdempotencyRequirement::Required;
        let parsed = schema::decode(&schema_bytes).unwrap();
        assert_eq!(
            artifact.validate_against_schema(&parsed),
            Err(MethodPolicyError::SchemaMismatch)
        );
    }

    #[test]
    fn decoder_rejects_unknown_tags_trailing_and_hostile_bounds() {
        let (artifact, _) = policy_artifact();
        let encoded = artifact.encode().unwrap();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        ));

        let name_position = 4 + crate::RUNTIME_ABI_ID.0.len() + 32 + 8 + 4;
        let mode_position = name_position + 4 + artifact.methods[0].name.len();
        let idempotency_position = mode_position + 1 + 32 * 3;
        let attestation_position = idempotency_position + 1;
        for position in [mode_position, idempotency_position, attestation_position] {
            let mut unknown = encoded.clone();
            unknown[position] = 0xff;
            assert!(matches!(
                ActorMethodPolicyArtifact::decode(&unknown),
                Err(WireError::Decode(DecodeError::InvalidTag))
            ));
        }

        let count_position = 4 + crate::RUNTIME_ABI_ID.0.len() + 32 + 8;
        let mut hostile_count = encoded.clone();
        hostile_count[count_position..count_position + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&hostile_count),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        ));

        let mut hostile_name = encoded;
        hostile_name[name_position..name_position + 4]
            .copy_from_slice(&((MAX_METHOD_POLICY_NAME_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&hostile_name),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        ));

        let oversized = alloc::vec![0; MAX_METHOD_POLICY_ENCODED_BYTES + 1];
        assert_eq!(
            ActorMethodPolicyArtifact::decode(&oversized),
            Err(WireError::LimitExceeded)
        );

        let (_, schema_bytes) = policy_artifact();
        let mut aggregate = ActorMethodPolicyArtifact {
            actor_schema: BlobRef::of_bytes(&schema_bytes),
            methods: (0..MAX_METHOD_POLICIES)
                .map(|index| {
                    let name = alloc::format!("{index:03}-{}", "x".repeat(124));
                    let mut method = method(&name, MethodMode::Query, 21);
                    method.attestation = AttestationRequirement::Required {
                        proof_system: Hash([22; 32]),
                    };
                    method
                })
                .collect(),
        };
        aggregate
            .methods
            .sort_by(|left, right| left.name.cmp(&right.name));
        assert_eq!(aggregate.validate(), Err(MethodPolicyError::LimitExceeded));
    }

    #[test]
    fn zero_identities_and_previous_generation_magic_are_rejected() {
        let (mut artifact, _) = policy_artifact();
        artifact.methods[0].authorization_policy = Hash::ZERO;
        assert_eq!(artifact.validate(), Err(MethodPolicyError::InvalidMethod));

        let (artifact, _) = policy_artifact();
        let mut old = artifact.encode().unwrap();
        old[..4].copy_from_slice(b"VRPW");
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&old),
            Err(WireError::Decode(DecodeError::InvalidTag))
        ));
    }
}
