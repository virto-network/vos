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
use crate::{BlobRef, CapabilityId, Hash, MethodMode, RoleId};

/// The only accepted clean-generation method-policy wire magic.
pub const METHOD_POLICY_MAGIC: [u8; 4] = *b"AMP2";
pub const MAX_METHOD_POLICIES: usize = schema::MAX_METHODS;
pub const MAX_METHOD_POLICY_NAME_BYTES: usize = schema::MAX_NAME_BYTES;
pub const MAX_METHOD_ARGUMENTS: usize = schema::MAX_FIELDS;
pub const MAX_METHOD_ARGUMENT_NAME_BYTES: usize = schema::MAX_NAME_BYTES;
pub const MAX_METHOD_TYPE_IDENTITY_BYTES: usize = schema::MAX_TYPE_IDENTITY_BYTES;
/// Matches the runtime's separately bounded deployment-artifact window.
pub const MAX_METHOD_POLICY_ENCODED_BYTES: usize = crate::MAX_RUNTIME_EXECUTION_ARTIFACT_BYTES;

/// Domain for a method's declaration-ordered argument-schema identity.
pub const ARGUMENT_SCHEMA_ID_DOMAIN: &[u8] = b"vos/agent/method-arguments-schema/v1";
/// Domain for a method's return-schema identity.
pub const RETURN_SCHEMA_ID_DOMAIN: &[u8] = b"vos/agent/method-return-schema/v1";
/// Domain for the exact typed authorization selector enforced at ingress.
pub const AUTHORIZATION_POLICY_ID_DOMAIN: &[u8] = b"vos/agent/method-authorization-policy/v2";

/// One authorization predicate for a method.
///
/// The variants are deliberately exclusive. A policy cannot smuggle a legacy
/// conjunction of partially populated role/capability fields into the clean
/// generation, and a runtime can inspect the exact predicate without an
/// out-of-band hash preimage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationPolicySelector {
    Public,
    SpaceRole(RoleId),
    ActorRole(RoleId),
    Capability(CapabilityId),
}

impl AuthorizationPolicySelector {
    pub const fn validate(self) -> bool {
        match self {
            Self::Public => true,
            Self::SpaceRole(role) | Self::ActorRole(role) => !role_is_zero(role),
            Self::Capability(capability) => !capability_is_zero(capability),
        }
    }

    /// Stable identity of this exact selector.
    ///
    /// The typed tag and optional identifier are committed together with the
    /// runtime ABI identity. Invalid zero identifiers and the unusable zero
    /// digest are never returned as policy identities.
    pub fn identity(self) -> Result<Hash, MethodPolicyError> {
        if !self.validate() {
            return Err(MethodPolicyError::InvalidAuthorizationPolicy);
        }
        let tag = [self.wire_tag()];
        let identity = match self {
            Self::Public => Hash::digest(
                AUTHORIZATION_POLICY_ID_DOMAIN,
                &[crate::RUNTIME_ABI_ID.as_bytes(), &tag],
            ),
            Self::SpaceRole(role) | Self::ActorRole(role) => Hash::digest(
                AUTHORIZATION_POLICY_ID_DOMAIN,
                &[crate::RUNTIME_ABI_ID.as_bytes(), &tag, role.as_bytes()],
            ),
            Self::Capability(capability) => Hash::digest(
                AUTHORIZATION_POLICY_ID_DOMAIN,
                &[
                    crate::RUNTIME_ABI_ID.as_bytes(),
                    &tag,
                    capability.as_bytes(),
                ],
            ),
        };
        if hash_is_zero(identity) {
            Err(MethodPolicyError::InvalidAuthorizationPolicy)
        } else {
            Ok(identity)
        }
    }

    const fn wire_tag(self) -> u8 {
        match self {
            Self::Public => 0,
            Self::SpaceRole(_) => 1,
            Self::ActorRole(_) => 2,
            Self::Capability(_) => 3,
        }
    }

    const fn encoded_len(self) -> usize {
        match self {
            Self::Public => 1,
            Self::SpaceRole(_) | Self::ActorRole(_) | Self::Capability(_) => 1 + 32,
        }
    }
}

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

/// One named argument in exact source declaration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodArgument {
    pub name: String,
    /// Exact producer-supplied type identity exposed to call encoders.
    pub type_identity: String,
}

impl MethodArgument {
    pub fn validate(&self) -> bool {
        valid_argument_name(&self.name) && valid_type_identity(&self.type_identity)
    }
}

/// Derive the stable identity of a declaration-ordered argument schema.
///
/// The preimage is a canonical list of length-framed argument names and type
/// identities. Argument order is significant; names must be unique.
pub fn argument_schema_id(arguments: &[MethodArgument]) -> Result<Hash, MethodPolicyError> {
    validate_arguments(arguments)?;
    let mut preimage = Vec::new();
    let capacity = arguments_encoded_len(arguments).ok_or(MethodPolicyError::LimitExceeded)?;
    preimage
        .try_reserve_exact(capacity)
        .map_err(|_| MethodPolicyError::LimitExceeded)?;
    Encoder(&mut preimage).list(arguments, encode_argument);
    debug_assert_eq!(preimage.len(), capacity);
    Ok(Hash::digest(
        ARGUMENT_SCHEMA_ID_DOMAIN,
        &[crate::RUNTIME_ABI_ID.as_bytes(), &preimage],
    ))
}

/// Derive the stable identity of one exact return type.
pub fn return_schema_id(return_type_identity: &str) -> Result<Hash, MethodPolicyError> {
    if !valid_type_identity(return_type_identity) {
        return Err(MethodPolicyError::InvalidMethodAbi);
    }
    let capacity = 4usize
        .checked_add(return_type_identity.len())
        .ok_or(MethodPolicyError::LimitExceeded)?;
    let mut preimage = Vec::new();
    preimage
        .try_reserve_exact(capacity)
        .map_err(|_| MethodPolicyError::LimitExceeded)?;
    Encoder(&mut preimage).string(return_type_identity);
    debug_assert_eq!(preimage.len(), capacity);
    Ok(Hash::digest(
        RETURN_SCHEMA_ID_DOMAIN,
        &[crate::RUNTIME_ABI_ID.as_bytes(), &preimage],
    ))
}

/// Complete signed contract for one actor method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorMethodPolicy {
    pub name: String,
    pub mode: MethodMode,
    /// Canonical complete argument-schema preimage, in declaration order.
    pub arguments: Vec<MethodArgument>,
    /// Canonical return-schema preimage.
    pub return_type_identity: String,
    /// Exact typed policy expected in an invocation authority selector.
    pub authorization_policy: AuthorizationPolicySelector,
    pub idempotency: IdempotencyRequirement,
    pub attestation: AttestationRequirement,
}

impl ActorMethodPolicy {
    pub fn validate(&self) -> Result<(), MethodPolicyError> {
        if self.name.is_empty()
            || self.name.len() > MAX_METHOD_POLICY_NAME_BYTES
            || !self.idempotency.is_valid_for(self.mode)
            || !self.attestation.is_valid()
        {
            return Err(MethodPolicyError::InvalidMethod);
        }
        if self.authorization_policy.identity().is_err() {
            return Err(MethodPolicyError::InvalidAuthorizationPolicy);
        }
        validate_arguments(&self.arguments)?;
        if !valid_type_identity(&self.return_type_identity) {
            return Err(MethodPolicyError::InvalidMethodAbi);
        }
        Ok(())
    }

    pub fn argument_schema_id(&self) -> Result<Hash, MethodPolicyError> {
        argument_schema_id(&self.arguments)
    }

    pub fn return_schema_id(&self) -> Result<Hash, MethodPolicyError> {
        return_schema_id(&self.return_type_identity)
    }

    pub fn authorization_policy_id(&self) -> Result<Hash, MethodPolicyError> {
        self.authorization_policy.identity()
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
        {
            return Err(MethodPolicyError::InvalidArtifact);
        }
        if self.methods.len() > MAX_METHOD_POLICIES {
            return Err(MethodPolicyError::LimitExceeded);
        }
        for method in &self.methods {
            method.validate()?;
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
            // Method name framing, mode, argument-list framing, return-type
            // framing, idempotency, and attestation tag. The typed
            // authorization encoding is added separately; non-public
            // authorization and required attestation each add an exact
            // 32-byte identity.
            let fixed = 4usize + 1 + 4 + 4 + 1 + 1;
            length = length
                .checked_add(fixed)?
                .checked_add(method.name.len())?
                .checked_add(method.return_type_identity.len())?
                .checked_add(method.authorization_policy.encoded_len())?
                .checked_add(arguments_encoded_len(&method.arguments)?.checked_sub(4)?)?;
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
    InvalidMethodAbi,
    InvalidAuthorizationPolicy,
    DuplicateArgument,
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
            Self::InvalidMethodAbi => formatter.write_str("invalid actor method ABI metadata"),
            Self::InvalidAuthorizationPolicy => {
                formatter.write_str("invalid actor method authorization policy")
            }
            Self::DuplicateArgument => formatter.write_str("duplicate actor method argument name"),
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

const fn role_is_zero(value: RoleId) -> bool {
    hash_is_zero(Hash(value.0))
}

const fn capability_is_zero(value: CapabilityId) -> bool {
    hash_is_zero(Hash(value.0))
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

fn valid_argument_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_METHOD_ARGUMENT_NAME_BYTES
}

fn valid_type_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_METHOD_TYPE_IDENTITY_BYTES
}

fn validate_arguments(arguments: &[MethodArgument]) -> Result<(), MethodPolicyError> {
    if arguments.len() > MAX_METHOD_ARGUMENTS {
        return Err(MethodPolicyError::LimitExceeded);
    }
    for (index, argument) in arguments.iter().enumerate() {
        if !argument.validate() {
            return Err(MethodPolicyError::InvalidMethodAbi);
        }
        if arguments[..index]
            .iter()
            .any(|previous| previous.name == argument.name)
        {
            return Err(MethodPolicyError::DuplicateArgument);
        }
    }
    Ok(())
}

fn arguments_encoded_len(arguments: &[MethodArgument]) -> Option<usize> {
    let mut length = 4usize;
    for argument in arguments {
        length = length
            .checked_add(4)?
            .checked_add(argument.name.len())?
            .checked_add(4)?
            .checked_add(argument.type_identity.len())?;
    }
    Some(length)
}

fn encode_argument(encoder: &mut Encoder<'_>, argument: &MethodArgument) {
    encoder.string(&argument.name);
    encoder.string(&argument.type_identity);
}

fn decode_argument(decoder: &mut Decoder<'_>) -> Result<MethodArgument, DecodeError> {
    Ok(MethodArgument {
        name: decoder.string_bounded(MAX_METHOD_ARGUMENT_NAME_BYTES)?,
        type_identity: decoder.string_bounded(MAX_METHOD_TYPE_IDENTITY_BYTES)?,
    })
}

fn encode_method(encoder: &mut Encoder<'_>, method: &ActorMethodPolicy) {
    encoder.string(&method.name);
    encoder.u8(method.mode as u8);
    encoder.list(&method.arguments, encode_argument);
    encoder.string(&method.return_type_identity);
    encode_authorization_policy(encoder, method.authorization_policy);
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
        arguments: decoder.list_bounded(MAX_METHOD_ARGUMENTS, decode_argument)?,
        return_type_identity: decoder.string_bounded(MAX_METHOD_TYPE_IDENTITY_BYTES)?,
        authorization_policy: decode_authorization_policy(decoder)?,
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

fn encode_authorization_policy(
    encoder: &mut Encoder<'_>,
    authorization: AuthorizationPolicySelector,
) {
    encoder.u8(authorization.wire_tag());
    match authorization {
        AuthorizationPolicySelector::Public => {}
        AuthorizationPolicySelector::SpaceRole(role)
        | AuthorizationPolicySelector::ActorRole(role) => encoder.fixed(role.as_bytes()),
        AuthorizationPolicySelector::Capability(capability) => encoder.fixed(capability.as_bytes()),
    }
}

fn decode_authorization_policy(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorizationPolicySelector, DecodeError> {
    match decoder.u8()? {
        0 => Ok(AuthorizationPolicySelector::Public),
        1 => Ok(AuthorizationPolicySelector::SpaceRole(RoleId(
            decoder.fixed()?,
        ))),
        2 => Ok(AuthorizationPolicySelector::ActorRole(RoleId(
            decoder.fixed()?,
        ))),
        3 => Ok(AuthorizationPolicySelector::Capability(CapabilityId(
            decoder.fixed()?,
        ))),
        _ => Err(DecodeError::InvalidTag),
    }
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
            arguments: alloc::vec![MethodArgument {
                name: "request".into(),
                type_identity: alloc::format!("example::Request{seed}"),
            }],
            return_type_identity: alloc::format!("example::Response{seed}"),
            authorization_policy: AuthorizationPolicySelector::Capability(CapabilityId(
                [seed.wrapping_add(2); 32],
            )),
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

    struct FirstMethodOffsets {
        method_name_length: usize,
        mode: usize,
        argument_count: usize,
        argument_name_length: usize,
        argument_type_length: usize,
        return_type_length: usize,
        authorization: usize,
        idempotency: usize,
        attestation: usize,
    }

    fn first_method_offsets(artifact: &ActorMethodPolicyArtifact) -> FirstMethodOffsets {
        let method = &artifact.methods[0];
        assert_eq!(method.arguments.len(), 1);
        let argument = &method.arguments[0];
        let method_name_length = 4 + crate::RUNTIME_ABI_ID.0.len() + 32 + 8 + 4;
        let mode = method_name_length + 4 + method.name.len();
        let argument_count = mode + 1;
        let argument_name_length = argument_count + 4;
        let argument_type_length = argument_name_length + 4 + argument.name.len();
        let return_type_length = argument_type_length + 4 + argument.type_identity.len();
        let authorization = return_type_length + 4 + method.return_type_identity.len();
        let idempotency = authorization + method.authorization_policy.encoded_len();
        FirstMethodOffsets {
            method_name_length,
            mode,
            argument_count,
            argument_name_length,
            argument_type_length,
            return_type_length,
            authorization,
            idempotency,
            attestation: idempotency + 1,
        }
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
    fn empty_policy_is_canonical_only_for_an_empty_referenced_schema() {
        let empty_schema = ParsedSchema {
            fields: Vec::new(),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let artifact = ActorMethodPolicyArtifact {
            actor_schema: BlobRef::of_bytes(&empty_schema),
            methods: Vec::new(),
        };
        artifact
            .validate_against_schema_bytes(&empty_schema)
            .unwrap();
        let encoded = artifact.encode().unwrap();
        assert_eq!(artifact.encoded_len(), Some(encoded.len()));
        assert_eq!(
            ActorMethodPolicyArtifact::decode(&encoded).unwrap(),
            artifact
        );

        let (_, nonempty_schema) = schema();
        let mismatched = ActorMethodPolicyArtifact {
            actor_schema: BlobRef::of_bytes(&nonempty_schema),
            methods: Vec::new(),
        };
        assert!(mismatched.validate().is_ok());
        assert_eq!(
            mismatched.validate_against_schema_bytes(&nonempty_schema),
            Err(MethodPolicyError::SchemaMismatch)
        );
    }

    #[test]
    fn argument_and_return_schema_ids_commit_exact_canonical_preimages() {
        let mut arguments = alloc::vec![
            MethodArgument {
                name: "left".into(),
                type_identity: "example::Left".into(),
            },
            MethodArgument {
                name: "right".into(),
                type_identity: "example::Right".into(),
            },
        ];
        let original = argument_schema_id(&arguments).unwrap();
        let mut preimage = Vec::new();
        Encoder(&mut preimage).list(&arguments, encode_argument);
        assert_eq!(
            original,
            Hash::digest(
                ARGUMENT_SCHEMA_ID_DOMAIN,
                &[crate::RUNTIME_ABI_ID.as_bytes(), &preimage],
            )
        );

        arguments[0].name.push('2');
        assert_ne!(argument_schema_id(&arguments).unwrap(), original);
        arguments[0].name.pop();
        arguments[0].type_identity.push('2');
        assert_ne!(argument_schema_id(&arguments).unwrap(), original);
        arguments[0].type_identity.pop();
        arguments.swap(0, 1);
        assert_ne!(argument_schema_id(&arguments).unwrap(), original);

        let return_id = return_schema_id("example::Output").unwrap();
        assert_eq!(
            return_id,
            Hash::digest(
                RETURN_SCHEMA_ID_DOMAIN,
                &[
                    crate::RUNTIME_ABI_ID.as_bytes(),
                    &("example::Output".len() as u32).to_le_bytes(),
                    b"example::Output",
                ],
            )
        );
        assert_ne!(return_schema_id("example::Output2").unwrap(), return_id);

        let (artifact, _) = policy_artifact();
        assert_eq!(
            artifact.methods[0].argument_schema_id().unwrap(),
            argument_schema_id(&artifact.methods[0].arguments).unwrap()
        );
        assert_eq!(
            artifact.methods[0].return_schema_id().unwrap(),
            return_schema_id(&artifact.methods[0].return_type_identity).unwrap()
        );
    }

    #[test]
    fn typed_authorization_selectors_have_exact_nonzero_identities() {
        let selectors = [
            AuthorizationPolicySelector::Public,
            AuthorizationPolicySelector::SpaceRole(RoleId([3; 32])),
            AuthorizationPolicySelector::ActorRole(RoleId([3; 32])),
            AuthorizationPolicySelector::Capability(CapabilityId([3; 32])),
        ];
        let mut identities = Vec::new();
        for selector in selectors {
            assert!(selector.validate());
            let identity = selector.identity().unwrap();
            assert_ne!(identity, Hash::ZERO);
            identities.push(identity);

            let (mut artifact, _) = policy_artifact();
            artifact.methods[0].authorization_policy = selector;
            let encoded = artifact.encode().unwrap();
            assert_eq!(
                ActorMethodPolicyArtifact::decode(&encoded).unwrap(),
                artifact
            );
        }
        for (index, identity) in identities.iter().enumerate() {
            assert!(
                identities[index + 1..]
                    .iter()
                    .all(|other| other != identity)
            );
        }

        let role = RoleId([8; 32]);
        let expected = Hash::digest(
            AUTHORIZATION_POLICY_ID_DOMAIN,
            &[crate::RUNTIME_ABI_ID.as_bytes(), &[1], role.as_bytes()],
        );
        assert_eq!(
            AuthorizationPolicySelector::SpaceRole(role)
                .identity()
                .unwrap(),
            expected
        );

        let (artifact, _) = policy_artifact();
        assert_eq!(
            artifact.methods[0].authorization_policy_id().unwrap(),
            artifact.methods[0].authorization_policy.identity().unwrap()
        );
    }

    #[test]
    fn method_abi_requires_unique_bounded_names_and_types() {
        let (mut artifact, _) = policy_artifact();
        let duplicate = artifact.methods[0].arguments[0].clone();
        artifact.methods[0].arguments.push(duplicate);
        assert_eq!(
            artifact.methods[0].argument_schema_id(),
            Err(MethodPolicyError::DuplicateArgument)
        );
        assert_eq!(
            artifact.validate(),
            Err(MethodPolicyError::DuplicateArgument)
        );
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&encode_unchecked(&artifact)),
            Err(WireError::Decode(DecodeError::NonCanonical))
        ));

        let (mut artifact, _) = policy_artifact();
        artifact.methods[0].arguments[0].name.clear();
        assert_eq!(
            artifact.validate(),
            Err(MethodPolicyError::InvalidMethodAbi)
        );

        let (mut artifact, _) = policy_artifact();
        artifact.methods[0].arguments[0].type_identity.clear();
        assert_eq!(
            artifact.validate(),
            Err(MethodPolicyError::InvalidMethodAbi)
        );

        let (mut artifact, _) = policy_artifact();
        artifact.methods[0].return_type_identity.clear();
        assert_eq!(
            artifact.validate(),
            Err(MethodPolicyError::InvalidMethodAbi)
        );

        let (mut artifact, _) = policy_artifact();
        artifact.methods[0].arguments = (0..=MAX_METHOD_ARGUMENTS)
            .map(|index| MethodArgument {
                name: alloc::format!("arg{index}"),
                type_identity: "example::Argument".into(),
            })
            .collect();
        assert_eq!(artifact.validate(), Err(MethodPolicyError::LimitExceeded));
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&encode_unchecked(&artifact)),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        ));
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
        let offsets = first_method_offsets(&artifact);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        ));

        for position in [
            offsets.mode,
            offsets.authorization,
            offsets.idempotency,
            offsets.attestation,
        ] {
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

        let mut hostile_argument_count = encoded.clone();
        hostile_argument_count[offsets.argument_count..offsets.argument_count + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&hostile_argument_count),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        ));

        let mut hostile_name = encoded.clone();
        hostile_name[offsets.method_name_length..offsets.method_name_length + 4]
            .copy_from_slice(&((MAX_METHOD_POLICY_NAME_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&hostile_name),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        ));

        let mut hostile_argument_name = encoded.clone();
        hostile_argument_name[offsets.argument_name_length..offsets.argument_name_length + 4]
            .copy_from_slice(&((MAX_METHOD_ARGUMENT_NAME_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&hostile_argument_name),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        ));

        for position in [offsets.argument_type_length, offsets.return_type_length] {
            let mut hostile_type = encoded.clone();
            hostile_type[position..position + 4]
                .copy_from_slice(&((MAX_METHOD_TYPE_IDENTITY_BYTES + 1) as u32).to_le_bytes());
            assert!(matches!(
                ActorMethodPolicyArtifact::decode(&hostile_type),
                Err(WireError::Decode(DecodeError::LimitExceeded))
            ));
        }

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
                    method.arguments[0].type_identity =
                        alloc::format!("example::{}", "A".repeat(488));
                    method.return_type_identity = alloc::format!("example::{}", "R".repeat(488));
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
        for selector in [
            AuthorizationPolicySelector::SpaceRole(RoleId::ZERO),
            AuthorizationPolicySelector::ActorRole(RoleId::ZERO),
            AuthorizationPolicySelector::Capability(CapabilityId::ZERO),
        ] {
            assert_eq!(
                selector.identity(),
                Err(MethodPolicyError::InvalidAuthorizationPolicy)
            );
            let (mut artifact, _) = policy_artifact();
            artifact.methods[0].authorization_policy = selector;
            assert_eq!(
                artifact.validate(),
                Err(MethodPolicyError::InvalidAuthorizationPolicy)
            );
            assert!(matches!(
                ActorMethodPolicyArtifact::decode(&encode_unchecked(&artifact)),
                Err(WireError::Decode(DecodeError::NonCanonical))
            ));
        }

        let (artifact, _) = policy_artifact();
        let mut old = artifact.encode().unwrap();
        old[..4].copy_from_slice(b"AMP1");
        assert!(matches!(
            ActorMethodPolicyArtifact::decode(&old),
            Err(WireError::Decode(DecodeError::InvalidTag))
        ));
    }
}
