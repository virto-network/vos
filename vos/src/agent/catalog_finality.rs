//! Authority-finalized facts for exact catalog mutations.
//!
//! A Merge catalog must not reinterpret an old author signature against its
//! current role state. Instead, the authority finalizes exact canonical
//! mutation and result bytes under a historical committee. The resulting
//! receipt is immutable data: decoding proves canonical bounded shape, while
//! [`FinalizedCatalogMutationReceipt::verify`] requires the independently
//! authenticated committee which was live for the receipt's QC epoch.
//!
//! This module defines the clean-break v2 evidence protocol and its
//! non-circular head derivations. It does not authenticate credentials,
//! reserve operation IDs or global sequences, persist authority history, or
//! materialize catalog rows. Integration must perform those transitions and
//! exactly recompute every derivation before applying Merge state.

use alloc::vec::Vec;
use core::fmt;

use super::committee::{
    AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee, AuthorityCommitteeError,
    AuthorityQuorumCertificate, MAX_AUTHORITY_QC_WIRE_BYTES,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{CapabilityId, CredentialId, Hash, OperationId, PrincipalId, SpaceId};

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;
const CATALOG_MUTATION_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/catalog-mutation/v2";
const CATALOG_MUTATION_RESULT_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/catalog-mutation-result/v2";
const CATALOG_MUTATION_INTENT_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/catalog-mutation-intent/v2";
const RESULTING_CATALOG_HEAD_DOMAIN: &[u8] = b"vos/agent/resulting-catalog-head/v2";
const RESULTING_AUTHORITY_GENERATION_DOMAIN: &[u8] = b"vos/agent/resulting-authority-generation/v2";

/// Maximum exact mutation payload accepted by the finality protocol.
pub const MAX_CATALOG_MUTATION_PAYLOAD_BYTES: usize = 64 * 1024;
/// Maximum exact projection/result payload accepted by the finality protocol.
pub const MAX_CATALOG_MUTATION_PROJECTION_BYTES: usize = 64 * 1024;
/// Maximum mutation plus projection bytes in one finalized transition.
///
/// Each component independently admits 64 KiB, while their combined bound
/// keeps a complete fact and receipt within the surrounding journal limits.
pub const MAX_CATALOG_TRANSITION_DATA_BYTES: usize = 64 * 1024;
/// Exact wire size of one [`CatalogBinding`].
pub const CATALOG_BINDING_WIRE_BYTES: usize = SERVICE_WIRE_HEADER_BYTES + 3 * 32;
/// Maximum complete [`CatalogMutation`] wire.
pub const MAX_CATALOG_MUTATION_WIRE_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 1 + 4 + MAX_CATALOG_MUTATION_PAYLOAD_BYTES;
/// Maximum complete [`CatalogMutationResult`] wire.
pub const MAX_CATALOG_MUTATION_RESULT_WIRE_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 1 + 4 + MAX_CATALOG_MUTATION_PROJECTION_BYTES;
/// Maximum complete [`CatalogMutationIntent`] wire.
pub const MAX_CATALOG_MUTATION_INTENT_WIRE_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + CATALOG_BINDING_WIRE_BYTES
    + 6 * 32
    + 4
    + MAX_CATALOG_MUTATION_WIRE_BYTES;
/// Maximum complete finalized fact, including its exact intent and result.
pub const MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES: usize =
    // Fact header, two nested lengths, four hashes, and sequence.
    SERVICE_WIRE_HEADER_BYTES
        + 2 * 4
        + 4 * 32
        + 8
        // Intent header, nested lengths, binding, six selectors, mutation
        // header/tag/length, and result header/tag/length.
        + SERVICE_WIRE_HEADER_BYTES
        + 2 * 4
        + CATALOG_BINDING_WIRE_BYTES
        + 6 * 32
        + SERVICE_WIRE_HEADER_BYTES
        + 1
        + 4
        + SERVICE_WIRE_HEADER_BYTES
        + 1
        + 4
        + MAX_CATALOG_TRANSITION_DATA_BYTES;
/// Maximum complete finalized receipt, including its bounded authority QC.
pub const MAX_FINALIZED_CATALOG_MUTATION_RECEIPT_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES
    + 4
    + MAX_AUTHORITY_QC_WIRE_BYTES;

/// Genesis-scoped identity of one catalog and its external authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogBinding {
    space: SpaceId,
    catalog_binding: Hash,
    authority_binding: Hash,
}

impl CatalogBinding {
    pub fn new(
        space: SpaceId,
        catalog_binding: Hash,
        authority_binding: Hash,
    ) -> Result<Self, CatalogFinalityError> {
        let binding = Self {
            space,
            catalog_binding,
            authority_binding,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn catalog_binding(&self) -> Hash {
        self.catalog_binding
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub fn validate(&self) -> Result<(), CatalogFinalityError> {
        if self.space == SpaceId::ZERO
            || self.catalog_binding == Hash::ZERO
            || self.authority_binding == Hash::ZERO
        {
            return Err(CatalogFinalityError::InvalidBinding);
        }
        enforce_encoded_bound(self, CATALOG_BINDING_WIRE_BYTES)
    }
}

impl ServiceWire for CatalogBinding {
    const MAGIC: [u8; 4] = *b"CBN2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.catalog_binding.0);
        encoder.fixed(&self.authority_binding.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, CATALOG_BINDING_WIRE_BYTES)?;
        let binding = Self {
            space: SpaceId(decoder.fixed()?),
            catalog_binding: Hash(decoder.fixed()?),
            authority_binding: Hash(decoder.fixed()?),
        };
        binding.validate().map_err(map_decode_error)?;
        Ok(binding)
    }
}

/// Canonical semantic class of a catalog mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum CatalogMutationKind {
    PublishArtifact = 0,
    RetireArtifact = 1,
    PublishAgent = 2,
    RetireAgent = 3,
    ReserveActorInstall = 4,
    CompleteActorInstall = 5,
    AbortActorInstall = 6,
    ReserveActorUpgrade = 7,
    CompleteActorUpgrade = 8,
    AbortActorUpgrade = 9,
    ReserveActorRemoval = 10,
    CompleteActorRemoval = 11,
    AbortActorRemoval = 12,
    UpdateAgentAlias = 13,
    UpdateReplicaSet = 14,
    UpdateMetadata = 15,
    UpdateRemoteMapping = 16,
}

impl CatalogMutationKind {
    fn decode(tag: u8) -> Result<Self, DecodeError> {
        match tag {
            0 => Ok(Self::PublishArtifact),
            1 => Ok(Self::RetireArtifact),
            2 => Ok(Self::PublishAgent),
            3 => Ok(Self::RetireAgent),
            4 => Ok(Self::ReserveActorInstall),
            5 => Ok(Self::CompleteActorInstall),
            6 => Ok(Self::AbortActorInstall),
            7 => Ok(Self::ReserveActorUpgrade),
            8 => Ok(Self::CompleteActorUpgrade),
            9 => Ok(Self::AbortActorUpgrade),
            10 => Ok(Self::ReserveActorRemoval),
            11 => Ok(Self::CompleteActorRemoval),
            12 => Ok(Self::AbortActorRemoval),
            13 => Ok(Self::UpdateAgentAlias),
            14 => Ok(Self::UpdateReplicaSet),
            15 => Ok(Self::UpdateMetadata),
            16 => Ok(Self::UpdateRemoteMapping),
            _ => Err(DecodeError::InvalidTag),
        }
    }
}

/// Exact bounded bytes of one catalog mutation.
///
/// The payload is an opaque canonical octet string at this protocol layer.
/// Before admission, integration must decode it using the selected `kind`,
/// require exact decode/re-encode equality, and derive the required capability
/// from that semantic mutation. Finality then preserves those exact bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogMutation {
    kind: CatalogMutationKind,
    payload: Vec<u8>,
}

impl CatalogMutation {
    pub fn new(kind: CatalogMutationKind, payload: Vec<u8>) -> Result<Self, CatalogFinalityError> {
        let mutation = Self { kind, payload };
        mutation.validate()?;
        Ok(mutation)
    }

    pub const fn kind(&self) -> CatalogMutationKind {
        self.kind
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(CATALOG_MUTATION_COMMITMENT_DOMAIN, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), CatalogFinalityError> {
        if self.payload.is_empty() {
            return Err(CatalogFinalityError::InvalidMutation);
        }
        if self.payload.len() > MAX_CATALOG_MUTATION_PAYLOAD_BYTES {
            return Err(CatalogFinalityError::LimitExceeded);
        }
        enforce_encoded_bound(self, MAX_CATALOG_MUTATION_WIRE_BYTES)
    }
}

impl ServiceWire for CatalogMutation {
    const MAGIC: [u8; 4] = *b"CMU2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.u8(self.kind as u8);
        encoder.bytes(&self.payload);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_CATALOG_MUTATION_WIRE_BYTES)?;
        let kind = CatalogMutationKind::decode(decoder.u8()?)?;
        let payload = decode_bounded_bytes(decoder, MAX_CATALOG_MUTATION_PAYLOAD_BYTES)?;
        let mutation = Self { kind, payload };
        mutation.validate().map_err(map_decode_error)?;
        Ok(mutation)
    }
}

/// Canonical semantic result of a finalized catalog attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum CatalogMutationDisposition {
    Applied = 0,
    Rejected = 1,
    StaleAuthority = 2,
    StaleCatalog = 3,
    Conflict = 4,
    NotFound = 5,
    InUse = 6,
    HostLifecycleRequired = 7,
    Capacity = 8,
}

impl CatalogMutationDisposition {
    fn decode(tag: u8) -> Result<Self, DecodeError> {
        match tag {
            0 => Ok(Self::Applied),
            1 => Ok(Self::Rejected),
            2 => Ok(Self::StaleAuthority),
            3 => Ok(Self::StaleCatalog),
            4 => Ok(Self::Conflict),
            5 => Ok(Self::NotFound),
            6 => Ok(Self::InUse),
            7 => Ok(Self::HostLifecycleRequired),
            8 => Ok(Self::Capacity),
            _ => Err(DecodeError::InvalidTag),
        }
    }

    const fn is_stale(self) -> bool {
        matches!(self, Self::StaleAuthority | Self::StaleCatalog)
    }
}

/// Exact bounded projection/result bytes certified for one mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogMutationResult {
    disposition: CatalogMutationDisposition,
    projection: Vec<u8>,
}

impl CatalogMutationResult {
    pub fn new(
        disposition: CatalogMutationDisposition,
        projection: Vec<u8>,
    ) -> Result<Self, CatalogFinalityError> {
        let result = Self {
            disposition,
            projection,
        };
        result.validate()?;
        Ok(result)
    }

    pub const fn disposition(&self) -> CatalogMutationDisposition {
        self.disposition
    }

    pub fn projection(&self) -> &[u8] {
        &self.projection
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(CATALOG_MUTATION_RESULT_COMMITMENT_DOMAIN, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), CatalogFinalityError> {
        if self.projection.len() > MAX_CATALOG_MUTATION_PROJECTION_BYTES {
            return Err(CatalogFinalityError::LimitExceeded);
        }
        if (self.disposition == CatalogMutationDisposition::Applied && self.projection.is_empty())
            || (self.disposition.is_stale() && !self.projection.is_empty())
        {
            return Err(CatalogFinalityError::InvalidResult);
        }
        enforce_encoded_bound(self, MAX_CATALOG_MUTATION_RESULT_WIRE_BYTES)
    }
}

impl ServiceWire for CatalogMutationResult {
    const MAGIC: [u8; 4] = *b"CRS2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.u8(self.disposition as u8);
        encoder.bytes(&self.projection);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_CATALOG_MUTATION_RESULT_WIRE_BYTES)?;
        let disposition = CatalogMutationDisposition::decode(decoder.u8()?)?;
        let projection = decode_bounded_bytes(decoder, MAX_CATALOG_MUTATION_PROJECTION_BYTES)?;
        let result = Self {
            disposition,
            projection,
        };
        result.validate().map_err(map_decode_error)?;
        Ok(result)
    }
}

/// Exact authority admission and compare-and-swap intent.
///
/// `required_capability` is committed evidence, not a caller-selected policy
/// override: admission must compare it with the capability derived from the
/// exact kind-specific mutation before requesting any authority signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogMutationIntent {
    binding: CatalogBinding,
    expected_authority_generation: Hash,
    expected_catalog_head: Hash,
    author: PrincipalId,
    credential: CredentialId,
    required_capability: CapabilityId,
    operation_id: OperationId,
    mutation: CatalogMutation,
}

impl CatalogMutationIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: CatalogBinding,
        expected_authority_generation: Hash,
        expected_catalog_head: Hash,
        author: PrincipalId,
        credential: CredentialId,
        required_capability: CapabilityId,
        operation_id: OperationId,
        mutation: CatalogMutation,
    ) -> Result<Self, CatalogFinalityError> {
        let intent = Self {
            binding,
            expected_authority_generation,
            expected_catalog_head,
            author,
            credential,
            required_capability,
            operation_id,
            mutation,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub const fn binding(&self) -> CatalogBinding {
        self.binding
    }

    pub const fn expected_authority_generation(&self) -> Hash {
        self.expected_authority_generation
    }

    pub const fn expected_catalog_head(&self) -> Hash {
        self.expected_catalog_head
    }

    pub const fn author(&self) -> PrincipalId {
        self.author
    }

    pub const fn credential(&self) -> CredentialId {
        self.credential
    }

    pub const fn required_capability(&self) -> CapabilityId {
        self.required_capability
    }

    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub const fn mutation(&self) -> &CatalogMutation {
        &self.mutation
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(CATALOG_MUTATION_INTENT_COMMITMENT_DOMAIN, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), CatalogFinalityError> {
        self.binding.validate()?;
        self.mutation.validate()?;
        if self.expected_authority_generation == Hash::ZERO
            || self.expected_catalog_head == Hash::ZERO
            || self.author == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.required_capability == CapabilityId::ZERO
            || self.operation_id == OperationId::ZERO
        {
            return Err(CatalogFinalityError::InvalidIntent);
        }
        enforce_encoded_bound(self, MAX_CATALOG_MUTATION_INTENT_WIRE_BYTES)
    }
}

impl ServiceWire for CatalogMutationIntent {
    const MAGIC: [u8; 4] = *b"CMI2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.binding.encode());
        encoder.fixed(&self.expected_authority_generation.0);
        encoder.fixed(&self.expected_catalog_head.0);
        encoder.fixed(&self.author.0);
        encoder.fixed(&self.credential.0);
        encoder.fixed(&self.required_capability.0);
        encoder.fixed(&self.operation_id.0);
        encoder.bytes(&self.mutation.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_CATALOG_MUTATION_INTENT_WIRE_BYTES)?;
        let intent = Self {
            binding: decode_nested(decoder, CATALOG_BINDING_WIRE_BYTES)?,
            expected_authority_generation: Hash(decoder.fixed()?),
            expected_catalog_head: Hash(decoder.fixed()?),
            author: PrincipalId(decoder.fixed()?),
            credential: CredentialId(decoder.fixed()?),
            required_capability: CapabilityId(decoder.fixed()?),
            operation_id: OperationId(decoder.fixed()?),
            mutation: decode_nested(decoder, MAX_CATALOG_MUTATION_WIRE_BYTES)?,
        };
        intent.validate().map_err(map_decode_error)?;
        Ok(intent)
    }
}

/// Derive the next catalog head for every finalized attempt, including a
/// rejected or stale attempt.
pub fn derive_resulting_catalog_head(
    predecessor_catalog_head: Hash,
    intent_commitment: Hash,
    result_commitment: Hash,
    sequence: u64,
) -> Hash {
    let sequence = sequence.to_le_bytes();
    Hash::digest(
        RESULTING_CATALOG_HEAD_DOMAIN,
        &[
            &predecessor_catalog_head.0,
            &intent_commitment.0,
            &result_commitment.0,
            &sequence,
        ],
    )
}

/// Derive the next authority generation without hashing the successor state
/// or QC, avoiding a self-referential fixed point.
pub fn derive_resulting_authority_generation(
    predecessor_authority_generation: Hash,
    resulting_catalog_head: Hash,
    intent_commitment: Hash,
    result_commitment: Hash,
    sequence: u64,
) -> Hash {
    let sequence = sequence.to_le_bytes();
    Hash::digest(
        RESULTING_AUTHORITY_GENERATION_DOMAIN,
        &[
            &predecessor_authority_generation.0,
            &resulting_catalog_head.0,
            &intent_commitment.0,
            &result_commitment.0,
            &sequence,
        ],
    )
}

/// Exact catalog attempt and result certified at one global sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedCatalogMutationFact {
    intent: CatalogMutationIntent,
    actual_predecessor_authority_generation: Hash,
    actual_predecessor_catalog_head: Hash,
    result: CatalogMutationResult,
    resulting_catalog_head: Hash,
    resulting_authority_generation: Hash,
    sequence: u64,
}

impl FinalizedCatalogMutationFact {
    pub fn new(
        intent: CatalogMutationIntent,
        actual_predecessor_authority_generation: Hash,
        actual_predecessor_catalog_head: Hash,
        result: CatalogMutationResult,
        sequence: u64,
    ) -> Result<Self, CatalogFinalityError> {
        let intent_commitment = intent.commitment();
        let result_commitment = result.commitment();
        let resulting_catalog_head = derive_resulting_catalog_head(
            actual_predecessor_catalog_head,
            intent_commitment,
            result_commitment,
            sequence,
        );
        let resulting_authority_generation = derive_resulting_authority_generation(
            actual_predecessor_authority_generation,
            resulting_catalog_head,
            intent_commitment,
            result_commitment,
            sequence,
        );
        let fact = Self {
            intent,
            actual_predecessor_authority_generation,
            actual_predecessor_catalog_head,
            result,
            resulting_catalog_head,
            resulting_authority_generation,
            sequence,
        };
        fact.validate()?;
        Ok(fact)
    }

    pub const fn intent(&self) -> &CatalogMutationIntent {
        &self.intent
    }

    pub const fn actual_predecessor_authority_generation(&self) -> Hash {
        self.actual_predecessor_authority_generation
    }

    pub const fn actual_predecessor_catalog_head(&self) -> Hash {
        self.actual_predecessor_catalog_head
    }

    pub const fn result(&self) -> &CatalogMutationResult {
        &self.result
    }

    pub const fn resulting_catalog_head(&self) -> Hash {
        self.resulting_catalog_head
    }

    pub const fn resulting_authority_generation(&self) -> Hash {
        self.resulting_authority_generation
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn authority_claim(&self) -> AuthorityClaimCommitment {
        AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::Catalog,
            self.sequence,
            &self.encode(),
        )
    }

    pub fn validate(&self) -> Result<(), CatalogFinalityError> {
        self.intent.validate()?;
        self.result.validate()?;
        if self
            .intent
            .mutation
            .payload
            .len()
            .checked_add(self.result.projection.len())
            .ok_or(CatalogFinalityError::LimitExceeded)?
            > MAX_CATALOG_TRANSITION_DATA_BYTES
        {
            return Err(CatalogFinalityError::LimitExceeded);
        }
        if self.actual_predecessor_authority_generation == Hash::ZERO
            || self.actual_predecessor_catalog_head == Hash::ZERO
            || self.sequence == 0
        {
            return Err(CatalogFinalityError::InvalidFact);
        }

        let authority_is_stale = self.intent.expected_authority_generation
            != self.actual_predecessor_authority_generation;
        let catalog_is_stale =
            self.intent.expected_catalog_head != self.actual_predecessor_catalog_head;
        let disposition = self.result.disposition;
        if (authority_is_stale && disposition != CatalogMutationDisposition::StaleAuthority)
            || (!authority_is_stale
                && catalog_is_stale
                && disposition != CatalogMutationDisposition::StaleCatalog)
            || (!authority_is_stale && !catalog_is_stale && disposition.is_stale())
        {
            return Err(CatalogFinalityError::InvalidFact);
        }

        let intent_commitment = self.intent.commitment();
        let result_commitment = self.result.commitment();
        let resulting_catalog_head = derive_resulting_catalog_head(
            self.actual_predecessor_catalog_head,
            intent_commitment,
            result_commitment,
            self.sequence,
        );
        let resulting_authority_generation = derive_resulting_authority_generation(
            self.actual_predecessor_authority_generation,
            resulting_catalog_head,
            intent_commitment,
            result_commitment,
            self.sequence,
        );
        if self.resulting_catalog_head != resulting_catalog_head
            || self.resulting_authority_generation != resulting_authority_generation
            || self.resulting_catalog_head == Hash::ZERO
            || self.resulting_authority_generation == Hash::ZERO
        {
            return Err(CatalogFinalityError::InvalidFact);
        }
        enforce_encoded_bound(self, MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES)
    }
}

impl ServiceWire for FinalizedCatalogMutationFact {
    const MAGIC: [u8; 4] = *b"CMF2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.intent.encode());
        encoder.fixed(&self.actual_predecessor_authority_generation.0);
        encoder.fixed(&self.actual_predecessor_catalog_head.0);
        encoder.bytes(&self.result.encode());
        encoder.fixed(&self.resulting_catalog_head.0);
        encoder.fixed(&self.resulting_authority_generation.0);
        encoder.u64(self.sequence);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES)?;
        let fact = Self {
            intent: decode_nested(decoder, MAX_CATALOG_MUTATION_INTENT_WIRE_BYTES)?,
            actual_predecessor_authority_generation: Hash(decoder.fixed()?),
            actual_predecessor_catalog_head: Hash(decoder.fixed()?),
            result: decode_nested(decoder, MAX_CATALOG_MUTATION_RESULT_WIRE_BYTES)?,
            resulting_catalog_head: Hash(decoder.fixed()?),
            resulting_authority_generation: Hash(decoder.fixed()?),
            sequence: decoder.u64()?,
        };
        fact.validate().map_err(map_decode_error)?;
        Ok(fact)
    }
}

/// Quorum-certified finalization of one exact catalog mutation result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedCatalogMutationReceipt {
    fact: FinalizedCatalogMutationFact,
    certificate: AuthorityQuorumCertificate,
}

impl FinalizedCatalogMutationReceipt {
    pub fn new(
        fact: FinalizedCatalogMutationFact,
        certificate: AuthorityQuorumCertificate,
        trusted_binding: CatalogBinding,
        historical_committee: &AuthorityCommittee,
    ) -> Result<Self, CatalogFinalityError> {
        let receipt = Self { fact, certificate };
        receipt.verify(trusted_binding, historical_committee)?;
        Ok(receipt)
    }

    pub const fn fact(&self) -> &FinalizedCatalogMutationFact {
        &self.fact
    }

    pub const fn certificate(&self) -> &AuthorityQuorumCertificate {
        &self.certificate
    }

    pub fn verify(
        &self,
        trusted_binding: CatalogBinding,
        historical_committee: &AuthorityCommittee,
    ) -> Result<(), CatalogFinalityError> {
        self.validate_shape()?;
        trusted_binding.validate()?;
        let binding = self.fact.intent.binding;
        if binding != trusted_binding {
            return Err(CatalogFinalityError::InvalidReceipt);
        }
        if historical_committee.space() != trusted_binding.space {
            return Err(CatalogFinalityError::WrongSpace);
        }
        if historical_committee.authority_binding() != trusted_binding.authority_binding {
            return Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::WrongAuthorityBinding,
            ));
        }
        self.certificate
            .verify(historical_committee, self.fact.authority_claim())
            .map_err(CatalogFinalityError::Authority)
    }

    fn validate_shape(&self) -> Result<(), CatalogFinalityError> {
        self.fact.validate()?;
        if self.certificate.authority_binding() != self.fact.intent.binding.authority_binding
            || self.certificate.claim() != self.fact.authority_claim()
        {
            return Err(CatalogFinalityError::InvalidReceipt);
        }
        enforce_encoded_bound(self, MAX_FINALIZED_CATALOG_MUTATION_RECEIPT_BYTES)
    }
}

impl ServiceWire for FinalizedCatalogMutationReceipt {
    const MAGIC: [u8; 4] = *b"CMR2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.fact.encode());
        encoder.bytes(&self.certificate.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_FINALIZED_CATALOG_MUTATION_RECEIPT_BYTES)?;
        let receipt = Self {
            fact: decode_nested(decoder, MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES)?,
            certificate: decode_nested(decoder, MAX_AUTHORITY_QC_WIRE_BYTES)?,
        };
        receipt.validate_shape().map_err(map_decode_error)?;
        Ok(receipt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogFinalityError {
    InvalidBinding,
    InvalidMutation,
    InvalidResult,
    InvalidIntent,
    InvalidFact,
    InvalidReceipt,
    WrongSpace,
    LimitExceeded,
    Authority(AuthorityCommitteeError),
}

impl fmt::Display for CatalogFinalityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid finalized catalog mutation: {self:?}")
    }
}

impl core::error::Error for CatalogFinalityError {}

fn enforce_complete_bound(decoder: &Decoder<'_>, maximum: usize) -> Result<(), DecodeError> {
    let maximum_body = maximum
        .checked_sub(SERVICE_WIRE_HEADER_BYTES)
        .ok_or(DecodeError::LimitExceeded)?;
    if decoder.remaining() > maximum_body {
        Err(DecodeError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn decode_bounded_bytes(decoder: &mut Decoder<'_>, maximum: usize) -> Result<Vec<u8>, DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(bytes.to_vec())
}

fn decode_nested<T: ServiceWire>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<T, DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > maximum {
        return Err(DecodeError::LimitExceeded);
    }
    T::decode(bytes)
}

fn enforce_encoded_bound<T: ServiceWire>(
    value: &T,
    maximum: usize,
) -> Result<(), CatalogFinalityError> {
    if value.encode().len() > maximum {
        Err(CatalogFinalityError::LimitExceeded)
    } else {
        Ok(())
    }
}

fn map_decode_error(error: CatalogFinalityError) -> DecodeError {
    match error {
        CatalogFinalityError::LimitExceeded
        | CatalogFinalityError::Authority(AuthorityCommitteeError::CommitteeTooLarge)
        | CatalogFinalityError::Authority(AuthorityCommitteeError::CertificateTooLarge) => {
            DecodeError::LimitExceeded
        }
        _ => DecodeError::NonCanonical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::super::committee::{
        AuthorityCommitteeMember, AuthorityMemberRole, AuthoritySignature, AuthoritySignerId,
    };
    use crate::service::NodeId;

    const ALL_MUTATION_KINDS: [CatalogMutationKind; 17] = [
        CatalogMutationKind::PublishArtifact,
        CatalogMutationKind::RetireArtifact,
        CatalogMutationKind::PublishAgent,
        CatalogMutationKind::RetireAgent,
        CatalogMutationKind::ReserveActorInstall,
        CatalogMutationKind::CompleteActorInstall,
        CatalogMutationKind::AbortActorInstall,
        CatalogMutationKind::ReserveActorUpgrade,
        CatalogMutationKind::CompleteActorUpgrade,
        CatalogMutationKind::AbortActorUpgrade,
        CatalogMutationKind::ReserveActorRemoval,
        CatalogMutationKind::CompleteActorRemoval,
        CatalogMutationKind::AbortActorRemoval,
        CatalogMutationKind::UpdateAgentAlias,
        CatalogMutationKind::UpdateReplicaSet,
        CatalogMutationKind::UpdateMetadata,
        CatalogMutationKind::UpdateRemoteMapping,
    ];

    const ALL_DISPOSITIONS: [CatalogMutationDisposition; 9] = [
        CatalogMutationDisposition::Applied,
        CatalogMutationDisposition::Rejected,
        CatalogMutationDisposition::StaleAuthority,
        CatalogMutationDisposition::StaleCatalog,
        CatalogMutationDisposition::Conflict,
        CatalogMutationDisposition::NotFound,
        CatalogMutationDisposition::InUse,
        CatalogMutationDisposition::HostLifecycleRequired,
        CatalogMutationDisposition::Capacity,
    ];

    fn binding() -> CatalogBinding {
        CatalogBinding::new(SpaceId([0x11; 32]), Hash([0x12; 32]), Hash([0x13; 32])).unwrap()
    }

    fn mutation() -> CatalogMutation {
        CatalogMutation::new(CatalogMutationKind::PublishArtifact, vec![0x1a, 0x1b]).unwrap()
    }

    fn result() -> CatalogMutationResult {
        CatalogMutationResult::new(CatalogMutationDisposition::Applied, vec![0x1c, 0x1d]).unwrap()
    }

    fn intent() -> CatalogMutationIntent {
        CatalogMutationIntent::new(
            binding(),
            Hash([0x14; 32]),
            Hash([0x15; 32]),
            PrincipalId([0x16; 32]),
            CredentialId([0x17; 32]),
            CapabilityId([0x18; 32]),
            OperationId([0x19; 32]),
            mutation(),
        )
        .unwrap()
    }

    fn fact() -> FinalizedCatalogMutationFact {
        let intent = intent();
        FinalizedCatalogMutationFact::new(
            intent.clone(),
            intent.expected_authority_generation(),
            intent.expected_catalog_head(),
            result(),
            7,
        )
        .unwrap()
    }

    fn signing_keys(seed: u8) -> Vec<SigningKey> {
        (0..3)
            .map(|offset| SigningKey::from_bytes(&[seed.wrapping_add(offset); 32]))
            .collect()
    }

    fn committee_with_roles(
        space: SpaceId,
        authority_binding: Hash,
        keys: &[SigningKey],
        roles: &[AuthorityMemberRole],
        epoch: u64,
        previous: Option<Hash>,
    ) -> AuthorityCommittee {
        let mut members = keys
            .iter()
            .zip(roles)
            .enumerate()
            .map(|(index, (key, role))| {
                AuthorityCommitteeMember::new(
                    NodeId([(index as u8).wrapping_add(1); 32]),
                    key.verifying_key().to_bytes(),
                    *role,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(AuthorityCommitteeMember::signer);
        AuthorityCommittee::new(space, authority_binding, epoch, previous, members).unwrap()
    }

    fn test_committee(binding: CatalogBinding, keys: &[SigningKey]) -> AuthorityCommittee {
        committee_with_roles(
            binding.space(),
            binding.authority_binding(),
            keys,
            &[
                AuthorityMemberRole::Voter,
                AuthorityMemberRole::Voter,
                AuthorityMemberRole::Voter,
            ],
            1,
            None,
        )
    }

    fn signatures(
        committee: &AuthorityCommittee,
        claim: AuthorityClaimCommitment,
        keys: &[SigningKey],
    ) -> Vec<AuthoritySignature> {
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim,
        );
        let mut signatures = keys
            .iter()
            .map(|key| {
                AuthoritySignature::new(
                    AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes()),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(AuthoritySignature::signer);
        signatures
    }

    fn certificate(
        committee: &AuthorityCommittee,
        claim: AuthorityClaimCommitment,
        keys: &[SigningKey],
    ) -> AuthorityQuorumCertificate {
        AuthorityQuorumCertificate::new(committee, claim, signatures(committee, claim, keys))
            .unwrap()
    }

    fn fixture() -> (
        FinalizedCatalogMutationFact,
        AuthorityCommittee,
        Vec<SigningKey>,
        FinalizedCatalogMutationReceipt,
    ) {
        let fact = fact();
        let keys = signing_keys(0x21);
        let committee = test_committee(fact.intent().binding(), &keys);
        let certificate = certificate(&committee, fact.authority_claim(), &keys[..2]);
        let receipt = FinalizedCatalogMutationReceipt::new(
            fact.clone(),
            certificate,
            fact.intent().binding(),
            &committee,
        )
        .unwrap();
        (fact, committee, keys, receipt)
    }

    #[test]
    fn every_mutation_kind_has_a_canonical_distinct_wire_and_commitment() {
        let mut commitments = Vec::new();
        for kind in ALL_MUTATION_KINDS {
            let mutation = CatalogMutation::new(kind, vec![0xa5]).unwrap();
            assert_eq!(
                CatalogMutation::decode(&mutation.encode()),
                Ok(mutation.clone())
            );
            assert_eq!(mutation.kind(), kind);
            assert_eq!(mutation.payload(), &[0xa5]);
            assert!(
                commitments
                    .iter()
                    .all(|prior| *prior != mutation.commitment())
            );
            commitments.push(mutation.commitment());
        }
    }

    #[test]
    fn mutation_payload_is_exact_nonempty_and_bounded() {
        assert_eq!(
            CatalogMutation::new(CatalogMutationKind::UpdateMetadata, Vec::new()),
            Err(CatalogFinalityError::InvalidMutation)
        );
        let maximum = CatalogMutation::new(
            CatalogMutationKind::UpdateMetadata,
            vec![0x5a; MAX_CATALOG_MUTATION_PAYLOAD_BYTES],
        )
        .unwrap();
        assert_eq!(maximum.encode().len(), MAX_CATALOG_MUTATION_WIRE_BYTES);
        assert_eq!(CatalogMutation::decode(&maximum.encode()), Ok(maximum));
        assert_eq!(
            CatalogMutation::new(
                CatalogMutationKind::UpdateMetadata,
                vec![0; MAX_CATALOG_MUTATION_PAYLOAD_BYTES + 1],
            ),
            Err(CatalogFinalityError::LimitExceeded)
        );
    }

    #[test]
    fn every_result_disposition_has_a_canonical_distinct_commitment() {
        let mut commitments = Vec::new();
        for disposition in ALL_DISPOSITIONS {
            let projection = match disposition {
                CatalogMutationDisposition::Applied => vec![0xb5],
                CatalogMutationDisposition::StaleAuthority
                | CatalogMutationDisposition::StaleCatalog => Vec::new(),
                _ => vec![0xb6],
            };
            let result = CatalogMutationResult::new(disposition, projection).unwrap();
            assert_eq!(
                CatalogMutationResult::decode(&result.encode()),
                Ok(result.clone())
            );
            assert_eq!(result.disposition(), disposition);
            assert!(
                commitments
                    .iter()
                    .all(|prior| *prior != result.commitment())
            );
            commitments.push(result.commitment());
        }
    }

    #[test]
    fn result_projection_rules_and_bound_are_strict() {
        assert_eq!(
            CatalogMutationResult::new(CatalogMutationDisposition::Applied, Vec::new()),
            Err(CatalogFinalityError::InvalidResult)
        );
        for disposition in [
            CatalogMutationDisposition::StaleAuthority,
            CatalogMutationDisposition::StaleCatalog,
        ] {
            assert_eq!(
                CatalogMutationResult::new(disposition, vec![1]),
                Err(CatalogFinalityError::InvalidResult)
            );
        }
        let maximum = CatalogMutationResult::new(
            CatalogMutationDisposition::Rejected,
            vec![0x6a; MAX_CATALOG_MUTATION_PROJECTION_BYTES],
        )
        .unwrap();
        assert_eq!(
            maximum.encode().len(),
            MAX_CATALOG_MUTATION_RESULT_WIRE_BYTES
        );
        assert_eq!(
            CatalogMutationResult::decode(&maximum.encode()),
            Ok(maximum)
        );
        assert_eq!(
            CatalogMutationResult::new(
                CatalogMutationDisposition::Rejected,
                vec![0; MAX_CATALOG_MUTATION_PROJECTION_BYTES + 1],
            ),
            Err(CatalogFinalityError::LimitExceeded)
        );
    }

    #[test]
    fn aggregate_transition_data_bound_is_strict() {
        let intent = CatalogMutationIntent::new(
            binding(),
            Hash([0x14; 32]),
            Hash([0x15; 32]),
            PrincipalId([0x16; 32]),
            CredentialId([0x17; 32]),
            CapabilityId([0x18; 32]),
            OperationId([0x19; 32]),
            CatalogMutation::new(
                CatalogMutationKind::PublishArtifact,
                vec![1; MAX_CATALOG_TRANSITION_DATA_BYTES - 1],
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            FinalizedCatalogMutationFact::new(
                intent.clone(),
                intent.expected_authority_generation(),
                intent.expected_catalog_head(),
                CatalogMutationResult::new(CatalogMutationDisposition::Applied, vec![2]).unwrap(),
                1,
            )
            .is_ok()
        );
        assert_eq!(
            FinalizedCatalogMutationFact::new(
                intent.clone(),
                intent.expected_authority_generation(),
                intent.expected_catalog_head(),
                CatalogMutationResult::new(CatalogMutationDisposition::Applied, vec![2, 3])
                    .unwrap(),
                1,
            ),
            Err(CatalogFinalityError::LimitExceeded)
        );

        let max_fact = FinalizedCatalogMutationFact::new(
            intent.clone(),
            intent.expected_authority_generation(),
            intent.expected_catalog_head(),
            CatalogMutationResult::new(CatalogMutationDisposition::Rejected, vec![2]).unwrap(),
            1,
        )
        .unwrap();
        assert_eq!(
            max_fact.encode().len(),
            MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES
        );
    }

    #[test]
    fn canonical_round_trips_commitments_derivations_and_historical_qc() {
        let (fact, committee, _, receipt) = fixture();
        let intent = fact.intent();
        assert_eq!(binding().encode().len(), CATALOG_BINDING_WIRE_BYTES);
        assert_eq!(CatalogBinding::decode(&binding().encode()), Ok(binding()));
        let decoded_intent = CatalogMutationIntent::decode(&intent.encode()).unwrap();
        assert_eq!(&decoded_intent, intent);
        assert_eq!(decoded_intent.commitment(), intent.commitment());
        assert_eq!(
            FinalizedCatalogMutationFact::decode(&fact.encode()),
            Ok(fact.clone())
        );
        assert_eq!(
            FinalizedCatalogMutationReceipt::decode(&receipt.encode()),
            Ok(receipt.clone())
        );
        assert_eq!(
            fact.authority_claim().domain(),
            AuthorityClaimDomain::Catalog
        );
        assert_eq!(fact.authority_claim().sequence(), fact.sequence());
        assert_eq!(
            fact.resulting_catalog_head(),
            derive_resulting_catalog_head(
                fact.actual_predecessor_catalog_head(),
                fact.intent().commitment(),
                fact.result().commitment(),
                fact.sequence(),
            )
        );
        assert_eq!(
            fact.resulting_authority_generation(),
            derive_resulting_authority_generation(
                fact.actual_predecessor_authority_generation(),
                fact.resulting_catalog_head(),
                fact.intent().commitment(),
                fact.result().commitment(),
                fact.sequence(),
            )
        );
        assert_eq!(receipt.verify(binding(), &committee), Ok(()));
        assert!(receipt.encode().len() <= MAX_FINALIZED_CATALOG_MUTATION_RECEIPT_BYTES);
    }

    #[test]
    fn intent_commitment_binds_every_selector_and_exact_mutation_byte() {
        let valid = intent();
        let mutations = [
            CatalogMutationIntent {
                binding: CatalogBinding {
                    space: SpaceId([0x31; 32]),
                    ..valid.binding
                },
                ..valid.clone()
            },
            CatalogMutationIntent {
                binding: CatalogBinding {
                    catalog_binding: Hash([0x32; 32]),
                    ..valid.binding
                },
                ..valid.clone()
            },
            CatalogMutationIntent {
                binding: CatalogBinding {
                    authority_binding: Hash([0x33; 32]),
                    ..valid.binding
                },
                ..valid.clone()
            },
            CatalogMutationIntent {
                expected_authority_generation: Hash([0x34; 32]),
                ..valid.clone()
            },
            CatalogMutationIntent {
                expected_catalog_head: Hash([0x35; 32]),
                ..valid.clone()
            },
            CatalogMutationIntent {
                author: PrincipalId([0x36; 32]),
                ..valid.clone()
            },
            CatalogMutationIntent {
                credential: CredentialId([0x37; 32]),
                ..valid.clone()
            },
            CatalogMutationIntent {
                required_capability: CapabilityId([0x38; 32]),
                ..valid.clone()
            },
            CatalogMutationIntent {
                operation_id: OperationId([0x39; 32]),
                ..valid.clone()
            },
            CatalogMutationIntent {
                mutation: CatalogMutation::new(
                    CatalogMutationKind::RetireArtifact,
                    vec![0x1a, 0x1b],
                )
                .unwrap(),
                ..valid.clone()
            },
            CatalogMutationIntent {
                mutation: CatalogMutation::new(
                    CatalogMutationKind::PublishArtifact,
                    vec![0x1a, 0x1c],
                )
                .unwrap(),
                ..valid.clone()
            },
        ];
        for mutated in mutations {
            assert_ne!(mutated.commitment(), valid.commitment());
        }
    }

    #[test]
    fn every_zero_binding_and_intent_selector_is_rejected() {
        let valid_binding = binding();
        for invalid in [
            CatalogBinding {
                space: SpaceId::ZERO,
                ..valid_binding
            },
            CatalogBinding {
                catalog_binding: Hash::ZERO,
                ..valid_binding
            },
            CatalogBinding {
                authority_binding: Hash::ZERO,
                ..valid_binding
            },
        ] {
            assert_eq!(
                invalid.validate(),
                Err(CatalogFinalityError::InvalidBinding)
            );
            assert_eq!(
                CatalogBinding::decode(&invalid.encode()),
                Err(DecodeError::NonCanonical)
            );
        }

        let valid = intent();
        let candidates = [
            CatalogMutationIntent {
                expected_authority_generation: Hash::ZERO,
                ..valid.clone()
            },
            CatalogMutationIntent {
                expected_catalog_head: Hash::ZERO,
                ..valid.clone()
            },
            CatalogMutationIntent {
                author: PrincipalId::ZERO,
                ..valid.clone()
            },
            CatalogMutationIntent {
                credential: CredentialId::ZERO,
                ..valid.clone()
            },
            CatalogMutationIntent {
                required_capability: CapabilityId::ZERO,
                ..valid.clone()
            },
            CatalogMutationIntent {
                operation_id: OperationId::ZERO,
                ..valid.clone()
            },
        ];
        for invalid in candidates {
            assert_eq!(invalid.validate(), Err(CatalogFinalityError::InvalidIntent));
            assert_eq!(
                CatalogMutationIntent::decode(&invalid.encode()),
                Err(DecodeError::NonCanonical)
            );
        }
    }

    #[test]
    fn stale_disposition_is_exact_and_authority_mismatch_takes_precedence() {
        let base = intent();
        let actual_authority = Hash([0x71; 32]);
        let actual_head = Hash([0x72; 32]);
        let stale_authority =
            CatalogMutationResult::new(CatalogMutationDisposition::StaleAuthority, Vec::new())
                .unwrap();
        assert!(
            FinalizedCatalogMutationFact::new(
                base.clone(),
                actual_authority,
                actual_head,
                stale_authority,
                8,
            )
            .is_ok()
        );

        let stale_catalog_intent = CatalogMutationIntent {
            expected_authority_generation: actual_authority,
            ..base.clone()
        };
        let stale_catalog =
            CatalogMutationResult::new(CatalogMutationDisposition::StaleCatalog, Vec::new())
                .unwrap();
        assert!(
            FinalizedCatalogMutationFact::new(
                stale_catalog_intent.clone(),
                actual_authority,
                actual_head,
                stale_catalog.clone(),
                8,
            )
            .is_ok()
        );

        let nonstale_intent = CatalogMutationIntent {
            expected_authority_generation: actual_authority,
            expected_catalog_head: actual_head,
            ..base
        };
        assert_eq!(
            FinalizedCatalogMutationFact::new(
                nonstale_intent.clone(),
                actual_authority,
                actual_head,
                stale_catalog,
                8,
            ),
            Err(CatalogFinalityError::InvalidFact)
        );
        assert_eq!(
            FinalizedCatalogMutationFact::new(
                nonstale_intent,
                Hash([0x73; 32]),
                actual_head,
                CatalogMutationResult::new(CatalogMutationDisposition::Rejected, Vec::new())
                    .unwrap(),
                8,
            ),
            Err(CatalogFinalityError::InvalidFact)
        );
        assert_eq!(
            FinalizedCatalogMutationFact::new(
                stale_catalog_intent,
                actual_authority,
                actual_head,
                CatalogMutationResult::new(CatalogMutationDisposition::StaleAuthority, Vec::new(),)
                    .unwrap(),
                8,
            ),
            Err(CatalogFinalityError::InvalidFact)
        );
    }

    #[test]
    fn every_finalized_disposition_advances_both_derived_chains() {
        for (index, disposition) in ALL_DISPOSITIONS.into_iter().enumerate() {
            let actual_authority = Hash([0x81; 32]);
            let actual_head = Hash([0x82; 32]);
            let mut intent = intent();
            intent.expected_authority_generation = actual_authority;
            intent.expected_catalog_head = actual_head;
            if disposition == CatalogMutationDisposition::StaleAuthority {
                intent.expected_authority_generation = Hash([0x83; 32]);
            } else if disposition == CatalogMutationDisposition::StaleCatalog {
                intent.expected_catalog_head = Hash([0x84; 32]);
            }
            let projection = match disposition {
                CatalogMutationDisposition::Applied => vec![index as u8 + 1],
                CatalogMutationDisposition::StaleAuthority
                | CatalogMutationDisposition::StaleCatalog => Vec::new(),
                _ => vec![index as u8 + 1],
            };
            let fact = FinalizedCatalogMutationFact::new(
                intent,
                actual_authority,
                actual_head,
                CatalogMutationResult::new(disposition, projection).unwrap(),
                index as u64 + 1,
            )
            .unwrap();
            assert_ne!(fact.resulting_catalog_head(), actual_head);
            assert_ne!(fact.resulting_authority_generation(), actual_authority);
            assert_eq!(fact.validate(), Ok(()));
        }
    }

    #[test]
    fn fact_rejects_zero_predecessors_sequence_and_forged_derivations() {
        let valid = fact();
        for invalid in [
            FinalizedCatalogMutationFact {
                actual_predecessor_authority_generation: Hash::ZERO,
                ..valid.clone()
            },
            FinalizedCatalogMutationFact {
                actual_predecessor_catalog_head: Hash::ZERO,
                ..valid.clone()
            },
            FinalizedCatalogMutationFact {
                resulting_catalog_head: Hash([0x91; 32]),
                ..valid.clone()
            },
            FinalizedCatalogMutationFact {
                resulting_authority_generation: Hash([0x92; 32]),
                ..valid.clone()
            },
            FinalizedCatalogMutationFact {
                sequence: 0,
                ..valid.clone()
            },
        ] {
            assert_eq!(invalid.validate(), Err(CatalogFinalityError::InvalidFact));
            assert_eq!(
                FinalizedCatalogMutationFact::decode(&invalid.encode()),
                Err(DecodeError::NonCanonical)
            );
        }
    }

    #[test]
    fn derivations_bind_predecessors_intent_result_and_sequence() {
        let valid = fact();
        let intent_commitment = valid.intent().commitment();
        let result_commitment = valid.result().commitment();
        let head = valid.resulting_catalog_head();
        for mutated in [
            derive_resulting_catalog_head(
                Hash([0xa1; 32]),
                intent_commitment,
                result_commitment,
                valid.sequence(),
            ),
            derive_resulting_catalog_head(
                valid.actual_predecessor_catalog_head(),
                Hash([0xa2; 32]),
                result_commitment,
                valid.sequence(),
            ),
            derive_resulting_catalog_head(
                valid.actual_predecessor_catalog_head(),
                intent_commitment,
                Hash([0xa3; 32]),
                valid.sequence(),
            ),
            derive_resulting_catalog_head(
                valid.actual_predecessor_catalog_head(),
                intent_commitment,
                result_commitment,
                valid.sequence() + 1,
            ),
        ] {
            assert_ne!(mutated, head);
        }

        let generation = valid.resulting_authority_generation();
        for mutated in [
            derive_resulting_authority_generation(
                Hash([0xa4; 32]),
                head,
                intent_commitment,
                result_commitment,
                valid.sequence(),
            ),
            derive_resulting_authority_generation(
                valid.actual_predecessor_authority_generation(),
                Hash([0xa5; 32]),
                intent_commitment,
                result_commitment,
                valid.sequence(),
            ),
            derive_resulting_authority_generation(
                valid.actual_predecessor_authority_generation(),
                head,
                Hash([0xa6; 32]),
                result_commitment,
                valid.sequence(),
            ),
            derive_resulting_authority_generation(
                valid.actual_predecessor_authority_generation(),
                head,
                intent_commitment,
                Hash([0xa7; 32]),
                valid.sequence(),
            ),
            derive_resulting_authority_generation(
                valid.actual_predecessor_authority_generation(),
                head,
                intent_commitment,
                result_commitment,
                valid.sequence() + 1,
            ),
        ] {
            assert_ne!(mutated, generation);
        }
    }

    #[test]
    fn qc_claim_binds_exact_fact_and_rejects_a_stale_certificate() {
        let (valid, committee, _, receipt) = fixture();
        let original_claim = valid.authority_claim();
        let mut mutated = valid.clone();
        mutated.sequence += 1;
        mutated.resulting_catalog_head = derive_resulting_catalog_head(
            mutated.actual_predecessor_catalog_head,
            mutated.intent.commitment(),
            mutated.result.commitment(),
            mutated.sequence,
        );
        mutated.resulting_authority_generation = derive_resulting_authority_generation(
            mutated.actual_predecessor_authority_generation,
            mutated.resulting_catalog_head,
            mutated.intent.commitment(),
            mutated.result.commitment(),
            mutated.sequence,
        );
        assert_eq!(mutated.validate(), Ok(()));
        assert_ne!(mutated.authority_claim(), original_claim);
        assert_eq!(
            FinalizedCatalogMutationReceipt {
                fact: mutated,
                certificate: receipt.certificate().clone(),
            }
            .verify(binding(), &committee),
            Err(CatalogFinalityError::InvalidReceipt)
        );
    }

    #[test]
    fn receipt_rejects_wrong_claim_domain_sequence_and_payload() {
        let (fact, committee, keys, _) = fixture();
        let claims = [
            AuthorityClaimCommitment::of_bytes(
                AuthorityClaimDomain::NodeControl,
                fact.sequence(),
                &fact.encode(),
            ),
            AuthorityClaimCommitment::of_bytes(
                AuthorityClaimDomain::Catalog,
                fact.sequence() + 1,
                &fact.encode(),
            ),
            AuthorityClaimCommitment::of_bytes(
                AuthorityClaimDomain::Catalog,
                fact.sequence(),
                b"different finalized fact",
            ),
        ];
        for claim in claims {
            let receipt = FinalizedCatalogMutationReceipt {
                fact: fact.clone(),
                certificate: certificate(&committee, claim, &keys[..2]),
            };
            assert_eq!(
                receipt.verify(binding(), &committee),
                Err(CatalogFinalityError::InvalidReceipt)
            );
            assert_eq!(
                FinalizedCatalogMutationReceipt::decode(&receipt.encode()),
                Err(DecodeError::NonCanonical)
            );
        }
    }

    #[test]
    fn independently_selected_committee_binding_epoch_and_roster_are_exact() {
        let (fact, committee, keys, receipt) = fixture();
        let wrong_catalog_binding = CatalogBinding {
            catalog_binding: Hash([0xaf; 32]),
            ..binding()
        };
        assert_eq!(
            receipt.verify(wrong_catalog_binding, &committee),
            Err(CatalogFinalityError::InvalidReceipt)
        );

        let foreign_space = committee_with_roles(
            SpaceId([0xb0; 32]),
            fact.intent().binding().authority_binding(),
            &keys,
            &[
                AuthorityMemberRole::Voter,
                AuthorityMemberRole::Voter,
                AuthorityMemberRole::Voter,
            ],
            1,
            None,
        );
        assert_eq!(
            receipt.verify(binding(), &foreign_space),
            Err(CatalogFinalityError::WrongSpace)
        );

        let foreign_binding = test_committee(
            CatalogBinding {
                authority_binding: Hash([0xb1; 32]),
                ..fact.intent().binding()
            },
            &keys,
        );
        assert_eq!(
            receipt.verify(binding(), &foreign_binding),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::WrongAuthorityBinding
            ))
        );

        let wrong_epoch = committee_with_roles(
            fact.intent().binding().space(),
            fact.intent().binding().authority_binding(),
            &keys,
            &[
                AuthorityMemberRole::Voter,
                AuthorityMemberRole::Voter,
                AuthorityMemberRole::Voter,
            ],
            2,
            Some(committee.commitment()),
        );
        assert_eq!(
            receipt.verify(binding(), &wrong_epoch),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::WrongEpoch
            ))
        );

        let foreign_keys = signing_keys(0xc1);
        let wrong_roster = test_committee(fact.intent().binding(), &foreign_keys);
        assert_eq!(
            receipt.verify(binding(), &wrong_roster),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::WrongCommittee
            ))
        );
    }

    #[test]
    fn quorum_rejects_insufficient_unknown_observer_and_bad_signatures() {
        let (fact, committee, keys, _) = fixture();
        let claim = fact.authority_claim();

        let insufficient = AuthorityQuorumCertificate::new(
            &committee,
            claim,
            signatures(&committee, claim, &keys[..1]),
        )
        .unwrap();
        assert_eq!(
            FinalizedCatalogMutationReceipt {
                fact: fact.clone(),
                certificate: insufficient,
            }
            .verify(binding(), &committee),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::InsufficientQuorum
            ))
        );

        let unknown_key = SigningKey::from_bytes(&[0xd1; 32]);
        let mut unknown = signatures(&committee, claim, &keys[..1]);
        unknown.extend(signatures(&committee, claim, &[unknown_key]));
        unknown.sort_by_key(AuthoritySignature::signer);
        let unknown = AuthorityQuorumCertificate::new(&committee, claim, unknown).unwrap();
        assert_eq!(
            FinalizedCatalogMutationReceipt {
                fact: fact.clone(),
                certificate: unknown,
            }
            .verify(binding(), &committee),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::UnknownSigner
            ))
        );

        let observer_committee = committee_with_roles(
            fact.intent().binding().space(),
            fact.intent().binding().authority_binding(),
            &keys,
            &[
                AuthorityMemberRole::Voter,
                AuthorityMemberRole::Voter,
                AuthorityMemberRole::Observer,
            ],
            1,
            None,
        );
        let observer_qc = certificate(
            &observer_committee,
            claim,
            &[keys[0].clone(), keys[2].clone()],
        );
        assert_eq!(
            FinalizedCatalogMutationReceipt {
                fact: fact.clone(),
                certificate: observer_qc,
            }
            .verify(binding(), &observer_committee),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::ObserverSignature
            ))
        );

        let mut bad = signatures(&committee, claim, &keys[..2]);
        let first = bad[0].clone();
        let mut bytes = *first.signature();
        bytes[0] ^= 1;
        bad[0] = AuthoritySignature::new(first.signer(), bytes).unwrap();
        let bad = AuthorityQuorumCertificate::new(&committee, claim, bad).unwrap();
        assert_eq!(
            FinalizedCatalogMutationReceipt {
                fact,
                certificate: bad,
            }
            .verify(binding(), &committee),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::InvalidSignature
            ))
        );
    }

    #[test]
    fn public_receipt_constructor_requires_a_valid_historical_quorum() {
        let (fact, committee, keys, _) = fixture();
        let insufficient = AuthorityQuorumCertificate::new(
            &committee,
            fact.authority_claim(),
            signatures(&committee, fact.authority_claim(), &keys[..1]),
        )
        .unwrap();
        assert_eq!(
            FinalizedCatalogMutationReceipt::new(fact, insufficient, binding(), &committee),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::InsufficientQuorum
            ))
        );
    }

    #[test]
    fn wire_bounds_unknown_tags_trailing_bytes_and_nested_wires_fail_closed() {
        let (fact, _, _, receipt) = fixture();

        let mut unknown_mutation = mutation().encode();
        unknown_mutation[SERVICE_WIRE_HEADER_BYTES] = 0xff;
        assert_eq!(
            CatalogMutation::decode(&unknown_mutation),
            Err(DecodeError::InvalidTag)
        );

        let mut unknown_result = result().encode();
        unknown_result[SERVICE_WIRE_HEADER_BYTES] = 0xff;
        assert_eq!(
            CatalogMutationResult::decode(&unknown_result),
            Err(DecodeError::InvalidTag)
        );

        let mut malicious_length = mutation().encode();
        malicious_length.truncate(SERVICE_WIRE_HEADER_BYTES + 1);
        malicious_length.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            CatalogMutation::decode(&malicious_length),
            Err(DecodeError::LimitExceeded)
        );

        let mut oversized_binding = binding().encode();
        oversized_binding.push(0);
        assert_eq!(
            CatalogBinding::decode(&oversized_binding),
            Err(DecodeError::LimitExceeded)
        );

        let mut trailing_mutation = mutation().encode();
        trailing_mutation.push(0);
        assert_eq!(
            CatalogMutation::decode(&trailing_mutation),
            Err(DecodeError::TrailingBytes)
        );

        let mut oversized_fact = fact.encode();
        oversized_fact.resize(MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES + 1, 0);
        assert_eq!(
            FinalizedCatalogMutationFact::decode(&oversized_fact),
            Err(DecodeError::LimitExceeded)
        );

        let mut trailing_receipt = receipt.encode();
        trailing_receipt.push(0);
        assert_eq!(
            FinalizedCatalogMutationReceipt::decode(&trailing_receipt),
            Err(DecodeError::TrailingBytes)
        );

        let mut oversized_nested = receipt.encode();
        oversized_nested.truncate(SERVICE_WIRE_HEADER_BYTES);
        oversized_nested.extend_from_slice(
            &u32::try_from(MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES + 1)
                .unwrap()
                .to_le_bytes(),
        );
        oversized_nested.resize(
            SERVICE_WIRE_HEADER_BYTES + 4 + MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES + 1,
            0,
        );
        assert_eq!(
            FinalizedCatalogMutationReceipt::decode(&oversized_nested),
            Err(DecodeError::LimitExceeded)
        );

        let mut malformed_nested = receipt.encode();
        let nested_magic = SERVICE_WIRE_HEADER_BYTES + 4;
        malformed_nested[nested_magic] ^= 0xff;
        assert_eq!(
            FinalizedCatalogMutationReceipt::decode(&malformed_nested),
            Err(DecodeError::InvalidTag)
        );
    }
}
