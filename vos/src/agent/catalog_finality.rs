//! Authority-finalized facts for registry mutations.
//!
//! A Merge catalog must not reinterpret an old author signature against its
//! current role state. Instead, the authority finalizes one exact mutation
//! intent and result under a historical committee. The resulting receipt is
//! immutable data: decoding proves only canonical shape, while [`verify`](
//! FinalizedCatalogMutationReceipt::verify) requires the independently
//! authenticated committee which was live for the receipt's QC epoch.
//!
//! This is an evidence envelope, not a complete catalog state machine. It does
//! not authenticate credentials, reserve operation IDs or global sequences,
//! compare the expected catalog head, advance authority state, compute the
//! projected fact/result, or apply registry rows. Integration must perform
//! those transitions and exactly recompute every commitment before
//! materializing Merge state.

use alloc::vec::Vec;
use core::fmt;

use super::committee::{
    AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee, AuthorityCommitteeError,
    AuthorityQuorumCertificate, MAX_AUTHORITY_QC_WIRE_BYTES,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{CapabilityId, CredentialId, Hash, OperationId, PrincipalId, SpaceId};

const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;
const CATALOG_MUTATION_INTENT_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/catalog-mutation-intent/v1";

/// Exact wire size of one [`CatalogBinding`].
pub const CATALOG_BINDING_WIRE_BYTES: usize = SERVICE_WIRE_HEADER_BYTES + 3 * 32;
/// Exact wire size of one [`CatalogMutationIntent`].
pub const CATALOG_MUTATION_INTENT_WIRE_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 4 + CATALOG_BINDING_WIRE_BYTES + 7 * 32;
/// Maximum complete finalized fact, including its nested intent envelope.
pub const MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES: usize =
    SERVICE_WIRE_HEADER_BYTES + 4 + CATALOG_MUTATION_INTENT_WIRE_BYTES + 3 * 32 + 8;
/// Maximum complete finalized receipt, including its bounded authority QC.
pub const MAX_FINALIZED_CATALOG_MUTATION_RECEIPT_BYTES: usize = SERVICE_WIRE_HEADER_BYTES
    + 4
    + MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES
    + 4
    + MAX_AUTHORITY_QC_WIRE_BYTES;

/// Genesis-scoped identity of one catalog and its external authority.
///
/// `catalog_binding` identifies the exact catalog incarnation independently
/// of its changing head. It and `authority_binding` are trust roots supplied
/// by integration; a receipt never selects either one for its verifier.
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
    const MAGIC: [u8; 4] = *b"ACBG";

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

/// Exact authority admission and CAS fact proposed for catalog finalization.
///
/// `authority_generation` is the authenticated commitment of the complete
/// authority state from which this decision was made. It is deliberately
/// distinct from the QC's numeric committee epoch and from `sequence`, the
/// authority-global finalization position. `expected_catalog_commitment` is
/// the compare-and-swap head, while `fact` commits the exact canonical
/// mutation fact submitted for projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogMutationIntent {
    binding: CatalogBinding,
    authority_generation: Hash,
    expected_catalog_commitment: Hash,
    author: PrincipalId,
    credential: CredentialId,
    required_capability: CapabilityId,
    operation_id: OperationId,
    fact: Hash,
}

impl CatalogMutationIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: CatalogBinding,
        authority_generation: Hash,
        expected_catalog_commitment: Hash,
        author: PrincipalId,
        credential: CredentialId,
        required_capability: CapabilityId,
        operation_id: OperationId,
        fact: Hash,
    ) -> Result<Self, CatalogFinalityError> {
        let intent = Self {
            binding,
            authority_generation,
            expected_catalog_commitment,
            author,
            credential,
            required_capability,
            operation_id,
            fact,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub const fn binding(&self) -> CatalogBinding {
        self.binding
    }

    pub const fn authority_generation(&self) -> Hash {
        self.authority_generation
    }

    pub const fn expected_catalog_commitment(&self) -> Hash {
        self.expected_catalog_commitment
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

    pub const fn fact(&self) -> Hash {
        self.fact
    }

    /// Stable commitment of the complete canonical mutation intent.
    pub fn commitment(&self) -> Hash {
        Hash::digest(CATALOG_MUTATION_INTENT_COMMITMENT_DOMAIN, &[&self.encode()])
    }

    pub fn validate(&self) -> Result<(), CatalogFinalityError> {
        self.binding.validate()?;
        if self.authority_generation == Hash::ZERO
            || self.expected_catalog_commitment == Hash::ZERO
            || self.author == PrincipalId::ZERO
            || self.credential == CredentialId::ZERO
            || self.required_capability == CapabilityId::ZERO
            || self.operation_id == OperationId::ZERO
            || self.fact == Hash::ZERO
        {
            return Err(CatalogFinalityError::InvalidIntent);
        }
        enforce_encoded_bound(self, CATALOG_MUTATION_INTENT_WIRE_BYTES)
    }
}

impl ServiceWire for CatalogMutationIntent {
    const MAGIC: [u8; 4] = *b"ACMI";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.binding.encode());
        encoder.fixed(&self.authority_generation.0);
        encoder.fixed(&self.expected_catalog_commitment.0);
        encoder.fixed(&self.author.0);
        encoder.fixed(&self.credential.0);
        encoder.fixed(&self.required_capability.0);
        encoder.fixed(&self.operation_id.0);
        encoder.fixed(&self.fact.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, CATALOG_MUTATION_INTENT_WIRE_BYTES)?;
        let intent = Self {
            binding: decode_nested(decoder, CATALOG_BINDING_WIRE_BYTES)?,
            authority_generation: Hash(decoder.fixed()?),
            expected_catalog_commitment: Hash(decoder.fixed()?),
            author: PrincipalId(decoder.fixed()?),
            credential: CredentialId(decoder.fixed()?),
            required_capability: CapabilityId(decoder.fixed()?),
            operation_id: OperationId(decoder.fixed()?),
            fact: Hash(decoder.fixed()?),
        };
        intent.validate().map_err(map_decode_error)?;
        Ok(intent)
    }
}

/// Exact projected catalog fact and result certified at one global sequence.
///
/// The Catalog-domain claim commits this complete wire, including the
/// input generation/head/mutation and the resulting authority generation,
/// projected fact, result, and numeric sequence. This type does not compute or
/// apply that transition; integration must do so before requesting signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedCatalogMutationFact {
    intent: CatalogMutationIntent,
    resulting_authority_generation: Hash,
    fact_commitment: Hash,
    result_commitment: Hash,
    sequence: u64,
}

impl FinalizedCatalogMutationFact {
    pub fn new(
        intent: CatalogMutationIntent,
        resulting_authority_generation: Hash,
        fact_commitment: Hash,
        result_commitment: Hash,
        sequence: u64,
    ) -> Result<Self, CatalogFinalityError> {
        let fact = Self {
            intent,
            resulting_authority_generation,
            fact_commitment,
            result_commitment,
            sequence,
        };
        fact.validate()?;
        Ok(fact)
    }

    pub const fn intent(&self) -> CatalogMutationIntent {
        self.intent
    }

    pub const fn resulting_authority_generation(&self) -> Hash {
        self.resulting_authority_generation
    }

    pub const fn fact_commitment(&self) -> Hash {
        self.fact_commitment
    }

    pub const fn result_commitment(&self) -> Hash {
        self.result_commitment
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Exact Catalog-domain authority claim which a quorum must sign.
    pub fn authority_claim(&self) -> AuthorityClaimCommitment {
        AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::Catalog,
            self.sequence,
            &self.encode(),
        )
    }

    pub fn validate(&self) -> Result<(), CatalogFinalityError> {
        self.intent.validate()?;
        if self.resulting_authority_generation == Hash::ZERO
            || self.fact_commitment == Hash::ZERO
            || self.result_commitment == Hash::ZERO
            || self.sequence == 0
        {
            return Err(CatalogFinalityError::InvalidFact);
        }
        enforce_encoded_bound(self, MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES)
    }
}

impl ServiceWire for FinalizedCatalogMutationFact {
    const MAGIC: [u8; 4] = *b"ACMF";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.intent.encode());
        encoder.fixed(&self.resulting_authority_generation.0);
        encoder.fixed(&self.fact_commitment.0);
        encoder.fixed(&self.result_commitment.0);
        encoder.u64(self.sequence);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_bound(decoder, MAX_FINALIZED_CATALOG_MUTATION_FACT_BYTES)?;
        let fact = Self {
            intent: decode_nested(decoder, CATALOG_MUTATION_INTENT_WIRE_BYTES)?,
            resulting_authority_generation: Hash(decoder.fixed()?),
            fact_commitment: Hash(decoder.fixed()?),
            result_commitment: Hash(decoder.fixed()?),
            sequence: decoder.u64()?,
        };
        fact.validate().map_err(map_decode_error)?;
        Ok(fact)
    }
}

/// Quorum-certified finalization of one exact registry mutation result.
///
/// Construction verifies the QC against an independently authenticated
/// historical committee. Decoding alone only establishes canonical bounded
/// shape; consumers must call [`Self::verify`] with the committee selected by
/// trusted history for this receipt's QC epoch, never with a current-role
/// lookup or a committee selected by the receipt itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedCatalogMutationReceipt {
    fact: FinalizedCatalogMutationFact,
    certificate: AuthorityQuorumCertificate,
}

impl FinalizedCatalogMutationReceipt {
    pub fn new(
        fact: FinalizedCatalogMutationFact,
        certificate: AuthorityQuorumCertificate,
        historical_committee: &AuthorityCommittee,
    ) -> Result<Self, CatalogFinalityError> {
        let receipt = Self { fact, certificate };
        receipt.verify(historical_committee)?;
        Ok(receipt)
    }

    pub const fn fact(&self) -> FinalizedCatalogMutationFact {
        self.fact
    }

    pub const fn certificate(&self) -> &AuthorityQuorumCertificate {
        &self.certificate
    }

    /// Verify against the independently authenticated committee for the
    /// certificate epoch. This never consults current catalog roles.
    pub fn verify(
        &self,
        historical_committee: &AuthorityCommittee,
    ) -> Result<(), CatalogFinalityError> {
        self.validate_shape()?;
        let binding = self.fact.intent.binding;
        if historical_committee.space() != binding.space {
            return Err(CatalogFinalityError::WrongSpace);
        }
        if historical_committee.authority_binding() != binding.authority_binding {
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
    const MAGIC: [u8; 4] = *b"ACMR";

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

    fn binding() -> CatalogBinding {
        CatalogBinding::new(SpaceId([0x11; 32]), Hash([0x12; 32]), Hash([0x13; 32])).unwrap()
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
            Hash([0x1a; 32]),
        )
        .unwrap()
    }

    fn intent_mutations(valid: CatalogMutationIntent) -> [CatalogMutationIntent; 10] {
        [
            CatalogMutationIntent {
                binding: CatalogBinding {
                    space: SpaceId([0x31; 32]),
                    ..valid.binding
                },
                ..valid
            },
            CatalogMutationIntent {
                binding: CatalogBinding {
                    catalog_binding: Hash([0x32; 32]),
                    ..valid.binding
                },
                ..valid
            },
            CatalogMutationIntent {
                binding: CatalogBinding {
                    authority_binding: Hash([0x33; 32]),
                    ..valid.binding
                },
                ..valid
            },
            CatalogMutationIntent {
                authority_generation: Hash([0x34; 32]),
                ..valid
            },
            CatalogMutationIntent {
                expected_catalog_commitment: Hash([0x35; 32]),
                ..valid
            },
            CatalogMutationIntent {
                author: PrincipalId([0x36; 32]),
                ..valid
            },
            CatalogMutationIntent {
                credential: CredentialId([0x37; 32]),
                ..valid
            },
            CatalogMutationIntent {
                required_capability: CapabilityId([0x38; 32]),
                ..valid
            },
            CatalogMutationIntent {
                operation_id: OperationId([0x39; 32]),
                ..valid
            },
            CatalogMutationIntent {
                fact: Hash([0x3a; 32]),
                ..valid
            },
        ]
    }

    fn signing_keys(seed: u8) -> Vec<SigningKey> {
        (0..3)
            .map(|offset| SigningKey::from_bytes(&[seed.wrapping_add(offset); 32]))
            .collect()
    }

    fn committee_with_roles(
        space: SpaceId,
        binding: Hash,
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
        AuthorityCommittee::new(space, binding, epoch, previous, members).unwrap()
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
        let fact = FinalizedCatalogMutationFact::new(
            intent(),
            Hash([0x1b; 32]),
            Hash([0x1c; 32]),
            Hash([0x1d; 32]),
            7,
        )
        .unwrap();
        let keys = signing_keys(0x21);
        let committee = test_committee(fact.intent().binding(), &keys);
        let certificate = certificate(&committee, fact.authority_claim(), &keys[..2]);
        let receipt = FinalizedCatalogMutationReceipt::new(fact, certificate, &committee).unwrap();
        (fact, committee, keys, receipt)
    }

    #[test]
    fn canonical_round_trips_commitments_and_verifies_historical_qc() {
        let (fact, committee, _, receipt) = fixture();
        let intent = fact.intent();
        assert_eq!(binding().encode().len(), CATALOG_BINDING_WIRE_BYTES);
        assert_eq!(CatalogBinding::decode(&binding().encode()), Ok(binding()));
        assert_eq!(intent.encode().len(), CATALOG_MUTATION_INTENT_WIRE_BYTES);
        let decoded_intent = CatalogMutationIntent::decode(&intent.encode()).unwrap();
        assert_eq!(decoded_intent, intent);
        assert_eq!(decoded_intent.commitment(), intent.commitment());
        assert_eq!(
            intent.commitment(),
            Hash::digest(
                CATALOG_MUTATION_INTENT_COMMITMENT_DOMAIN,
                &[&intent.encode()]
            )
        );
        assert_eq!(
            FinalizedCatalogMutationFact::decode(&fact.encode()),
            Ok(fact)
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
            fact.authority_claim(),
            AuthorityClaimCommitment::of_bytes(
                AuthorityClaimDomain::Catalog,
                fact.sequence(),
                &fact.encode(),
            )
        );
        assert_eq!(receipt.verify(&committee), Ok(()));
        assert!(receipt.encode().len() <= MAX_FINALIZED_CATALOG_MUTATION_RECEIPT_BYTES);
    }

    #[test]
    fn intent_commitment_binds_every_typed_selector_and_fact() {
        let valid = intent();
        for mutated in intent_mutations(valid) {
            assert_ne!(mutated.commitment(), valid.commitment());
        }
    }

    #[test]
    fn every_zero_catalog_binding_field_is_rejected_by_shape_and_decode() {
        let valid = binding();
        for invalid in [
            CatalogBinding {
                space: SpaceId::ZERO,
                ..valid
            },
            CatalogBinding {
                catalog_binding: Hash::ZERO,
                ..valid
            },
            CatalogBinding {
                authority_binding: Hash::ZERO,
                ..valid
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
    }

    #[test]
    fn every_zero_intent_selector_is_rejected_by_shape_and_decode() {
        let valid = intent();
        let candidates = [
            CatalogMutationIntent {
                authority_generation: Hash::ZERO,
                ..valid
            },
            CatalogMutationIntent {
                expected_catalog_commitment: Hash::ZERO,
                ..valid
            },
            CatalogMutationIntent {
                author: PrincipalId::ZERO,
                ..valid
            },
            CatalogMutationIntent {
                credential: CredentialId::ZERO,
                ..valid
            },
            CatalogMutationIntent {
                required_capability: CapabilityId::ZERO,
                ..valid
            },
            CatalogMutationIntent {
                operation_id: OperationId::ZERO,
                ..valid
            },
            CatalogMutationIntent {
                fact: Hash::ZERO,
                ..valid
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
    fn every_zero_finalized_output_or_sequence_is_rejected_by_shape_and_decode() {
        let valid = FinalizedCatalogMutationFact::new(
            intent(),
            Hash([0x41; 32]),
            Hash([0x42; 32]),
            Hash([0x43; 32]),
            9,
        )
        .unwrap();
        for invalid in [
            FinalizedCatalogMutationFact {
                resulting_authority_generation: Hash::ZERO,
                ..valid
            },
            FinalizedCatalogMutationFact {
                fact_commitment: Hash::ZERO,
                ..valid
            },
            FinalizedCatalogMutationFact {
                result_commitment: Hash::ZERO,
                ..valid
            },
            FinalizedCatalogMutationFact {
                sequence: 0,
                ..valid
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
    fn qc_claim_changes_for_every_certified_fact_field() {
        let (valid, committee, _, receipt) = fixture();
        let original_claim = valid.authority_claim();
        let original_certificate = receipt.certificate().clone();
        let base = valid.intent();
        let mut mutations = intent_mutations(base)
            .map(|intent| FinalizedCatalogMutationFact { intent, ..valid })
            .to_vec();
        mutations.extend([
            FinalizedCatalogMutationFact {
                resulting_authority_generation: Hash([0x51; 32]),
                ..valid
            },
            FinalizedCatalogMutationFact {
                fact_commitment: Hash([0x52; 32]),
                ..valid
            },
            FinalizedCatalogMutationFact {
                result_commitment: Hash([0x53; 32]),
                ..valid
            },
            FinalizedCatalogMutationFact {
                sequence: valid.sequence() + 1,
                ..valid
            },
        ]);
        for mutated in mutations {
            assert_ne!(mutated.authority_claim(), original_claim);
            let stale = FinalizedCatalogMutationReceipt {
                fact: mutated,
                certificate: original_certificate.clone(),
            };
            assert_eq!(
                stale.verify(&committee),
                Err(CatalogFinalityError::InvalidReceipt)
            );
        }
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
                fact,
                certificate: certificate(&committee, claim, &keys[..2]),
            };
            assert_eq!(
                receipt.verify(&committee),
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
        let foreign_space = committee_with_roles(
            SpaceId([0x50; 32]),
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
            receipt.verify(&foreign_space),
            Err(CatalogFinalityError::WrongSpace)
        );

        let foreign_binding = test_committee(
            CatalogBinding {
                authority_binding: Hash([0x51; 32]),
                ..fact.intent().binding()
            },
            &keys,
        );
        assert_eq!(
            receipt.verify(&foreign_binding),
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
            receipt.verify(&wrong_epoch),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::WrongEpoch
            ))
        );

        let foreign_keys = signing_keys(0x61);
        let wrong_roster = test_committee(fact.intent().binding(), &foreign_keys);
        assert_eq!(
            receipt.verify(&wrong_roster),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::WrongCommittee
            ))
        );
    }

    #[test]
    fn quorum_verification_rejects_insufficient_unknown_observer_and_bad_signatures() {
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
                fact,
                certificate: insufficient,
            }
            .verify(&committee),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::InsufficientQuorum
            ))
        );

        let unknown_key = SigningKey::from_bytes(&[0x71; 32]);
        let mut unknown = signatures(&committee, claim, &keys[..1]);
        unknown.extend(signatures(&committee, claim, &[unknown_key]));
        unknown.sort_by_key(AuthoritySignature::signer);
        let unknown = AuthorityQuorumCertificate::new(&committee, claim, unknown).unwrap();
        assert_eq!(
            FinalizedCatalogMutationReceipt {
                fact,
                certificate: unknown
            }
            .verify(&committee),
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
                fact,
                certificate: observer_qc
            }
            .verify(&observer_committee),
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
                certificate: bad
            }
            .verify(&committee),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::InvalidSignature
            ))
        );
    }

    #[test]
    fn unverified_receipts_cannot_be_constructed_through_public_constructor() {
        let (fact, committee, keys, _) = fixture();
        let insufficient = AuthorityQuorumCertificate::new(
            &committee,
            fact.authority_claim(),
            signatures(&committee, fact.authority_claim(), &keys[..1]),
        )
        .unwrap();
        assert_eq!(
            FinalizedCatalogMutationReceipt::new(fact, insufficient, &committee),
            Err(CatalogFinalityError::Authority(
                AuthorityCommitteeError::InsufficientQuorum
            ))
        );
    }

    #[test]
    fn wire_bounds_trailing_bytes_and_malformed_nested_envelopes_fail_closed() {
        let (fact, _, _, receipt) = fixture();

        let mut oversized_binding = binding().encode();
        oversized_binding.push(0);
        assert_eq!(
            CatalogBinding::decode(&oversized_binding),
            Err(DecodeError::LimitExceeded)
        );

        let mut oversized_intent = intent().encode();
        oversized_intent.push(0);
        assert_eq!(
            CatalogMutationIntent::decode(&oversized_intent),
            Err(DecodeError::LimitExceeded)
        );

        let mut oversized_fact = fact.encode();
        oversized_fact.push(0);
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
