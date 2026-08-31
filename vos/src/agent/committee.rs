//! Canonical authority committees and quorum certificates.
//!
//! Authority signing keys are deliberately independent from node transport
//! identities. A committee member binds one complete [`NodeId`] to one raw
//! Ed25519 authority key, while [`AuthoritySignerId`] is derived from that raw
//! key in a dedicated domain. Nothing in this module accepts a `PeerId`, a
//! compact routing prefix, or a package-producer key as authority evidence.
//!
//! Certificates never select their own trust root. Callers must verify them
//! against an independently obtained [`AuthorityCommittee`] or, for the first
//! system-Agent genesis, the crate-sealed [`TrustedRootAnchor`]. This module
//! exposes neither key generation nor signing; it only defines canonical
//! messages and verifies externally produced signatures.

use alloc::vec::Vec;
use core::fmt;

use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, Hash, NodeId, SpaceId};

/// Hard protocol bound for voters and observers in one authority committee.
pub const MAX_AUTHORITY_COMMITTEE_MEMBERS: usize = 256;
/// A QC cannot contain more signatures than the bounded committee roster.
pub const MAX_AUTHORITY_QC_SIGNATURES: usize = MAX_AUTHORITY_COMMITTEE_MEMBERS;
pub const AUTHORITY_ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const AUTHORITY_ED25519_SIGNATURE_BYTES: usize = 64;

/// Maximum complete root-anchor record, including its service-wire header.
pub const MAX_ROOT_ANCHOR_RECORD_BYTES: usize = 32 * 1024;
/// Maximum complete authority QC, including its service-wire header.
pub const MAX_AUTHORITY_QC_WIRE_BYTES: usize = 32 * 1024;
/// Maximum complete system-Agent genesis evidence record.
pub const MAX_SYSTEM_GENESIS_EVIDENCE_BYTES: usize = 40 * 1024;
/// Maximum complete system-Agent genesis admission record.
pub const MAX_SYSTEM_GENESIS_ADMISSION_BYTES: usize = 1024;

const MAX_AUTHORITY_ROTATION_WIRE_BYTES: usize = 4 * 1024;
const MAX_SYSTEM_GENESIS_CLAIM_WIRE_BYTES: usize = 4 * 1024;
const SERVICE_WIRE_HEADER_BYTES: usize = 4 + 32;

const SIGNER_ID_DOMAIN: &[u8] = b"vos/agent/authority-signer/v1";
const COMMITTEE_COMMITMENT_DOMAIN: &[u8] = b"vos/agent/authority-committee/v1";
const CLAIM_HASH_DOMAIN: &[u8] = b"vos/agent/authority-claim/v1";
const QC_MESSAGE_DOMAIN: &[u8] = b"vos/agent/authority-qc/v1";
const ROOT_ANCHOR_ID_DOMAIN: &[u8] = b"vos/agent/root-anchor-record/v1";
const ROOT_ANCHOR_CONFIG_DOMAIN: &[u8] = b"vos/agent/root-anchor-config/v1";
const GENESIS_INTENT_DOMAIN: &[u8] = b"vos/agent/system-genesis-intent/v1";
const GENESIS_EVIDENCE_DOMAIN: &[u8] = b"vos/agent/system-genesis-evidence/v1";
const GENESIS_ADMISSION_DOMAIN: &[u8] = b"vos/agent/system-genesis-admission/v1";

macro_rules! authority_id_type {
    ($name:ident, $label:literal) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0; 32]);

            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub const fn as_hash(self) -> Hash {
                Hash(self.0)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(value: [u8; 32]) -> Self {
                Self(value)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "("))?;
                for byte in &self.0[..4] {
                    write!(formatter, "{byte:02x}")?;
                }
                formatter.write_str("…)")
            }
        }
    };
}

authority_id_type!(RootAnchorId, "RootAnchorId");
authority_id_type!(RootAnchorConfigCommitment, "RootAnchorConfigCommitment");
authority_id_type!(GenesisIntentId, "GenesisIntentId");
authority_id_type!(SystemAgentGenesisEvidenceId, "SystemAgentGenesisEvidenceId");
authority_id_type!(
    SystemAgentGenesisAdmissionId,
    "SystemAgentGenesisAdmissionId"
);

/// Stable identity of a certified authority signing key.
///
/// This is not a transport `NodeId` and is not derived from a libp2p public
/// key wrapper. It commits to the exact raw 32-byte Ed25519 authority key.
#[repr(transparent)]
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthoritySignerId([u8; 32]);

impl AuthoritySignerId {
    pub const ZERO: Self = Self([0; 32]);

    pub fn of_raw_ed25519(public_key: &[u8; AUTHORITY_ED25519_PUBLIC_KEY_BYTES]) -> Self {
        Self(Hash::digest(SIGNER_ID_DOMAIN, &[public_key]).0)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AuthoritySignerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthoritySignerId(")?;
        for byte in &self.0[..4] {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…)")
    }
}

/// Whether one certified authority key contributes to quorum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AuthorityMemberRole {
    Voter = 0,
    Observer = 1,
}

/// One authority identity certified to one exact replica node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityCommitteeMember {
    node: NodeId,
    signer: AuthoritySignerId,
    public_key: [u8; AUTHORITY_ED25519_PUBLIC_KEY_BYTES],
    role: AuthorityMemberRole,
}

impl AuthorityCommitteeMember {
    pub fn new(
        node: NodeId,
        public_key: [u8; AUTHORITY_ED25519_PUBLIC_KEY_BYTES],
        role: AuthorityMemberRole,
    ) -> Result<Self, AuthorityCommitteeError> {
        if node == NodeId::ZERO || public_key == [0; AUTHORITY_ED25519_PUBLIC_KEY_BYTES] {
            return Err(AuthorityCommitteeError::InvalidMember);
        }
        let member = Self {
            node,
            signer: AuthoritySignerId::of_raw_ed25519(&public_key),
            public_key,
            role,
        };
        member.validate()?;
        Ok(member)
    }

    pub const fn node(&self) -> NodeId {
        self.node
    }

    pub const fn signer(&self) -> AuthoritySignerId {
        self.signer
    }

    pub const fn public_key(&self) -> &[u8; AUTHORITY_ED25519_PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    pub const fn role(&self) -> AuthorityMemberRole {
        self.role
    }

    fn validate(&self) -> Result<(), AuthorityCommitteeError> {
        if self.node == NodeId::ZERO
            || self.public_key == [0; AUTHORITY_ED25519_PUBLIC_KEY_BYTES]
            || self.signer == AuthoritySignerId::ZERO
            || self.signer != AuthoritySignerId::of_raw_ed25519(&self.public_key)
        {
            return Err(AuthorityCommitteeError::InvalidMember);
        }
        Ok(())
    }
}

/// Immutable authority roster for one space and authority deployment.
///
/// Members are strictly sorted by signer identity. Both signer and full node
/// identities are unique. The quorum threshold is derived as `voters / 2 + 1`
/// and is never serialized or supplied by a caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityCommittee {
    space: SpaceId,
    authority_binding: Hash,
    epoch: u64,
    previous_committee: Option<Hash>,
    members: Vec<AuthorityCommitteeMember>,
}

impl AuthorityCommittee {
    pub fn new(
        space: SpaceId,
        authority_binding: Hash,
        epoch: u64,
        previous_committee: Option<Hash>,
        members: Vec<AuthorityCommitteeMember>,
    ) -> Result<Self, AuthorityCommitteeError> {
        let committee = Self {
            space,
            authority_binding,
            epoch,
            previous_committee,
            members,
        };
        committee.validate()?;
        Ok(committee)
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn previous_committee(&self) -> Option<Hash> {
        self.previous_committee
    }

    pub fn members(&self) -> &[AuthorityCommitteeMember] {
        &self.members
    }

    pub fn voter_count(&self) -> usize {
        self.members
            .iter()
            .filter(|member| member.role == AuthorityMemberRole::Voter)
            .count()
    }

    pub fn quorum_threshold(&self) -> usize {
        self.voter_count() / 2 + 1
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(COMMITTEE_COMMITMENT_DOMAIN, &[&self.encode()])
    }

    pub fn member(&self, signer: AuthoritySignerId) -> Option<&AuthorityCommitteeMember> {
        self.members
            .binary_search_by_key(&signer, AuthorityCommitteeMember::signer)
            .ok()
            .map(|index| &self.members[index])
    }

    pub fn validate(&self) -> Result<(), AuthorityCommitteeError> {
        if self.space == SpaceId::ZERO || self.authority_binding == Hash::ZERO {
            return Err(AuthorityCommitteeError::InvalidBinding);
        }
        if self.epoch == 0 {
            return Err(AuthorityCommitteeError::InvalidEpoch);
        }
        match (self.epoch, self.previous_committee) {
            (1, None) => {}
            (1, Some(_)) | (_, None) => {
                return Err(AuthorityCommitteeError::InvalidPreviousCommittee);
            }
            (_, Some(previous)) if previous == Hash::ZERO => {
                return Err(AuthorityCommitteeError::InvalidPreviousCommittee);
            }
            (_, Some(_)) => {}
        }
        if self.members.is_empty() {
            return Err(AuthorityCommitteeError::NoVoters);
        }
        if self.members.len() > MAX_AUTHORITY_COMMITTEE_MEMBERS {
            return Err(AuthorityCommitteeError::CommitteeTooLarge);
        }

        let mut voters = 0usize;
        for (index, member) in self.members.iter().enumerate() {
            member.validate()?;
            if member.role == AuthorityMemberRole::Voter {
                voters += 1;
            }
            if let Some(previous) = index.checked_sub(1).map(|index| &self.members[index]) {
                if previous.signer >= member.signer {
                    return Err(AuthorityCommitteeError::NonCanonicalOrder);
                }
            }
            if self.members[..index]
                .iter()
                .any(|existing| existing.node == member.node)
            {
                return Err(AuthorityCommitteeError::DuplicateNode);
            }
        }
        if voters == 0 {
            return Err(AuthorityCommitteeError::NoVoters);
        }
        Ok(())
    }
}

impl ServiceWire for AuthorityCommittee {
    const MAGIC: [u8; 4] = *b"AGCM";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.authority_binding.0);
        encoder.u64(self.epoch);
        encoder.option(&self.previous_committee, |encoder, previous| {
            encoder.fixed(&previous.0)
        });
        encoder.u32(self.members.len() as u32);
        for member in &self.members {
            encode_member(&mut encoder, member);
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let space = SpaceId(decoder.fixed()?);
        let authority_binding = Hash(decoder.fixed()?);
        let epoch = decoder.u64()?;
        let previous_committee = decoder.option(|decoder| Ok(Hash(decoder.fixed()?)))?;
        let len = decoder.u32()? as usize;
        if len > MAX_AUTHORITY_COMMITTEE_MEMBERS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut members = Vec::new();
        members
            .try_reserve_exact(len)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..len {
            members.push(decode_member(decoder)?);
        }
        Self::new(space, authority_binding, epoch, previous_committee, members)
            .map_err(canonical_decode_error)
    }
}

/// Domain of one authority-certified payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AuthorityClaimDomain {
    Lifecycle = 0,
    Invocation = 1,
    SystemAgentGenesis = 2,
    CommitteeRotation = 3,
    Catalog = 4,
    NodeControl = 5,
}

/// Exact domain-separated claim named by a QC.
///
/// `payload_commitment` is the commitment of the complete operation-specific
/// wire. [`Self::claim_hash`] additionally binds its semantic domain and
/// monotone authority sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityClaimCommitment {
    domain: AuthorityClaimDomain,
    sequence: u64,
    payload_commitment: Hash,
}

impl AuthorityClaimCommitment {
    pub fn of_bytes(domain: AuthorityClaimDomain, sequence: u64, payload: &[u8]) -> Self {
        Self {
            domain,
            sequence,
            payload_commitment: Hash::digest(b"vos/agent/authority-payload/v1", &[payload]),
        }
    }

    pub fn from_payload_commitment(
        domain: AuthorityClaimDomain,
        sequence: u64,
        payload_commitment: Hash,
    ) -> Result<Self, AuthorityCommitteeError> {
        let claim = Self {
            domain,
            sequence,
            payload_commitment,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub const fn domain(&self) -> AuthorityClaimDomain {
        self.domain
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn payload_commitment(&self) -> Hash {
        self.payload_commitment
    }

    pub fn claim_hash(&self) -> Hash {
        Hash::digest(
            CLAIM_HASH_DOMAIN,
            &[
                &[self.domain as u8],
                &self.sequence.to_le_bytes(),
                &self.payload_commitment.0,
            ],
        )
    }

    fn validate(&self) -> Result<(), AuthorityCommitteeError> {
        if self.sequence == 0 || self.payload_commitment == Hash::ZERO {
            return Err(AuthorityCommitteeError::InvalidClaim);
        }
        Ok(())
    }
}

/// One canonical authority signature. Signature lists are strictly ordered by
/// signer identity, which makes duplicate or equivocal roster entries fail at
/// the decoding boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritySignature {
    signer: AuthoritySignerId,
    signature: [u8; AUTHORITY_ED25519_SIGNATURE_BYTES],
}

impl AuthoritySignature {
    pub fn new(
        signer: AuthoritySignerId,
        signature: [u8; AUTHORITY_ED25519_SIGNATURE_BYTES],
    ) -> Result<Self, AuthorityCommitteeError> {
        if signer == AuthoritySignerId::ZERO {
            return Err(AuthorityCommitteeError::InvalidSigner);
        }
        Ok(Self { signer, signature })
    }

    pub const fn signer(&self) -> AuthoritySignerId {
        self.signer
    }

    pub const fn signature(&self) -> &[u8; AUTHORITY_ED25519_SIGNATURE_BYTES] {
        &self.signature
    }
}

/// Majority certificate for one exact authority claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityQuorumCertificate {
    authority_binding: Hash,
    epoch: u64,
    committee: Hash,
    claim: AuthorityClaimCommitment,
    signatures: Vec<AuthoritySignature>,
}

impl AuthorityQuorumCertificate {
    pub fn new(
        committee: &AuthorityCommittee,
        claim: AuthorityClaimCommitment,
        signatures: Vec<AuthoritySignature>,
    ) -> Result<Self, AuthorityCommitteeError> {
        let certificate = Self {
            authority_binding: committee.authority_binding,
            epoch: committee.epoch,
            committee: committee.commitment(),
            claim,
            signatures,
        };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn committee(&self) -> Hash {
        self.committee
    }

    pub const fn claim(&self) -> AuthorityClaimCommitment {
        self.claim
    }

    pub fn signatures(&self) -> &[AuthoritySignature] {
        &self.signatures
    }

    /// Canonical hash signed by every QC member. Integrators give these bytes
    /// to independently held authority keys; this module never holds a secret
    /// key and deliberately has no signing convenience API.
    pub fn signing_message(
        authority_binding: Hash,
        epoch: u64,
        committee: Hash,
        claim: AuthorityClaimCommitment,
    ) -> Hash {
        Hash::digest(
            QC_MESSAGE_DOMAIN,
            &[
                &authority_binding.0,
                &epoch.to_le_bytes(),
                &committee.0,
                &claim.claim_hash().0,
            ],
        )
    }

    pub fn message(&self) -> Hash {
        Self::signing_message(
            self.authority_binding,
            self.epoch,
            self.committee,
            self.claim,
        )
    }

    /// Verify against an independently trusted committee and an exact
    /// expected claim. No committee or claim embedded in the certificate is
    /// accepted as the verification policy.
    pub fn verify(
        &self,
        trusted_committee: &AuthorityCommittee,
        expected_claim: AuthorityClaimCommitment,
    ) -> Result<(), AuthorityCommitteeError> {
        trusted_committee.validate()?;
        self.validate_shape()?;
        if self.authority_binding != trusted_committee.authority_binding {
            return Err(AuthorityCommitteeError::WrongAuthorityBinding);
        }
        if self.epoch != trusted_committee.epoch {
            return Err(AuthorityCommitteeError::WrongEpoch);
        }
        if self.committee != trusted_committee.commitment() {
            return Err(AuthorityCommitteeError::WrongCommittee);
        }
        if self.claim != expected_claim {
            return Err(AuthorityCommitteeError::WrongClaim);
        }
        if self.signatures.len() < trusted_committee.quorum_threshold() {
            return Err(AuthorityCommitteeError::InsufficientQuorum);
        }

        let message = self.message();
        for authority_signature in &self.signatures {
            let member = trusted_committee
                .member(authority_signature.signer)
                .ok_or(AuthorityCommitteeError::UnknownSigner)?;
            if member.role != AuthorityMemberRole::Voter {
                return Err(AuthorityCommitteeError::ObserverSignature);
            }
            if !verify_ed25519(
                &member.public_key,
                &message.0,
                &authority_signature.signature,
            ) {
                return Err(AuthorityCommitteeError::InvalidSignature);
            }
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AuthorityCommitteeError> {
        if self.authority_binding == Hash::ZERO || self.committee == Hash::ZERO {
            return Err(AuthorityCommitteeError::InvalidBinding);
        }
        if self.epoch == 0 {
            return Err(AuthorityCommitteeError::InvalidEpoch);
        }
        self.claim.validate()?;
        if self.signatures.is_empty() {
            return Err(AuthorityCommitteeError::InsufficientQuorum);
        }
        if self.signatures.len() > MAX_AUTHORITY_QC_SIGNATURES {
            return Err(AuthorityCommitteeError::CertificateTooLarge);
        }
        for (index, signature) in self.signatures.iter().enumerate() {
            if signature.signer == AuthoritySignerId::ZERO {
                return Err(AuthorityCommitteeError::InvalidSigner);
            }
            if let Some(previous) = index.checked_sub(1).map(|index| &self.signatures[index]) {
                if previous.signer >= signature.signer {
                    return Err(AuthorityCommitteeError::NonCanonicalOrder);
                }
            }
        }
        Ok(())
    }
}

impl ServiceWire for AuthorityQuorumCertificate {
    const MAGIC: [u8; 4] = *b"AGQC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.authority_binding.0);
        encoder.u64(self.epoch);
        encoder.fixed(&self.committee.0);
        encode_claim(&mut encoder, self.claim);
        encoder.u32(self.signatures.len() as u32);
        for signature in &self.signatures {
            encode_signature(&mut encoder, signature);
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_wire_bound(decoder, MAX_AUTHORITY_QC_WIRE_BYTES)?;
        let authority_binding = Hash(decoder.fixed()?);
        let epoch = decoder.u64()?;
        let committee = Hash(decoder.fixed()?);
        let claim = decode_claim(decoder)?;
        let len = decoder.u32()? as usize;
        if len > MAX_AUTHORITY_QC_SIGNATURES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut signatures = Vec::new();
        signatures
            .try_reserve_exact(len)
            .map_err(|_| DecodeError::LimitExceeded)?;
        for _ in 0..len {
            signatures.push(decode_signature(decoder)?);
        }
        let certificate = Self {
            authority_binding,
            epoch,
            committee,
            claim,
            signatures,
        };
        certificate
            .validate_shape()
            .map_err(canonical_decode_error)?;
        Ok(certificate)
    }
}

/// Exact transition jointly certified by the retiring and incoming
/// committees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityCommitteeRotation {
    space: SpaceId,
    authority_binding: Hash,
    old_epoch: u64,
    old_committee: Hash,
    new_epoch: u64,
    new_committee: Hash,
    rotation_sequence: u64,
    first_sequence: u64,
}

impl AuthorityCommitteeRotation {
    pub fn new(
        old: &AuthorityCommittee,
        new: &AuthorityCommittee,
        rotation_sequence: u64,
        first_sequence: u64,
    ) -> Result<Self, AuthorityCommitteeError> {
        old.validate()?;
        new.validate()?;
        let transition = Self {
            space: old.space,
            authority_binding: old.authority_binding,
            old_epoch: old.epoch,
            old_committee: old.commitment(),
            new_epoch: new.epoch,
            new_committee: new.commitment(),
            rotation_sequence,
            first_sequence,
        };
        transition.validate_against(old, new)?;
        Ok(transition)
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub const fn old_epoch(&self) -> u64 {
        self.old_epoch
    }

    pub const fn old_committee(&self) -> Hash {
        self.old_committee
    }

    pub const fn new_epoch(&self) -> u64 {
        self.new_epoch
    }

    pub const fn new_committee(&self) -> Hash {
        self.new_committee
    }

    pub const fn rotation_sequence(&self) -> u64 {
        self.rotation_sequence
    }

    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    pub fn claim(&self) -> AuthorityClaimCommitment {
        AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::CommitteeRotation,
            self.rotation_sequence,
            &self.encode(),
        )
    }

    pub fn validate_against(
        &self,
        old: &AuthorityCommittee,
        new: &AuthorityCommittee,
    ) -> Result<(), AuthorityCommitteeError> {
        old.validate()?;
        new.validate()?;
        if self.space == SpaceId::ZERO
            || self.authority_binding == Hash::ZERO
            || self.space != old.space
            || self.space != new.space
            || self.authority_binding != old.authority_binding
            || self.authority_binding != new.authority_binding
        {
            return Err(AuthorityCommitteeError::WrongAuthorityBinding);
        }
        if self.old_epoch != old.epoch
            || self.new_epoch != new.epoch
            || self.old_epoch.checked_add(1) != Some(self.new_epoch)
        {
            return Err(AuthorityCommitteeError::InvalidRotationEpoch);
        }
        if self.old_committee != old.commitment()
            || self.new_committee != new.commitment()
            || new.previous_committee != Some(self.old_committee)
        {
            return Err(AuthorityCommitteeError::InvalidRotationLink);
        }
        if self.rotation_sequence == 0 || self.first_sequence <= self.rotation_sequence {
            return Err(AuthorityCommitteeError::InvalidRotationSequence);
        }
        Ok(())
    }
}

impl ServiceWire for AuthorityCommitteeRotation {
    const MAGIC: [u8; 4] = *b"AGCR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.authority_binding.0);
        encoder.u64(self.old_epoch);
        encoder.fixed(&self.old_committee.0);
        encoder.u64(self.new_epoch);
        encoder.fixed(&self.new_committee.0);
        encoder.u64(self.rotation_sequence);
        encoder.u64(self.first_sequence);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let transition = Self {
            space: SpaceId(decoder.fixed()?),
            authority_binding: Hash(decoder.fixed()?),
            old_epoch: decoder.u64()?,
            old_committee: Hash(decoder.fixed()?),
            new_epoch: decoder.u64()?,
            new_committee: Hash(decoder.fixed()?),
            rotation_sequence: decoder.u64()?,
            first_sequence: decoder.u64()?,
        };
        if transition.space == SpaceId::ZERO
            || transition.authority_binding == Hash::ZERO
            || transition.old_epoch == 0
            || transition.old_epoch.checked_add(1) != Some(transition.new_epoch)
            || transition.old_committee == Hash::ZERO
            || transition.new_committee == Hash::ZERO
            || transition.rotation_sequence == 0
            || transition.first_sequence <= transition.rotation_sequence
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(transition)
    }
}

/// Joint old-majority/new-majority proof for one exact committee transition.
/// The incoming majority signatures also prove possession of the new voter
/// keys before the new epoch can become active; observer signatures are never
/// accepted in either half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JointAuthorityRotationCertificate {
    transition: AuthorityCommitteeRotation,
    old_certificate: AuthorityQuorumCertificate,
    new_certificate: AuthorityQuorumCertificate,
}

impl JointAuthorityRotationCertificate {
    pub fn new(
        transition: AuthorityCommitteeRotation,
        old_certificate: AuthorityQuorumCertificate,
        new_certificate: AuthorityQuorumCertificate,
    ) -> Result<Self, AuthorityCommitteeError> {
        let certificate = Self {
            transition,
            old_certificate,
            new_certificate,
        };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    pub const fn transition(&self) -> &AuthorityCommitteeRotation {
        &self.transition
    }

    pub const fn old_certificate(&self) -> &AuthorityQuorumCertificate {
        &self.old_certificate
    }

    pub const fn new_certificate(&self) -> &AuthorityQuorumCertificate {
        &self.new_certificate
    }

    pub fn verify(
        &self,
        old: &AuthorityCommittee,
        new: &AuthorityCommittee,
    ) -> Result<(), AuthorityCommitteeError> {
        self.validate_shape()?;
        self.transition.validate_against(old, new)?;
        let claim = self.transition.claim();
        self.old_certificate.verify(old, claim)?;
        self.new_certificate.verify(new, claim)?;
        Ok(())
    }

    /// Verify the exact first certificate admitted after rotation. The
    /// transition itself commits to this sequence, preventing reuse of an old
    /// epoch sequence under the incoming committee.
    pub fn verify_first_new_certificate(
        &self,
        old: &AuthorityCommittee,
        new: &AuthorityCommittee,
        first_certificate: &AuthorityQuorumCertificate,
        expected_claim: AuthorityClaimCommitment,
    ) -> Result<(), AuthorityCommitteeError> {
        self.verify(old, new)?;
        if expected_claim.sequence != self.transition.first_sequence
            || expected_claim.sequence <= self.transition.rotation_sequence
        {
            return Err(AuthorityCommitteeError::InvalidRotationSequence);
        }
        first_certificate.verify(new, expected_claim)
    }

    fn validate_shape(&self) -> Result<(), AuthorityCommitteeError> {
        let claim = self.transition.claim();
        if self.old_certificate.claim != claim || self.new_certificate.claim != claim {
            return Err(AuthorityCommitteeError::WrongClaim);
        }
        if self.old_certificate.authority_binding != self.transition.authority_binding
            || self.new_certificate.authority_binding != self.transition.authority_binding
        {
            return Err(AuthorityCommitteeError::WrongAuthorityBinding);
        }
        if self.old_certificate.epoch != self.transition.old_epoch
            || self.new_certificate.epoch != self.transition.new_epoch
        {
            return Err(AuthorityCommitteeError::WrongEpoch);
        }
        if self.old_certificate.committee != self.transition.old_committee
            || self.new_certificate.committee != self.transition.new_committee
        {
            return Err(AuthorityCommitteeError::WrongCommittee);
        }
        Ok(())
    }
}

impl ServiceWire for JointAuthorityRotationCertificate {
    const MAGIC: [u8; 4] = *b"AGJR";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.transition.encode());
        encoder.bytes(&self.old_certificate.encode());
        encoder.bytes(&self.new_certificate.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let transition = decode_nested_wire::<AuthorityCommitteeRotation>(
            decoder,
            MAX_AUTHORITY_ROTATION_WIRE_BYTES,
        )?;
        let old_certificate =
            decode_nested_wire::<AuthorityQuorumCertificate>(decoder, MAX_AUTHORITY_QC_WIRE_BYTES)?;
        let new_certificate =
            decode_nested_wire::<AuthorityQuorumCertificate>(decoder, MAX_AUTHORITY_QC_WIRE_BYTES)?;
        let certificate = Self {
            transition,
            old_certificate,
            new_certificate,
        };
        certificate
            .validate_shape()
            .map_err(canonical_decode_error)?;
        Ok(certificate)
    }
}

/// Durable, independently provisioned trust root for the first system Agent.
/// The record is public data; merely decoding or constructing one does not
/// make it trusted. Production trust is established only by exact daemon
/// configuration pins through [`TrustedRootAnchor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootAnchorRecord {
    config_version: u64,
    space: SpaceId,
    system_agent: AgentId,
    authority_binding: Hash,
    root_certification: Hash,
    initial_committee: AuthorityCommittee,
}

impl RootAnchorRecord {
    pub fn new(
        config_version: u64,
        space: SpaceId,
        system_agent: AgentId,
        authority_binding: Hash,
        root_certification: Hash,
        initial_committee: AuthorityCommittee,
    ) -> Result<Self, AuthorityCommitteeError> {
        let record = Self {
            config_version,
            space,
            system_agent,
            authority_binding,
            root_certification,
            initial_committee,
        };
        record.validate()?;
        Ok(record)
    }

    pub const fn config_version(&self) -> u64 {
        self.config_version
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn system_agent(&self) -> AgentId {
        self.system_agent
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub const fn root_certification(&self) -> Hash {
        self.root_certification
    }

    pub const fn initial_committee(&self) -> &AuthorityCommittee {
        &self.initial_committee
    }

    pub fn id(&self) -> RootAnchorId {
        RootAnchorId(Hash::digest(ROOT_ANCHOR_ID_DOMAIN, &[&self.encode()]).0)
    }

    pub fn config_commitment(&self) -> RootAnchorConfigCommitment {
        let id = self.id();
        RootAnchorConfigCommitment(
            Hash::digest(
                ROOT_ANCHOR_CONFIG_DOMAIN,
                &[&self.config_version.to_le_bytes(), id.as_bytes()],
            )
            .0,
        )
    }

    /// Validate canonical persisted root configuration. This does not make the
    /// record trusted; promotion still requires exact daemon pins.
    pub fn validate(&self) -> Result<(), AuthorityCommitteeError> {
        self.initial_committee.validate()?;
        if self.config_version == 0
            || self.space == SpaceId::ZERO
            || self.system_agent == AgentId::ZERO
            || self.authority_binding == Hash::ZERO
            || self.root_certification == Hash::ZERO
            || self.initial_committee.space != self.space
            || self.initial_committee.authority_binding != self.authority_binding
            || self.initial_committee.epoch != 1
            || self.initial_committee.previous_committee.is_some()
        {
            return Err(AuthorityCommitteeError::InvalidRootAnchor);
        }
        if self.encode().len() > MAX_ROOT_ANCHOR_RECORD_BYTES {
            return Err(AuthorityCommitteeError::RootAnchorTooLarge);
        }
        Ok(())
    }
}

impl ServiceWire for RootAnchorRecord {
    const MAGIC: [u8; 4] = *b"AGRA";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.u64(self.config_version);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.system_agent.0);
        encoder.fixed(&self.authority_binding.0);
        encoder.fixed(&self.root_certification.0);
        encoder.bytes(&self.initial_committee.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_wire_bound(decoder, MAX_ROOT_ANCHOR_RECORD_BYTES)?;
        let record = Self {
            config_version: decoder.u64()?,
            space: SpaceId(decoder.fixed()?),
            system_agent: AgentId(decoder.fixed()?),
            authority_binding: Hash(decoder.fixed()?),
            root_certification: Hash(decoder.fixed()?),
            initial_committee: decode_nested_wire::<AuthorityCommittee>(
                decoder,
                MAX_ROOT_ANCHOR_RECORD_BYTES,
            )?,
        };
        record.validate().map_err(canonical_decode_error)?;
        Ok(record)
    }
}

impl GenesisIntentId {
    /// Commit to the canonical runtime binding and the unauthenticated inner
    /// `LifecycleRequest::Create` operation. In particular, neither an
    /// `Authorized` wrapper nor its genesis evidence is part of this ID, so
    /// the later admission record can be inserted into the journal without a
    /// commitment cycle.
    pub fn from_commitments(
        runtime_binding: Hash,
        inner_create_request: Hash,
    ) -> Result<Self, AuthorityCommitteeError> {
        if runtime_binding == Hash::ZERO || inner_create_request == Hash::ZERO {
            return Err(AuthorityCommitteeError::InvalidGenesisIntent);
        }
        Ok(Self(
            Hash::digest(
                GENESIS_INTENT_DOMAIN,
                &[&runtime_binding.0, &inner_create_request.0],
            )
            .0,
        ))
    }
}

/// Exact journal-derived commitments expected during genesis verification.
/// This value is not authority evidence. It makes the verifier compare every
/// certified output with independently materialized runtime/Create inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemAgentGenesisExpectations {
    runtime_binding: Hash,
    inner_create_request: Hash,
    post_create_state: Hash,
    artifact_closure: Hash,
    sequence: u64,
}

impl SystemAgentGenesisExpectations {
    pub fn new(
        runtime_binding: Hash,
        inner_create_request: Hash,
        post_create_state: Hash,
        artifact_closure: Hash,
        sequence: u64,
    ) -> Result<Self, AuthorityCommitteeError> {
        let expected = Self {
            runtime_binding,
            inner_create_request,
            post_create_state,
            artifact_closure,
            sequence,
        };
        expected.validate()?;
        Ok(expected)
    }

    pub const fn runtime_binding(&self) -> Hash {
        self.runtime_binding
    }

    pub const fn inner_create_request(&self) -> Hash {
        self.inner_create_request
    }

    pub const fn post_create_state(&self) -> Hash {
        self.post_create_state
    }

    pub const fn artifact_closure(&self) -> Hash {
        self.artifact_closure
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn genesis_intent(&self) -> GenesisIntentId {
        // Construction validated both inputs. Hashing directly keeps this
        // infallible accessor free of a latent panic path.
        GenesisIntentId(
            Hash::digest(
                GENESIS_INTENT_DOMAIN,
                &[&self.runtime_binding.0, &self.inner_create_request.0],
            )
            .0,
        )
    }

    fn validate(&self) -> Result<(), AuthorityCommitteeError> {
        if self.runtime_binding == Hash::ZERO
            || self.inner_create_request == Hash::ZERO
            || self.post_create_state == Hash::ZERO
            || self.artifact_closure == Hash::ZERO
            || self.sequence == 0
        {
            return Err(AuthorityCommitteeError::InvalidGenesisExpectation);
        }
        Ok(())
    }
}

/// Exact, cycle-free system-Agent genesis payload certified by the root
/// authority committee. The final journal-genesis ID is intentionally absent:
/// it can only be derived after the resulting admission ID is embedded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAgentGenesisClaim {
    space: SpaceId,
    system_agent: AgentId,
    authority_binding: Hash,
    root_certification: Hash,
    root_anchor: RootAnchorId,
    root_anchor_config_version: u64,
    root_anchor_config: RootAnchorConfigCommitment,
    genesis_intent: GenesisIntentId,
    runtime_binding: Hash,
    post_create_state: Hash,
    artifact_closure: Hash,
    sequence: u64,
}

impl SystemAgentGenesisClaim {
    pub fn new(
        root_anchor: &RootAnchorRecord,
        expected: SystemAgentGenesisExpectations,
    ) -> Result<Self, AuthorityCommitteeError> {
        root_anchor.validate()?;
        expected.validate()?;
        let claim = Self {
            space: root_anchor.space,
            system_agent: root_anchor.system_agent,
            authority_binding: root_anchor.authority_binding,
            root_certification: root_anchor.root_certification,
            root_anchor: root_anchor.id(),
            root_anchor_config_version: root_anchor.config_version,
            root_anchor_config: root_anchor.config_commitment(),
            genesis_intent: expected.genesis_intent(),
            runtime_binding: expected.runtime_binding,
            post_create_state: expected.post_create_state,
            artifact_closure: expected.artifact_closure,
            sequence: expected.sequence,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub const fn space(&self) -> SpaceId {
        self.space
    }

    pub const fn system_agent(&self) -> AgentId {
        self.system_agent
    }

    pub const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub const fn root_certification(&self) -> Hash {
        self.root_certification
    }

    pub const fn root_anchor(&self) -> RootAnchorId {
        self.root_anchor
    }

    pub const fn root_anchor_config_version(&self) -> u64 {
        self.root_anchor_config_version
    }

    pub const fn root_anchor_config(&self) -> RootAnchorConfigCommitment {
        self.root_anchor_config
    }

    pub const fn genesis_intent(&self) -> GenesisIntentId {
        self.genesis_intent
    }

    pub const fn runtime_binding(&self) -> Hash {
        self.runtime_binding
    }

    pub const fn post_create_state(&self) -> Hash {
        self.post_create_state
    }

    pub const fn artifact_closure(&self) -> Hash {
        self.artifact_closure
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn authority_claim(&self) -> AuthorityClaimCommitment {
        AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::SystemAgentGenesis,
            self.sequence,
            &self.encode(),
        )
    }

    fn validate(&self) -> Result<(), AuthorityCommitteeError> {
        if self.space == SpaceId::ZERO
            || self.system_agent == AgentId::ZERO
            || self.authority_binding == Hash::ZERO
            || self.root_certification == Hash::ZERO
            || self.root_anchor == RootAnchorId::ZERO
            || self.root_anchor_config_version == 0
            || self.root_anchor_config == RootAnchorConfigCommitment::ZERO
            || self.genesis_intent == GenesisIntentId::ZERO
            || self.runtime_binding == Hash::ZERO
            || self.post_create_state == Hash::ZERO
            || self.artifact_closure == Hash::ZERO
            || self.sequence == 0
        {
            return Err(AuthorityCommitteeError::InvalidGenesisClaim);
        }
        Ok(())
    }
}

impl ServiceWire for SystemAgentGenesisClaim {
    const MAGIC: [u8; 4] = *b"AGGC";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.space.0);
        encoder.fixed(&self.system_agent.0);
        encoder.fixed(&self.authority_binding.0);
        encoder.fixed(&self.root_certification.0);
        encoder.fixed(self.root_anchor.as_bytes());
        encoder.u64(self.root_anchor_config_version);
        encoder.fixed(self.root_anchor_config.as_bytes());
        encoder.fixed(self.genesis_intent.as_bytes());
        encoder.fixed(&self.runtime_binding.0);
        encoder.fixed(&self.post_create_state.0);
        encoder.fixed(&self.artifact_closure.0);
        encoder.u64(self.sequence);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_wire_bound(decoder, MAX_SYSTEM_GENESIS_CLAIM_WIRE_BYTES)?;
        let claim = Self {
            space: SpaceId(decoder.fixed()?),
            system_agent: AgentId(decoder.fixed()?),
            authority_binding: Hash(decoder.fixed()?),
            root_certification: Hash(decoder.fixed()?),
            root_anchor: RootAnchorId(decoder.fixed()?),
            root_anchor_config_version: decoder.u64()?,
            root_anchor_config: RootAnchorConfigCommitment(decoder.fixed()?),
            genesis_intent: GenesisIntentId(decoder.fixed()?),
            runtime_binding: Hash(decoder.fixed()?),
            post_create_state: Hash(decoder.fixed()?),
            artifact_closure: Hash(decoder.fixed()?),
            sequence: decoder.u64()?,
        };
        claim.validate().map_err(canonical_decode_error)?;
        Ok(claim)
    }
}

/// Exact daemon-pinned trust input for first system-Agent admission.
///
/// The constructor is crate-sealed: external callers may decode and inspect a
/// [`RootAnchorRecord`], but cannot promote a caller-selected record or QC to
/// a trust root. The daemon adapter must independently pin the record version,
/// content ID, config commitment, and exact genesis claim.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct TrustedRootAnchor {
    record: RootAnchorRecord,
    id: RootAnchorId,
    config_commitment: RootAnchorConfigCommitment,
    genesis_claim: AuthorityClaimCommitment,
}

#[allow(dead_code)]
impl TrustedRootAnchor {
    pub(crate) fn verify_configured(
        record: RootAnchorRecord,
        expected_config_version: u64,
        expected_id: RootAnchorId,
        expected_config_commitment: RootAnchorConfigCommitment,
        expected_genesis_claim: AuthorityClaimCommitment,
    ) -> Result<Self, AuthorityCommitteeError> {
        record.validate()?;
        expected_genesis_claim.validate()?;
        let actual_id = record.id();
        let actual_config_commitment = record.config_commitment();
        if expected_config_version == 0
            || expected_id == RootAnchorId::ZERO
            || expected_config_commitment == RootAnchorConfigCommitment::ZERO
            || expected_genesis_claim.domain != AuthorityClaimDomain::SystemAgentGenesis
        {
            return Err(AuthorityCommitteeError::InvalidBootstrapAnchor);
        }
        if record.config_version != expected_config_version
            || actual_id != expected_id
            || actual_config_commitment != expected_config_commitment
        {
            return Err(AuthorityCommitteeError::WrongBootstrapAnchor);
        }
        Ok(Self {
            record,
            id: actual_id,
            config_commitment: actual_config_commitment,
            genesis_claim: expected_genesis_claim,
        })
    }

    pub(crate) const fn record(&self) -> &RootAnchorRecord {
        &self.record
    }

    pub(crate) const fn id(&self) -> RootAnchorId {
        self.id
    }

    pub(crate) const fn config_commitment(&self) -> RootAnchorConfigCommitment {
        self.config_commitment
    }

    pub(crate) const fn genesis_claim(&self) -> AuthorityClaimCommitment {
        self.genesis_claim
    }
}

/// Root-certified evidence from which the replay layer may mint its otherwise
/// unforgeable production genesis admission capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemAgentGenesisEvidence {
    claim: SystemAgentGenesisClaim,
    certificate: AuthorityQuorumCertificate,
}

impl SystemAgentGenesisEvidence {
    pub fn new(
        claim: SystemAgentGenesisClaim,
        certificate: AuthorityQuorumCertificate,
    ) -> Result<Self, AuthorityCommitteeError> {
        let evidence = Self { claim, certificate };
        evidence.validate()?;
        Ok(evidence)
    }

    pub const fn claim(&self) -> &SystemAgentGenesisClaim {
        &self.claim
    }

    pub const fn certificate(&self) -> &AuthorityQuorumCertificate {
        &self.certificate
    }

    pub fn id(&self) -> SystemAgentGenesisEvidenceId {
        SystemAgentGenesisEvidenceId(Hash::digest(GENESIS_EVIDENCE_DOMAIN, &[&self.encode()]).0)
    }

    /// Validate the complete canonical evidence shape and its storage bound.
    /// This does not promote the evidence to trusted admission; callers still
    /// require the crate-sealed root verifier.
    pub fn validate(&self) -> Result<(), AuthorityCommitteeError> {
        self.validate_shape()?;
        if self.encode().len() > MAX_SYSTEM_GENESIS_EVIDENCE_BYTES {
            return Err(AuthorityCommitteeError::GenesisEvidenceTooLarge);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn verify(
        &self,
        anchor: &TrustedRootAnchor,
        expected: SystemAgentGenesisExpectations,
    ) -> Result<VerifiedSystemAgentGenesis, AuthorityCommitteeError> {
        self.validate_shape()?;
        expected.validate()?;
        let record = &anchor.record;
        if self.claim.space != record.space
            || self.claim.system_agent != record.system_agent
            || self.claim.authority_binding != record.authority_binding
            || self.claim.root_certification != record.root_certification
            || self.claim.root_anchor != anchor.id
            || self.claim.root_anchor_config_version != record.config_version
            || self.claim.root_anchor_config != anchor.config_commitment
            || self.claim.authority_claim() != anchor.genesis_claim
        {
            return Err(AuthorityCommitteeError::WrongBootstrapAnchor);
        }
        if self.claim.runtime_binding != expected.runtime_binding
            || self.claim.genesis_intent != expected.genesis_intent()
        {
            return Err(AuthorityCommitteeError::WrongGenesisIntent);
        }
        if self.claim.post_create_state != expected.post_create_state
            || self.claim.artifact_closure != expected.artifact_closure
            || self.claim.sequence != expected.sequence
        {
            return Err(AuthorityCommitteeError::WrongGenesisExpectation);
        }
        self.certificate
            .verify(&record.initial_committee, self.claim.authority_claim())?;

        let admission = SystemAgentGenesisAdmissionRecord::for_verified_evidence(self);
        Ok(VerifiedSystemAgentGenesis {
            root_anchor: anchor.record.clone(),
            space: self.claim.space,
            system_agent: self.claim.system_agent,
            authority_binding: self.claim.authority_binding,
            genesis_intent: self.claim.genesis_intent,
            runtime_binding: self.claim.runtime_binding,
            post_create_state: self.claim.post_create_state,
            artifact_closure: self.claim.artifact_closure,
            sequence: self.claim.sequence,
            evidence: self.id(),
            admission,
        })
    }

    fn validate_shape(&self) -> Result<(), AuthorityCommitteeError> {
        self.claim.validate()?;
        self.certificate.validate_shape()?;
        if self.certificate.claim != self.claim.authority_claim() {
            return Err(AuthorityCommitteeError::WrongClaim);
        }
        if self.certificate.authority_binding != self.claim.authority_binding {
            return Err(AuthorityCommitteeError::WrongAuthorityBinding);
        }
        if self.certificate.epoch != 1 {
            return Err(AuthorityCommitteeError::WrongEpoch);
        }
        Ok(())
    }
}

impl ServiceWire for SystemAgentGenesisEvidence {
    const MAGIC: [u8; 4] = *b"AGGE";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.claim.encode());
        encoder.bytes(&self.certificate.encode());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_wire_bound(decoder, MAX_SYSTEM_GENESIS_EVIDENCE_BYTES)?;
        let claim = decode_nested_wire::<SystemAgentGenesisClaim>(
            decoder,
            MAX_SYSTEM_GENESIS_CLAIM_WIRE_BYTES,
        )?;
        let certificate =
            decode_nested_wire::<AuthorityQuorumCertificate>(decoder, MAX_AUTHORITY_QC_WIRE_BYTES)?;
        let evidence = Self { claim, certificate };
        evidence.validate_shape().map_err(canonical_decode_error)?;
        Ok(evidence)
    }
}

/// Small durable record proving which exact content-addressed evidence was
/// admitted under which independently pinned root. It contains no unbounded
/// bytes and is trusted only together with [`VerifiedSystemAgentGenesis`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemAgentGenesisAdmissionRecord {
    root_anchor: RootAnchorId,
    root_anchor_config_version: u64,
    root_anchor_config: RootAnchorConfigCommitment,
    evidence: SystemAgentGenesisEvidenceId,
    claim: AuthorityClaimCommitment,
}

impl SystemAgentGenesisAdmissionRecord {
    fn for_verified_evidence(evidence: &SystemAgentGenesisEvidence) -> Self {
        Self {
            root_anchor: evidence.claim.root_anchor,
            root_anchor_config_version: evidence.claim.root_anchor_config_version,
            root_anchor_config: evidence.claim.root_anchor_config,
            evidence: evidence.id(),
            claim: evidence.claim.authority_claim(),
        }
    }

    pub const fn root_anchor(&self) -> RootAnchorId {
        self.root_anchor
    }

    pub const fn root_anchor_config_version(&self) -> u64 {
        self.root_anchor_config_version
    }

    pub const fn root_anchor_config(&self) -> RootAnchorConfigCommitment {
        self.root_anchor_config
    }

    pub const fn evidence(&self) -> SystemAgentGenesisEvidenceId {
        self.evidence
    }

    pub const fn claim(&self) -> AuthorityClaimCommitment {
        self.claim
    }

    pub fn id(&self) -> SystemAgentGenesisAdmissionId {
        SystemAgentGenesisAdmissionId(Hash::digest(GENESIS_ADMISSION_DOMAIN, &[&self.encode()]).0)
    }

    /// Validate canonical persisted shape. Trust still requires exact equality
    /// with the admission record minted by [`SystemAgentGenesisEvidence::verify`].
    pub fn validate(&self) -> Result<(), AuthorityCommitteeError> {
        self.claim.validate()?;
        if self.root_anchor == RootAnchorId::ZERO
            || self.root_anchor_config_version == 0
            || self.root_anchor_config == RootAnchorConfigCommitment::ZERO
            || self.evidence == SystemAgentGenesisEvidenceId::ZERO
            || self.claim.domain != AuthorityClaimDomain::SystemAgentGenesis
        {
            return Err(AuthorityCommitteeError::InvalidGenesisAdmission);
        }
        if self.encode().len() > MAX_SYSTEM_GENESIS_ADMISSION_BYTES {
            return Err(AuthorityCommitteeError::GenesisAdmissionTooLarge);
        }
        Ok(())
    }
}

impl ServiceWire for SystemAgentGenesisAdmissionRecord {
    const MAGIC: [u8; 4] = *b"AGGA";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.root_anchor.as_bytes());
        encoder.u64(self.root_anchor_config_version);
        encoder.fixed(self.root_anchor_config.as_bytes());
        encoder.fixed(self.evidence.as_bytes());
        encode_claim(&mut encoder, self.claim);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        enforce_complete_wire_bound(decoder, MAX_SYSTEM_GENESIS_ADMISSION_BYTES)?;
        let admission = Self {
            root_anchor: RootAnchorId(decoder.fixed()?),
            root_anchor_config_version: decoder.u64()?,
            root_anchor_config: RootAnchorConfigCommitment(decoder.fixed()?),
            evidence: SystemAgentGenesisEvidenceId(decoder.fixed()?),
            claim: decode_claim(decoder)?,
        };
        admission.validate().map_err(canonical_decode_error)?;
        Ok(admission)
    }
}

/// Opaque result of exact root-pin, expectation, and quorum verification.
/// Sibling journal code can consume this capability without acquiring access
/// to a signing key or accepting decoded admission bytes as authority.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct VerifiedSystemAgentGenesis {
    root_anchor: RootAnchorRecord,
    space: SpaceId,
    system_agent: AgentId,
    authority_binding: Hash,
    genesis_intent: GenesisIntentId,
    runtime_binding: Hash,
    post_create_state: Hash,
    artifact_closure: Hash,
    sequence: u64,
    evidence: SystemAgentGenesisEvidenceId,
    admission: SystemAgentGenesisAdmissionRecord,
}

#[allow(dead_code)]
impl VerifiedSystemAgentGenesis {
    pub(crate) const fn root_anchor(&self) -> &RootAnchorRecord {
        &self.root_anchor
    }

    pub(crate) const fn space(&self) -> SpaceId {
        self.space
    }

    pub(crate) const fn system_agent(&self) -> AgentId {
        self.system_agent
    }

    pub(crate) const fn authority_binding(&self) -> Hash {
        self.authority_binding
    }

    pub(crate) const fn genesis_intent(&self) -> GenesisIntentId {
        self.genesis_intent
    }

    pub(crate) const fn runtime_binding(&self) -> Hash {
        self.runtime_binding
    }

    pub(crate) const fn post_create_state(&self) -> Hash {
        self.post_create_state
    }

    pub(crate) const fn artifact_closure(&self) -> Hash {
        self.artifact_closure
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn evidence_id(&self) -> SystemAgentGenesisEvidenceId {
        self.evidence
    }

    pub(crate) const fn admission_record(&self) -> SystemAgentGenesisAdmissionRecord {
        self.admission
    }

    pub(crate) fn admission_id(&self) -> SystemAgentGenesisAdmissionId {
        self.admission.id()
    }

    pub(crate) fn admission_commitment(&self) -> Hash {
        self.admission.id().as_hash()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityCommitteeError {
    InvalidBinding,
    InvalidMember,
    InvalidSigner,
    InvalidEpoch,
    InvalidPreviousCommittee,
    CommitteeTooLarge,
    CertificateTooLarge,
    NoVoters,
    DuplicateNode,
    NonCanonicalOrder,
    InvalidClaim,
    WrongAuthorityBinding,
    WrongEpoch,
    WrongCommittee,
    WrongClaim,
    UnknownSigner,
    ObserverSignature,
    InsufficientQuorum,
    InvalidSignature,
    InvalidRotationEpoch,
    InvalidRotationLink,
    InvalidRotationSequence,
    InvalidRootAnchor,
    RootAnchorTooLarge,
    InvalidGenesisIntent,
    InvalidGenesisExpectation,
    InvalidGenesisClaim,
    GenesisEvidenceTooLarge,
    InvalidGenesisAdmission,
    GenesisAdmissionTooLarge,
    InvalidBootstrapAnchor,
    WrongBootstrapAnchor,
    WrongGenesisIntent,
    WrongGenesisExpectation,
}

impl fmt::Display for AuthorityCommitteeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid authority committee evidence: {self:?}")
    }
}

impl core::error::Error for AuthorityCommitteeError {}

fn encode_member(encoder: &mut Encoder<'_>, member: &AuthorityCommitteeMember) {
    encoder.fixed(&member.node.0);
    encoder.fixed(&member.signer.0);
    encoder.fixed(&member.public_key);
    encoder.u8(member.role as u8);
}

fn decode_member(decoder: &mut Decoder<'_>) -> Result<AuthorityCommitteeMember, DecodeError> {
    let node = NodeId(decoder.fixed()?);
    let signer = AuthoritySignerId(decoder.fixed()?);
    let public_key = decoder.fixed()?;
    let role = match decoder.u8()? {
        0 => AuthorityMemberRole::Voter,
        1 => AuthorityMemberRole::Observer,
        _ => return Err(DecodeError::InvalidTag),
    };
    let member = AuthorityCommitteeMember {
        node,
        signer,
        public_key,
        role,
    };
    member.validate().map_err(canonical_decode_error)?;
    Ok(member)
}

fn encode_claim(encoder: &mut Encoder<'_>, claim: AuthorityClaimCommitment) {
    encoder.u8(claim.domain as u8);
    encoder.u64(claim.sequence);
    encoder.fixed(&claim.payload_commitment.0);
}

fn decode_claim(decoder: &mut Decoder<'_>) -> Result<AuthorityClaimCommitment, DecodeError> {
    let domain = match decoder.u8()? {
        0 => AuthorityClaimDomain::Lifecycle,
        1 => AuthorityClaimDomain::Invocation,
        2 => AuthorityClaimDomain::SystemAgentGenesis,
        3 => AuthorityClaimDomain::CommitteeRotation,
        4 => AuthorityClaimDomain::Catalog,
        5 => AuthorityClaimDomain::NodeControl,
        _ => return Err(DecodeError::InvalidTag),
    };
    AuthorityClaimCommitment::from_payload_commitment(
        domain,
        decoder.u64()?,
        Hash(decoder.fixed()?),
    )
    .map_err(canonical_decode_error)
}

fn encode_signature(encoder: &mut Encoder<'_>, signature: &AuthoritySignature) {
    encoder.fixed(&signature.signer.0);
    encoder.0.extend_from_slice(&signature.signature);
}

fn decode_signature(decoder: &mut Decoder<'_>) -> Result<AuthoritySignature, DecodeError> {
    let signer = AuthoritySignerId(decoder.fixed()?);
    let signature = decoder
        .take(AUTHORITY_ED25519_SIGNATURE_BYTES)?
        .try_into()
        .map_err(|_| DecodeError::Truncated)?;
    AuthoritySignature::new(signer, signature).map_err(canonical_decode_error)
}

fn canonical_decode_error(error: AuthorityCommitteeError) -> DecodeError {
    match error {
        AuthorityCommitteeError::CommitteeTooLarge
        | AuthorityCommitteeError::CertificateTooLarge
        | AuthorityCommitteeError::RootAnchorTooLarge
        | AuthorityCommitteeError::GenesisEvidenceTooLarge
        | AuthorityCommitteeError::GenesisAdmissionTooLarge => DecodeError::LimitExceeded,
        _ => DecodeError::NonCanonical,
    }
}

fn enforce_complete_wire_bound(
    decoder: &Decoder<'_>,
    max_wire_bytes: usize,
) -> Result<(), DecodeError> {
    let max_body_bytes = max_wire_bytes
        .checked_sub(SERVICE_WIRE_HEADER_BYTES)
        .ok_or(DecodeError::LimitExceeded)?;
    if decoder.remaining() > max_body_bytes {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(())
}

fn decode_nested_wire<T: ServiceWire>(
    decoder: &mut Decoder<'_>,
    max_bytes: usize,
) -> Result<T, DecodeError> {
    let bytes = decoder.bytes_ref()?;
    if bytes.len() > max_bytes {
        return Err(DecodeError::LimitExceeded);
    }
    T::decode(bytes)
}

#[cfg(any(feature = "std", feature = "agent-runtime"))]
fn verify_ed25519(
    public_key: &[u8; AUTHORITY_ED25519_PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; AUTHORITY_ED25519_SIGNATURE_BYTES],
) -> bool {
    let Ok(public_key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return false;
    };
    public_key.verify_strict(message, &signature).is_ok()
}

// Wire types remain available to ordinary no-std consumers. Only the host and
// the standard agent runtime carry Ed25519 verification; all other feature
// sets fail closed instead of treating host preflight as authoritative.
#[cfg(not(any(feature = "std", feature = "agent-runtime")))]
fn verify_ed25519(
    _public_key: &[u8; AUTHORITY_ED25519_PUBLIC_KEY_BYTES],
    _message: &[u8],
    _signature: &[u8; AUTHORITY_ED25519_SIGNATURE_BYTES],
) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn keys(range: core::ops::RangeInclusive<u8>) -> Vec<SigningKey> {
        range
            .map(|byte| SigningKey::from_bytes(&[byte; 32]))
            .collect()
    }

    fn member(
        key: &SigningKey,
        node_byte: u8,
        role: AuthorityMemberRole,
    ) -> AuthorityCommitteeMember {
        AuthorityCommitteeMember::new(
            NodeId([node_byte; 32]),
            key.verifying_key().to_bytes(),
            role,
        )
        .unwrap()
    }

    fn committee(
        epoch: u64,
        previous: Option<Hash>,
        keys: &[SigningKey],
        observers: &[SigningKey],
    ) -> AuthorityCommittee {
        let mut members = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            members.push(member(key, (index + 1) as u8, AuthorityMemberRole::Voter));
        }
        for (index, key) in observers.iter().enumerate() {
            members.push(member(
                key,
                (keys.len() + index + 1) as u8,
                AuthorityMemberRole::Observer,
            ));
        }
        members.sort_by_key(AuthorityCommitteeMember::signer);
        AuthorityCommittee::new(
            SpaceId([0x41; 32]),
            Hash([0x42; 32]),
            epoch,
            previous,
            members,
        )
        .unwrap()
    }

    fn certificate(
        committee: &AuthorityCommittee,
        claim: AuthorityClaimCommitment,
        signers: &[&SigningKey],
    ) -> AuthorityQuorumCertificate {
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim,
        );
        let mut signatures = signers
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
        AuthorityQuorumCertificate::new(committee, claim, signatures).unwrap()
    }

    #[test]
    fn majority_qc_is_canonical_and_verifies() {
        let voters = keys(1..=3);
        let observers = keys(9..=9);
        let committee = committee(1, None, &voters, &observers);
        assert_eq!(committee.voter_count(), 3);
        assert_eq!(committee.quorum_threshold(), 2);
        assert_eq!(
            AuthorityCommittee::decode(&committee.encode()).unwrap(),
            committee
        );

        let claim = AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::Lifecycle,
            7,
            b"exact lifecycle operation",
        );
        let qc = certificate(&committee, claim, &[&voters[0], &voters[2]]);
        assert_eq!(
            AuthorityQuorumCertificate::decode(&qc.encode()).unwrap(),
            qc
        );
        assert_eq!(qc.verify(&committee, claim), Ok(()));
    }

    #[test]
    fn claim_and_certificate_tampering_fail() {
        let voters = keys(1..=3);
        let committee = committee(1, None, &voters, &[]);
        let claim = AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::Invocation,
            8,
            b"invoke actor A",
        );
        let mut qc = certificate(&committee, claim, &[&voters[0], &voters[1]]);
        let wrong_claim = AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::Invocation,
            8,
            b"invoke actor B",
        );
        assert_eq!(
            qc.verify(&committee, wrong_claim),
            Err(AuthorityCommitteeError::WrongClaim)
        );

        qc.signatures[0].signature[0] ^= 1;
        assert_eq!(
            qc.verify(&committee, claim),
            Err(AuthorityCommitteeError::InvalidSignature)
        );
    }

    #[test]
    fn duplicate_signatures_and_roster_identities_are_rejected() {
        let voters = keys(1..=3);
        let committee = committee(1, None, &voters, &[]);
        let claim =
            AuthorityClaimCommitment::of_bytes(AuthorityClaimDomain::Lifecycle, 1, b"operation");
        let mut qc = certificate(&committee, claim, &[&voters[0], &voters[1]]);
        qc.signatures[1] = qc.signatures[0].clone();
        assert_eq!(
            AuthorityQuorumCertificate::decode(&qc.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut duplicate_node = committee.members.clone();
        duplicate_node[1].node = duplicate_node[0].node;
        duplicate_node.sort_by_key(AuthorityCommitteeMember::signer);
        assert_eq!(
            AuthorityCommittee::new(
                committee.space,
                committee.authority_binding,
                1,
                None,
                duplicate_node,
            ),
            Err(AuthorityCommitteeError::DuplicateNode)
        );
    }

    #[test]
    fn observers_never_contribute_to_quorum() {
        let voters = keys(1..=3);
        let observers = keys(9..=9);
        let committee = committee(1, None, &voters, &observers);
        let claim =
            AuthorityClaimCommitment::of_bytes(AuthorityClaimDomain::Catalog, 2, b"catalog update");
        let qc = certificate(&committee, claim, &[&voters[0], &observers[0]]);
        assert_eq!(
            qc.verify(&committee, claim),
            Err(AuthorityCommitteeError::ObserverSignature)
        );

        let one_voter = certificate(&committee, claim, &[&voters[0]]);
        assert_eq!(
            one_voter.verify(&committee, claim),
            Err(AuthorityCommitteeError::InsufficientQuorum)
        );
    }

    #[test]
    fn wrong_epoch_or_authority_cannot_reuse_a_qc() {
        let voters = keys(1..=3);
        let old = committee(1, None, &voters, &[]);
        let claim =
            AuthorityClaimCommitment::of_bytes(AuthorityClaimDomain::NodeControl, 3, b"node grant");
        let qc = certificate(&old, claim, &[&voters[0], &voters[1]]);

        let next = committee(2, Some(old.commitment()), &voters, &[]);
        assert_eq!(
            qc.verify(&next, claim),
            Err(AuthorityCommitteeError::WrongEpoch)
        );

        let mut wrong_authority = old.clone();
        wrong_authority.authority_binding = Hash([0x77; 32]);
        assert_eq!(
            qc.verify(&wrong_authority, claim),
            Err(AuthorityCommitteeError::WrongAuthorityBinding)
        );
    }

    #[test]
    fn rotation_requires_old_and_new_majorities_and_sequence_boundary() {
        let old_keys = keys(1..=3);
        let new_keys = keys(4..=6);
        let old = committee(1, None, &old_keys, &[]);
        let new = committee(2, Some(old.commitment()), &new_keys, &[]);
        let transition = AuthorityCommitteeRotation::new(&old, &new, 10, 12).unwrap();
        let rotation_claim = transition.claim();
        let old_qc = certificate(&old, rotation_claim, &[&old_keys[0], &old_keys[1]]);
        let new_qc = certificate(&new, rotation_claim, &[&new_keys[0], &new_keys[2]]);
        let joint = JointAuthorityRotationCertificate::new(transition, old_qc, new_qc).unwrap();
        assert_eq!(joint.verify(&old, &new), Ok(()));
        assert_eq!(
            JointAuthorityRotationCertificate::decode(&joint.encode()).unwrap(),
            joint
        );

        let first_claim = AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::Lifecycle,
            12,
            b"first new epoch operation",
        );
        let first_qc = certificate(&new, first_claim, &[&new_keys[0], &new_keys[1]]);
        assert_eq!(
            joint.verify_first_new_certificate(&old, &new, &first_qc, first_claim),
            Ok(())
        );

        let stale_claim = AuthorityClaimCommitment::of_bytes(
            AuthorityClaimDomain::Lifecycle,
            10,
            b"stale operation",
        );
        let stale_qc = certificate(&new, stale_claim, &[&new_keys[0], &new_keys[1]]);
        assert_eq!(
            joint.verify_first_new_certificate(&old, &new, &stale_qc, stale_claim),
            Err(AuthorityCommitteeError::InvalidRotationSequence)
        );

        let insufficient_new = certificate(&new, rotation_claim, &[&new_keys[0]]);
        let joint = JointAuthorityRotationCertificate::new(
            joint.transition.clone(),
            joint.old_certificate.clone(),
            insufficient_new,
        )
        .unwrap();
        assert_eq!(
            joint.verify(&old, &new),
            Err(AuthorityCommitteeError::InsufficientQuorum)
        );
        assert_eq!(
            AuthorityCommitteeRotation::new(&old, &new, 10, 10),
            Err(AuthorityCommitteeError::InvalidRotationSequence)
        );
    }

    #[test]
    fn rotation_rejects_wrong_previous_commitment_and_nonmonotone_epoch() {
        let old_keys = keys(1..=3);
        let new_keys = keys(4..=6);
        let old = committee(1, None, &old_keys, &[]);
        let wrong_link = committee(2, Some(Hash([0x99; 32])), &new_keys, &[]);
        assert_eq!(
            AuthorityCommitteeRotation::new(&old, &wrong_link, 4, 5),
            Err(AuthorityCommitteeError::InvalidRotationLink)
        );

        let skipped_epoch = committee(3, Some(old.commitment()), &new_keys, &[]);
        assert_eq!(
            AuthorityCommitteeRotation::new(&old, &skipped_epoch, 4, 5),
            Err(AuthorityCommitteeError::InvalidRotationEpoch)
        );

        let same_epoch = AuthorityCommittee::new(
            old.space,
            old.authority_binding,
            1,
            None,
            old.members.clone(),
        )
        .unwrap();
        assert_eq!(
            AuthorityCommitteeRotation::new(&old, &same_epoch, 4, 5),
            Err(AuthorityCommitteeError::InvalidRotationEpoch)
        );
    }

    fn root_anchor(committee: AuthorityCommittee, config_version: u64) -> RootAnchorRecord {
        RootAnchorRecord::new(
            config_version,
            committee.space,
            AgentId([0x51; 32]),
            committee.authority_binding,
            Hash([0x52; 32]),
            committee,
        )
        .unwrap()
    }

    fn genesis_expectations(sequence: u64) -> SystemAgentGenesisExpectations {
        SystemAgentGenesisExpectations::new(
            Hash([0x53; 32]),
            Hash([0x54; 32]),
            Hash([0x55; 32]),
            Hash([0x56; 32]),
            sequence,
        )
        .unwrap()
    }

    #[test]
    fn system_genesis_admission_is_cycle_free_canonical_and_exact() {
        let voters = keys(1..=3);
        let committee = committee(1, None, &voters, &[]);
        let root = root_anchor(committee.clone(), 7);
        let expected = genesis_expectations(1);
        let claim = SystemAgentGenesisClaim::new(&root, expected).unwrap();
        let anchor = TrustedRootAnchor::verify_configured(
            root.clone(),
            root.config_version(),
            root.id(),
            root.config_commitment(),
            claim.authority_claim(),
        )
        .unwrap();
        let qc = certificate(
            &committee,
            claim.authority_claim(),
            &[&voters[0], &voters[2]],
        );
        let evidence = SystemAgentGenesisEvidence::new(claim.clone(), qc).unwrap();

        assert_eq!(RootAnchorRecord::decode(&root.encode()).unwrap(), root);
        assert_eq!(
            SystemAgentGenesisClaim::decode(&claim.encode()).unwrap(),
            claim
        );
        assert_eq!(
            SystemAgentGenesisEvidence::decode(&evidence.encode()).unwrap(),
            evidence
        );
        assert!(root.encode().len() <= MAX_ROOT_ANCHOR_RECORD_BYTES);
        assert!(evidence.encode().len() <= MAX_SYSTEM_GENESIS_EVIDENCE_BYTES);
        assert_eq!(anchor.record(), &root);
        assert_eq!(anchor.id(), root.id());
        assert_eq!(anchor.config_commitment(), root.config_commitment());
        assert_eq!(anchor.genesis_claim(), claim.authority_claim());

        let verified = evidence.verify(&anchor, expected).unwrap();
        let admission = verified.admission_record();
        assert_eq!(
            SystemAgentGenesisAdmissionRecord::decode(&admission.encode()).unwrap(),
            admission
        );
        assert!(admission.encode().len() <= MAX_SYSTEM_GENESIS_ADMISSION_BYTES);
        assert_eq!(admission.root_anchor(), root.id());
        assert_eq!(verified.root_anchor(), &root);
        assert_eq!(admission.evidence(), evidence.id());
        assert_eq!(verified.system_agent(), root.system_agent());
        assert_eq!(verified.genesis_intent(), expected.genesis_intent());
        assert_eq!(verified.runtime_binding(), expected.runtime_binding());
        assert_eq!(verified.post_create_state(), expected.post_create_state());
        assert_eq!(verified.artifact_closure(), expected.artifact_closure());
        assert_eq!(verified.sequence(), expected.sequence());
        assert_eq!(verified.evidence_id(), evidence.id());
        assert_eq!(verified.admission_id(), admission.id());
        assert_eq!(verified.admission_commitment(), admission.id().as_hash());

        // The intent can be derived before evidence, admission, and the final
        // journal record exist. Changing either preimage changes only this
        // upstream identifier and cannot introduce an evidence/journal cycle.
        assert_ne!(
            expected.genesis_intent(),
            GenesisIntentId::from_commitments(expected.runtime_binding(), Hash([0x57; 32]))
                .unwrap()
        );
    }

    #[test]
    fn system_genesis_rejects_stale_and_alternate_intents() {
        let voters = keys(1..=3);
        let committee = committee(1, None, &voters, &[]);
        let root = root_anchor(committee.clone(), 3);
        let expected = genesis_expectations(8);
        let claim = SystemAgentGenesisClaim::new(&root, expected).unwrap();
        let anchor = TrustedRootAnchor::verify_configured(
            root.clone(),
            root.config_version(),
            root.id(),
            root.config_commitment(),
            claim.authority_claim(),
        )
        .unwrap();
        let evidence = SystemAgentGenesisEvidence::new(
            claim.clone(),
            certificate(
                &committee,
                claim.authority_claim(),
                &[&voters[0], &voters[1]],
            ),
        )
        .unwrap();

        let alternate_create = SystemAgentGenesisExpectations::new(
            expected.runtime_binding(),
            Hash([0x60; 32]),
            expected.post_create_state(),
            expected.artifact_closure(),
            expected.sequence(),
        )
        .unwrap();
        assert_eq!(
            evidence.verify(&anchor, alternate_create),
            Err(AuthorityCommitteeError::WrongGenesisIntent)
        );

        let alternate_runtime = SystemAgentGenesisExpectations::new(
            Hash([0x61; 32]),
            expected.inner_create_request(),
            expected.post_create_state(),
            expected.artifact_closure(),
            expected.sequence(),
        )
        .unwrap();
        assert_eq!(
            evidence.verify(&anchor, alternate_runtime),
            Err(AuthorityCommitteeError::WrongGenesisIntent)
        );

        let stale_expected = genesis_expectations(7);
        let stale_claim = SystemAgentGenesisClaim::new(&root, stale_expected).unwrap();
        let stale_evidence = SystemAgentGenesisEvidence::new(
            stale_claim.clone(),
            certificate(
                &committee,
                stale_claim.authority_claim(),
                &[&voters[0], &voters[1]],
            ),
        )
        .unwrap();
        assert_eq!(
            stale_evidence.verify(&anchor, stale_expected),
            Err(AuthorityCommitteeError::WrongBootstrapAnchor)
        );

        let wrong_outputs = SystemAgentGenesisExpectations::new(
            expected.runtime_binding(),
            expected.inner_create_request(),
            Hash([0x62; 32]),
            expected.artifact_closure(),
            expected.sequence(),
        )
        .unwrap();
        assert_eq!(
            evidence.verify(&anchor, wrong_outputs),
            Err(AuthorityCommitteeError::WrongGenesisExpectation)
        );
    }

    #[test]
    fn system_genesis_rejects_alternate_roots_and_tampered_evidence() {
        let voters = keys(1..=3);
        let committee = committee(1, None, &voters, &[]);
        let root = root_anchor(committee.clone(), 4);
        let expected = genesis_expectations(1);
        let claim = SystemAgentGenesisClaim::new(&root, expected).unwrap();
        let anchor = TrustedRootAnchor::verify_configured(
            root.clone(),
            root.config_version(),
            root.id(),
            root.config_commitment(),
            claim.authority_claim(),
        )
        .unwrap();
        let mut evidence = SystemAgentGenesisEvidence::new(
            claim.clone(),
            certificate(
                &committee,
                claim.authority_claim(),
                &[&voters[0], &voters[2]],
            ),
        )
        .unwrap();
        let verified = evidence.verify(&anchor, expected).unwrap();
        assert_eq!(verified.root_anchor(), &root);

        let alternate_root = root_anchor(committee.clone(), 5);
        assert_eq!(
            TrustedRootAnchor::verify_configured(
                alternate_root,
                root.config_version(),
                root.id(),
                root.config_commitment(),
                claim.authority_claim(),
            ),
            Err(AuthorityCommitteeError::WrongBootstrapAnchor)
        );

        let mut tampered_root = root.clone();
        tampered_root.root_certification.0[0] ^= 1;
        tampered_root.validate().unwrap();
        assert_ne!(tampered_root.id(), root.id());
        assert_eq!(
            TrustedRootAnchor::verify_configured(
                tampered_root,
                root.config_version(),
                root.id(),
                root.config_commitment(),
                claim.authority_claim(),
            ),
            Err(AuthorityCommitteeError::WrongBootstrapAnchor)
        );

        let untampered_id = evidence.id();
        evidence.certificate.signatures[0].signature[0] ^= 1;
        assert_ne!(evidence.id(), untampered_id);
        assert_eq!(
            evidence.verify(&anchor, expected),
            Err(AuthorityCommitteeError::InvalidSignature)
        );
    }

    #[test]
    fn genesis_wires_reject_oversized_inputs_before_nested_allocation() {
        let voters = keys(1..=1);
        let committee = committee(1, None, &voters, &[]);
        let root = root_anchor(committee.clone(), 1);
        let expected = genesis_expectations(1);
        let claim = SystemAgentGenesisClaim::new(&root, expected).unwrap();
        let evidence = SystemAgentGenesisEvidence::new(
            claim.clone(),
            certificate(&committee, claim.authority_claim(), &[&voters[0]]),
        )
        .unwrap();

        let mut oversized_root = root.encode();
        oversized_root.resize(MAX_ROOT_ANCHOR_RECORD_BYTES + 1, 0);
        assert_eq!(
            RootAnchorRecord::decode(&oversized_root),
            Err(DecodeError::LimitExceeded)
        );

        let mut oversized_evidence = evidence.encode();
        oversized_evidence.resize(MAX_SYSTEM_GENESIS_EVIDENCE_BYTES + 1, 0);
        assert_eq!(
            SystemAgentGenesisEvidence::decode(&oversized_evidence),
            Err(DecodeError::LimitExceeded)
        );
    }

    #[test]
    fn committee_wire_rejects_oversized_rosters_before_allocation() {
        let voters = keys(1..=1);
        let committee = committee(1, None, &voters, &[]);
        let mut encoded = committee.encode();
        // Header + space + binding + epoch + absent-previous tag.
        let count_offset = 4 + 32 + 32 + 32 + 8 + 1;
        encoded[count_offset..count_offset + 4]
            .copy_from_slice(&((MAX_AUTHORITY_COMMITTEE_MEMBERS + 1) as u32).to_le_bytes());
        assert_eq!(
            AuthorityCommittee::decode(&encoded),
            Err(DecodeError::LimitExceeded)
        );
    }
}
