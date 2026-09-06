//! Canonical protocol records for owner-node-only Private agents.

use alloc::vec::Vec;

use crate::{ActorId, AgentId, BlobRef, Hash, NodeId, PrincipalId, SpaceId};

pub const MAX_PRIVATE_NODES: usize = 256;
pub const MAX_TRANSPORT_IDENTITY_BYTES: usize = 512;
/// Exact multihash length of an inline libp2p Ed25519 public key.
///
/// VOS clean-generation transport identities are Ed25519 only. The libp2p
/// public-key protobuf is 36 bytes (`08 01 12 20 || key`) and therefore uses
/// the identity multihash (`00 24 || protobuf`) rather than a hashed PeerId.
pub const ED25519_TRANSPORT_PEER_ID_BYTES: usize = 38;
pub const MAX_SEALED_KEY_BYTES: usize = 4 * 1024;
pub const MAX_PRIVATE_CIPHERTEXT_BYTES: usize = 8 * 1024 * 1024;
/// A recovery grant contains at most one fixed-size data-key entry for every
/// epoch which can precede a valid recovery control.
pub const MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS: usize = 4_096;
pub const MAX_PRIVATE_RECOVERY_KEYRING_CIPHERTEXT_BYTES: usize = 512 * 1024;
/// An Invite carries at most one independently sealed historical data key for
/// every authenticated data epoch which precedes the current epoch.
pub const MAX_PRIVATE_INVITE_HISTORY_EPOCHS: usize = 4_096;
/// Exact host seal size used by an Invite history grant. Keeping this bound
/// distinct from the extensible generic sealed-key ceiling prevents a bounded
/// Invite control from expanding to tens of megabytes.
pub const PRIVATE_INVITE_HISTORY_SEALED_KEY_BYTES: usize = 4 + 32 + 24 + 48;
pub const PRIVATE_SIGNATURE_BYTES: usize = 64;
pub const PRIVATE_NONCE_BYTES: usize = 24;

const ED25519_TRANSPORT_PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

/// Construct the one canonical libp2p PeerId representation accepted for a
/// clean-generation Ed25519 transport public key.
pub fn canonical_ed25519_peer_id(public_key: &[u8; 32]) -> [u8; ED25519_TRANSPORT_PEER_ID_BYTES] {
    let mut peer_id = [0; ED25519_TRANSPORT_PEER_ID_BYTES];
    peer_id[..ED25519_TRANSPORT_PEER_ID_PREFIX.len()]
        .copy_from_slice(&ED25519_TRANSPORT_PEER_ID_PREFIX);
    peer_id[ED25519_TRANSPORT_PEER_ID_PREFIX.len()..].copy_from_slice(public_key);
    peer_id
}

/// Crypto seam for verifying a node's transport-key possession proof.
///
/// Implementations must perform strict Ed25519 verification. Keeping the
/// provider outside this `no_std` model lets both the authority actor and a
/// host-side policy client verify exactly the same canonical enrollment.
pub trait NodeEncryptionEnrollmentVerifier {
    fn verify(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; PRIVATE_SIGNATURE_BYTES],
    ) -> bool;
}

/// One node-owned X25519 recipient enrolled into a Space authority.
///
/// The administrator's separately authenticated authority mutation proves
/// authorization to bind `principal`; this transport signature independently
/// proves possession of the exact full Ed25519 PeerId being bound. Repeating
/// the public key, PeerId, and derived NodeId is deliberate and prevents any
/// compact routing hint or alternate libp2p key encoding from entering policy
/// state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeEncryptionEnrollment {
    pub space: SpaceId,
    pub principal: PrincipalId,
    pub node: NodeId,
    pub transport_public_key: [u8; 32],
    pub transport_peer_id: [u8; ED25519_TRANSPORT_PEER_ID_BYTES],
    pub encryption_public_key: [u8; 32],
    pub transport_signature: [u8; PRIVATE_SIGNATURE_BYTES],
}

impl NodeEncryptionEnrollment {
    /// Derive all redundant transport identity fields from the exact Ed25519
    /// public key. `transport_signature` signs [`Self::signing_bytes`].
    pub fn from_keys(
        space: SpaceId,
        principal: PrincipalId,
        transport_public_key: [u8; 32],
        encryption_public_key: [u8; 32],
        transport_signature: [u8; PRIVATE_SIGNATURE_BYTES],
    ) -> Self {
        let transport_peer_id = canonical_ed25519_peer_id(&transport_public_key);
        Self {
            space,
            principal,
            node: NodeId::of_authenticated_peer(&transport_peer_id),
            transport_public_key,
            transport_peer_id,
            encryption_public_key,
            transport_signature,
        }
    }

    pub fn validate_shape(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.principal != PrincipalId::ZERO
            && self.transport_public_key != [0; 32]
            && self.transport_peer_id == canonical_ed25519_peer_id(&self.transport_public_key)
            && self.node == NodeId::of_authenticated_peer(&self.transport_peer_id)
            && self.node != NodeId::ZERO
            && self.encryption_public_key != [0; 32]
            && self.transport_signature != [0; PRIVATE_SIGNATURE_BYTES]
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::node_encryption_enrollment_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/private/node-encryption-enrollment/v1",
            &[&self.signing_bytes(), &self.transport_signature],
        )
    }

    pub fn verify_with<V: NodeEncryptionEnrollmentVerifier>(&self, verifier: &V) -> bool {
        self.validate_shape()
            && verifier.verify(
                &self.transport_public_key,
                &self.signing_bytes(),
                &self.transport_signature,
            )
    }

    /// Verify possession before materializing the exact Private control
    /// identity whose commitment can be compared with an enrolled
    /// system-authority row.
    pub fn verified_private_identity<V: NodeEncryptionEnrollmentVerifier>(
        &self,
        verifier: &V,
    ) -> Option<PrivateNodeIdentity> {
        self.verify_with(verifier).then(|| PrivateNodeIdentity {
            node: self.node,
            principal: self.principal,
            transport_identity: self.transport_peer_id.to_vec(),
            encryption_public_key: self.encryption_public_key,
            authority_binding: self.commitment(),
            transport_signature: self.transport_signature,
        })
    }
}

/// X25519 encryption identity authenticated by the node's full transport
/// identity and bound to its owning Principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateNodeIdentity {
    pub node: NodeId,
    pub principal: PrincipalId,
    pub transport_identity: Vec<u8>,
    pub encryption_public_key: [u8; 32],
    /// System-authority evidence binding the exact Node transport identity and
    /// encryption key to `principal`.
    pub authority_binding: Hash,
    pub transport_signature: [u8; PRIVATE_SIGNATURE_BYTES],
}

impl PrivateNodeIdentity {
    pub fn validate(&self) -> bool {
        self.node != NodeId::ZERO
            && self.principal != PrincipalId::ZERO
            && !self.transport_identity.is_empty()
            && self.transport_identity.len() <= MAX_TRANSPORT_IDENTITY_BYTES
            && NodeId::of_authenticated_peer(&self.transport_identity) == self.node
            && self.encryption_public_key != [0; 32]
            && self.authority_binding != Hash::ZERO
            && self.transport_signature != [0; PRIVATE_SIGNATURE_BYTES]
    }

    /// Require byte-for-byte equality with the authority-enrolled transport
    /// and encryption identity. A Private identity is Agent-scoped and has no
    /// Space field, so its caller must select the enrollment from the expected
    /// Space's authenticated authority state before calling this helper.
    pub fn matches_enrollment(&self, enrollment: &NodeEncryptionEnrollment) -> bool {
        enrollment.validate_shape()
            && self.node == enrollment.node
            && self.principal == enrollment.principal
            && self.transport_identity.as_slice() == enrollment.transport_peer_id
            && self.encryption_public_key == enrollment.encryption_public_key
            && self.authority_binding == enrollment.commitment()
            && self.transport_signature == enrollment.transport_signature
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedPrivateKey {
    pub node: NodeId,
    pub recipient_key: [u8; 32],
    pub sealed: Vec<u8>,
}

impl SealedPrivateKey {
    pub fn validate(&self) -> bool {
        self.node != NodeId::ZERO
            && self.recipient_key != [0; 32]
            && !self.sealed.is_empty()
            && self.sealed.len() <= MAX_SEALED_KEY_BYTES
    }
}

/// One historical data-epoch key independently sealed to the exact Node
/// admitted by an owner-signed Invite transition. All binding fields are
/// repeated in canonical wire so substitution is rejected before decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateInviteHistoryGrant {
    pub space: SpaceId,
    pub agent: AgentId,
    pub owner: PrincipalId,
    pub transition: Hash,
    pub recipient: NodeId,
    pub recipient_key: [u8; 32],
    pub epoch: u64,
    pub data_key_commitment: Hash,
    pub sealed_data_key: SealedPrivateKey,
}

impl PrivateInviteHistoryGrant {
    pub fn validate(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != AgentId::ZERO
            && self.owner != PrincipalId::ZERO
            && self.transition != Hash::ZERO
            && self.recipient != NodeId::ZERO
            && self.recipient_key != [0; 32]
            && self.data_key_commitment != Hash::ZERO
            && self.sealed_data_key.validate()
            && self.sealed_data_key.node == self.recipient
            && self.sealed_data_key.recipient_key == self.recipient_key
            && self.sealed_data_key.sealed.len() == PRIVATE_INVITE_HISTORY_SEALED_KEY_BYTES
    }
}

/// One data key sealed to a dedicated offline X25519 recovery recipient.
/// This recipient is deliberately not a Node identity and is independent of
/// the Ed25519 key which signs recovery controls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRecoveryKey {
    pub recipient_key: [u8; 32],
    pub sealed: Vec<u8>,
}

impl SealedRecoveryKey {
    pub fn validate(&self) -> bool {
        self.recipient_key != [0; 32]
            && !self.sealed.is_empty()
            && self.sealed.len() <= MAX_SEALED_KEY_BYTES
    }
}

/// Separately sealed owner-signing and data-encryption keys for one epoch.
/// Offline recovery signing remains a public commitment; the independent
/// recovery-encryption recipient receives only this epoch's sealed data key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKeyEpoch {
    pub space: SpaceId,
    pub agent: AgentId,
    pub epoch: u64,
    pub owner_key_commitment: Hash,
    pub data_key_commitment: Hash,
    pub recovery_key_commitment: Hash,
    pub recovery_encryption_public_key: [u8; 32],
    pub sealed_recovery_data_key: SealedRecoveryKey,
    pub sealed_owner_keys: Vec<SealedPrivateKey>,
    pub sealed_data_keys: Vec<SealedPrivateKey>,
}

impl PrivateKeyEpoch {
    pub fn validate(&self) -> bool {
        if self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.owner_key_commitment == Hash::ZERO
            || self.data_key_commitment == Hash::ZERO
            || self.recovery_key_commitment == Hash::ZERO
            || self.recovery_encryption_public_key == [0; 32]
            || !self.sealed_recovery_data_key.validate()
            || self.sealed_recovery_data_key.recipient_key != self.recovery_encryption_public_key
            || self.sealed_owner_keys.is_empty()
            || self.sealed_owner_keys.len() > MAX_PRIVATE_NODES
            || self.sealed_data_keys.len() != self.sealed_owner_keys.len()
        {
            return false;
        }
        if self
            .sealed_owner_keys
            .iter()
            .chain(self.sealed_data_keys.iter())
            .any(|key| !key.validate())
        {
            return false;
        }
        self.sealed_owner_keys
            .iter()
            .zip(&self.sealed_data_keys)
            .all(|(owner, data)| {
                owner.node == data.node && owner.recipient_key == data.recipient_key
            })
            && self
                .sealed_owner_keys
                .windows(2)
                .all(|pair| pair[0].node < pair[1].node)
    }
}

/// Recovery-signed, ciphertext-only transfer of historical data keys to the
/// exact replacement Node set. The wrapping key is separately sealed to each
/// replacement and never appears in canonical wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateRecoveryKeyringGrant {
    pub key_commitment: Hash,
    pub sealed_keys: Vec<SealedPrivateKey>,
    pub ciphertext: EncryptedPrivateObject,
}

impl PrivateRecoveryKeyringGrant {
    pub fn validate(&self) -> bool {
        self.key_commitment != Hash::ZERO
            && !self.sealed_keys.is_empty()
            && self.sealed_keys.len() <= MAX_PRIVATE_NODES
            && self.sealed_keys.iter().all(SealedPrivateKey::validate)
            && self
                .sealed_keys
                .windows(2)
                .all(|pair| pair[0].node < pair[1].node)
            && self.ciphertext.validate()
            && self.ciphertext.kind == EncryptedObjectKind::Control
            && self.ciphertext.ciphertext.len() <= MAX_PRIVATE_RECOVERY_KEYRING_CIPHERTEXT_BYTES
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptedObjectKind {
    CrdtNode = 0,
    Package = 1,
    Blob = 2,
    Index = 3,
    Snapshot = 4,
    Control = 5,
}

/// Authenticated ciphertext. Implementations bind every header field as AEAD
/// associated data; `content` is the plaintext content identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedPrivateObject {
    pub space: SpaceId,
    pub agent: AgentId,
    pub epoch: u64,
    pub kind: EncryptedObjectKind,
    pub content: Hash,
    pub nonce: [u8; PRIVATE_NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

impl EncryptedPrivateObject {
    pub fn validate(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != AgentId::ZERO
            && self.content != Hash::ZERO
            && self.nonce != [0; PRIVATE_NONCE_BYTES]
            && !self.ciphertext.is_empty()
            && self.ciphertext.len() <= MAX_PRIVATE_CIPHERTEXT_BYTES
    }

    pub fn associated_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(21 + 32 + 32 + 8 + 1 + 32);
        data.extend_from_slice(b"vos/private/object/v1");
        data.extend_from_slice(self.space.as_bytes());
        data.extend_from_slice(self.agent.as_bytes());
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.push(self.kind as u8);
        data.extend_from_slice(self.content.as_bytes());
        data
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateControlOperation {
    Invite {
        node: PrivateNodeIdentity,
        epoch: u64,
        sealed_owner_key: SealedPrivateKey,
        sealed_data_key: SealedPrivateKey,
        historical_grants: Vec<PrivateInviteHistoryGrant>,
    },
    Revoke {
        node: NodeId,
        next_epoch: PrivateKeyEpoch,
    },
    RotateKeys {
        next_epoch: PrivateKeyEpoch,
    },
    SetResourcePolicy {
        policy: BlobRef,
    },
    ActorLifecycle {
        actor: ActorId,
        operation: PrivateActorLifecycleKind,
        request: Hash,
    },
    /// Offline recovery supersedes every active control head and rotates all
    /// keys before admitting replacements.
    Recover {
        superseded_heads: Vec<Hash>,
        next_epoch: PrivateKeyEpoch,
        replacement_nodes: Vec<PrivateNodeIdentity>,
        historical_keyring: PrivateRecoveryKeyringGrant,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateActorLifecycleKind {
    Install = 0,
    Upgrade = 1,
    Suspend = 2,
    Resume = 3,
    Remove = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivateControlSigner {
    Owner = 0,
    Recovery = 1,
}

/// Owner-signed monotonic private control chain record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateControlRecord {
    pub space: SpaceId,
    pub agent: AgentId,
    pub sequence: u64,
    pub previous: Option<Hash>,
    pub operation: PrivateControlOperation,
    /// Recovery records use the independently retained offline recovery key;
    /// ordinary control records use the current owner-signing key.
    pub signer: PrivateControlSigner,
    pub signer_public_key: [u8; 32],
    pub signature: [u8; PRIVATE_SIGNATURE_BYTES],
}

impl PrivateControlRecord {
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::private_control_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/private/control-record",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    /// Commitment to the exact Invite transition fields which precede its
    /// historical grants. Each grant binds this value in its seal AAD, while
    /// the final owner signature authenticates both the transition and the
    /// complete canonical grant list.
    pub fn invite_transition_binding(&self) -> Option<Hash> {
        crate::wire::private_invite_transition_binding(self)
    }

    pub fn validate_shape(&self) -> bool {
        self.space != SpaceId::ZERO
            && self.agent != AgentId::ZERO
            && self.signer_public_key != [0; 32]
            && self.signature != [0; PRIVATE_SIGNATURE_BYTES]
            && match (&self.operation, self.sequence, self.previous) {
                (PrivateControlOperation::Recover { .. }, _, None) => true,
                (_, 0, None) => true,
                (_, 0, Some(_)) | (_, _, None) => false,
                (_, _, Some(previous)) => previous != Hash::ZERO,
            }
            && match &self.operation {
                PrivateControlOperation::Invite {
                    node,
                    epoch,
                    sealed_owner_key,
                    sealed_data_key,
                    historical_grants,
                } => {
                    let transition = self.invite_transition_binding();
                    node.validate()
                        && sealed_owner_key.validate()
                        && sealed_data_key.validate()
                        && sealed_owner_key.node == node.node
                        && sealed_data_key.node == node.node
                        && sealed_owner_key.recipient_key == node.encryption_public_key
                        && sealed_data_key.recipient_key == node.encryption_public_key
                        && historical_grants.len() <= MAX_PRIVATE_INVITE_HISTORY_EPOCHS
                        && historical_grants
                            .windows(2)
                            .all(|pair| pair[0].epoch < pair[1].epoch)
                        && historical_grants.iter().all(|grant| {
                            grant.validate()
                                && grant.space == self.space
                                && grant.agent == self.agent
                                && grant.owner == node.principal
                                && Some(grant.transition) == transition
                                && grant.recipient == node.node
                                && grant.recipient_key == node.encryption_public_key
                                && grant.epoch < *epoch
                        })
                }
                PrivateControlOperation::Revoke { node, next_epoch } => {
                    *node != NodeId::ZERO
                        && next_epoch.validate()
                        && next_epoch.space == self.space
                        && next_epoch.agent == self.agent
                }
                PrivateControlOperation::RotateKeys { next_epoch } => {
                    next_epoch.validate()
                        && next_epoch.space == self.space
                        && next_epoch.agent == self.agent
                }
                PrivateControlOperation::SetResourcePolicy { policy } => {
                    policy.hash != Hash::ZERO
                        && policy.len != 0
                        && policy.len <= crate::MAX_CATALOG_ARTIFACT_BYTES
                }
                PrivateControlOperation::ActorLifecycle { actor, request, .. } => {
                    *actor != ActorId::ZERO && *request != Hash::ZERO
                }
                PrivateControlOperation::Recover {
                    superseded_heads,
                    next_epoch,
                    replacement_nodes,
                    historical_keyring,
                } => {
                    superseded_heads.len() <= MAX_PRIVATE_NODES
                        && superseded_heads.iter().all(|head| *head != Hash::ZERO)
                        && superseded_heads.windows(2).all(|pair| pair[0] < pair[1])
                        && (superseded_heads.is_empty() == self.previous.is_none())
                        && next_epoch.validate()
                        && next_epoch.space == self.space
                        && next_epoch.agent == self.agent
                        && !replacement_nodes.is_empty()
                        && replacement_nodes.len() <= MAX_PRIVATE_NODES
                        && replacement_nodes.iter().all(PrivateNodeIdentity::validate)
                        && replacement_nodes
                            .windows(2)
                            .all(|pair| pair[0].node < pair[1].node)
                        && historical_keyring.validate()
                        && historical_keyring.key_commitment != next_epoch.data_key_commitment
                        && historical_keyring.ciphertext.space == self.space
                        && historical_keyring.ciphertext.agent == self.agent
                        && historical_keyring.ciphertext.epoch == next_epoch.epoch
                        && historical_keyring.sealed_keys.len() == replacement_nodes.len()
                        && historical_keyring
                            .sealed_keys
                            .iter()
                            .zip(replacement_nodes)
                            .all(|(sealed, node)| {
                                sealed.node == node.node
                                    && sealed.recipient_key == node.encryption_public_key
                            })
                }
            }
            && matches!(
                (&self.operation, self.signer),
                (
                    PrivateControlOperation::Recover { .. },
                    PrivateControlSigner::Recovery
                ) | (
                    PrivateControlOperation::Invite { .. }
                        | PrivateControlOperation::Revoke { .. }
                        | PrivateControlOperation::RotateKeys { .. }
                        | PrivateControlOperation::SetResourcePolicy { .. }
                        | PrivateControlOperation::ActorLifecycle { .. },
                    PrivateControlSigner::Owner
                )
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::CanonicalWire;

    struct ExactEnrollmentVerifier {
        public_key: [u8; 32],
        message: Vec<u8>,
        signature: [u8; PRIVATE_SIGNATURE_BYTES],
    }

    impl NodeEncryptionEnrollmentVerifier for ExactEnrollmentVerifier {
        fn verify(
            &self,
            public_key: &[u8; 32],
            message: &[u8],
            signature: &[u8; PRIVATE_SIGNATURE_BYTES],
        ) -> bool {
            *public_key == self.public_key
                && message == self.message
                && *signature == self.signature
        }
    }

    fn enrollment() -> NodeEncryptionEnrollment {
        NodeEncryptionEnrollment::from_keys(
            SpaceId([1; 32]),
            PrincipalId([2; 32]),
            [3; 32],
            [4; 32],
            [5; PRIVATE_SIGNATURE_BYTES],
        )
    }

    #[test]
    fn ed25519_enrollment_binds_exact_full_peer_node_and_x25519_key() {
        let enrollment = enrollment();
        assert_eq!(
            enrollment.transport_peer_id[..6],
            [0x00, 0x24, 0x08, 0x01, 0x12, 0x20]
        );
        assert_eq!(enrollment.transport_peer_id[6..], [3; 32]);
        assert_eq!(
            enrollment.node,
            NodeId::of_authenticated_peer(&enrollment.transport_peer_id)
        );
        assert!(enrollment.validate_shape());

        let verifier = ExactEnrollmentVerifier {
            public_key: enrollment.transport_public_key,
            message: enrollment.signing_bytes(),
            signature: enrollment.transport_signature,
        };
        assert!(enrollment.verify_with(&verifier));

        let identity = enrollment.verified_private_identity(&verifier).unwrap();
        assert!(identity.matches_enrollment(&enrollment));
        assert_eq!(identity.authority_binding, enrollment.commitment());

        let encoded = enrollment.encode().unwrap();
        assert_eq!(NodeEncryptionEnrollment::decode(&encoded), Ok(enrollment));
    }

    #[test]
    fn enrollment_rejects_compact_or_substituted_transport_evidence() {
        let enrollment = enrollment();
        let verifier = ExactEnrollmentVerifier {
            public_key: enrollment.transport_public_key,
            message: enrollment.signing_bytes(),
            signature: enrollment.transport_signature,
        };

        let mut compact = enrollment;
        compact.transport_peer_id[0] = 0x12;
        assert!(!compact.validate_shape());
        assert!(!compact.verify_with(&verifier));

        let mut substituted_node = enrollment;
        substituted_node.node = NodeId([7; 32]);
        assert!(!substituted_node.validate_shape());

        let mut substituted_recipient = enrollment;
        substituted_recipient.encryption_public_key = [8; 32];
        assert!(substituted_recipient.validate_shape());
        assert!(!substituted_recipient.verify_with(&verifier));

        let mut old_abi = enrollment.encode().unwrap();
        old_abi[4] ^= 0xff;
        assert!(NodeEncryptionEnrollment::decode(&old_abi).is_err());
    }

    #[test]
    fn encrypted_object_associated_data_binds_identity_epoch_kind_and_content() {
        let object = EncryptedPrivateObject {
            space: SpaceId([9; 32]),
            agent: AgentId([1; 32]),
            epoch: 7,
            kind: EncryptedObjectKind::Snapshot,
            content: Hash([2; 32]),
            nonce: [3; PRIVATE_NONCE_BYTES],
            ciphertext: alloc::vec![4; 32],
        };
        assert!(object.validate());
        let mut other = object.clone();
        other.epoch += 1;
        assert_ne!(object.associated_data(), other.associated_data());
        let mut other_space = object.clone();
        other_space.space = SpaceId([8; 32]);
        assert_ne!(object.associated_data(), other_space.associated_data());
    }

    #[test]
    fn private_key_seals_are_sorted_and_paired_by_exact_node() {
        let sealed = |node| SealedPrivateKey {
            node: NodeId([node; 32]),
            recipient_key: [node + 1; 32],
            sealed: alloc::vec![node; 48],
        };
        let mut epoch = PrivateKeyEpoch {
            space: SpaceId([9; 32]),
            agent: AgentId([1; 32]),
            epoch: 1,
            owner_key_commitment: Hash([2; 32]),
            data_key_commitment: Hash([3; 32]),
            recovery_key_commitment: Hash([4; 32]),
            recovery_encryption_public_key: [8; 32],
            sealed_recovery_data_key: SealedRecoveryKey {
                recipient_key: [8; 32],
                sealed: alloc::vec![9; 48],
            },
            sealed_owner_keys: alloc::vec![sealed(5), sealed(7)],
            sealed_data_keys: alloc::vec![sealed(5), sealed(7)],
        };
        assert!(epoch.validate());
        epoch.sealed_data_keys.swap(0, 1);
        assert!(!epoch.validate());
    }
}
