//! Canonical protocol records for owner-node-only Private agents.

use alloc::vec::Vec;

use crate::{ActorId, AgentId, BlobRef, Hash, NodeId, PrincipalId, SpaceId};

pub const MAX_PRIVATE_NODES: usize = 256;
pub const MAX_TRANSPORT_IDENTITY_BYTES: usize = 512;
pub const MAX_SEALED_KEY_BYTES: usize = 4 * 1024;
pub const MAX_PRIVATE_CIPHERTEXT_BYTES: usize = 8 * 1024 * 1024;
/// A recovery grant contains at most one fixed-size data-key entry for every
/// epoch which can precede a valid recovery control.
pub const MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS: usize = 4_096;
pub const MAX_PRIVATE_RECOVERY_KEYRING_CIPHERTEXT_BYTES: usize = 512 * 1024;
pub const PRIVATE_SIGNATURE_BYTES: usize = 64;
pub const PRIVATE_NONCE_BYTES: usize = 24;

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
                    sealed_owner_key,
                    sealed_data_key,
                    ..
                } => {
                    node.validate()
                        && sealed_owner_key.validate()
                        && sealed_data_key.validate()
                        && sealed_owner_key.node == node.node
                        && sealed_data_key.node == node.node
                        && sealed_owner_key.recipient_key == node.encryption_public_key
                        && sealed_data_key.recipient_key == node.encryption_public_key
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
