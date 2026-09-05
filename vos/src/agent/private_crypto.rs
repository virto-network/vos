//! Host-side cryptography and control-chain verification for Private agents.
//!
//! This module deliberately owns no persistence or anti-entropy. Callers may
//! persist canonical SDK records after successful verification, but plaintext
//! owner, data, recovery, and node-decryption keys remain in zeroizing wrappers
//! and are never included in a record.

use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use vos_agent_sdk::private::{
    EncryptedObjectKind, EncryptedPrivateObject, MAX_PRIVATE_CIPHERTEXT_BYTES, MAX_PRIVATE_NODES,
    PRIVATE_NONCE_BYTES, PrivateControlOperation, PrivateControlRecord, PrivateControlSigner,
    PrivateKeyEpoch, PrivateNodeIdentity, SealedPrivateKey,
};
use vos_agent_sdk::{AgentId, Hash, NodeId, PrincipalId, SpaceId};

const SECRET_BYTES: usize = 32;
const AEAD_TAG_BYTES: usize = 16;
const SEALED_MAGIC: &[u8; 4] = b"VPK1";
const SEALED_EPHEMERAL_BYTES: usize = 32;
const SEALED_NONCE_BYTES: usize = PRIVATE_NONCE_BYTES;
const SEALED_CIPHERTEXT_BYTES: usize = SECRET_BYTES + AEAD_TAG_BYTES;
const SEALED_BYTES: usize =
    SEALED_MAGIC.len() + SEALED_EPHEMERAL_BYTES + SEALED_NONCE_BYTES + SEALED_CIPHERTEXT_BYTES;

/// Hard ceiling for records replayed into one in-memory verifier instance.
/// A caller needing a later checkpoint must persist a separately authenticated
/// snapshot and replay into a fresh verifier; this module does not define that
/// persistence format.
pub const MAX_PRIVATE_CONTROL_RECORDS: u64 = 4_096;

const OWNER_PUBLIC_DOMAIN: &[u8] = b"vos/private/owner-signing-public/v1";
const DATA_KEY_DOMAIN: &[u8] = b"vos/private/data-key/v1";
const RECOVERY_PUBLIC_DOMAIN: &[u8] = b"vos/private/recovery-signing-public/v1";
const PLAINTEXT_DOMAIN: &[u8] = b"vos/private/plaintext/v1";
const SEAL_KDF_DOMAIN: &[u8] = b"vos/private/key-seal/kdf/v1";
const SEAL_AAD_DOMAIN: &[u8] = b"vos/private/key-seal/aad/v1";
const SEAL_SALT: &[u8] = b"vos/private/key-seal/salt/v1";
const OBJECT_KDF_DOMAIN: &[u8] = b"vos/private/object-key/kdf/v1";
const OBJECT_SALT: &[u8] = b"vos/private/object-key/salt/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateCryptoError {
    Randomness,
    InvalidKey,
    InvalidRecord,
    InvalidScope,
    InvalidEpoch,
    InvalidMembership,
    UnauthorizedNode,
    WrongRecipient,
    MissingRecipient,
    KeyAgreement,
    KeyDerivation,
    Encryption,
    Decryption,
    KeyCommitment,
    InvalidSignature,
    WrongSigner,
    WrongSequence,
    WrongPrevious,
    LimitExceeded,
}

impl fmt::Display for PrivateCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Private-agent cryptographic validation failed: {self:?}"
        )
    }
}

impl core::error::Error for PrivateCryptoError {}

struct Secret32(Zeroizing<[u8; SECRET_BYTES]>);

impl Secret32 {
    fn from_bytes(mut bytes: [u8; SECRET_BYTES]) -> Result<Self, PrivateCryptoError> {
        if bytes == [0; SECRET_BYTES] {
            bytes.zeroize();
            return Err(PrivateCryptoError::InvalidKey);
        }
        let secret = Self(Zeroizing::new(bytes));
        bytes.zeroize();
        Ok(secret)
    }

    fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, PrivateCryptoError> {
        let mut bytes = Zeroizing::new([0; SECRET_BYTES]);
        rng.try_fill_bytes(&mut *bytes)
            .map_err(|_| PrivateCryptoError::Randomness)?;
        if *bytes == [0; SECRET_BYTES] {
            return Err(PrivateCryptoError::Randomness);
        }
        Ok(Self(bytes))
    }

    fn bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.0
    }
}

/// Online Ed25519 key for ordinary Private control operations.
///
/// The seed is zeroized on drop and cannot be cloned or formatted.
pub struct OwnerSigningKey(Secret32);

impl OwnerSigningKey {
    /// Load a seed from an external secure keystore. The caller remains
    /// responsible for erasing any other copy it retained.
    pub fn from_seed(seed: [u8; SECRET_BYTES]) -> Result<Self, PrivateCryptoError> {
        Secret32::from_bytes(seed).map(Self)
    }

    pub fn generate() -> Result<Self, PrivateCryptoError> {
        Self::generate_with(&mut OsRng)
    }

    fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, PrivateCryptoError> {
        Secret32::generate(rng).map(Self)
    }

    pub fn verifying_key(&self) -> [u8; SECRET_BYTES] {
        SigningKey::from_bytes(self.0.bytes())
            .verifying_key()
            .to_bytes()
    }

    pub fn commitment(&self) -> Hash {
        owner_public_key_commitment(&self.verifying_key())
    }
}

/// Offline Ed25519 recovery key. Its seed is zeroized on drop and is never
/// sealed into a [`PrivateKeyEpoch`].
pub struct RecoverySigningKey(Secret32);

impl RecoverySigningKey {
    /// Load a seed from an external offline keystore. The caller remains
    /// responsible for erasing any other copy it retained.
    pub fn from_seed(seed: [u8; SECRET_BYTES]) -> Result<Self, PrivateCryptoError> {
        Secret32::from_bytes(seed).map(Self)
    }

    pub fn generate() -> Result<Self, PrivateCryptoError> {
        Self::generate_with(&mut OsRng)
    }

    fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, PrivateCryptoError> {
        Secret32::generate(rng).map(Self)
    }

    pub fn verifying_key(&self) -> [u8; SECRET_BYTES] {
        SigningKey::from_bytes(self.0.bytes())
            .verifying_key()
            .to_bytes()
    }

    pub fn commitment(&self) -> Hash {
        recovery_public_key_commitment(&self.verifying_key())
    }
}

/// Symmetric key for Private objects. Bytes are zeroized on drop and cannot
/// be cloned or formatted.
pub struct PrivateDataKey(Secret32);

impl PrivateDataKey {
    /// Load bytes from an external secure keystore. The caller remains
    /// responsible for erasing any other copy it retained.
    pub fn from_bytes(bytes: [u8; SECRET_BYTES]) -> Result<Self, PrivateCryptoError> {
        Secret32::from_bytes(bytes).map(Self)
    }

    pub fn generate() -> Result<Self, PrivateCryptoError> {
        Self::generate_with(&mut OsRng)
    }

    fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, PrivateCryptoError> {
        Secret32::generate(rng).map(Self)
    }

    pub fn commitment(&self) -> Hash {
        data_key_commitment(self.0.bytes())
    }
}

/// Long-lived X25519 recipient key held by an authenticated node. Bytes are
/// zeroized on drop and cannot be cloned or formatted.
pub struct PrivateNodeDecryptionKey(Secret32);

impl PrivateNodeDecryptionKey {
    /// Load bytes from the node's secure keystore. The caller remains
    /// responsible for erasing any other copy it retained.
    pub fn from_bytes(bytes: [u8; SECRET_BYTES]) -> Result<Self, PrivateCryptoError> {
        Secret32::from_bytes(bytes).map(Self)
    }

    pub fn generate() -> Result<Self, PrivateCryptoError> {
        Self::generate_with(&mut OsRng)
    }

    fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, PrivateCryptoError> {
        Secret32::generate(rng).map(Self)
    }

    pub fn public_key(&self) -> [u8; SECRET_BYTES] {
        let secret = StaticSecret::from(*self.0.bytes());
        X25519PublicKey::from(&secret).to_bytes()
    }
}

fn owner_public_key_commitment(public_key: &[u8; SECRET_BYTES]) -> Hash {
    Hash::digest(OWNER_PUBLIC_DOMAIN, &[public_key])
}

fn recovery_public_key_commitment(public_key: &[u8; SECRET_BYTES]) -> Hash {
    Hash::digest(RECOVERY_PUBLIC_DOMAIN, &[public_key])
}

fn data_key_commitment(key: &[u8; SECRET_BYTES]) -> Hash {
    Hash::digest(DATA_KEY_DOMAIN, &[key])
}

fn strict_ed25519_public_key(
    public_key: &[u8; SECRET_BYTES],
) -> Result<VerifyingKey, PrivateCryptoError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| PrivateCryptoError::InvalidKey)?;
    if key.is_weak() {
        return Err(PrivateCryptoError::InvalidKey);
    }
    Ok(key)
}

fn valid_x25519_public_key(public_key: &[u8; SECRET_BYTES]) -> bool {
    if *public_key == [0; SECRET_BYTES] {
        return false;
    }
    // X25519 public keys are Montgomery u-coordinates rather than encoded
    // group points. A contributory DH with a fixed non-secret probe rejects
    // the low-order inputs which a byte-shape check cannot distinguish.
    let probe = StaticSecret::from([0xA5; SECRET_BYTES]);
    probe
        .diffie_hellman(&X25519PublicKey::from(*public_key))
        .was_contributory()
}

/// Content identity authenticated by [`EncryptedPrivateObject`].
pub fn private_content_identity(plaintext: &[u8]) -> Hash {
    Hash::digest(PLAINTEXT_DOMAIN, &[plaintext])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum EpochKeyKind {
    Owner = 0,
    Data = 1,
}

#[derive(Clone, Copy)]
struct SealContext<'a> {
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    kind: EpochKeyKind,
    recipient_node: NodeId,
    recipient_key: &'a [u8; SECRET_BYTES],
    key_commitment: Hash,
    ephemeral_key: &'a [u8; SECRET_BYTES],
}

fn seal_context(domain: &[u8], input: SealContext<'_>) -> Vec<u8> {
    let mut context = Vec::with_capacity(
        domain.len() + 32 + 32 + 8 + 1 + 32 + SECRET_BYTES + 32 + SEALED_EPHEMERAL_BYTES,
    );
    context.extend_from_slice(domain);
    context.extend_from_slice(input.space.as_bytes());
    context.extend_from_slice(input.agent.as_bytes());
    context.extend_from_slice(&input.epoch.to_le_bytes());
    context.push(input.kind as u8);
    context.extend_from_slice(input.recipient_node.as_bytes());
    context.extend_from_slice(input.recipient_key);
    context.extend_from_slice(input.key_commitment.as_bytes());
    context.extend_from_slice(input.ephemeral_key);
    context
}

fn derive_seal_key(
    shared_secret: &[u8; SECRET_BYTES],
    context: &[u8],
) -> Result<Zeroizing<[u8; SECRET_BYTES]>, PrivateCryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(SEAL_SALT), shared_secret);
    let mut key = Zeroizing::new([0; SECRET_BYTES]);
    hkdf.expand(context, &mut *key)
        .map_err(|_| PrivateCryptoError::KeyDerivation)?;
    Ok(key)
}

fn sealed_envelope_has_strict_shape(sealed: &SealedPrivateKey) -> bool {
    if !sealed.validate()
        || sealed.sealed.len() != SEALED_BYTES
        || sealed.sealed.get(..SEALED_MAGIC.len()) != Some(SEALED_MAGIC)
        || !valid_x25519_public_key(&sealed.recipient_key)
    {
        return false;
    }
    let ephemeral_offset = SEALED_MAGIC.len();
    let nonce_offset = ephemeral_offset + SEALED_EPHEMERAL_BYTES;
    let ciphertext_offset = nonce_offset + SEALED_NONCE_BYTES;
    let ephemeral_public: [u8; SEALED_EPHEMERAL_BYTES] =
        match sealed.sealed[ephemeral_offset..nonce_offset].try_into() {
            Ok(public_key) => public_key,
            Err(_) => return false,
        };
    valid_x25519_public_key(&ephemeral_public)
        && sealed.sealed[nonce_offset..ciphertext_offset]
            .iter()
            .any(|byte| *byte != 0)
}

#[allow(clippy::too_many_arguments)]
fn seal_epoch_secret<R: RngCore + CryptoRng>(
    rng: &mut R,
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    kind: EpochKeyKind,
    secret: &[u8; SECRET_BYTES],
    key_commitment: Hash,
    recipient: &PrivateNodeIdentity,
) -> Result<SealedPrivateKey, PrivateCryptoError> {
    if space == SpaceId::ZERO
        || agent == AgentId::ZERO
        || !recipient.validate()
        || key_commitment == Hash::ZERO
    {
        return Err(PrivateCryptoError::InvalidRecord);
    }

    let ephemeral = Secret32::generate(rng)?;
    let ephemeral_secret = StaticSecret::from(*ephemeral.bytes());
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    let recipient_public = X25519PublicKey::from(recipient.encryption_public_key);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    if !shared.was_contributory() {
        return Err(PrivateCryptoError::KeyAgreement);
    }
    let input = SealContext {
        space,
        agent,
        epoch,
        kind,
        recipient_node: recipient.node,
        recipient_key: &recipient.encryption_public_key,
        key_commitment,
        ephemeral_key: &ephemeral_public,
    };
    let kdf_context = seal_context(SEAL_KDF_DOMAIN, input);
    let wrapping_key = derive_seal_key(shared.as_bytes(), &kdf_context)?;
    let aad = seal_context(SEAL_AAD_DOMAIN, input);
    let mut nonce = [0; SEALED_NONCE_BYTES];
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| PrivateCryptoError::Randomness)?;
    if nonce == [0; SEALED_NONCE_BYTES] {
        return Err(PrivateCryptoError::Randomness);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
        .map_err(|_| PrivateCryptoError::InvalidKey)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret,
                aad: &aad,
            },
        )
        .map_err(|_| PrivateCryptoError::Encryption)?;
    if ciphertext.len() != SEALED_CIPHERTEXT_BYTES {
        return Err(PrivateCryptoError::Encryption);
    }

    let mut sealed = Vec::with_capacity(SEALED_BYTES);
    sealed.extend_from_slice(SEALED_MAGIC);
    sealed.extend_from_slice(&ephemeral_public);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(SealedPrivateKey {
        node: recipient.node,
        recipient_key: recipient.encryption_public_key,
        sealed,
    })
}

#[allow(clippy::too_many_arguments)]
fn unseal_epoch_secret(
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    kind: EpochKeyKind,
    key_commitment: Hash,
    recipient_node: NodeId,
    recipient_key: &[u8; SECRET_BYTES],
    sealed: &SealedPrivateKey,
    decryption_key: &PrivateNodeDecryptionKey,
) -> Result<Secret32, PrivateCryptoError> {
    if sealed.node != recipient_node
        || sealed.recipient_key != *recipient_key
        || decryption_key.public_key() != *recipient_key
    {
        return Err(PrivateCryptoError::WrongRecipient);
    }
    if !sealed_envelope_has_strict_shape(sealed) {
        return Err(PrivateCryptoError::Decryption);
    }
    let ephemeral_offset = SEALED_MAGIC.len();
    let nonce_offset = ephemeral_offset + SEALED_EPHEMERAL_BYTES;
    let ciphertext_offset = nonce_offset + SEALED_NONCE_BYTES;
    let ephemeral_public: [u8; SEALED_EPHEMERAL_BYTES] = sealed.sealed
        [ephemeral_offset..nonce_offset]
        .try_into()
        .map_err(|_| PrivateCryptoError::Decryption)?;
    let nonce: [u8; SEALED_NONCE_BYTES] = sealed.sealed[nonce_offset..ciphertext_offset]
        .try_into()
        .map_err(|_| PrivateCryptoError::Decryption)?;
    if nonce == [0; SEALED_NONCE_BYTES] {
        return Err(PrivateCryptoError::Decryption);
    }
    let node_secret = StaticSecret::from(*decryption_key.0.bytes());
    let shared = node_secret.diffie_hellman(&X25519PublicKey::from(ephemeral_public));
    if !shared.was_contributory() {
        return Err(PrivateCryptoError::KeyAgreement);
    }
    let input = SealContext {
        space,
        agent,
        epoch,
        kind,
        recipient_node,
        recipient_key,
        key_commitment,
        ephemeral_key: &ephemeral_public,
    };
    let kdf_context = seal_context(SEAL_KDF_DOMAIN, input);
    let wrapping_key = derive_seal_key(shared.as_bytes(), &kdf_context)?;
    let aad = seal_context(SEAL_AAD_DOMAIN, input);
    let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
        .map_err(|_| PrivateCryptoError::InvalidKey)?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &sealed.sealed[ciphertext_offset..],
                aad: &aad,
            },
        )
        .map_err(|_| PrivateCryptoError::Decryption)?;
    if plaintext.len() != SECRET_BYTES {
        plaintext.zeroize();
        return Err(PrivateCryptoError::Decryption);
    }
    let mut bytes = Zeroizing::new([0; SECRET_BYTES]);
    bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(Secret32(bytes))
}

fn verify_unsealed_commitment(
    secret: &Secret32,
    kind: EpochKeyKind,
    expected: Hash,
) -> Result<(), PrivateCryptoError> {
    let actual = match kind {
        EpochKeyKind::Owner => {
            let public = SigningKey::from_bytes(secret.bytes())
                .verifying_key()
                .to_bytes();
            owner_public_key_commitment(&public)
        }
        EpochKeyKind::Data => data_key_commitment(secret.bytes()),
    };
    if actual != expected {
        return Err(PrivateCryptoError::KeyCommitment);
    }
    Ok(())
}

fn find_seal(
    seals: &[SealedPrivateKey],
    node: NodeId,
) -> Result<&SealedPrivateKey, PrivateCryptoError> {
    seals
        .binary_search_by_key(&node, |seal| seal.node)
        .ok()
        .and_then(|index| seals.get(index))
        .ok_or(PrivateCryptoError::MissingRecipient)
}

pub fn seal_owner_key_for_node(
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    key: &OwnerSigningKey,
    recipient: &PrivateNodeIdentity,
) -> Result<SealedPrivateKey, PrivateCryptoError> {
    seal_epoch_secret(
        &mut OsRng,
        space,
        agent,
        epoch,
        EpochKeyKind::Owner,
        key.0.bytes(),
        key.commitment(),
        recipient,
    )
}

pub fn seal_data_key_for_node(
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    key: &PrivateDataKey,
    recipient: &PrivateNodeIdentity,
) -> Result<SealedPrivateKey, PrivateCryptoError> {
    seal_epoch_secret(
        &mut OsRng,
        space,
        agent,
        epoch,
        EpochKeyKind::Data,
        key.0.bytes(),
        key.commitment(),
        recipient,
    )
}

pub fn unwrap_owner_key(
    epoch: &PrivateKeyEpoch,
    recipient: &PrivateNodeIdentity,
    decryption_key: &PrivateNodeDecryptionKey,
) -> Result<OwnerSigningKey, PrivateCryptoError> {
    if !epoch.validate() || !recipient.validate() {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    let sealed = find_seal(&epoch.sealed_owner_keys, recipient.node)?;
    let secret = unseal_epoch_secret(
        epoch.space,
        epoch.agent,
        epoch.epoch,
        EpochKeyKind::Owner,
        epoch.owner_key_commitment,
        recipient.node,
        &recipient.encryption_public_key,
        sealed,
        decryption_key,
    )?;
    verify_unsealed_commitment(&secret, EpochKeyKind::Owner, epoch.owner_key_commitment)?;
    Ok(OwnerSigningKey(secret))
}

pub fn unwrap_data_key(
    epoch: &PrivateKeyEpoch,
    recipient: &PrivateNodeIdentity,
    decryption_key: &PrivateNodeDecryptionKey,
) -> Result<PrivateDataKey, PrivateCryptoError> {
    if !epoch.validate() || !recipient.validate() {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    let sealed = find_seal(&epoch.sealed_data_keys, recipient.node)?;
    let secret = unseal_epoch_secret(
        epoch.space,
        epoch.agent,
        epoch.epoch,
        EpochKeyKind::Data,
        epoch.data_key_commitment,
        recipient.node,
        &recipient.encryption_public_key,
        sealed,
        decryption_key,
    )?;
    verify_unsealed_commitment(&secret, EpochKeyKind::Data, epoch.data_key_commitment)?;
    Ok(PrivateDataKey(secret))
}

/// Verification seam for system-authority evidence attached to a full
/// authenticated [`PrivateNodeIdentity`]. Implementations must validate the
/// transport signature and the nonzero authority-binding commitment for this
/// exact `(space, agent, expected principal, transport identity, NodeId,
/// encryption key)` tuple. There is intentionally no Principal-, SSH-, or
/// credential-only admission method.
pub trait PrivateNodeAuthorityVerifier {
    fn verify_private_node_binding(
        &self,
        space: SpaceId,
        agent: AgentId,
        expected_principal: PrincipalId,
        node: &PrivateNodeIdentity,
    ) -> bool;
}

fn validate_authorized_nodes<V: PrivateNodeAuthorityVerifier>(
    space: SpaceId,
    agent: AgentId,
    owner: PrincipalId,
    nodes: &[PrivateNodeIdentity],
    authority: &V,
) -> Result<(), PrivateCryptoError> {
    if space == SpaceId::ZERO || agent == AgentId::ZERO || owner == PrincipalId::ZERO {
        return Err(PrivateCryptoError::InvalidScope);
    }
    if nodes.is_empty() {
        return Err(PrivateCryptoError::InvalidMembership);
    }
    if nodes.len() > MAX_PRIVATE_NODES {
        return Err(PrivateCryptoError::LimitExceeded);
    }
    if nodes.windows(2).any(|pair| pair[0].node >= pair[1].node) {
        return Err(PrivateCryptoError::InvalidMembership);
    }
    if nodes.iter().any(|node| {
        !node.validate()
            || !valid_x25519_public_key(&node.encryption_public_key)
            || node.principal != owner
            || !authority.verify_private_node_binding(space, agent, owner, node)
    }) {
        return Err(PrivateCryptoError::UnauthorizedNode);
    }
    Ok(())
}

fn epoch_matches_nodes(epoch: &PrivateKeyEpoch, nodes: &[PrivateNodeIdentity]) -> bool {
    epoch.validate()
        && epoch.sealed_owner_keys.len() == nodes.len()
        && epoch
            .sealed_owner_keys
            .iter()
            .zip(&epoch.sealed_data_keys)
            .zip(nodes)
            .all(|((owner, data), node)| {
                sealed_envelope_has_strict_shape(owner)
                    && sealed_envelope_has_strict_shape(data)
                    && owner.sealed != data.sealed
                    && owner.node == node.node
                    && data.node == node.node
                    && owner.recipient_key == node.encryption_public_key
                    && data.recipient_key == node.encryption_public_key
            })
}

/// Fresh independently generated online owner and data keys plus the
/// ciphertext-only epoch record safe to persist.
pub struct GeneratedPrivateEpoch {
    pub record: PrivateKeyEpoch,
    pub owner_key: OwnerSigningKey,
    pub data_key: PrivateDataKey,
}

pub fn generate_fresh_private_epoch<V: PrivateNodeAuthorityVerifier>(
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    owner: PrincipalId,
    nodes: &[PrivateNodeIdentity],
    recovery_public_key: [u8; SECRET_BYTES],
    authority: &V,
) -> Result<GeneratedPrivateEpoch, PrivateCryptoError> {
    generate_fresh_private_epoch_with(
        &mut OsRng,
        space,
        agent,
        epoch,
        owner,
        nodes,
        recovery_public_key,
        authority,
    )
}

#[allow(clippy::too_many_arguments)]
fn generate_fresh_private_epoch_with<R, V>(
    rng: &mut R,
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    owner: PrincipalId,
    nodes: &[PrivateNodeIdentity],
    recovery_public_key: [u8; SECRET_BYTES],
    authority: &V,
) -> Result<GeneratedPrivateEpoch, PrivateCryptoError>
where
    R: RngCore + CryptoRng,
    V: PrivateNodeAuthorityVerifier,
{
    validate_authorized_nodes(space, agent, owner, nodes, authority)?;
    strict_ed25519_public_key(&recovery_public_key)?;
    let owner_key = OwnerSigningKey::generate_with(rng)?;
    let data_key = PrivateDataKey::generate_with(rng)?;
    let mut sealed_owner_keys = Vec::new();
    let mut sealed_data_keys = Vec::new();
    sealed_owner_keys
        .try_reserve(nodes.len())
        .map_err(|_| PrivateCryptoError::LimitExceeded)?;
    sealed_data_keys
        .try_reserve(nodes.len())
        .map_err(|_| PrivateCryptoError::LimitExceeded)?;
    for node in nodes {
        sealed_owner_keys.push(seal_epoch_secret(
            rng,
            space,
            agent,
            epoch,
            EpochKeyKind::Owner,
            owner_key.0.bytes(),
            owner_key.commitment(),
            node,
        )?);
        sealed_data_keys.push(seal_epoch_secret(
            rng,
            space,
            agent,
            epoch,
            EpochKeyKind::Data,
            data_key.0.bytes(),
            data_key.commitment(),
            node,
        )?);
    }
    let record = PrivateKeyEpoch {
        space,
        agent,
        epoch,
        owner_key_commitment: owner_key.commitment(),
        data_key_commitment: data_key.commitment(),
        recovery_key_commitment: recovery_public_key_commitment(&recovery_public_key),
        sealed_owner_keys,
        sealed_data_keys,
    };
    if !epoch_matches_nodes(&record, nodes) {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    Ok(GeneratedPrivateEpoch {
        record,
        owner_key,
        data_key,
    })
}

fn derive_object_key(
    data_key: &PrivateDataKey,
    associated_data: &[u8],
) -> Result<Zeroizing<[u8; SECRET_BYTES]>, PrivateCryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(OBJECT_SALT), data_key.0.bytes());
    let mut info = Vec::with_capacity(OBJECT_KDF_DOMAIN.len() + associated_data.len());
    info.extend_from_slice(OBJECT_KDF_DOMAIN);
    info.extend_from_slice(associated_data);
    let mut key = Zeroizing::new([0; SECRET_BYTES]);
    hkdf.expand(&info, &mut *key)
        .map_err(|_| PrivateCryptoError::KeyDerivation)?;
    Ok(key)
}

pub fn encrypt_private_object(
    data_key: &PrivateDataKey,
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    kind: EncryptedObjectKind,
    plaintext: &[u8],
) -> Result<EncryptedPrivateObject, PrivateCryptoError> {
    encrypt_private_object_with(&mut OsRng, data_key, space, agent, epoch, kind, plaintext)
}

fn encrypt_private_object_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    data_key: &PrivateDataKey,
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    kind: EncryptedObjectKind,
    plaintext: &[u8],
) -> Result<EncryptedPrivateObject, PrivateCryptoError> {
    if space == SpaceId::ZERO
        || agent == AgentId::ZERO
        || plaintext.len() > MAX_PRIVATE_CIPHERTEXT_BYTES.saturating_sub(AEAD_TAG_BYTES)
    {
        return Err(PrivateCryptoError::LimitExceeded);
    }
    let mut nonce = [0; PRIVATE_NONCE_BYTES];
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| PrivateCryptoError::Randomness)?;
    if nonce == [0; PRIVATE_NONCE_BYTES] {
        return Err(PrivateCryptoError::Randomness);
    }
    let mut object = EncryptedPrivateObject {
        space,
        agent,
        epoch,
        kind,
        content: private_content_identity(plaintext),
        nonce,
        ciphertext: Vec::new(),
    };
    let associated_data = object.associated_data();
    let object_key = derive_object_key(data_key, &associated_data)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*object_key)
        .map_err(|_| PrivateCryptoError::InvalidKey)?;
    object.ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&object.nonce),
            Payload {
                msg: plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| PrivateCryptoError::Encryption)?;
    if !object.validate() {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    Ok(object)
}

pub fn decrypt_private_object(
    data_key: &PrivateDataKey,
    object: &EncryptedPrivateObject,
) -> Result<Vec<u8>, PrivateCryptoError> {
    if !object.validate() {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    let associated_data = object.associated_data();
    let object_key = derive_object_key(data_key, &associated_data)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*object_key)
        .map_err(|_| PrivateCryptoError::InvalidKey)?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&object.nonce),
            Payload {
                msg: &object.ciphertext,
                aad: &associated_data,
            },
        )
        .map_err(|_| PrivateCryptoError::Decryption)?;
    if private_content_identity(&plaintext) != object.content {
        plaintext.zeroize();
        return Err(PrivateCryptoError::KeyCommitment);
    }
    Ok(plaintext)
}

fn sign_control_record(
    record: &mut PrivateControlRecord,
    signer: PrivateControlSigner,
    secret: &Secret32,
) -> Result<(), PrivateCryptoError> {
    let operation_matches = matches!(
        (&record.operation, signer),
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
    );
    if !operation_matches {
        return Err(PrivateCryptoError::WrongSigner);
    }
    let signing_key = SigningKey::from_bytes(secret.bytes());
    record.signer = signer;
    record.signer_public_key = signing_key.verifying_key().to_bytes();
    record.signature = [1; 64];
    if !record.validate_shape() {
        record.signature = [0; 64];
        return Err(PrivateCryptoError::InvalidRecord);
    }
    record.signature = [0; 64];
    record.signature = signing_key.sign(&record.signing_bytes()).to_bytes();
    if !record.validate_shape() {
        record.signature.zeroize();
        return Err(PrivateCryptoError::InvalidRecord);
    }
    Ok(())
}

pub fn sign_owner_control_record(
    record: &mut PrivateControlRecord,
    key: &OwnerSigningKey,
) -> Result<(), PrivateCryptoError> {
    sign_control_record(record, PrivateControlSigner::Owner, &key.0)
}

pub fn sign_recovery_control_record(
    record: &mut PrivateControlRecord,
    key: &RecoverySigningKey,
) -> Result<(), PrivateCryptoError> {
    sign_control_record(record, PrivateControlSigner::Recovery, &key.0)
}

pub fn verify_control_record_signature(
    record: &PrivateControlRecord,
) -> Result<(), PrivateCryptoError> {
    if !record.validate_shape() {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    let public_key = strict_ed25519_public_key(&record.signer_public_key)
        .map_err(|_| PrivateCryptoError::InvalidSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&record.signature);
    public_key
        .verify_strict(&record.signing_bytes(), &signature)
        .map_err(|_| PrivateCryptoError::InvalidSignature)
}

/// Stateful, bounded validator for one Private agent's monotonic control
/// chain. This type contains no secret material. Persistence and branch
/// transport are caller-owned boundaries; every supplied record is checked
/// synchronously against the current authenticated head.
pub struct PrivateControlChainVerifier {
    space: SpaceId,
    agent: AgentId,
    owner: PrincipalId,
    recovery_public_key: [u8; SECRET_BYTES],
    epoch: PrivateKeyEpoch,
    nodes: Vec<PrivateNodeIdentity>,
    head: Option<Hash>,
    next_sequence: u64,
    record_count: u64,
}

impl PrivateControlChainVerifier {
    pub fn new_genesis<V: PrivateNodeAuthorityVerifier>(
        space: SpaceId,
        agent: AgentId,
        owner: PrincipalId,
        recovery_public_key: [u8; SECRET_BYTES],
        epoch: PrivateKeyEpoch,
        nodes: Vec<PrivateNodeIdentity>,
        authority: &V,
    ) -> Result<Self, PrivateCryptoError> {
        validate_authorized_nodes(space, agent, owner, &nodes, authority)?;
        strict_ed25519_public_key(&recovery_public_key)?;
        if epoch.space != space
            || epoch.agent != agent
            || epoch.epoch != 0
            || epoch.recovery_key_commitment != recovery_public_key_commitment(&recovery_public_key)
            || !epoch_matches_nodes(&epoch, &nodes)
        {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        Ok(Self {
            space,
            agent,
            owner,
            recovery_public_key,
            epoch,
            nodes,
            head: None,
            next_sequence: 0,
            record_count: 0,
        })
    }

    pub fn head(&self) -> Option<Hash> {
        self.head
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn epoch(&self) -> &PrivateKeyEpoch {
        &self.epoch
    }

    pub fn nodes(&self) -> &[PrivateNodeIdentity] {
        &self.nodes
    }

    pub fn apply<V: PrivateNodeAuthorityVerifier>(
        &mut self,
        record: &PrivateControlRecord,
        authority: &V,
    ) -> Result<(), PrivateCryptoError> {
        if self.record_count >= MAX_PRIVATE_CONTROL_RECORDS {
            return Err(PrivateCryptoError::LimitExceeded);
        }
        if !record.validate_shape() {
            return Err(PrivateCryptoError::InvalidRecord);
        }
        if record.space != self.space || record.agent != self.agent {
            return Err(PrivateCryptoError::InvalidScope);
        }
        if record.sequence != self.next_sequence {
            return Err(PrivateCryptoError::WrongSequence);
        }
        if record.previous != self.head {
            return Err(PrivateCryptoError::WrongPrevious);
        }
        self.verify_current_signer(record)?;
        verify_control_record_signature(record)?;

        let mut next_epoch = self.epoch.clone();
        let mut next_nodes = self.nodes.clone();
        match &record.operation {
            PrivateControlOperation::Invite {
                node,
                epoch,
                sealed_owner_key,
                sealed_data_key,
            } => {
                if *epoch != self.epoch.epoch {
                    return Err(PrivateCryptoError::InvalidEpoch);
                }
                validate_authorized_nodes(
                    self.space,
                    self.agent,
                    self.owner,
                    core::slice::from_ref(node),
                    authority,
                )?;
                if next_nodes.len() >= MAX_PRIVATE_NODES {
                    return Err(PrivateCryptoError::LimitExceeded);
                }
                let position = next_nodes
                    .binary_search_by_key(&node.node, |entry| entry.node)
                    .err()
                    .ok_or(PrivateCryptoError::InvalidMembership)?;
                if sealed_owner_key.node != node.node
                    || sealed_data_key.node != node.node
                    || sealed_owner_key.recipient_key != node.encryption_public_key
                    || sealed_data_key.recipient_key != node.encryption_public_key
                    || !sealed_envelope_has_strict_shape(sealed_owner_key)
                    || !sealed_envelope_has_strict_shape(sealed_data_key)
                    || sealed_owner_key.sealed == sealed_data_key.sealed
                {
                    return Err(PrivateCryptoError::WrongRecipient);
                }
                next_nodes.insert(position, node.clone());
                next_epoch
                    .sealed_owner_keys
                    .insert(position, sealed_owner_key.clone());
                next_epoch
                    .sealed_data_keys
                    .insert(position, sealed_data_key.clone());
                if !epoch_matches_nodes(&next_epoch, &next_nodes) {
                    return Err(PrivateCryptoError::InvalidEpoch);
                }
            }
            PrivateControlOperation::Revoke {
                node,
                next_epoch: candidate,
            } => {
                let position = next_nodes
                    .binary_search_by_key(node, |entry| entry.node)
                    .map_err(|_| PrivateCryptoError::InvalidMembership)?;
                next_nodes.remove(position);
                self.validate_successor_epoch(candidate, &next_nodes, authority)?;
                next_epoch = candidate.clone();
            }
            PrivateControlOperation::RotateKeys {
                next_epoch: candidate,
            } => {
                self.validate_successor_epoch(candidate, &next_nodes, authority)?;
                next_epoch = candidate.clone();
            }
            PrivateControlOperation::Recover {
                superseded_heads,
                next_epoch: candidate,
                replacement_nodes,
            } => {
                let head = self.head.ok_or(PrivateCryptoError::WrongPrevious)?;
                if superseded_heads.binary_search(&head).is_err() {
                    return Err(PrivateCryptoError::WrongPrevious);
                }
                self.validate_successor_epoch(candidate, replacement_nodes, authority)?;
                next_nodes = replacement_nodes.clone();
                next_epoch = candidate.clone();
            }
            PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. } => {}
        }

        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(PrivateCryptoError::LimitExceeded)?;
        self.epoch = next_epoch;
        self.nodes = next_nodes;
        self.head = Some(record.commitment());
        self.next_sequence = next_sequence;
        self.record_count += 1;
        Ok(())
    }

    fn verify_current_signer(
        &self,
        record: &PrivateControlRecord,
    ) -> Result<(), PrivateCryptoError> {
        let matches = match record.signer {
            PrivateControlSigner::Owner => {
                owner_public_key_commitment(&record.signer_public_key)
                    == self.epoch.owner_key_commitment
            }
            PrivateControlSigner::Recovery => {
                record.signer_public_key == self.recovery_public_key
                    && recovery_public_key_commitment(&record.signer_public_key)
                        == self.epoch.recovery_key_commitment
            }
        };
        if !matches {
            return Err(PrivateCryptoError::WrongSigner);
        }
        Ok(())
    }

    fn validate_successor_epoch<V: PrivateNodeAuthorityVerifier>(
        &self,
        candidate: &PrivateKeyEpoch,
        nodes: &[PrivateNodeIdentity],
        authority: &V,
    ) -> Result<(), PrivateCryptoError> {
        if candidate.space != self.space
            || candidate.agent != self.agent
            || self.epoch.epoch.checked_add(1) != Some(candidate.epoch)
            || candidate.owner_key_commitment == self.epoch.owner_key_commitment
            || candidate.data_key_commitment == self.epoch.data_key_commitment
            || candidate.recovery_key_commitment != self.epoch.recovery_key_commitment
        {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        validate_authorized_nodes(self.space, self.agent, self.owner, nodes, authority)?;
        if !epoch_matches_nodes(candidate, nodes) {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use vos_agent_sdk::private::{MAX_SEALED_KEY_BYTES, PrivateActorLifecycleKind};
    use vos_agent_sdk::wire::CanonicalWire;
    use vos_agent_sdk::{ActorId, BlobRef};

    const TEST_BINDING_DOMAIN: &[u8] = b"vos/test/private-node-authority/v1";

    struct TestAuthority;

    impl TestAuthority {
        fn binding(
            space: SpaceId,
            agent: AgentId,
            principal: PrincipalId,
            node: &PrivateNodeIdentity,
        ) -> Hash {
            Hash::digest(
                TEST_BINDING_DOMAIN,
                &[
                    space.as_bytes(),
                    agent.as_bytes(),
                    principal.as_bytes(),
                    node.node.as_bytes(),
                    &node.transport_identity,
                    &node.encryption_public_key,
                    &node.transport_signature,
                ],
            )
        }
    }

    impl PrivateNodeAuthorityVerifier for TestAuthority {
        fn verify_private_node_binding(
            &self,
            space: SpaceId,
            agent: AgentId,
            expected_principal: PrincipalId,
            node: &PrivateNodeIdentity,
        ) -> bool {
            node.principal == expected_principal
                && node.authority_binding == Self::binding(space, agent, expected_principal, node)
        }
    }

    struct Recipient {
        identity: PrivateNodeIdentity,
        key: PrivateNodeDecryptionKey,
    }

    fn make_recipient(
        rng: &mut ChaCha20Rng,
        space: SpaceId,
        agent: AgentId,
        owner: PrincipalId,
        label: u8,
    ) -> Recipient {
        let key = PrivateNodeDecryptionKey::generate_with(rng).unwrap();
        let transport_identity = vec![label; 48];
        let mut identity = PrivateNodeIdentity {
            node: NodeId::of_authenticated_peer(&transport_identity),
            principal: owner,
            transport_identity,
            encryption_public_key: key.public_key(),
            authority_binding: Hash::ZERO,
            transport_signature: [label; 64],
        };
        identity.authority_binding = TestAuthority::binding(space, agent, owner, &identity);
        assert!(identity.validate());
        Recipient { identity, key }
    }

    struct Fixture {
        rng: ChaCha20Rng,
        space: SpaceId,
        agent: AgentId,
        owner: PrincipalId,
        recovery: RecoverySigningKey,
        recipients: Vec<Recipient>,
        generated: GeneratedPrivateEpoch,
    }

    fn fixture(count: usize) -> Fixture {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let space = SpaceId([1; 32]);
        let agent = AgentId([2; 32]);
        let owner = PrincipalId([3; 32]);
        let recovery = RecoverySigningKey::generate_with(&mut rng).unwrap();
        let mut recipients: Vec<_> = (0..count)
            .map(|index| {
                make_recipient(
                    &mut rng,
                    space,
                    agent,
                    owner,
                    u8::try_from(index + 11).unwrap(),
                )
            })
            .collect();
        recipients.sort_by_key(|recipient| recipient.identity.node);
        let nodes: Vec<_> = recipients
            .iter()
            .map(|recipient| recipient.identity.clone())
            .collect();
        let generated = generate_fresh_private_epoch_with(
            &mut rng,
            space,
            agent,
            0,
            owner,
            &nodes,
            recovery.verifying_key(),
            &TestAuthority,
        )
        .unwrap();
        Fixture {
            rng,
            space,
            agent,
            owner,
            recovery,
            recipients,
            generated,
        }
    }

    fn nodes(fixture: &Fixture) -> Vec<PrivateNodeIdentity> {
        fixture
            .recipients
            .iter()
            .map(|recipient| recipient.identity.clone())
            .collect()
    }

    fn new_chain(fixture: &Fixture) -> PrivateControlChainVerifier {
        PrivateControlChainVerifier::new_genesis(
            fixture.space,
            fixture.agent,
            fixture.owner,
            fixture.recovery.verifying_key(),
            fixture.generated.record.clone(),
            nodes(fixture),
            &TestAuthority,
        )
        .unwrap()
    }

    fn unsigned_record(
        fixture: &Fixture,
        sequence: u64,
        previous: Option<Hash>,
        operation: PrivateControlOperation,
    ) -> PrivateControlRecord {
        PrivateControlRecord {
            space: fixture.space,
            agent: fixture.agent,
            sequence,
            previous,
            operation,
            signer: PrivateControlSigner::Owner,
            signer_public_key: [0; 32],
            signature: [0; 64],
        }
    }

    fn policy_operation(byte: u8) -> PrivateControlOperation {
        PrivateControlOperation::SetResourcePolicy {
            policy: BlobRef {
                hash: Hash([byte; 32]),
                len: 1,
            },
        }
    }

    #[test]
    fn epoch_seals_objects_signatures_and_sdk_wires_round_trip() {
        let mut fixture = fixture(2);
        assert_ne!(
            fixture.generated.record.sealed_owner_keys,
            fixture.generated.record.sealed_data_keys
        );
        for recipient in &fixture.recipients {
            let owner = unwrap_owner_key(
                &fixture.generated.record,
                &recipient.identity,
                &recipient.key,
            )
            .unwrap();
            let data = unwrap_data_key(
                &fixture.generated.record,
                &recipient.identity,
                &recipient.key,
            )
            .unwrap();
            assert_eq!(owner.commitment(), fixture.generated.owner_key.commitment());
            assert_eq!(data.commitment(), fixture.generated.data_key.commitment());
        }
        let epoch_wire = fixture.generated.record.encode().unwrap();
        assert_eq!(
            PrivateKeyEpoch::decode(&epoch_wire),
            Ok(fixture.generated.record.clone())
        );

        let sentinel = b"PRIVATE-PLAINTEXT-SENTINEL-6f13";
        let object = encrypt_private_object_with(
            &mut fixture.rng,
            &fixture.generated.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Snapshot,
            sentinel,
        )
        .unwrap();
        assert_eq!(
            decrypt_private_object(&fixture.generated.data_key, &object).unwrap(),
            sentinel
        );
        let object_wire = object.encode().unwrap();
        assert!(
            !object_wire
                .windows(sentinel.len())
                .any(|window| window == sentinel)
        );

        let mut record = unsigned_record(&fixture, 0, None, policy_operation(19));
        sign_owner_control_record(&mut record, &fixture.generated.owner_key).unwrap();
        verify_control_record_signature(&record).unwrap();
        let record_wire = record.encode().unwrap();
        assert_eq!(PrivateControlRecord::decode(&record_wire), Ok(record));
    }

    #[test]
    fn key_seal_rejects_every_scope_kind_and_recipient_substitution() {
        let mut fixture = fixture(1);
        let recipient = &fixture.recipients[0];
        unwrap_owner_key(
            &fixture.generated.record,
            &recipient.identity,
            &recipient.key,
        )
        .unwrap();

        let mut changed_space = fixture.generated.record.clone();
        changed_space.space = SpaceId([31; 32]);
        assert!(unwrap_owner_key(&changed_space, &recipient.identity, &recipient.key).is_err());
        let mut changed_agent = fixture.generated.record.clone();
        changed_agent.agent = AgentId([32; 32]);
        assert!(unwrap_owner_key(&changed_agent, &recipient.identity, &recipient.key).is_err());
        let mut changed_epoch = fixture.generated.record.clone();
        changed_epoch.epoch += 1;
        assert!(unwrap_owner_key(&changed_epoch, &recipient.identity, &recipient.key).is_err());

        let mut changed_kind = fixture.generated.record.clone();
        changed_kind.sealed_data_keys = changed_kind.sealed_owner_keys.clone();
        assert!(unwrap_data_key(&changed_kind, &recipient.identity, &recipient.key).is_err());

        let owner_seal = &fixture.generated.record.sealed_owner_keys[0];
        let mut changed_node = owner_seal.clone();
        changed_node.node = NodeId([33; 32]);
        assert!(
            unseal_epoch_secret(
                fixture.space,
                fixture.agent,
                0,
                EpochKeyKind::Owner,
                fixture.generated.record.owner_key_commitment,
                changed_node.node,
                &recipient.identity.encryption_public_key,
                &changed_node,
                &recipient.key,
            )
            .is_err()
        );

        let other = make_recipient(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            fixture.owner,
            91,
        );
        let mut changed_recipient = owner_seal.clone();
        changed_recipient.node = other.identity.node;
        changed_recipient.recipient_key = other.identity.encryption_public_key;
        assert!(
            unseal_epoch_secret(
                fixture.space,
                fixture.agent,
                0,
                EpochKeyKind::Owner,
                fixture.generated.record.owner_key_commitment,
                other.identity.node,
                &other.identity.encryption_public_key,
                &changed_recipient,
                &other.key,
            )
            .is_err()
        );

        let mut changed_commitment = fixture.generated.record.clone();
        changed_commitment.owner_key_commitment = Hash([34; 32]);
        assert!(
            unwrap_owner_key(&changed_commitment, &recipient.identity, &recipient.key).is_err()
        );
        let mut changed_ephemeral = fixture.generated.record.clone();
        changed_ephemeral.sealed_owner_keys[0].sealed[SEALED_MAGIC.len()] ^= 1;
        assert!(unwrap_owner_key(&changed_ephemeral, &recipient.identity, &recipient.key).is_err());
        let mut changed_nonce = fixture.generated.record.clone();
        changed_nonce.sealed_owner_keys[0].sealed[SEALED_MAGIC.len() + SEALED_EPHEMERAL_BYTES] ^= 1;
        assert!(unwrap_owner_key(&changed_nonce, &recipient.identity, &recipient.key).is_err());
        let mut changed_ciphertext = fixture.generated.record.clone();
        changed_ciphertext.sealed_owner_keys[0].sealed
            [SEALED_MAGIC.len() + SEALED_EPHEMERAL_BYTES + SEALED_NONCE_BYTES] ^= 1;
        assert!(
            unwrap_owner_key(&changed_ciphertext, &recipient.identity, &recipient.key).is_err()
        );
    }

    #[test]
    fn private_object_rejects_all_header_nonce_ciphertext_and_key_substitutions() {
        let mut fixture = fixture(1);
        let object = encrypt_private_object_with(
            &mut fixture.rng,
            &fixture.generated.data_key,
            fixture.space,
            fixture.agent,
            0,
            EncryptedObjectKind::Blob,
            b"authenticated private value",
        )
        .unwrap();
        assert_eq!(
            object.content,
            private_content_identity(b"authenticated private value")
        );

        let mut variants = Vec::new();
        let mut changed = object.clone();
        changed.space = SpaceId([41; 32]);
        variants.push(changed);
        let mut changed = object.clone();
        changed.agent = AgentId([42; 32]);
        variants.push(changed);
        let mut changed = object.clone();
        changed.epoch += 1;
        variants.push(changed);
        let mut changed = object.clone();
        changed.kind = EncryptedObjectKind::Index;
        variants.push(changed);
        let mut changed = object.clone();
        changed.content = Hash([43; 32]);
        variants.push(changed);
        let mut changed = object.clone();
        changed.nonce[0] ^= 1;
        variants.push(changed);
        let mut changed = object.clone();
        changed.ciphertext[0] ^= 1;
        variants.push(changed);
        assert!(variants.iter().all(|changed| {
            decrypt_private_object(&fixture.generated.data_key, changed).is_err()
        }));

        let wrong_key = PrivateDataKey::generate_with(&mut fixture.rng).unwrap();
        assert!(decrypt_private_object(&wrong_key, &object).is_err());
    }

    #[test]
    fn chain_rejects_wrong_signer_sequence_previous_principal_and_authority() {
        let mut fixture = fixture(1);

        let mut wrong_signer_chain = new_chain(&fixture);
        let alien = OwnerSigningKey::generate_with(&mut fixture.rng).unwrap();
        let mut record = unsigned_record(&fixture, 0, None, policy_operation(51));
        sign_owner_control_record(&mut record, &alien).unwrap();
        assert_eq!(
            wrong_signer_chain.apply(&record, &TestAuthority),
            Err(PrivateCryptoError::WrongSigner)
        );

        let mut wrong_sequence_chain = new_chain(&fixture);
        let mut record = unsigned_record(&fixture, 1, Some(Hash([50; 32])), policy_operation(52));
        sign_owner_control_record(&mut record, &fixture.generated.owner_key).unwrap();
        assert_eq!(
            wrong_sequence_chain.apply(&record, &TestAuthority),
            Err(PrivateCryptoError::WrongSequence)
        );

        let mut chain = new_chain(&fixture);
        let mut first = unsigned_record(&fixture, 0, None, policy_operation(53));
        sign_owner_control_record(&mut first, &fixture.generated.owner_key).unwrap();
        chain.apply(&first, &TestAuthority).unwrap();
        let mut invalid_signature = first.clone();
        invalid_signature.signature[0] ^= 1;
        assert_eq!(
            verify_control_record_signature(&invalid_signature),
            Err(PrivateCryptoError::InvalidSignature)
        );
        let mut wrong_previous =
            unsigned_record(&fixture, 1, Some(Hash([54; 32])), policy_operation(55));
        sign_owner_control_record(&mut wrong_previous, &fixture.generated.owner_key).unwrap();
        assert_eq!(
            chain.apply(&wrong_previous, &TestAuthority),
            Err(PrivateCryptoError::WrongPrevious)
        );

        let mut unauthorized = make_recipient(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            PrincipalId([56; 32]),
            57,
        );
        let owner_seal = seal_epoch_secret(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            0,
            EpochKeyKind::Owner,
            fixture.generated.owner_key.0.bytes(),
            fixture.generated.owner_key.commitment(),
            &unauthorized.identity,
        )
        .unwrap();
        let data_seal = seal_epoch_secret(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            0,
            EpochKeyKind::Data,
            fixture.generated.data_key.0.bytes(),
            fixture.generated.data_key.commitment(),
            &unauthorized.identity,
        )
        .unwrap();
        let mut invite = unsigned_record(
            &fixture,
            1,
            chain.head(),
            PrivateControlOperation::Invite {
                node: unauthorized.identity.clone(),
                epoch: 0,
                sealed_owner_key: owner_seal,
                sealed_data_key: data_seal,
            },
        );
        sign_owner_control_record(&mut invite, &fixture.generated.owner_key).unwrap();
        assert_eq!(
            chain.apply(&invite, &TestAuthority),
            Err(PrivateCryptoError::UnauthorizedNode)
        );

        unauthorized.identity.principal = fixture.owner;
        unauthorized.identity.authority_binding = Hash([58; 32]);
        let owner_seal = seal_epoch_secret(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            0,
            EpochKeyKind::Owner,
            fixture.generated.owner_key.0.bytes(),
            fixture.generated.owner_key.commitment(),
            &unauthorized.identity,
        )
        .unwrap();
        let data_seal = seal_epoch_secret(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            0,
            EpochKeyKind::Data,
            fixture.generated.data_key.0.bytes(),
            fixture.generated.data_key.commitment(),
            &unauthorized.identity,
        )
        .unwrap();
        let mut invite = unsigned_record(
            &fixture,
            1,
            chain.head(),
            PrivateControlOperation::Invite {
                node: unauthorized.identity,
                epoch: 0,
                sealed_owner_key: owner_seal,
                sealed_data_key: data_seal,
            },
        );
        sign_owner_control_record(&mut invite, &fixture.generated.owner_key).unwrap();
        assert_eq!(
            chain.apply(&invite, &TestAuthority),
            Err(PrivateCryptoError::UnauthorizedNode)
        );
    }

    #[test]
    fn invite_and_rotation_preserve_exact_sorted_membership() {
        let mut fixture = fixture(1);
        let invited = make_recipient(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            fixture.owner,
            59,
        );
        let sealed_owner_key = seal_epoch_secret(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            0,
            EpochKeyKind::Owner,
            fixture.generated.owner_key.0.bytes(),
            fixture.generated.owner_key.commitment(),
            &invited.identity,
        )
        .unwrap();
        let sealed_data_key = seal_epoch_secret(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            0,
            EpochKeyKind::Data,
            fixture.generated.data_key.0.bytes(),
            fixture.generated.data_key.commitment(),
            &invited.identity,
        )
        .unwrap();
        let mut invite = unsigned_record(
            &fixture,
            0,
            None,
            PrivateControlOperation::Invite {
                node: invited.identity.clone(),
                epoch: 0,
                sealed_owner_key,
                sealed_data_key,
            },
        );
        sign_owner_control_record(&mut invite, &fixture.generated.owner_key).unwrap();
        let mut chain = new_chain(&fixture);
        chain.apply(&invite, &TestAuthority).unwrap();
        assert!(
            chain
                .nodes()
                .windows(2)
                .all(|pair| pair[0].node < pair[1].node)
        );
        assert_eq!(chain.nodes().len(), 2);
        assert_eq!(
            unwrap_owner_key(chain.epoch(), &invited.identity, &invited.key)
                .unwrap()
                .commitment(),
            fixture.generated.owner_key.commitment()
        );
        assert_eq!(
            unwrap_data_key(chain.epoch(), &invited.identity, &invited.key)
                .unwrap()
                .commitment(),
            fixture.generated.data_key.commitment()
        );

        let members = chain.nodes().to_vec();
        let successor = generate_fresh_private_epoch_with(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            1,
            fixture.owner,
            &members,
            fixture.recovery.verifying_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut rotate = unsigned_record(
            &fixture,
            1,
            chain.head(),
            PrivateControlOperation::RotateKeys {
                next_epoch: successor.record.clone(),
            },
        );
        sign_owner_control_record(&mut rotate, &fixture.generated.owner_key).unwrap();
        chain.apply(&rotate, &TestAuthority).unwrap();
        assert_eq!(chain.nodes(), members);
        assert_eq!(chain.epoch().epoch, 1);
        assert_eq!(
            chain.epoch().data_key_commitment,
            successor.data_key.commitment()
        );
        assert_eq!(
            chain.epoch().owner_key_commitment,
            successor.owner_key.commitment()
        );
    }

    #[test]
    fn revocation_rotates_both_compromised_keys_and_omits_exact_node() {
        let mut fixture = fixture(2);
        let revoked_node = fixture.recipients[0].identity.clone();
        let survivor = fixture.recipients[1].identity.clone();
        let successor = generate_fresh_private_epoch_with(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            1,
            fixture.owner,
            core::slice::from_ref(&survivor),
            fixture.recovery.verifying_key(),
            &TestAuthority,
        )
        .unwrap();
        assert_ne!(
            successor.record.owner_key_commitment,
            fixture.generated.record.owner_key_commitment
        );
        assert_ne!(
            successor.record.data_key_commitment,
            fixture.generated.record.data_key_commitment
        );
        let mut record = unsigned_record(
            &fixture,
            0,
            None,
            PrivateControlOperation::Revoke {
                node: revoked_node.node,
                next_epoch: successor.record.clone(),
            },
        );
        sign_owner_control_record(&mut record, &fixture.generated.owner_key).unwrap();
        let mut chain = new_chain(&fixture);
        chain.apply(&record, &TestAuthority).unwrap();
        assert_eq!(chain.nodes(), core::slice::from_ref(&survivor));
        assert!(matches!(
            unwrap_data_key(chain.epoch(), &revoked_node, &fixture.recipients[0].key),
            Err(PrivateCryptoError::MissingRecipient)
        ));
        assert_eq!(
            unwrap_data_key(chain.epoch(), &survivor, &fixture.recipients[1].key)
                .unwrap()
                .commitment(),
            successor.data_key.commitment()
        );
    }

    #[test]
    fn recovery_supersedes_sorted_heads_and_admits_only_replacements() {
        let mut fixture = fixture(1);
        let mut chain = new_chain(&fixture);
        let mut first = unsigned_record(
            &fixture,
            0,
            None,
            PrivateControlOperation::ActorLifecycle {
                actor: ActorId([61; 32]),
                operation: PrivateActorLifecycleKind::Suspend,
                request: Hash([62; 32]),
            },
        );
        sign_owner_control_record(&mut first, &fixture.generated.owner_key).unwrap();
        chain.apply(&first, &TestAuthority).unwrap();
        let current_head = chain.head().unwrap();

        let replacement = make_recipient(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            fixture.owner,
            63,
        );
        let successor = generate_fresh_private_epoch_with(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            1,
            fixture.owner,
            core::slice::from_ref(&replacement.identity),
            fixture.recovery.verifying_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut heads = vec![current_head, Hash([64; 32])];
        heads.sort();
        heads.dedup();
        assert_eq!(heads.len(), 2);
        let mut recovery = unsigned_record(
            &fixture,
            1,
            Some(current_head),
            PrivateControlOperation::Recover {
                superseded_heads: heads.clone(),
                next_epoch: successor.record.clone(),
                replacement_nodes: vec![replacement.identity.clone()],
            },
        );
        let mut unsorted = recovery.clone();
        let PrivateControlOperation::Recover {
            superseded_heads, ..
        } = &mut unsorted.operation
        else {
            unreachable!()
        };
        superseded_heads.swap(0, 1);
        assert_eq!(
            sign_recovery_control_record(&mut unsorted, &fixture.recovery),
            Err(PrivateCryptoError::InvalidRecord)
        );
        assert_eq!(
            sign_owner_control_record(&mut recovery.clone(), &fixture.generated.owner_key),
            Err(PrivateCryptoError::WrongSigner)
        );
        let wrong_recovery_key = RecoverySigningKey::generate_with(&mut fixture.rng).unwrap();
        let mut wrong_recovery = recovery.clone();
        sign_recovery_control_record(&mut wrong_recovery, &wrong_recovery_key).unwrap();
        assert_eq!(
            chain.apply(&wrong_recovery, &TestAuthority),
            Err(PrivateCryptoError::WrongSigner)
        );
        let mut missing_current_head = recovery.clone();
        let PrivateControlOperation::Recover {
            superseded_heads, ..
        } = &mut missing_current_head.operation
        else {
            unreachable!()
        };
        *superseded_heads = vec![Hash([65; 32])];
        sign_recovery_control_record(&mut missing_current_head, &fixture.recovery).unwrap();
        assert_eq!(
            chain.apply(&missing_current_head, &TestAuthority),
            Err(PrivateCryptoError::WrongPrevious)
        );
        sign_recovery_control_record(&mut recovery, &fixture.recovery).unwrap();
        chain.apply(&recovery, &TestAuthority).unwrap();
        assert_eq!(chain.nodes(), core::slice::from_ref(&replacement.identity));
        assert_eq!(chain.epoch().epoch, 1);
        assert_eq!(
            unwrap_data_key(chain.epoch(), &replacement.identity, &replacement.key)
                .unwrap()
                .commitment(),
            successor.data_key.commitment()
        );
        assert!(matches!(
            unwrap_data_key(
                chain.epoch(),
                &fixture.recipients[0].identity,
                &fixture.recipients[0].key,
            ),
            Err(PrivateCryptoError::MissingRecipient)
        ));
    }

    #[test]
    fn membership_and_envelope_bounds_fail_before_acceptance() {
        let mut fixture = fixture(2);
        let mut unsorted = nodes(&fixture);
        unsorted.swap(0, 1);
        assert_eq!(
            generate_fresh_private_epoch_with(
                &mut fixture.rng,
                fixture.space,
                fixture.agent,
                1,
                fixture.owner,
                &unsorted,
                fixture.recovery.verifying_key(),
                &TestAuthority,
            )
            .err(),
            Some(PrivateCryptoError::InvalidMembership)
        );
        let too_many = vec![fixture.recipients[0].identity.clone(); MAX_PRIVATE_NODES + 1];
        assert_eq!(
            generate_fresh_private_epoch_with(
                &mut fixture.rng,
                fixture.space,
                fixture.agent,
                1,
                fixture.owner,
                &too_many,
                fixture.recovery.verifying_key(),
                &TestAuthority,
            )
            .err(),
            Some(PrivateCryptoError::LimitExceeded)
        );
        let duplicate = vec![
            fixture.recipients[0].identity.clone(),
            fixture.recipients[0].identity.clone(),
        ];
        assert_eq!(
            generate_fresh_private_epoch_with(
                &mut fixture.rng,
                fixture.space,
                fixture.agent,
                1,
                fixture.owner,
                &duplicate,
                fixture.recovery.verifying_key(),
                &TestAuthority,
            )
            .err(),
            Some(PrivateCryptoError::InvalidMembership)
        );

        let recipient = &fixture.recipients[0];
        let mut truncated = fixture.generated.record.clone();
        truncated.sealed_owner_keys[0].sealed.pop();
        assert!(unwrap_owner_key(&truncated, &recipient.identity, &recipient.key).is_err());
        let mut chain = new_chain(&fixture);
        chain.record_count = MAX_PRIVATE_CONTROL_RECORDS;
        let mut bounded = unsigned_record(&fixture, 0, None, policy_operation(71));
        sign_owner_control_record(&mut bounded, &fixture.generated.owner_key).unwrap();
        assert_eq!(
            chain.apply(&bounded, &TestAuthority),
            Err(PrivateCryptoError::LimitExceeded)
        );
        assert!(SEALED_BYTES <= MAX_SEALED_KEY_BYTES);
        assert_eq!(MAX_PRIVATE_CONTROL_RECORDS, 4_096);
    }
}
