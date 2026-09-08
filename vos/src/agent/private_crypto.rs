//! Host-side cryptography and control-chain verification for Private agents.
//!
//! This module deliberately owns no persistence or anti-entropy. Callers may
//! persist canonical SDK records after successful verification, but plaintext
//! owner, data, recovery, and node-decryption keys remain in zeroizing wrappers
//! and are never included in a record.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use vos_agent_sdk::authority::ManagedAgentTarget;
use vos_agent_sdk::authority_operation::PrivateRecoveryAuthorityProofSigner;
use vos_agent_sdk::private::{
    EncryptedObjectKind, EncryptedPrivateObject, MAX_PRIVATE_CIPHERTEXT_BYTES,
    MAX_PRIVATE_INVITE_HISTORY_EPOCHS, MAX_PRIVATE_NODES,
    MAX_PRIVATE_RECOVERY_KEYRING_CIPHERTEXT_BYTES, MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS,
    NodeEncryptionEnrollmentVerifier, PRIVATE_INVITE_HISTORY_SEALED_KEY_BYTES, PRIVATE_NONCE_BYTES,
    PRIVATE_SIGNATURE_BYTES, PrivateControlOperation, PrivateControlRecord, PrivateControlSigner,
    PrivateInviteHistoryGrant, PrivateKeyEpoch, PrivateNodeIdentity, PrivateRecoveryKeyringGrant,
    SealedPrivateKey, SealedRecoveryKey, recovery_signing_public_key_commitment,
    valid_x25519_public_key as sdk_valid_x25519_public_key,
};
use vos_agent_sdk::wire::{CanonicalWire, authority_private_node_identity_commitment};
use vos_agent_sdk::{AgentId, Hash, NodeId, PrincipalId, RUNTIME_ABI_ID, SpaceId};
use vos_protocol::wire::{DecodeError, Decoder, Encoder};

const SECRET_BYTES: usize = 32;
const AEAD_TAG_BYTES: usize = 16;
const SEALED_MAGIC: &[u8; 4] = b"VPK1";
const SEALED_EPHEMERAL_BYTES: usize = 32;
const SEALED_NONCE_BYTES: usize = PRIVATE_NONCE_BYTES;
const SEALED_CIPHERTEXT_BYTES: usize = SECRET_BYTES + AEAD_TAG_BYTES;
const SEALED_BYTES: usize =
    SEALED_MAGIC.len() + SEALED_EPHEMERAL_BYTES + SEALED_NONCE_BYTES + SEALED_CIPHERTEXT_BYTES;
const RECOVERY_SEALED_MAGIC: &[u8; 4] = b"VRK1";
const INVITE_HISTORY_SEALED_MAGIC: &[u8; 4] = b"VIH1";

/// Hard ceiling for records replayed into one in-memory verifier instance.
/// A caller needing a later checkpoint must persist a separately authenticated
/// snapshot and replay into a fresh verifier; this module does not define that
/// persistence format.
pub const MAX_PRIVATE_CONTROL_RECORDS: u64 = 4_096;

const OWNER_PUBLIC_DOMAIN: &[u8] = b"vos/private/owner-signing-public/v1";
const DATA_KEY_DOMAIN: &[u8] = b"vos/private/data-key/v1";
const CONTENT_IDENTITY_DOMAIN: &[u8] = b"vos/private/content-identity/v2";
const SEAL_KDF_DOMAIN: &[u8] = b"vos/private/key-seal/kdf/v1";
const SEAL_AAD_DOMAIN: &[u8] = b"vos/private/key-seal/aad/v1";
const SEAL_SALT: &[u8] = b"vos/private/key-seal/salt/v1";
const RECOVERY_SEAL_KDF_DOMAIN: &[u8] = b"vos/private/recovery-data-seal/kdf/v1";
const RECOVERY_SEAL_AAD_DOMAIN: &[u8] = b"vos/private/recovery-data-seal/aad/v1";
const RECOVERY_SEAL_SALT: &[u8] = b"vos/private/recovery-data-seal/salt/v1";
const INVITE_HISTORY_SEAL_KDF_DOMAIN: &[u8] = b"vos/private/invite-history-seal/kdf/v1";
const INVITE_HISTORY_SEAL_AAD_DOMAIN: &[u8] = b"vos/private/invite-history-seal/aad/v1";
const INVITE_HISTORY_SEAL_SALT: &[u8] = b"vos/private/invite-history-seal/salt/v1";
const OBJECT_KDF_DOMAIN: &[u8] = b"vos/private/object-key/kdf/v1";
const OBJECT_SALT: &[u8] = b"vos/private/object-key/salt/v1";
const RECOVERY_KEYRING_MAGIC: &[u8; 4] = b"PVKG";
const RECOVERY_KEYRING_VERSION: u16 = 1;
const RECOVERY_KEYRING_FIXED_BYTES: usize = 4 + 2 + 32 + 32 + 32 + 8 + 4;
const RECOVERY_KEYRING_ENTRY_BYTES: usize = 8 + 32 + SECRET_BYTES;
const RECOVERY_PLAN_KDF_SALT: &[u8] = b"vos/private/recovery-plan-auth/salt/v1";
const RECOVERY_PLAN_KDF_DOMAIN: &[u8] = b"vos/private/recovery-plan-auth/v1";
const REPLICA_ESTABLISHMENT_PLAN_KDF_SALT: &[u8] =
    b"vos/private/replica-establishment-plan-auth/salt/v1";
const REPLICA_ESTABLISHMENT_PLAN_KDF_DOMAIN: &[u8] =
    b"vos/private/replica-establishment-plan-auth/v1";
const STABLE_IMPORT_CERTIFICATE_BODY_DOMAIN: &[u8] =
    b"vos/private/stable-import-certificate/body/v1";
const STABLE_IMPORT_CERTIFICATE_KDF_SALT: &[u8] =
    b"vos/private/stable-import-certificate-auth/salt/v1";
const STABLE_IMPORT_CERTIFICATE_KDF_DOMAIN: &[u8] =
    b"vos/private/stable-import-certificate-auth/v1";

/// Exact PSI1 framing: canonical header, destination/source context, and MAC.
pub(crate) const PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES: usize = 4 + 32 + 10 * 32 + 32;

/// Destination-authenticated proof that one fully verified source PSE2 was
/// accepted only after this node durably produced and reopened its own PAPL.
///
/// PSI1 is node-local and intentionally absent from Store core commitments,
/// portable Store archives, and sync frames. Decoding proves canonical shape
/// only; consumers must call [`Self::verify_for`] with every independently
/// reopened input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateStableImportCertificate {
    route: ManagedAgentTarget,
    owner: PrincipalId,
    descriptor: Hash,
    destination_identity: Hash,
    control: Hash,
    local_application: Hash,
    source_evidence: Hash,
    stable_projection: Hash,
    authenticator: Hash,
}

impl PrivateStableImportCertificate {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue(
        route: ManagedAgentTarget,
        owner: PrincipalId,
        descriptor: Hash,
        destination: &PrivateNodeIdentity,
        control: Hash,
        local_application: Hash,
        source_evidence: Hash,
        stable_projection: Hash,
        node_key: &PrivateNodeDecryptionKey,
    ) -> Result<Self, PrivateCryptoError> {
        if !destination.validate()
            || destination.principal != owner
            || destination.encryption_public_key != node_key.public_key()
        {
            return Err(PrivateCryptoError::InvalidScope);
        }
        let mut certificate = Self {
            route,
            owner,
            descriptor,
            destination_identity: authority_private_node_identity_commitment(destination),
            control,
            local_application,
            source_evidence,
            stable_projection,
            authenticator: Hash::ZERO,
        };
        if !certificate.validate_context() {
            return Err(PrivateCryptoError::InvalidRecord);
        }
        certificate.authenticator =
            node_key.stable_import_certificate_authenticator(certificate.body_commitment())?;
        if certificate.authenticator == Hash::ZERO {
            return Err(PrivateCryptoError::KeyDerivation);
        }
        Ok(certificate)
    }

    pub(crate) const fn route(&self) -> ManagedAgentTarget {
        self.route
    }

    pub(crate) const fn owner(&self) -> PrincipalId {
        self.owner
    }

    pub(crate) const fn descriptor(&self) -> Hash {
        self.descriptor
    }

    pub(crate) const fn destination_identity(&self) -> Hash {
        self.destination_identity
    }

    pub(crate) const fn control(&self) -> Hash {
        self.control
    }

    pub(crate) const fn local_application(&self) -> Hash {
        self.local_application
    }

    pub(crate) const fn source_evidence(&self) -> Hash {
        self.source_evidence
    }

    pub(crate) const fn stable_projection(&self) -> Hash {
        self.stable_projection
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_for(
        &self,
        route: ManagedAgentTarget,
        owner: PrincipalId,
        descriptor: Hash,
        destination: &PrivateNodeIdentity,
        control: Hash,
        local_application: Hash,
        source_evidence: Hash,
        stable_projection: Hash,
        node_key: &PrivateNodeDecryptionKey,
    ) -> Result<(), PrivateCryptoError> {
        let expected_authenticator =
            node_key.stable_import_certificate_authenticator(self.body_commitment())?;
        if !destination.validate()
            || destination.principal != owner
            || destination.encryption_public_key != node_key.public_key()
            || self.route != route
            || self.owner != owner
            || self.descriptor != descriptor
            || self.destination_identity != authority_private_node_identity_commitment(destination)
            || self.control != control
            || self.local_application != local_application
            || self.source_evidence != source_evidence
            || self.stable_projection != stable_projection
            || !self.validate_context()
            || self.authenticator == Hash::ZERO
            || !bool::from(
                expected_authenticator
                    .as_bytes()
                    .ct_eq(self.authenticator.as_bytes()),
            )
        {
            return Err(PrivateCryptoError::InvalidSignature);
        }
        Ok(())
    }

    fn validate_context(&self) -> bool {
        self.route.is_valid()
            && self.owner != PrincipalId::ZERO
            && self.descriptor != Hash::ZERO
            && self.destination_identity != Hash::ZERO
            && self.control != Hash::ZERO
            && self.local_application != Hash::ZERO
            && self.source_evidence != Hash::ZERO
            && self.stable_projection != Hash::ZERO
    }

    fn body_commitment(&self) -> Hash {
        let mut bytes = Vec::with_capacity(PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES - 32);
        bytes.extend_from_slice(&Self::MAGIC);
        bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(&mut bytes);
        encode_stable_import_certificate_context(&mut encoder, self);
        Hash::digest(STABLE_IMPORT_CERTIFICATE_BODY_DOMAIN, &[&bytes])
    }
}

fn encode_stable_import_certificate_context(
    encoder: &mut Encoder<'_>,
    certificate: &PrivateStableImportCertificate,
) {
    encoder.fixed(certificate.route.space.as_bytes());
    encoder.fixed(certificate.route.agent.as_bytes());
    encoder.fixed(certificate.route.runtime_deployment.as_bytes());
    encoder.fixed(certificate.owner.as_bytes());
    encoder.fixed(certificate.descriptor.as_bytes());
    encoder.fixed(certificate.destination_identity.as_bytes());
    encoder.fixed(certificate.control.as_bytes());
    encoder.fixed(certificate.local_application.as_bytes());
    encoder.fixed(certificate.source_evidence.as_bytes());
    encoder.fixed(certificate.stable_projection.as_bytes());
}

impl CanonicalWire for PrivateStableImportCertificate {
    const MAGIC: [u8; 4] = *b"PSI1";
    const MAX_ENCODED_BYTES: usize = PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES;

    fn validate_wire(&self) -> bool {
        self.validate_context() && self.authenticator != Hash::ZERO
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        encode_stable_import_certificate_context(encoder, self);
        encoder.fixed(self.authenticator.as_bytes());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let certificate = Self {
            route: ManagedAgentTarget {
                space: SpaceId(decoder.fixed()?),
                agent: AgentId(decoder.fixed()?),
                runtime_deployment: vos_agent_sdk::DeploymentId(decoder.fixed()?),
            },
            owner: PrincipalId(decoder.fixed()?),
            descriptor: Hash(decoder.fixed()?),
            destination_identity: Hash(decoder.fixed()?),
            control: Hash(decoder.fixed()?),
            local_application: Hash(decoder.fixed()?),
            source_evidence: Hash(decoder.fixed()?),
            stable_projection: Hash(decoder.fixed()?),
            authenticator: Hash(decoder.fixed()?),
        };
        certificate
            .validate_wire()
            .then_some(certificate)
            .ok_or(DecodeError::NonCanonical)
    }
}

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

impl PrivateRecoveryAuthorityProofSigner for RecoverySigningKey {
    fn recovery_public_key(&self) -> [u8; SECRET_BYTES] {
        self.verifying_key()
    }

    fn sign_private_recovery_authority_proof(
        &self,
        message: &[u8],
    ) -> [u8; PRIVATE_SIGNATURE_BYTES] {
        SigningKey::from_bytes(self.0.bytes())
            .sign(message)
            .to_bytes()
    }
}

/// X25519 secret held with the offline recovery kit. It is independent of the
/// Ed25519 recovery-signing seed and is never admitted as a Node identity.
pub struct OfflineRecoveryDecryptionKey(Secret32);

impl OfflineRecoveryDecryptionKey {
    pub fn from_bytes(bytes: [u8; SECRET_BYTES]) -> Result<Self, PrivateCryptoError> {
        Secret32::from_bytes(bytes).map(Self)
    }

    pub fn generate() -> Result<Self, PrivateCryptoError> {
        Secret32::generate(&mut OsRng).map(Self)
    }

    fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, PrivateCryptoError> {
        Secret32::generate(rng).map(Self)
    }

    pub fn public_key(&self) -> [u8; SECRET_BYTES] {
        let secret = StaticSecret::from(*self.0.bytes());
        X25519PublicKey::from(&secret).to_bytes()
    }
}

/// Both independent secret halves required by one offline recovery ceremony.
/// The kit is non-cloneable, non-formattable, and zeroizes both halves.
pub struct OfflineRecoveryKit {
    signing: RecoverySigningKey,
    decryption: OfflineRecoveryDecryptionKey,
}

impl OfflineRecoveryKit {
    pub fn new(
        signing: RecoverySigningKey,
        decryption: OfflineRecoveryDecryptionKey,
    ) -> Result<Self, PrivateCryptoError> {
        if signing.0.bytes() == decryption.0.bytes()
            || signing.verifying_key() == decryption.public_key()
        {
            return Err(PrivateCryptoError::InvalidKey);
        }
        Ok(Self {
            signing,
            decryption,
        })
    }

    pub fn signing_public_key(&self) -> [u8; SECRET_BYTES] {
        self.signing.verifying_key()
    }

    pub fn encryption_public_key(&self) -> [u8; SECRET_BYTES] {
        self.decryption.public_key()
    }

    pub(crate) fn signing_key(&self) -> &RecoverySigningKey {
        &self.signing
    }

    pub(crate) fn decryption_key(&self) -> &OfflineRecoveryDecryptionKey {
        &self.decryption
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

    /// Copy into a zeroizing buffer solely for canonical encrypted keyring
    /// construction. Callers must never persist the returned plaintext.
    pub(crate) fn recovery_bytes(&self) -> Zeroizing<[u8; SECRET_BYTES]> {
        Zeroizing::new(*self.0.bytes())
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

    /// Authenticate a bounded ciphertext-only recovery plan to this exact
    /// host recipient. This is used only to resume already-prepared random
    /// recovery bytes after a crash; it never authenticates network input.
    pub(crate) fn recovery_plan_authenticator(
        &self,
        plan_hash: Hash,
    ) -> Result<Hash, PrivateCryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(RECOVERY_PLAN_KDF_SALT), self.0.bytes());
        let mut info = Vec::with_capacity(RECOVERY_PLAN_KDF_DOMAIN.len() + 32);
        info.extend_from_slice(RECOVERY_PLAN_KDF_DOMAIN);
        info.extend_from_slice(plan_hash.as_bytes());
        let mut output = Zeroizing::new([0; SECRET_BYTES]);
        hkdf.expand(&info, &mut *output)
            .map_err(|_| PrivateCryptoError::KeyDerivation)?;
        Ok(Hash(*output))
    }

    /// Authenticate one bounded, ciphertext-only replica-establishment plan
    /// to this exact destination. A distinct KDF domain prevents a staged
    /// import manifest from being replayed as an offline-recovery plan.
    pub(crate) fn replica_establishment_plan_authenticator(
        &self,
        plan_hash: Hash,
    ) -> Result<Hash, PrivateCryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(REPLICA_ESTABLISHMENT_PLAN_KDF_SALT), self.0.bytes());
        let mut info = Vec::with_capacity(REPLICA_ESTABLISHMENT_PLAN_KDF_DOMAIN.len() + 32);
        info.extend_from_slice(REPLICA_ESTABLISHMENT_PLAN_KDF_DOMAIN);
        info.extend_from_slice(plan_hash.as_bytes());
        let mut output = Zeroizing::new([0; SECRET_BYTES]);
        hkdf.expand(&info, &mut *output)
            .map_err(|_| PrivateCryptoError::KeyDerivation)?;
        Ok(Hash(*output))
    }

    /// Authenticate one PSI1 body to this exact destination-node secret.
    /// Separate salt and info domains prevent either authenticator from being
    /// replayed as a recovery-plan MAC or another node-key derivation.
    fn stable_import_certificate_authenticator(
        &self,
        body_hash: Hash,
    ) -> Result<Hash, PrivateCryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(STABLE_IMPORT_CERTIFICATE_KDF_SALT), self.0.bytes());
        let mut info = Vec::with_capacity(STABLE_IMPORT_CERTIFICATE_KDF_DOMAIN.len() + 32);
        info.extend_from_slice(STABLE_IMPORT_CERTIFICATE_KDF_DOMAIN);
        info.extend_from_slice(body_hash.as_bytes());
        let mut output = Zeroizing::new([0; SECRET_BYTES]);
        hkdf.expand(&info, &mut *output)
            .map_err(|_| PrivateCryptoError::KeyDerivation)?;
        Ok(Hash(*output))
    }
}

fn owner_public_key_commitment(public_key: &[u8; SECRET_BYTES]) -> Hash {
    Hash::digest(OWNER_PUBLIC_DOMAIN, &[public_key])
}

fn recovery_public_key_commitment(public_key: &[u8; SECRET_BYTES]) -> Hash {
    recovery_signing_public_key_commitment(public_key)
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

pub(crate) fn valid_x25519_public_key(public_key: &[u8; SECRET_BYTES]) -> bool {
    if !sdk_valid_x25519_public_key(public_key) {
        return false;
    }
    // Keep an independent contributory-DH check at the cryptographic use
    // boundary. The SDK predicate above is also required because RFC 7748
    // masks bit 255 and would otherwise accept high-bit aliases.
    let probe = StaticSecret::from([0xA5; SECRET_BYTES]);
    probe
        .diffie_hellman(&X25519PublicKey::from(*public_key))
        .was_contributory()
}

/// Epoch-confidential content identity authenticated by
/// [`EncryptedPrivateObject`].
///
/// The identity is a keyed, domain-separated digest. Its exact private data
/// epoch key and complete object scope prevent equal plaintext from becoming
/// linkable across spaces, agents, epochs, or object kinds.
pub fn private_content_identity(
    data_key: &PrivateDataKey,
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    kind: EncryptedObjectKind,
    plaintext: &[u8],
) -> Hash {
    let mut parameters = blake2b_simd::Params::new();
    parameters.hash_length(32).key(data_key.0.bytes());
    let mut state = parameters.to_state();
    state.update(CONTENT_IDENTITY_DOMAIN);
    state.update(space.as_bytes());
    state.update(agent.as_bytes());
    state.update(&epoch.to_le_bytes());
    state.update(&[kind as u8]);
    state.update(&(plaintext.len() as u64).to_le_bytes());
    state.update(plaintext);
    let digest = state.finalize();
    let mut identity = [0; 32];
    identity.copy_from_slice(digest.as_bytes());
    Hash(identity)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum EpochKeyKind {
    Owner = 0,
    Data = 1,
    History = 2,
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
    salt: &[u8],
    shared_secret: &[u8; SECRET_BYTES],
    context: &[u8],
) -> Result<Zeroizing<[u8; SECRET_BYTES]>, PrivateCryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
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
    let wrapping_key = derive_seal_key(SEAL_SALT, shared.as_bytes(), &kdf_context)?;
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
    let wrapping_key = derive_seal_key(SEAL_SALT, shared.as_bytes(), &kdf_context)?;
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

#[derive(Clone, Copy)]
struct InviteHistorySealContext<'a> {
    space: SpaceId,
    agent: AgentId,
    owner: PrincipalId,
    transition: Hash,
    epoch: u64,
    recipient_node: NodeId,
    recipient_key: &'a [u8; SECRET_BYTES],
    data_key_commitment: Hash,
    ephemeral_key: &'a [u8; SECRET_BYTES],
}

fn invite_history_seal_context(domain: &[u8], input: InviteHistorySealContext<'_>) -> Vec<u8> {
    let mut context = Vec::with_capacity(domain.len() + 8 * 32 + 8);
    context.extend_from_slice(domain);
    context.extend_from_slice(input.space.as_bytes());
    context.extend_from_slice(input.agent.as_bytes());
    context.extend_from_slice(input.owner.as_bytes());
    context.extend_from_slice(input.transition.as_bytes());
    context.extend_from_slice(&input.epoch.to_le_bytes());
    context.extend_from_slice(input.recipient_node.as_bytes());
    context.extend_from_slice(input.recipient_key);
    context.extend_from_slice(input.data_key_commitment.as_bytes());
    context.extend_from_slice(input.ephemeral_key);
    context
}

fn invite_history_sealed_envelope_has_strict_shape(grant: &PrivateInviteHistoryGrant) -> bool {
    if !grant.validate()
        || grant.sealed_data_key.sealed.len() != SEALED_BYTES
        || SEALED_BYTES != PRIVATE_INVITE_HISTORY_SEALED_KEY_BYTES
        || grant
            .sealed_data_key
            .sealed
            .get(..INVITE_HISTORY_SEALED_MAGIC.len())
            != Some(INVITE_HISTORY_SEALED_MAGIC)
        || !valid_x25519_public_key(&grant.recipient_key)
    {
        return false;
    }
    let ephemeral_offset = INVITE_HISTORY_SEALED_MAGIC.len();
    let nonce_offset = ephemeral_offset + SEALED_EPHEMERAL_BYTES;
    let ciphertext_offset = nonce_offset + SEALED_NONCE_BYTES;
    let Ok(ephemeral_public) = grant.sealed_data_key.sealed[ephemeral_offset..nonce_offset]
        .try_into()
        .map(|value: [u8; SEALED_EPHEMERAL_BYTES]| value)
    else {
        return false;
    };
    valid_x25519_public_key(&ephemeral_public)
        && grant.sealed_data_key.sealed[nonce_offset..ciphertext_offset]
            .iter()
            .any(|byte| *byte != 0)
}

#[allow(clippy::too_many_arguments)]
fn seal_invite_history_data_key_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    space: SpaceId,
    agent: AgentId,
    owner: PrincipalId,
    transition: Hash,
    epoch: u64,
    data_key: &PrivateDataKey,
    recipient: &PrivateNodeIdentity,
) -> Result<PrivateInviteHistoryGrant, PrivateCryptoError> {
    if space == SpaceId::ZERO
        || agent == AgentId::ZERO
        || owner == PrincipalId::ZERO
        || transition == Hash::ZERO
        || !recipient.validate()
        || recipient.principal != owner
    {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    let ephemeral = Secret32::generate(rng)?;
    let ephemeral_secret = StaticSecret::from(*ephemeral.bytes());
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    let shared =
        ephemeral_secret.diffie_hellman(&X25519PublicKey::from(recipient.encryption_public_key));
    if !shared.was_contributory() {
        return Err(PrivateCryptoError::KeyAgreement);
    }
    let input = InviteHistorySealContext {
        space,
        agent,
        owner,
        transition,
        epoch,
        recipient_node: recipient.node,
        recipient_key: &recipient.encryption_public_key,
        data_key_commitment: data_key.commitment(),
        ephemeral_key: &ephemeral_public,
    };
    let kdf_context = invite_history_seal_context(INVITE_HISTORY_SEAL_KDF_DOMAIN, input);
    let wrapping_key = derive_seal_key(INVITE_HISTORY_SEAL_SALT, shared.as_bytes(), &kdf_context)?;
    let aad = invite_history_seal_context(INVITE_HISTORY_SEAL_AAD_DOMAIN, input);
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
                msg: data_key.0.bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| PrivateCryptoError::Encryption)?;
    if ciphertext.len() != SEALED_CIPHERTEXT_BYTES {
        return Err(PrivateCryptoError::Encryption);
    }
    let mut sealed = Vec::with_capacity(SEALED_BYTES);
    sealed.extend_from_slice(INVITE_HISTORY_SEALED_MAGIC);
    sealed.extend_from_slice(&ephemeral_public);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    let grant = PrivateInviteHistoryGrant {
        space,
        agent,
        owner,
        transition,
        recipient: recipient.node,
        recipient_key: recipient.encryption_public_key,
        epoch,
        data_key_commitment: data_key.commitment(),
        sealed_data_key: SealedPrivateKey {
            node: recipient.node,
            recipient_key: recipient.encryption_public_key,
            sealed,
        },
    };
    invite_history_sealed_envelope_has_strict_shape(&grant)
        .then_some(grant)
        .ok_or(PrivateCryptoError::Encryption)
}

fn unwrap_invite_history_data_key(
    grant: &PrivateInviteHistoryGrant,
    recipient: &PrivateNodeIdentity,
    decryption_key: &PrivateNodeDecryptionKey,
) -> Result<PrivateDataKey, PrivateCryptoError> {
    if !invite_history_sealed_envelope_has_strict_shape(grant)
        || !recipient.validate()
        || grant.owner != recipient.principal
        || grant.recipient != recipient.node
        || grant.recipient_key != recipient.encryption_public_key
        || decryption_key.public_key() != recipient.encryption_public_key
    {
        return Err(PrivateCryptoError::WrongRecipient);
    }
    let ephemeral_offset = INVITE_HISTORY_SEALED_MAGIC.len();
    let nonce_offset = ephemeral_offset + SEALED_EPHEMERAL_BYTES;
    let ciphertext_offset = nonce_offset + SEALED_NONCE_BYTES;
    let ephemeral_public: [u8; SEALED_EPHEMERAL_BYTES] = grant.sealed_data_key.sealed
        [ephemeral_offset..nonce_offset]
        .try_into()
        .map_err(|_| PrivateCryptoError::Decryption)?;
    let nonce: [u8; SEALED_NONCE_BYTES] = grant.sealed_data_key.sealed
        [nonce_offset..ciphertext_offset]
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
    let input = InviteHistorySealContext {
        space: grant.space,
        agent: grant.agent,
        owner: grant.owner,
        transition: grant.transition,
        epoch: grant.epoch,
        recipient_node: grant.recipient,
        recipient_key: &grant.recipient_key,
        data_key_commitment: grant.data_key_commitment,
        ephemeral_key: &ephemeral_public,
    };
    let kdf_context = invite_history_seal_context(INVITE_HISTORY_SEAL_KDF_DOMAIN, input);
    let wrapping_key = derive_seal_key(INVITE_HISTORY_SEAL_SALT, shared.as_bytes(), &kdf_context)?;
    let aad = invite_history_seal_context(INVITE_HISTORY_SEAL_AAD_DOMAIN, input);
    let cipher = XChaCha20Poly1305::new_from_slice(&*wrapping_key)
        .map_err(|_| PrivateCryptoError::InvalidKey)?;
    let mut plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &grant.sealed_data_key.sealed[ciphertext_offset..],
                aad: &aad,
            },
        )
        .map_err(|_| PrivateCryptoError::Decryption)?;
    if plaintext.len() != SECRET_BYTES {
        plaintext.zeroize();
        return Err(PrivateCryptoError::Decryption);
    }
    let mut raw = Zeroizing::new([0; SECRET_BYTES]);
    raw.copy_from_slice(&plaintext);
    plaintext.zeroize();
    let key = PrivateDataKey(Secret32(raw));
    if key.commitment() != grant.data_key_commitment {
        return Err(PrivateCryptoError::KeyCommitment);
    }
    Ok(key)
}

#[derive(Clone, Copy)]
struct RecoverySealContext<'a> {
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    recipient_key: &'a [u8; SECRET_BYTES],
    data_key_commitment: Hash,
    ephemeral_key: &'a [u8; SECRET_BYTES],
}

fn recovery_seal_context(domain: &[u8], input: RecoverySealContext<'_>) -> Vec<u8> {
    let mut context = Vec::with_capacity(domain.len() + 32 + 32 + 8 + 32 + 32 + 32);
    context.extend_from_slice(domain);
    context.extend_from_slice(input.space.as_bytes());
    context.extend_from_slice(input.agent.as_bytes());
    context.extend_from_slice(&input.epoch.to_le_bytes());
    context.extend_from_slice(input.recipient_key);
    context.extend_from_slice(input.data_key_commitment.as_bytes());
    context.extend_from_slice(input.ephemeral_key);
    context
}

fn recovery_sealed_envelope_has_strict_shape(sealed: &SealedRecoveryKey) -> bool {
    if !sealed.validate()
        || sealed.sealed.len() != SEALED_BYTES
        || sealed.sealed.get(..RECOVERY_SEALED_MAGIC.len()) != Some(RECOVERY_SEALED_MAGIC)
        || !valid_x25519_public_key(&sealed.recipient_key)
    {
        return false;
    }
    let ephemeral_offset = RECOVERY_SEALED_MAGIC.len();
    let nonce_offset = ephemeral_offset + SEALED_EPHEMERAL_BYTES;
    let ciphertext_offset = nonce_offset + SEALED_NONCE_BYTES;
    let Ok(ephemeral_public) = sealed.sealed[ephemeral_offset..nonce_offset]
        .try_into()
        .map(|value: [u8; SEALED_EPHEMERAL_BYTES]| value)
    else {
        return false;
    };
    valid_x25519_public_key(&ephemeral_public)
        && sealed.sealed[nonce_offset..ciphertext_offset]
            .iter()
            .any(|byte| *byte != 0)
}

#[allow(clippy::too_many_arguments)]
fn seal_recovery_data_key_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    data_key: &PrivateDataKey,
    recipient_key: [u8; SECRET_BYTES],
) -> Result<SealedRecoveryKey, PrivateCryptoError> {
    if space == SpaceId::ZERO || agent == AgentId::ZERO || !valid_x25519_public_key(&recipient_key)
    {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    let ephemeral = Secret32::generate(rng)?;
    let ephemeral_secret = StaticSecret::from(*ephemeral.bytes());
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&X25519PublicKey::from(recipient_key));
    if !shared.was_contributory() {
        return Err(PrivateCryptoError::KeyAgreement);
    }
    let input = RecoverySealContext {
        space,
        agent,
        epoch,
        recipient_key: &recipient_key,
        data_key_commitment: data_key.commitment(),
        ephemeral_key: &ephemeral_public,
    };
    let kdf_context = recovery_seal_context(RECOVERY_SEAL_KDF_DOMAIN, input);
    let wrapping_key = derive_seal_key(RECOVERY_SEAL_SALT, shared.as_bytes(), &kdf_context)?;
    let aad = recovery_seal_context(RECOVERY_SEAL_AAD_DOMAIN, input);
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
                msg: data_key.0.bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| PrivateCryptoError::Encryption)?;
    if ciphertext.len() != SEALED_CIPHERTEXT_BYTES {
        return Err(PrivateCryptoError::Encryption);
    }
    let mut bytes = Vec::with_capacity(SEALED_BYTES);
    bytes.extend_from_slice(RECOVERY_SEALED_MAGIC);
    bytes.extend_from_slice(&ephemeral_public);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    Ok(SealedRecoveryKey {
        recipient_key,
        sealed: bytes,
    })
}

pub fn seal_recovery_data_key(
    space: SpaceId,
    agent: AgentId,
    epoch: u64,
    data_key: &PrivateDataKey,
    recipient_key: [u8; SECRET_BYTES],
) -> Result<SealedRecoveryKey, PrivateCryptoError> {
    seal_recovery_data_key_with(&mut OsRng, space, agent, epoch, data_key, recipient_key)
}

pub fn unwrap_recovery_data_key(
    epoch: &PrivateKeyEpoch,
    decryption_key: &OfflineRecoveryDecryptionKey,
) -> Result<PrivateDataKey, PrivateCryptoError> {
    let sealed = &epoch.sealed_recovery_data_key;
    let recipient_key = decryption_key.public_key();
    if !epoch.validate()
        || epoch.recovery_encryption_public_key != recipient_key
        || sealed.recipient_key != recipient_key
        || !recovery_sealed_envelope_has_strict_shape(sealed)
    {
        return Err(PrivateCryptoError::WrongRecipient);
    }
    let ephemeral_offset = RECOVERY_SEALED_MAGIC.len();
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
    let secret = StaticSecret::from(*decryption_key.0.bytes());
    let shared = secret.diffie_hellman(&X25519PublicKey::from(ephemeral_public));
    if !shared.was_contributory() {
        return Err(PrivateCryptoError::KeyAgreement);
    }
    let input = RecoverySealContext {
        space: epoch.space,
        agent: epoch.agent,
        epoch: epoch.epoch,
        recipient_key: &recipient_key,
        data_key_commitment: epoch.data_key_commitment,
        ephemeral_key: &ephemeral_public,
    };
    let kdf_context = recovery_seal_context(RECOVERY_SEAL_KDF_DOMAIN, input);
    let wrapping_key = derive_seal_key(RECOVERY_SEAL_SALT, shared.as_bytes(), &kdf_context)?;
    let aad = recovery_seal_context(RECOVERY_SEAL_AAD_DOMAIN, input);
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
    let key = PrivateDataKey(Secret32(bytes));
    if key.commitment() != epoch.data_key_commitment {
        return Err(PrivateCryptoError::KeyCommitment);
    }
    Ok(key)
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
        EpochKeyKind::Data | EpochKeyKind::History => data_key_commitment(secret.bytes()),
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

pub fn seal_recovery_keyring_key_for_node(
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
        EpochKeyKind::History,
        key.0.bytes(),
        key.commitment(),
        recipient,
    )
}

pub fn unwrap_recovery_keyring_key(
    grant: &PrivateRecoveryKeyringGrant,
    recipient: &PrivateNodeIdentity,
    decryption_key: &PrivateNodeDecryptionKey,
) -> Result<PrivateDataKey, PrivateCryptoError> {
    if !grant.validate() || !recipient.validate() {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    let sealed = find_seal(&grant.sealed_keys, recipient.node)?;
    let secret = unseal_epoch_secret(
        grant.ciphertext.space,
        grant.ciphertext.agent,
        grant.ciphertext.epoch,
        EpochKeyKind::History,
        grant.key_commitment,
        recipient.node,
        &recipient.encryption_public_key,
        sealed,
        decryption_key,
    )?;
    verify_unsealed_commitment(&secret, EpochKeyKind::History, grant.key_commitment)?;
    Ok(PrivateDataKey(secret))
}

/// Build the complete canonical set of historical data-key grants for one
/// exact Invite transition. The current epoch remains independently sealed in
/// the Invite's ordinary `sealed_data_key` field and is never duplicated here.
pub fn build_invite_history_grants(
    invite: &PrivateControlRecord,
    authenticated_epochs: &[PrivateKeyEpoch],
    data_keys: &BTreeMap<u64, PrivateDataKey>,
) -> Result<Vec<PrivateInviteHistoryGrant>, PrivateCryptoError> {
    let PrivateControlOperation::Invite {
        node,
        epoch: current_epoch,
        sealed_owner_key,
        sealed_data_key,
        historical_grants,
    } = &invite.operation
    else {
        return Err(PrivateCryptoError::InvalidRecord);
    };
    let historical_count = authenticated_epochs
        .len()
        .checked_sub(1)
        .ok_or(PrivateCryptoError::InvalidEpoch)?;
    let transition = invite
        .invite_transition_binding()
        .ok_or(PrivateCryptoError::InvalidRecord)?;
    if invite.space == SpaceId::ZERO
        || invite.agent == AgentId::ZERO
        || !node.validate()
        || node.principal == PrincipalId::ZERO
        || !historical_grants.is_empty()
        || historical_count > MAX_PRIVATE_INVITE_HISTORY_EPOCHS
        || authenticated_epochs.len() != data_keys.len()
        || authenticated_epochs.last().is_none_or(|epoch| {
            epoch.space != invite.space
                || epoch.agent != invite.agent
                || epoch.epoch != *current_epoch
        })
        || sealed_owner_key.node != node.node
        || sealed_data_key.node != node.node
        || sealed_owner_key.recipient_key != node.encryption_public_key
        || sealed_data_key.recipient_key != node.encryption_public_key
        || !sealed_envelope_has_strict_shape(sealed_owner_key)
        || !sealed_envelope_has_strict_shape(sealed_data_key)
    {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    let mut grants = Vec::new();
    grants
        .try_reserve_exact(historical_count)
        .map_err(|_| PrivateCryptoError::LimitExceeded)?;
    let mut previous_epoch = None;
    for authenticated in authenticated_epochs {
        if !authenticated.validate()
            || authenticated.space != invite.space
            || authenticated.agent != invite.agent
            || previous_epoch.is_some_and(|previous| previous >= authenticated.epoch)
            || authenticated.epoch > *current_epoch
        {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        let key = data_keys
            .get(&authenticated.epoch)
            .ok_or(PrivateCryptoError::MissingRecipient)?;
        if key.commitment() != authenticated.data_key_commitment {
            return Err(PrivateCryptoError::KeyCommitment);
        }
        previous_epoch = Some(authenticated.epoch);
    }
    for authenticated in &authenticated_epochs[..historical_count] {
        grants.push(seal_invite_history_data_key_with(
            &mut OsRng,
            invite.space,
            invite.agent,
            node.principal,
            transition,
            authenticated.epoch,
            data_keys
                .get(&authenticated.epoch)
                .ok_or(PrivateCryptoError::MissingRecipient)?,
            node,
        )?);
    }
    Ok(grants)
}

/// Open a complete Invite history for one exact newly authorized Node. No key
/// is returned unless the owner-signed record grants every authenticated data
/// epoch preceding the current epoch exactly once and in canonical order.
pub fn unwrap_invite_history_grants(
    invite: &PrivateControlRecord,
    authenticated_epochs: &[PrivateKeyEpoch],
    owner: PrincipalId,
    recipient: &PrivateNodeIdentity,
    decryption_key: &PrivateNodeDecryptionKey,
) -> Result<BTreeMap<u64, PrivateDataKey>, PrivateCryptoError> {
    let PrivateControlOperation::Invite {
        node,
        epoch: current_epoch,
        historical_grants,
        ..
    } = &invite.operation
    else {
        return Err(PrivateCryptoError::InvalidRecord);
    };
    let historical_count = authenticated_epochs
        .len()
        .checked_sub(1)
        .ok_or(PrivateCryptoError::InvalidEpoch)?;
    let transition = invite
        .invite_transition_binding()
        .ok_or(PrivateCryptoError::InvalidRecord)?;
    if !invite.validate_shape()
        || owner == PrincipalId::ZERO
        || node != recipient
        || node.principal != owner
        || historical_count > MAX_PRIVATE_INVITE_HISTORY_EPOCHS
        || historical_grants.len() != historical_count
        || authenticated_epochs.last().is_none_or(|epoch| {
            epoch.space != invite.space
                || epoch.agent != invite.agent
                || epoch.epoch != *current_epoch
        })
    {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    verify_control_record_signature(invite)?;
    let mut keys = BTreeMap::new();
    for (grant, authenticated) in historical_grants
        .iter()
        .zip(&authenticated_epochs[..historical_count])
    {
        if !authenticated.validate()
            || grant.space != invite.space
            || grant.agent != invite.agent
            || grant.owner != owner
            || grant.transition != transition
            || grant.recipient != recipient.node
            || grant.recipient_key != recipient.encryption_public_key
            || grant.epoch != authenticated.epoch
            || grant.data_key_commitment != authenticated.data_key_commitment
            || grant.epoch >= *current_epoch
        {
            return Err(PrivateCryptoError::InvalidRecord);
        }
        let key = unwrap_invite_history_data_key(grant, recipient, decryption_key)?;
        if key.commitment() != authenticated.data_key_commitment
            || keys.insert(grant.epoch, key).is_some()
        {
            return Err(PrivateCryptoError::KeyCommitment);
        }
    }
    if keys.len() != historical_count {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    Ok(keys)
}

/// Build the one canonical, complete encrypted history grant carried by a
/// recovery control. `authenticated_epochs` and `data_keys` must describe
/// exactly the full pre-recovery epoch history; omission and substitution are
/// rejected before any grant is sealed.
pub fn build_recovery_keyring_grant(
    authenticated_epochs: &[PrivateKeyEpoch],
    data_keys: &BTreeMap<u64, PrivateDataKey>,
    successor_epoch: &PrivateKeyEpoch,
    replacement_nodes: &[PrivateNodeIdentity],
) -> Result<PrivateRecoveryKeyringGrant, PrivateCryptoError> {
    if authenticated_epochs.len() > MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS {
        return Err(PrivateCryptoError::LimitExceeded);
    }
    if authenticated_epochs.is_empty()
        || authenticated_epochs.len() != data_keys.len()
        || !successor_epoch.validate()
        || successor_epoch.epoch
            <= authenticated_epochs
                .last()
                .ok_or(PrivateCryptoError::InvalidEpoch)?
                .epoch
        || replacement_nodes.is_empty()
        || replacement_nodes.len() > MAX_PRIVATE_NODES
        || replacement_nodes
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
        || !epoch_matches_nodes(successor_epoch, replacement_nodes)
    {
        return Err(PrivateCryptoError::InvalidRecord);
    }

    let plaintext_len = RECOVERY_KEYRING_FIXED_BYTES
        .checked_add(
            authenticated_epochs
                .len()
                .checked_mul(RECOVERY_KEYRING_ENTRY_BYTES)
                .ok_or(PrivateCryptoError::LimitExceeded)?,
        )
        .ok_or(PrivateCryptoError::LimitExceeded)?;
    if plaintext_len > MAX_PRIVATE_RECOVERY_KEYRING_CIPHERTEXT_BYTES.saturating_sub(AEAD_TAG_BYTES)
    {
        return Err(PrivateCryptoError::LimitExceeded);
    }
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(plaintext_len)
        .map_err(|_| PrivateCryptoError::LimitExceeded)?;
    plaintext.extend_from_slice(RECOVERY_KEYRING_MAGIC);
    plaintext.extend_from_slice(&RECOVERY_KEYRING_VERSION.to_le_bytes());
    plaintext.extend_from_slice(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes());
    plaintext.extend_from_slice(successor_epoch.space.as_bytes());
    plaintext.extend_from_slice(successor_epoch.agent.as_bytes());
    plaintext.extend_from_slice(&successor_epoch.epoch.to_le_bytes());
    plaintext.extend_from_slice(
        &u32::try_from(authenticated_epochs.len())
            .map_err(|_| PrivateCryptoError::LimitExceeded)?
            .to_le_bytes(),
    );
    let mut previous_epoch = None;
    for epoch in authenticated_epochs {
        if !epoch.validate()
            || epoch.space != successor_epoch.space
            || epoch.agent != successor_epoch.agent
            || previous_epoch.is_some_and(|previous| previous >= epoch.epoch)
            || epoch.epoch >= successor_epoch.epoch
        {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        let data_key = data_keys
            .get(&epoch.epoch)
            .ok_or(PrivateCryptoError::MissingRecipient)?;
        if data_key.commitment() != epoch.data_key_commitment {
            return Err(PrivateCryptoError::KeyCommitment);
        }
        let raw_key = data_key.recovery_bytes();
        plaintext.extend_from_slice(&epoch.epoch.to_le_bytes());
        plaintext.extend_from_slice(epoch.data_key_commitment.as_bytes());
        plaintext.extend_from_slice(&*raw_key);
        previous_epoch = Some(epoch.epoch);
    }
    if plaintext.len() != plaintext_len {
        return Err(PrivateCryptoError::InvalidRecord);
    }

    let wrapping_key = PrivateDataKey::generate()?;
    if wrapping_key.commitment() == successor_epoch.data_key_commitment {
        return Err(PrivateCryptoError::Randomness);
    }
    let ciphertext = encrypt_private_object(
        &wrapping_key,
        successor_epoch.space,
        successor_epoch.agent,
        successor_epoch.epoch,
        EncryptedObjectKind::Control,
        &plaintext,
    )?;
    if ciphertext.ciphertext.len() > MAX_PRIVATE_RECOVERY_KEYRING_CIPHERTEXT_BYTES {
        return Err(PrivateCryptoError::LimitExceeded);
    }
    let mut sealed_keys = Vec::new();
    sealed_keys
        .try_reserve_exact(replacement_nodes.len())
        .map_err(|_| PrivateCryptoError::LimitExceeded)?;
    for node in replacement_nodes {
        sealed_keys.push(seal_recovery_keyring_key_for_node(
            successor_epoch.space,
            successor_epoch.agent,
            successor_epoch.epoch,
            &wrapping_key,
            node,
        )?);
    }
    let grant = PrivateRecoveryKeyringGrant {
        key_commitment: wrapping_key.commitment(),
        sealed_keys,
        ciphertext,
    };
    if !grant.validate() {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    Ok(grant)
}

/// Open and completely revalidate a recovery keyring for one exact
/// replacement node. No key is returned unless every authenticated prior
/// epoch appears once, in order, with its exact data-key commitment.
pub fn unwrap_recovery_keyring(
    grant: &PrivateRecoveryKeyringGrant,
    authenticated_epochs: &[PrivateKeyEpoch],
    recipient: &PrivateNodeIdentity,
    decryption_key: &PrivateNodeDecryptionKey,
) -> Result<BTreeMap<u64, PrivateDataKey>, PrivateCryptoError> {
    if authenticated_epochs.len() > MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS {
        return Err(PrivateCryptoError::LimitExceeded);
    }
    if authenticated_epochs.is_empty()
        || !grant.validate()
        || grant.ciphertext.kind != EncryptedObjectKind::Control
    {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    let wrapping_key = unwrap_recovery_keyring_key(grant, recipient, decryption_key)?;
    let plaintext = Zeroizing::new(decrypt_private_object(&wrapping_key, &grant.ciphertext)?);
    let expected_len = RECOVERY_KEYRING_FIXED_BYTES
        .checked_add(
            authenticated_epochs
                .len()
                .checked_mul(RECOVERY_KEYRING_ENTRY_BYTES)
                .ok_or(PrivateCryptoError::LimitExceeded)?,
        )
        .ok_or(PrivateCryptoError::LimitExceeded)?;
    if plaintext.len() != expected_len
        || plaintext.get(..4) != Some(RECOVERY_KEYRING_MAGIC)
        || u16::from_le_bytes(
            plaintext
                .get(4..6)
                .ok_or(PrivateCryptoError::InvalidRecord)?
                .try_into()
                .map_err(|_| PrivateCryptoError::InvalidRecord)?,
        ) != RECOVERY_KEYRING_VERSION
        || plaintext.get(6..38) != Some(vos_agent_sdk::RUNTIME_ABI_ID.as_bytes())
        || plaintext.get(38..70) != Some(grant.ciphertext.space.as_bytes())
        || plaintext.get(70..102) != Some(grant.ciphertext.agent.as_bytes())
        || u64::from_le_bytes(
            plaintext
                .get(102..110)
                .ok_or(PrivateCryptoError::InvalidRecord)?
                .try_into()
                .map_err(|_| PrivateCryptoError::InvalidRecord)?,
        ) != grant.ciphertext.epoch
        || usize::try_from(u32::from_le_bytes(
            plaintext
                .get(110..114)
                .ok_or(PrivateCryptoError::InvalidRecord)?
                .try_into()
                .map_err(|_| PrivateCryptoError::InvalidRecord)?,
        ))
        .map_err(|_| PrivateCryptoError::LimitExceeded)?
            != authenticated_epochs.len()
    {
        return Err(PrivateCryptoError::InvalidRecord);
    }

    let mut keys = BTreeMap::new();
    let mut offset = RECOVERY_KEYRING_FIXED_BYTES;
    for epoch in authenticated_epochs {
        if !epoch.validate()
            || epoch.space != grant.ciphertext.space
            || epoch.agent != grant.ciphertext.agent
            || epoch.epoch >= grant.ciphertext.epoch
        {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        let encoded_epoch = u64::from_le_bytes(
            plaintext
                .get(offset..offset + 8)
                .ok_or(PrivateCryptoError::InvalidRecord)?
                .try_into()
                .map_err(|_| PrivateCryptoError::InvalidRecord)?,
        );
        offset += 8;
        let commitment = Hash(
            plaintext
                .get(offset..offset + 32)
                .ok_or(PrivateCryptoError::InvalidRecord)?
                .try_into()
                .map_err(|_| PrivateCryptoError::InvalidRecord)?,
        );
        offset += 32;
        let mut raw_key: [u8; SECRET_BYTES] = plaintext
            .get(offset..offset + SECRET_BYTES)
            .ok_or(PrivateCryptoError::InvalidRecord)?
            .try_into()
            .map_err(|_| PrivateCryptoError::InvalidRecord)?;
        offset += SECRET_BYTES;
        if encoded_epoch != epoch.epoch || commitment != epoch.data_key_commitment {
            raw_key.zeroize();
            return Err(PrivateCryptoError::KeyCommitment);
        }
        let data_key = PrivateDataKey::from_bytes(raw_key)?;
        raw_key.zeroize();
        if data_key.commitment() != commitment || keys.insert(encoded_epoch, data_key).is_some() {
            return Err(PrivateCryptoError::KeyCommitment);
        }
    }
    if offset != plaintext.len() || keys.len() != authenticated_epochs.len() {
        return Err(PrivateCryptoError::InvalidRecord);
    }
    Ok(keys)
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

/// Strict host verifier for the transport-key possession half of a system
/// authority node enrollment. Authority authorization remains a separate
/// state-machine decision; this verifier proves only that the exact Ed25519
/// transport key signed the canonical Space/Principal/Node/X25519 tuple.
#[derive(Clone, Copy, Debug, Default)]
pub struct StrictNodeEncryptionEnrollmentVerifier;

impl NodeEncryptionEnrollmentVerifier for StrictNodeEncryptionEnrollmentVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        VerifyingKey::from_bytes(public_key).is_ok_and(|key| {
            !key.is_weak()
                && key
                    .verify_strict(message, &Signature::from_bytes(signature))
                    .is_ok()
        })
    }
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
    recovery_encryption_public_key: [u8; SECRET_BYTES],
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
        recovery_encryption_public_key,
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
    recovery_encryption_public_key: [u8; SECRET_BYTES],
    authority: &V,
) -> Result<GeneratedPrivateEpoch, PrivateCryptoError>
where
    R: RngCore + CryptoRng,
    V: PrivateNodeAuthorityVerifier,
{
    validate_authorized_nodes(space, agent, owner, nodes, authority)?;
    strict_ed25519_public_key(&recovery_public_key)?;
    if !valid_x25519_public_key(&recovery_encryption_public_key)
        || recovery_encryption_public_key == recovery_public_key
    {
        return Err(PrivateCryptoError::InvalidKey);
    }
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
    let sealed_recovery_data_key = seal_recovery_data_key_with(
        rng,
        space,
        agent,
        epoch,
        &data_key,
        recovery_encryption_public_key,
    )?;
    let record = PrivateKeyEpoch {
        space,
        agent,
        epoch,
        owner_key_commitment: owner_key.commitment(),
        data_key_commitment: data_key.commitment(),
        recovery_key_commitment: recovery_public_key_commitment(&recovery_public_key),
        recovery_encryption_public_key,
        sealed_recovery_data_key,
        sealed_owner_keys,
        sealed_data_keys,
    };
    if !epoch_matches_nodes(&record, nodes)
        || !recovery_sealed_envelope_has_strict_shape(&record.sealed_recovery_data_key)
    {
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
        content: private_content_identity(data_key, space, agent, epoch, kind, plaintext),
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
    if private_content_identity(
        data_key,
        object.space,
        object.agent,
        object.epoch,
        object.kind,
        &plaintext,
    ) != object.content
    {
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
#[derive(Clone)]
pub struct PrivateControlChainVerifier {
    space: SpaceId,
    agent: AgentId,
    owner: PrincipalId,
    recovery_public_key: [u8; SECRET_BYTES],
    recovery_encryption_public_key: [u8; SECRET_BYTES],
    epoch: PrivateKeyEpoch,
    data_epoch_commitments: Vec<(u64, Hash)>,
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
        recovery_encryption_public_key: [u8; SECRET_BYTES],
        epoch: PrivateKeyEpoch,
        nodes: Vec<PrivateNodeIdentity>,
        authority: &V,
    ) -> Result<Self, PrivateCryptoError> {
        validate_authorized_nodes(space, agent, owner, &nodes, authority)?;
        strict_ed25519_public_key(&recovery_public_key)?;
        if !valid_x25519_public_key(&recovery_encryption_public_key)
            || recovery_encryption_public_key == recovery_public_key
        {
            return Err(PrivateCryptoError::InvalidKey);
        }
        if epoch.space != space
            || epoch.agent != agent
            || epoch.epoch != 0
            || epoch.recovery_key_commitment != recovery_public_key_commitment(&recovery_public_key)
            || epoch.recovery_encryption_public_key != recovery_encryption_public_key
            || !recovery_sealed_envelope_has_strict_shape(&epoch.sealed_recovery_data_key)
            || !epoch_matches_nodes(&epoch, &nodes)
        {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        let data_epoch_commitments = alloc::vec![(epoch.epoch, epoch.data_key_commitment)];
        Ok(Self {
            space,
            agent,
            owner,
            recovery_public_key,
            recovery_encryption_public_key,
            epoch,
            data_epoch_commitments,
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
        let mut next_data_epoch_commitments = self.data_epoch_commitments.clone();
        let mut next_nodes = self.nodes.clone();
        match &record.operation {
            PrivateControlOperation::Invite {
                node,
                epoch,
                sealed_owner_key,
                sealed_data_key,
                historical_grants,
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
                self.validate_invite_history(record, node, *epoch, historical_grants)?;
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
                historical_keyring,
            } => {
                match self.head {
                    Some(head) if superseded_heads.binary_search(&head).is_ok() => {}
                    None if superseded_heads.is_empty() => {}
                    _ => return Err(PrivateCryptoError::WrongPrevious),
                }
                self.validate_successor_epoch(candidate, replacement_nodes, authority)?;
                self.validate_recovery_keyring(historical_keyring, candidate, replacement_nodes)?;
                next_nodes = replacement_nodes.clone();
                next_epoch = candidate.clone();
            }
            PrivateControlOperation::SetResourcePolicy { .. }
            | PrivateControlOperation::ActorLifecycle { .. } => {}
        }

        if next_epoch.epoch != self.epoch.epoch {
            if next_data_epoch_commitments.len() > MAX_PRIVATE_INVITE_HISTORY_EPOCHS {
                return Err(PrivateCryptoError::LimitExceeded);
            }
            next_data_epoch_commitments.push((next_epoch.epoch, next_epoch.data_key_commitment));
        }

        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(PrivateCryptoError::LimitExceeded)?;
        self.epoch = next_epoch;
        self.data_epoch_commitments = next_data_epoch_commitments;
        self.nodes = next_nodes;
        self.head = Some(record.commitment());
        self.next_sequence = next_sequence;
        self.record_count += 1;
        Ok(())
    }

    /// Adopt an offline-recovery record from a different authenticated
    /// control fork. Unlike [`Self::apply`], this deliberately does not
    /// require `previous` to equal the local head: the local head must instead
    /// appear in the signed, strictly sorted `superseded_heads` set. Sequence
    /// and epoch jumps are monotonic so a stale recovery cannot roll a fork
    /// backwards.
    pub fn apply_recovery_from_superseded_head<V: PrivateNodeAuthorityVerifier>(
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
        if record.sequence < self.next_sequence {
            return Err(PrivateCryptoError::WrongSequence);
        }
        let PrivateControlOperation::Recover {
            superseded_heads,
            next_epoch,
            replacement_nodes,
            historical_keyring,
        } = &record.operation
        else {
            return Err(PrivateCryptoError::WrongSigner);
        };
        match (self.head, record.previous) {
            (Some(local_head), Some(selected_head))
                if superseded_heads.binary_search(&local_head).is_ok()
                    && superseded_heads.binary_search(&selected_head).is_ok() => {}
            (None, None) if superseded_heads.is_empty() => {}
            _ => return Err(PrivateCryptoError::WrongPrevious),
        }
        self.verify_current_signer(record)?;
        verify_control_record_signature(record)?;
        self.validate_recovery_epoch(next_epoch, replacement_nodes, authority)?;
        self.validate_recovery_keyring(historical_keyring, next_epoch, replacement_nodes)?;
        if self.data_epoch_commitments.len() > MAX_PRIVATE_INVITE_HISTORY_EPOCHS {
            return Err(PrivateCryptoError::LimitExceeded);
        }
        let next_sequence = record
            .sequence
            .checked_add(1)
            .ok_or(PrivateCryptoError::LimitExceeded)?;
        self.epoch = next_epoch.clone();
        self.data_epoch_commitments
            .push((next_epoch.epoch, next_epoch.data_key_commitment));
        self.nodes = replacement_nodes.clone();
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

    fn validate_invite_history(
        &self,
        record: &PrivateControlRecord,
        node: &PrivateNodeIdentity,
        current_epoch: u64,
        grants: &[PrivateInviteHistoryGrant],
    ) -> Result<(), PrivateCryptoError> {
        let history_count = self
            .data_epoch_commitments
            .len()
            .checked_sub(1)
            .ok_or(PrivateCryptoError::InvalidEpoch)?;
        let transition = record
            .invite_transition_binding()
            .ok_or(PrivateCryptoError::InvalidRecord)?;
        if current_epoch != self.epoch.epoch
            || node.principal != self.owner
            || history_count > MAX_PRIVATE_INVITE_HISTORY_EPOCHS
            || grants.len() != history_count
            || self.data_epoch_commitments.last()
                != Some(&(self.epoch.epoch, self.epoch.data_key_commitment))
        {
            return Err(PrivateCryptoError::InvalidRecord);
        }
        for (grant, (epoch, commitment)) in grants
            .iter()
            .zip(&self.data_epoch_commitments[..history_count])
        {
            if !invite_history_sealed_envelope_has_strict_shape(grant)
                || grant.space != self.space
                || grant.agent != self.agent
                || grant.owner != self.owner
                || grant.transition != transition
                || grant.recipient != node.node
                || grant.recipient_key != node.encryption_public_key
                || grant.epoch != *epoch
                || grant.data_key_commitment != *commitment
                || grant.epoch >= current_epoch
            {
                return Err(PrivateCryptoError::InvalidRecord);
            }
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
            || candidate.recovery_encryption_public_key != self.recovery_encryption_public_key
            || !recovery_sealed_envelope_has_strict_shape(&candidate.sealed_recovery_data_key)
        {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        validate_authorized_nodes(self.space, self.agent, self.owner, nodes, authority)?;
        if !epoch_matches_nodes(candidate, nodes) {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        Ok(())
    }

    fn validate_recovery_epoch<V: PrivateNodeAuthorityVerifier>(
        &self,
        candidate: &PrivateKeyEpoch,
        nodes: &[PrivateNodeIdentity],
        authority: &V,
    ) -> Result<(), PrivateCryptoError> {
        if candidate.space != self.space
            || candidate.agent != self.agent
            || candidate.epoch <= self.epoch.epoch
            || candidate.owner_key_commitment == self.epoch.owner_key_commitment
            || candidate.data_key_commitment == self.epoch.data_key_commitment
            || candidate.recovery_key_commitment != self.epoch.recovery_key_commitment
            || candidate.recovery_encryption_public_key != self.recovery_encryption_public_key
            || !recovery_sealed_envelope_has_strict_shape(&candidate.sealed_recovery_data_key)
        {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        validate_authorized_nodes(self.space, self.agent, self.owner, nodes, authority)?;
        if !epoch_matches_nodes(candidate, nodes) {
            return Err(PrivateCryptoError::InvalidEpoch);
        }
        Ok(())
    }

    fn validate_recovery_keyring(
        &self,
        grant: &PrivateRecoveryKeyringGrant,
        next_epoch: &PrivateKeyEpoch,
        replacement_nodes: &[PrivateNodeIdentity],
    ) -> Result<(), PrivateCryptoError> {
        if !grant.validate()
            || grant.ciphertext.space != self.space
            || grant.ciphertext.agent != self.agent
            || grant.ciphertext.epoch != next_epoch.epoch
            || grant.key_commitment == next_epoch.data_key_commitment
            || grant.sealed_keys.len() != replacement_nodes.len()
            || grant
                .sealed_keys
                .iter()
                .zip(replacement_nodes)
                .any(|(sealed, node)| {
                    !sealed_envelope_has_strict_shape(sealed)
                        || sealed.node != node.node
                        || sealed.recipient_key != node.encryption_public_key
                })
        {
            return Err(PrivateCryptoError::InvalidRecord);
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
    use vos_agent_sdk::private::{
        MAX_SEALED_KEY_BYTES, NodeEncryptionEnrollment, PrivateActorLifecycleKind,
    };
    use vos_agent_sdk::wire::CanonicalWire;
    use vos_agent_sdk::{ActorId, BlobRef, DeploymentId};

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

    #[test]
    fn strict_node_enrollment_verifier_rejects_every_signed_field_substitution() {
        let signing = SigningKey::from_bytes(&[0x41; 32]);
        let mut enrollment = NodeEncryptionEnrollment::from_keys(
            SpaceId([0x42; 32]),
            PrincipalId([0x43; 32]),
            signing.verifying_key().to_bytes(),
            [0x44; 32],
            [0; 64],
        );
        enrollment.transport_signature = signing.sign(&enrollment.signing_bytes()).to_bytes();
        assert!(enrollment.verify_with(&StrictNodeEncryptionEnrollmentVerifier));

        let mut wrong_space = enrollment;
        wrong_space.space.0[0] ^= 1;
        assert!(!wrong_space.verify_with(&StrictNodeEncryptionEnrollmentVerifier));

        let mut wrong_principal = enrollment;
        wrong_principal.principal.0[0] ^= 1;
        assert!(!wrong_principal.verify_with(&StrictNodeEncryptionEnrollmentVerifier));

        let mut wrong_recipient = enrollment;
        wrong_recipient.encryption_public_key[0] ^= 1;
        assert!(!wrong_recipient.verify_with(&StrictNodeEncryptionEnrollmentVerifier));

        let mut wrong_signature = enrollment;
        wrong_signature.transport_signature[0] ^= 1;
        assert!(!wrong_signature.verify_with(&StrictNodeEncryptionEnrollmentVerifier));
    }

    #[test]
    fn x25519_keys_reject_low_order_values_and_high_bit_aliases() {
        for low_order in vos_agent_sdk::private::X25519_LOW_ORDER_PUBLIC_KEYS {
            assert!(!valid_x25519_public_key(&low_order));

            let mut high_bit_alias = low_order;
            high_bit_alias[31] |= 0x80;
            assert!(!valid_x25519_public_key(&high_bit_alias));
        }

        let ordinary_secret = StaticSecret::from([0x37; SECRET_BYTES]);
        let ordinary = X25519PublicKey::from(&ordinary_secret).to_bytes();
        assert!(valid_x25519_public_key(&ordinary));
        let mut high_bit_alias = ordinary;
        high_bit_alias[31] |= 0x80;
        assert!(!valid_x25519_public_key(&high_bit_alias));
    }

    #[test]
    fn stable_import_certificate_is_exact_destination_authenticated_and_clean_break() {
        let fixture = fixture(2);
        let destination = &fixture.recipients[0];
        let route = ManagedAgentTarget {
            space: fixture.space,
            agent: fixture.agent,
            runtime_deployment: DeploymentId([0x31; 32]),
        };
        let descriptor = Hash([0x32; 32]);
        let control = Hash([0x33; 32]);
        let local_application = Hash([0x34; 32]);
        let source_evidence = Hash([0x35; 32]);
        let stable_projection = Hash([0x36; 32]);
        let certificate = PrivateStableImportCertificate::issue(
            route,
            fixture.owner,
            descriptor,
            &destination.identity,
            control,
            local_application,
            source_evidence,
            stable_projection,
            &destination.key,
        )
        .unwrap();
        let repeated = PrivateStableImportCertificate::issue(
            route,
            fixture.owner,
            descriptor,
            &destination.identity,
            control,
            local_application,
            source_evidence,
            stable_projection,
            &destination.key,
        )
        .unwrap();
        assert_eq!(certificate, repeated);
        assert_eq!(certificate.route(), route);
        assert_eq!(certificate.owner(), fixture.owner);
        assert_eq!(certificate.descriptor(), descriptor);
        assert_eq!(
            certificate.destination_identity(),
            authority_private_node_identity_commitment(&destination.identity)
        );
        assert_eq!(certificate.control(), control);
        assert_eq!(certificate.local_application(), local_application);
        assert_eq!(certificate.source_evidence(), source_evidence);
        assert_eq!(certificate.stable_projection(), stable_projection);
        certificate
            .verify_for(
                route,
                fixture.owner,
                descriptor,
                &destination.identity,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            )
            .unwrap();

        let wire = certificate.encode().unwrap();
        assert_eq!(wire.len(), PRIVATE_STABLE_IMPORT_CERTIFICATE_WIRE_BYTES);
        assert_eq!(&wire[..4], b"PSI1");
        assert_eq!(
            PrivateStableImportCertificate::decode(&wire),
            Ok(certificate.clone())
        );
        assert_ne!(
            destination
                .key
                .stable_import_certificate_authenticator(certificate.body_commitment())
                .unwrap(),
            destination
                .key
                .recovery_plan_authenticator(certificate.body_commitment())
                .unwrap()
        );

        let mut old_generation = wire.clone();
        old_generation[..4].copy_from_slice(b"PSI0");
        assert!(PrivateStableImportCertificate::decode(&old_generation).is_err());
        let mut wrong_abi = wire.clone();
        wrong_abi[4] ^= 1;
        assert!(PrivateStableImportCertificate::decode(&wrong_abi).is_err());
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(PrivateStableImportCertificate::decode(&trailing).is_err());
        assert!(PrivateStableImportCertificate::decode(&wire[..wire.len() - 1]).is_err());
        let mut zero_descriptor = wire.clone();
        // Canonical header + route (3 fields) + owner.
        zero_descriptor[4 + 32 + 4 * 32..4 + 32 + 5 * 32].fill(0);
        assert!(PrivateStableImportCertificate::decode(&zero_descriptor).is_err());
        let mut forged_wire = wire;
        let last = forged_wire.len() - 1;
        forged_wire[last] ^= 1;
        let forged = PrivateStableImportCertificate::decode(&forged_wire).unwrap();
        assert_eq!(
            forged.verify_for(
                route,
                fixture.owner,
                descriptor,
                &destination.identity,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            Err(PrivateCryptoError::InvalidSignature)
        );
    }

    #[test]
    fn stable_import_certificate_rejects_every_context_and_key_substitution() {
        let fixture = fixture(2);
        let destination = &fixture.recipients[0];
        let route = ManagedAgentTarget {
            space: fixture.space,
            agent: fixture.agent,
            runtime_deployment: DeploymentId([0x41; 32]),
        };
        let descriptor = Hash([0x42; 32]);
        let control = Hash([0x43; 32]);
        let local_application = Hash([0x44; 32]);
        let source_evidence = Hash([0x45; 32]);
        let stable_projection = Hash([0x46; 32]);
        let certificate = PrivateStableImportCertificate::issue(
            route,
            fixture.owner,
            descriptor,
            &destination.identity,
            control,
            local_application,
            source_evidence,
            stable_projection,
            &destination.key,
        )
        .unwrap();
        let verify = |route,
                      owner,
                      descriptor,
                      destination: &PrivateNodeIdentity,
                      control,
                      local_application,
                      source_evidence,
                      stable_projection,
                      key: &PrivateNodeDecryptionKey| {
            certificate.verify_for(
                route,
                owner,
                descriptor,
                destination,
                control,
                local_application,
                source_evidence,
                stable_projection,
                key,
            )
        };
        let invalid = Err(PrivateCryptoError::InvalidSignature);
        let mut wrong_route = route;
        wrong_route.space.0[0] ^= 1;
        assert_eq!(
            verify(
                wrong_route,
                fixture.owner,
                descriptor,
                &destination.identity,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            invalid
        );
        wrong_route = route;
        wrong_route.agent.0[0] ^= 1;
        assert_eq!(
            verify(
                wrong_route,
                fixture.owner,
                descriptor,
                &destination.identity,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            invalid
        );
        wrong_route = route;
        wrong_route.runtime_deployment.0[0] ^= 1;
        assert_eq!(
            verify(
                wrong_route,
                fixture.owner,
                descriptor,
                &destination.identity,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            invalid
        );
        let mut wrong_destination = destination.identity.clone();
        wrong_destination.authority_binding.0[0] ^= 1;
        for result in [
            verify(
                route,
                PrincipalId([0x47; 32]),
                descriptor,
                &destination.identity,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            verify(
                route,
                fixture.owner,
                Hash([0x48; 32]),
                &destination.identity,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            verify(
                route,
                fixture.owner,
                descriptor,
                &wrong_destination,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            verify(
                route,
                fixture.owner,
                descriptor,
                &destination.identity,
                Hash([0x49; 32]),
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            verify(
                route,
                fixture.owner,
                descriptor,
                &destination.identity,
                control,
                Hash([0x4a; 32]),
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            verify(
                route,
                fixture.owner,
                descriptor,
                &destination.identity,
                control,
                local_application,
                Hash([0x4b; 32]),
                stable_projection,
                &destination.key,
            ),
            verify(
                route,
                fixture.owner,
                descriptor,
                &destination.identity,
                control,
                local_application,
                source_evidence,
                Hash([0x4c; 32]),
                &destination.key,
            ),
            verify(
                route,
                fixture.owner,
                descriptor,
                &fixture.recipients[1].identity,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &fixture.recipients[1].key,
            ),
        ] {
            assert_eq!(result, invalid);
        }

        assert_eq!(
            PrivateStableImportCertificate::issue(
                route,
                fixture.owner,
                descriptor,
                &destination.identity,
                Hash::ZERO,
                local_application,
                source_evidence,
                stable_projection,
                &destination.key,
            ),
            Err(PrivateCryptoError::InvalidRecord)
        );
        assert_eq!(
            PrivateStableImportCertificate::issue(
                route,
                fixture.owner,
                descriptor,
                &destination.identity,
                control,
                local_application,
                source_evidence,
                stable_projection,
                &fixture.recipients[1].key,
            ),
            Err(PrivateCryptoError::InvalidScope)
        );
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
        recovery_encryption: OfflineRecoveryDecryptionKey,
        recipients: Vec<Recipient>,
        generated: GeneratedPrivateEpoch,
    }

    fn fixture(count: usize) -> Fixture {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let space = SpaceId([1; 32]);
        let agent = AgentId([2; 32]);
        let owner = PrincipalId([3; 32]);
        let recovery = RecoverySigningKey::generate_with(&mut rng).unwrap();
        let recovery_encryption = OfflineRecoveryDecryptionKey::generate_with(&mut rng).unwrap();
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
            recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        Fixture {
            rng,
            space,
            agent,
            owner,
            recovery,
            recovery_encryption,
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
            fixture.recovery_encryption.public_key(),
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
            private_content_identity(
                &fixture.generated.data_key,
                fixture.space,
                fixture.agent,
                0,
                EncryptedObjectKind::Blob,
                b"authenticated private value",
            )
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
    fn equal_plaintext_identities_are_unlinkable_across_keys_scopes_epochs_and_kinds() {
        let mut fixture = fixture(1);
        let plaintext = b"same private plaintext";
        let other_key = PrivateDataKey::generate_with(&mut fixture.rng).unwrap();
        let identities = [
            private_content_identity(
                &fixture.generated.data_key,
                fixture.space,
                fixture.agent,
                0,
                EncryptedObjectKind::Blob,
                plaintext,
            ),
            private_content_identity(
                &fixture.generated.data_key,
                fixture.space,
                fixture.agent,
                1,
                EncryptedObjectKind::Blob,
                plaintext,
            ),
            private_content_identity(
                &fixture.generated.data_key,
                fixture.space,
                fixture.agent,
                0,
                EncryptedObjectKind::Snapshot,
                plaintext,
            ),
            private_content_identity(
                &fixture.generated.data_key,
                fixture.space,
                AgentId([0xA7; 32]),
                0,
                EncryptedObjectKind::Blob,
                plaintext,
            ),
            private_content_identity(
                &fixture.generated.data_key,
                SpaceId([0xB8; 32]),
                fixture.agent,
                0,
                EncryptedObjectKind::Blob,
                plaintext,
            ),
            private_content_identity(
                &other_key,
                fixture.space,
                fixture.agent,
                0,
                EncryptedObjectKind::Blob,
                plaintext,
            ),
        ];
        for (position, identity) in identities.iter().enumerate() {
            assert_ne!(*identity, Hash::ZERO);
            assert!(
                identities[..position].iter().all(|prior| prior != identity),
                "private content identity collision at case {position}"
            );
        }
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
                historical_grants: Vec::new(),
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
                historical_grants: Vec::new(),
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
                historical_grants: Vec::new(),
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
            fixture.recovery_encryption.public_key(),
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
    fn late_invite_history_is_complete_transition_bound_and_hostile_to_substitution() {
        let mut fixture = fixture(1);
        let invited = make_recipient(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            fixture.owner,
            60,
        );
        let mut chain = new_chain(&fixture);
        let mut epochs = vec![fixture.generated.record.clone()];
        let mut data_keys = BTreeMap::new();
        data_keys.insert(
            0,
            PrivateDataKey::from_bytes(*fixture.generated.data_key.0.bytes()).unwrap(),
        );
        let mut owner = OwnerSigningKey::from_seed(*fixture.generated.owner_key.0.bytes()).unwrap();
        for next_epoch in 1..=2 {
            let generated = generate_fresh_private_epoch_with(
                &mut fixture.rng,
                fixture.space,
                fixture.agent,
                next_epoch,
                fixture.owner,
                chain.nodes(),
                fixture.recovery.verifying_key(),
                fixture.recovery_encryption.public_key(),
                &TestAuthority,
            )
            .unwrap();
            let mut rotate = unsigned_record(
                &fixture,
                next_epoch - 1,
                chain.head(),
                PrivateControlOperation::RotateKeys {
                    next_epoch: generated.record.clone(),
                },
            );
            sign_owner_control_record(&mut rotate, &owner).unwrap();
            chain.apply(&rotate, &TestAuthority).unwrap();
            epochs.push(generated.record);
            data_keys.insert(next_epoch, generated.data_key);
            owner = generated.owner_key;
        }

        let sealed_owner_key =
            seal_owner_key_for_node(fixture.space, fixture.agent, 2, &owner, &invited.identity)
                .unwrap();
        let sealed_data_key = seal_data_key_for_node(
            fixture.space,
            fixture.agent,
            2,
            data_keys.get(&2).unwrap(),
            &invited.identity,
        )
        .unwrap();
        let mut invite = unsigned_record(
            &fixture,
            2,
            chain.head(),
            PrivateControlOperation::Invite {
                node: invited.identity.clone(),
                epoch: 2,
                sealed_owner_key,
                sealed_data_key,
                historical_grants: Vec::new(),
            },
        );
        let grants = build_invite_history_grants(&invite, &epochs, &data_keys).unwrap();
        assert_eq!(
            grants.iter().map(|grant| grant.epoch).collect::<Vec<_>>(),
            vec![0, 1]
        );
        let PrivateControlOperation::Invite {
            historical_grants, ..
        } = &mut invite.operation
        else {
            unreachable!()
        };
        *historical_grants = grants;
        sign_owner_control_record(&mut invite, &owner).unwrap();
        let opened = unwrap_invite_history_grants(
            &invite,
            &epochs,
            fixture.owner,
            &invited.identity,
            &invited.key,
        )
        .unwrap();
        assert_eq!(opened.len(), 2);
        for epoch in 0..2 {
            assert_eq!(opened[&epoch].commitment(), data_keys[&epoch].commitment());
        }

        let mut omitted = invite.clone();
        let PrivateControlOperation::Invite {
            historical_grants, ..
        } = &mut omitted.operation
        else {
            unreachable!()
        };
        historical_grants.pop();
        sign_owner_control_record(&mut omitted, &owner).unwrap();
        assert_eq!(
            chain.clone().apply(&omitted, &TestAuthority),
            Err(PrivateCryptoError::InvalidRecord)
        );

        let mut duplicate = invite.clone();
        let PrivateControlOperation::Invite {
            historical_grants, ..
        } = &mut duplicate.operation
        else {
            unreachable!()
        };
        historical_grants.push(historical_grants[1].clone());
        assert_eq!(
            sign_owner_control_record(&mut duplicate, &owner),
            Err(PrivateCryptoError::InvalidRecord)
        );

        let mut reordered = invite.clone();
        let PrivateControlOperation::Invite {
            historical_grants, ..
        } = &mut reordered.operation
        else {
            unreachable!()
        };
        historical_grants.swap(0, 1);
        assert_eq!(
            sign_owner_control_record(&mut reordered, &owner),
            Err(PrivateCryptoError::InvalidRecord)
        );

        let mutations: [fn(&mut PrivateInviteHistoryGrant); 4] = [
            |grant: &mut PrivateInviteHistoryGrant| grant.agent = AgentId([0x91; 32]),
            |grant: &mut PrivateInviteHistoryGrant| grant.recipient = NodeId([0x92; 32]),
            |grant: &mut PrivateInviteHistoryGrant| grant.owner = PrincipalId([0x93; 32]),
            |grant: &mut PrivateInviteHistoryGrant| grant.transition = Hash([0x94; 32]),
        ];
        for mutate in mutations {
            let mut changed = invite.clone();
            let PrivateControlOperation::Invite {
                historical_grants, ..
            } = &mut changed.operation
            else {
                unreachable!()
            };
            mutate(&mut historical_grants[0]);
            assert_eq!(
                sign_owner_control_record(&mut changed, &owner),
                Err(PrivateCryptoError::InvalidRecord)
            );
        }

        let mut forged = invite.clone();
        let PrivateControlOperation::Invite {
            historical_grants, ..
        } = &mut forged.operation
        else {
            unreachable!()
        };
        *historical_grants[0]
            .sealed_data_key
            .sealed
            .last_mut()
            .unwrap() ^= 1;
        sign_owner_control_record(&mut forged, &owner).unwrap();
        assert!(matches!(
            unwrap_invite_history_grants(
                &forged,
                &epochs,
                fixture.owner,
                &invited.identity,
                &invited.key,
            ),
            Err(PrivateCryptoError::Decryption)
        ));

        chain.apply(&invite, &TestAuthority).unwrap();
    }

    #[test]
    fn invite_history_accepts_exact_4096_boundary_and_rejects_one_more() {
        let mut fixture = fixture(1);
        let invited = make_recipient(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            fixture.owner,
            61,
        );
        let mut chain = new_chain(&fixture);
        let commitment = fixture.generated.data_key.commitment();
        chain.epoch.epoch = MAX_PRIVATE_INVITE_HISTORY_EPOCHS as u64;
        chain.data_epoch_commitments = (0..=MAX_PRIVATE_INVITE_HISTORY_EPOCHS as u64)
            .map(|epoch| (epoch, commitment))
            .collect();
        let sealed_owner_key = seal_owner_key_for_node(
            fixture.space,
            fixture.agent,
            chain.epoch.epoch,
            &fixture.generated.owner_key,
            &invited.identity,
        )
        .unwrap();
        let sealed_data_key = seal_data_key_for_node(
            fixture.space,
            fixture.agent,
            chain.epoch.epoch,
            &fixture.generated.data_key,
            &invited.identity,
        )
        .unwrap();
        let mut invite = unsigned_record(
            &fixture,
            0,
            None,
            PrivateControlOperation::Invite {
                node: invited.identity.clone(),
                epoch: chain.epoch.epoch,
                sealed_owner_key,
                sealed_data_key,
                historical_grants: Vec::new(),
            },
        );
        let transition = invite.invite_transition_binding().unwrap();
        let prototype = seal_invite_history_data_key_with(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            fixture.owner,
            transition,
            0,
            &fixture.generated.data_key,
            &invited.identity,
        )
        .unwrap();
        let grants: Vec<_> = (0..MAX_PRIVATE_INVITE_HISTORY_EPOCHS as u64)
            .map(|epoch| {
                let mut grant = prototype.clone();
                grant.epoch = epoch;
                grant
            })
            .collect();
        let PrivateControlOperation::Invite {
            historical_grants, ..
        } = &mut invite.operation
        else {
            unreachable!()
        };
        *historical_grants = grants;
        sign_owner_control_record(&mut invite, &fixture.generated.owner_key).unwrap();
        assert!(invite.validate_shape());
        let wire = invite.encode().unwrap();
        assert_eq!(PrivateControlRecord::decode(&wire), Ok(invite.clone()));
        chain.apply(&invite, &TestAuthority).unwrap();

        let mut excess = invite;
        let PrivateControlOperation::Invite {
            historical_grants, ..
        } = &mut excess.operation
        else {
            unreachable!()
        };
        historical_grants.push(historical_grants.last().unwrap().clone());
        assert_eq!(
            historical_grants.len(),
            MAX_PRIVATE_INVITE_HISTORY_EPOCHS + 1
        );
        assert!(!excess.validate_shape());
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
            fixture.recovery_encryption.public_key(),
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
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let mut heads = vec![current_head, Hash([64; 32])];
        heads.sort();
        heads.dedup();
        assert_eq!(heads.len(), 2);
        let mut historical_keys = BTreeMap::new();
        historical_keys.insert(
            fixture.generated.record.epoch,
            unwrap_data_key(
                &fixture.generated.record,
                &fixture.recipients[0].identity,
                &fixture.recipients[0].key,
            )
            .unwrap(),
        );
        let historical_keyring = build_recovery_keyring_grant(
            core::slice::from_ref(&fixture.generated.record),
            &historical_keys,
            &successor.record,
            core::slice::from_ref(&replacement.identity),
        )
        .unwrap();
        let mut recovery = unsigned_record(
            &fixture,
            1,
            Some(current_head),
            PrivateControlOperation::Recover {
                superseded_heads: heads.clone(),
                next_epoch: successor.record.clone(),
                replacement_nodes: vec![replacement.identity.clone()],
                historical_keyring,
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
    fn offline_recovery_seals_and_complete_keyring_fail_closed() {
        assert!(matches!(
            OfflineRecoveryKit::new(
                RecoverySigningKey::from_seed([93; 32]).unwrap(),
                OfflineRecoveryDecryptionKey::from_bytes([93; 32]).unwrap(),
            ),
            Err(PrivateCryptoError::InvalidKey)
        ));
        let mut fixture = fixture(2);
        let recovered =
            unwrap_recovery_data_key(&fixture.generated.record, &fixture.recovery_encryption)
                .unwrap();
        assert_eq!(
            recovered.commitment(),
            fixture.generated.record.data_key_commitment
        );
        let wrong_recovery_encryption = OfflineRecoveryDecryptionKey::from_bytes([91; 32]).unwrap();
        assert!(matches!(
            unwrap_recovery_data_key(&fixture.generated.record, &wrong_recovery_encryption),
            Err(PrivateCryptoError::WrongRecipient)
        ));

        let replacement_nodes = nodes(&fixture);
        let successor = generate_fresh_private_epoch_with(
            &mut fixture.rng,
            fixture.space,
            fixture.agent,
            1,
            fixture.owner,
            &replacement_nodes,
            fixture.recovery.verifying_key(),
            fixture.recovery_encryption.public_key(),
            &TestAuthority,
        )
        .unwrap();
        let historical = BTreeMap::from([(
            fixture.generated.record.epoch,
            unwrap_data_key(
                &fixture.generated.record,
                &fixture.recipients[0].identity,
                &fixture.recipients[0].key,
            )
            .unwrap(),
        )]);
        let grant = build_recovery_keyring_grant(
            core::slice::from_ref(&fixture.generated.record),
            &historical,
            &successor.record,
            &replacement_nodes,
        )
        .unwrap();
        let opened = unwrap_recovery_keyring(
            &grant,
            core::slice::from_ref(&fixture.generated.record),
            &fixture.recipients[0].identity,
            &fixture.recipients[0].key,
        )
        .unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(
            opened[&0].commitment(),
            fixture.generated.record.data_key_commitment
        );
        assert!(
            unwrap_recovery_keyring(
                &grant,
                core::slice::from_ref(&fixture.generated.record),
                &fixture.recipients[0].identity,
                &fixture.recipients[1].key,
            )
            .is_err()
        );

        let mut tampered = grant.clone();
        tampered.ciphertext.ciphertext[0] ^= 1;
        assert!(
            unwrap_recovery_keyring(
                &tampered,
                core::slice::from_ref(&fixture.generated.record),
                &fixture.recipients[0].identity,
                &fixture.recipients[0].key,
            )
            .is_err()
        );
        assert!(matches!(
            build_recovery_keyring_grant(
                core::slice::from_ref(&fixture.generated.record),
                &BTreeMap::new(),
                &successor.record,
                &replacement_nodes,
            ),
            Err(PrivateCryptoError::InvalidRecord)
        ));
        let substituted = BTreeMap::from([(
            fixture.generated.record.epoch,
            PrivateDataKey::from_bytes([92; 32]).unwrap(),
        )]);
        assert!(matches!(
            build_recovery_keyring_grant(
                core::slice::from_ref(&fixture.generated.record),
                &substituted,
                &successor.record,
                &replacement_nodes,
            ),
            Err(PrivateCryptoError::KeyCommitment)
        ));
        let too_many =
            vec![fixture.generated.record.clone(); MAX_PRIVATE_RECOVERY_KEYRING_EPOCHS + 1];
        assert!(matches!(
            build_recovery_keyring_grant(
                &too_many,
                &BTreeMap::new(),
                &successor.record,
                &replacement_nodes,
            ),
            Err(PrivateCryptoError::LimitExceeded)
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
                fixture.recovery_encryption.public_key(),
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
                fixture.recovery_encryption.public_key(),
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
                fixture.recovery_encryption.public_key(),
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
