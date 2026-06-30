//! Identity binding — a custom MLS credential tying the messenger's
//! seed-derived MLS signing key to a VERIFIED space PeerId.
//!
//! The MLS signer is still the deterministic `HKDF(seed)`-derived
//! Ed25519 key ([`crate::mls::derive_signer`]) — keeping it is what the
//! host-vs-PVM determinism gate needs. Additionally, a credential
//! carrying `(peer_id, display_name, binding_cert)`, where the cert is
//! the operator's libp2p identity key signing over the MLS public key,
//! the PeerId, and the space id. A custom [`IdentityProvider`] verifies
//! that cert on every leaf mls-rs validates (commit/add and welcome/join),
//! so an MLS key can only enter a group under a PeerId its real operator
//! authorized — closing the nickname-impersonation gap.
//!
//! The credential's bytes fold into the signed `LeafNodeTBS`, so the
//! `data` blob MUST be encoded canonically (fixed field order,
//! length-prefixed) or the determinism gate breaks. Verification is
//! validation-only and never affects output bytes.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use mls_rs::ExtensionList;
use mls_rs::identity::SigningIdentity;
use mls_rs::time::MlsTime;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::identity::{
    Credential, CredentialType, CustomCredential, IdentityProvider, MemberValidationContext,
};
// Shared with the CLI signer (`vosx`) so the operator's binding cert
// round-trips byte-for-byte — one source of truth in `space-registry`.
use space_registry::binding_signed_bytes;

/// Private-use MLS credential type id for VOS identity-bound credentials
/// (≠ `CredentialType::BASIC`=1 / `X509`=2).
pub(crate) const VOS_CREDENTIAL_TYPE: u16 = 0xF001;

/// Ed25519 signature length — the binding cert is exactly this.
const SIG_LEN: usize = 64;

/// A member's verified identity binding, provisioned at `register`/`bind`.
#[derive(Clone, Debug)]
pub(crate) struct Binding {
    /// The operator's space PeerId (libp2p multihash bytes) — the verified
    /// identity, same encoding as `space-registry`'s `AuthGrantRow.peer_id`.
    pub peer_id: Vec<u8>,
    /// Cosmetic display name. Not authoritative.
    pub display_name: String,
    /// `Sign_{operatorKey}(domain ‖ mls_pubkey ‖ peer_id ‖ space_id)` —
    /// see [`space_registry::binding_signed_bytes`].
    pub cert: Vec<u8>,
}

/// Canonical credential payload: `[peer_id][display_name][cert]`, each
/// `u16`-length-prefixed. Deterministic — it folds into the signed leaf.
fn encode_credential_data(b: &Binding) -> Vec<u8> {
    let name = b.display_name.as_bytes();
    let mut out = Vec::with_capacity(6 + b.peer_id.len() + name.len() + b.cert.len());
    out.extend_from_slice(&(b.peer_id.len() as u16).to_le_bytes());
    out.extend_from_slice(&b.peer_id);
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&(b.cert.len() as u16).to_le_bytes());
    out.extend_from_slice(&b.cert);
    out
}

/// A credential decoded back from its on-the-wire bytes.
pub(crate) struct DecodedCredential {
    pub peer_id: Vec<u8>,
    pub display_name: String,
    pub cert: Vec<u8>,
}

fn read_field(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos + 2 > data.len() {
        return None;
    }
    let len = u16::from_le_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + len > data.len() {
        return None;
    }
    let v = data[*pos..*pos + len].to_vec();
    *pos += len;
    Some(v)
}

pub(crate) fn decode_credential_data(data: &[u8]) -> Option<DecodedCredential> {
    let mut pos = 0usize;
    let peer_id = read_field(data, &mut pos)?;
    let name = read_field(data, &mut pos)?;
    let cert = read_field(data, &mut pos)?;
    if pos != data.len() {
        return None; // trailing garbage
    }
    Some(DecodedCredential {
        peer_id,
        display_name: String::from_utf8(name).ok()?,
        cert,
    })
}

/// Build the custom MLS [`Credential`] for a binding.
pub(crate) fn vos_credential(b: &Binding) -> Credential {
    Credential::Custom(CustomCredential::new(
        CredentialType::new(VOS_CREDENTIAL_TYPE),
        encode_credential_data(b),
    ))
}

/// Decode the VOS binding carried by a roster member's / KeyPackage's signing
/// identity. `None` if the credential isn't a well-formed VOS credential.
pub(crate) fn member_binding(si: &SigningIdentity) -> Option<DecodedCredential> {
    let custom = si.credential.as_custom()?;
    if custom.credential_type != CredentialType::new(VOS_CREDENTIAL_TYPE) {
        return None;
    }
    decode_credential_data(&custom.data)
}

/// Extract the raw 32-byte Ed25519 key embedded in a libp2p ed25519 PeerId
/// (identity-multihash: `00 24 08 01 12 20 ‖ key[32]`). Mirrors
/// `space_registry::ed25519_pubkey_from_peer_id`.
fn ed25519_pubkey_from_peer_id(peer_id: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    if peer_id.len() != 38 || peer_id[..6] != PREFIX {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&peer_id[6..]);
    Some(key)
}

/// Verify the binding cert proves `peer_id`'s operator authorized
/// `mls_pubkey` for `space_id`. Pure (no I/O), deterministic.
pub(crate) fn verify_binding(
    mls_pubkey: &[u8],
    peer_id: &[u8],
    cert: &[u8],
    space_id: &[u8; 32],
) -> bool {
    let Some(pk) = ed25519_pubkey_from_peer_id(peer_id) else {
        return false;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let sig_arr: [u8; SIG_LEN] = match cert.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let msg = binding_signed_bytes(mls_pubkey, peer_id, space_id);
    vk.verify_strict(&msg, &sig).is_ok()
}

/// Custom MLS [`IdentityProvider`]: on every leaf mls-rs validates, decode
/// the VOS credential and verify its binding cert against the leaf's own
/// signature key and this space's id. Rejects a leaf whose MLS key the
/// claimed PeerId never authorized. (Enrollment — "is this PeerId a space
/// member" — is checked separately, messenger-side, since it needs a
/// registry read this sync hook can't do.)
#[derive(Clone, Debug)]
pub(crate) struct VosIdentityProvider {
    space_id: [u8; 32],
}

impl VosIdentityProvider {
    pub(crate) fn new(space_id: [u8; 32]) -> Self {
        Self { space_id }
    }

    fn decode(&self, si: &SigningIdentity) -> Result<DecodedCredential, VosIdentityError> {
        let custom = si
            .credential
            .as_custom()
            .ok_or(VosIdentityError("not a VOS custom credential"))?;
        if custom.credential_type != CredentialType::new(VOS_CREDENTIAL_TYPE) {
            return Err(VosIdentityError("unexpected credential type"));
        }
        decode_credential_data(&custom.data).ok_or(VosIdentityError("malformed credential"))
    }
}

#[derive(Debug)]
pub(crate) struct VosIdentityError(&'static str);

impl core::fmt::Display for VosIdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "vos identity: {}", self.0)
    }
}

impl IntoAnyError for VosIdentityError {}

impl IdentityProvider for VosIdentityProvider {
    type Error = VosIdentityError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        let dec = self.decode(signing_identity)?;
        if !verify_binding(
            signing_identity.signature_key.as_bytes(),
            &dec.peer_id,
            &dec.cert,
            &self.space_id,
        ) {
            return Err(VosIdentityError("binding cert verification failed"));
        }
        Ok(())
    }

    fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        // Same binding check; external senders are not yet supported.
        let dec = self.decode(signing_identity)?;
        if !verify_binding(
            signing_identity.signature_key.as_bytes(),
            &dec.peer_id,
            &dec.cert,
            &self.space_id,
        ) {
            return Err(VosIdentityError("binding cert verification failed"));
        }
        Ok(())
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        // Stable per-member id = the verified PeerId, so two leaves of the
        // same member compare equal regardless of display name.
        Ok(self.decode(signing_identity)?.peer_id)
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        // A leaf may be replaced only by one bound to the same PeerId.
        Ok(self.decode(predecessor)?.peer_id == self.decode(successor)?.peer_id)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::new(VOS_CREDENTIAL_TYPE)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::{Signer, SigningKey};
    use mls_rs_core::crypto::SignaturePublicKey;

    const SPACE: [u8; 32] = [0x11; 32];

    /// The 38-byte libp2p ed25519 PeerId for an operator key.
    fn op_peer_id(op: &SigningKey) -> Vec<u8> {
        let mut id = vec![0x00u8, 0x24, 0x08, 0x01, 0x12, 0x20];
        id.extend_from_slice(&op.verifying_key().to_bytes());
        id
    }

    /// A correctly-signed binding: the operator key signs over the MLS key,
    /// its own PeerId, and the space id.
    fn valid_binding(op: &SigningKey, mls_pubkey: &[u8], name: &str) -> Binding {
        let peer_id = op_peer_id(op);
        let sig = op.sign(&binding_signed_bytes(mls_pubkey, &peer_id, &SPACE));
        Binding {
            peer_id,
            display_name: String::from(name),
            cert: sig.to_bytes().to_vec(),
        }
    }

    #[test]
    fn credential_data_round_trips() {
        let b = Binding {
            peer_id: vec![1, 2, 3],
            display_name: String::from("alice"),
            cert: vec![9u8; 64],
        };
        let data = encode_credential_data(&b);
        let dec = decode_credential_data(&data).expect("round-trips");
        assert_eq!(dec.peer_id, b.peer_id);
        assert_eq!(dec.display_name, b.display_name);
        assert_eq!(dec.cert, b.cert);
        // Trailing garbage and truncation are rejected (canonical only).
        let mut trailing = data.clone();
        trailing.push(0);
        assert!(decode_credential_data(&trailing).is_none());
        assert!(decode_credential_data(&data[..data.len() - 1]).is_none());
    }

    #[test]
    fn verify_binding_accepts_valid_rejects_forged() {
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let mls_pubkey = [0xABu8; 32];
        let b = valid_binding(&op, &mls_pubkey, "alice");
        assert!(verify_binding(&mls_pubkey, &b.peer_id, &b.cert, &SPACE));

        // Wrong MLS key, wrong space — both rejected (the cert binds all three).
        assert!(!verify_binding(&[0xCDu8; 32], &b.peer_id, &b.cert, &SPACE));
        assert!(!verify_binding(&mls_pubkey, &b.peer_id, &b.cert, &[0x22u8; 32]));

        // A cert signed by an attacker but claiming the victim's PeerId fails:
        // the signature doesn't verify under the claimed PeerId's key.
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let victim_pid = op_peer_id(&op);
        let bad = attacker.sign(&binding_signed_bytes(&mls_pubkey, &victim_pid, &SPACE));
        assert!(!verify_binding(&mls_pubkey, &victim_pid, &bad.to_bytes(), &SPACE));
    }

    #[test]
    fn provider_validates_valid_rejects_forged_and_mismatched_key() {
        let provider = VosIdentityProvider::new(SPACE);
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let mls_pubkey = [0xABu8; 32];
        let b = valid_binding(&op, &mls_pubkey, "alice");

        let si = SigningIdentity::new(
            vos_credential(&b),
            SignaturePublicKey::from(mls_pubkey.to_vec()),
        );
        assert!(
            provider
                .validate_member(&si, None, MemberValidationContext::None)
                .is_ok(),
            "a valid binding passes validate_member",
        );
        assert_eq!(
            provider.identity(&si, &ExtensionList::default()).unwrap(),
            b.peer_id,
            "identity() is the verified PeerId",
        );

        // Forged: cert by a different operator under the victim's PeerId.
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let victim_pid = op_peer_id(&op);
        let bad = attacker.sign(&binding_signed_bytes(&mls_pubkey, &victim_pid, &SPACE));
        let forged = Binding {
            peer_id: victim_pid,
            display_name: String::from("alice"),
            cert: bad.to_bytes().to_vec(),
        };
        let si_forged = SigningIdentity::new(
            vos_credential(&forged),
            SignaturePublicKey::from(mls_pubkey.to_vec()),
        );
        assert!(
            provider
                .validate_member(&si_forged, None, MemberValidationContext::None)
                .is_err(),
            "a forged cert is rejected",
        );

        // The leaf's signature_key must match what the cert binds — a stolen
        // cert pasted onto a different MLS key is rejected.
        let si_mismatch = SigningIdentity::new(
            vos_credential(&b),
            SignaturePublicKey::from(vec![0xCDu8; 32]),
        );
        assert!(
            provider
                .validate_member(&si_mismatch, None, MemberValidationContext::None)
                .is_err(),
            "cert bound to a different MLS key is rejected",
        );
    }
}
