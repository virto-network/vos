//! Explicit Local signer actor.
//!
//! The secret seed is immutable installation data and never becomes a host
//! signing capability. Callers obtain a visible signature and submit it to a
//! Shared workflow as a separate operation.

use ed25519_dalek::{Signer as _, SigningKey};
use vos::prelude::*;

const SIGNING_DOMAIN: &[u8] = b"vos/local-signer/v1";
const MAX_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum SignerRole {
    Sign = 0,
}

impl vos::RoleByte for SignerRole {
    fn from_byte(byte: u8) -> Option<Self> {
        (byte == Self::Sign as u8).then_some(Self::Sign)
    }

    fn as_byte(self) -> u8 {
        self as u8
    }
}

const SIGNER_SPACE_ROLE_MAP: vos::SpaceRoleMap<SignerRole> = vos::SpaceRoleMap {
    admin: Some(SignerRole::Sign),
    developer: Some(SignerRole::Sign),
    member: Some(SignerRole::Sign),
    guest: None,
};

#[actor(
    agent,
    role = SignerRole,
    default_role = SignerRole::Sign,
    space_role_map = SIGNER_SPACE_ROLE_MAP
)]
pub struct LocalSigner {
    #[state(const)]
    secret_seed: [u8; 32],
    #[state(local)]
    signatures: u64,
}

#[messages(agent)]
impl LocalSigner {
    fn new(secret_seed: [u8; 32]) -> Self {
        Self {
            secret_seed,
            signatures: 0,
        }
    }

    #[msg(query)]
    fn public_key(&self) -> Vec<u8> {
        SigningKey::from_bytes(&self.secret_seed)
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    #[msg(
        local,
        role = SignerRole::Sign,
        actor_role_id = "5151515151515151515151515151515151515151515151515151515151515151"
    )]
    fn sign(&mut self, context: [u8; 32], message: Vec<u8>) -> Vec<u8> {
        let Some(signature) = signature_for(self.secret_seed, context, &message) else {
            return Vec::new();
        };
        self.signatures = self.signatures.saturating_add(1);
        signature.to_vec()
    }
}

fn signature_for(secret_seed: [u8; 32], context: [u8; 32], message: &[u8]) -> Option<[u8; 64]> {
    (message.len() <= MAX_MESSAGE_BYTES).then(|| {
        SigningKey::from_bytes(&secret_seed)
            .sign(&signing_message(context, message))
            .to_bytes()
    })
}

fn signing_message(context: [u8; 32], message: &[u8]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + 8 + message.len());
    signed.extend_from_slice(SIGNING_DOMAIN);
    signed.extend_from_slice(&context);
    signed.extend_from_slice(&(message.len() as u64).to_le_bytes());
    signed.extend_from_slice(message);
    signed
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier as _};

    #[test]
    fn signatures_bind_context_length_and_exact_message() {
        let seed = [7; 32];
        let context = [9; 32];
        let signer = LocalSigner::new(seed);
        assert_eq!(signer.signatures, 0);
        let signature = signature_for(seed, context, b"approve").unwrap();
        let verifying_key = SigningKey::from_bytes(&seed).verifying_key();
        verifying_key
            .verify(
                &signing_message(context, b"approve"),
                &Signature::from_bytes(&signature),
            )
            .unwrap();
        assert!(
            verifying_key
                .verify(
                    &signing_message([10; 32], b"approve"),
                    &Signature::from_bytes(&signature),
                )
                .is_err()
        );
        assert!(
            verifying_key
                .verify(
                    &signing_message(context, b"approve!"),
                    &Signature::from_bytes(&signature),
                )
                .is_err()
        );
    }

    #[test]
    fn oversized_messages_are_refused_without_signing() {
        assert!(signature_for([3; 32], [4; 32], &vec![0; MAX_MESSAGE_BYTES + 1]).is_none());
    }
}
