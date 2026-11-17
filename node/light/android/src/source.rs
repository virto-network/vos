// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The secret's source: a keyed HMAC-SHA-256 whose key never leaves the
//! device, evaluated once per use after the user's consent at the source
//! itself (a biometric or the screen lock's PIN at the Android Keystore; the
//! PIN and a touch at a security key). Its 32-byte output for the space's
//! input is equivalent to the member's secret: it crosses into the process at
//! each use, is copied once and zeroized.

use std::future::Future;
use std::pin::Pin;

use zeroize::Zeroizing;

/// A boxed future, as the facility's traits return them.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub use s4_credential_contract::Kind;

/// The relying party a security key's credential is made under: a CTAP2
/// string, not a WebAuthn origin, the same for every space (the salt is
/// the space's input).
pub const RP_ID: &str = "vos.device";

/// What the device keeps to reach its source again.
#[derive(Clone, Debug, PartialEq, Eq, vos_abi::Encode, vos_abi::Decode)]
pub enum Reference {
    /// The Keystore key's alias.
    #[codec(index = 1)]
    Keystore { alias: String },
    /// The security key's credential id.
    #[codec(index = 2)]
    SecurityKey { credential: Vec<u8> },
}

impl Reference {
    pub fn kind(&self) -> Kind {
        match self {
            Reference::Keystore { .. } => Kind::Keystore,
            Reference::SecurityKey { .. } => Kind::SecurityKey,
        }
    }

    /// Its bytes across the client's boundary: the kind's byte (1 the
    /// Keystore, 2 a security key), then the alias's UTF-8 or the
    /// credential id.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Reference::Keystore { alias } => [&[1], alias.as_bytes()].concat(),
            Reference::SecurityKey { credential } => [&[2], credential.as_slice()].concat(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first()? {
            (1, alias) if !alias.is_empty() => Some(Reference::Keystore {
                alias: String::from_utf8(alias.to_vec()).ok()?,
            }),
            (2, credential) if !credential.is_empty() => Some(Reference::SecurityKey {
                credential: credential.to_vec(),
            }),
            _ => None,
        }
    }
}

/// Why a source gave nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// The user declined, or dismissed the source's own prompt.
    Declined,
    /// The source failed: its message, which holds no secret.
    Failed(String),
}

/// A source's output, on the heap and zeroized on drop: handed between
/// threads and tasks, it moves as a pointer and leaves no copy of its bytes
/// in a freed task or future.
pub type Output = Box<Zeroizing<[u8; 32]>>;

/// The device's secret sources.
pub trait Source: Send + Sync + 'static {
    /// The kinds this device offers, the default first; none when it has
    /// no source (an Android older than 11, say).
    fn kinds(&self) -> Vec<Kind>;

    /// Make a new key of `kind`: its reference.
    fn create(&self, kind: Kind) -> BoxFuture<'_, Result<Reference, SourceError>>;

    /// The keyed HMAC of `input` under the key `reference` names, after the
    /// user's consent at the source.
    fn evaluate<'a>(
        &'a self,
        reference: &'a Reference,
        input: [u8; 32],
    ) -> BoxFuture<'a, Result<Output, SourceError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_crosses_as_its_bytes() {
        for reference in [
            Reference::Keystore {
                alias: "vos.device.7".into(),
            },
            Reference::SecurityKey {
                credential: vec![9; 64],
            },
        ] {
            assert_eq!(
                Reference::from_bytes(&reference.to_bytes()),
                Some(reference)
            );
        }
        for bytes in [&[][..], &[1], &[2], &[3, 1], &[1, 0xff]] {
            assert_eq!(Reference::from_bytes(bytes), None);
        }
        assert_eq!(
            Kind::from_bit(Kind::SecurityKey.bit()),
            Some(Kind::SecurityKey)
        );
        assert_eq!(Kind::from_bit(Kind::Admin.bit()), Some(Kind::Admin));
        assert_eq!(Kind::from_bit(Kind::Kit.bit()), Some(Kind::Kit));
        assert_eq!(Kind::from_bit(16), None);
    }
}
