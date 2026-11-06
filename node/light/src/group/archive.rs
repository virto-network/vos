//! The key archive (`light-node.md` §3.4): the naming secret, from which
//! every scope's id derives, every scope key of every confirmed epoch, a
//! union indexed by epoch, and the recovery wrap key `R` (§3.5). A device keeps it in its store; a new device
//! receives it over the pairing channel; sealed under an epoch's archive
//! key it travels to the agent. Archives that disagree keep every
//! candidate key, and the AEAD decides.

use blake2::Blake2b;
use blake2::digest::Digest;
use blake2::digest::consts::U16;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use vos_wire::personal::Scope;
use vos_wire::{Decode, Encode};
use zeroize::Zeroizing;

/// The exporter's label for a scope's key: `k(scope, n) =
/// MLS-Exporter("vos/personal/scope", scope_id, 32)`.
pub const SCOPE_LABEL: &[u8] = b"vos/personal/scope";

/// The exporter's label for the archive's key in an epoch.
pub const ARCHIVE_LABEL: &[u8] = b"vos/personal/archive";

/// A scope's id: `BLAKE2b-128("vos/personal/scope-id" ‖ naming ‖ name)`.
pub fn scope_id(naming: &[u8; 32], name: &[u8]) -> Scope {
    let mut hasher = Blake2b::<U16>::new();
    hasher.update(b"vos/personal/scope-id");
    hasher.update(naming);
    hasher.update(name);
    hasher.finalize().into()
}

/// The candidate keys of one scope in one epoch.
pub type Keys = ((u64, Scope), Vec<[u8; 32]>);

/// The recovery wrap key `R = R1 ⊕ R2`, which recovery envelopes are
/// sealed under, and the control log's index of the claim or kit rotation
/// that drew it: of two, the later stands.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub struct Recovery {
    pub since: u64,
    pub r: [u8; 32],
}

/// The archive: the naming secret, the scopes whose keys it records at
/// each confirmed epoch, the keys, each `(epoch, scope)` with every
/// candidate key archives disagreeing on, and `R`, once the claim drew it.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub struct Archive {
    pub naming: [u8; 32],
    pub scopes: Vec<Scope>,
    pub keys: Vec<Keys>,
    pub recovery: Option<Recovery>,
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("scopes", &self.scopes.len())
            .field("keys", &self.keys.len())
            .field(
                "recovery",
                &self.recovery.as_ref().map(|recovery| recovery.since),
            )
            .finish_non_exhaustive()
    }
}

impl Archive {
    /// An archive holding a naming secret drawn from the operating system,
    /// and no key.
    pub fn fresh() -> Option<Self> {
        let mut naming = [0; 32];
        getrandom::getrandom(&mut naming).ok()?;
        Some(Self {
            naming,
            scopes: Vec::new(),
            keys: Vec::new(),
            recovery: None,
        })
    }

    /// The id of the scope named `name`.
    pub fn scope(&self, name: &[u8]) -> Scope {
        scope_id(&self.naming, name)
    }

    /// The candidate keys of `scope` in `epoch`.
    pub fn keys(&self, epoch: u64, scope: &Scope) -> &[[u8; 32]] {
        match self
            .keys
            .binary_search_by(|(at, _)| at.cmp(&(epoch, *scope)))
        {
            Ok(found) => &self.keys[found].1,
            Err(_) => &[],
        }
    }

    /// Record `key` as a candidate of `scope` in `epoch`. Candidates are
    /// kept in order, so two archives holding the same keys encode alike.
    pub fn record(&mut self, epoch: u64, scope: Scope, key: [u8; 32]) {
        match self
            .keys
            .binary_search_by(|(at, _)| at.cmp(&(epoch, scope)))
        {
            Ok(found) => {
                let keys = &mut self.keys[found].1;
                if let Err(at) = keys.binary_search(&key) {
                    keys.insert(at, key);
                }
            }
            Err(at) => self.keys.insert(at, ((epoch, scope), vec![key])),
        }
    }

    /// Track `scope`: its key is recorded at every confirmed epoch from now.
    pub fn track(&mut self, scope: Scope) {
        if let Err(at) = self.scopes.binary_search(&scope) {
            self.scopes.insert(at, scope);
        }
    }

    /// The union of this archive and `other`: every scope and every key of
    /// either, and the later `R`. The naming secret stays this archive's.
    pub fn merge(&mut self, other: &Archive) {
        if let Some(theirs) = &other.recovery
            && self
                .recovery
                .as_ref()
                .is_none_or(|mine| theirs.since > mine.since)
        {
            self.recovery = Some(theirs.clone());
        }
        for scope in &other.scopes {
            self.track(*scope);
        }
        for ((epoch, scope), keys) in &other.keys {
            for key in keys {
                self.record(*epoch, *scope, *key);
            }
        }
    }

    /// This archive without `R`: what travels through the agent.
    pub fn without_recovery(&self) -> Archive {
        let mut archive = self.clone();
        if let Some(mut recovery) = archive.recovery.take() {
            use zeroize::Zeroize;
            recovery.r.zeroize();
        }
        archive
    }

    /// The scopes and keys of this archive that `other` lacks, with this
    /// archive's naming secret and no `R`.
    pub fn beyond(&self, other: &Archive) -> Archive {
        Archive {
            naming: self.naming,
            scopes: self
                .scopes
                .iter()
                .filter(|scope| other.scopes.binary_search(scope).is_err())
                .copied()
                .collect(),
            keys: self
                .keys
                .iter()
                .filter_map(|((epoch, scope), keys)| {
                    let theirs = other.keys(*epoch, scope);
                    let new: Vec<[u8; 32]> = keys
                        .iter()
                        .filter(|key| !theirs.contains(key))
                        .copied()
                        .collect();
                    (!new.is_empty()).then_some(((*epoch, *scope), new))
                })
                .collect(),
            recovery: None,
        }
    }

    /// Whether it holds no scope and no key.
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty() && self.keys.is_empty()
    }

    /// The archive sealed under `key` with `nonce`: XChaCha20-Poly1305 over
    /// its encoding, `aad` bound.
    pub fn seal(&self, key: &[u8; 32], nonce: &[u8; 24], aad: &[u8]) -> Vec<u8> {
        let plain = Zeroizing::new(self.encode());
        XChaCha20Poly1305::new(key.into())
            .encrypt(XNonce::from_slice(nonce), Payload { msg: &plain, aad })
            .expect("an archive seals")
    }

    /// An archive `sealed` under `key` with `nonce` and `aad`; `None` for
    /// bytes that do not open or decode.
    pub fn open(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], sealed: &[u8]) -> Option<Self> {
        let plain = XChaCha20Poly1305::new(key.into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: sealed, aad })
            .ok()?;
        let plain = Zeroizing::new(plain);
        Self::decode_exact(&plain)
    }
}

impl Drop for Archive {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.naming.zeroize();
        for (_, keys) in &mut self.keys {
            keys.zeroize();
        }
        if let Some(recovery) = &mut self.recovery {
            recovery.r.zeroize();
        }
    }
}
