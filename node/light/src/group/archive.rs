//! The key archive (`light-node.md` §3.4): the naming secret, from which
//! every new scope's id derives, and the naming secrets of the groups a
//! restore recovered, from which their scopes' ids still derive; every
//! scope key of every confirmed epoch, a union indexed by epoch; and the
//! recovery wrap key `R` (§3.5), with the ones this device drew that the
//! control log has not named yet; and the authors a move carried (§3.9):
//! the devices of the groups it left, each up to the node it carried in
//! each scope, this device's own (its move, its restore, a pairing's) and
//! those another device of the set vouched for, signed by its sync key. A
//! device keeps it in its store; a new device receives it over the pairing
//! channel; sealed under an epoch's archive key it travels to the agent,
//! `R` with it and the drawn ones never, its own carried authors vouched
//! for. Archives that disagree keep every candidate key, and the AEAD
//! decides.

use blake2::Blake2b;
use blake2::digest::Digest;
use blake2::digest::consts::U16;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use vos_wire::personal::Scope;
use vos_wire::{Decode, Encode};
use zeroize::{Zeroize, Zeroizing};

/// The `R`s a device holds drawn and not yet named.
const DRAWN: usize = 4;

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
/// sealed under, and the control log's index of the entry that made it
/// the kit's (the claim's, a kit rotation's or a restore's maturity, a
/// re-sealing commit's verdict): of two, the later stands.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub struct Recovery {
    pub since: u64,
    pub r: [u8; 32],
}

/// The archive: the naming secret, the earlier groups' naming secrets, the
/// scopes whose keys it records at each confirmed epoch, the keys, each
/// `(epoch, scope)` with every candidate key archives disagreeing on, `R`
/// once the claim drew it, the `R`s this device drew that the log has not
/// named yet, and the authors a move carried, by author and scope.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub struct Archive {
    pub naming: [u8; 32],
    pub previous: Vec<[u8; 32]>,
    pub scopes: Vec<Scope>,
    pub keys: Vec<Keys>,
    pub recovery: Option<Recovery>,
    pub drawn: Vec<[u8; 32]>,
    pub authors: Vec<CarriedAuthor>,
    pub vouched: Vec<Vouched>,
}

/// An author a move carried in a scope: a device of a group it left, its
/// nodes there read as the set's up to number `through`, the highest a
/// leaving device held short of the author's cutoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct CarriedAuthor {
    pub author: [u8; 32],
    pub scope: Scope,
    pub through: u64,
}

/// A carried author a device of the set vouched for, signed by its sync
/// key `by`: read as the set's while `by` has a voice, and once its
/// removal matured only at positions up to its frontier, so a device's
/// vouching leaves no author writing after its removal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Vouched {
    pub carried: CarriedAuthor,
    pub by: [u8; 32],
    pub signature: [u8; 64],
}

impl CarriedAuthor {
    /// What a device signs to vouch for it at the agent whose identity is
    /// `agent`.
    pub fn message(&self, agent: &[u8; 32]) -> Vec<u8> {
        [
            &b"vos/personal/carried"[..],
            agent,
            &self.author,
            &self.scope,
            &self.through.to_be_bytes(),
        ]
        .concat()
    }
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("previous", &self.previous.len())
            .field("scopes", &self.scopes.len())
            .field("keys", &self.keys.len())
            .field(
                "recovery",
                &self.recovery.as_ref().map(|recovery| recovery.since),
            )
            .field("drawn", &self.drawn.len())
            .field("authors", &self.authors.len())
            .field("vouched", &self.vouched.len())
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
            previous: Vec::new(),
            scopes: Vec::new(),
            keys: Vec::new(),
            recovery: None,
            drawn: Vec::new(),
            authors: Vec::new(),
            vouched: Vec::new(),
        })
    }

    /// The id of the scope named `name`: an earlier group's, if the
    /// archive tracks that scope, else the naming secret's, so a restored
    /// device reads its old scopes and names new ones afresh.
    pub fn scope(&self, name: &[u8]) -> Scope {
        self.previous
            .iter()
            .map(|naming| scope_id(naming, name))
            .find(|id| self.scopes.binary_search(id).is_ok())
            .unwrap_or_else(|| scope_id(&self.naming, name))
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

    /// Admit `carried`'s author in its scope up to its number: of two, the
    /// higher stands.
    pub fn carried(&mut self, carried: CarriedAuthor) {
        let key = |at: &CarriedAuthor| (at.author, at.scope);
        match self
            .authors
            .binary_search_by(|at| key(at).cmp(&key(&carried)))
        {
            Ok(found) => {
                let held = &mut self.authors[found].through;
                *held = (*held).max(carried.through);
            }
            Err(at) => self.authors.insert(at, carried),
        }
    }

    /// The number up to which `author`'s nodes in `scope` were carried by
    /// a move of this device's: none for an author no move of its carried
    /// there.
    pub fn through(&self, author: &[u8; 32], scope: &Scope) -> Option<u64> {
        self.authors
            .binary_search_by(|at| (at.author, at.scope).cmp(&(*author, *scope)))
            .ok()
            .map(|found| self.authors[found].through)
    }

    /// Admit `vouched`, its signature checked by the caller: of two by one
    /// voucher, the higher stands.
    pub fn vouch(&mut self, vouched: Vouched) {
        let key = |at: &Vouched| (at.carried.author, at.carried.scope, at.by);
        match self
            .vouched
            .binary_search_by(|at| key(at).cmp(&key(&vouched)))
        {
            Ok(found) if self.vouched[found].carried.through < vouched.carried.through => {
                self.vouched[found] = vouched;
            }
            Ok(_) => {}
            Err(at) => self.vouched.insert(at, vouched),
        }
    }

    /// The vouchers for `author`'s nodes in `scope`, each with the number
    /// it vouched up to.
    pub fn vouchers(&self, author: &[u8; 32], scope: &Scope) -> Vec<([u8; 32], u64)> {
        self.vouched
            .iter()
            .filter(|at| at.carried.author == *author && at.carried.scope == *scope)
            .map(|at| (at.by, at.carried.through))
            .collect()
    }

    /// Track `scope`: its key is recorded at every confirmed epoch from now.
    pub fn track(&mut self, scope: Scope) {
        if let Err(at) = self.scopes.binary_search(&scope) {
            self.scopes.insert(at, scope);
        }
    }

    /// The union of this archive and `other`: every scope, every earlier
    /// naming secret and every key of either, and the later `R`. The naming
    /// secret and the drawn `R`s stay this archive's.
    pub fn merge(&mut self, other: &Archive) {
        if let Some(theirs) = &other.recovery
            && self
                .recovery
                .as_ref()
                .is_none_or(|mine| theirs.since > mine.since)
            && let Some(mut old) = self.recovery.replace(theirs.clone())
        {
            old.r.zeroize();
        }
        self.merge_keys(other);
    }

    /// `other`'s scopes, earlier naming secrets, keys and carried authors,
    /// its own and those vouched for, merged in, its `R` left out.
    pub fn merge_keys(&mut self, other: &Archive) {
        for naming in &other.previous {
            self.remember(*naming);
        }
        for carried in &other.authors {
            self.carried(*carried);
        }
        for vouched in &other.vouched {
            self.vouch(*vouched);
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

    /// A recovered group's archive taken in: its naming secret one of the
    /// earlier groups', its scopes and keys merged, its `R` left out.
    pub fn inherit(&mut self, other: &Archive) {
        self.remember(other.naming);
        self.merge_keys(other);
    }

    fn remember(&mut self, naming: [u8; 32]) {
        if naming != self.naming && !self.previous.contains(&naming) {
            self.previous.push(naming);
        }
    }

    /// This archive without `R` and the drawn ones: what the recovery
    /// scope holds under `R`.
    pub fn without_recovery(&self) -> Archive {
        let mut archive = self.shareable();
        if let Some(mut recovery) = archive.recovery.take() {
            recovery.r.zeroize();
        }
        archive
    }

    /// This archive without the `R`s this device drew: what a pairing
    /// hands over, and what travels sealed under an epoch's archive key.
    pub fn shareable(&self) -> Archive {
        let mut archive = self.clone();
        archive.drawn.zeroize();
        archive.drawn.clear();
        archive
    }

    /// Hold `r`, drawn by this device, until the log names it: the newest
    /// few kept.
    pub fn draw(&mut self, r: [u8; 32]) {
        if self.drawn.len() >= DRAWN {
            let mut oldest = self.drawn.remove(0);
            oldest.zeroize();
        }
        self.drawn.push(r);
    }

    /// Take as the kit's the `R` this device drew whose hash is `hash`,
    /// named by the log at `since`: whether it held one.
    pub fn name(&mut self, since: u64, hash: &[u8; 32]) -> bool {
        let Some(at) = self
            .drawn
            .iter()
            .position(|r| vos_wire::personal::r_hash(r) == *hash)
        else {
            return false;
        };
        let mut r = self.drawn.remove(at);
        if self.recovery.as_ref().is_none_or(|mine| since > mine.since) {
            if let Some(mut old) = self.recovery.replace(Recovery { since, r }) {
                old.r.zeroize();
            }
        } else {
            r.zeroize();
        }
        true
    }

    /// Drop the drawn `R` whose hash is `hash`: the call that named it
    /// closed without making it the kit's.
    pub fn forget(&mut self, hash: &[u8; 32]) {
        if let Some(at) = self
            .drawn
            .iter()
            .position(|r| vos_wire::personal::r_hash(r) == *hash)
        {
            let mut r = self.drawn.remove(at);
            r.zeroize();
        }
    }

    /// The scopes, keys and carried authors of this archive that `other`
    /// lacks, with this archive's naming secret and no `R`.
    pub fn beyond(&self, other: &Archive) -> Archive {
        Archive {
            naming: self.naming,
            previous: self
                .previous
                .iter()
                .filter(|naming| !other.previous.contains(naming))
                .copied()
                .collect(),
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
            drawn: Vec::new(),
            authors: self
                .authors
                .iter()
                .filter(|at| {
                    other
                        .through(&at.author, &at.scope)
                        .is_none_or(|theirs| theirs < at.through)
                })
                .copied()
                .collect(),
            vouched: self
                .vouched
                .iter()
                .filter(|at| !other.vouched.contains(at))
                .copied()
                .collect(),
        }
    }

    /// Whether it holds no earlier naming secret, no scope, no key and no
    /// carried author.
    pub fn is_empty(&self) -> bool {
        self.previous.is_empty()
            && self.scopes.is_empty()
            && self.keys.is_empty()
            && self.authors.is_empty()
            && self.vouched.is_empty()
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
        self.naming.zeroize();
        self.previous.zeroize();
        self.drawn.zeroize();
        for (_, keys) in &mut self.keys {
            keys.zeroize();
        }
        if let Some(recovery) = &mut self.recovery {
            recovery.r.zeroize();
        }
    }
}
