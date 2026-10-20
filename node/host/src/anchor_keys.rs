//! The node's anchor keys: the ed25519 keys its leadership of the space's
//! representative signs anchors with. The first is the node key, which a
//! founding node's genesis names, so a venue registers it with the space;
//! each rotation makes another, kept durably beside it before its public
//! half is shown, for the space's controller to register (`add_authority`).
//! The node signs with the newest of its keys the venue lists, and with
//! none when the venue lists none of them; a node holding a listed key may
//! replicate the representative.

use std::path::Path;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use vos_venue::kreivo::AccountSeed;

use crate::storage::{Change, StorageThread};
use crate::store::{Fjall, PersistMode};
use crate::{lock, random};

/// A node's anchor keys, oldest first: the node key, then each rotation's.
pub(crate) struct AnchorKeys {
    held: Mutex<Held>,
    /// Held across a rotation's commit, so two rotations number their
    /// keys apart.
    rotating: smol::lock::Mutex<()>,
}

struct Held {
    keys: Vec<SigningKey>,
    /// The number the next rotation's key takes: past every one stored,
    /// an unreadable one's too.
    next: u64,
}

/// The number after the last of `stored`, as [`Fjall::anchor_secrets`]
/// lists them: 1 with none.
fn next_number(stored: &[(u64, Option<[u8; 32]>)]) -> u64 {
    stored.last().map_or(1, |(number, _)| number + 1)
}

impl AnchorKeys {
    /// The keys `store` holds past the node key, whose seed is `secret`.
    pub(crate) fn load(secret: &[u8; 32], store: &Fjall) -> Result<Self, fjall::Error> {
        let stored = store.anchor_secrets()?;
        let keys = std::iter::once(*secret)
            .chain(stored.iter().filter_map(|(_, seed)| *seed))
            .map(|seed| SigningKey::from_bytes(&seed))
            .collect();
        Ok(Self {
            held: Mutex::new(Held {
                keys,
                next: next_number(&stored),
            }),
            rotating: smol::lock::Mutex::new(()),
        })
    }

    /// Their public halves, oldest first.
    pub(crate) fn public(&self) -> Vec<[u8; 32]> {
        lock(&self.held)
            .keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect()
    }

    /// The newest key among `listed`, the anchor keys a venue registered:
    /// none when it lists none of them.
    pub(crate) fn listed(&self, listed: &[[u8; 32]]) -> Option<SigningKey> {
        lock(&self.held)
            .keys
            .iter()
            .rev()
            .find(|key| listed.contains(&key.verifying_key().to_bytes()))
            .cloned()
    }

    /// Make a key, committed durably by `storage` before it is used or
    /// shown: its public half.
    pub(crate) async fn rotate(&self, storage: &StorageThread) -> Result<[u8; 32], String> {
        let _rotating = self.rotating.lock().await;
        let number = lock(&self.held).next;
        let seed = random();
        storage
            .commit(vec![Change::AnchorKey { number, seed }])
            .await?;
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        let mut held = lock(&self.held);
        held.keys.push(key);
        held.next = number + 1;
        Ok(public)
    }
}

/// The store of the stopped node whose data directory is `data`, and its
/// node key's seed: refused when the node has not run.
fn stopped(data: &Path) -> Result<(Fjall, [u8; 32]), String> {
    let path = data.join(crate::STORE);
    let failed = |error: fjall::Error| format!("{}: {error:?}", path.display());
    if !path.exists() {
        return Err(format!(
            "{}: no node's store; run the node once first",
            path.display()
        ));
    }
    let store = Fjall::open(&path).map_err(failed)?;
    let Some(secret) = store.node_secret().map_err(failed)? else {
        return Err(format!(
            "{}: the node has no key yet; run it once first",
            path.display()
        ));
    };
    Ok((store, secret))
}

fn failed(data: &Path) -> impl Fn(fjall::Error) -> String {
    let path = data.join(crate::STORE);
    move |error| format!("{}: {error:?}", path.display())
}

/// Make an anchor key for the node whose data directory is `data`, its
/// node stopped: kept durably in its store before its public half is
/// returned, for the space's controller to register. The node signs with
/// it once a venue lists it.
pub fn rotate_anchor_key(data: impl AsRef<Path>) -> Result<[u8; 32], String> {
    let data = data.as_ref();
    let (store, _) = stopped(data)?;
    let number = next_number(&store.anchor_secrets().map_err(failed(data))?);
    let seed: [u8; 32] = random();
    let mut batch = store.batch();
    batch.anchor_secret(number, &seed);
    batch.commit(PersistMode::SyncAll).map_err(failed(data))?;
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

/// The account key at its space's venue of the node whose data directory
/// is `data`, its node stopped: its newest, made and kept durably if it
/// has none, for the space's controller to register its account as an
/// authority.
pub fn venue_account(data: impl AsRef<Path>) -> Result<AccountSeed, String> {
    let data = data.as_ref();
    let (store, _) = stopped(data)?;
    crate::node::venue_account_secret(&store)
        .map(AccountSeed::new)
        .map_err(|error| format!("{}: {error:?}", data.display()))
}

/// Make the node whose data directory is `data`, its node stopped, a new
/// account key at its space's venue, kept durably beside the old, which
/// stays in the store: the old and the new. The node signs as the new
/// from its next start; the controller removes the old authority, then
/// adds the new paired with the node's anchor key (a key paired with one
/// authority is refused to another), so the node anchors nothing between
/// the two calls.
pub fn rotate_venue_account(
    data: impl AsRef<Path>,
) -> Result<(Option<AccountSeed>, AccountSeed), String> {
    let data = data.as_ref();
    let (store, _) = stopped(data)?;
    let old = store
        .venue_account_secrets()
        .map_err(failed(data))?
        .into_iter()
        .rev()
        .find_map(|(_, seed)| seed)
        .map(AccountSeed::new);
    let new = crate::node::new_venue_account(&store)
        .map(AccountSeed::new)
        .map_err(|error| format!("{}: {error:?}", data.display()))?;
    Ok((old, new))
}

/// The node key of the stopped node whose data directory is `data`, and
/// its signature over `digest`: a founding node's, registering its space
/// at a venue.
pub fn sign_with_node_key(
    data: impl AsRef<Path>,
    digest: &[u8; 32],
) -> Result<([u8; 32], [u8; 64]), String> {
    use ed25519_dalek::Signer;
    let (_, secret) = stopped(data.as_ref())?;
    let key = SigningKey::from_bytes(&secret);
    Ok((key.verifying_key().to_bytes(), key.sign(digest).to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unreadable key's number is never reused: the next rotation
    /// numbers past it, so it cannot overwrite the newest key.
    #[test]
    fn a_rotation_numbers_past_an_unreadable_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(crate::STORE);
        let store = Fjall::open(&path).unwrap();
        let mut batch = store.batch();
        batch.node_secret(&[1; 32]);
        batch.anchor_secret(1, &[2; 32]);
        batch.anchor_secret(2, &[3; 32]);
        batch.commit(PersistMode::SyncAll).unwrap();
        store.corrupt_anchor_secret(1);
        drop(store);
        let made = rotate_anchor_key(dir.path()).unwrap();
        let store = Fjall::open(&path).unwrap();
        let stored = store.anchor_secrets().unwrap();
        assert_eq!(stored.len(), 3);
        assert_eq!(stored[0], (1, None), "the unreadable row kept as it was");
        assert_eq!(stored[1], (2, Some([3; 32])), "the newest key kept");
        let (number, seed) = stored[2];
        assert_eq!(number, 3);
        assert_eq!(
            SigningKey::from_bytes(&seed.unwrap())
                .verifying_key()
                .to_bytes(),
            made
        );
        let keys = AnchorKeys::load(&[1; 32], &store).unwrap();
        assert_eq!(keys.public().len(), 3, "the node key and the two readable");
        assert_eq!(lock(&keys.held).next, 4);
    }

    /// A node's account key at its venue is made once, kept in its store
    /// beside its node key and anchor keys, and never one of them; it is
    /// never shown. A rotation makes another, which the node signs as, and
    /// keeps the old. A node that has not run has none to make.
    #[test]
    fn the_venue_account_is_made_once_and_kept_apart() {
        let dir = tempfile::tempdir().unwrap();
        assert!(venue_account(dir.path()).is_err(), "no store yet");
        let path = dir.path().join(crate::STORE);
        let store = Fjall::open(&path).unwrap();
        let mut batch = store.batch();
        batch.node_secret(&[1; 32]);
        batch.anchor_secret(1, &[2; 32]);
        batch.commit(PersistMode::SyncAll).unwrap();
        drop(store);
        let made = venue_account(dir.path()).unwrap();
        let again = venue_account(dir.path()).unwrap();
        assert_eq!(made.secret(), again.secret(), "kept");
        assert_ne!(*made.secret(), [1; 32], "not the node key");
        assert_ne!(*made.secret(), [2; 32], "not an anchor key");
        assert_eq!(format!("{made:?}"), "AccountSeed(..)");
        let store = Fjall::open(&path).unwrap();
        let stored = store.venue_account_secrets().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, 1);
        assert_eq!(stored[0].1.as_deref(), Some(made.secret()));
        assert_eq!(store.anchor_secrets().unwrap(), [(1, Some([2; 32]))]);
        drop(store);
        let (old, new) = rotate_venue_account(dir.path()).unwrap();
        assert_eq!(old.unwrap().secret(), made.secret(), "the old one returned");
        assert_ne!(new.secret(), made.secret());
        assert_eq!(
            venue_account(dir.path()).unwrap().secret(),
            new.secret(),
            "the newest signs"
        );
        let store = Fjall::open(&path).unwrap();
        let numbers: Vec<u64> = store
            .venue_account_secrets()
            .unwrap()
            .iter()
            .map(|(number, _)| *number)
            .collect();
        assert_eq!(numbers, [1, 2], "the old one kept");
        drop(store);
        let digest = [9; 32];
        let (key, signature) = sign_with_node_key(dir.path(), &digest).unwrap();
        let node = SigningKey::from_bytes(&[1; 32]).verifying_key();
        assert_eq!(key, node.to_bytes(), "the node key signs");
        assert!(
            node.verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&signature))
                .is_ok()
        );
    }
}
