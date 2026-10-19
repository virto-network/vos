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

use crate::storage::{Change, StorageThread};
use crate::store::{Fjall, PersistMode};
use crate::{lock, random};

/// A node's anchor keys, oldest first: the node key, then each rotation's.
pub(crate) struct AnchorKeys {
    keys: Mutex<Vec<SigningKey>>,
    /// Held across a rotation's commit, so two rotations number their
    /// keys apart.
    rotating: smol::lock::Mutex<()>,
}

impl AnchorKeys {
    /// The keys `store` holds past the node key, whose seed is `secret`.
    pub(crate) fn load(secret: &[u8; 32], store: &Fjall) -> Result<Self, fjall::Error> {
        let keys = std::iter::once(*secret)
            .chain(store.anchor_secrets()?)
            .map(|seed| SigningKey::from_bytes(&seed))
            .collect();
        Ok(Self {
            keys: Mutex::new(keys),
            rotating: smol::lock::Mutex::new(()),
        })
    }

    /// Their public halves, oldest first.
    pub(crate) fn public(&self) -> Vec<[u8; 32]> {
        lock(&self.keys)
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect()
    }

    /// The newest key among `listed`, the anchor keys a venue registered:
    /// none when it lists none of them.
    pub(crate) fn listed(&self, listed: &[[u8; 32]]) -> Option<SigningKey> {
        lock(&self.keys)
            .iter()
            .rev()
            .find(|key| listed.contains(&key.verifying_key().to_bytes()))
            .cloned()
    }

    /// Make a key, committed durably by `storage` before it is used or
    /// shown: its public half.
    pub(crate) async fn rotate(&self, storage: &StorageThread) -> Result<[u8; 32], String> {
        let _rotating = self.rotating.lock().await;
        let number = lock(&self.keys).len() as u64;
        let seed = random();
        storage
            .commit(vec![Change::AnchorKey { number, seed }])
            .await?;
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        lock(&self.keys).push(key);
        Ok(public)
    }
}

/// Make an anchor key for the node whose data directory is `data`, its
/// node stopped: kept durably in its store before its public half is
/// returned, for the space's controller to register. The node signs with
/// it once a venue lists it.
pub fn rotate_anchor_key(data: impl AsRef<Path>) -> Result<[u8; 32], String> {
    let path = data.as_ref().join(crate::STORE);
    let failed = |error: fjall::Error| format!("{}: {error:?}", path.display());
    if !path.exists() {
        return Err(format!(
            "{}: no node's store; run the node once first",
            path.display()
        ));
    }
    let store = Fjall::open(&path).map_err(failed)?;
    if store.node_secret().map_err(failed)?.is_none() {
        return Err(format!(
            "{}: the node has no key yet; run it once first",
            path.display()
        ));
    }
    let number = store.anchor_secrets().map_err(failed)?.len() as u64 + 1;
    let seed: [u8; 32] = random();
    let mut batch = store.batch();
    batch.anchor_secret(number, &seed);
    batch.commit(PersistMode::SyncAll).map_err(failed)?;
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}
