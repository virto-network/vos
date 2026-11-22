//! What the device keeps of its personal space: rows of the light node's
//! store, in its group keyspace under `p/`, each written in the batch of
//! the change it describes (a claim's, a pairing's group, a restore's
//! split), so no reconciliation is needed after a crash. Their encoding is
//! the store's layout's ([`crate::store::LAYOUT`]): a store of another
//! layout is refused whole, and a change to a row is a new layout.

use vos_abi::{Decode, Encode};

use super::{Acked, Error, Kept, Refreshed, Restoring, State};
use crate::store::{Change, Store};

/// The home the device's agent is at and the agent, written in the batch
/// that makes them the device's: the claim's, the pairing's group's, the
/// restore's split's.
const HOME: &[u8] = b"p/home";
/// The secret source's key, written the moment it is made.
const SOURCE: &[u8] = b"p/source";
/// The admin key's public half and its attestation.
const ADMIN: &[u8] = b"p/admin";
/// The admin keys offered to replace this device's, the newest last.
const NEXT_ADMIN: &[u8] = b"p/next-admin";
/// The device's label.
const LABEL: &[u8] = b"p/label";
/// A restore opened, from before its call until it matures.
const RESTORING: &[u8] = b"p/restoring";
/// A joiner's acknowledgement, until it is put in its slot.
const ACKED: &[u8] = b"p/acked";
/// The kit's calls as signed, until their evidence is posted.
const KIT_CALLS: &[u8] = b"p/kit-calls";
/// The home's onion set's last read from its registrar.
const ONIONS: &[u8] = b"p/onions";
/// Present while a claim's new kit is shown and no claim holds it.
const KIT_SHOWN: &[u8] = b"p/kit-shown";
/// Written in a store's first batch: the store is the device's from then
/// on ([`super::Personal::open`] takes the newest store that holds it).
const READY: &[u8] = b"p/ready";

fn row<T: Decode>(store: &Store, key: &[u8]) -> Result<Option<T>, Error> {
    match store.group_row(key).map_err(super::store_failed)? {
        None => Ok(None),
        Some(bytes) => T::decode_exact(&bytes).map(Some).ok_or_else(|| {
            Error::NeedsRepair(format!("its row {} does not decode", key.escape_ascii()))
        }),
    }
}

impl State {
    /// What `store` keeps.
    pub(super) fn read(store: &Store) -> Result<Self, Error> {
        let (home, agent) =
            row::<(Option<Kept>, Option<(u32, [u8; 32])>)>(store, HOME)?.unwrap_or_default();
        Ok(Self {
            home,
            agent,
            source: row(store, SOURCE)?,
            admin: row(store, ADMIN)?,
            label: row(store, LABEL)?.unwrap_or_default(),
            next_admin: row(store, NEXT_ADMIN)?.unwrap_or_default(),
            restoring: row::<Restoring>(store, RESTORING)?,
            acked: row::<Acked>(store, ACKED)?,
            kit_calls: row(store, KIT_CALLS)?.unwrap_or_default(),
            onions: row::<Refreshed>(store, ONIONS)?,
            kit_shown: store
                .group_row(KIT_SHOWN)
                .map_err(super::store_failed)?
                .is_some(),
        })
    }

    /// Every row of what the device keeps, one absent deleted.
    pub(super) fn rows(&self) -> Vec<Change> {
        fn some<T: Encode>(value: &Option<T>) -> Option<Vec<u8>> {
            value.as_ref().map(Encode::encode)
        }
        let home = (self.home.is_some() || self.agent.is_some())
            .then(|| (self.home.clone(), self.agent).encode());
        vec![
            (HOME.to_vec(), home),
            (SOURCE.to_vec(), some(&self.source)),
            (ADMIN.to_vec(), some(&self.admin)),
            (LABEL.to_vec(), Some(self.label.encode())),
            (
                NEXT_ADMIN.to_vec(),
                (!self.next_admin.is_empty()).then(|| self.next_admin.encode()),
            ),
            (RESTORING.to_vec(), some(&self.restoring)),
            (ACKED.to_vec(), some(&self.acked)),
            (
                KIT_CALLS.to_vec(),
                (!self.kit_calls.is_empty()).then(|| self.kit_calls.encode()),
            ),
            (ONIONS.to_vec(), some(&self.onions)),
            (KIT_SHOWN.to_vec(), self.kit_shown.then(Vec::new)),
        ]
    }

    /// The rows of a store made the device's: what it keeps, and its mark.
    pub(super) fn first_rows(&self) -> Vec<Change> {
        let mut rows = self.rows();
        rows.push((READY.to_vec(), Some(Vec::new())));
        rows
    }
}

/// Whether `store` was made the device's.
pub(super) fn ready(store: &Store) -> Result<bool, Error> {
    Ok(store
        .group_row(READY)
        .map_err(super::store_failed)?
        .is_some())
}
