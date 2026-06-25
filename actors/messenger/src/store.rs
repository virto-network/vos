//! mls-rs storage providers + snapshot/restore.
//!
//! OpenMLS kept every secret in one opaque key-value `StorageProvider` map the
//! messenger snapshotted wholesale. mls-rs instead splits persistence across
//! `GroupStateStorage` (group ratchet state, keyed by group id, with an
//! N-epoch sliding window) and `KeyPackageStorage` (KeyPackage private parts,
//! keyed by key-package ref). We implement both over `BTreeMap`s — deterministic
//! iteration order, no platform RNG — sharing state across the Client's clones
//! through `Arc<Mutex<…>>` (mls-rs requires the providers be `Send + Sync` and
//! the `Group` writes through a *clone* of the provider, so our snapshot clone
//! must see those writes). The maps are snapshotted into the messenger's
//! rkyv-persisted node-local state after every mutating MLS op, and restored on
//! open, so MLS state survives daemon restarts while never leaving this node.
//!
//! `max_past_epochs` has no mls-rs config knob — prior-epoch retention is owned
//! entirely by this store's trim-on-write (the in-memory provider defaults to a
//! mere 3), so the custom store is what enforces the messenger's 64-epoch
//! window. Group mutations are NOT auto-persisted: callers must
//! `Group::write_to_storage()` before snapshotting.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

// Shared, `Send + Sync` storage cells, mirroring how mls-rs's own in-memory
// providers share state across a Client's clones: `spin::Mutex` (a real
// spinlock — safe but never contended in the single-threaded dispatch model)
// over an `Arc`. The host build uses `alloc::sync::Arc`; the no-atomics PVM
// target has no `alloc::sync::Arc`, so it uses `portable_atomic_util::Arc`
// (atomics emulated via `portable-atomic` + `critical-section`).
#[cfg(not(target_arch = "riscv64"))]
use alloc::sync::Arc;
#[cfg(target_arch = "riscv64")]
use portable_atomic_util::Arc;
use spin::Mutex;

use mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

use core::convert::Infallible;

/// Per-group record: the latest group state + a sliding window of prior-epoch
/// secrets (front = oldest retained), mirroring `InMemoryGroupStateStorage`.
#[derive(Clone, Default)]
struct GroupData {
    state: Zeroizing<Vec<u8>>,
    epochs: VecDeque<EpochRecord>,
}

/// `GroupStateStorage` over a shared `BTreeMap`, trimming to a fixed number of
/// retained prior epochs (= the messenger's `MAX_PAST_EPOCHS`).
#[derive(Clone)]
pub(crate) struct VosGroupStateStorage {
    inner: Arc<Mutex<BTreeMap<Vec<u8>, GroupData>>>,
    max_epoch_retention: usize,
}

impl VosGroupStateStorage {
    fn lock(&self) -> spin::MutexGuard<'_, BTreeMap<Vec<u8>, GroupData>> {
        self.inner.lock()
    }

    /// Drop a group's entire ratchet state (used after an eviction, so a
    /// re-invite's Welcome can rebuild a fresh group under the same id).
    pub(crate) fn delete_group(&self, group_id: &[u8]) {
        self.lock().remove(group_id);
    }
}

impl GroupStateStorage for VosGroupStateStorage {
    type Error = Infallible;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Infallible> {
        Ok(self.lock().get(group_id).map(|d| d.state.clone()))
    }

    fn epoch(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<Zeroizing<Vec<u8>>>, Infallible> {
        Ok(self.lock().get(group_id).and_then(|d| {
            let front = d.epochs.front()?.id;
            let i = epoch_id.checked_sub(front)? as usize;
            d.epochs.get(i).map(|e| e.data.clone())
        }))
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Infallible> {
        Ok(self
            .lock()
            .get(group_id)
            .and_then(|d| d.epochs.back().map(|e| e.id)))
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Infallible> {
        let mut map = self.lock();
        let d = map.entry(state.id).or_default();
        d.state = state.data;
        for e in epoch_inserts {
            d.epochs.push_back(e);
        }
        for u in epoch_updates {
            if let Some(front) = d.epochs.front().map(|e| e.id)
                && let Some(i) = u.id.checked_sub(front)
                && let Some(slot) = d.epochs.get_mut(i as usize)
            {
                *slot = u;
            }
        }
        while d.epochs.len() > self.max_epoch_retention {
            d.epochs.pop_front();
        }
        Ok(())
    }
}

/// `KeyPackageStorage` over a shared `BTreeMap`. mls-rs auto-inserts on
/// `generate_key_package_message` and auto-deletes on a successful join.
#[derive(Clone, Default)]
pub(crate) struct VosKeyPackageStorage {
    inner: Arc<Mutex<BTreeMap<Vec<u8>, KeyPackageData>>>,
}

impl VosKeyPackageStorage {
    fn lock(&self) -> spin::MutexGuard<'_, BTreeMap<Vec<u8>, KeyPackageData>> {
        self.inner.lock()
    }
}

impl KeyPackageStorage for VosKeyPackageStorage {
    type Error = Infallible;

    fn delete(&mut self, id: &[u8]) -> Result<(), Infallible> {
        self.lock().remove(id);
        Ok(())
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Infallible> {
        self.lock().insert(id, pkg);
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Infallible> {
        Ok(self.lock().get(id).cloned())
    }
}

/// Both stores, restored from a snapshot (or fresh), ready to hand to the
/// Client builder. The messenger keeps its own clones (sharing the `Arc`s) so
/// it can [`snapshot`] them after a group op writes through the Client's clone.
pub(crate) struct VosStores {
    pub(crate) group_state: VosGroupStateStorage,
    pub(crate) key_packages: VosKeyPackageStorage,
}

impl VosStores {
    /// Fresh empty stores with the given prior-epoch retention.
    fn empty(max_epoch_retention: usize) -> Self {
        VosStores {
            group_state: VosGroupStateStorage {
                inner: Arc::new(Mutex::new(BTreeMap::new())),
                max_epoch_retention,
            },
            key_packages: VosKeyPackageStorage::default(),
        }
    }
}

// ── Snapshot codec ─────────────────────────────────────────────────
//
// Layout (all lengths LE):
//   [group_count u32]
//     repeat: [gid_len u32][gid][state_len u32][state]
//             [epoch_count u32] repeat: [epoch_id u64][data_len u32][data]
//   [kp_count u32]
//     repeat: [id_len u32][kpd_len u32][id][kpd (KeyPackageData::mls_encode)]
// A corrupt/truncated snapshot degrades to fresh empty stores (never panics),
// matching the OpenMLS provider's tolerance.

fn put_u32(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_le_bytes());
}
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len());
    out.extend_from_slice(b);
}

/// Serialize both stores into persistable bytes.
pub(crate) fn snapshot(stores: &VosStores) -> Vec<u8> {
    let mut out = Vec::new();
    let gs = stores.group_state.lock();
    put_u32(&mut out, gs.len());
    for (gid, d) in gs.iter() {
        put_bytes(&mut out, gid);
        put_bytes(&mut out, &d.state);
        put_u32(&mut out, d.epochs.len());
        for e in &d.epochs {
            out.extend_from_slice(&e.id.to_le_bytes());
            put_bytes(&mut out, &e.data);
        }
    }
    drop(gs);
    let kps = stores.key_packages.lock();
    put_u32(&mut out, kps.len());
    for (id, kpd) in kps.iter() {
        let encoded = kpd.mls_encode_to_vec().unwrap_or_default();
        put_bytes(&mut out, id);
        put_bytes(&mut out, &encoded);
    }
    out
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn u32(&mut self) -> Option<usize> {
        let end = self.at.checked_add(4)?;
        let v = u32::from_le_bytes(self.bytes.get(self.at..end)?.try_into().ok()?);
        self.at = end;
        Some(v as usize)
    }
    fn u64(&mut self) -> Option<u64> {
        let end = self.at.checked_add(8)?;
        let v = u64::from_le_bytes(self.bytes.get(self.at..end)?.try_into().ok()?);
        self.at = end;
        Some(v)
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let len = self.u32()?;
        let end = self.at.checked_add(len)?;
        let b = self.bytes.get(self.at..end)?.to_vec();
        self.at = end;
        Some(b)
    }
}

/// Restore both stores from a snapshot, or fresh empty stores when the snapshot
/// is empty or corrupt. `max_epoch_retention` = the messenger's MAX_PAST_EPOCHS.
pub(crate) fn restore(bytes: &[u8], max_epoch_retention: usize) -> VosStores {
    let stores = VosStores::empty(max_epoch_retention);
    if bytes.is_empty() || decode_into(bytes, &stores).is_none() {
        return VosStores::empty(max_epoch_retention);
    }
    stores
}

fn decode_into(bytes: &[u8], stores: &VosStores) -> Option<()> {
    let mut r = Reader { bytes, at: 0 };
    let group_count = r.u32()?;
    {
        let mut gs = stores.group_state.lock();
        for _ in 0..group_count {
            let gid = r.bytes()?;
            let state = r.bytes()?;
            let epoch_count = r.u32()?;
            let mut epochs = VecDeque::with_capacity(epoch_count);
            for _ in 0..epoch_count {
                let id = r.u64()?;
                let data = r.bytes()?;
                epochs.push_back(EpochRecord {
                    id,
                    data: Zeroizing::new(data),
                });
            }
            gs.insert(
                gid,
                GroupData {
                    state: Zeroizing::new(state),
                    epochs,
                },
            );
        }
    }
    let kp_count = r.u32()?;
    {
        let mut kps = stores.key_packages.lock();
        for _ in 0..kp_count {
            let id = r.bytes()?;
            let encoded = r.bytes()?;
            let kpd = KeyPackageData::mls_decode(&mut &encoded[..]).ok()?;
            kps.insert(id, kpd);
        }
    }
    Some(())
}
