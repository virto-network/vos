//! Storage-backed collections — actor state that lives as per-service
//! KV rows instead of inside the rkyv state blob.
//!
//! A `#[storage]` field on an `#[actor]` struct is a typed handle over a
//! slice of the agent's keyspace: point reads go through `STORAGE_R`,
//! mutations queue as per-key `Write`/`Delete` effects in the halt
//! payload, and the guest's memory footprint is bounded by the rows a
//! dispatch actually touches — not by the collection size. The handle
//! itself carries no data (it archives as a unit), so the state blob
//! stays small and the anchor cheap.
//!
//! ## Key layout
//!
//! Each handle owns the prefix `s/<field>/` (macro-assigned from the
//! field name; override with `#[storage(prefix = "…")]`). Renaming a
//! field without pinning its prefix orphans the rows — the prefix is
//! part of the actor's upgrade contract. Within a prefix:
//!
//! ```text
//! s/<field>/v<key-bytes>     value row (one per entry)
//! s/<field>/i<page: u32 BE>  index page: sorted, fixed-stride key bytes
//! s/<field>/m                meta row: count + page directory
//! s/<field>/l                length row (StorageVec)
//! s/<field>/e<idx: u64 BE>   element row (StorageVec)
//! s/<field>/x                value row (StorageValue)
//! ```
//!
//! Point ops read at most a value row; ordered iteration reads key-only
//! index pages (~[`PAGE_BYTES`] each) and fetches values lazily, so a
//! paged query touches a handful of rows however large the map is. No
//! iteration hostcall exists or is needed — the index is ordinary rows,
//! which also keeps actors portable to a conformant JAM host (where
//! `STORAGE_R` is accumulate-only and refine data arrives as witness).
//!
//! ## Dispatch semantics
//!
//! Reads overlay the dispatch's own pending mutations (read-your-own-
//! writes, tombstones read as absent), then a per-dispatch cache, then
//! the host. At dispatch end the framework drains the pending set into
//! the refine payload — ahead of the final state write — so row
//! mutations commit atomically with the state blob in the same
//! [`AgentDelta`](crate::commit::AgentDelta) and replicate as ordinary
//! effects under CRDT/Raft.
//!
//! Storage handles are usable only inside a dispatch on the service
//! runtime; an uninitialized handle (constructed outside `#[actor]`)
//! panics on first use.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::codec::{Decode, Encode};

mod committed;
pub use committed::{CommittedMap, CommittedMapIter};

/// Hard per-value ceiling. A row past this belongs in the blob CAS by
/// hash, not in the agent keyspace: the guest heap is 256 KiB and every
/// oversized row rides the halt payload toward the 1 MiB cap.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Byte budget for one index page of keys. Sized to fit the 4 KiB
/// hostcall probe buffer in a single `STORAGE_R` round-trip.
pub const PAGE_BYTES: usize = 3072;

// ── Dispatch-scoped overlay ──────────────────────────────────────────

struct DispatchState {
    /// This dispatch's queued mutations: `None` = delete tombstone.
    /// A `BTreeMap` so last-wins per key is applied at queue time and
    /// the drain emits one effect per touched key, in key order.
    pending: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// Rows read from the host this dispatch (`None` = host said
    /// absent). Cleared at dispatch end: an out-of-band CRDT merge may
    /// rewrite rows between dispatches, so nothing cached outlives the
    /// dispatch that read it.
    cache: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl DispatchState {
    const fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            cache: BTreeMap::new(),
        }
    }
}

// The guest is single-threaded (one PVM, one dispatch at a time), so a
// static mut behind an accessor is sound there — same pattern as the
// framework's ACTOR_HOLDER. Host builds (unit tests, actors dev-deped
// from std code) get a thread-local instead.
#[cfg(not(feature = "std"))]
fn with_state<R>(f: impl FnOnce(&mut DispatchState) -> R) -> R {
    static mut DISPATCH: DispatchState = DispatchState::new();
    unsafe { f(&mut *core::ptr::addr_of_mut!(DISPATCH)) }
}

#[cfg(feature = "std")]
fn with_state<R>(f: impl FnOnce(&mut DispatchState) -> R) -> R {
    std::thread_local! {
        static DISPATCH: core::cell::RefCell<DispatchState> =
            const { core::cell::RefCell::new(DispatchState::new()) };
    }
    DISPATCH.with(|s| f(&mut s.borrow_mut()))
}

/// Queue a framework-owned row write into the dispatch overlay — the
/// halt path uses this for the committed-storage composite root, so
/// the row rides the same drain as the handles' own mutations.
#[cfg_attr(not(feature = "service"), allow(dead_code))]
pub(crate) fn store_raw(key: Vec<u8>, value: Vec<u8>) {
    overlay_store(key, Some(value));
}

/// Drain the dispatch's queued row mutations (key order, one per key)
/// and drop the read cache. Called by the framework when packing the
/// refine payload; the drained rows become `Write`/`Delete` effects
/// ahead of the final state write.
// Only the service message loop drains; other build flavors compile the
// storage types for their rlib surface without a dispatch cycle.
#[cfg_attr(not(feature = "service"), allow(dead_code))]
pub(crate) fn end_dispatch() -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    with_state(|s| {
        s.cache.clear();
        core::mem::take(&mut s.pending).into_iter().collect()
    })
}

/// The effective value of `key` for this dispatch: pending mutations
/// (tombstones = absent), then the read cache, then the host.
fn overlay_load(key: &[u8]) -> Option<Vec<u8>> {
    with_state(|s| {
        if let Some(pending) = s.pending.get(key) {
            return Ok(pending.clone());
        }
        if let Some(cached) = s.cache.get(key) {
            return Ok(cached.clone());
        }
        Err(())
    })
    .unwrap_or_else(|()| {
        let value = backend_read(key);
        with_state(|s| s.cache.insert(key.to_vec(), value.clone()));
        value
    })
}

/// Mutate a row's pending value in place, seeding it from the cache or
/// the host on first touch. One full copy cheaper per mutation than
/// load-modify-store — repeated index-page updates inside one dispatch
/// (bulk loads) live on this.
fn overlay_mutate<R>(key: &[u8], f: impl FnOnce(&mut Option<Vec<u8>>) -> R) -> R {
    let seeded = with_state(|s| {
        if s.pending.contains_key(key) {
            return true;
        }
        if let Some(cached) = s.cache.get(key) {
            let cached = cached.clone();
            s.pending.insert(key.to_vec(), cached);
            return true;
        }
        false
    });
    if !seeded {
        let value = backend_read(key);
        with_state(|s| s.pending.insert(key.to_vec(), value));
    }
    with_state(|s| {
        let slot = s.pending.get_mut(key).expect("seeded above");
        let out = f(slot);
        if let Some(v) = slot {
            assert!(
                v.len() <= MAX_VALUE_BYTES,
                "storage value of {} bytes exceeds MAX_VALUE_BYTES ({})",
                v.len(),
                MAX_VALUE_BYTES,
            );
        }
        out
    })
}

fn overlay_store(key: Vec<u8>, value: Option<Vec<u8>>) {
    if let Some(v) = &value {
        assert!(
            v.len() <= MAX_VALUE_BYTES,
            "storage value of {} bytes exceeds MAX_VALUE_BYTES ({}) — \
             store a content hash and put the payload in the blob store",
            v.len(),
            MAX_VALUE_BYTES,
        );
    }
    with_state(|s| {
        s.pending.insert(key, value);
    });
}

// ── Backend: STORAGE_R on the guest, a mock keyspace on std ─────────

/// Read the full row from the host: probe with a stack buffer, grow to
/// the exact size when larger (`STORAGE_R` copies `min(len, buf)` and
/// returns the full length). Present-but-empty and absent are distinct.
#[cfg(all(feature = "service", not(feature = "std")))]
fn backend_read(key: &[u8]) -> Option<Vec<u8>> {
    use crate::abi::error::HOST_NONE;
    use crate::abi::pvm::hostcalls;

    let mut probe = [0u8; super::lifecycle::BUF_SIZE];
    let n = hostcalls::read(key, &mut probe);
    if n == HOST_NONE {
        return None;
    }
    if n <= probe.len() as u64 {
        return Some(probe[..n as usize].to_vec());
    }
    assert!(
        n as usize <= MAX_VALUE_BYTES,
        "storage row is {n} bytes — over MAX_VALUE_BYTES; the keyspace \
         holds a value the storage types refuse to write",
    );
    let mut full = alloc::vec![0u8; n as usize];
    let m = hostcalls::read(key, &mut full);
    assert!(m == n, "storage row changed size mid-dispatch");
    Some(full)
}

#[cfg(all(not(feature = "service"), not(feature = "std")))]
fn backend_read(_key: &[u8]) -> Option<Vec<u8>> {
    panic!("storage types need the service runtime");
}

#[cfg(feature = "std")]
fn backend_read(key: &[u8]) -> Option<Vec<u8>> {
    mock::read(key)
}

/// Host-side stand-in for the agent keyspace, backing the storage types
/// in unit tests: seed rows, and `commit` a drained dispatch the way
/// the host applies an [`AgentDelta`](crate::commit::AgentDelta).
#[cfg(feature = "std")]
pub mod mock {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    std::thread_local! {
        static ROWS: core::cell::RefCell<BTreeMap<Vec<u8>, Vec<u8>>> =
            const { core::cell::RefCell::new(BTreeMap::new()) };
    }

    pub(super) fn read(key: &[u8]) -> Option<Vec<u8>> {
        ROWS.with(|r| r.borrow().get(key).cloned())
    }

    /// Apply a drained dispatch (the [`end_dispatch`](super::end_dispatch)
    /// result) to the mock keyspace — the host's commit, in miniature.
    pub fn commit(rows: Vec<(Vec<u8>, Option<Vec<u8>>)>) {
        ROWS.with(|r| {
            let mut r = r.borrow_mut();
            for (key, value) in rows {
                match value {
                    Some(v) => {
                        r.insert(key, v);
                    }
                    None => {
                        r.remove(&key);
                    }
                }
            }
        });
    }

    /// Wipe the keyspace AND the dispatch overlay (test isolation —
    /// both are thread-local, and the test pool reuses threads). Also
    /// models the host `ServiceStorage::clear_service` a soft restart
    /// runs before replay.
    pub fn reset() {
        ROWS.with(|r| r.borrow_mut().clear());
        super::with_state(|s| {
            s.cache.clear();
            s.pending.clear();
        });
    }

    /// Snapshot every row, for byte-identity comparisons across two
    /// materializations of the same op sequence.
    pub fn snapshot() -> BTreeMap<Vec<u8>, Vec<u8>> {
        ROWS.with(|r| r.borrow().clone())
    }
}

// ── FixedKey ─────────────────────────────────────────────────────────

/// Fixed-width byte-encodable keys. Keys order by their encoded bytes,
/// so integer impls use big-endian; the fixed width is what lets index
/// pages hold keys at a constant stride and, later, what makes keys
/// usable as SMT paths (`anchor_kind 0x02`).
pub trait FixedKey: Copy + Ord {
    const WIDTH: usize;
    fn write_to(&self, out: &mut Vec<u8>);
    fn read_from(bytes: &[u8]) -> Self;
}

impl<const N: usize> FixedKey for [u8; N] {
    const WIDTH: usize = N;
    fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
    fn read_from(bytes: &[u8]) -> Self {
        bytes[..N].try_into().expect("index page key stride")
    }
}

macro_rules! int_fixed_key {
    ($($t:ty),*) => {$(
        impl FixedKey for $t {
            const WIDTH: usize = core::mem::size_of::<$t>();
            fn write_to(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
            fn read_from(bytes: &[u8]) -> Self {
                <$t>::from_be_bytes(bytes[..Self::WIDTH].try_into().expect("key stride"))
            }
        }
    )*};
}
int_fixed_key!(u16, u32, u64);

// ── Shared handle core ───────────────────────────────────────────────

/// Row-key builder + init guard shared by every handle type.
struct Core {
    prefix: Vec<u8>,
}

impl Core {
    const fn uninit() -> Self {
        Self { prefix: Vec::new() }
    }

    fn init(&mut self, prefix: &[u8]) {
        self.prefix = prefix.to_vec();
    }

    fn row(&self, tag: u8, suffix: &[u8]) -> Vec<u8> {
        assert!(
            !self.prefix.is_empty(),
            "storage handle used before init — storage types live as \
             #[storage] fields of an #[actor] struct",
        );
        let mut key = Vec::with_capacity(self.prefix.len() + 1 + suffix.len());
        key.extend_from_slice(&self.prefix);
        key.push(tag);
        key.extend_from_slice(suffix);
        key
    }
}

fn decode_or_panic<T: Decode>(bytes: &[u8], what: &str) -> T {
    T::try_decode(bytes)
        .unwrap_or_else(|| panic!("corrupt {what} row — decode failed"))
}

/// Stamp the unit rkyv impls a handle needs to sit inside a derived
/// actor struct: it archives as `()` and deserializes to an
/// uninitialized handle, which the macro-generated `__init_storage`
/// then points at its prefix.
macro_rules! unit_archive {
    ($name:ident<$($p:ident),*>) => {
        impl<$($p),*> rkyv::Archive for $name<$($p),*> {
            type Archived = ();
            type Resolver = ();
            fn resolve(&self, _resolver: (), _out: rkyv::Place<()>) {}
        }
        impl<$($p),*, S: rkyv::rancor::Fallible + ?Sized> rkyv::Serialize<S>
            for $name<$($p),*>
        {
            fn serialize(&self, _s: &mut S) -> Result<(), S::Error> {
                Ok(())
            }
        }
        impl<$($p),*, D: rkyv::rancor::Fallible + ?Sized>
            rkyv::Deserialize<$name<$($p),*>, D> for ()
        {
            fn deserialize(&self, _d: &mut D) -> Result<$name<$($p),*>, D::Error> {
                Ok($name::default())
            }
        }
    };
}
pub(crate) use unit_archive;

// ── StorageValue ─────────────────────────────────────────────────────

/// One off-blob value row.
pub struct StorageValue<T> {
    core: Core,
    _marker: PhantomData<T>,
}

impl<T> Default for StorageValue<T> {
    fn default() -> Self {
        Self {
            core: Core::uninit(),
            _marker: PhantomData,
        }
    }
}

unit_archive!(StorageValue<T>);

impl<T: Encode + Decode> StorageValue<T> {
    #[doc(hidden)]
    pub fn __init(&mut self, prefix: &[u8]) {
        self.core.init(prefix);
    }

    fn key(&self) -> Vec<u8> {
        self.core.row(b'x', &[])
    }

    pub fn get(&self) -> Option<T> {
        overlay_load(&self.key()).map(|b| decode_or_panic(&b, "StorageValue"))
    }

    pub fn set(&mut self, value: &T) {
        overlay_store(self.key(), Some(value.encode()));
    }

    /// Remove and return the value.
    pub fn take(&mut self) -> Option<T> {
        let out = self.get();
        if out.is_some() {
            overlay_store(self.key(), None);
        }
        out
    }
}

// ── Map meta + index pages ───────────────────────────────────────────

/// Meta row = `[count: u64 LE][next_page: u32 LE][dir_len: u32 LE]`
/// then `dir_len × (first_key: WIDTH bytes ‖ page_id: u32 LE)` sorted
/// by first key; a key belongs to the last entry whose first key is
/// ≤ it (the first entry's key is an all-zeros floor sentinel).
///
/// Operated on IN PLACE in the dispatch overlay: per-mutation meta
/// work is a stride binary-search plus an 8-byte patch, never a
/// decode/re-encode — a bulk dispatch touches the meta hundreds of
/// times, and per-entry allocations there put the naive first-fit
/// guest allocator on a quadratic path.
mod meta {
    use alloc::vec::Vec;

    const HEADER: usize = 16;

    pub fn empty(width: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + width + 4);
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.resize(HEADER + width, 0);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    pub fn count(bytes: &[u8]) -> u64 {
        u64::from_le_bytes(bytes[..8].try_into().expect("meta count"))
    }

    pub fn add_count(bytes: &mut [u8], delta: i64) {
        let c = (count(bytes) as i64 + delta) as u64;
        bytes[..8].copy_from_slice(&c.to_le_bytes());
    }

    fn dir_len(bytes: &[u8]) -> usize {
        u32::from_le_bytes(bytes[12..16].try_into().expect("meta dir_len")) as usize
    }

    fn entry_key(bytes: &[u8], slot: usize, width: usize) -> &[u8] {
        let at = HEADER + slot * (width + 4);
        &bytes[at..at + width]
    }

    pub fn entry_page(bytes: &[u8], slot: usize, width: usize) -> u32 {
        let at = HEADER + slot * (width + 4) + width;
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("meta page id"))
    }

    /// Directory slot whose page holds `kb`.
    pub fn slot_for(bytes: &[u8], kb: &[u8], width: usize) -> usize {
        let mut lo = 0usize;
        let mut hi = dir_len(bytes);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if entry_key(bytes, mid, width) <= kb {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo.saturating_sub(1)
    }

    /// Allocate the next page id and splice its dir entry in after
    /// `slot` (page splits only — rare).
    pub fn split_insert(bytes: &mut Vec<u8>, slot: usize, split_key: &[u8], width: usize) -> u32 {
        let page = u32::from_le_bytes(bytes[8..12].try_into().expect("meta next_page"));
        bytes[8..12].copy_from_slice(&(page + 1).to_le_bytes());
        let new_len = dir_len(bytes) as u32 + 1;
        bytes[12..16].copy_from_slice(&new_len.to_le_bytes());
        let at = HEADER + (slot + 1) * (width + 4);
        let mut entry = Vec::with_capacity(width + 4);
        entry.extend_from_slice(split_key);
        entry.extend_from_slice(&page.to_le_bytes());
        bytes.splice(at..at, entry);
        page
    }

    /// Owned decoded directory — iterator setup only.
    pub fn dir(bytes: &[u8], width: usize) -> Vec<(Vec<u8>, u32)> {
        (0..dir_len(bytes))
            .map(|slot| {
                (
                    entry_key(bytes, slot, width).to_vec(),
                    entry_page(bytes, slot, width),
                )
            })
            .collect()
    }
}

// ── StorageMap ───────────────────────────────────────────────────────

/// Ordered map over per-entry rows: `get`/`insert`/`remove` touch one
/// value row plus (on mutation) one index page and the meta row;
/// `iter_from` walks key-only index pages and fetches values lazily.
pub struct StorageMap<K, V> {
    core: Core,
    _marker: PhantomData<(K, V)>,
}

impl<K, V> Default for StorageMap<K, V> {
    fn default() -> Self {
        Self {
            core: Core::uninit(),
            _marker: PhantomData,
        }
    }
}

unit_archive!(StorageMap<K, V>);

impl<K: FixedKey, V: Encode + Decode> StorageMap<K, V> {
    #[doc(hidden)]
    pub fn __init(&mut self, prefix: &[u8]) {
        self.core.init(prefix);
    }

    fn key_bytes(key: &K) -> Vec<u8> {
        let mut out = Vec::with_capacity(K::WIDTH);
        key.write_to(&mut out);
        out
    }

    fn value_row(&self, key_bytes: &[u8]) -> Vec<u8> {
        self.core.row(b'v', key_bytes)
    }

    fn page_row(&self, page: u32) -> Vec<u8> {
        self.core.row(b'i', &page.to_be_bytes())
    }

    fn meta_row(&self) -> Vec<u8> {
        self.core.row(b'm', &[])
    }

    /// Run `f` against the pending meta bytes in place (seeding an
    /// empty meta on first touch). Mutation paths only — reads use
    /// [`overlay_load`] so they never queue a meta write.
    fn with_meta<R>(&self, f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
        overlay_mutate(&self.meta_row(), |slot| {
            let bytes = slot.get_or_insert_with(|| meta::empty(K::WIDTH));
            f(bytes)
        })
    }

    /// The owned page directory, for iterator setup.
    fn load_dir(&self) -> Vec<(Vec<u8>, u32)> {
        match overlay_load(&self.meta_row()) {
            Some(bytes) => meta::dir(&bytes, K::WIDTH),
            None => alloc::vec![(alloc::vec![0u8; K::WIDTH], 0)],
        }
    }

    fn load_page(&self, page: u32) -> Vec<u8> {
        overlay_load(&self.page_row(page)).unwrap_or_default()
    }

    const fn max_page_keys() -> usize {
        PAGE_BYTES / K::WIDTH
    }

    pub fn get(&self, key: &K) -> Option<V> {
        overlay_load(&self.value_row(&Self::key_bytes(key)))
            .map(|b| decode_or_panic(&b, "StorageMap value"))
    }

    pub fn contains(&self, key: &K) -> bool {
        overlay_load(&self.value_row(&Self::key_bytes(key))).is_some()
    }

    pub fn len(&self) -> u64 {
        overlay_load(&self.meta_row())
            .map(|b| meta::count(&b))
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert or replace. Returns `true` when the key is new.
    ///
    /// Membership comes from the index page (already in the dispatch
    /// overlay), not a value-row probe — a bulk load's Nth insert
    /// costs zero additional host reads. The page and the value row
    /// mutate together, so "key on a page ⟺ value row exists" holds
    /// within every committed delta.
    pub fn insert(&mut self, key: &K, value: &V) -> bool {
        let kb = Self::key_bytes(key);
        let fresh = self.index_insert(&kb);
        overlay_store(self.value_row(&kb), Some(value.encode()));
        fresh
    }

    /// Remove. Returns `true` when the key was present (per the index
    /// page — see [`insert`](Self::insert) for the invariant).
    pub fn remove(&mut self, key: &K) -> bool {
        let kb = Self::key_bytes(key);
        let page_id = self.with_meta(|m| {
            let slot = meta::slot_for(m, &kb, K::WIDTH);
            meta::entry_page(m, slot, K::WIDTH)
        });
        let present = overlay_mutate(&self.page_row(page_id), |slot_value| {
            if let Some(page) = slot_value
                && let Some(at) = page_find(page, &kb, K::WIDTH)
            {
                page.drain(at..at + K::WIDTH);
                return true;
            }
            false
        });
        if !present {
            return false;
        }
        overlay_store(self.value_row(&kb), None);
        self.with_meta(|m| meta::add_count(m, -1));
        true
    }

    /// Put `kb` on its index page; returns whether it was fresh and
    /// bumps the meta count. A split (rare) moves the upper half of
    /// the page out to a fresh page and a new directory entry.
    fn index_insert(&mut self, kb: &[u8]) -> bool {
        let (slot, page_id) = self.with_meta(|m| {
            let slot = meta::slot_for(m, kb, K::WIDTH);
            (slot, meta::entry_page(m, slot, K::WIDTH))
        });
        let (fresh, split) = overlay_mutate(&self.page_row(page_id), |slot_value| {
            let page = slot_value.get_or_insert_with(Vec::new);
            let at = page_lower_bound(page, kb, K::WIDTH);
            let fresh = page.get(at..at + K::WIDTH) != Some(kb);
            if fresh {
                let old_len = page.len();
                page.resize(old_len + K::WIDTH, 0);
                page.copy_within(at..old_len, at + K::WIDTH);
                page[at..at + K::WIDTH].copy_from_slice(kb);
            }
            let split = if page.len() / K::WIDTH > Self::max_page_keys() {
                let mid = (page.len() / K::WIDTH / 2) * K::WIDTH;
                let upper = page.split_off(mid);
                let split_key = upper[..K::WIDTH].to_vec();
                Some((split_key, upper))
            } else {
                None
            };
            (fresh, split)
        });
        if let Some((split_key, upper)) = split {
            let new_page =
                self.with_meta(|m| meta::split_insert(m, slot, &split_key, K::WIDTH));
            overlay_store(self.page_row(new_page), Some(upper));
        }
        if fresh {
            self.with_meta(|m| meta::add_count(m, 1));
        }
        fresh
    }

    /// Key-ordered iteration starting at the first key ≥ `start`.
    /// Values are fetched lazily, one row per yielded entry.
    pub fn iter_from(&self, start: &K) -> StorageMapIter<'_, K, V> {
        let dir = self.load_dir();
        let kb = Self::key_bytes(start);
        let slot = dir
            .partition_point(|(first, _)| first.as_slice() <= kb.as_slice())
            .saturating_sub(1);
        let page = self.load_page(dir[slot].1);
        let off = page_lower_bound(&page, &kb, K::WIDTH);
        StorageMapIter {
            map: self,
            dir,
            slot,
            page,
            off,
        }
    }

    /// Key-ordered iteration over the whole map.
    pub fn iter(&self) -> StorageMapIter<'_, K, V> {
        let dir = self.load_dir();
        let page = self.load_page(dir[0].1);
        StorageMapIter {
            map: self,
            dir,
            slot: 0,
            page,
            off: 0,
        }
    }
}

/// Offset of `kb` in a sorted fixed-stride page, or `None`.
fn page_find(page: &[u8], kb: &[u8], width: usize) -> Option<usize> {
    let at = page_lower_bound(page, kb, width);
    (page.get(at..at + width) == Some(kb)).then_some(at)
}

/// Byte offset of the first key ≥ `kb` in a sorted fixed-stride page.
fn page_lower_bound(page: &[u8], kb: &[u8], width: usize) -> usize {
    let n = page.len() / width;
    let mut lo = 0usize;
    let mut hi = n;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if &page[mid * width..(mid + 1) * width] < kb {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo * width
}

pub struct StorageMapIter<'a, K, V> {
    map: &'a StorageMap<K, V>,
    dir: Vec<(Vec<u8>, u32)>,
    slot: usize,
    page: Vec<u8>,
    off: usize,
}

impl<K: FixedKey, V: Encode + Decode> Iterator for StorageMapIter<'_, K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<(K, V)> {
        loop {
            if self.off + K::WIDTH <= self.page.len() {
                let kb = &self.page[self.off..self.off + K::WIDTH];
                let key = K::read_from(kb);
                let value = self
                    .map
                    .get(&key)
                    .expect("index page names a key with no value row");
                self.off += K::WIDTH;
                return Some((key, value));
            }
            self.slot += 1;
            let (_, page_id) = self.dir.get(self.slot)?;
            self.page = self.map.load_page(*page_id);
            self.off = 0;
        }
    }
}

// ── StorageSet ───────────────────────────────────────────────────────

/// Ordered set: value rows carry one marker byte (presence checks never
/// decode), the index pages are the same as [`StorageMap`]'s.
pub struct StorageSet<K> {
    map: StorageMap<K, ()>,
}

impl<K> Default for StorageSet<K> {
    fn default() -> Self {
        Self {
            map: StorageMap::default(),
        }
    }
}

unit_archive!(StorageSet<K>);

impl<K: FixedKey> StorageSet<K> {
    #[doc(hidden)]
    pub fn __init(&mut self, prefix: &[u8]) {
        self.map.__init(prefix);
    }

    pub fn contains(&self, key: &K) -> bool {
        overlay_load(&self.map.value_row(&StorageMap::<K, ()>::key_bytes(key))).is_some()
    }

    /// Insert. Returns `true` when the key is new.
    pub fn insert(&mut self, key: &K) -> bool {
        let kb = StorageMap::<K, ()>::key_bytes(key);
        let fresh = self.map.index_insert(&kb);
        if fresh {
            overlay_store(self.map.value_row(&kb), Some(alloc::vec![1u8]));
        }
        fresh
    }

    /// Remove. Returns `true` when the key was present. The marker row
    /// and index bookkeeping match the map's remove exactly, and its
    /// remove never decodes values.
    pub fn remove(&mut self, key: &K) -> bool {
        self.map.remove(key)
    }

    pub fn len(&self) -> u64 {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Key-ordered iteration starting at the first key ≥ `start`.
    pub fn iter_from(&self, start: &K) -> impl Iterator<Item = K> + '_ {
        SetIter {
            inner: self.map.iter_from(start),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = K> + '_ {
        SetIter {
            inner: self.map.iter(),
        }
    }
}

/// Set iteration must not decode marker rows as `()`, so it walks the
/// same pages but skips the value fetch.
struct SetIter<'a, K> {
    inner: StorageMapIter<'a, K, ()>,
}

impl<K: FixedKey> Iterator for SetIter<'_, K> {
    type Item = K;

    fn next(&mut self) -> Option<K> {
        let it = &mut self.inner;
        loop {
            if it.off + K::WIDTH <= it.page.len() {
                let key = K::read_from(&it.page[it.off..it.off + K::WIDTH]);
                it.off += K::WIDTH;
                return Some(key);
            }
            it.slot += 1;
            let (_, page_id) = it.dir.get(it.slot)?;
            it.page = it.map.load_page(*page_id);
            it.off = 0;
        }
    }
}

// ── StorageVec ───────────────────────────────────────────────────────

/// Append-friendly dense sequence: one row per element plus a length
/// row. `push`/`get` are O(1) rows; `swap_remove` is two.
pub struct StorageVec<T> {
    core: Core,
    _marker: PhantomData<T>,
}

impl<T> Default for StorageVec<T> {
    fn default() -> Self {
        Self {
            core: Core::uninit(),
            _marker: PhantomData,
        }
    }
}

unit_archive!(StorageVec<T>);

impl<T: Encode + Decode> StorageVec<T> {
    #[doc(hidden)]
    pub fn __init(&mut self, prefix: &[u8]) {
        self.core.init(prefix);
    }

    fn len_row(&self) -> Vec<u8> {
        self.core.row(b'l', &[])
    }

    fn elem_row(&self, idx: u64) -> Vec<u8> {
        self.core.row(b'e', &idx.to_be_bytes())
    }

    pub fn len(&self) -> u64 {
        overlay_load(&self.len_row())
            .map(|b| u64::from_le_bytes(b[..8].try_into().expect("length row")))
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn set_len(&mut self, len: u64) {
        overlay_store(self.len_row(), Some(len.to_le_bytes().to_vec()));
    }

    pub fn get(&self, idx: u64) -> Option<T> {
        if idx >= self.len() {
            return None;
        }
        overlay_load(&self.elem_row(idx)).map(|b| decode_or_panic(&b, "StorageVec element"))
    }

    pub fn set(&mut self, idx: u64, value: &T) {
        assert!(idx < self.len(), "StorageVec::set out of bounds");
        overlay_store(self.elem_row(idx), Some(value.encode()));
    }

    pub fn push(&mut self, value: &T) {
        let len = self.len();
        overlay_store(self.elem_row(len), Some(value.encode()));
        self.set_len(len + 1);
    }

    /// Remove and return element `idx`, filling the hole with the last
    /// element. Position-stable collections should not use this.
    pub fn swap_remove(&mut self, idx: u64) -> Option<T> {
        let len = self.len();
        if idx >= len {
            return None;
        }
        let out = self.get(idx);
        let last = len - 1;
        if idx != last {
            let tail = overlay_load(&self.elem_row(last)).expect("dense element row");
            overlay_store(self.elem_row(idx), Some(tail));
        }
        overlay_store(self.elem_row(last), None);
        self.set_len(last);
        out
    }

    /// Index-ordered iteration; one row per yielded element.
    pub fn iter(&self) -> impl Iterator<Item = T> + '_ {
        (0..self.len()).map(move |i| self.get(i).expect("dense element row"))
    }
}

// ── Paged replies ────────────────────────────────────────────────────

/// Fill a reply page from an iterator under both a row cap and an
/// encoded-byte budget — the msg-log pattern, so list handlers stay
/// under the dispatch reply caps however large the collection grows.
/// Returns the page and whether the iterator had more (the caller
/// derives its cursor from the last row).
pub fn fill_page<T: Encode>(
    iter: &mut impl Iterator<Item = T>,
    max_rows: usize,
    byte_budget: usize,
) -> (Vec<T>, bool) {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for item in iter {
        bytes += item.encode().len();
        if !out.is_empty() && (out.len() >= max_rows || bytes > byte_budget) {
            return (out, true);
        }
        out.push(item);
        if out.len() >= max_rows || bytes > byte_budget {
            // The page is at capacity; report `more` only if another
            // item exists — peeking would drop it, so let the caller
            // treat a full page as "possibly more".
            return (out, true);
        }
    }
    (out, false)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// The overlay + mock keyspace are thread-local, and `cargo test`
    /// runs tests on a shared pool — every test isolates itself.
    fn fresh() {
        mock::reset();
        let _ = end_dispatch();
    }

    fn map() -> StorageMap<[u8; 16], u64> {
        let mut m = StorageMap::default();
        m.__init(b"s/accounts/");
        m
    }

    fn key(i: u64) -> [u8; 16] {
        let mut k = [0u8; 16];
        k[8..].copy_from_slice(&i.to_be_bytes());
        k
    }

    #[test]
    fn map_point_ops_and_read_your_writes() {
        fresh();
        let mut m = map();
        assert!(m.get(&key(1)).is_none());
        assert!(m.insert(&key(1), &10));
        assert!(!m.insert(&key(1), &11), "replace is not a fresh insert");
        assert_eq!(m.get(&key(1)), Some(11), "read-your-own-writes");
        assert_eq!(m.len(), 1);
        assert!(m.remove(&key(1)));
        assert!(!m.remove(&key(1)));
        assert!(m.get(&key(1)).is_none(), "tombstone reads as absent");
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn map_survives_commit_boundary() {
        fresh();
        let mut m = map();
        for i in 0..10 {
            m.insert(&key(i), &(i * 100));
        }
        mock::commit(end_dispatch());
        // Next dispatch: reads come from the (mock) host rows.
        let m = map();
        assert_eq!(m.len(), 10);
        assert_eq!(m.get(&key(7)), Some(700));
        let collected: Vec<_> = m.iter().map(|(_, v)| v).collect();
        assert_eq!(collected, (0..10).map(|i| i * 100).collect::<Vec<_>>());
    }

    #[test]
    fn map_page_split_keeps_order_and_reach() {
        fresh();
        let mut m = map();
        // Insert far past one page (3072/16 = 192 keys/page) in a
        // shuffled order so splits happen mid-stream.
        let n: u64 = 1000;
        for i in 0..n {
            let j = (i * 7919) % n; // co-prime walk = pseudo-shuffle
            m.insert(&key(j), &j);
        }
        mock::commit(end_dispatch());

        let m = map();
        assert_eq!(m.len(), n);
        // Every key reachable by point read and by ordered iteration.
        for i in (0..n).step_by(97) {
            assert_eq!(m.get(&key(i)), Some(i));
        }
        let keys: Vec<u64> = m.iter().map(|(_, v)| v).collect();
        assert_eq!(keys, (0..n).collect::<Vec<_>>(), "iteration is key-ordered");
        // Multiple pages actually exist.
        assert!(
            m.load_dir().len() > 2,
            "1000 keys at 192/page must have split"
        );
    }

    #[test]
    fn map_iter_from_starts_mid_range() {
        fresh();
        let mut m = map();
        for i in 0..500u64 {
            m.insert(&key(i), &i);
        }
        let tail: Vec<u64> = m.iter_from(&key(490)).map(|(_, v)| v).collect();
        assert_eq!(tail, (490..500).collect::<Vec<_>>());
        // A start key that is absent lands on the next present key.
        m.remove(&key(495));
        let tail: Vec<u64> = m.iter_from(&key(495)).map(|(_, v)| v).collect();
        assert_eq!(tail, alloc::vec![496, 497, 498, 499]);
    }

    #[test]
    fn set_and_vec_basics() {
        fresh();
        let mut s: StorageSet<[u8; 32]> = StorageSet::default();
        s.__init(b"s/received/");
        let id = [7u8; 32];
        assert!(s.insert(&id));
        assert!(!s.insert(&id), "dedup");
        assert!(s.contains(&id));
        assert_eq!(s.len(), 1);
        assert_eq!(s.iter().collect::<Vec<_>>(), alloc::vec![id]);
        assert!(s.remove(&id));
        assert!(!s.contains(&id));

        let mut v: StorageVec<u64> = StorageVec::default();
        v.__init(b"s/log/");
        v.push(&1);
        v.push(&2);
        v.push(&3);
        assert_eq!(v.len(), 3);
        assert_eq!(v.get(1), Some(2));
        assert_eq!(v.swap_remove(0), Some(1));
        assert_eq!(v.iter().collect::<Vec<_>>(), alloc::vec![3, 2]);
    }

    #[test]
    fn vec_replay_needs_a_cleared_keyspace() {
        // A CRDT soft restart rebuilds rows by re-executing the guest's
        // op log from genesis. `StorageVec::push` is positional — it reads
        // the stored length row — so replaying the same pushes onto the
        // surviving pre-merge rows appends past the stale length instead of
        // rebuilding from zero, doubling the vector. `ServiceStorage::
        // clear_service` (modelled here by `mock::reset`) wipes the
        // keyspace first so the rebuild matches a from-genesis replay
        // byte-for-byte. This is the sharpest form of the divergence:
        // unlike a `StorageMap` (whose count self-heals because inserts are
        // membership-gated), the vector's final length is wrong.
        fn replay() {
            let mut v: StorageVec<u64> = StorageVec::default();
            v.__init(b"s/log/");
            v.push(&10);
            v.push(&20);
            mock::commit(end_dispatch());
        }
        fn stored_len() -> u64 {
            let mut v: StorageVec<u64> = StorageVec::default();
            v.__init(b"s/log/");
            v.len()
        }

        // From-genesis: the true rebuild.
        fresh();
        replay();
        let canonical = mock::snapshot();
        assert_eq!(stored_len(), 2);

        // Replay onto surviving rows (no clear): length doubles.
        fresh();
        replay(); // stale materialization: l = 2
        replay(); // "soft-restart" replay onto the stale rows
        assert_eq!(stored_len(), 4, "positional push appends past stale length");

        // Clear the keyspace before replay: rebuild is byte-identical.
        fresh();
        replay(); // stale materialization
        mock::reset(); // clear_service wipes the whole keyspace
        replay(); // replay from empty
        assert_eq!(stored_len(), 2, "clear-before-replay rebuilds the true length");
        assert_eq!(
            mock::snapshot(),
            canonical,
            "cleared rebuild is byte-identical to the from-genesis materialization",
        );
    }

    #[test]
    fn value_roundtrip_and_take() {
        fresh();
        let mut c: StorageValue<u64> = StorageValue::default();
        c.__init(b"s/config/");
        assert!(c.get().is_none());
        c.set(&42);
        assert_eq!(c.get(), Some(42));
        mock::commit(end_dispatch());
        let mut c: StorageValue<u64> = StorageValue::default();
        c.__init(b"s/config/");
        assert_eq!(c.take(), Some(42));
        assert!(c.get().is_none());
    }

    #[test]
    fn drain_emits_one_effect_per_key_in_key_order() {
        fresh();
        let mut m = map();
        m.insert(&key(2), &2);
        m.insert(&key(1), &1);
        m.insert(&key(1), &10); // overwrite folds into one effect
        m.remove(&key(2)); // net: value tombstone + index rewrite
        let drained = end_dispatch();
        let keys: Vec<&[u8]> = drained.iter().map(|(k, _)| k.as_slice()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "drain is key-ordered");
        assert_eq!(
            drained.iter().filter(|(k, _)| keys.iter().filter(|k2| **k2 == k.as_slice()).count() > 1).count(),
            0,
            "one effect per touched key"
        );
        // key(2)'s value row nets out to a tombstone.
        let mut vrow = b"s/accounts/v".to_vec();
        vrow.extend_from_slice(&key(2));
        assert!(matches!(
            drained.iter().find(|(k, _)| *k == vrow),
            Some((_, None))
        ));
    }

    #[test]
    fn cache_cleared_at_dispatch_end() {
        fresh();
        let m = map();
        assert!(m.get(&key(1)).is_none()); // caches the miss
        mock::commit(alloc::vec![]);
        // Simulate an out-of-band write landing between dispatches.
        let mut m2 = map();
        m2.insert(&key(1), &5);
        mock::commit(end_dispatch());
        let m = map();
        assert_eq!(m.get(&key(1)), Some(5), "no stale miss survives a dispatch");
    }

    #[test]
    #[should_panic(expected = "storage handle used before init")]
    fn uninit_handle_panics() {
        fresh();
        let m: StorageMap<u64, u64> = StorageMap::default();
        let _ = m.get(&1);
    }

    #[test]
    #[should_panic(expected = "exceeds MAX_VALUE_BYTES")]
    fn oversized_value_panics() {
        fresh();
        let mut v: StorageValue<Vec<u8>> = StorageValue::default();
        v.__init(b"s/blob/");
        v.set(&alloc::vec![0u8; MAX_VALUE_BYTES + 1]);
    }

    #[test]
    fn fill_page_respects_row_and_byte_budgets() {
        fresh();
        let mut it = (0..100u64).map(|i| i);
        let (page, more) = fill_page(&mut it, 10, usize::MAX);
        assert_eq!(page.len(), 10);
        assert!(more);
        // Byte budget bites first: u64 encodes to 8 bytes.
        let mut it = (0..100u64).map(|i| i);
        let (page, more) = fill_page(&mut it, 1000, 40);
        assert!(page.len() <= 6, "byte budget must bound the page");
        assert!(more);
        // Exhaustion reports no more.
        let mut it = (0..3u64).map(|i| i);
        let (page, more) = fill_page(&mut it, 10, usize::MAX);
        assert_eq!(page.len(), 3);
        assert!(!more);
    }
}
