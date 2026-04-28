//! # registry
//!
//! Hyperspace service registry. Provides:
//!
//! - **Wire types** ([`RegistryEntry`], [`Page`], [`PageRequest`])
//!   shared between the registry actor and any host that drives it.
//!   `no_std + alloc` so the riscv64-target actor can use them.
//! - **Replication-id derivation** ([`replication_id`]) so all
//!   nodes that share a hyperspace name end up in the same CRDT
//!   replication group.
//! - **Host-side client** ([`Client`]) — std-feature-gated sugar
//!   over `VosNode::invoke` for the four registry messages.
//!
//! The registry actor lives at [`SERVICE_ID`] (== `ServiceId(0)`,
//! historically reserved as `REGISTRY`). All nodes in a hyperspace
//! run a replica there; cycle-1–8 machinery converges them.
//!
//! ## Naming
//!
//! Names are slash-separated UTF-8 strings: `kunekt/scheduler`,
//! `myapp/workers/processor`. A `BTreeMap<String, _>` in the
//! actor lets `list(prefix=Some("myapp/"), ...)` cheaply range
//! over descendants.
//!
//! ## Pagination
//!
//! `list` and `by_role` page their results to fit under the
//! cycle-2 producer cap (1 MiB per reply). Default page is 64
//! entries; hard cap is [`MAX_PAGE_SIZE`]. Caller passes the
//! previous page's `next` cursor as `after` to continue.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// The well-known `ServiceId` every hyperspace registry runs at.
/// Matches `vos::abi::service::ServiceId::REGISTRY` so existing
/// code that addresses `ServiceId(0)` ends up at the right
/// service.
pub const SERVICE_ID_RAW: u32 = 0;

/// Default number of entries a `list` / `by_role` reply returns.
pub const DEFAULT_PAGE_SIZE: u32 = 64;

/// Hard cap on entries per page. With 256-byte average per entry
/// (name + roles), this keeps reply payloads well below the
/// cycle-2 1 MiB producer cap.
pub const MAX_PAGE_SIZE: u32 = 256;

/// One row in the registry. Owned by the node that announced it.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct RegistryEntry {
    pub name: String,
    /// 16-bit prefix of the node hosting this service. Combine
    /// with `service_id` to construct the full
    /// `ServiceId::new(owner_prefix, local_id)` for routing.
    pub owner_prefix: u16,
    /// Local id (low 16 bits) on the owner node.
    pub service_id: u16,
    pub roles: Vec<String>,
    /// Logical-time tick at which the registry last observed this
    /// entry — bumped on `announce` and on every `heartbeat`.
    /// Compare against [`Page::clock`] (or another entry's
    /// `last_seen`) to gauge freshness; the registry never
    /// touches wall-clock time, so this is purely a CRDT-friendly
    /// monotone counter — see [`is_alive_within`].
    pub last_seen: u64,
}

impl RegistryEntry {
    /// Reassemble the full `ServiceId` u32 from `(owner_prefix,
    /// service_id)`. Inverse of `ServiceId::new(prefix, local)`.
    pub fn full_service_id(&self) -> u32 {
        ((self.owner_prefix as u32) << 16) | (self.service_id as u32)
    }

    /// Returns `true` when `clock - self.last_seen <= max_age`.
    /// `clock` is typically a [`Page::clock`] snapshot. Saturating
    /// math: if the entry's `last_seen` somehow exceeds `clock`,
    /// treat it as alive.
    pub fn is_alive_within(&self, clock: u64, max_age: u64) -> bool {
        clock.saturating_sub(self.last_seen) <= max_age
    }
}

/// Pagination request for `list` / `by_role`.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct PageRequest {
    /// Restrict to names starting with this string. Empty string
    /// means "no prefix filter" — list everything.
    pub prefix: String,
    /// Cursor: skip entries up to and including this name. Empty
    /// string means "start from the beginning".
    pub after: String,
    /// Max entries to return. Capped at [`MAX_PAGE_SIZE`].
    pub limit: u32,
}

impl PageRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn with_after(mut self, after: impl Into<String>) -> Self {
        self.after = after.into();
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = limit.min(MAX_PAGE_SIZE);
        self
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            after: String::new(),
            limit: DEFAULT_PAGE_SIZE,
        }
    }
}

/// One page of `list` / `by_role` results.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct Page {
    pub entries: Vec<RegistryEntry>,
    /// Cursor to pass as the next request's `after`. Empty string
    /// when this page exhausts the result set.
    pub next: String,
    /// Registry's tick at the moment this page was assembled. Use
    /// with [`RegistryEntry::is_alive_within`] to filter stale
    /// entries client-side.
    pub clock: u64,
}

impl Page {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            next: String::new(),
            clock: 0,
        }
    }

    /// `true` if more pages remain. The caller continues by
    /// passing `self.next` as the next `PageRequest::after`.
    pub fn has_more(&self) -> bool {
        !self.next.is_empty()
    }
}

/// Derive the 32-byte CRDT replication-id for a hyperspace's
/// registry. Every node that runs a registry replica with the
/// same hyperspace name auto-shares this group.
///
/// The leading domain string `"vos-registry/v1"` namespaces the
/// derivation so a future v2 schema change can roll without
/// colliding with v1 replicas.
pub fn replication_id(hyperspace: &str) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(b"vos-registry/v1");
    h.update(&[0u8]);
    h.update(hyperspace.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Encode an rkyv-serializable value as raw bytes for the
/// `Value::Bytes` payload the registry actor returns. Symmetric
/// with [`decode_archived`].
pub fn encode_archived<T>(value: &T) -> Vec<u8>
where
    T: for<'a> rkyv::Serialize<rkyv::api::high::HighSerializer<rkyv::util::AlignedVec, rkyv::ser::allocator::ArenaHandle<'a>, rkyv::rancor::Error>>,
{
    rkyv::to_bytes::<rkyv::rancor::Error>(value)
        .expect("rkyv encode")
        .to_vec()
}

/// Decode a previously-`encode_archived`d byte string back into
/// `T`. `None` if the bytes are malformed.
pub fn decode_archived<T>(bytes: &[u8]) -> Option<T>
where
    T: rkyv::Archive,
    T::Archived: rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    if bytes.is_empty() {
        return None;
    }
    // Alignment dance — see vos::actors::codec for the same pattern.
    let aligned: rkyv::util::AlignedVec<16> = if (bytes.as_ptr() as usize)
        % core::mem::align_of::<T::Archived>() != 0
    {
        let mut av = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
        av.extend_from_slice(bytes);
        av
    } else {
        // Already aligned: still copy — keeps lifetime simple and
        // the cost is bounded (entries are small).
        let mut av = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
        av.extend_from_slice(bytes);
        av
    };
    let archived = unsafe { rkyv::access_unchecked::<T::Archived>(&aligned) };
    rkyv::deserialize::<T, rkyv::rancor::Error>(archived).ok()
}

// Host-side client lives in the separate `registry-client`
// crate to avoid a vos → registry → vos build cycle.
