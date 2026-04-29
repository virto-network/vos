//! Hyperspace registry actor.
//!
//! Hosts a CRDT-replicated `name → RegistryEntry` directory. Every
//! node in a hyperspace runs a replica at the well-known
//! `ServiceId::REGISTRY`; cycles 1–8 converge them.
//!
//! Messages (matched by name in the manifest's `on_start` and by
//! the `registry::Client` host helper):
//!
//! - `announce(name, owner_prefix, service_id, [roles])` —
//!   register / replace an entry. Bumps the entry's `last_seen`.
//! - `heartbeat(name)` — keepalive ping; bumps `last_seen` for
//!   an existing entry. No-op when the name isn't registered.
//! - `remove(name)` — clean shutdown.
//! - `lookup(name) -> Option<RegistryEntry>` — point query;
//!   replies as rkyv-encoded bytes inside `Value::Bytes`, or
//!   `Value::Unit` when the name isn't registered.
//! - `list(prefix, after, limit) -> Page` — sorted scan of
//!   names starting with `prefix`, exclusive cursor `after`,
//!   capped at [`registry::MAX_PAGE_SIZE`]. Page includes the
//!   registry's current `clock` so callers can age-filter the
//!   returned entries.
//! - `by_role(role, prefix, after, limit) -> Page` — same
//!   pagination shape, filtered by role membership.
//!
//! ## Liveness model
//!
//! The registry never reads wall-clock time (PVM is deterministic
//! and replays); instead it maintains a monotone `tick` counter
//! that bumps on every `announce`/`heartbeat`. Each entry's
//! `last_seen` records the tick at its most recent touch, and
//! `Page::clock` snapshots the current tick. Callers compute
//! freshness by `clock - last_seen` against an age threshold of
//! their own choosing — see [`RegistryEntry::is_alive_within`].

#![no_std]

// `extern crate alloc;` and `use alloc::{format, string::String,
// vec::Vec};` are emitted by `#[messages]` further down — we
// don't need to declare them here.

// ── Wire types ─────────────────────────────────────────────────────
//
// Shared between the actor (this same crate, riscv64 build) and any
// host that drives it (vosx, tests). Living next to the actor, not
// in vos, keeps registry from being special — vos doesn't know
// about us.

/// The well-known `ServiceId` every hyperspace registry runs at.
/// Matches `vos::abi::service::ServiceId::REGISTRY`.
pub const SERVICE_ID_RAW: u32 = 0;

/// Default number of entries a `list` / `by_role` reply returns.
pub const DEFAULT_PAGE_SIZE: u32 = 64;

/// Hard cap on entries per page. With ~256-byte average per entry
/// (name + roles), this keeps reply payloads under the cycle-2
/// 1 MiB producer cap.
pub const MAX_PAGE_SIZE: u32 = 256;

/// One row in the registry.
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = vos::rkyv)]
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
    pub last_seen: u64,
}

impl RegistryEntry {
    /// Reassemble the full `ServiceId` u32 from
    /// `(owner_prefix, service_id)`.
    pub fn full_service_id(&self) -> u32 {
        ((self.owner_prefix as u32) << 16) | (self.service_id as u32)
    }

    /// Returns `true` when `clock - self.last_seen <= max_age`.
    pub fn is_alive_within(&self, clock: u64, max_age: u64) -> bool {
        clock.saturating_sub(self.last_seen) <= max_age
    }
}

/// Pagination request for `list` / `by_role`.
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[rkyv(crate = vos::rkyv)]
pub struct PageRequest {
    pub prefix: String,
    pub after: String,
    pub limit: u32,
}

impl PageRequest {
    pub fn new() -> Self { Self::default() }

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

/// One page of `list` / `by_role` results.
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = vos::rkyv)]
pub struct Page {
    pub entries: Vec<RegistryEntry>,
    /// Cursor for the next request. Empty when exhausted.
    pub next: String,
    /// Registry's tick at the moment this page was assembled.
    pub clock: u64,
}

impl Page {
    pub fn empty() -> Self {
        Self { entries: Vec::new(), next: String::new(), clock: 0 }
    }
    pub fn has_more(&self) -> bool { !self.next.is_empty() }
}

/// Encode an rkyv-serializable value as raw bytes.
pub fn encode_archived<T>(value: &T) -> Vec<u8>
where
    T: for<'a> vos::rkyv::Serialize<vos::rkyv::api::high::HighSerializer<vos::rkyv::util::AlignedVec, vos::rkyv::ser::allocator::ArenaHandle<'a>, vos::rkyv::rancor::Error>>,
{
    vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(value)
        .expect("rkyv encode")
        .to_vec()
}

/// Decode rkyv-encoded bytes back into `T`. `None` on parse error
/// or empty input.
pub fn decode_archived<T>(bytes: &[u8]) -> Option<T>
where
    T: vos::rkyv::Archive,
    T::Archived: vos::rkyv::Deserialize<T, vos::rkyv::api::high::HighDeserializer<vos::rkyv::rancor::Error>>,
{
    if bytes.is_empty() { return None; }
    let mut av = vos::rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    av.extend_from_slice(bytes);
    let archived = unsafe { vos::rkyv::access_unchecked::<T::Archived>(&av) };
    vos::rkyv::deserialize::<T, vos::rkyv::rancor::Error>(archived).ok()
}

// ── Actor ──────────────────────────────────────────────────────────
//
// `#[messages]` lives here in the lib so that, when the consumer
// enables `feature = "host"`, the macro emits the host
// `RegistryClient` struct alongside the dispatch glue. Hosts
// (vosx, tests) call `RegistryClient::at(&node, ...).announce(...)`
// — typed, no manual `Msg` wrangling. The riscv64 PVM entry
// emission also lives here and propagates from this rlib into
// `main.rs`'s bin link.

use vos::{actor, messages};

#[actor]
pub struct Registry {
    /// Sorted `(name, entry)` pairs. Kept sorted on every
    /// announce so prefix scans and pagination are simple linear
    /// walks. We use `Vec` rather than `BTreeMap::range` because
    /// LLVM's BTreeMap codegen produces PVM-unsupported
    /// instructions (e.g. `slt` with `x0` as rs1) for the
    /// riscv64em-javm target.
    entries: Vec<(String, EntryStored)>,
    /// Monotone tick counter — incremented on every `announce`
    /// and `heartbeat`. Surfaced as `Page::clock` so callers can
    /// age-filter entries.
    tick: u64,
}

/// Stored shape — like `RegistryEntry` but without the
/// redundant `name` field (the entry's tuple slot holds it).
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone)]
#[rkyv(crate = vos::rkyv)]
struct EntryStored {
    owner_prefix: u16,
    service_id: u16,
    roles: Vec<String>,
    last_seen: u64,
}

#[messages]
impl Registry {
    fn new() -> Self {
        Self { entries: Vec::new(), tick: 0 }
    }

    /// Register or replace `name`. `service_id` and
    /// `owner_prefix` arrive as u32 because the dynamic `Msg`
    /// arg system treats integers as u32/u64; we truncate the
    /// upper half here.
    #[msg]
    async fn announce(
        &mut self,
        name: String,
        owner_prefix: u32,
        service_id: u32,
        roles: Vec<String>,
    ) {
        self.tick += 1;
        let stored = EntryStored {
            owner_prefix: owner_prefix as u16,
            service_id: service_id as u16,
            roles,
            last_seen: self.tick,
        };
        let mut idx = 0usize;
        let mut found = false;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                self.entries[idx].1 = stored.clone();
                found = true;
                break;
            }
            if self.entries[idx].0.as_str() > name.as_str() {
                break;
            }
            idx += 1;
        }
        if !found {
            self.entries.insert(idx, (name, stored));
        }
    }

    /// Liveness ping. Bumps the entry's `last_seen` to the
    /// current `tick`. No-op when the name isn't registered.
    #[msg]
    async fn heartbeat(&mut self, name: String) {
        self.tick += 1;
        let mut idx = 0usize;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                self.entries[idx].1.last_seen = self.tick;
                return;
            }
            idx += 1;
        }
    }

    #[msg]
    async fn remove(&mut self, name: String) {
        let mut idx = 0usize;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                self.entries.remove(idx);
                break;
            }
            idx += 1;
        }
    }

    /// Resolve a name to its full `ServiceId` u32. Returns 0
    /// when the name isn't registered. Lighter than `lookup`
    /// for hosts that only need the address — no rkyv schema
    /// involved on the caller side.
    #[msg]
    async fn resolve(&self, name: String) -> u32 {
        let mut idx = 0usize;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                let stored = &self.entries[idx].1;
                return ((stored.owner_prefix as u32) << 16) | (stored.service_id as u32);
            }
            idx += 1;
        }
        0
    }

    /// Returns rkyv-encoded `RegistryEntry` bytes when the name
    /// is registered; returns an empty `Vec<u8>` (decoded host-
    /// side as `Ok(None)`) when it isn't.
    #[msg]
    async fn lookup(&self, name: String) -> Vec<u8> {
        let mut idx = 0usize;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                let stored = &self.entries[idx].1;
                let entry = RegistryEntry {
                    name,
                    owner_prefix: stored.owner_prefix,
                    service_id: stored.service_id,
                    roles: stored.roles.clone(),
                    last_seen: stored.last_seen,
                };
                return encode_archived(&entry);
            }
            idx += 1;
        }
        Vec::new()
    }

    /// Paginated scan. `prefix` filters by leading-slash path,
    /// `after` is an exclusive cursor (empty = start), `limit`
    /// is capped at `MAX_PAGE_SIZE`.
    #[msg]
    async fn list(&self, prefix: String, after: String, limit: u32) -> Vec<u8> {
        let page = collect_page(&self.entries, &prefix, &after, limit, &String::new(), self.tick);
        encode_archived(&page)
    }

    /// Same shape as `list`, but only entries whose `roles`
    /// contains `role`.
    #[msg]
    async fn by_role(&self, role: String, prefix: String, after: String, limit: u32) -> Vec<u8> {
        let page = collect_page(&self.entries, &prefix, &after, limit, &role, self.tick);
        encode_archived(&page)
    }
}

/// Shared pagination machinery for `list` and `by_role`.
fn collect_page(
    entries: &[(String, EntryStored)],
    prefix: &str,
    after: &str,
    limit: u32,
    role_filter: &str,
    clock: u64,
) -> Page {
    let mut limit = limit;
    if limit == 0 || limit > MAX_PAGE_SIZE {
        limit = MAX_PAGE_SIZE;
    }
    let limit = limit as usize;

    let mut out = Vec::new();
    let mut next = String::new();

    let mut idx = 0usize;
    while idx < entries.len() {
        let (name, stored) = &entries[idx];
        idx += 1;

        if !after.is_empty() && name.as_str() <= after {
            continue;
        }
        if !prefix.is_empty() && !name.starts_with(prefix) {
            if !out.is_empty() && name.as_str() > prefix {
                break;
            }
            continue;
        }
        if !role_filter.is_empty() {
            let mut has = false;
            let mut ri = 0usize;
            while ri < stored.roles.len() {
                if stored.roles[ri] == role_filter {
                    has = true;
                    break;
                }
                ri += 1;
            }
            if !has {
                continue;
            }
        }

        if out.len() >= limit {
            if let Some(last) = out.last() {
                let last: &RegistryEntry = last;
                next = last.name.clone();
            }
            break;
        }
        out.push(RegistryEntry {
            name: name.clone(),
            owner_prefix: stored.owner_prefix,
            service_id: stored.service_id,
            roles: stored.roles.clone(),
            last_seen: stored.last_seen,
        });
    }

    Page { entries: out, next, clock }
}

// ── Host helpers (`host` feature) ──────────────────────────────────
//
// `replication_id` is host policy — deriving the CRDT group from
// the hyperspace name. The typed `RegistryClient` is generated
// by `#[messages]` above (also gated on `host`); see how vosx
// and the integration tests use it.
//
// Once blake2b becomes a host ecall, `replication_id` routes
// through that and this dep drops out.

/// Derive the 32-byte CRDT replication-id for a hyperspace's
/// registry. Every node in the same hyperspace ends up in the same
/// CRDT group.
#[cfg(feature = "host")]
pub fn replication_id(hyperspace: &str) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(b"vos-registry/v1");
    h.update(&[0u8]);
    h.update(hyperspace.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

// `RegistryClient` (the typed host wrapper) is now generated by
// `#[messages]` above — one method per `#[msg]`, all returning
// `Result<HandlerReturnType, vos::actors::client::ClientError>`.
// See the macro emission in `vos-macros`.
