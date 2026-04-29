//! Hyperspace service registry — wire types and host client.
//!
//! This module is the single source of truth for the registry
//! protocol. Both sides import from here:
//!
//! - The PVM actor at `crates/actors/registry` uses the wire
//!   types ([`RegistryEntry`], [`Page`], [`PageRequest`]) and the
//!   `encode_archived` helper.
//! - Hosts driving the registry call into the std-only [`Client`]
//!   at the bottom of the module — same shape as the actor's
//!   message handlers, just a typed wrapper over
//!   `VosNode::invoke`.
//!
//! Living inside `vos` (rather than as a separate crate beside
//! the actor) sidesteps the historical `vos → registry → vos`
//! cycle: the actor depends on `vos` for the framework, vos owns
//! the wire types, and the std-gated `Client` is just another
//! host helper.
//!
//! ## Naming
//!
//! Names are slash-separated UTF-8 strings: `kunekt/scheduler`,
//! `myapp/workers/processor`. The actor keeps entries sorted so
//! `list(prefix=…)` is a linear scan over the prefix range.
//!
//! ## Pagination
//!
//! `list` and `by_role` page their replies to fit under the
//! cycle-2 producer cap (1 MiB). Default page is
//! [`DEFAULT_PAGE_SIZE`]; hard cap is [`MAX_PAGE_SIZE`]. Caller
//! passes the previous page's `next` cursor as `after` to
//! continue.

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
    /// monotone counter — see [`RegistryEntry::is_alive_within`].
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
    let mut av = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
    av.extend_from_slice(bytes);
    let archived = unsafe { rkyv::access_unchecked::<T::Archived>(&av) };
    rkyv::deserialize::<T, rkyv::rancor::Error>(archived).ok()
}

// ── Host-side helpers (std-only) ───────────────────────────────────

/// Derive the 32-byte CRDT replication-id for a hyperspace's
/// registry. Every node that runs a registry replica with the
/// same hyperspace name auto-shares this group.
///
/// The leading domain string `"vos-registry/v1"` namespaces the
/// derivation so a future v2 schema change can roll without
/// colliding with v1 replicas.
#[cfg(feature = "std")]
pub fn replication_id(hyperspace: &str) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(b"vos-registry/v1");
    h.update(&[0u8]);
    h.update(hyperspace.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Typed host wrapper over `VosNode::invoke` for the registry
/// actor's six messages. Lets host-side code (tests, vosx
/// commands, integration scripts) drive a local or remote
/// registry replica without inlining the wire encoding each
/// time.
#[cfg(feature = "std")]
pub struct Client<'a> {
    node: &'a crate::node::VosNode,
    target: crate::abi::service::ServiceId,
}

#[cfg(feature = "std")]
impl<'a> Client<'a> {
    /// Bind to the local node's own registry replica at the
    /// well-known [`SERVICE_ID_RAW`].
    pub fn local(node: &'a crate::node::VosNode) -> Self {
        Self {
            node,
            target: crate::abi::service::ServiceId(SERVICE_ID_RAW),
        }
    }

    /// Bind to a registry replica at an explicit `ServiceId`.
    /// Useful for tests that install the actor somewhere other
    /// than the well-known slot.
    pub fn at(node: &'a crate::node::VosNode, target: crate::abi::service::ServiceId) -> Self {
        Self { node, target }
    }

    /// Announce a service. Idempotent — re-announcing replaces
    /// the existing entry and bumps `last_seen`.
    pub fn announce(
        &self,
        name: &str,
        owner_prefix: u16,
        service_id: u16,
        roles: &[String],
    ) -> Result<(), ClientError> {
        // Always pass `roles` (even empty) — the actor's
        // `#[messages]`-generated `from_dynamic` requires the
        // field to be present or it silently skips the dispatch.
        let m = crate::value::Msg::new("announce")
            .with("name", name)
            .with("owner_prefix", owner_prefix as u32)
            .with("service_id", service_id as u32)
            .with("roles", roles.to_vec());
        self.invoke(m).map(|_| ())
    }

    /// Liveness ping. Bumps the entry's `last_seen` so the
    /// registry's tick — and the entry's freshness — advances.
    /// No-op when the name isn't registered.
    pub fn heartbeat(&self, name: &str) -> Result<(), ClientError> {
        self.invoke(crate::value::Msg::new("heartbeat").with("name", name))
            .map(|_| ())
    }

    /// Remove a service entry. No-op if the name isn't registered.
    pub fn remove(&self, name: &str) -> Result<(), ClientError> {
        self.invoke(crate::value::Msg::new("remove").with("name", name))
            .map(|_| ())
    }

    /// Look up a single name. `Ok(None)` when the name isn't
    /// registered.
    pub fn lookup(&self, name: &str) -> Result<Option<RegistryEntry>, ClientError> {
        let bytes = self.invoke(crate::value::Msg::new("lookup").with("name", name))?;
        let value: crate::value::Value = crate::Decode::decode(&bytes);
        let payload = match value {
            crate::value::Value::Bytes(b) => b,
            crate::value::Value::Unit => return Ok(None),
            other => return Err(ClientError::UnexpectedReply(format!("{other:?}"))),
        };
        if payload.is_empty() {
            return Ok(None);
        }
        decode_archived::<RegistryEntry>(&payload)
            .map(Some)
            .ok_or(ClientError::Decode)
    }

    /// Find every entry that advertises `role`. Paginates the
    /// same way [`list`](Self::list) does.
    pub fn by_role(&self, role: &str, request: PageRequest) -> Result<Page, ClientError> {
        let bytes = self.invoke(
            crate::value::Msg::new("by_role")
                .with("role", role)
                .with("prefix", request.prefix.clone())
                .with("after", request.after.clone())
                .with("limit", request.limit.min(MAX_PAGE_SIZE)),
        )?;
        decode_page(&bytes)
    }

    /// List entries (optionally restricted to a slash-prefix).
    pub fn list(&self, request: PageRequest) -> Result<Page, ClientError> {
        let bytes = self.invoke(
            crate::value::Msg::new("list")
                .with("prefix", request.prefix.clone())
                .with("after", request.after.clone())
                .with("limit", request.limit.min(MAX_PAGE_SIZE)),
        )?;
        decode_page(&bytes)
    }

    /// Iterator-style `list` that walks every page until the
    /// cursor empties. Convenient for small registries; large
    /// ones should call [`list`](Self::list) directly to bound
    /// memory.
    pub fn list_all(&self, prefix: &str) -> Result<Vec<RegistryEntry>, ClientError> {
        let mut out = Vec::new();
        let mut after = String::new();
        loop {
            let req = PageRequest::new().with_prefix(prefix).with_after(after);
            let page = self.list(req)?;
            let next = page.next.clone();
            out.extend(page.entries);
            if next.is_empty() {
                break;
            }
            after = next;
        }
        Ok(out)
    }

    fn invoke(&self, msg: crate::value::Msg) -> Result<Vec<u8>, ClientError> {
        let encoded = crate::Encode::encode(&msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        self.node
            .invoke(self.target, payload)
            .ok_or(ClientError::Unreachable)
    }
}

#[cfg(feature = "std")]
fn decode_page(bytes: &[u8]) -> Result<Page, ClientError> {
    let value: crate::value::Value = crate::Decode::decode(bytes);
    let payload = match value {
        crate::value::Value::Bytes(b) => b,
        crate::value::Value::Unit => return Ok(Page::empty()),
        other => return Err(ClientError::UnexpectedReply(format!("{other:?}"))),
    };
    if payload.is_empty() {
        return Ok(Page::empty());
    }
    decode_archived::<Page>(&payload).ok_or(ClientError::Decode)
}

/// Error returned by [`Client`] methods.
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum ClientError {
    /// Invoke timed out / target not registered / channel
    /// disconnected. Treat as transient at first; surfaces as
    /// `None` from `VosNode::invoke`.
    Unreachable,
    /// Reply payload couldn't be rkyv-decoded into the expected
    /// shape — usually a version skew between the actor and
    /// this crate.
    Decode,
    /// Reply was a `Value` variant we didn't expect.
    UnexpectedReply(String),
}

#[cfg(feature = "std")]
impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable => write!(f, "registry: target unreachable"),
            Self::Decode => write!(f, "registry: failed to decode reply"),
            Self::UnexpectedReply(s) => write!(f, "registry: unexpected reply: {s}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ClientError {}
