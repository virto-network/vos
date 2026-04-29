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

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

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
// The `#[actor]` + `#[messages]` blocks live in `main.rs`, not
// here. The `#[messages]` macro emits PVM entry symbols
// (`_start`, `accumulate`) gated on `target_arch = "riscv64"`;
// keeping that emission out of the lib means another actor
// crate can take a regular path-dep on `registry` (for the
// types and `Client`) without colliding on `_start` at link
// time.

// ── Host helpers (`host` feature) ──────────────────────────────────
//
// `replication_id` and `Client` are host concerns: deriving the CRDT
// group, invoking the actor over the local node's invoke routes.
// Gated on the `host` feature — driver-side code, not std-side.
// The riscv64 actor build leaves `host` off and pulls neither
// blake2b_simd nor `vos::node::*`. Once blake2b becomes a host
// ecall, `replication_id` will route through that and this dep
// drops out.

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

/// Typed host wrapper over `VosNode::invoke` for the registry's
/// six messages. Ordinary actor — uses the regular invoke plumbing,
/// no special infra.
#[cfg(feature = "host")]
pub struct Client<'a> {
    node: &'a vos::node::VosNode,
    target: vos::abi::service::ServiceId,
}

#[cfg(feature = "host")]
impl<'a> Client<'a> {
    /// Bind to the local node's own registry replica at the
    /// well-known [`SERVICE_ID_RAW`].
    pub fn local(node: &'a vos::node::VosNode) -> Self {
        Self::at(node, vos::abi::service::ServiceId(SERVICE_ID_RAW))
    }

    /// Bind to a registry replica at an explicit `ServiceId`.
    pub fn at(node: &'a vos::node::VosNode, target: vos::abi::service::ServiceId) -> Self {
        Self { node, target }
    }

    pub fn announce(
        &self,
        name: &str,
        owner_prefix: u16,
        service_id: u16,
        roles: &[String],
    ) -> Result<(), ClientError> {
        let m = vos::value::Msg::new("announce")
            .with("name", name)
            .with("owner_prefix", owner_prefix as u32)
            .with("service_id", service_id as u32)
            .with("roles", roles.to_vec());
        self.invoke(m).map(|_| ())
    }

    pub fn heartbeat(&self, name: &str) -> Result<(), ClientError> {
        self.invoke(vos::value::Msg::new("heartbeat").with("name", name))
            .map(|_| ())
    }

    pub fn remove(&self, name: &str) -> Result<(), ClientError> {
        self.invoke(vos::value::Msg::new("remove").with("name", name))
            .map(|_| ())
    }

    pub fn lookup(&self, name: &str) -> Result<Option<RegistryEntry>, ClientError> {
        let bytes = self.invoke(vos::value::Msg::new("lookup").with("name", name))?;
        let value: vos::value::Value = vos::Decode::decode(&bytes);
        let payload = match value {
            vos::value::Value::Bytes(b) => b,
            vos::value::Value::Unit => return Ok(None),
            other => return Err(ClientError::UnexpectedReply(format!("{other:?}"))),
        };
        if payload.is_empty() {
            return Ok(None);
        }
        decode_archived::<RegistryEntry>(&payload)
            .map(Some)
            .ok_or(ClientError::Decode)
    }

    pub fn by_role(&self, role: &str, request: PageRequest) -> Result<Page, ClientError> {
        let bytes = self.invoke(
            vos::value::Msg::new("by_role")
                .with("role", role)
                .with("prefix", request.prefix.clone())
                .with("after", request.after.clone())
                .with("limit", request.limit.min(MAX_PAGE_SIZE)),
        )?;
        decode_page(&bytes)
    }

    pub fn list(&self, request: PageRequest) -> Result<Page, ClientError> {
        let bytes = self.invoke(
            vos::value::Msg::new("list")
                .with("prefix", request.prefix.clone())
                .with("after", request.after.clone())
                .with("limit", request.limit.min(MAX_PAGE_SIZE)),
        )?;
        decode_page(&bytes)
    }

    pub fn list_all(&self, prefix: &str) -> Result<Vec<RegistryEntry>, ClientError> {
        let mut out = Vec::new();
        let mut after = String::new();
        loop {
            let req = PageRequest::new().with_prefix(prefix).with_after(after);
            let page = self.list(req)?;
            let next = page.next.clone();
            out.extend(page.entries);
            if next.is_empty() { break; }
            after = next;
        }
        Ok(out)
    }

    fn invoke(&self, msg: vos::value::Msg) -> Result<Vec<u8>, ClientError> {
        let encoded = vos::Encode::encode(&msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(vos::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        self.node.invoke(self.target, payload).ok_or(ClientError::Unreachable)
    }
}

#[cfg(feature = "host")]
fn decode_page(bytes: &[u8]) -> Result<Page, ClientError> {
    let value: vos::value::Value = vos::Decode::decode(bytes);
    let payload = match value {
        vos::value::Value::Bytes(b) => b,
        vos::value::Value::Unit => return Ok(Page::empty()),
        other => return Err(ClientError::UnexpectedReply(format!("{other:?}"))),
    };
    if payload.is_empty() {
        return Ok(Page::empty());
    }
    decode_archived::<Page>(&payload).ok_or(ClientError::Decode)
}

#[cfg(feature = "host")]
#[derive(Debug)]
pub enum ClientError {
    Unreachable,
    Decode,
    UnexpectedReply(String),
}

#[cfg(feature = "host")]
impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unreachable => write!(f, "registry: target unreachable"),
            Self::Decode => write!(f, "registry: failed to decode reply"),
            Self::UnexpectedReply(s) => write!(f, "registry: unexpected reply: {s}"),
        }
    }
}

#[cfg(feature = "host")]
impl core::error::Error for ClientError {}
