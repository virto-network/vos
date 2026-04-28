//! Host-side client for the registry actor.
//!
//! Wraps `VosNode::invoke` calls to `ServiceId::REGISTRY` with
//! typed inputs and rkyv-decoded outputs. Both the local node's
//! own replica and any cross-node replica answer through the
//! same `Frame::InvokeRequest` / `Frame::InvokeReply` pair, so
//! a [`Client`] backed by a `VosNode` works whether the registry
//! it talks to lives locally or across the wire.
//!
//! Lives in a separate crate from `registry` so `vos` can depend
//! on `registry` (for the no_std wire types and the
//! `replication_id` derivation) without forming a cycle. Vosx
//! itself inlines the announce-encoding for the same reason.

pub use registry::{Page, PageRequest, RegistryEntry, MAX_PAGE_SIZE, DEFAULT_PAGE_SIZE};
use registry::decode_archived;

use vos::abi::service::ServiceId;
use vos::node::VosNode;
use vos::value::{Msg, TAG_DYNAMIC};
use vos::Encode;

/// Sugar over `VosNode::invoke` for the four registry messages.
pub struct Client<'a> {
    node: &'a VosNode,
    target: ServiceId,
}

impl<'a> Client<'a> {
    /// Bind to the local node's own registry replica at the
    /// well-known [`registry::SERVICE_ID_RAW`].
    pub fn local(node: &'a VosNode) -> Self {
        Self {
            node,
            target: ServiceId(registry::SERVICE_ID_RAW),
        }
    }

    /// Bind to a registry replica at an explicit `ServiceId`.
    /// Useful for tests / inspection that install the actor
    /// somewhere other than the well-known slot.
    pub fn at(node: &'a VosNode, target: ServiceId) -> Self {
        Self { node, target }
    }

    /// Announce a service. Idempotent — re-announcing replaces
    /// the existing entry.
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
        let m = Msg::new("announce")
            .with("name", name)
            .with("owner_prefix", owner_prefix as u32)
            .with("service_id", service_id as u32)
            .with("roles", roles.to_vec());
        self.invoke(m).map(|_| ())
    }

    /// Remove a service entry. No-op if the name isn't registered.
    pub fn remove(&self, name: &str) -> Result<(), ClientError> {
        self.invoke(Msg::new("remove").with("name", name))
            .map(|_| ())
    }

    /// Look up a single name. `Ok(None)` when the name isn't
    /// registered.
    pub fn lookup(&self, name: &str) -> Result<Option<RegistryEntry>, ClientError> {
        let bytes = self.invoke(Msg::new("lookup").with("name", name))?;
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

    /// Find every entry that advertises `role`. Paginates the
    /// same way [`list`](Self::list) does.
    pub fn by_role(&self, role: &str, request: PageRequest) -> Result<Page, ClientError> {
        let bytes = self.invoke(
            Msg::new("by_role")
                .with("role", role)
                .with("prefix", request.prefix.clone())
                .with("after", request.after.clone())
                .with("limit", request.limit.min(registry::MAX_PAGE_SIZE)),
        )?;
        decode_page(&bytes)
    }

    /// List entries (optionally restricted to a slash-prefix).
    pub fn list(&self, request: PageRequest) -> Result<Page, ClientError> {
        let bytes = self.invoke(
            Msg::new("list")
                .with("prefix", request.prefix.clone())
                .with("after", request.after.clone())
                .with("limit", request.limit.min(registry::MAX_PAGE_SIZE)),
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

    fn invoke(&self, msg: Msg) -> Result<Vec<u8>, ClientError> {
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        self.node
            .invoke(self.target, payload)
            .ok_or(ClientError::Unreachable)
    }
}

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

/// Error returned by [`Client`] methods.
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

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable => write!(f, "registry: target unreachable"),
            Self::Decode => write!(f, "registry: failed to decode reply"),
            Self::UnexpectedReply(s) => write!(f, "registry: unexpected reply: {s}"),
        }
    }
}

impl std::error::Error for ClientError {}
