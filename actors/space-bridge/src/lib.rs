//! Space bridge — the per-space cross-space gateway agent.
//!
//! Each member space of a hyperspace runs ONE bridge agent. Peer
//! spaces address the bridge by name through the hyperspace
//! registry; the bridge dispatches incoming `forward` calls to a
//! locally-resolvable target.
//!
//! ## Topology
//!
//! ```text
//!   Actor in space A  ──>  bridge-A  ──[hyperspace transport]──>  bridge-B  ──>  actor in space B
//! ```
//!
//! Routing falls out of existing libp2p infrastructure: bridge-B's
//! ServiceId is published in the hyperspace registry's host_mappings,
//! so any actor in space-A can `ctx.resolve("bridge-b")` and ask it
//! directly. The cross-space hop is just an envelope ride between
//! two normal agents.
//!
//! ## What the bridge IS (v1)
//!
//! - **An ergonomic convention for cross-space addressing.** Peer
//!   spaces target a single well-known name per space ("bridge-X")
//!   instead of memorizing every internal agent's ServiceId.
//! - **A future enforcement point.** When admission lands, this is
//!   where it goes — signature verification against the hyperspace
//!   registry's known-bridge pubkey set, rate limiting, audit
//!   logging.
//! - **A diagnostic surface.** `where_am_i` lets the cross-space
//!   smoke test confirm an envelope reached the intended peer-space
//!   bridge instead of looping back locally.
//!
//! ## What the bridge IS NOT (v1) — read carefully
//!
//! - **NOT a security boundary.** v1 has no admission, no origin
//!   signature, no allow-listing. Any peer space that knows an
//!   internal agent's ServiceId can address it directly (e.g., by
//!   poisoning the hyperspace registry's host_mappings — see the
//!   register_remote trust gap). The bridge is convention, not
//!   enforcement. Do not deploy across untrusted operators until
//!   admission lands.
//! - **NOT a privacy boundary either.** Cross-space envelopes
//!   transit libp2p unencrypted at the VOS layer (the payload may
//!   be encrypted at the application layer — e.g. cipher-clerk's
//!   sealed vouchers — but the addressing metadata is in the clear).
//! - **NOT a rate limiter or batcher.** Each `forward` is a
//!   synchronous local invoke. Production deployments layer those
//!   on top.

use vos::prelude::*;

/// `forward` succeeded; payload is the target's reply bytes
/// (possibly empty).
pub const FORWARD_OK: u8 = 0;
/// `target_name` did not resolve to a known agent. Payload empty.
pub const FORWARD_NOT_FOUND: u8 = 1;
/// `target_name` resolved to the bridge itself — refusing to
/// recurse. Payload empty.
pub const FORWARD_SELF_TARGET: u8 = 2;
/// The target resolved but the invoke failed (timeout, panic,
/// NotFound at the kernel level, etc.). Payload empty.
pub const FORWARD_INVOKE_FAILED: u8 = 3;

/// Result envelope for `SpaceBridge::forward`. Distinguishes
/// success-with-empty-bytes from any of three error conditions
/// the previous bare-`Vec<u8>` return collapsed indistinguishably.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ForwardReply {
    /// One of `FORWARD_OK` / `FORWARD_NOT_FOUND` /
    /// `FORWARD_SELF_TARGET` / `FORWARD_INVOKE_FAILED`.
    pub status: u8,
    /// Target's reply bytes when `status == FORWARD_OK`. The
    /// payload encodes the target's `Value` return — callers
    /// `vos::Decode::decode` it against the type they expect.
    /// Empty for every non-OK status.
    pub payload: Vec<u8>,
}

#[actor]
pub struct SpaceBridge;

#[messages]
impl SpaceBridge {
    fn new() -> Self {
        SpaceBridge
    }

    /// Return this bridge's own `ServiceId` packed as u32.
    /// Diagnostic — the cross-space smoke test asks for this
    /// through a libp2p hop to confirm the envelope reached the
    /// intended peer-space bridge instead of looping back locally.
    #[msg]
    async fn where_am_i(&self, ctx: &mut Context<Self>) -> u32 {
        ctx.id().0
    }

    /// Dispatch `payload` to a locally-addressable agent and
    /// return its reply.
    ///
    /// `target_name` is run through `ctx.resolve`, which checks
    /// the bridge's local registry first then falls through to
    /// the hyperspace registry (per [`vos::actors::Context::resolve`]).
    /// In practice that means the bridge can forward to:
    ///
    /// - Agents installed in its own space's local registry
    ///   (typical bank-internal targets — clerk-ledger,
    ///   clerk-voucher, etc.)
    /// - Agents advertised in the hyperspace registry's
    ///   host_mappings, which CAN point at peers across the
    ///   federation. This is a deliberate flexibility (lets a
    ///   bridge act as a transparent relay) but it also means
    ///   forwarding to a name registered to a peer space WILL
    ///   route there — not "local only" despite the bridge's
    ///   role-name.
    ///
    /// Return shape — see [`ForwardReply`]:
    /// - `FORWARD_OK`: target replied. `payload` is the rkyv-
    ///   encoded `Value` the handler returned.
    /// - `FORWARD_NOT_FOUND`: resolve returned 0.
    /// - `FORWARD_SELF_TARGET`: resolve pointed at the bridge
    ///   itself — refusing to recurse.
    /// - `FORWARD_INVOKE_FAILED`: kernel-level invoke error.
    ///
    /// v1 has no admission control on this handler — see the
    /// crate-level doc for the trust caveats.
    #[msg]
    async fn forward(
        &self,
        ctx: &mut Context<Self>,
        target_name: String,
        payload: Vec<u8>,
    ) -> ForwardReply {
        let target_id = ctx.resolve(target_name).await;
        if target_id == 0 {
            return ForwardReply {
                status: FORWARD_NOT_FOUND,
                payload: alloc::vec::Vec::new(),
            };
        }
        if target_id == ctx.id().0 {
            // Resolve pointed at us — refuse to forward to self
            // rather than recurse and rely on chain detection.
            return ForwardReply {
                status: FORWARD_SELF_TARGET,
                payload: alloc::vec::Vec::new(),
            };
        }
        match ctx
            .ask_raw(vos::abi::service::ServiceId(target_id), &payload)
            .await
        {
            Ok(reply) => ForwardReply {
                status: FORWARD_OK,
                payload: vos::Encode::encode(&reply),
            },
            Err(_) => ForwardReply {
                status: FORWARD_INVOKE_FAILED,
                payload: alloc::vec::Vec::new(),
            },
        }
    }
}
