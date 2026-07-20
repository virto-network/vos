//! Generated typed-reference support.
//!
//! `#[messages]` emits a `{Actor}Ref` struct per actor with one
//! async method per `#[msg]`. Each method packs args into a
//! dynamic `Msg`, hands the encoded payload to an [`Invoker`],
//! and decodes the reply into the handler's declared return
//! type. The same `Ref` works from PVM actor handlers (where
//! [`Context<A>`](super::Context) is the invoker) and from host
//! code (where `&VosNode` is the invoker, gated on `std`).
//!
//! Refs hold only a [`ServiceId`](super::context::ServiceId) and
//! are cheap to construct — keep them as locals next to the call
//! site, or as fields on a long-lived host struct.

use super::context::ServiceId;
use super::value::Value;
use alloc::{string::String, vec::Vec};
use core::future::Future;

/// Error returned by every macro-generated host client method.
#[derive(Debug)]
pub enum ClientError {
    /// `VosNode::invoke` returned `None` — target not registered,
    /// timed out, or the channel disconnected.
    Unreachable,
    /// Reply payload was a `Value` variant that didn't match
    /// the handler's declared return type. Carries a debug
    /// rendering of the actual value for diagnostics.
    UnexpectedReply(String),
    /// Reply payload was the right `Value` shape but couldn't
    /// be rkyv-decoded into the user-defined return type. Most
    /// often a version skew between the actor and the consumer.
    Decode,
    /// The remote daemon's dispatch-layer auth gate refused the
    /// call (`STATUS_FORBIDDEN` envelope). The local peer lacks
    /// the role required for the targeted handler.
    Forbidden,
    /// Name resolution did not find an installed actor.
    NotFound,
    /// `Context::child` resolved an actor outside the caller's owned tree.
    NotOwnedChild,
    /// The runtime returned an attestation package whose typed method, claim
    /// wire, or statement did not match the committed reply.
    InvalidAttestation(crate::AttestationError),
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unreachable => write!(f, "client: target unreachable"),
            Self::UnexpectedReply(s) => write!(f, "client: unexpected reply: {s}"),
            Self::Decode => write!(f, "client: failed to decode reply"),
            Self::Forbidden => write!(f, "permission denied: caller lacks the required role"),
            Self::NotFound => write!(f, "client: actor name was not found"),
            Self::NotOwnedChild => write!(f, "client: actor is not an owned child"),
            Self::InvalidAttestation(error) => write!(f, "client: {error}"),
        }
    }
}

impl core::error::Error for ClientError {}

/// Send a dynamically-shaped message to a service and await its reply.
///
/// Implemented for both call sites a typed `Ref` needs to support:
///
/// - `Context<A>` — used inside an actor handler. The future genuinely
///   yields when the PVM is on the worker path; on the deterministic
///   PVM path the `INVOKE` hostcall already returned the bytes by the
///   time we poll, so the future is `Ready` on first poll.
/// - `&VosNode` (host, gated on `std`) — drives the same
///   synchronous-invoke path `vosx space call` uses. The returned future is
///   always `Ready` immediately; host callers wrap the call in
///   [`block_on`](crate::block_on) to recover a `Result<T, _>`.
///
/// `Ref` methods are generic over `<I: Invoker>` so the same typed
/// surface works in both worlds.
pub trait Invoker {
    /// Invoke `target` with the already-encoded `payload`
    /// (`[TAG_DYNAMIC] ++ rkyv(Msg)`) and return the decoded reply.
    fn invoke(
        &mut self,
        target: ServiceId,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Value, ClientError>> + '_;
}

/// Runtime result for an attested invocation. The generated client decodes
/// `value` with the ordinary method reply codec and then binds that preview to
/// `statement` before exposing an [`Attestation`](crate::Attestation).
#[derive(Debug, Clone, PartialEq)]
pub struct AttestedInvocationResult {
    pub value: Value,
    pub producer_name: String,
    pub producer: crate::v2::ProducerId,
    pub statement: crate::AttestationStatementV3,
    pub proof: Vec<u8>,
}

/// Separate transport capability for methods declared `#[msg(attested)]`.
/// Ordinary invokers cannot accidentally receive an unproved value from an
/// attested generated handle.
pub trait AttestationInvoker: Invoker {
    fn invoke_attested(
        &mut self,
        target: ServiceId,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<AttestedInvocationResult, ClientError>> + '_;
}

/// Implemented by every macro-generated `{Actor}Ref`. It binds the route-only
/// reference to an invoker and returns the generated handle whose methods no
/// longer need an extra `ctx` argument.
pub trait ActorReference: Copy {
    type Handle<'a, I: Invoker + 'a>: 'a
    where
        Self: 'a;

    fn bind<'a, I: Invoker + 'a>(target: ServiceId, invoker: &'a mut I) -> Self::Handle<'a, I>;
}

/// Generic spelling for a bound macro-generated actor handle.
pub type ActorHandle<'a, R, I> = <R as ActorReference>::Handle<'a, I>;

// `Context<A>` already exposes the right primitive — `ask_raw` returns
// an `Ask` future yielding `Result<Value, InvokeError>`. The Invoker
// shape just collapses `InvokeError` into `ClientError::Unreachable`,
// matching what the old `ActorClient` emission produced.
impl<A: super::Actor> Invoker for super::Context<A> {
    #[allow(clippy::manual_async_fn)]
    fn invoke(
        &mut self,
        target: ServiceId,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Value, ClientError>> + '_ {
        async move {
            self.ask_raw(target, &payload)
                .await
                .map_err(|_| ClientError::Unreachable)
        }
    }
}
