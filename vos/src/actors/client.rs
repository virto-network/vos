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
//! Application code normally receives a bound handle from
//! [`Context::actor`](super::Context::actor) or
//! [`Context::child`](super::Context::child). Those handles carry the full
//! [`ActorId`](crate::v2::ActorId) used by the v2 scheduler. Raw refs retain a
//! route-only [`ServiceId`](super::context::ServiceId) constructor solely as
//! an advanced adapter for legacy hosts.

use super::context::ServiceId;
use super::value::Value;
use alloc::{string::String, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

/// Deterministic failure returned by an actor execution or scheduler call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    Panicked,
    Cycle,
    OutOfGas,
    ReplyTooBig,
    Unknown(u8),
}

impl core::fmt::Display for CallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Panicked => f.write_str("target actor panicked"),
            Self::Cycle => f.write_str("causal actor-call cycle"),
            Self::OutOfGas => f.write_str("target actor ran out of gas"),
            Self::ReplyTooBig => f.write_str("actor reply exceeds the caller buffer"),
            Self::Unknown(status) => write!(f, "unknown actor-call status 0x{status:02x}"),
        }
    }
}

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
    /// The target or scheduler returned a deterministic execution failure.
    Call(CallError),
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
            Self::Call(error) => write!(f, "client: {error}"),
        }
    }
}

impl core::error::Error for ClientError {}

impl From<super::value::InvokeError> for ClientError {
    fn from(error: super::value::InvokeError) -> Self {
        match error {
            super::value::InvokeError::NotFound => Self::NotFound,
            super::value::InvokeError::Panicked => Self::Call(CallError::Panicked),
            super::value::InvokeError::Cycle => Self::Call(CallError::Cycle),
            super::value::InvokeError::OutOfGas => Self::Call(CallError::OutOfGas),
            super::value::InvokeError::TooBig => Self::Call(CallError::ReplyTooBig),
            super::value::InvokeError::Unknown(status) => Self::Call(CallError::Unknown(status)),
        }
    }
}

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

    /// Invoke a canonical v2 actor identity. Host-only legacy invokers do not
    /// acquire an implicit ActorId-to-ServiceId mapping; they must override
    /// this method or report the target as unreachable.
    fn invoke_actor(
        &mut self,
        _target: crate::v2::ActorId,
        _payload: Vec<u8>,
    ) -> impl Future<Output = Result<Value, ClientError>> + '_ {
        core::future::ready(Err(ClientError::Unreachable))
    }
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

/// One exact attested-await result. The pending form exists only in the
/// transition-finalization fork; JAR restores the machine before this future
/// is reconstructed with the committed package.
#[doc(hidden)]
pub struct AttestedAsk {
    result: Option<Result<AttestedInvocationResult, ClientError>>,
}

impl AttestedAsk {
    pub(crate) fn ready(result: Result<AttestedInvocationResult, ClientError>) -> Self {
        Self {
            result: Some(result),
        }
    }

    #[cfg(feature = "pvm")]
    pub(crate) fn checkpoint_pending() -> Self {
        Self { result: None }
    }
}

impl Future for AttestedAsk {
    type Output = Result<AttestedInvocationResult, ClientError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        self.result.take().map_or(Poll::Pending, Poll::Ready)
    }
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

    /// Attested counterpart of [`Invoker::invoke_actor`]. The default rejects
    /// the call so an adapter cannot accidentally return an unproved legacy
    /// value for a canonical actor identity.
    fn invoke_actor_attested(
        &mut self,
        _target: crate::v2::ActorId,
        _payload: Vec<u8>,
    ) -> impl Future<Output = Result<AttestedInvocationResult, ClientError>> + '_ {
        core::future::ready(Err(ClientError::Unreachable))
    }
}

/// Identity carried by a generated bound handle.
///
/// `Actor` is the application-facing v2 form. `Service` exists only so the
/// legacy host/runtime adapter can keep driving raw service routes during the
/// clean-break rollout; it is intentionally absent from the application
/// prelude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ActorTarget {
    Actor(crate::v2::ActorId),
    Service(ServiceId),
}

/// Implemented by every macro-generated `{Actor}Ref`. It binds a canonical
/// actor identity to an invoker and returns a handle whose methods need no
/// extra `ctx` argument.
pub trait ActorReference: Copy {
    type Handle<'a, I: Invoker + 'a>: 'a
    where
        Self: 'a;

    fn bind<'a, I: Invoker + 'a>(
        target: crate::v2::ActorId,
        invoker: &'a mut I,
    ) -> Self::Handle<'a, I>;

    /// Advanced legacy-host adapter. Application code should resolve actors
    /// through `Context` and receive an ActorId-bound handle instead.
    #[doc(hidden)]
    fn bind_service<'a, I: Invoker + 'a>(
        target: ServiceId,
        invoker: &'a mut I,
    ) -> Self::Handle<'a, I>;
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
                .map_err(ClientError::from)
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn invoke_actor(
        &mut self,
        target: crate::v2::ActorId,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Value, ClientError>> + '_ {
        async move {
            self.ask_actor_raw(target, &payload, None)
                .await
                .map_err(ClientError::from)
        }
    }
}

impl<A: super::Actor> AttestationInvoker for super::Context<A> {
    fn invoke_attested(
        &mut self,
        _target: ServiceId,
        _payload: Vec<u8>,
    ) -> impl Future<Output = Result<AttestedInvocationResult, ClientError>> + '_ {
        AttestedAsk::ready(Err(ClientError::Unreachable))
    }

    fn invoke_actor_attested(
        &mut self,
        target: crate::v2::ActorId,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<AttestedInvocationResult, ClientError>> + '_ {
        self.ask_actor_attested_raw(target, &payload, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causal_cycles_remain_typed_at_the_generated_handle_boundary() {
        assert!(matches!(
            ClientError::from(super::super::value::InvokeError::Cycle),
            ClientError::Call(CallError::Cycle)
        ));
    }
}
