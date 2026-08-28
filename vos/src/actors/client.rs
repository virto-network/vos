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
//! Application code receives a bound handle from
//! [`Context::actor`](super::Context::actor) or
//! [`Context::child`](super::Context::child). Those handles carry the full
//! [`ActorId`](crate::service::ActorId) used by the service scheduler.

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
    Timeout,
    OutOfGas,
    ReplyTooBig,
    Unknown(u8),
}

impl core::fmt::Display for CallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Panicked => f.write_str("target actor panicked"),
            Self::Cycle => f.write_str("causal actor-call cycle"),
            Self::Timeout => f.write_str("actor-call logical-timeslot deadline expired"),
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
    /// often an interface mismatch between the actor and the consumer.
    Decode,
    /// The remote daemon's dispatch-layer auth gate refused the
    /// call (`STATUS_FORBIDDEN` envelope). The local peer lacks
    /// the role required for the targeted handler.
    Forbidden,
    /// Name resolution did not find an installed actor.
    NotFound,
    /// `Context::child` resolved an actor outside the caller's owned tree.
    NotOwnedChild,
    /// The requested child cannot be staged in the current service actor slice.
    SpawnUnavailable,
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
            Self::SpawnUnavailable => write!(
                f,
                "client: child creation is unavailable for this actor slice"
            ),
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
            super::value::InvokeError::Forbidden => Self::Forbidden,
            super::value::InvokeError::Panicked => Self::Call(CallError::Panicked),
            super::value::InvokeError::Cycle => Self::Call(CallError::Cycle),
            super::value::InvokeError::Timeout => Self::Call(CallError::Timeout),
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
    /// Invoke a canonical actor identity with an encoded dynamic message.
    fn invoke_actor(
        &mut self,
        target: crate::service::ActorId,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Value, ClientError>> + '_;
}

/// Error-mapping wrapper for an actor or native-extension invocation which has
/// already copied its request bytes into the runtime. Keeping only the returned
/// [`Ask`] alive is important on guest targets: the request buffer must not
/// become an unrelated field in the compiler-generated future state beside the
/// reply.
#[doc(hidden)]
pub struct ClientAsk {
    inner: super::run::Ask,
}

impl ClientAsk {
    fn new(inner: super::run::Ask) -> Self {
        Self { inner }
    }
}

impl Future for ClientAsk {
    type Output = Result<Value, ClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner)
            .poll(cx)
            .map(|result| result.map_err(ClientError::from))
    }
}

/// Send a dynamically-shaped message to a node-local native extension.
///
/// This is deliberately separate from [`Invoker`]: an extension instance name
/// is host-local configuration, not a canonical [`ActorId`](crate::ActorId),
/// and it must pass the root's explicit `intra_caps` gate.
pub trait ExtensionInvoker {
    fn invoke_extension(
        &mut self,
        target: String,
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
    pub producer: crate::service::ProducerId,
    pub statement: crate::attestation::AttestationStatement,
    pub trace: crate::service::Hash,
    pub proof: Vec<u8>,
}

/// One exact attested-await result. The pending form exists only in the
/// transition-finalization fork; PVM restores the machine before this future
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
    fn invoke_actor_attested(
        &mut self,
        target: crate::service::ActorId,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<AttestedInvocationResult, ClientError>> + '_;
}

/// Implemented by every macro-generated `{Actor}Ref`. It binds a canonical
/// actor identity to an invoker and returns a handle whose methods need no
/// extra `ctx` argument.
pub trait ActorReference: Copy {
    type Handle<'a, I: Invoker + 'a>: 'a
    where
        Self: 'a;

    fn bind<'a, I: Invoker + 'a>(
        target: crate::service::ActorId,
        invoker: &'a mut I,
    ) -> Self::Handle<'a, I>;
}

/// Compile-time relationship between an actor state type and the generated
/// reference exposing that actor's message surface. Keeping this as a marker
/// trait, rather than an associated public type, permits application actors
/// to remain private without losing type equality at `Context::spawn`.
#[doc(hidden)]
pub trait ActorReferenceFor<A: super::Actor>: ActorReference {}

/// Implemented by macro-generated references that can also bind their message
/// surface to a node-local native extension instance.
pub trait ExtensionReference: Copy {
    type Handle<'a, I: ExtensionInvoker + 'a>: 'a
    where
        Self: 'a;

    fn bind_extension<'a, I: ExtensionInvoker + 'a>(
        target: String,
        invoker: &'a mut I,
    ) -> Self::Handle<'a, I>;
}

/// Generic spelling for a bound macro-generated actor handle.
pub type ActorHandle<'a, R, I> = <R as ActorReference>::Handle<'a, I>;

/// Generic spelling for a bound macro-generated native-extension handle.
pub type ExtensionHandle<'a, R, I> = <R as ExtensionReference>::Handle<'a, I>;

impl<A: super::Actor> Invoker for super::Context<A> {
    fn invoke_actor(
        &mut self,
        target: crate::service::ActorId,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Value, ClientError>> + '_ {
        let ask = self.ask_actor_raw(target, payload.as_slice(), None);
        ClientAsk::new(ask)
    }
}

#[cfg(feature = "native-extension-client")]
impl<A: super::Actor> ExtensionInvoker for super::Context<A> {
    fn invoke_extension(
        &mut self,
        target: String,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Value, ClientError>> + '_ {
        let ask = self.ask_extension_raw(&target, &payload);
        ClientAsk::new(ask)
    }
}

impl<A: super::Actor> AttestationInvoker for super::Context<A> {
    fn invoke_actor_attested(
        &mut self,
        target: crate::service::ActorId,
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

    #[test]
    fn authorization_denials_remain_typed_at_the_generated_handle_boundary() {
        assert!(matches!(
            ClientError::from(super::super::value::InvokeError::Forbidden),
            ClientError::Forbidden
        ));
    }
}
