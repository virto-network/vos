//! Handler contexts. A query's context reaches only operations that
//! read; a command's adds the ones that write.

use core::marker::PhantomData;

use vos_wire::abi::failure;
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::{Decode, DecodeError, Encode};

use crate::host;

/// A handler of an actor, as a message another actor can send.
pub trait Method: Encode {
    /// The actor that handles it.
    type Actor;
    const ID: u32;
    type Reply: Decode;
    type Error: Decode;
}

/// A `&self` handler: callable from queries too.
pub trait QueryMethod: Method {}

/// An `#[attestable]` method, run as its own program.
pub trait AttestableMethod: Encode {
    type Actor;
    const ID: u32;
    type Output: Decode;
}

/// The error type of a handler that cannot fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Never {}

impl Decode for Never {
    fn decode(_: &[u8]) -> Result<(Self, usize), DecodeError> {
        Err(DecodeError::InvalidDiscriminator(0))
    }
}

impl Encode for Never {
    fn encode_to(&self, _: &mut alloc::vec::Vec<u8>) {
        match *self {}
    }
}

/// An instance of actor `A` in this agent.
pub struct Ref<A> {
    pub instance: InstanceId,
    _actor: PhantomData<fn() -> A>,
}

impl<A> Ref<A> {
    pub const fn new(instance: InstanceId) -> Self {
        Self {
            instance,
            _actor: PhantomData,
        }
    }
}

impl<A> Clone for Ref<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A> Copy for Ref<A> {}

/// Why a nested call returned an error. Any other failure of the callee
/// fails the whole step, so the caller never sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError<E> {
    /// The callee's own error.
    Failed(E),
    /// This instance lacks the callee's role; the callee did not run.
    Forbidden,
    /// The reply or error did not decode as the method's types.
    Undecodable,
}

fn decode<T: Decode>(bytes: &[u8]) -> Option<T> {
    T::decode(bytes).ok().map(|(value, _)| value)
}

fn outcome<R: Decode, E: Decode>(
    result: Result<alloc::vec::Vec<u8>, (u32, alloc::vec::Vec<u8>)>,
) -> Result<R, CallError<E>> {
    match result {
        Ok(reply) => decode(&reply).ok_or(CallError::Undecodable),
        Err((failure::HANDLER, detail)) => {
            Err(decode(&detail).map_or(CallError::Undecodable, CallError::Failed))
        }
        Err((failure::FORBIDDEN, _)) => Err(CallError::Forbidden),
        Err(_) => Err(CallError::Undecodable),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

/// The context of a `&self` handler.
pub struct Query<A> {
    _actor: PhantomData<fn() -> A>,
}

impl<A> Query<A> {
    #[doc(hidden)]
    pub const fn new() -> Self {
        Self {
            _actor: PhantomData,
        }
    }

    /// Who invoked this handler: the calling instance, for a nested call.
    pub fn caller(&self) -> Principal {
        decode(&host::caller()).expect("the agent passes a principal")
    }

    /// This agent and instance.
    pub fn me(&self) -> (AgentId, InstanceId) {
        let (instance, agent) = host::self_id();
        (AgentId(agent), InstanceId(instance))
    }

    /// The time of the batch, or for a query of the last applied one, in
    /// milliseconds since the Unix epoch.
    pub fn now(&self) -> u64 {
        host::now()
    }

    /// 32 bytes derived from the batch seed: the same on every replica.
    pub fn random(&self) -> [u8; 32] {
        host::random()
    }

    pub fn log(&self, level: Level, message: &str) {
        host::log(level as u8, message.as_bytes());
    }

    /// Call a query of another instance of this agent.
    pub async fn call<M: QueryMethod>(
        &self,
        to: Ref<M::Actor>,
        message: M,
    ) -> Result<M::Reply, CallError<M::Error>> {
        outcome(host::call(to.instance.0, M::ID, &message.encode()))
    }
}

/// The context of a `&mut self` handler: everything a query has, and the
/// operations that write.
pub struct Command<A> {
    query: Query<A>,
}

impl<A> core::ops::Deref for Command<A> {
    type Target = Query<A>;

    fn deref(&self) -> &Query<A> {
        &self.query
    }
}

impl<A> Command<A> {
    #[doc(hidden)]
    pub const fn new() -> Self {
        Self {
            query: Query::new(),
        }
    }

    /// Call any handler of another instance of this agent. The callee runs
    /// nested and completes before this returns.
    pub async fn call<M: Method>(
        &mut self,
        to: Ref<M::Actor>,
        message: M,
    ) -> Result<M::Reply, CallError<M::Error>> {
        outcome(host::call(to.instance.0, M::ID, &message.encode()))
    }

    /// Send a message to an instance of any agent, delivered after this
    /// step commits.
    pub fn send<M: Method>(&mut self, agent: AgentId, to: Ref<M::Actor>, message: M) {
        host::send(agent.0, to.instance.0, M::ID, &message.encode());
    }

    /// Run one of this actor's attestable methods as its own program.
    pub async fn attest<M: AttestableMethod<Actor = A>>(
        &mut self,
        arguments: M,
    ) -> Result<M::Output, CallError<Never>> {
        match host::attest(M::ID, &arguments.encode()) {
            Ok(output) => decode(&output).ok_or(CallError::Undecodable),
            Err(_) => Err(CallError::Undecodable),
        }
    }
}
