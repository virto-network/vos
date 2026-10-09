//! Identifiers.

use alloc::vec::Vec;
use scale::{Decode, Encode};

/// An agent: on JAM, a service, so it shares the service id's width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct AgentId(pub u32);

/// An actor instance installed in an agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct InstanceId(pub u32);

/// A client session. The server assigns it and never reuses one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct SessionId(pub u64);

/// A method of an actor, numbered by its schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct MethodId(pub u32);

/// BLAKE2b-256 of a standard program blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct ProgramHash(pub [u8; 32]);

/// Who made a request: a client, authenticated at ingress by its key,
/// another agent, or, for a nested call, the calling instance of the same
/// agent. Each holds only the roles granted to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum Principal {
    #[codec(index = 0)]
    Client([u8; 32]),
    #[codec(index = 1)]
    Agent(AgentId),
    #[codec(index = 2)]
    Instance(InstanceId),
}
