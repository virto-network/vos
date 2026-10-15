//! Identifiers.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::keys::Transform;

/// An agent: on JAM, a service, so it shares the service id's width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct AgentId(pub u32);

/// An actor instance installed in an agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct InstanceId(pub u32);

/// A session's compact number inside its agent: accumulate assigns it when
/// it creates the session, and never reuses one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct SessionId(pub u64);

/// A committed map: an instance's field, by its tag, under its key
/// transform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct MapId {
    pub instance: InstanceId,
    pub tag: u32,
    pub transform: Transform,
}

/// A client session, named by the client: its key, a random name, and
/// its creation time in milliseconds since the Unix epoch. The three
/// together are its identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct Session {
    pub key: [u8; 32],
    pub name: [u8; 16],
    pub t0: u64,
}

/// How a step names its session: by its compact id when the agent holds
/// it, whole when the step creates it. Boxed, so every step does not carry
/// a new session's size.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum SessionRef {
    #[codec(index = 0)]
    Known(SessionId),
    #[codec(index = 1)]
    New(alloc::boxed::Box<Session>),
}

/// A workflow of an agent: numbered by the agent when it starts one, and
/// never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct WorkflowId(pub u64);

/// A method of an actor, numbered by its schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct MethodId(pub u32);

/// BLAKE2b-256 of a standard program blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct ProgramHash(pub [u8; 32]);

impl ProgramHash {
    /// The hash of program `blob`.
    pub fn of(blob: &[u8]) -> Self {
        Self(crate::result::digest(blob))
    }
}

/// The id `name` derives in `domain`: the first four bytes, big-endian, of
/// BLAKE2b-256 over `domain` and `name`. A method's in `vos/method/`, a
/// table's or committed map's in `vos/table/`.
pub fn derive_id(domain: &str, name: &str) -> u32 {
    let hash = vos_pvm_precompiles::blake2b_hash::<32>(domain.as_bytes(), &[name.as_bytes()]);
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

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
