//! Identifiers.

use alloc::vec::Vec;
use scale::{Decode, Encode};

use crate::keys::Transform;

/// An agent: on JAM, a service, so it shares the service id's width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct AgentId(pub u32);

impl AgentId {
    /// The id of node `creator`'s agent `serial`, below `1 << 24`: a node
    /// numbers the agents it creates in its own range, the id's top 8 bits
    /// its number.
    pub fn new(creator: u8, serial: u32) -> Self {
        AgentId(u32::from(creator) << 24 | serial)
    }

    /// The number of the node whose range the agent is in.
    pub fn creator(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// Which of its creator's agents it is.
    pub fn serial(self) -> u32 {
        self.0 & 0x00ff_ffff
    }
}

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

/// A read at a window's cut that a workflow asked for: the workflow, and
/// the await it suspends at. One await asks once, so the pair names one
/// request for good, whichever window it is served at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct RequestId {
    pub workflow: WorkflowId,
    pub awaits: u64,
}

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
/// agent; or the sender of a proven call, whose device proof ingress
/// verified (`identity-and-authority.md` §5). Each holds only the roles
/// granted to it, and a proven call's origin none: a guard admits it.
/// Index 5 is reserved for `Identity`, 6 for `Jam`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub enum Principal {
    #[codec(index = 0)]
    Client([u8; 32]),
    #[codec(index = 1)]
    Agent(AgentId),
    #[codec(index = 2)]
    Instance(InstanceId),
    /// An auth proof's: the sender knows the secret behind a member's leaf,
    /// and `nullifier` is its pseudonym in `scope`, stable across its
    /// calls. Each digest is eight M31 words, as little-endian `u32`s.
    #[codec(index = 3)]
    Anonymous {
        scope: [u8; 32],
        nullifier: [u8; 32],
    },
    /// An owner proof's: the sender knows the secret behind `digest`, the
    /// owner a row names.
    #[codec(index = 4)]
    Owner([u8; 32]),
    /// A proof of an actor's own device kernel (`#[msg(proven = k)]`):
    /// `program` is the kernel's device program the proof was verified
    /// under. The claim reaches the handler as its first argument, and the
    /// handler checks it.
    #[codec(index = 7)]
    Kernel { program: [u8; 32] },
}

impl Principal {
    /// Whether a device proof made it: no role is ever granted to one.
    pub const fn is_credential(&self) -> bool {
        matches!(
            self,
            Principal::Anonymous { .. } | Principal::Owner(_) | Principal::Kernel { .. }
        )
    }
}
