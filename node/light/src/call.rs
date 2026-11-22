//! The call a proof authorizes (`identity-and-authority.md` §5): its scope
//! and its binding, computed here so a client never builds them.

use scale::Encode as _;
use vos_abi::SpaceId;
use vos_abi::abi::cap;
use vos_abi::ids::{AgentId, InstanceId, MethodId, derive_id};
use vos_wire::credentials;

use crate::{DeviceError, Digest};

/// A guard's scope name: 1 to this many bytes.
pub const NAME_BYTES: usize = 64;

/// One call of one method, in one space: what a proof's binding names.
/// `nonce` is the client's, at random ([`Call::new`] draws it from the
/// operating system); `expires_ms` is by the node's clock, which `Time`
/// answers ([`crate::wire::time_request`]), at most 120 s past it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// The space's `SpaceId`.
    pub space: [u8; 32],
    pub agent: u32,
    pub instance: u32,
    pub method: u32,
    /// The method's arguments in SCALE, at most `cap::REQUEST` less
    /// `cap::CLAIM` bytes.
    pub arguments: Vec<u8>,
    pub nonce: [u8; 16],
    pub expires_ms: u64,
}

impl Call {
    /// The call, its nonce drawn from the operating system.
    pub fn new(
        space: [u8; 32],
        agent: u32,
        instance: u32,
        method: u32,
        arguments: Vec<u8>,
        expires_ms: u64,
    ) -> Result<Self, DeviceError> {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| DeviceError::Prove)?;
        Ok(Self {
            space,
            agent,
            instance,
            method,
            arguments,
            nonce,
            expires_ms,
        })
    }

    /// Its arguments within `cap::REQUEST` less a claim's cap, as ingress
    /// takes a proven call's.
    pub(crate) fn check(&self) -> Result<(), DeviceError> {
        if self.arguments.len() > cap::REQUEST - cap::CLAIM {
            return Err(DeviceError::Config);
        }
        Ok(())
    }

    /// The binding digest `b` of a proof of the device program whose id is
    /// `program`, as ingress computes it ([`credentials::Bound::digest`]).
    pub fn binding_digest(&self, program: &[u8; 32]) -> [u8; 32] {
        credentials::Bound {
            space: &SpaceId(self.space),
            agent: AgentId(self.agent),
            instance: InstanceId(self.instance),
            method: MethodId(self.method),
            program,
            arguments: &self.arguments,
            nonce: &self.nonce,
            expires_ms: self.expires_ms,
        }
        .digest()
    }

    /// The claim's `binding`: `C(T(binding), W(b))`.
    pub fn binding(&self, program: &[u8; 32]) -> Digest {
        Digest::from_bytes(&credentials::binding(&self.binding_digest(program)))
            .expect("a compression's words are below p")
    }
}

/// The scope a guard named `name` gives in `space`'s agent `agent` at
/// `instance`, as ingress computes it ([`credentials::scope`]):
/// `C(T(scope), W(BLAKE2b-256("vos/cred/scope/v1" ‖ space ‖ agent ‖ instance ‖ name)))`,
/// the agent and the instance four little-endian bytes each, `name` as the
/// codec writes it (a `u32` little-endian length, then the bytes); `None`
/// for a name not 1 to [`NAME_BYTES`] bytes.
pub fn scope(space: &[u8; 32], agent: u32, instance: u32, name: &[u8]) -> Option<Digest> {
    if name.is_empty() || name.len() > NAME_BYTES {
        return None;
    }
    let scope = credentials::scope(&SpaceId(*space), AgentId(agent), InstanceId(instance), name);
    Some(Digest::from_bytes(&scope).expect("a compression's words are below p"))
}

/// The id of the method named `name`, as an actor's handler derives it:
/// [`derive_id`] in `vos/method/`.
pub fn method_id(name: &str) -> u32 {
    derive_id("vos/method/", name)
}

/// The arguments of the ledger's owner-guarded `transfer(to, amount,
/// key)`, which pays from the account of the digest the proof states, once
/// under `key`: the payee's name as the codec writes bytes, the amount,
/// then the key.
pub fn transfer_arguments(to: &str, amount: u64, key: &[u8; 32]) -> Vec<u8> {
    (to.as_bytes().to_vec(), amount, *key).encode()
}
