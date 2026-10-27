//! The call a proof authorizes (`identity-and-authority.md` §5): its scope
//! and its binding, computed here so a client never builds them.

use vos_pvm_precompiles::blake2b_hash;
use vos_wire::abi::cap;
use vos_wire::credentials::{Tag, compress, reduced};

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
    /// The method's arguments in SCALE, at most `cap::REQUEST` bytes.
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

    /// Its arguments within `cap::REQUEST`.
    pub(crate) fn check(&self) -> Result<(), DeviceError> {
        if self.arguments.len() > cap::REQUEST {
            return Err(DeviceError::Config);
        }
        Ok(())
    }

    /// The binding digest `b` of a proof of the statement whose program id
    /// is `program` and kind `kind`:
    /// `BLAKE2b-256("vos/cred/binding/v1" ‖ space ‖ agent ‖ instance ‖ method ‖ program ‖ kind ‖ arguments ‖ nonce ‖ expires_ms)`,
    /// the agent, instance and method four little-endian bytes each, the
    /// arguments as the codec writes them (a `u32` little-endian length,
    /// then the bytes).
    pub fn binding_digest(&self, program: &[u8; 32], kind: u8) -> [u8; 32] {
        let length = (self.arguments.len() as u32).to_le_bytes();
        blake2b_hash::<32>(
            b"vos/cred/binding/v1",
            &[
                &self.space,
                &self.agent.to_le_bytes(),
                &self.instance.to_le_bytes(),
                &self.method.to_le_bytes(),
                program,
                &[kind],
                &length,
                &self.arguments,
                &self.nonce,
                &self.expires_ms.to_le_bytes(),
            ],
        )
    }

    /// The proof's public `binding`: `C(T(binding), W(b))`.
    pub fn binding(&self, program: &[u8; 32], kind: u8) -> Digest {
        Digest(compress(
            &Tag::Binding.block(),
            &reduced(&self.binding_digest(program, kind)),
        ))
    }
}

/// The scope a guard named `name` gives in `space`'s agent `agent` at
/// `instance`:
/// `C(T(scope), W(BLAKE2b-256("vos/cred/scope/v1" ‖ space ‖ agent ‖ instance ‖ name)))`,
/// the agent and the instance four little-endian bytes each, `name` as the
/// codec writes it (a `u32` little-endian length, then the bytes); `None`
/// for a name not 1 to [`NAME_BYTES`] bytes.
pub fn scope(space: &[u8; 32], agent: u32, instance: u32, name: &[u8]) -> Option<Digest> {
    if name.is_empty() || name.len() > NAME_BYTES {
        return None;
    }
    let hash = blake2b_hash::<32>(
        b"vos/cred/scope/v1",
        &[
            space,
            &agent.to_le_bytes(),
            &instance.to_le_bytes(),
            &(name.len() as u32).to_le_bytes(),
            name,
        ],
    );
    Some(Digest(compress(&Tag::Scope.block(), &reduced(&hash))))
}
