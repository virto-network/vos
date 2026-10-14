//! Values the agent keeps under its system keys ([`crate::keys`]).

use alloc::vec::Vec;

use crate::abi::Kind;
use crate::ids::{MethodId, ProgramHash};
use crate::schema::Schema;
use crate::{Decode, Encode};

/// An installed instance, under [`crate::keys::installed`]: its program,
/// the programs beside it, each bound to a method of its kind, the agent's
/// role byte for each role name, and the program's schema, read once at
/// install.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Installed {
    pub program: ProgramHash,
    pub beside: Vec<(MethodId, Kind, ProgramHash)>,
    pub roles: Vec<(Vec<u8>, u8)>,
    pub schema: Schema,
}

impl Installed {
    pub fn role(&self, name: &[u8]) -> Option<u8> {
        self.roles
            .iter()
            .find(|(role, _)| role == name)
            .map(|(_, byte)| *byte)
    }

    /// The program bound to `method` as a method of `kind`.
    pub fn bound(&self, method: MethodId, kind: Kind) -> Option<ProgramHash> {
        self.beside
            .iter()
            .find(|(bound, of, _)| *bound == method && *of == kind)
            .map(|(_, _, program)| *program)
    }

    pub fn attestable(&self, method: MethodId) -> Option<ProgramHash> {
        self.bound(method, Kind::Attestable)
    }

    /// Every program the instance runs, its own first: what its agent pins.
    pub fn programs(&self) -> impl Iterator<Item = ProgramHash> + '_ {
        core::iter::once(self.program).chain(self.beside.iter().map(|(_, _, program)| *program))
    }
}

/// A session's mark, under [`crate::keys::session`]: the last sequence
/// consumed and the work-result time it was consumed at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SessionMark {
    pub sequence: u64,
    pub time: u64,
}

/// Every value the agent stores begins with this byte. Gray Paper storage
/// deletes a key written with an empty value; the byte keeps an empty
/// value present, as the actor ABI allows.
pub const STORED: u8 = 1;

/// A value as the agent stores it.
pub fn stored(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + value.len());
    bytes.push(STORED);
    bytes.extend_from_slice(value);
    bytes
}

/// A stored value's bytes, or `None` for bytes the agent did not store.
pub fn unstored(bytes: &[u8]) -> Option<&[u8]> {
    match bytes.split_first() {
        Some((&STORED, value)) => Some(value),
        _ => None,
    }
}

/// A committed map's value as its value row holds it
/// ([`crate::keys::committed`]): the state version that wrote it, a
/// little-endian `u64`, then the value.
pub fn versioned(version: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + value.len());
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(value);
    bytes
}

/// [`stored`] of [`versioned`], in one allocation: a value row as the agent
/// writes it.
pub fn stored_versioned(version: u64, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9 + value.len());
    bytes.push(STORED);
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(value);
    bytes
}

/// A value row's version and value, or `None` for bytes too short to be one.
pub fn unversioned(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (version, value) = bytes.split_first_chunk::<8>()?;
    Some((u64::from_le_bytes(*version), value))
}
