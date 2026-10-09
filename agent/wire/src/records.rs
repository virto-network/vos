//! Values the agent keeps under its system keys ([`crate::keys`]).

use alloc::vec::Vec;

use crate::ids::{MethodId, ProgramHash};
use crate::schema::Schema;
use crate::{Decode, Encode};

/// An installed instance, under [`crate::keys::installed`]: its program,
/// the program bound to each attestable method, the agent's role byte for
/// each role name, and the program's schema, read once at install.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Installed {
    pub program: ProgramHash,
    pub attestables: Vec<(MethodId, ProgramHash)>,
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

    pub fn attestable(&self, method: MethodId) -> Option<ProgramHash> {
        self.attestables
            .iter()
            .find(|(bound, _)| *bound == method)
            .map(|(_, program)| *program)
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
