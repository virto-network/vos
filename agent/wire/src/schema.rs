//! An actor program's schema: its methods. The program carries it first in
//! its read-only data, so the agent reads it from a loaded machine and the
//! node from the blob, without running anything.

use alloc::vec::Vec;

use crate::abi::Kind;
use crate::ids::MethodId;
use crate::{Decode, Encode};

/// The section starts with these bytes, then the schema's length as four
/// little-endian bytes, then the schema.
pub const MAGIC: [u8; 4] = *b"VOSS";

/// The most a schema may hold: what a refine reads before installing.
pub const MAX_LEN: usize = 64 << 10;
pub const MAX_METHODS: usize = 1024;
pub const MAX_NAME: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Schema {
    pub methods: Vec<MethodSchema>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct MethodSchema {
    /// The first four bytes, big-endian, of BLAKE2b-256 over `vos/method/`
    /// and the method's name.
    pub id: MethodId,
    pub name: Vec<u8>,
    pub kind: Kind,
    /// The role a caller needs, by name; installing maps it to a role
    /// byte.
    pub role: Option<Vec<u8>>,
    /// The gas limit the handler requests; the agent caps it by policy.
    /// `None` takes the agent's default.
    pub gas: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// The read-only data does not start with a schema section.
    Missing,
    /// The section is larger than [`MAX_LEN`] or ends early.
    Size,
    Undecodable,
    /// Too many methods, or a name too long.
    Limits,
    /// Method id 0, which is reserved.
    ReservedId,
    Duplicate(MethodId),
}

impl Schema {
    /// The section's bytes.
    pub fn section(&self) -> Vec<u8> {
        let body = self.encode();
        let mut section = Vec::with_capacity(8 + body.len());
        section.extend_from_slice(&MAGIC);
        section.extend_from_slice(&(body.len() as u32).to_le_bytes());
        section.extend_from_slice(&body);
        section
    }

    /// Read and validate the schema at the start of a program's read-only
    /// data.
    pub fn read(ro_data: &[u8]) -> Result<Self, SchemaError> {
        if ro_data.get(..4) != Some(&MAGIC[..]) {
            return Err(SchemaError::Missing);
        }
        let len = ro_data
            .get(4..8)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")) as usize)
            .ok_or(SchemaError::Size)?;
        if len > MAX_LEN {
            return Err(SchemaError::Size);
        }
        let body = ro_data.get(8..8 + len).ok_or(SchemaError::Size)?;
        let (schema, used) = Self::decode(body).map_err(|_| SchemaError::Undecodable)?;
        if used != len {
            return Err(SchemaError::Undecodable);
        }
        schema.validate()?;
        Ok(schema)
    }

    /// Unique, non-zero ids within the limits.
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.methods.len() > MAX_METHODS {
            return Err(SchemaError::Limits);
        }
        let mut ids: Vec<u32> = Vec::with_capacity(self.methods.len());
        for method in &self.methods {
            if method.name.len() > MAX_NAME
                || method
                    .role
                    .as_ref()
                    .is_some_and(|role| role.len() > MAX_NAME)
            {
                return Err(SchemaError::Limits);
            }
            if method.id.0 == 0 {
                return Err(SchemaError::ReservedId);
            }
            ids.push(method.id.0);
        }
        // Sorted, a duplicate sits next to its twin: a refine validates a
        // schema of a thousand methods without comparing every pair.
        ids.sort_unstable();
        match ids.windows(2).find(|pair| pair[0] == pair[1]) {
            Some(pair) => Err(SchemaError::Duplicate(MethodId(pair[0]))),
            None => Ok(()),
        }
    }

    pub fn method(&self, id: MethodId) -> Option<&MethodSchema> {
        self.methods.iter().find(|method| method.id == id)
    }

    /// The id of the method named `name`.
    pub fn method_id(&self, name: &str) -> Option<MethodId> {
        self.methods
            .iter()
            .find(|method| method.name == name.as_bytes())
            .map(|method| method.id)
    }
}
