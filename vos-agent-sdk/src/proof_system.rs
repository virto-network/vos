//! Exact proof-system capability and requirement sets.
//!
//! The fixed-capacity representation keeps the runtime model `Copy` and
//! allocation-free. Only the active prefix is canonical: it is strictly
//! sorted, contains no zero identity, and is bounded to sixteen systems.

use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

use crate::Hash;
use crate::wire::{CanonicalWire, WireError};

/// Maximum distinct proof systems advertised or required by one package.
pub const MAX_PROOF_SYSTEMS: usize = 16;
/// Standalone canonical proof-system-set artifact magic.
pub const PROOF_SYSTEM_SET_MAGIC: [u8; 4] = *b"APS1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofSystemSet {
    len: u8,
    systems: [Hash; MAX_PROOF_SYSTEMS],
}

impl Default for ProofSystemSet {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl ProofSystemSet {
    pub const EMPTY: Self = Self {
        len: 0,
        systems: [Hash::ZERO; MAX_PROOF_SYSTEMS],
    };

    /// Construct an exact set from a strictly sorted, unique, nonzero slice.
    pub fn from_sorted(systems: &[Hash]) -> Result<Self, ProofSystemSetError> {
        if systems.len() > MAX_PROOF_SYSTEMS
            || systems.contains(&Hash::ZERO)
            || systems.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ProofSystemSetError::NonCanonical);
        }
        let mut value = Self::EMPTY;
        value.systems[..systems.len()].copy_from_slice(systems);
        value.len = systems.len() as u8;
        Ok(value)
    }

    pub const fn len(self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[Hash] {
        &self.systems[..self.len as usize]
    }

    pub fn contains(&self, system: Hash) -> bool {
        self.as_slice().binary_search(&system).is_ok()
    }

    pub fn is_subset_of(&self, supported: &Self) -> bool {
        self.as_slice()
            .iter()
            .all(|system| supported.contains(*system))
    }

    /// Insert one nonzero identity while retaining canonical order.
    pub fn insert(&mut self, system: Hash) -> Result<(), ProofSystemSetError> {
        if system == Hash::ZERO {
            return Err(ProofSystemSetError::NonCanonical);
        }
        match self.as_slice().binary_search(&system) {
            Ok(_) => Ok(()),
            Err(position) => {
                let len = self.len();
                if len == MAX_PROOF_SYSTEMS {
                    return Err(ProofSystemSetError::LimitExceeded);
                }
                self.systems.copy_within(position..len, position + 1);
                self.systems[position] = system;
                self.len += 1;
                Ok(())
            }
        }
    }

    pub fn union(mut self, other: &Self) -> Result<Self, ProofSystemSetError> {
        for system in other.as_slice() {
            self.insert(*system)?;
        }
        Ok(self)
    }

    pub(crate) fn encode_embedded(&self, encoder: &mut Encoder<'_>) {
        encoder.u8(self.len);
        for system in self.as_slice() {
            encoder.fixed(system.as_bytes());
        }
    }

    pub(crate) fn decode_embedded(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let count = decoder.u8()? as usize;
        if count > MAX_PROOF_SYSTEMS {
            return Err(DecodeError::LimitExceeded);
        }
        let mut systems = [Hash::ZERO; MAX_PROOF_SYSTEMS];
        for system in &mut systems[..count] {
            *system = Hash(decoder.fixed()?);
        }
        Self::from_sorted(&systems[..count]).map_err(|error| match error {
            ProofSystemSetError::LimitExceeded => DecodeError::LimitExceeded,
            ProofSystemSetError::NonCanonical => DecodeError::NonCanonical,
        })
    }
}

impl CanonicalWire for ProofSystemSet {
    const MAGIC: [u8; 4] = PROOF_SYSTEM_SET_MAGIC;
    const MAX_ENCODED_BYTES: usize = 4 + 32 + 1 + MAX_PROOF_SYSTEMS * 32;

    fn validate_wire(&self) -> bool {
        Self::from_sorted(self.as_slice()).is_ok()
            && self.systems[self.len()..]
                .iter()
                .all(|system| *system == Hash::ZERO)
    }

    fn encode_body(&self, encoder: &mut Encoder<'_>) {
        self.encode_embedded(encoder);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Self::decode_embedded(decoder)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSystemSetError {
    NonCanonical,
    LimitExceeded,
}

impl fmt::Display for ProofSystemSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonical => formatter.write_str("noncanonical proof-system set"),
            Self::LimitExceeded => formatter.write_str("proof-system set limit exceeded"),
        }
    }
}

impl core::error::Error for ProofSystemSetError {}

impl From<WireError> for ProofSystemSetError {
    fn from(value: WireError) -> Self {
        match value {
            WireError::LimitExceeded | WireError::Decode(DecodeError::LimitExceeded) => {
                Self::LimitExceeded
            }
            _ => Self::NonCanonical,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn hash(byte: u8) -> Hash {
        Hash([byte; 32])
    }

    #[test]
    fn canonical_round_trip_and_subset_compatibility() {
        let required = ProofSystemSet::from_sorted(&[hash(2), hash(4)]).unwrap();
        let supported = ProofSystemSet::from_sorted(&[hash(1), hash(2), hash(4)]).unwrap();
        assert!(required.is_subset_of(&supported));
        assert!(!supported.is_subset_of(&required));
        assert_eq!(
            ProofSystemSet::decode(&required.encode().unwrap()).unwrap(),
            required
        );
    }

    #[test]
    fn insertion_is_sorted_unique_and_bounded() {
        let mut set = ProofSystemSet::EMPTY;
        set.insert(hash(3)).unwrap();
        set.insert(hash(1)).unwrap();
        set.insert(hash(3)).unwrap();
        assert_eq!(set.as_slice(), &[hash(1), hash(3)]);
        for byte in 4..=17 {
            set.insert(hash(byte)).unwrap();
        }
        assert_eq!(
            set.insert(hash(18)),
            Err(ProofSystemSetError::LimitExceeded)
        );
    }

    #[test]
    fn rejects_zero_duplicate_order_oversize_and_trailing_wire() {
        assert_eq!(
            ProofSystemSet::from_sorted(&[Hash::ZERO]),
            Err(ProofSystemSetError::NonCanonical)
        );
        assert_eq!(
            ProofSystemSet::from_sorted(&[hash(1), hash(1)]),
            Err(ProofSystemSetError::NonCanonical)
        );
        assert_eq!(
            ProofSystemSet::from_sorted(&[hash(2), hash(1)]),
            Err(ProofSystemSetError::NonCanonical)
        );
        assert_eq!(
            ProofSystemSet::from_sorted(&[hash(1); MAX_PROOF_SYSTEMS + 1]),
            Err(ProofSystemSetError::NonCanonical)
        );

        let empty = ProofSystemSet::EMPTY.encode().unwrap();
        let count_offset = 4 + 32;
        let mut oversized = empty.clone();
        oversized[count_offset] = (MAX_PROOF_SYSTEMS + 1) as u8;
        assert_eq!(
            ProofSystemSet::decode(&oversized),
            Err(WireError::Decode(DecodeError::LimitExceeded))
        );

        let mut zero = empty.clone();
        zero[count_offset] = 1;
        zero.extend_from_slice(Hash::ZERO.as_bytes());
        assert_eq!(
            ProofSystemSet::decode(&zero),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );

        let mut duplicate = empty.clone();
        duplicate[count_offset] = 2;
        duplicate.extend_from_slice(hash(1).as_bytes());
        duplicate.extend_from_slice(hash(1).as_bytes());
        assert_eq!(
            ProofSystemSet::decode(&duplicate),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );

        let mut reversed = empty.clone();
        reversed[count_offset] = 2;
        reversed.extend_from_slice(hash(2).as_bytes());
        reversed.extend_from_slice(hash(1).as_bytes());
        assert_eq!(
            ProofSystemSet::decode(&reversed),
            Err(WireError::Decode(DecodeError::NonCanonical))
        );

        let mut trailing: Vec<u8> = empty;
        trailing.push(0);
        assert_eq!(
            ProofSystemSet::decode(&trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes))
        );

        let mut old_magic = ProofSystemSet::EMPTY.encode().unwrap();
        old_magic[..4].copy_from_slice(b"APS0");
        assert_eq!(
            ProofSystemSet::decode(&old_magic),
            Err(WireError::Decode(DecodeError::InvalidTag))
        );
    }
}
