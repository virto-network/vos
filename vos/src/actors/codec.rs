//! Codec traits for actor state serialization.
//!
//! `Encode` and `Decode` wrap rkyv with blanket impls so any type with
//! rkyv `Archive`/`Serialize`/`Deserialize` derives automatically satisfies
//! the `Actor` supertrait bounds.

use alloc::vec::Vec;

/// Serialize to bytes. Blanket-implemented for all rkyv-serializable types.
pub trait Encode {
    fn encode(&self) -> Vec<u8>;
}

/// Deserialize from bytes. Blanket-implemented for all rkyv-deserializable types.
pub trait Decode: Sized {
    /// Decode bytes and panic on a structurally invalid input. Validation is
    /// still mandatory here: keeping the convenience API memory-safe means a
    /// missed trust-boundary check can at worst fail-stop, never reach rkyv's
    /// unchecked archive access.
    fn decode(bytes: &[u8]) -> Self;

    /// Decode from possibly-corrupt bytes. Returns `None` when the buffer
    /// fails rkyv's bytecheck validation (alignment, pointer-window
    /// invariants, type-shape invariants). Used at trust boundaries —
    /// persisted-state restoration and untrusted FETCH inputs — so a
    /// hand-corrupted or schema-drifted blob can be rejected instead of
    /// reaching unchecked archive access.
    fn try_decode(bytes: &[u8]) -> Option<Self>;
}

impl<T> Encode for T
where
    T: for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
{
    fn encode(&self) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .unwrap()
            .to_vec()
    }
}

impl<T> Decode for T
where
    T: rkyv::Archive,
    T::Archived: rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>
        + rkyv::Portable
        + for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>,
{
    fn decode(bytes: &[u8]) -> Self {
        Self::try_decode(bytes).expect("Decode::decode called with an invalid archive")
    }

    fn try_decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        // rkyv::access validates alignment, bounds, pointer windows,
        // and (via bytecheck) per-type structural invariants. Corrupted
        // or schema-drifted bytes return Err here instead of decoding
        // to garbage like access_unchecked would.
        let aligned;
        let slice: &[u8] =
            if !(bytes.as_ptr() as usize).is_multiple_of(core::mem::align_of::<T::Archived>()) {
                let mut av = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
                av.extend_from_slice(bytes);
                aligned = av;
                aligned.as_slice()
            } else {
                bytes
            };
        let archived = rkyv::access::<T::Archived, rkyv::rancor::Error>(slice).ok()?;
        rkyv::deserialize::<T, rkyv::rancor::Error>(archived).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{Decode, Encode};
    use crate::value::Value;

    #[test]
    fn infallible_decode_still_validates_before_archive_access() {
        let corrupt = [0xff; 32];
        assert_eq!(Value::try_decode(&corrupt), None);
        assert!(std::panic::catch_unwind(|| Value::decode(&corrupt)).is_err());
    }

    #[test]
    fn checked_decode_accepts_an_unaligned_valid_archive() {
        let value = Value::Bytes(vec![1, 2, 3, 4]);
        let encoded = value.encode();
        let mut unaligned = vec![0u8; encoded.len() + 1];
        unaligned[1..].copy_from_slice(&encoded);

        assert_eq!(Value::try_decode(&unaligned[1..]), Some(value.clone()));
        assert_eq!(Value::decode(&unaligned[1..]), value);
    }
}
