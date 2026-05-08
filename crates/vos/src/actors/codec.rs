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
    /// Decode from trusted bytes — panics on a structurally invalid input.
    /// Used in dispatch hot paths where the bytes were just produced by
    /// `Encode::encode` (e.g. wire frames, refine output payload).
    fn decode(bytes: &[u8]) -> Self;

    /// Decode from possibly-corrupt bytes. Returns `None` when the buffer
    /// fails rkyv's bytecheck validation (alignment, pointer-window
    /// invariants, type-shape invariants). Used at trust boundaries —
    /// persisted-state restoration, untrusted FETCH inputs — so a
    /// hand-corrupted or schema-drifted blob falls back to a fresh
    /// instance instead of decoding silently to garbage.
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
        assert!(!bytes.is_empty(), "Decode::decode called with empty bytes");
        // Ensure alignment — rkyv requires the buffer to be aligned
        // to access archived data. Input from FETCH/socket may not be.
        let aligned =
            if !(bytes.as_ptr() as usize).is_multiple_of(core::mem::align_of::<T::Archived>()) {
                let mut av = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
                av.extend_from_slice(bytes);
                let archived = unsafe { rkyv::access_unchecked::<T::Archived>(&av) };
                return rkyv::deserialize::<T, rkyv::rancor::Error>(archived).unwrap();
            } else {
                bytes
            };
        let archived = unsafe { rkyv::access_unchecked::<T::Archived>(aligned) };
        rkyv::deserialize::<T, rkyv::rancor::Error>(archived).unwrap()
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
