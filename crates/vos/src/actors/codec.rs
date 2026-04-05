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
    fn decode(bytes: &[u8]) -> Self;
}

impl<T> Encode for T
where
    T: for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<rkyv::util::AlignedVec, rkyv::ser::allocator::ArenaHandle<'a>, rkyv::rancor::Error>,
    >,
{
    fn encode(&self) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self).unwrap().to_vec()
    }
}

impl<T> Decode for T
where
    T: rkyv::Archive,
    T::Archived: rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    fn decode(bytes: &[u8]) -> Self {
        let archived = unsafe { rkyv::access_unchecked::<T::Archived>(bytes) };
        rkyv::deserialize::<T, rkyv::rancor::Error>(archived).unwrap()
    }
}
