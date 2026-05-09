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
    T::Archived: rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    fn decode(bytes: &[u8]) -> Self {
        assert!(!bytes.is_empty(), "Decode::decode called with empty bytes");
        // Ensure alignment — rkyv requires the buffer to be aligned
        // to access archived data. Input from FETCH/socket may not be.
        let aligned = if (bytes.as_ptr() as usize) % core::mem::align_of::<T::Archived>() != 0 {
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
}
