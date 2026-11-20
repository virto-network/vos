//! A hand-lean device kernel beside the SDK's (`light-node.md` §4.2):
//! `owner_lean`, owner's statement by hand over `vos_sdk::p2`'s call and
//! word accesses alone, the baseline the stock `owner` kernel's steps are
//! measured against (as the `device` test actor's `auth` is the stock
//! `auth`'s). Its claim is owner's public arguments, `owner` and the call's
//! `binding`, the binding carried without being read.

#![no_std]

extern crate alloc;

use vos_sdk::p2::{Tag, TagHash};
use vos_sdk::prelude::*;

/// The kernel's reference run: the credential kernels' public reference
/// statement (`vos_sdk::p2::reference`) in its arguments, the stock
/// `owner` kernel's bytes, decoded where they lie.
mod reference {
    use alloc::vec::Vec;

    use vos_sdk::p2::reference::{BINDING, SECRET};

    use super::*;

    pub fn owner_lean() -> sdk_device::OwnerLean {
        let owner = [
            SECRET.encode(),
            Tag::Owner.hash(&SECRET).encode(),
            BINDING.encode(),
        ];
        let bytes: &'static [u8] = Vec::leak(owner.concat());
        sdk_device::OwnerLean::decode(bytes)
            .expect("owner's arguments are owner_lean's")
            .0
    }
}

/// `N` bytes of a kernel's arguments where its witness input left them,
/// decoded as their address: the hand-lean kernel's argument. Valid only
/// while the bytes it was decoded from live, which a kernel's arguments do
/// for its run; nothing else may encode one.
#[derive(Clone, Copy)]
pub struct Raw<const N: usize>(*const u8);

impl<const N: usize> Decode for Raw<N> {
    fn decode(data: &[u8]) -> Result<(Self, usize), vos_sdk::scale::DecodeError> {
        if data.len() < N {
            return Err(vos_sdk::scale::DecodeError::UnexpectedEof);
        }
        Ok((Self(data.as_ptr()), N))
    }
}

impl<const N: usize> Encode for Raw<N> {
    #[inline(always)]
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.reserve(N);
        let len = buf.len();
        // SAFETY: `N` bytes reserved past `len`, each written before the
        // length takes them in; the source's live in the argument pages.
        unsafe {
            let to = buf.as_mut_ptr().add(len);
            for i in 0..N / 8 {
                vos_sdk::p2::store_u64(to.add(8 * i), vos_sdk::p2::load_u64(self.0.add(8 * i)));
            }
            buf.set_len(len + N);
        }
    }
}

#[actor]
pub struct SdkDevice {}

#[messages]
impl SdkDevice {
    /// Owner's statement by hand: the secret's 8-aligned words and the
    /// tag's written into one block, the call, and the result compared with
    /// the claim's word by word, never stopping early.
    #[attestable(device, reference = reference::owner_lean)]
    pub fn owner_lean(secret: Raw<32>, #[public] owner: Raw<32>, #[public] binding: Raw<32>) {
        let _ = binding;
        let mut block = [0u64; 8];
        block[0] = u64::from(Tag::Owner.word());
        let mut differ = 0;
        // SAFETY: the secret's 32 bytes and the owner's, live in the
        // argument pages; the block's 64 bytes and its first 32 written.
        unsafe {
            for i in 0..4 {
                block[4 + i] = vos_sdk::p2::load_u64(secret.0.add(8 * i));
            }
            let at = block.as_mut_ptr();
            vos_sdk::p2::call(at, at);
            for (i, &word) in block[..4].iter().enumerate() {
                differ |= word ^ vos_sdk::p2::load_u64(owner.0.add(8 * i));
            }
        }
        assert!(differ == 0, "the owner");
    }
}
