//! The credential statements as device kernels written with the SDK
//! (`light-node.md` §4.2): `auth` and `owner` as a developer writes them,
//! their arguments by reference read in place and their hashes
//! `vos_sdk::p2`'s, measured against the hand-lean kernels' steps (the
//! `device` test actor's `auth`, and `owner_lean` here: owner by hand over
//! `p2`'s call and word accesses alone).
//!
//! Each claim is the kernel's public arguments: auth's `map_root`,
//! `scope`, `nullifier` and the call's `binding`, owner's `owner` and
//! `binding`, the binding carried without being read.

#![no_std]

extern crate alloc;

use vos_sdk::p2::{Digest, InPlace, Path, Secret, Tag, TagHash};
use vos_sdk::prelude::*;

/// Auth's claim: the member's leaf under `map_root`, and `nullifier` its
/// pseudonym in `scope`.
#[derive(Clone, Copy, InPlace)]
#[repr(C)]
pub struct AuthClaim {
    pub map_root: Digest,
    pub scope: Digest,
    pub nullifier: Digest,
    pub binding: Digest,
}

/// Owner's claim: `owner` the secret's owner digest.
#[derive(Clone, Copy, InPlace)]
#[repr(C)]
pub struct OwnerClaim {
    pub owner: Digest,
    pub binding: Digest,
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
    pub fn new() -> Self {
        Self {}
    }

    /// The secret's member's leaf lies under `map_root` by `path`, and
    /// `nullifier` is its nullifier in `scope`.
    #[attestable(device)]
    pub fn auth(path: &Path, secret: &Secret, #[public] claim: &AuthClaim) {
        let member = Tag::Member.hash(secret);
        assert_eq!(path.root(&Tag::Leaf.hash(&member)), claim.map_root);
        assert_eq!(Tag::Nf.hash(secret).hash(&claim.scope), claim.nullifier);
    }

    /// The secret's owner digest is `owner`.
    #[attestable(device)]
    pub fn owner(secret: &Secret, #[public] claim: &OwnerClaim) {
        assert_eq!(Tag::Owner.hash(secret), claim.owner);
    }

    /// Owner's statement by hand: the secret's 8-aligned words and the
    /// tag's written into one block, the call, and the result compared with
    /// the claim's word by word, never stopping early.
    #[attestable(device)]
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
