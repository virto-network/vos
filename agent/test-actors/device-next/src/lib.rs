//! The `device` test actor's next release (`light-node.md` §4.4): its
//! `login` guard in the same scope, now admitting each pseudonym once, and
//! the same `auth` statement in the same arguments, its
//! kernel written otherwise, with the SDK, so its device program, and the
//! program id a binding names, differ while its claims do not. Installed
//! over the `device` actor, it is an upgrade whose window admits both
//! releases: a member's pseudonym in `"login"` is the same under either,
//! and its `login` admits each pseudonym once, whichever release proved.
//!
//! Its arguments are the `device` actor's: the 32 siblings and the secret
//! read in place, the slot's four bytes, then auth's public arguments as
//! `CredentialPublic::Auth` encodes them (the kind byte and four digests),
//! each digest copied, as the kind byte leaves them unaligned.

#![no_std]

extern crate alloc;

use vos_sdk::p2::{DEPTH, Digest, InPlace, Path, Secret, Tag, TagHash};
use vos_sdk::prelude::*;

/// The 32 siblings from the leaf's level up, read in place.
#[derive(Clone, Copy, InPlace)]
#[repr(C)]
pub struct Siblings(pub [Digest; DEPTH]);

/// `auth`'s reference run: the credential kernels' public reference
/// statement (`vos_sdk::p2::reference`).
mod reference {
    use vos_sdk::p2::reference::{BINDING, PATH, SCOPE, SECRET};

    use super::*;

    pub fn auth() -> device_next::Auth {
        let member = Tag::Member.hash(&SECRET);
        device_next::Auth {
            siblings: Siblings(PATH.siblings),
            secret: SECRET,
            slot: 0,
            kind: 0,
            map_root: PATH.root(&Tag::Leaf.hash(&member)),
            scope: SCOPE,
            nullifier: Tag::Nf.hash(&SECRET).hash(&SCOPE),
            binding: BINDING,
        }
    }
}

#[actor]
pub struct DeviceNext {}

#[messages]
impl DeviceNext {
    pub fn new() -> Self {
        Self {}
    }

    /// A member signed in, once, by a credential proof or a device proof
    /// of `auth`, either release's: its pseudonym in the scope `"login"`.
    #[msg(credential = Auth("login"), device = "auth", once)]
    pub async fn login(&mut self, ctx: &mut Command<Self>) -> Option<[u8; 32]> {
        ctx.nullifier()
    }

    /// Auth over the Poseidon2 tree: `secret`'s leaf at `slot` under
    /// `map_root` by `siblings`, and `nullifier` its nullifier for `scope`.
    #[attestable(device, reference = reference::auth)]
    #[allow(clippy::too_many_arguments)]
    pub fn auth(
        siblings: &Siblings,
        secret: &Secret,
        slot: u32,
        #[public] kind: u8,
        #[public] map_root: Digest,
        #[public] scope: Digest,
        #[public] nullifier: Digest,
        #[public] binding: Digest,
    ) {
        let _ = binding;
        assert!(kind == 0, "auth's kind");
        let path = Path {
            siblings: siblings.0,
            slot: u64::from(slot),
        };
        let member = Tag::Member.hash(secret);
        assert_eq!(path.root(&Tag::Leaf.hash(&member)), map_root);
        assert_eq!(Tag::Nf.hash(secret).hash(&scope), nullifier);
    }
}
