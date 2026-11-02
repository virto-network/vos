use vos_sdk::p2::{Digest, InPlace, Path, Secret, Tag, TagHash};
use vos_sdk::prelude::*;

#[derive(Clone, Copy, InPlace)]
#[repr(C)]
pub struct Claim {
    pub map_root: Digest,
    pub binding: Digest,
}

#[actor]
pub struct Kernels {}

#[messages]
impl Kernels {
    pub fn new() -> Self {
        Self {}
    }

    /// Arguments by reference first, read in place, then one by value.
    #[attestable(device)]
    pub fn member(path: &Path, secret: &Secret, #[public] claim: &Claim, tag: u32) {
        let _ = tag;
        assert_eq!(path.root(&Tag::Member.hash(secret)), claim.map_root);
    }
}

fn main() {
    let message = kernels::Member {
        path: Path {
            siblings: [Digest::default(); vos_sdk::p2::DEPTH],
            slot: 0,
        },
        secret: Digest::default(),
        claim: Claim {
            map_root: Digest::default(),
            binding: Digest::default(),
        },
        tag: 7,
    };
    assert_eq!(message.encode().len(), 1032 + 32 + 64 + 4);
}
