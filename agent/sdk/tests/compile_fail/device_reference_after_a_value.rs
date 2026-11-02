use vos_sdk::p2::{Digest, Secret, Tag, TagHash};
use vos_sdk::prelude::*;

#[actor]
pub struct Kernels {}

#[messages]
impl Kernels {
    pub fn new() -> Self {
        Self {}
    }

    /// An argument by reference after one by value would lie unaligned.
    #[attestable(device)]
    pub fn owner(slot: u32, secret: &Secret, #[public] owner: &Digest) {
        let _ = slot;
        assert_eq!(Tag::Owner.hash(secret), *owner);
    }
}

fn main() {}
