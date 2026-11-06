use vos_sdk::p2::Digest;
use vos_sdk::prelude::*;

#[actor]
pub struct Kernels {}

#[messages]
impl Kernels {
    pub fn new() -> Self {
        Self {}
    }

    /// An argument in place is read, never written.
    #[attestable(device, reference = reference)]
    pub fn touch(digest: &mut Digest) {
        digest.0[0] = 0;
    }
}

fn reference() {}

fn main() {}
