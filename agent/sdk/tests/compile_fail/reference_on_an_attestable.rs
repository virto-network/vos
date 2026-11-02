use vos_sdk::p2::Digest;
use vos_sdk::prelude::*;

#[actor]
pub struct Kernels {}

#[messages]
impl Kernels {
    pub fn new() -> Self {
        Self {}
    }

    /// Only a device kernel reads its arguments in place.
    #[attestable]
    pub fn echo(digest: &Digest) -> u32 {
        digest.0[0]
    }
}

fn main() {}
