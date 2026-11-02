use vos_sdk::p2::{Digest, InPlace};

/// A `u32` after a digest leaves four bytes of padding.
#[derive(Clone, Copy, InPlace)]
#[repr(C)]
pub struct Padded {
    pub digest: Digest,
    pub slot: u32,
}

/// Not `#[repr(C)]`: its layout is not its encoding.
#[derive(Clone, Copy, InPlace)]
pub struct Unordered {
    pub digest: Digest,
}

fn main() {}
