use vos_sdk::p2::{Digest, InPlace};

/// A `bool` is not every bit pattern.
#[derive(Clone, Copy, InPlace)]
#[repr(C)]
pub struct Flagged {
    pub digest: Digest,
    pub flag: bool,
}

/// Aligned past eight bytes, so not where an argument lies.
#[derive(Clone, Copy, InPlace)]
#[repr(C, align(16))]
pub struct Wide {
    pub digests: [Digest; 2],
}

/// Generic: its layout is not one.
#[derive(Clone, Copy, InPlace)]
#[repr(C)]
pub struct Generic<T: Copy> {
    pub value: T,
}

fn main() {}
