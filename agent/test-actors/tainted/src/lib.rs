//! An attestable method that reaches a host call other than a
//! precompile, through a helper: no kernel may be derived from it, so its
//! package cannot be installed.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

#[actor]
pub struct Tainted {}

/// `value` stamped with the batch's time: a host call.
#[inline(never)]
fn stamped(value: u64) -> u64 {
    value ^ vos_sdk::host::now()
}

#[messages]
impl Tainted {
    pub fn new() -> Self {
        Self {}
    }

    #[attestable]
    pub fn stamp(value: u64) -> u64 {
        stamped(value)
    }
}
