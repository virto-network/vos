//! An actor whose program is past JAM's limit, 512 KiB: a table of 640 KiB
//! in its read-only data, which a handler reads.

#![no_std]

use vos_sdk::prelude::*;

/// The table's words.
const WORDS: usize = 80 << 10;

/// Words no two alike, so the table is data, not zeros.
static TABLE: [u64; WORDS] = {
    let mut table = [0u64; WORDS];
    let mut index = 0;
    while index < WORDS {
        table[index] = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        index += 1;
    }
    table
};

#[actor]
pub struct Bulky {}

#[messages]
impl Bulky {
    pub fn new() -> Self {
        Self {}
    }

    /// The table's word at `index`, wrapped.
    #[msg]
    pub fn word(&self, index: u32) -> u64 {
        let table = core::hint::black_box(&TABLE);
        table[index as usize % WORDS]
    }
}
