//! An attestable method declaring more gas than a kernel runs with on JAM,
//! 2,457,600: what its 4,096 compressions pay for.

#![no_std]

use vos_sdk::prelude::*;

#[actor]
pub struct Greedy {}

#[messages]
impl Greedy {
    pub fn new() -> Self {
        Self {}
    }

    #[attestable(gas = 3_000_000)]
    pub fn hash(x: u64) -> u64 {
        x.rotate_left(7)
    }
}
