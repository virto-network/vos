//! What a target bounds at run time: attests by count and by their bytes
//! either way, a kernel's gas, and a handler's heap against a workflow's.

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use vos_sdk::prelude::*;

#[actor]
pub struct Bounds {}

#[messages]
impl Bounds {
    pub fn new() -> Self {
        Self {}
    }

    /// Attest `echo` `count` times, each with `padding` bytes beside the
    /// output's length, asking for `output` bytes back: the bytes echoed.
    #[msg]
    pub async fn attest(
        &mut self,
        ctx: &mut Command<Self>,
        count: u32,
        padding: u32,
        output: u32,
    ) -> u64 {
        let mut echoed = 0;
        for _ in 0..count {
            let echo = bounds::Echo {
                padding: vec![7; padding as usize],
                output,
            };
            echoed += ctx.attest(echo).await.map_or(0, |bytes| bytes.len() as u64);
        }
        echoed
    }

    /// `output` bytes, each the padding's length.
    #[attestable]
    pub fn echo(padding: Vec<u8>, output: u32) -> Vec<u8> {
        vec![padding.len() as u8; output as usize]
    }

    /// Attest `spin` for `rounds`: its word.
    #[msg]
    pub async fn spun(&mut self, ctx: &mut Command<Self>, rounds: u32) -> u64 {
        ctx.attest(bounds::Spin { rounds }).await.unwrap_or(0)
    }

    /// A word mixed `rounds` times, within a small gas limit.
    #[attestable(gas = 50_000)]
    pub fn spin(rounds: u32) -> u64 {
        let mut word = 0u64;
        for round in 0..rounds {
            word = core::hint::black_box(word.wrapping_mul(31).wrapping_add(u64::from(round)));
        }
        word
    }

    /// Allocate `bytes`, touching none of them: the bytes allocated.
    #[msg]
    pub fn reserve(&self, bytes: u32) -> u32 {
        let reserved: Vec<u8> = core::hint::black_box(Vec::with_capacity(bytes as usize));
        reserved.capacity() as u32
    }

    /// The same in a workflow, which allocates from its whole heap.
    #[workflow]
    pub async fn reserved(bytes: u32) -> u32 {
        let reserved: Vec<u8> = core::hint::black_box(Vec::with_capacity(bytes as usize));
        reserved.capacity() as u32
    }
}
