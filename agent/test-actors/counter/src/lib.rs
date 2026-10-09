//! A counter: struct state, a query, and a command that can fail.

#![no_std]

use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum CounterError {
    #[codec(index = 0)]
    Overflow,
}

#[messages]
impl Counter {
    pub fn new() -> Self {
        Self { value: 0 }
    }

    #[msg]
    pub async fn increment(&mut self, by: u64) -> Result<u64, CounterError> {
        self.value = self.value.checked_add(by).ok_or(CounterError::Overflow)?;
        Ok(self.value)
    }

    #[msg]
    pub async fn value(&self) -> u64 {
        self.value
    }

    /// Set the counter to the batch time, and return a random draw.
    #[msg]
    pub async fn stamp(&mut self, ctx: &mut Command<Self>) -> [u8; 32] {
        self.value = ctx.now();
        ctx.random()
    }
}
