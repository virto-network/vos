//! FizzBuzz actor — handles Tick messages, printing fizzbuzz output.
//!
//! Demonstrates an actor with internal state and conditional logic.

#![no_std]
#![no_main]

extern crate alloc;

use example_actors::println;
use pvx_actors::{Actor, messages};

static OUTPUTS: [&[u8]; 15] = [
    b"1", b"2", b"fizz", b"4", b"buzz",
    b"fizz", b"7", b"8", b"fizz", b"buzz",
    b"11", b"fizz", b"13", b"14", b"fizzbuzz",
];

#[derive(Actor)]
struct FizzBuzz {
    position: u8,
}

#[messages]
impl FizzBuzz {
    fn new() -> Self {
        FizzBuzz { position: 0 }
    }

    #[msg]
    async fn tick(&mut self, _ctx: &mut Context<Self>) {
        if (self.position as usize) < OUTPUTS.len() {
            println(OUTPUTS[self.position as usize]);
            self.position += 1;
        }
    }
}
