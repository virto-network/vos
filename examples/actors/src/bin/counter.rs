//! Counter actor — handles Increment and Print messages.
//!
//! Demonstrates stateful actors with constructor args and multiple message types.
//! The executor sends an init message with the starting count, then delivers
//! Increment/PrintCount messages. Yielding, recv, and checkpointing are automatic.

#![no_std]
#![no_main]

extern crate alloc;

use example_actors::{print, println, print_digit};
use pvx_actors::{Actor, messages};

#[derive(Actor)]
struct Counter {
    count: u8,
}

#[messages]
impl Counter {
    fn new(initial: u8) -> Self {
        Counter { count: initial }
    }

    #[msg]
    async fn increment(&mut self, _ctx: &mut Context<Self>) -> u8 {
        self.count += 1;
        self.count
    }

    #[msg]
    async fn print_count(&self, _ctx: &mut Context<Self>) {
        print(b"count = ");
        print_digit(self.count);
        println(b"");
    }
}
