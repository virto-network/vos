//! Greeter actor — responds to Greet messages with a personalized greeting.
//!
//! Demonstrates a stateless actor with `#[derive(Actor)]` and `#[messages]`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use example_actors::{print, println};
use pvx_actors::{Actor, messages};

#[derive(Actor)]
struct Greeter;

#[messages]
impl Greeter {
    fn new() -> Self {
        Greeter
    }

    #[msg]
    async fn greet(&self, name: Vec<u8>, _ctx: &mut Context<Self>) {
        print(b"Hello, ");
        print(&name);
        println(b"!");
    }
}
