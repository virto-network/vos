//! FizzBuzz actor — handles Tick messages, printing fizzbuzz output.
//!
//! Demonstrates an actor with internal state and conditional logic.
//! Cooperative yielding happens automatically after each message delivery.

#![no_std]
#![no_main]

use example_actors::println;
use pvx_actors::{Actor, block_on, messages};

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
    #[msg]
    async fn tick(&mut self, _ctx: &mut Context<Self>) {
        if (self.position as usize) < OUTPUTS.len() {
            println(OUTPUTS[self.position as usize]);
            self.position += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let mut fb = FizzBuzz { position: 0 };
    let mut ctx = pvx_actors::Context::new(pvx_actors::ActorId(
        pvx_scape::io::self_id() as u16,
    ));

    block_on(async {
        let mut i: u8 = 0;
        while i < 15 {
            FizzBuzzMsg::Tick(Tick)
                .deliver(&mut fb, &mut ctx).await;
            i += 1;
        }
    });
}
