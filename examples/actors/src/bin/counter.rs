//! Counter actor — handles Increment and Print messages.
//!
//! Demonstrates stateful actors with multiple message types running in PVM.
//! Cooperative yielding happens automatically after each message delivery.

#![no_std]
#![no_main]

extern crate alloc;

use example_actors::{print, println, print_digit};
use pvx_actors::{Actor, block_on, messages};

#[derive(Actor)]
struct Counter {
    count: u8,
}

#[messages]
impl Counter {
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let mut counter = Counter { count: 0 };
    let mut ctx = pvx_actors::Context::new(pvx_actors::ActorId(
        pvx_scape::io::self_id() as u16,
    ));

    block_on(async {
        let mut i: u8 = 0;
        while i < 5 {
            CounterMsg::Increment(Increment)
                .deliver(&mut counter, &mut ctx).await;
            CounterMsg::PrintCount(PrintCount)
                .deliver(&mut counter, &mut ctx).await;
            i += 1;
        }
    });
}
