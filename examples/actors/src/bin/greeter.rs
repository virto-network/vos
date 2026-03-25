//! Greeter actor — responds to Greet messages with a personalized greeting.
//!
//! Demonstrates `#[derive(Actor)]` and `#[messages]` macro usage in a PVM program.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use example_actors::{print, println};
use pvx_actors::{Actor, block_on, messages};

#[derive(Actor)]
struct Greeter;

#[messages]
impl Greeter {
    #[msg]
    async fn greet(&self, name: Vec<u8>, _ctx: &mut Context<Self>) {
        print(b"Hello, ");
        print(&name);
        println(b"!");
    }
}

fn to_vec(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len());
    for &b in s {
        v.push(b);
    }
    v
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let mut greeter = Greeter;
    let mut ctx = pvx_actors::Context::new(pvx_actors::ActorId(
        pvx_scape::io::self_id() as u16,
    ));

    block_on(async {
        GreeterMsg::Greet(Greet { name: to_vec(b"Kunekt") })
            .deliver(&mut greeter, &mut ctx).await;
    });
}
