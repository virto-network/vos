//! Greeter actor — responds to Greet messages with a personalized greeting.
//!
//! Demonstrates `#[derive(Actor)]` and `#[messages]` macro usage in a PVM program.

#![no_std]
#![no_main]

use example_actors::{print, println};
use pvx_actors::{Actor, block_on, messages};

#[derive(Actor)]
struct Greeter;

#[messages]
impl Greeter {
    #[msg]
    async fn greet(&self, name: &'static [u8], _ctx: &mut Context<Self>) {
        print(b"Hello, ");
        print(name);
        println(b"!");
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let mut greeter = Greeter;
    let mut ctx = pvx_actors::Context::new(pvx_actors::ActorId(
        pvx_scape::io::self_id() as u16,
    ));

    block_on(async {
        GreeterMsg::Greet(Greet { name: b"Kunekt" })
            .deliver(&mut greeter, &mut ctx).await;
        GreeterMsg::Greet(Greet { name: b"World" })
            .deliver(&mut greeter, &mut ctx).await;
    });
}
