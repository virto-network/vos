//! Greeter actor — responds to Greet messages with a personalized greeting.
//!
//! Demonstrates a stateless actor with `#[actor]` and `#[messages]`.

use vos::{actor, messages};

#[actor]
struct Greeter;

#[messages]
impl Greeter {
    fn new() -> Self {
        Greeter
    }

    #[msg]
    async fn greet(&self, name: Vec<u8>, _ctx: &mut Context<Self>) {
        let name = String::from_utf8_lossy(&name);
        println!("Hello, {name}!");
    }
}
