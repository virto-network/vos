//! Greeter actor — responds to Greet messages with a personalized greeting.
//!
//! Demonstrates a stateless actor with `#[derive(Actor)]` and `#[messages]`.

use vos_actors::{Actor, messages};

#[derive(Actor)]
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
