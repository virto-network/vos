//! Greeter actor — responds to Greet messages with a personalized greeting.
//!
//! Demonstrates a stateless actor with `#[derive(Actor)]` and `#[messages]`.

use vos_actors::{Actor, messages};

#[derive(Actor)]
#[derive(
    vos_actors::rkyv::Archive,
    vos_actors::rkyv::Serialize,
    vos_actors::rkyv::Deserialize,
)]
#[rkyv(crate = vos_actors::rkyv)]
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
