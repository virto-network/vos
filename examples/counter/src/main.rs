//! Counter actor — handles Increment and PrintCount messages.
//!
//! Demonstrates stateful actors with constructor args and multiple message types.

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
        println!("count = {}", self.count);
    }
}
