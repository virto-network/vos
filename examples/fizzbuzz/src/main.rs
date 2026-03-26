//! FizzBuzz actor — handles Tick messages, printing fizzbuzz output.
//!
//! Demonstrates an actor with internal state and conditional logic.

use pvx_actors::{Actor, messages};

static OUTPUTS: [&str; 15] = [
    "1", "2", "fizz", "4", "buzz",
    "fizz", "7", "8", "fizz", "buzz",
    "11", "fizz", "13", "14", "fizzbuzz",
];

#[derive(Actor)]
struct FizzBuzz {
    position: u8,
}

#[messages]
impl FizzBuzz {
    fn new() -> Self {
        FizzBuzz { position: 0 }
    }

    #[msg]
    async fn tick(&mut self, _ctx: &mut Context<Self>) {
        if (self.position as usize) < OUTPUTS.len() {
            println!("{}", OUTPUTS[self.position as usize]);
            self.position += 1;
        }
    }
}
