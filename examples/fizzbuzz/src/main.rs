//! FizzBuzz actor — prints the fizzbuzz sequence, one per iteration.
//!
//! Demonstrates a stateful refine-only actor with conditional logic
//! and a yield loop. Each invocation prints the next fizzbuzz value.

use vos::{actor, messages};

#[actor]
struct FizzBuzz {
    n: u32,
}

#[messages]
impl FizzBuzz {
    fn new() -> Self {
        FizzBuzz { n: 0 }
    }

    #[msg]
    async fn run(&mut self, ctx: &mut Context<Self>) {
        loop {
            self.n += 1;
            if !ctx.replaying() {
                if self.n % 15 == 0 {
                    println!("fizzbuzz");
                } else if self.n % 3 == 0 {
                    println!("fizz");
                } else if self.n % 5 == 0 {
                    println!("buzz");
                } else {
                    println!("{}", self.n);
                }
            }
            ctx.yield_now().await;
        }
    }
}
