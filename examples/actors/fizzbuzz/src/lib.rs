// FizzBuzz actor — prints the fizzbuzz sequence, one per iteration.
//
// Demonstrates a stateful refine-only actor with conditional logic
// and a yield loop. Each invocation prints the next fizzbuzz value.

use vos::prelude::*;
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
    async fn start(&mut self, ctx: &mut Context<Self>) {
        loop {
            self.n += 1;
            if self.n % 15 == 0 {
                log::info!("fizzbuzz: fizzbuzz");
            } else if self.n % 3 == 0 {
                log::info!("fizzbuzz: fizz");
            } else if self.n % 5 == 0 {
                log::info!("fizzbuzz: buzz");
            } else {
                log::info!("fizzbuzz: {}", self.n);
            }
            ctx.yield_now().await;
        }
    }
}

