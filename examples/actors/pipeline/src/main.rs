//! Pipeline actor — multi-step cross-actor computation loop.
//!
//! Each iteration:
//! 1. Compute local values
//! 2. Ask Math to add (suspends, resumes with Value)
//! 3. Use the result, compute more
//! 4. Ask Math to multiply (suspends again)
//! 5. Accumulate the result
//! 6. If threshold crossed → return the accumulated value
//! 7. Otherwise → yield and loop
//!
//! Demonstrates `ctx.ask().await` returning `Value`, handler return
//! types as replies, and a loop that terminates with a result.

use vos::{actor, messages, value::Msg};
#[allow(unused_imports)]
use vos::{print, println, eprint, eprintln};

const MATH_ID: u32 = 8;
const THRESHOLD: u64 = 1000;

#[actor]
struct Pipeline {
    step: u64,
    total: u64,
}

#[messages]
impl Pipeline {
    fn new() -> Self {
        Pipeline { step: 0, total: 0 }
    }

    /// Start until accumulated total crosses the threshold, then return it.
    #[msg]
    async fn start(&mut self, ctx: &mut Context<Self>) -> u64 {
        let math = vos::actors::context::ServiceId(MATH_ID);

        loop {
            self.step += 1;

            let base = self.step * 10;
            let offset = self.step * 3;

            // Ask Math to add
            let sum = ctx.ask(math, &Msg::new("add")
                .with("a", base)
                .with("b", offset))
                .await.unwrap()
                .as_u64().unwrap();
            println!("pipeline: {} + {} = {}", base, offset, sum);

            let factor = self.step + 1;

            // Ask Math to multiply
            let product = ctx.ask(math, &Msg::new("multiply")
                .with("a", sum)
                .with("b", factor))
                .await.unwrap()
                .as_u64().unwrap();
            println!("pipeline: {} * {} = {}", sum, factor, product);

            self.total += product;
            println!("pipeline: step {} total = {}", self.step, self.total);

            if self.total >= THRESHOLD {
                println!("pipeline: threshold crossed! returning {}", self.total);
                return self.total;
            }

            ctx.yield_now().await;
        }
    }
}

vos::pvm_main!(Pipeline);
