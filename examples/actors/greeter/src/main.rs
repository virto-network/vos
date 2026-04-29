//! Greeter actor — one-shot actor that prints a greeting and exits.
//!
//! Demonstrates the simplest refine-only actor: a single `start()` handler
//! that executes once and completes.

use vos::{actor, messages};
#[allow(unused_imports)]
use vos::{print, println, eprint, eprintln};

#[actor]
struct Greeter {
    n: u32,
}

#[messages]
impl Greeter {
    fn new() -> Self {
        Greeter { n: 42 }
    }

    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) {
        println!("greeter: Hello n={}", self.n);
    }
}

vos::pvm_main!(Greeter);
