//! Math actor — stateless compute service for cross-actor queries.
//!
//! Handlers return typed values that are automatically converted to
//! `Value` and sent back as replies to `ask()` callers.

use vos::{actor, messages};
#[allow(unused_imports)]
use vos::{print, println, eprint, eprintln};

#[actor]
struct Math;

#[messages]
impl Math {
    fn new() -> Self {
        Math
    }

    #[msg]
    async fn add(&self, a: u64, b: u64) -> u64 {
        println!("math: {} + {} = {}", a, b, a + b);
        a + b
    }

    #[msg]
    async fn multiply(&self, a: u64, b: u64) -> u64 {
        println!("math: {} * {} = {}", a, b, a * b);
        a * b
    }
}

vos::pvm_main!(Math);
