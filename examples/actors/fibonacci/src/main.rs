//! Fibonacci actor — computes fib(n) iteratively.
//!
//! Pure-ALU actor with no external I/O, suitable for ZK proving benchmarks.

use vos::{actor, messages};

#[actor]
struct Fibonacci {
    n: u32,
}

#[messages]
impl Fibonacci {
    fn new() -> Self {
        Fibonacci { n: 10 }
    }

    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) {
        let result = fib(self.n);
        println!("fib({}) = {}", self.n, result);
    }
}

fn fib(n: u32) -> u64 {
    if n <= 1 {
        return n as u64;
    }
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    for _ in 2..=n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    b
}
