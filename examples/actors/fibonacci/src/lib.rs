//! Fibonacci actor — computes fib(n) iteratively.
//!
//! Pure-ALU actor with no external I/O, suitable for ZK proving benchmarks.

use vos::prelude::*;

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
        // Pure-ALU: `black_box` the input so `fib` isn't const-folded and
        // the result so it isn't elided — no I/O (no string formatting), so
        // the trace stays small and provable.
        let n = core::hint::black_box(self.n);
        core::hint::black_box(fib(n));
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
