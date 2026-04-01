//! Hasher actor — endless compute loop demonstrating yield_now().
//!
//! Each invocation: hash once, print progress, yield to let the agent
//! re-invoke us. The loop body runs once per invocation — `try_poll`
//! returns `Yielded` on the first `.await`, and the agent re-sends
//! the same `Run` message to drive the next iteration.

use vos::{actor, messages};

/// Simple hash: XOR-fold with rotation.
fn simple_hash(input: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = input[i]
            .wrapping_add(input[(i + 7) % 32])
            .wrapping_mul(137)
            ^ input[(i + 13) % 32];
    }
    out
}

#[actor]
struct Hasher {
    current_hash: [u8; 32],
    iterations: u64,
}

#[messages]
impl Hasher {
    fn new(seed: Vec<u8>) -> Self {
        let mut hash = [0u8; 32];
        for (i, &b) in seed.iter().enumerate() {
            hash[i % 32] ^= b;
        }
        Hasher {
            current_hash: hash,
            iterations: 0,
        }
    }

    /// Run the hash loop. Each invocation executes one iteration:
    /// hash → print → yield. The agent re-invokes to drive the next one.
    #[msg]
    async fn run(&mut self, ctx: &mut Context<Self>) {
        loop {
            self.current_hash = simple_hash(&self.current_hash);
            self.iterations += 1;
            println!("hasher: iteration {} — hash[0..4]={:02x}{:02x}{:02x}{:02x}",
                self.iterations,
                self.current_hash[0], self.current_hash[1],
                self.current_hash[2], self.current_hash[3],
            );
            ctx.yield_now().await;
        }
    }

    /// Query the latest hash and iteration count.
    #[msg]
    async fn latest(&self, _ctx: &mut Context<Self>) -> (u64, u8, u8, u8, u8) {
        (
            self.iterations,
            self.current_hash[0],
            self.current_hash[1],
            self.current_hash[2],
            self.current_hash[3],
        )
    }
}
