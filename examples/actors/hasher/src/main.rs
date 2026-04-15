//! Hasher actor — computes N iterations of a simple hash chain.
//!
//! Pure-compute actor for ZK proving benchmarks: no yield, no I/O.

use vos::{actor, messages};

/// Simple hash: XOR-fold with rotation (no external deps needed).
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
    iterations: u32,
}

#[messages]
impl Hasher {
    fn new() -> Self {
        Hasher { iterations: 100 }
    }

    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) {
        let mut hash = [42u8; 32];
        for _ in 0..self.iterations {
            hash = simple_hash(&hash);
        }
        // Print first 4 bytes as a checksum
        let checksum = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        println!("hasher: {} iterations, checksum={checksum:#x}", self.iterations);
    }
}
