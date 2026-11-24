//! A small seeded generator (xorshift64): the core's election jitter, and
//! everything the simulation draws.

#[derive(Debug, Clone)]
pub struct Random(u64);

impl Random {
    /// A generator from `seed`. Xorshift maps zero to zero forever, so the
    /// state is made odd.
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// True with probability `per_million` / 1,000,000.
    pub fn chance(&mut self, per_million: u64) -> bool {
        self.next_u64() % 1_000_000 < per_million
    }

    /// Uniform in `low..=high`.
    pub fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.next_u64() % (high - low + 1)
    }
}
