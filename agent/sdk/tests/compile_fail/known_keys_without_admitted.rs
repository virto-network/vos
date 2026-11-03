use vos_sdk::prelude::*;

#[actor(known_keys)]
pub struct Gated {
    count: u64,
}

#[messages]
impl Gated {
    pub fn new() -> Self {
        Self { count: 0 }
    }
}

fn main() {}
