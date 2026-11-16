use vos_sdk::prelude::*;

#[actor(known_keys)]
pub struct Gated {
    admitted: Table<[u8; 32], (), Ordered>,
}

#[messages]
impl Gated {
}

fn main() {}
