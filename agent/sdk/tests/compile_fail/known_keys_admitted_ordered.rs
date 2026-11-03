use vos_sdk::prelude::*;

#[actor(known_keys)]
pub struct Gated {
    admitted: Table<[u8; 32], (), Ordered>,
}

#[messages]
impl Gated {
    pub fn new() -> Self {
        Self {
            admitted: Table::default(),
        }
    }
}

fn main() {}
