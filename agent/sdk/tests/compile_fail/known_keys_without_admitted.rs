use vos_sdk::prelude::*;

#[actor(known_keys)]
pub struct Gated {
    count: Cell<u64>,
}

#[messages]
impl Gated {
}

fn main() {}
