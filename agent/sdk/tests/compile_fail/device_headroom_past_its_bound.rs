use vos_sdk::prelude::*;

#[actor]
pub struct Poll {
    votes: u64,
}

#[messages]
impl Poll {
    pub fn new() -> Self {
        Self { votes: 0 }
    }

    /// A program's sizes are raised by at most four.
    #[attestable(device, reference = reference, headroom = 5)]
    pub fn proof(#[public] root: [u8; 32]) {
        let _ = root;
    }
}

fn reference() {}

fn main() {}
