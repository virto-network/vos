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

    /// A reference returns its own kernel's message.
    #[attestable(device, reference = reference)]
    pub fn proof(#[public] root: [u8; 32]) {
        let _ = root;
    }

    #[attestable(device, reference = reference)]
    pub fn other(#[public] count: u64) {
        let _ = count;
    }
}

fn reference() -> poll::Proof {
    poll::Proof { root: [0; 32] }
}

fn main() {}
