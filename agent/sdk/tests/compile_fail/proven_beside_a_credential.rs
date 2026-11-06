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

    /// One guard a handler.
    #[msg(credential = Owner, proven = proof)]
    pub fn vote(&mut self, claim: [u8; 32]) {
        let _ = claim;
        self.votes += 1;
    }

    #[attestable(device, reference = reference)]
    pub fn proof(#[public] root: [u8; 32]) {
        let _ = root;
    }
}

fn reference() -> poll::Proof {
    poll::Proof { root: [0; 32] }
}

fn main() {}
