use vos_sdk::prelude::*;

#[actor]
pub struct Poll {
    votes: Cell<u64>,
}

#[messages]
impl Poll {
    /// One guard a handler.
    #[msg(credential = Owner, proven = proof)]
    pub fn vote(&mut self, claim: [u8; 32]) {
        let _ = claim;
        self.votes.set(&(self.votes.get_or_default() + 1));
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
