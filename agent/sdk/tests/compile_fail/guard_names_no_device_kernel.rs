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

    /// `proven` names a method that is attestable but no device kernel.
    #[msg(proven = proof)]
    pub fn vote(&mut self, claim: [u8; 32]) {
        let _ = claim;
        self.votes += 1;
    }

    #[attestable]
    pub fn proof(#[public] root: [u8; 32]) {
        let _ = root;
    }
}

fn main() {}
