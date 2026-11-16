use vos_sdk::prelude::*;

#[actor]
pub struct Poll {
    votes: Cell<u64>,
}

#[messages]
impl Poll {
    /// `proven` names a method that is attestable but no device kernel.
    #[msg(proven = proof)]
    pub fn vote(&mut self, claim: [u8; 32]) {
        let _ = claim;
        self.votes.set(&(self.votes.get_or_default() + 1));
    }

    #[attestable]
    pub fn proof(#[public] root: [u8; 32]) {
        let _ = root;
    }
}

fn main() {}
