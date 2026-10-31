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

    /// `device` names a method that is attestable but no device kernel.
    #[msg(credential = Auth("vote"), device = "proof")]
    pub fn vote(&mut self) {
        self.votes += 1;
    }

    #[attestable]
    pub fn proof(#[public] root: [u8; 32]) {
        let _ = root;
    }
}

fn main() {}
