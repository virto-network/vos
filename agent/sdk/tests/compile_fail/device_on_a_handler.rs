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

    /// Only an attestable method is a device kernel.
    #[msg(device)]
    pub fn vote(&mut self) {
        self.votes += 1;
    }
}

fn main() {}
