use vos_sdk::prelude::*;

#[actor]
pub struct Poll {
    votes: Cell<u64>,
}

#[messages]
impl Poll {
    /// Only an attestable method is a device kernel.
    #[msg(device)]
    pub fn vote(&mut self) {
        self.votes.set(&(self.votes.get_or_default() + 1));
    }
}

fn main() {}
