use vos_sdk::prelude::*;

#[actor]
pub struct Poll {
    votes: Cell<u64>,
}

#[messages]
impl Poll {
    /// The stock owner kernel's guard is `credential = Owner`.
    #[msg(proven = owner)]
    pub fn vote(&mut self) {
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
