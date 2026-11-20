use vos_sdk::prelude::*;

#[actor]
pub struct Poll {
    votes: Cell<u64>,
}

#[messages]
impl Poll {
    /// The guard takes device proofs of `proof`, a device kernel: the
    /// handler takes its claim first.
    #[msg(proven = proof)]
    pub fn vote(&mut self, claim: [u8; 32], weight: u64) {
        let _ = claim;
        self.votes.set(&(self.votes.get_or_default() + weight));
    }

    /// The stock `owner` kernel's guard.
    #[msg(credential = Owner)]
    pub fn pay(&mut self) {}

    /// Sized on a run of its reference, with a size's headroom.
    #[attestable(device, reference = reference, headroom = 1)]
    pub fn proof(#[public] root: [u8; 32]) {
        let _ = root;
    }
}

fn reference() -> poll::Proof {
    poll::Proof { root: [0; 32] }
}

fn main() {}
