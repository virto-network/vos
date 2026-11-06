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

    /// The guard takes device proofs of `proof`, a device kernel.
    #[msg(credential = Auth("vote"), device = "proof")]
    pub fn vote(&mut self) {
        self.votes += 1;
    }

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
