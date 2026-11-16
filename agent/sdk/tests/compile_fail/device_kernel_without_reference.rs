use vos_sdk::prelude::*;

#[actor]
pub struct Poll {
    votes: Cell<u64>,
}

#[messages]
impl Poll {
    /// A device kernel names the run its program is sized on.
    #[attestable(device)]
    pub fn proof(#[public] root: [u8; 32]) {
        let _ = root;
    }
}

fn main() {}
