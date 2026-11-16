use vos_sdk::prelude::*;

#[actor]
pub struct Poll {
    votes: Cell<u64>,
}

#[messages]
impl Poll {
    /// No venue judges a device's statement.
    #[attestable(device, venue_bound)]
    pub fn proof(#[public] root: [u8; 32]) {
        let _ = root;
    }
}

fn main() {}
