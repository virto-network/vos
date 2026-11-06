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

    /// No node attests a device kernel's method.
    #[msg]
    pub async fn check(&mut self, ctx: &mut Command<Self>, root: [u8; 32]) -> bool {
        ctx.attest(poll::Proof { root }).await.is_ok()
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
