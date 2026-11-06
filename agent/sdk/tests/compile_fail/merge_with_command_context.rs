use vos_sdk::prelude::*;

#[actor]
pub struct Notes {
    tags: crdt::GSet<u64>,
}

#[messages]
impl Notes {
    pub fn new() -> Self {
        Self {
            tags: Default::default(),
        }
    }

    /// A merge handler's context reaches nothing past its operation.
    #[msg(merge)]
    pub async fn tag(&mut self, ctx: &mut Command<Self>, tag: u64) {
        self.tags.insert(&tag);
        let _ = ctx;
    }
}

fn main() {}
