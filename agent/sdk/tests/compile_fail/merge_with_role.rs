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

    /// A merge handler runs on every device that applies its operation, by
    /// its author: no role admits it.
    #[msg(merge, role = "Member")]
    pub async fn tag(&mut self, tag: u64) {
        self.tags.insert(&tag);
    }
}

fn main() {}
