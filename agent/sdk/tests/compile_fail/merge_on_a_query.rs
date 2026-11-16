use vos_sdk::prelude::*;

#[actor]
pub struct Notes {
    tags: crdt::GSet<u64>,
}

#[messages]
impl Notes {
    /// A merge handler writes merge fields: it takes `&mut self`.
    #[msg(merge)]
    pub async fn tag(&self, tag: u64) -> bool {
        self.tags.contains(&tag)
    }
}

fn main() {}
