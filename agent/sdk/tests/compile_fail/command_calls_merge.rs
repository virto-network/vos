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

    #[msg(merge)]
    pub async fn tag(&mut self, tag: u64) {
        self.tags.insert(&tag);
    }

    /// A merge handler runs on the merge entry alone: no handler calls it.
    #[msg]
    pub async fn relay(&mut self, ctx: &mut Command<Self>, tag: u64) {
        let _ = ctx
            .call(Ref::<Notes>::new(InstanceId(1)), notes::Tag { tag })
            .await;
    }
}

fn main() {}
