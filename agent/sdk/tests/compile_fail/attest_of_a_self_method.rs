use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    entries: CommittedMap<u32, u64>,
}

#[messages]
impl Counter {
    pub fn new() -> Self {
        Self {
            entries: CommittedMap::default(),
        }
    }

    /// A `&self` method reads at a window's cut alone, from a workflow.
    #[msg]
    pub async fn check(&mut self, ctx: &mut Command<Self>, key: u32) -> u64 {
        ctx.attest(counter::Entry { key }).await.unwrap_or(0)
    }

    #[attestable]
    pub fn entry(&self, key: u32) -> u64 {
        self.entries.get(&key).unwrap_or(0)
    }
}

fn main() {}
