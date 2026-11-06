use vos_sdk::prelude::*;

/// Every merge field, a merge handler of each kind of write, with and
/// without its context, and queries that read them.
#[actor]
pub struct Notes {
    tags: crdt::GSet<String>,
    items: crdt::Set<u64, Ordered>,
    titles: crdt::Map<u64, String>,
}

#[messages]
impl Notes {
    pub fn new() -> Self {
        Self {
            tags: Default::default(),
            items: Default::default(),
            titles: Default::default(),
        }
    }

    #[msg(merge)]
    pub async fn tag(&mut self, tag: String) {
        self.tags.insert(&tag);
    }

    #[msg(merge, gas = 1_000_000)]
    pub async fn toggle(&mut self, item: u64, on: bool) {
        if on {
            self.items.insert(&item);
        } else {
            self.items.remove(&item);
        }
    }

    #[msg(merge)]
    pub async fn stamp(&mut self, ctx: &mut MergeContext<Self>, key: u64) -> u64 {
        let now = ctx.now();
        self.titles.insert(&key, &String::from("stamped"));
        self.titles.remove(&(key + 1));
        let _ = (ctx.random(), ctx.me());
        now
    }

    #[msg]
    pub async fn read(&self, key: u64) -> (bool, Vec<u64>, Vec<(u64, String)>) {
        let _ = self.titles.get(&key);
        (
            self.tags.contains(&String::from("home")),
            self.items.iter(None).collect(),
            self.titles.iter(Some(&key)).collect(),
        )
    }
}

fn main() {}
