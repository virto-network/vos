//! Merge fields on a device: a grow-only set of tags, an add/remove set
//! of items, and last-writer-wins maps of titles and counts, written by
//! merge handlers and read by queries; and probes of what the merge entry
//! refuses.

#![no_std]

extern crate alloc;

use alloc::format;

use vos_sdk::prelude::*;

#[actor]
pub struct Notes {
    tags: crdt::GSet<String>,
    items: crdt::Set<u64>,
    titles: crdt::Map<u64, String>,
    counts: crdt::Map<u64, u64>,
    /// A table, which no merge handler may write.
    scratch: Table<u64, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum NotesError {
    #[codec(index = 0)]
    Refused,
}

#[messages]
impl Notes {
    #[msg(merge)]
    pub async fn tag(&mut self, tag: String) {
        self.tags.insert(&tag);
    }

    #[msg(merge)]
    pub async fn add(&mut self, item: u64) {
        self.items.insert(&item);
    }

    #[msg(merge)]
    pub async fn remove(&mut self, item: u64) {
        self.items.remove(&item);
    }

    #[msg(merge)]
    pub async fn title(&mut self, key: u64, title: String) {
        self.titles.insert(&key, &title);
    }

    #[msg(merge)]
    pub async fn untitle(&mut self, key: u64) {
        self.titles.remove(&key);
    }

    /// Title `key` with the operation's time and first random byte: the
    /// same on every device that applies it.
    #[msg(merge)]
    pub async fn stamp(&mut self, ctx: &mut MergeContext<Self>, key: u64) -> String {
        let title = format!("{}:{}", ctx.now(), ctx.random()[0]);
        self.titles.insert(&key, &title);
        title
    }

    #[msg(merge)]
    pub async fn set(&mut self, key: u64, value: u64) {
        self.counts.insert(&key, &value);
    }

    /// Several writes of one element in one operation: the last stands.
    #[msg(merge)]
    pub async fn churn(&mut self, item: u64) {
        self.items.insert(&item);
        self.items.remove(&item);
        self.items.insert(&item);
    }

    /// A merge handler's own error: its operation is not recorded.
    #[msg(merge)]
    pub async fn refuse(&mut self, item: u64) -> Result<(), NotesError> {
        self.items.insert(&item);
        Err(NotesError::Refused)
    }

    /// A merge handler that reads a merge field: trapped.
    #[msg(merge)]
    pub async fn peek(&mut self, item: u64) {
        if !self.items.contains(&item) {
            self.items.insert(&item);
        }
    }

    /// A merge handler that writes a table: trapped.
    #[msg(merge)]
    pub async fn scribble(&mut self, key: u64) {
        self.scratch.insert(&key, &key);
    }

    /// A command, which no merge entry runs.
    #[msg]
    pub async fn bump(&mut self, key: u64) {
        self.scratch.insert(&key, &key);
    }

    #[msg]
    pub async fn has_tag(&self, tag: String) -> bool {
        self.tags.contains(&tag)
    }

    /// The tags, in their order.
    #[msg(gas = 50_000_000)]
    pub async fn tags(&self) -> Vec<String> {
        self.tags.iter(None).collect()
    }

    #[msg]
    pub async fn has(&self, item: u64) -> bool {
        self.items.contains(&item)
    }

    #[msg(gas = 50_000_000)]
    pub async fn items(&self) -> Vec<u64> {
        self.items.iter(None).collect()
    }

    #[msg]
    pub async fn title_of(&self, key: u64) -> Option<String> {
        self.titles.get(&key)
    }

    #[msg(gas = 50_000_000)]
    pub async fn titles(&self) -> Vec<(u64, String)> {
        self.titles.iter(None).collect()
    }

    #[msg]
    pub async fn count(&self, key: u64) -> Option<u64> {
        self.counts.get(&key)
    }

    /// The number of keys with counts, after `after`, at most `limit` of
    /// them: a read of the whole map, a page at a time.
    #[msg(gas = 100_000_000)]
    pub async fn counted(&self, after: Option<u64>, limit: u32) -> (u32, Option<u64>) {
        let mut seen = 0;
        let mut last = None;
        for (key, _) in self.counts.iter(after.as_ref()).take(limit as usize) {
            seen += 1;
            last = Some(key);
        }
        (seen, last)
    }
}
