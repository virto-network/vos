//! Bin entry. The actor framework's `_start` / `accumulate` PVM
//! symbols are emitted by `#[messages]` here so they only ever
//! land in the bin's translation unit. Wire types (
//! [`registry::RegistryEntry`], [`registry::Page`], etc.) live in
//! the lib so other crates can depend on them without pulling in
//! these entry symbols.

#![no_std]

use vos::{actor, messages};

use registry::{encode_archived, Page, RegistryEntry, MAX_PAGE_SIZE};

#[actor]
struct Registry {
    /// Sorted `(name, entry)` pairs. Kept sorted on every
    /// announce so prefix scans and pagination are simple linear
    /// walks. We use `Vec` rather than `BTreeMap::range` because
    /// LLVM's BTreeMap codegen produces PVM-unsupported
    /// instructions (e.g. `slt` with `x0` as rs1) for the
    /// riscv64em-javm target.
    entries: Vec<(String, EntryStored)>,
    /// Monotone tick counter — incremented on every `announce`
    /// and `heartbeat`. Surfaced as `Page::clock` so callers can
    /// age-filter entries.
    tick: u64,
}

/// Stored shape — like `RegistryEntry` but without the
/// redundant `name` field (the entry's tuple slot holds it).
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone)]
#[rkyv(crate = vos::rkyv)]
struct EntryStored {
    owner_prefix: u16,
    service_id: u16,
    roles: Vec<String>,
    last_seen: u64,
}

#[messages]
impl Registry {
    fn new() -> Self {
        Self { entries: Vec::new(), tick: 0 }
    }

    /// Register or replace `name`. `service_id` and
    /// `owner_prefix` arrive as u32 because the dynamic `Msg`
    /// arg system treats integers as u32/u64; we truncate the
    /// upper half here.
    #[msg]
    async fn announce(
        &mut self,
        name: String,
        owner_prefix: u32,
        service_id: u32,
        roles: Vec<String>,
    ) {
        self.tick += 1;
        let stored = EntryStored {
            owner_prefix: owner_prefix as u16,
            service_id: service_id as u16,
            roles,
            last_seen: self.tick,
        };
        let mut idx = 0usize;
        let mut found = false;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                self.entries[idx].1 = stored.clone();
                found = true;
                break;
            }
            if self.entries[idx].0.as_str() > name.as_str() {
                break;
            }
            idx += 1;
        }
        if !found {
            self.entries.insert(idx, (name, stored));
        }
    }

    /// Liveness ping. Bumps the entry's `last_seen` to the
    /// current `tick`. No-op when the name isn't registered.
    #[msg]
    async fn heartbeat(&mut self, name: String) {
        self.tick += 1;
        let mut idx = 0usize;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                self.entries[idx].1.last_seen = self.tick;
                return;
            }
            idx += 1;
        }
    }

    #[msg]
    async fn remove(&mut self, name: String) {
        let mut idx = 0usize;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                self.entries.remove(idx);
                break;
            }
            idx += 1;
        }
    }

    /// Resolve a name to its full `ServiceId` u32. Returns 0
    /// when the name isn't registered. Lighter than `lookup`
    /// for hosts that only need the address — no rkyv schema
    /// involved on the caller side.
    #[msg]
    async fn resolve(&self, name: String) -> u32 {
        let mut idx = 0usize;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                let stored = &self.entries[idx].1;
                return ((stored.owner_prefix as u32) << 16) | (stored.service_id as u32);
            }
            idx += 1;
        }
        0
    }

    /// Returns rkyv-encoded `RegistryEntry` bytes when the name
    /// is registered; returns an empty `Vec<u8>` (decoded host-
    /// side as `Ok(None)`) when it isn't.
    #[msg]
    async fn lookup(&self, name: String) -> Vec<u8> {
        let mut idx = 0usize;
        while idx < self.entries.len() {
            if self.entries[idx].0 == name {
                let stored = &self.entries[idx].1;
                let entry = RegistryEntry {
                    name,
                    owner_prefix: stored.owner_prefix,
                    service_id: stored.service_id,
                    roles: stored.roles.clone(),
                    last_seen: stored.last_seen,
                };
                return encode_archived(&entry);
            }
            idx += 1;
        }
        Vec::new()
    }

    /// Paginated scan. `prefix` filters by leading-slash path,
    /// `after` is an exclusive cursor (empty = start), `limit`
    /// is capped at `MAX_PAGE_SIZE`.
    #[msg]
    async fn list(&self, prefix: String, after: String, limit: u32) -> Vec<u8> {
        let page = collect_page(&self.entries, &prefix, &after, limit, &String::new(), self.tick);
        encode_archived(&page)
    }

    /// Same shape as `list`, but only entries whose `roles`
    /// contains `role`.
    #[msg]
    async fn by_role(&self, role: String, prefix: String, after: String, limit: u32) -> Vec<u8> {
        let page = collect_page(&self.entries, &prefix, &after, limit, &role, self.tick);
        encode_archived(&page)
    }
}

/// Shared pagination machinery for `list` and `by_role`.
fn collect_page(
    entries: &[(String, EntryStored)],
    prefix: &str,
    after: &str,
    limit: u32,
    role_filter: &str,
    clock: u64,
) -> Page {
    let mut limit = limit;
    if limit == 0 || limit > MAX_PAGE_SIZE {
        limit = MAX_PAGE_SIZE;
    }
    let limit = limit as usize;

    let mut out = Vec::new();
    let mut next = String::new();

    let mut idx = 0usize;
    while idx < entries.len() {
        let (name, stored) = &entries[idx];
        idx += 1;

        if !after.is_empty() && name.as_str() <= after {
            continue;
        }
        if !prefix.is_empty() && !name.starts_with(prefix) {
            if !out.is_empty() && name.as_str() > prefix {
                break;
            }
            continue;
        }
        if !role_filter.is_empty() {
            let mut has = false;
            let mut ri = 0usize;
            while ri < stored.roles.len() {
                if stored.roles[ri] == role_filter {
                    has = true;
                    break;
                }
                ri += 1;
            }
            if !has {
                continue;
            }
        }

        if out.len() >= limit {
            if let Some(last) = out.last() {
                let last: &RegistryEntry = last;
                next = last.name.clone();
            }
            break;
        }
        out.push(RegistryEntry {
            name: name.clone(),
            owner_prefix: stored.owner_prefix,
            service_id: stored.service_id,
            roles: stored.roles.clone(),
            last_seen: stored.last_seen,
        });
    }

    Page { entries: out, next, clock }
}

fn main() {}
