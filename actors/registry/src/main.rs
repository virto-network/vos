//! Hyperspace registry actor.
//!
//! Hosts a CRDT-replicated `name → RegistryEntry` directory. Every
//! node in a hyperspace runs a replica at the well-known
//! `ServiceId::REGISTRY`; cycles 1–8 converge them.
//!
//! Messages (matched by name in the manifest's `on_start` and by
//! the `registry::Client` host helper):
//!
//! - `announce(name, owner_prefix, service_id, [roles])` —
//!   register / replace an entry.
//! - `remove(name)` — clean shutdown.
//! - `lookup(name) -> Option<RegistryEntry>` — point query;
//!   replies as rkyv-encoded bytes inside `Value::Bytes`, or
//!   `Value::Unit` when the name isn't registered.
//! - `list(prefix, after, limit) -> Page` — sorted scan of
//!   names starting with `prefix`, exclusive cursor `after`,
//!   capped at [`registry::MAX_PAGE_SIZE`].
//! - `by_role(role, prefix, after, limit) -> Page` — same
//!   pagination shape, filtered by role membership.

use vos::{actor, messages};

use registry::{Page, RegistryEntry, encode_archived, MAX_PAGE_SIZE};

#[actor]
struct Registry {
    /// Sorted `(name, entry)` pairs. Kept sorted on every
    /// announce so prefix scans and pagination are simple linear
    /// walks. We use `Vec` rather than `BTreeMap::range` because
    /// LLVM's BTreeMap codegen produces PVM-unsupported
    /// instructions (e.g. `slt` with `x0` as rs1) for the
    /// riscv64em-javm target — see `reference_pvm_build` notes.
    entries: Vec<(String, EntryStored)>,
}

/// Stored shape — like [`registry::RegistryEntry`] but without
/// the redundant `name` field, since the entry's tuple slot
/// holds it.
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone)]
#[rkyv(crate = vos::rkyv)]
struct EntryStored {
    owner_prefix: u16,
    service_id: u16,
    roles: Vec<String>,
}

#[messages]
impl Registry {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register or replace `name`. `service_id` and
    /// `owner_prefix` arrive as u32 from the wire because the
    /// dynamic `Msg` arg system treats integers as u32/u64; we
    /// truncate the upper half here.
    #[msg]
    async fn announce(
        &mut self,
        name: String,
        owner_prefix: u32,
        service_id: u32,
        roles: Vec<String>,
    ) {
        let stored = EntryStored {
            owner_prefix: owner_prefix as u16,
            service_id: service_id as u16,
            roles,
        };
        // Sorted-insert: replace on equal key, otherwise insert
        // at the matching position. Linear in the entry count;
        // fine for phase-1 sizes.
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

    /// Returns rkyv-encoded `RegistryEntry` bytes when the name
    /// is registered; returns an empty `Vec<u8>` (which the
    /// reply path encodes as `Value::Bytes(empty)`, decoded as
    /// `Ok(None)` host-side) when it isn't.
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
                };
                return encode_archived(&entry);
            }
            idx += 1;
        }
        Vec::new()
    }

    /// Paginated scan. `prefix` filters by leading-slash path,
    /// `after` is an exclusive cursor (empty = start), `limit`
    /// is capped at [`MAX_PAGE_SIZE`].
    #[msg]
    async fn list(&self, prefix: String, after: String, limit: u32) -> Vec<u8> {
        let page = collect_page(&self.entries, &prefix, &after, limit, &String::new());
        encode_archived(&page)
    }

    /// Same shape as `list`, but only entries whose `roles`
    /// contains `role`.
    #[msg]
    async fn by_role(&self, role: String, prefix: String, after: String, limit: u32) -> Vec<u8> {
        let page = collect_page(&self.entries, &prefix, &after, limit, &role);
        encode_archived(&page)
    }
}

/// Shared pagination machinery for `list` and `by_role`.
/// `role_filter` is empty for the unfiltered `list` case; non-
/// empty for `by_role`. Linear scan over the sorted Vec.
fn collect_page(
    entries: &[(String, EntryStored)],
    prefix: &str,
    after: &str,
    limit: u32,
    role_filter: &str,
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
            // Past the prefix range (entries are sorted), stop.
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
            // We've already filled the page; the previous entry
            // is the cursor for the next call.
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
        });
    }

    Page { entries: out, next }
}
