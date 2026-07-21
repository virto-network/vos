//! Tally — a witness-delivered **Task** actor (`#[actor(task)]`).
//!
//! The canonical `Child::Task` fixture: input arrives as `(state, msg)`
//! patched into the `__VOS_WITNESS` buffer, no READ/FETCH, one message
//! per invocation, state travels through the parent's TaskRecord. The
//! live≡traced gate in `vos/tests/elf_integration.rs` runs this blob
//! both ways and asserts byte-identical images and work-results.

use vos::prelude::*;
use vos::storage::StorageMap;

#[actor(task)]
struct Tally {
    total: u64,
    steps: u32,
    /// Witnessed-read fixture: a Task has no live storage, so gets on
    /// this map are served from the rows the invoking parent named
    /// (staged from ITS keyspace under this same `s/saved/` prefix) —
    /// and panic as unproven for any key the parent didn't name.
    #[storage(prefix = "s/saved/")]
    saved: StorageMap<u64, u64>,
}

#[messages]
impl Tally {
    fn new() -> Self {
        Tally {
            total: 0,
            steps: 0,
            saved: Default::default(),
        }
    }

    /// Fold the witnessed values at `a` and `b` into the total —
    /// absent rows count zero (proven absence), unnamed rows panic
    /// (unproven read). The witnessed-read e2e drives this.
    #[msg]
    async fn add_saved(&mut self, a: u64, b: u64) -> u64 {
        self.total += self.saved.get(&a).unwrap_or(0);
        self.total += self.saved.get(&b).unwrap_or(0);
        self.total
    }

    /// One-shot: fold `n` into the running total and reply with it.
    #[msg]
    async fn add(&mut self, n: u64) -> u64 {
        self.total += n;
        self.total
    }

    /// Like `add`, but also persists an audit row. Task effects fold
    /// into the invoking parent's keyspace (a Task has no rows of its
    /// own) — the fixture the effect-log replay gate leans on: replay
    /// never re-runs the task, so a rebuilt replica gets this row only
    /// from the recorded invoke effects.
    #[msg]
    async fn add_recorded(&mut self, ctx: &mut Context<Self>, n: u64) -> u64 {
        self.total += n;
        ctx.store(b"tally/last_add", &n.to_le_bytes());
        self.total
    }

    /// Multi-step job: each invocation performs one step and yields
    /// until three steps are done — the suspended task is its
    /// TaskRecord, and the parent's drive passes deliver this same
    /// message with the saved state until completion.
    #[msg]
    async fn work(&mut self, ctx: &mut Context<Self>) -> u64 {
        self.steps += 1;
        self.total += u64::from(self.steps);
        if self.steps < 3 {
            ctx.yield_now().await;
        }
        self.total
    }
}
