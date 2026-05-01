//! Property-based testing for Raft safety invariants.
//!
//! These tests generate random sequences of inbound RPCs against
//! a single worker and verify that no matter what order or term
//! values arrive, the worker upholds the protocol invariants:
//!
//! 1. **Term monotonicity** — `current_term` never decreases.
//! 2. **At-most-one-vote-per-term** — `voted_for` is set for at
//!    most one peer in any given term.
//! 3. **Log-matching** — once an entry has been written at
//!    `(index, term)`, no other entry at the same index ever has
//!    a different term *unless* the term reported by the worker
//!    itself bumps in between (which authorizes the divergent
//!    leader to truncate). We assert by snapshotting the entry at
//!    each touched index after every RPC and detecting a term
//!    change at the same index without a corresponding worker-term
//!    advance — that's a violation.
//! 4. **Snap-pointer monotonicity** — `snap_last_index` only
//!    moves forward.
//! 5. **Commit-index monotonicity** — `commit_index` only moves
//!    forward.
//!
//! ## Determinism
//!
//! Every random source is seeded from the proptest seed so a
//! shrunk failure replays bit-for-bit. The worker's `Rng` (used
//! for jittered election timeouts) is `SeededRng`, an
//! xorshift64* identical to `StdRng` but with a caller-controlled
//! seed; the per-test seed is mixed in. The `Clock` is `StdClock`
//! but the test windows are wide enough that no spontaneous
//! election fires during the RPC sequence — timing differences
//! between runs don't affect the observable state.

#![cfg(feature = "std")]

use std::sync::{Arc, Mutex};

use futures_executor::block_on;
use proptest::prelude::*;
use vos_raft::{
    AppendEntriesReq, InstallSnapshotReq, LogEntry, Meta, RequestVoteReq, Storage,
    StdClock, Worker, WriteBatch,
};

/// Operations the test can issue against a single worker.
#[derive(Debug, Clone)]
enum Op {
    /// Inbound `AppendEntries` from a peer at `term` with given
    /// `prev_log_index`/`prev_log_term` and `n_entries` filler
    /// entries (all at `term`).
    Append {
        from: u16,
        term: u64,
        prev_log_index: u64,
        prev_log_term: u64,
        leader_commit: u64,
        n_entries: u8,
    },
    /// Inbound `RequestVote` from a peer.
    Vote {
        from: u16,
        term: u64,
        last_log_index: u64,
        last_log_term: u64,
    },
    /// Inbound `InstallSnapshot` from a peer.
    Install {
        from: u16,
        term: u64,
        last_included_index: u64,
        last_included_term: u64,
    },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let peers = 0xBBBBu16..=0xCCCC;
    let term = 0u64..50;
    let idx = 0u64..30;
    let n = 0u8..3;
    prop_oneof![
        (peers.clone(), term.clone(), idx.clone(), term.clone(), idx.clone(), n).prop_map(
            |(from, term, prev_log_index, prev_log_term, leader_commit, n_entries)| Op::Append {
                from,
                term,
                prev_log_index,
                prev_log_term,
                leader_commit,
                n_entries,
            },
        ),
        (peers.clone(), term.clone(), idx.clone(), term.clone()).prop_map(
            |(from, term, last_log_index, last_log_term)| Op::Vote {
                from,
                term,
                last_log_index,
                last_log_term,
            },
        ),
        (peers, term.clone(), idx, term).prop_map(
            |(from, term, last_included_index, last_included_term)| Op::Install {
                from,
                term,
                last_included_index,
                last_included_term,
            },
        ),
    ]
}

/// xorshift64* RNG that the test seeds explicitly so a shrunk
/// failure replays the same election-timer jitter on rerun.
#[derive(Clone)]
struct SeededRng(u64);

impl vos_raft::Rng for SeededRng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// Read-only view into the worker's live storage, captured by
/// the test so it can audit log-matching invariants without
/// exposing internals through the public API.
#[derive(Default)]
struct StorageMirror {
    entries: std::collections::BTreeMap<u64, LogEntry>,
    state: Vec<u8>,
    meta: Meta<u16>,
}

/// `Storage` impl that mirrors all writes into a shared
/// `Arc<Mutex<StorageMirror>>` the test holds a clone of. The
/// worker drives the live state machine; the mirror gives us a
/// snapshot we can introspect after every RPC.
struct SharedStorage {
    mirror: Arc<Mutex<StorageMirror>>,
}

impl Storage<u16> for SharedStorage {
    type Error = core::convert::Infallible;

    fn last_index(&self) -> u64 {
        let m = self.mirror.lock().unwrap();
        m.entries
            .keys()
            .next_back()
            .copied()
            .unwrap_or(m.meta.snap_last_index)
    }
    fn last_term(&self) -> u64 {
        let m = self.mirror.lock().unwrap();
        m.entries
            .values()
            .next_back()
            .map(|e| e.term)
            .unwrap_or(m.meta.snap_last_term)
    }
    fn snap_last_index(&self) -> u64 {
        self.mirror.lock().unwrap().meta.snap_last_index
    }
    fn snap_last_term(&self) -> u64 {
        self.mirror.lock().unwrap().meta.snap_last_term
    }
    async fn term_at(&self, index: u64) -> Result<Option<u64>, Self::Error> {
        let m = self.mirror.lock().unwrap();
        if index == 0 {
            return Ok(Some(0));
        }
        if index < m.meta.snap_last_index {
            return Ok(None);
        }
        if index == m.meta.snap_last_index && m.meta.snap_last_index > 0 {
            return Ok(Some(m.meta.snap_last_term));
        }
        Ok(m.entries.get(&index).map(|e| e.term))
    }
    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry>, Self::Error> {
        let m = self.mirror.lock().unwrap();
        if start > end {
            return Ok(Vec::new());
        }
        let eff_start = start.max(m.meta.snap_last_index + 1);
        Ok(m.entries.range(eff_start..=end).map(|(_, v)| v.clone()).collect())
    }
    async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.mirror.lock().unwrap().state.clone())
    }
    async fn load_meta(&self) -> Result<Meta<u16>, Self::Error> {
        Ok(self.mirror.lock().unwrap().meta.clone())
    }
    async fn commit_batch(&mut self, batch: WriteBatch<u16>) -> Result<(), Self::Error> {
        let mut m = self.mirror.lock().unwrap();
        if let Some(after) = batch.truncate_after {
            m.entries.retain(|k, _| *k <= after);
        }
        if let Some((idx, term)) = batch.compact_to {
            m.entries.retain(|k, _| *k > idx);
            m.meta.snap_last_index = idx;
            m.meta.snap_last_term = term;
        }
        for entry in batch.appends {
            m.entries.insert(entry.index, entry);
        }
        if let Some(state) = batch.state {
            m.state = state;
        }
        if let Some(meta) = batch.meta {
            m.meta = meta;
        }
        Ok(())
    }
}

fn make_worker(seed: u64) -> (Worker<u16>, Arc<Mutex<StorageMirror>>) {
    let mirror: Arc<Mutex<StorageMirror>> = Arc::new(Mutex::new(StorageMirror::default()));
    let storage = SharedStorage {
        mirror: mirror.clone(),
    };
    let mut cfg = vos_raft::Config::new(
        0xAAAA,
        vec![0xAAAA, 0xBBBB, 0xCCCC],
        [0xC0; 32],
    );
    // Long enough that no spontaneous election fires during the
    // property test — we want to observe *only* the random RPC
    // sequence's effect on state.
    cfg.election_timeout_ms = (60_000, 120_000);
    cfg.heartbeat_interval_ms = 50;
    let rng_seed = if seed == 0 { 0xBADC0FFEE } else { seed };
    let worker = Worker::spawn_with(
        storage,
        Arc::new(NoopTransport),
        cfg,
        (),
        StdClock,
        SeededRng(rng_seed),
    );
    (worker, mirror)
}

struct NoopTransport;

#[derive(Debug)]
struct NoopErr;
impl core::fmt::Display for NoopErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "noop")
    }
}
impl std::error::Error for NoopErr {}

impl vos_raft::Transport<u16> for NoopTransport {
    type Error = NoopErr;
    async fn send_append(
        &self,
        _peer: u16,
        _req: AppendEntriesReq<u16>,
    ) -> Result<vos_raft::AppendEntriesResp, NoopErr> {
        Err(NoopErr)
    }
    async fn send_vote(
        &self,
        _peer: u16,
        _req: RequestVoteReq<u16>,
    ) -> Result<vos_raft::RequestVoteResp, NoopErr> {
        Err(NoopErr)
    }
    async fn send_install(
        &self,
        _peer: u16,
        _req: InstallSnapshotReq<u16>,
    ) -> Result<vos_raft::InstallSnapshotResp, NoopErr> {
        Err(NoopErr)
    }
}

proptest! {
    // Each case spawns a fresh worker, so cap the count moderately
    // — thread-spawn dominates the runtime. 256 is a healthy
    // coverage budget that still finishes in ~1s.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// All five claimed invariants checked simultaneously across an
    /// arbitrary RPC sequence:
    ///
    /// 1. term monotonicity
    /// 4. snap-pointer monotonicity
    /// 5. commit-index monotonicity
    /// 3. log-matching: an entry at `(index, term)` doesn't get
    ///    overwritten by a different entry at the same `(index,
    ///    term)`, AND the entry-term never exceeds the worker's
    ///    `current_term` at observation time.
    ///
    /// (Invariant 2, at-most-one-vote-per-term, is in its own test
    /// below.)
    #[test]
    fn invariants_hold_under_random_rpcs(
        seed in any::<u64>(),
        ops in proptest::collection::vec(op_strategy(), 0..50),
    ) {
        let (worker, mirror) = make_worker(seed);
        let h = worker.handler();

        let mut prev_term = 0u64;
        let mut prev_commit = 0u64;
        let mut prev_snap = 0u64;
        // Per-index history: (entry_term, worker_term_at_observation).
        // A different entry_term at the same index in a later
        // observation is a log-matching violation unless the
        // worker's term has advanced between observations (which
        // authorizes a higher-term leader to truncate).
        let mut entry_history: std::collections::BTreeMap<u64, (u64, u64)> =
            std::collections::BTreeMap::new();

        for op in ops {
            match op {
                Op::Append {
                    from, term, prev_log_index, prev_log_term, leader_commit, n_entries,
                } => {
                    let entries: Vec<LogEntry> = (0..n_entries)
                        .map(|i| LogEntry {
                            index: prev_log_index + 1 + u64::from(i),
                            term,
                            payload: vec![i],
                        })
                        .collect();
                    let _ = block_on(h.handle_inbound_append(
                        from,
                        AppendEntriesReq {
                            leader: from,
                            term, prev_log_index, prev_log_term, leader_commit, entries,
                        },
                    ));
                }
                Op::Vote { from, term, last_log_index, last_log_term } => {
                    let _ = block_on(h.handle_inbound_vote(
                        from,
                        RequestVoteReq { candidate: from, term, last_log_index, last_log_term },
                    ));
                }
                Op::Install { from, term, last_included_index, last_included_term } => {
                    let _ = block_on(h.handle_inbound_install(
                        from,
                        InstallSnapshotReq {
                            leader: from,
                            term, last_included_index, last_included_term,
                            snapshot: vec![0xFF; 4],
                        },
                    ));
                }
            }

            let snap = block_on(h.snapshot()).expect("worker alive");

            // Invariant 1: term monotonicity.
            prop_assert!(
                snap.current_term >= prev_term,
                "term went backwards: {} -> {}", prev_term, snap.current_term,
            );
            // Invariant 5: commit-index monotonicity.
            prop_assert!(
                snap.commit_index >= prev_commit,
                "commit_index went backwards: {} -> {}", prev_commit, snap.commit_index,
            );
            // Invariant 4: snap-pointer monotonicity.
            prop_assert!(
                snap.snap_last_index >= prev_snap,
                "snap_last_index went backwards: {} -> {}",
                prev_snap, snap.snap_last_index,
            );
            // Worker's own internal invariant: commit_index
            // always covers the snap pointer (you can't commit
            // less than what's been compacted away).
            prop_assert!(
                snap.commit_index >= snap.snap_last_index,
                "commit_index {} < snap_last_index {}",
                snap.commit_index, snap.snap_last_index,
            );

            // Invariant 3: log-matching. Walk the live entry set
            // through the storage mirror and audit each entry's
            // (index, term) against the history. The mirror tracks
            // the worker's writes verbatim, so we see exactly what
            // the worker stored.
            let snapshot_meta = {
                let m = mirror.lock().unwrap();
                m.entries.iter().map(|(i, e)| (*i, e.term)).collect::<Vec<_>>()
            };
            for (idx, entry_term) in &snapshot_meta {
                prop_assert!(
                    *entry_term <= snap.current_term,
                    "entry term {} > worker current_term {} at index {}",
                    entry_term, snap.current_term, idx,
                );
                if let Some((prev_entry_term, prev_worker_term)) =
                    entry_history.get(idx).copied()
                    && *entry_term != prev_entry_term
                {
                    // Divergence at the same index — only valid
                    // if the worker's term advanced since the
                    // last observation (a higher-term leader's
                    // truncate-and-graft is the authorized path).
                    prop_assert!(
                        snap.current_term > prev_worker_term,
                        "log-matching violation at index {idx}: entry term \
                         changed {prev_entry_term} -> {entry_term} without \
                         worker term advancing (was {prev_worker_term})",
                    );
                }
                entry_history.insert(*idx, (*entry_term, snap.current_term));
            }

            prev_term = snap.current_term;
            prev_commit = snap.commit_index;
            prev_snap = snap.snap_last_index;
        }
    }

    /// Two `RequestVote`s in the same term, from different
    /// candidates: the worker grants at most one of them.
    #[test]
    fn at_most_one_vote_per_term_under_random_pairings(
        seed in any::<u64>(),
        term in 1u64..50,
        cand_a in 0xBBBBu16..=0xBBBE,
        cand_b in 0xBBBFu16..=0xBBC2,
    ) {
        prop_assume!(cand_a != cand_b);
        let (worker, _mirror) = make_worker(seed);
        let h = worker.handler();

        let r1 = block_on(h.handle_inbound_vote(
            cand_a,
            RequestVoteReq {
                candidate: cand_a, term, last_log_index: 0, last_log_term: 0,
            },
        ));
        let r2 = block_on(h.handle_inbound_vote(
            cand_b,
            RequestVoteReq {
                candidate: cand_b, term, last_log_index: 0, last_log_term: 0,
            },
        ));
        // Either we voted for the first only, or neither — never
        // both. (We may grant the second if the term has bumped,
        // but here both calls use the same `term`.)
        prop_assert!(
            !(r1.vote_granted && r2.vote_granted),
            "granted two votes in term {term}: r1={r1:?}, r2={r2:?}",
        );
    }
}
