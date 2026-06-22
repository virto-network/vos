//! Msg-ctl actor — the control plane of one messaging channel.
//!
//! A linear chain of MLS handshake records. One agent instance =
//! one channel, paired with that channel's `msg-log` data plane.
//! MLS group state advances in epochs, and the protocol tolerates
//! exactly **one Commit per epoch** — concurrent Commits fork the
//! group, and members who merged the losing fork cannot rewind.
//! This actor is the sequencer that makes the winner well-defined:
//! a `commit` for an epoch that already has one is rejected, so a
//! losing committer reprocesses the winner and re-issues at the
//! next epoch instead of stranding anyone.
//!
//! Sequencing is only as strong as the agent's consistency mode:
//! run with `consistency = "raft"` the accept/reject decision is
//! linearized across replicas and the guarantee is absolute. (A
//! crdt-mode deployment replicates the chain fine but two replicas
//! can accept different commits for the same epoch while
//! partitioned — only safe while a single member issues commits,
//! e.g. a channel whose creator does all the inviting.)
//!
//! Bodies are opaque MLS messages: a Commit (and optional Welcome
//! for members it adds) produced and consumed by the messenger
//! extension. Commits are encrypted to the group where the
//! ciphersuite allows; the Welcome is encrypted to the joiner's
//! KeyPackage. Nothing here needs plaintext.

#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "wasm32", no_std)]

use vos::prelude::*;

// ── Constants ─────────────────────────────────────────────────────

/// Domain tag for commit-record ids.
pub const COMMIT_ID_DOMAIN_TAG: &[u8] = b"vos-msg-commit/v1";

/// Per-field ciphertext bound. Keeps a `CommitRow` small and a
/// `commits` page predictable; the host's hard reply ceiling is far
/// higher (8 MiB), so this is a sizing choice, not a correctness
/// bound. Commit + welcome together are also held under
/// [`MAX_ROW_BYTES`].
pub const MAX_BODY_BYTES: usize = 8 * 1024;

/// Combined bound on `commit_body + welcome` so one row stays small.
/// Generous for small groups (an OpenMLS Welcome for a handful of
/// members is a few KiB); larger groups need welcome-by-blob-
/// reference, which can land without changing this actor's chain
/// semantics.
pub const MAX_ROW_BYTES: usize = 12 * 1024;

/// Byte budget for one `commits` page (same dispatch-cap
/// reasoning as msg-log's history paging).
pub const PAGE_BYTE_BUDGET: usize = 12 * 1024;

/// Hard cap on rows per `commits` page.
pub const PAGE_MAX_ROWS: u32 = 16;

// ── Status codes ──────────────────────────────────────────────────

pub const STATUS_OK: u8 = 0;
pub const STATUS_INVALID_INPUT: u8 = 1;
pub const STATUS_TOO_LARGE: u8 = 2;
/// The epoch already has a winning commit. The caller lost the
/// race: fetch the winner via `commit_at(epoch)`, process it,
/// and re-issue at the next epoch.
pub const STATUS_EPOCH_TAKEN: u8 = 3;
/// The epoch is ahead of the chain — the caller built a commit
/// on epochs this sequencer hasn't seen, which can't happen if
/// it processed the chain first. Refused so a gap never enters
/// the record.
pub const STATUS_EPOCH_GAP: u8 = 4;

// ── Wire types ────────────────────────────────────────────────────

/// One accepted commit. `epoch` is the epoch the commit was
/// *created at*; processing it advances the group to `epoch + 1`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CommitRow {
    /// Content-derived id — see [`commit_record_id`]. What a
    /// losing committer compares against to confirm its own
    /// commit lost.
    pub id: [u8; 32],
    pub epoch: u64,
    /// Sender wall clock, display only.
    pub ts_ms: u64,
    /// Opaque MLS Commit message.
    pub commit_body: Vec<u8>,
    /// Opaque MLS Welcome for members this commit added; empty
    /// when the commit added nobody.
    pub welcome: Vec<u8>,
    /// blake2b-256 of the joiner's KeyPackage so the joiner can
    /// spot its Welcome without trial-decrypting every record;
    /// zeroed when `welcome` is empty.
    pub welcome_hint: [u8; 32],
}

/// Reply shape for `commit`.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CommitOutcome {
    /// `STATUS_*` — `STATUS_OK` means this commit is the epoch's
    /// winner.
    pub status: u8,
    /// The epoch the chain expects next (= its current length).
    /// On `STATUS_EPOCH_TAKEN`/`GAP` this tells the caller how
    /// far behind/ahead it is.
    pub next_epoch: u64,
}

/// Reply shape for `head` — enough for a poller to decide
/// whether new commits exist.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct CtlHead {
    pub next_epoch: u64,
}

/// Content-derived id over every field of the record.
pub fn commit_record_id(
    epoch: u64,
    ts_ms: u64,
    commit_body: &[u8],
    welcome: &[u8],
    welcome_hint: &[u8; 32],
) -> [u8; 32] {
    vos::crypto::blake2b_hash(
        COMMIT_ID_DOMAIN_TAG,
        &[
            &epoch.to_le_bytes(),
            &ts_ms.to_le_bytes(),
            commit_body,
            welcome,
            welcome_hint,
        ],
    )
}

// ── Roles ─────────────────────────────────────────────────────────

/// Local role hierarchy. Any space member may submit commits —
/// whether a commit is *cryptographically* valid is MLS's job
/// (a non-member can't produce one the group accepts); the role
/// gate just keeps strangers from growing the chain.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum MsgCtlRole {
    None = 0,
    Reader = 1,
    Committer = 2,
}

impl vos::RoleByte for MsgCtlRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::Reader),
            2 => Some(Self::Committer),
            _ => None,
        }
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

pub const MSG_CTL_SPACE_ROLE_MAP: vos::SpaceRoleMap<MsgCtlRole> = vos::SpaceRoleMap {
    admin: Some(MsgCtlRole::Committer),
    developer: Some(MsgCtlRole::Committer),
    member: Some(MsgCtlRole::Committer),
    guest: None,
};

// ── Actor ─────────────────────────────────────────────────────────

#[actor(
    role = MsgCtlRole,
    default_role = MsgCtlRole::Reader,
    space_role_map = MSG_CTL_SPACE_ROLE_MAP
)]
pub struct MsgCtl {
    /// The linear commit chain; `commits[n]` is the winner of
    /// epoch `n`, so `commits.len()` is the next expected epoch.
    commits: Vec<CommitRow>,
}

#[messages]
impl MsgCtl {
    pub fn new() -> Self {
        Self {
            commits: Vec::new(),
        }
    }

    /// Submit the MLS Commit created at `epoch`. First writer for
    /// the chain's next epoch wins; everyone else gets
    /// [`STATUS_EPOCH_TAKEN`] and re-issues after processing the
    /// winner. Re-submitting the winning record itself is
    /// idempotent (`STATUS_OK`).
    #[msg(role = MsgCtlRole::Committer)]
    async fn commit(
        &mut self,
        epoch: u64,
        ts_ms: u64,
        commit_body: Vec<u8>,
        welcome: Vec<u8>,
        welcome_hint: Vec<u8>,
    ) -> CommitOutcome {
        let next_epoch = self.commits.len() as u64;
        let reply = |status: u8| CommitOutcome { status, next_epoch };

        if commit_body.is_empty() || (welcome.is_empty() != welcome_hint.is_empty()) {
            return reply(STATUS_INVALID_INPUT);
        }
        if commit_body.len() > MAX_BODY_BYTES
            || welcome.len() > MAX_BODY_BYTES
            || commit_body.len() + welcome.len() > MAX_ROW_BYTES
        {
            return reply(STATUS_TOO_LARGE);
        }
        let welcome_hint = match hint_to_32(&welcome_hint) {
            Some(h) => h,
            None => return reply(STATUS_INVALID_INPUT),
        };
        let id = commit_record_id(epoch, ts_ms, &commit_body, &welcome, &welcome_hint);
        if epoch < next_epoch {
            let winner = &self.commits[epoch as usize];
            if winner.id == id {
                return reply(STATUS_OK);
            }
            return reply(STATUS_EPOCH_TAKEN);
        }
        if epoch > next_epoch {
            return reply(STATUS_EPOCH_GAP);
        }
        self.commits.push(CommitRow {
            id,
            epoch,
            ts_ms,
            commit_body,
            welcome,
            welcome_hint,
        });
        CommitOutcome {
            status: STATUS_OK,
            next_epoch: next_epoch + 1,
        }
    }

    /// Page the chain starting at `from_epoch`, in epoch order.
    /// The page ends at `limit` rows, [`PAGE_MAX_ROWS`], or
    /// [`PAGE_BYTE_BUDGET`] — whichever bites first; callers
    /// continue from `last.epoch + 1`.
    #[msg]
    async fn commits(&self, from_epoch: u64, limit: u32) -> Vec<CommitRow> {
        let max_rows = limit.min(PAGE_MAX_ROWS) as usize;
        let mut out = Vec::new();
        let mut budget = PAGE_BYTE_BUDGET;
        let mut idx = from_epoch as usize;
        while idx < self.commits.len() && out.len() < max_rows {
            let row = &self.commits[idx];
            let cost = 96 + row.commit_body.len() + row.welcome.len();
            if cost > budget && !out.is_empty() {
                break;
            }
            budget = budget.saturating_sub(cost);
            out.push(row.clone());
            idx += 1;
        }
        out
    }

    /// Fetch one epoch's winning commit.
    #[msg]
    async fn commit_at(&self, epoch: u64) -> Option<CommitRow> {
        self.commits.get(epoch as usize).cloned()
    }

    /// Cheap poll target.
    #[msg]
    async fn head(&self) -> CtlHead {
        CtlHead {
            next_epoch: self.commits.len() as u64,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Normalise a wire hint: empty means "none" (all-zero), anything
/// else must be exactly 32 bytes.
fn hint_to_32(b: &[u8]) -> Option<[u8; 32]> {
    if b.is_empty() {
        return Some([0u8; 32]);
    }
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::Message;
    use vos::actors::context::ServiceId;

    fn ctl() -> MsgCtl {
        MsgCtl::new()
    }

    /// Handler futures never await anything external, so a single
    /// poll with a no-op waker resolves them — no executor (or
    /// vos `std` feature) needed in this crate's unit tests.
    fn run<F: core::future::Future>(fut: F) -> F::Output {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn raw() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw()
            }
            fn noop(_: *const ()) {}
            RawWaker::new(
                core::ptr::null(),
                &RawWakerVTable::new(clone, noop, noop, noop),
            )
        }
        let waker = unsafe { Waker::from_raw(raw()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = core::pin::pin!(fut);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("actor handler future was not immediately ready"),
        }
    }

    fn dispatch<M>(c: &mut MsgCtl, msg: M) -> <MsgCtl as Message<M>>::Output
    where
        MsgCtl: Message<M>,
    {
        let mut ctx: vos::Context<MsgCtl> = vos::Context::new(ServiceId(0));
        run(<MsgCtl as Message<M>>::handle(c, msg, &mut ctx))
    }

    fn submit(c: &mut MsgCtl, epoch: u64, body: &[u8]) -> CommitOutcome {
        dispatch(
            c,
            Commit {
                epoch,
                ts_ms: 1000 + epoch,
                commit_body: body.to_vec(),
                welcome: Vec::new(),
                welcome_hint: Vec::new(),
            },
        )
    }

    #[test]
    fn chain_advances_one_epoch_at_a_time() {
        let mut c = ctl();
        assert_eq!(
            submit(&mut c, 0, b"add-bob"),
            CommitOutcome {
                status: STATUS_OK,
                next_epoch: 1
            }
        );
        assert_eq!(
            submit(&mut c, 1, b"add-carol"),
            CommitOutcome {
                status: STATUS_OK,
                next_epoch: 2
            }
        );
        assert_eq!(dispatch(&mut c, Head), CtlHead { next_epoch: 2 });
    }

    #[test]
    fn second_commit_for_an_epoch_is_rejected_with_the_winner_intact() {
        // The MLS fork-prevention property: exactly one commit
        // wins each epoch; the loser is told to reprocess.
        let mut c = ctl();
        submit(&mut c, 0, b"alice-wins");
        let outcome = submit(&mut c, 0, b"bob-loses");
        assert_eq!(outcome.status, STATUS_EPOCH_TAKEN);
        assert_eq!(outcome.next_epoch, 1);
        let winner = dispatch(&mut c, CommitAt { epoch: 0 }).unwrap();
        assert_eq!(winner.commit_body, b"alice-wins");
    }

    #[test]
    fn resubmitting_the_winner_is_idempotent() {
        let mut c = ctl();
        submit(&mut c, 0, b"same");
        let again = submit(&mut c, 0, b"same");
        assert_eq!(again.status, STATUS_OK);
        assert_eq!(dispatch(&mut c, Head), CtlHead { next_epoch: 1 });
    }

    #[test]
    fn epoch_gap_is_refused() {
        // A commit built on unseen epochs means the caller skipped
        // processing the chain — never let a hole into the record.
        let mut c = ctl();
        let outcome = submit(&mut c, 3, b"from-the-future");
        assert_eq!(outcome.status, STATUS_EPOCH_GAP);
        assert_eq!(outcome.next_epoch, 0);
        assert_eq!(dispatch(&mut c, Head), CtlHead { next_epoch: 0 });
    }

    #[test]
    fn welcome_and_hint_must_travel_together() {
        let mut c = ctl();
        let outcome = dispatch(
            &mut c,
            Commit {
                epoch: 0,
                ts_ms: 0,
                commit_body: b"add".to_vec(),
                welcome: b"welcome-bytes".to_vec(),
                welcome_hint: Vec::new(),
            },
        );
        assert_eq!(outcome.status, STATUS_INVALID_INPUT);
        let outcome = dispatch(
            &mut c,
            Commit {
                epoch: 0,
                ts_ms: 0,
                commit_body: b"add".to_vec(),
                welcome: b"welcome-bytes".to_vec(),
                welcome_hint: vec![7u8; 32],
            },
        );
        assert_eq!(outcome.status, STATUS_OK);
        let row = dispatch(&mut c, CommitAt { epoch: 0 }).unwrap();
        assert_eq!(row.welcome, b"welcome-bytes");
        assert_eq!(row.welcome_hint, [7u8; 32]);
    }

    #[test]
    fn size_bounds_are_enforced() {
        let mut c = ctl();
        let over = vec![0u8; MAX_BODY_BYTES + 1];
        assert_eq!(submit(&mut c, 0, &over).status, STATUS_TOO_LARGE);
        // Each field within bounds but the row over the combined cap.
        let body = vec![0u8; 7 * 1024];
        let welcome = vec![1u8; 7 * 1024];
        let outcome = dispatch(
            &mut c,
            Commit {
                epoch: 0,
                ts_ms: 0,
                commit_body: body,
                welcome,
                welcome_hint: vec![7u8; 32],
            },
        );
        assert_eq!(outcome.status, STATUS_TOO_LARGE);
        assert_eq!(dispatch(&mut c, Head), CtlHead { next_epoch: 0 });
    }

    #[test]
    fn commits_pages_in_epoch_order() {
        let mut c = ctl();
        for e in 0..5u64 {
            submit(&mut c, e, format!("c{e}").as_bytes());
        }
        let first = dispatch(
            &mut c,
            Commits {
                from_epoch: 0,
                limit: 2,
            },
        );
        assert_eq!(first.len(), 2);
        assert_eq!(first[1].epoch, 1);
        let rest = dispatch(
            &mut c,
            Commits {
                from_epoch: first.last().unwrap().epoch + 1,
                limit: 10,
            },
        );
        assert_eq!(rest.len(), 3);
        assert_eq!(rest[0].commit_body, b"c2");
    }

    #[test]
    fn commits_paging_respects_byte_budget_but_returns_progress() {
        let mut c = ctl();
        let big = vec![0xAAu8; 7 * 1024];
        submit(&mut c, 0, &big);
        submit(&mut c, 1, &big);
        let rows = dispatch(
            &mut c,
            Commits {
                from_epoch: 0,
                limit: 10,
            },
        );
        assert_eq!(rows.len(), 1, "two 7 KiB commits exceed the 12 KiB budget");
    }
}
