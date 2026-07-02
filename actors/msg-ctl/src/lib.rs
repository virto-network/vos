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
//!
//! ## Module layout
//!
//! - [`consts`] — the commit-id domain tag and sizing/paging bounds.
//! - [`rows`] — wire types (`CommitRow`, `CommitOutcome`, `CtlHead`).
//! - [`roles`] — the [`MsgCtlRole`] gate + [`MSG_CTL_SPACE_ROLE_MAP`].
//!
//! `Status` — the handler return type — lives here rather than in its own
//! module: every `#[msg]` handler below returns it, so it reads best kept
//! next to the actor it gates.

#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "wasm32", no_std)]

pub mod consts;
pub mod roles;
pub mod rows;

#[cfg(test)]
mod tests;

pub use consts::*;
pub use roles::{MSG_CTL_SPACE_ROLE_MAP, MsgCtlRole};
pub use rows::{CommitOutcome, CommitRow, CtlHead, commit_record_id};

use vos::prelude::*;

// ── Status codes ──────────────────────────────────────────────────

/// Outcome of a commit submission. `Ok` means this commit won its epoch.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum Status {
    /// This commit is the epoch's winner.
    Ok = 0,
    /// An argument was empty or otherwise malformed.
    InvalidInput = 1,
    /// A byte field exceeded its size budget.
    TooLarge = 2,
    /// The epoch already has a winning commit. The caller lost the
    /// race: fetch the winner via `commit_at(epoch)`, process it,
    /// and re-issue at the next epoch.
    EpochTaken = 3,
    /// The epoch is ahead of the chain — the caller built a commit
    /// on epochs this sequencer hasn't seen, which can't happen if
    /// it processed the chain first. Refused so a gap never enters
    /// the record.
    EpochGap = 4,
}

impl Status {
    /// Decode a status byte (the over-the-wire discriminant) back into a
    /// `Status`. `None` for an unknown byte.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidInput),
            2 => Some(Self::TooLarge),
            3 => Some(Self::EpochTaken),
            4 => Some(Self::EpochGap),
            _ => None,
        }
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Status::Ok => "ok",
            Status::InvalidInput => "invalid input",
            Status::TooLarge => "too large",
            Status::EpochTaken => "epoch taken",
            Status::EpochGap => "epoch gap",
        })
    }
}

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
    /// [`Status::EpochTaken`] and re-issues after processing the
    /// winner. Re-submitting the winning record itself is
    /// idempotent (`Status::Ok`).
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
        let reply = |status: Status| CommitOutcome { status, next_epoch };

        if commit_body.is_empty() || (welcome.is_empty() != welcome_hint.is_empty()) {
            return reply(Status::InvalidInput);
        }
        if commit_body.len() > MAX_BODY_BYTES
            || welcome.len() > MAX_BODY_BYTES
            || commit_body.len() + welcome.len() > MAX_ROW_BYTES
        {
            return reply(Status::TooLarge);
        }
        let welcome_hint = match hint_to_32(&welcome_hint) {
            Some(h) => h,
            None => return reply(Status::InvalidInput),
        };
        let id = commit_record_id(epoch, ts_ms, &commit_body, &welcome, &welcome_hint);
        if epoch < next_epoch {
            let winner = &self.commits[epoch as usize];
            if winner.id == id {
                return reply(Status::Ok);
            }
            return reply(Status::EpochTaken);
        }
        if epoch > next_epoch {
            return reply(Status::EpochGap);
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
            status: Status::Ok,
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
    b.try_into().ok()
}
