//! The path held, refreshed apart from proofs (`slice-7-mobile.md` pin G,
//! pin L) [decided, S38]: fetched when `root()` moves and on a jittered
//! timer, never because a proof is about to be made, so a fetch's time
//! says nothing of a proof's. The client polls `root()` on a jittered timer
//! of its own and sends the queries on a connection of their own, apart
//! from the one that carries its proofs: the keeper only says when.
//!
//! **Freshness.** The credential actor's ring holds the last 64 roots, one
//! a tree-changing batch, and accepts a superseded root for
//! `ROOT_MAX_AGE` (10 minutes) while the ring still holds it. A held root
//! leaves the ring after 64 tree-changing batches, which in a busy space
//! comes before its age: the timer's period must be well under the time
//! the space takes to make 64 such batches, not merely under
//! `ROOT_MAX_AGE`. The timer fetches the path at least once a period, and
//! a `root()` answer that moved (the query names no member) fetches it
//! sooner, within [`PathKeeper::MOVED_SPREAD_MS`], so a held root is at most one period behind the tree: it
//! survives unless the space makes 64 tree-changing batches within one
//! period ([`PathKeeper::PERIOD_MS`], 30 s, with its jitter at most 45 s:
//! about 1.4 such batches a second, held for that long). A space faster
//! than that meets `RootUnknown`, which [`PathKeeper::unknown`] answers:
//! the path is dropped, fetched again at once, and the period halved (to
//! at least [`PathKeeper::MIN_PERIOD_MS`]) for the space's pace; it doubles
//! back toward the default at each fetch that finds the root unmoved.

use crate::{AuthWitness, DeviceError, Digest};

/// The member's path, and when to fetch again.
pub struct PathKeeper {
    member: Digest,
    held: Option<AuthWitness>,
    /// When the timer is next due, by the client's clock in milliseconds.
    next: u64,
    /// The timer's period before its jitter.
    period: u64,
    /// Whether a moved root has brought the timer forward since the last
    /// fetch.
    moved: bool,
}

impl PathKeeper {
    /// The timer's period, before its jitter of half a period either way:
    /// one twentieth of `ROOT_MAX_AGE`.
    pub const PERIOD_MS: u64 = vos_wire::defaults::ROOT_MAX_AGE / 20;
    /// The least period a run of `RootUnknown` answers halves it to.
    pub const MIN_PERIOD_MS: u64 = 1_000;
    /// The spread of the fetch a moved root brings forward: drawn
    /// uniformly below it, so the members online at a tree change do not
    /// all fetch at once.
    pub const MOVED_SPREAD_MS: u64 = 10_000;

    /// A keeper for `member`, holding no path: due at once.
    pub fn new(member: Digest) -> Self {
        Self {
            member,
            held: None,
            next: 0,
            period: Self::PERIOD_MS,
            moved: false,
        }
    }

    /// Whether to fetch the path now: none is held, or the jittered timer
    /// is due. `root`, the latest `root()` answer if one was read, brings
    /// the timer forward when it is not the held path's: to a time drawn
    /// below [`PathKeeper::MOVED_SPREAD_MS`] after the moment it is first
    /// seen, so a tree change does not make every online member fetch at
    /// once.
    pub fn due(&mut self, now_ms: u64, root: Option<&Digest>) -> bool {
        let Some(held) = &self.held else {
            return true;
        };
        if root.is_some_and(|root| *root != held.root) && !self.moved {
            self.moved = true;
            self.next = self
                .next
                .min(now_ms.saturating_add(jitter(Self::MOVED_SPREAD_MS)));
        }
        now_ms >= self.next
    }

    /// Holds `witness`, fetched at `now_ms`, and sets the timer: its next
    /// due time drawn uniformly between half a period and one and a half
    /// periods ahead. A path that does not place this member's leaf under
    /// its root is refused, and the one held kept.
    pub fn update(&mut self, witness: AuthWitness, now_ms: u64) -> Result<(), DeviceError> {
        if !witness.proves(&self.member) {
            return Err(DeviceError::Witness);
        }
        if self
            .held
            .as_ref()
            .is_some_and(|held| held.root == witness.root)
        {
            self.period = (self.period * 2).min(Self::PERIOD_MS);
        }
        self.held = Some(witness);
        self.moved = false;
        self.next = now_ms.saturating_add(self.period / 2 + jitter(self.period));
        Ok(())
    }

    /// The path a proof uses: the one held, with no fetch before it.
    pub fn witness(&self) -> Option<&AuthWitness> {
        self.held.as_ref()
    }

    /// A `RootUnknown` answer to a proof on the held path: the ring no
    /// longer holds its root (64 later tree-changing batches, a replica's
    /// lag, or a root replaced at its own batch time). The path is
    /// dropped, so [`PathKeeper::due`] says to fetch it again and the
    /// call is proved anew on the new one; the period is halved, to at
    /// least [`PathKeeper::MIN_PERIOD_MS`].
    pub fn unknown(&mut self) {
        self.held = None;
        self.period = (self.period / 2).max(Self::MIN_PERIOD_MS);
    }

    /// The timer's period now, before its jitter.
    pub fn period(&self) -> u64 {
        self.period
    }
}

/// A uniform draw below `period` from the operating system; 0 if it has
/// no randomness to give.
fn jitter(period: u64) -> u64 {
    let mut bytes = [0; 8];
    if period == 0 || getrandom::getrandom(&mut bytes).is_err() {
        return 0;
    }
    u64::from_le_bytes(bytes) % period
}
