//! The representative's leader's anchoring. The representative's close of
//! each window, the commit that finishes its cut's build, writes the
//! space's root `S_w` in a row ([`keys::anchor`]): the same bytes on every
//! replica, the cut fixed by the committed log. Its leader signs only those
//! rows, never a root from a batch under proposal, in window order, with
//! the node key, before each batch and every [`ANCHOR_RECHECK`] while one
//! waits, and hands each to the venue, whose client answers at once:
//! - taken: the next window goes too; the window settles once the venue
//!   holds its root;
//! - not yet: it and the later windows wait, and go again;
//! - never: settled, alerted;
//! - unlisted: the leadership is handed to a replica whose node key the
//!   venue lists, at most once a window of the space's clock; with none
//!   listed, an alert, and a wait;
//! - stopped: an alert, and a wait.
//!
//! A window past `MaxRootAge` by the venue's time is settled unsent. One at
//! which the venue holds another root goes only past the divergence guard:
//! the replicas are asked for their rows of it, and the anchor, which the
//! venue keeps as an equivocation's evidence and so ends the space, goes
//! once a quorum of the group holds this root and no replica another. A
//! replica holding another is an apply bug or a cloned store, not a theft:
//! nothing is sent, and the alert says so.

use std::time::{Duration, Instant};

use ed25519_dalek::Signer;
use vos_venue::{AnchorOutcome, Held};
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::vos_anchor::{Anchor, RootKind};

use super::Leader;
use crate::lock;
use crate::node::Inner;
use crate::roots;

/// How long an idle representative's leader waits before it offers a
/// waiting anchor again: a venue's clock a block behind takes it within
/// one.
const ANCHOR_RECHECK: Duration = Duration::from_secs(2);

/// How long the divergence guard waits for the replicas' rows.
const GUARD_WAIT: Duration = Duration::from_secs(2);

/// How many alerts a node keeps ([`Inner::anchor_alerts`]).
const ALERTS: usize = 64;

/// What a representative's leader alerts an operator to: each logged as an
/// error, once until another, and kept, the latest 64
/// (`Node::anchor_alerts`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorAlert {
    /// The venue will never take the window's anchor (its raw code), or
    /// the window aged unsent (none).
    Never { window: u64, code: Option<u32> },
    /// The venue does not list this node's key (its raw code): the
    /// leadership was handed to `to`, a replica whose key it lists, or,
    /// with none listed, waits.
    Unlisted {
        window: u64,
        code: u32,
        to: Option<NodeNumber>,
    },
    /// The space is ended or blocked at the venue (its raw code; 0 when its
    /// client read it so).
    Stopped { window: u64, code: u32 },
    /// The venue holds another root at the window, and replica `replica`
    /// holds another row of it than this one: an apply bug or a cloned
    /// store. Nothing was sent: a restored backup or a cloned store counts
    /// as a compromised node key, and the node is replaced.
    Divergent { window: u64, replica: NodeNumber },
}

impl AnchorAlert {
    fn window(&self) -> u64 {
        match self {
            Self::Never { window, .. }
            | Self::Unlisted { window, .. }
            | Self::Stopped { window, .. }
            | Self::Divergent { window, .. } => *window,
        }
    }
}

/// What a leadership knows of its anchors.
#[derive(Default)]
pub(super) struct Anchoring {
    /// The last window this leadership settled, every one before it
    /// settled too: the venue holds its root, or never takes it.
    settled: Option<u64>,
    /// When this leadership last offered the venue its waiting anchors.
    tried: Option<Instant>,
    /// The last alert it raised: one is raised once until another.
    alerted: Option<AnchorAlert>,
    /// The window of the node's clock in which it last handed its
    /// leadership on, unlisted.
    handed: Option<u64>,
}

/// What the divergence guard found of a window's row on the replicas.
enum Guard {
    /// A quorum of the group, this replica among it, holds this root, and
    /// no replica another.
    Agreed,
    /// That replica holds another root.
    Differs(NodeNumber),
    /// Too few replicas answered with a row.
    Unsure,
}

/// What became of a window's anchor offered to the venue.
enum Offered {
    /// Taken: it settles once the venue holds its root.
    Taken,
    /// Never taken: settled.
    Never,
    /// It waits, and the windows after it.
    Waits,
}

impl Leader {
    /// How long until an idle leader offers its waiting anchors again: a
    /// recheck after its last pass, while a row past the last settled
    /// waits; none while none does.
    pub(super) fn anchor_wait(&self) -> Option<Duration> {
        self.inner.venue.as_ref()?;
        if !self.represents() {
            return None;
        }
        let after = self.anchoring.settled.map(keys::anchor);
        let snapshot = self.inner.store.snapshot();
        let waiting = snapshot
            .scan(self.id, &keys::anchors(), after.as_deref())
            .next()
            .is_some();
        if !waiting {
            return None;
        }
        let since = self
            .anchoring
            .tried
            .map_or(ANCHOR_RECHECK, |at| at.elapsed());
        Some(ANCHOR_RECHECK.saturating_sub(since))
    }

    /// Offer the venue the rows past the last settled, in window order.
    pub(super) async fn anchor(&mut self) {
        let Some(venue) = self.inner.venue.clone() else {
            return;
        };
        if !self.represents() {
            return;
        }
        self.anchoring.tried = Some(Instant::now());
        let settled = self.anchoring.settled;
        let rows = match roots::anchors(&self.inner.store.snapshot(), self.id, settled) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("the anchor rows do not read: {error}");
                return;
            }
        };
        let (space, clock) = self.inner.space_and_clock();
        let now = venue.time().unwrap_or_else(|| (self.inner.clock)());
        let mut settling = true;
        for (window, root) in rows {
            let settled = if vos_venue::aged(&clock, window, now) {
                self.alert(AnchorAlert::Never { window, code: None });
                true
            } else {
                match venue.held(&space, window) {
                    Held::Unread => return,
                    Held::Root(held) if held == root => true,
                    Held::Root(_) if venue.status(&space).waits() => {
                        self.alert(AnchorAlert::Stopped { window, code: 0 });
                        return;
                    }
                    Held::Root(_) => match self.guard(window, &root).await {
                        Guard::Agreed => match self.offer(window, root) {
                            Offered::Waits => return,
                            offered => matches!(offered, Offered::Never),
                        },
                        Guard::Differs(replica) => {
                            self.alert(AnchorAlert::Divergent { window, replica });
                            true
                        }
                        Guard::Unsure => return,
                    },
                    Held::Nothing => match self.offer(window, root) {
                        Offered::Waits => return,
                        offered => matches!(offered, Offered::Never),
                    },
                }
            };
            settling &= settled;
            if settling {
                self.anchoring.settled = Some(window);
            }
        }
    }

    /// Sign the anchor of `root`, the space's root of `window`, with the
    /// node key, and hand it to the venue.
    fn offer(&mut self, window: u64, root: [u8; 32]) -> Offered {
        let Some(venue) = self.inner.venue.clone() else {
            return Offered::Waits;
        };
        let (space, _) = self.inner.space_and_clock();
        let key = &self.inner.node_key;
        let mut anchor = Anchor {
            space,
            window,
            kind: RootKind::Space,
            root,
            signer: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        anchor.signature = key.sign(&anchor.digest(&venue.id())).to_bytes();
        match venue.anchor(&anchor) {
            AnchorOutcome::Taken => Offered::Taken,
            AnchorOutcome::NotYet => Offered::Waits,
            AnchorOutcome::Never(code) => {
                self.alert(AnchorAlert::Never {
                    window,
                    code: Some(code),
                });
                Offered::Never
            }
            AnchorOutcome::Unlisted(code) => {
                let to = self.hand_off();
                self.alert(AnchorAlert::Unlisted { window, code, to });
                Offered::Waits
            }
            AnchorOutcome::Stopped(code) => {
                self.alert(AnchorAlert::Stopped { window, code });
                Offered::Waits
            }
        }
    }

    /// Hand this leadership to a replica of the representative whose node
    /// key the venue's client last read listed, once a window of the
    /// space's clock: the replica, or none when it handed on in this window
    /// already, or none is listed.
    fn hand_off(&mut self) -> Option<NodeNumber> {
        let (space, clock) = self.inner.space_and_clock();
        let open = clock.window((self.inner.clock)());
        if open.is_some() && self.anchoring.handed == open {
            return None;
        }
        let venue = self.inner.venue.as_ref()?;
        let listed = venue.anchor_keys(&space);
        let placement = self.inner.placement(self.id)?;
        let to = placement.replicas.iter().copied().find(|replica| {
            *replica != self.inner.number
                && self
                    .inner
                    .space
                    .as_ref()
                    .and_then(|space| space.node(*replica))
                    .is_some_and(|node| listed.contains(&node.key))
        })?;
        self.anchoring.handed = open;
        self.inner
            .to_group(self.id, crate::group::Local::Transfer(to));
        Some(to)
    }

    /// The divergence guard over `root`, this replica's row of `window`:
    /// the other replicas asked for theirs, for [`GUARD_WAIT`] at most.
    async fn guard(&mut self, window: u64, root: &[u8; 32]) -> Guard {
        let others: Vec<NodeNumber> = self
            .inner
            .placement(self.id)
            .map(|placement| placement.replicas)
            .unwrap_or_default()
            .into_iter()
            .filter(|replica| *replica != self.inner.number)
            .collect();
        let group = others.len() + 1;
        let quorum = group / 2 + 1;
        let wait = self.inner.anchor_rows.register(self.id);
        for replica in &others {
            self.inner.send(
                *replica,
                &PeerMessage::AnchorRow {
                    agent: self.id,
                    token: wait.token,
                    window,
                },
            );
        }
        let deadline = Instant::now() + GUARD_WAIT;
        let (mut agreed, mut answered) = (1, Vec::new());
        while agreed < group {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some((from, row)) = wait.within(left, std::future::pending::<()>()).await else {
                break;
            };
            if answered.contains(&from) {
                continue;
            }
            answered.push(from);
            match row {
                Some(row) if row == *root => agreed += 1,
                Some(_) => return Guard::Differs(from),
                None => {}
            }
        }
        if agreed >= quorum {
            Guard::Agreed
        } else {
            Guard::Unsure
        }
    }

    /// Raise `alert`, unless it is the last raised: logged, and kept.
    fn alert(&mut self, alert: AnchorAlert) {
        if self.anchoring.alerted == Some(alert) {
            return;
        }
        self.anchoring.alerted = Some(alert);
        tracing::error!(
            window = alert.window(),
            ?alert,
            "the representative's anchor"
        );
        let mut alerts = lock(&self.inner.anchor_alerts);
        if alerts.len() == ALERTS {
            alerts.pop_front();
        }
        alerts.push_back(alert);
    }
}

impl Inner {
    /// The representative's leader on node `from` asks for this replica's
    /// row of `window`: answered with it, or none.
    pub(crate) fn on_anchor_row(&self, from: NodeNumber, agent: AgentId, token: u64, window: u64) {
        if !self.admit(agent, from) {
            return;
        }
        let root = roots::anchor_of(&self.store.snapshot(), agent, window)
            .ok()
            .flatten();
        self.send(from, &PeerMessage::AnchorRowAnswer { agent, token, root });
    }

    /// The representative's leaders' alerts here, oldest first.
    pub(crate) fn anchor_alerts(&self) -> Vec<AnchorAlert> {
        lock(&self.anchor_alerts).iter().copied().collect()
    }
}
