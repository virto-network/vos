//! A window's close, as the leaders drive it. An agent's leader, once its
//! replica has built a window's cut, reports its root there to the space's
//! representative ([`Input::Report`]), saying whether reads wait on the
//! close. The representative's leader, once its replica has built its own
//! cut of the window, which closes it, signs the anchor of the space's
//! root `S_w` with the newest of this node's anchor keys the venue lists
//! and hands it to the venue, then sends
//! each agent that asked its path ([`Input::Close`]). Both are proposed
//! from the replica's state, never queued, and sent once: refine sends
//! nothing for a window its mark has passed ([`keys::reported`],
//! [`keys::close_mark`]).

use std::time::{Duration, Instant};

use ed25519_dalek::Signer;
use vos_venue::AnchorRefusal;
use vos_wire::batch::Input;
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::served::Closing;
use vos_wire::vos_anchor::{Anchor, MAX_ROOT_AGE_MS, RootKind, RootRead, space_root};
use vos_wire::{Decode, defaults};

use super::Leader;
use super::serve::fault;
use crate::fault::{Fault, read};
use crate::node::Pending;
use crate::roots;
use crate::store::Snapshot;

/// The most closes one batch proposes, each at most
/// [`defaults::CLOSE_PATHS`] paths.
const CLOSES: usize = 8;

/// How long an idle representative's leader waits before handing the
/// venue a waiting anchor again: a venue's clock a block behind takes it
/// within one.
const ANCHOR_RECHECK: Duration = Duration::from_secs(2);

/// The closes a leader proposes in a batch, or the hook that stopped it.
pub(super) enum Closes {
    Due(Vec<Pending>),
    /// A test's hook stopped the leader before a close.
    Stopped,
}

/// A window's close to propose: the window, the representative's root at
/// its cut, and the paths not yet sent.
type Unsent = (u64, Closing);

impl Leader {
    /// Whether a report or a close waits on this replica's state.
    pub(super) fn duties_due(&self) -> bool {
        let snapshot = self.inner.store.snapshot();
        self.reports(&snapshot)
            .is_ok_and(|reports| !reports.is_empty())
            || unsent(&snapshot, self.id, self.represents()).is_ok_and(|unsent| !unsent.is_empty())
    }

    /// How long until an idle leader hands the venue a waiting anchor
    /// again, a recheck after the last try, or takes up anchors left
    /// waiting ([`Leader::reseed_wait`]); none while neither is due.
    pub(super) fn anchor_wait(&self) -> Option<Duration> {
        let waiting = (!self.unanchored.is_empty()).then(|| {
            let since = self.anchor_tried.map_or(ANCHOR_RECHECK, |at| at.elapsed());
            ANCHOR_RECHECK.saturating_sub(since)
        });
        waiting.into_iter().chain(self.reseed_wait()).min()
    }

    /// The anchors the venue's client handed back to be signed again
    /// ([`vos_venue::VenueClient::unsettled`]) that this leadership has
    /// not taken up, nor settled for good.
    fn handed_back(&self) -> Vec<Anchor> {
        let Some(venue) = self.inner.venue.as_ref() else {
            return Vec::new();
        };
        let (space, _) = self.inner.space_and_clock();
        venue
            .unsettled(&space)
            .into_iter()
            .filter(|anchor| {
                !self.unanchored.contains_key(&anchor.window)
                    && !self.refused.contains(&anchor.window)
            })
            .collect()
    }

    /// How long until the representative's leader takes up anchors left
    /// waiting: at once for one the venue's client handed back, and its
    /// cut roots ([`Leader::seed_waiting`]) a window length after it last
    /// did. None before this leadership's first batch, which takes them
    /// up, or with no venue.
    fn reseed_wait(&self) -> Option<Duration> {
        self.inner.venue.as_ref()?;
        let seeded = self.seeded?;
        if !self.represents() {
            return None;
        }
        if !self.handed_back().is_empty() {
            return Some(Duration::ZERO);
        }
        let (_, clock) = self.inner.space_and_clock();
        Some(Duration::from_millis(clock.length_ms).saturating_sub(seeded.elapsed()))
    }

    /// Take up the anchors the venue's client handed back: each root
    /// signed again, by the newest key the venue lists, whether or not
    /// this replica still keeps its cut root. Whether to take up the cut
    /// roots' too: at a leadership's first batch, then a window length
    /// after it last did.
    fn take_up(&mut self) -> bool {
        if self.inner.venue.is_none() || !self.represents() {
            return false;
        }
        for anchor in self.handed_back() {
            self.anchored.remove(&anchor.window);
            self.unanchored.insert(anchor.window, anchor.root);
        }
        let (_, clock) = self.inner.space_and_clock();
        let every = Duration::from_millis(clock.length_ms);
        let due = self.seeded.is_none_or(|at| at.elapsed() >= every);
        if due {
            self.seeded = Some(Instant::now());
        }
        due
    }

    /// Whether this agent is its space's representative.
    fn represents(&self) -> bool {
        self.inner.representative() == Some(self.id)
    }

    /// The reports `snapshot` holds due: the root at each cut this replica
    /// keeps past the agent's last report, in window order, and whether
    /// requests wait on its close; none for the representative, or while
    /// the space has none, which this node knows of. A window a test's hook
    /// holds, and those after it, wait.
    pub(super) fn reports(&self, snapshot: &Snapshot) -> Result<Vec<Pending>, Fault> {
        let representative = self
            .inner
            .representative()
            .filter(|to| *to != self.id && self.inner.directory.get(*to).is_some());
        let Some(to) = representative else {
            return Ok(Vec::new());
        };
        let reported =
            read::<(u64, AgentId)>(snapshot, self.id, &keys::reported())?.map(|(window, _)| window);
        let mut due = Vec::new();
        for row in snapshot.scan(self.id, &keys::cut_roots(), None) {
            let (key, value) = row?;
            let Some(window) = keys::cut_root_entry(&key) else {
                continue;
            };
            if reported.is_some_and(|reported| window <= reported) {
                continue;
            }
            if !self.inner.hooks.report(self.id, window) {
                break;
            }
            let Some((root, _)) = <([u8; 32], u64)>::decode_exact(&value) else {
                return Err(fault(roots::Error::Corrupt("a cut root")));
            };
            let pending = !roots::served_at(snapshot, self.id, window)
                .map_err(fault)?
                .is_empty();
            due.push(Pending::Duty(Input::Report {
                to,
                window,
                root,
                pending,
            }));
        }
        Ok(due)
    }

    /// The representative's closes due on `snapshot`, at most [`CLOSES`]
    /// in window order, each window's anchor handed to the venue first
    /// ([`Leader::anchor_due`]).
    pub(super) fn closes(&mut self, snapshot: &Snapshot) -> Result<Closes, Fault> {
        if self.take_up() {
            self.seed_waiting(snapshot)?;
        }
        let unsent = unsent(snapshot, self.id, self.represents())?;
        let first = unsent.first().map(|(window, _)| *window);
        self.anchored
            .retain(|window| first.is_some_and(|first| *window >= first));
        let (space, _) = self.inner.space_and_clock();
        for (window, closing) in &unsent {
            if !self.anchored.contains(window) {
                let root = space_root(&space, *window, &closing.root);
                self.unanchored.entry(*window).or_insert(root);
            }
        }
        self.anchor_due();
        let mut due = Vec::new();
        for (window, closing) in unsent {
            if !self.inner.hooks.close(self.id, window) {
                return Ok(Closes::Stopped);
            }
            let mut chunks: Vec<_> = closing
                .paths
                .chunks(defaults::CLOSE_PATHS)
                .map(<[_]>::to_vec)
                .collect();
            if chunks.is_empty() {
                chunks.push(Vec::new());
            }
            for paths in chunks {
                if due.len() == CLOSES {
                    return Ok(Closes::Due(due));
                }
                due.push(Pending::Duty(Input::Close {
                    window,
                    rep_root: closing.root,
                    paths,
                }));
            }
        }
        Ok(Closes::Due(due))
    }

    /// Take up the anchors left waiting, by an earlier leadership or by
    /// the venue: every window up to the close mark whose cut root this
    /// replica still keeps (the representative's last
    /// [`defaults::CUT_KEEP`] windows) and whose root the venue does not
    /// hold anchored, whether never handed over, handed over and dropped
    /// by the venue's client to be signed again, or refused while the
    /// space was not registered there yet. Its close was sent, so no unsent
    /// close names it; the root is the representative's at its cut, the
    /// one its close carried.
    fn seed_waiting(&mut self, snapshot: &Snapshot) -> Result<(), Fault> {
        let Some(venue) = self.inner.venue.clone() else {
            return Ok(());
        };
        if !self.represents() {
            return Ok(());
        }
        let Some((through, _)) =
            read::<(u64, Option<AgentId>)>(snapshot, self.id, &keys::close_mark())?
        else {
            return Ok(());
        };
        let (space, _) = self.inner.space_and_clock();
        let mut kept = std::collections::BTreeSet::new();
        for row in snapshot.scan(self.id, &keys::cut_roots(), None) {
            let (key, value) = row?;
            let Some(window) = keys::cut_root_entry(&key).filter(|window| *window <= through)
            else {
                continue;
            };
            kept.insert(window);
            if self.refused.contains(&window) {
                continue;
            }
            let Some((root, _)) = <([u8; 32], u64)>::decode_exact(&value) else {
                return Err(fault(roots::Error::Corrupt("a cut root")));
            };
            let closing = roots::closing_of(snapshot, self.id, window).map_err(fault)?;
            if closing.is_some_and(|closing| closing.root != root) {
                return Err(fault(roots::Error::Corrupt(
                    "a close whose root is not its cut's",
                )));
            }
            let held = venue.anchored(&RootRead {
                kind: RootKind::Space,
                space,
                window,
                root: space_root(&space, window, &root),
            });
            if !held {
                let root = space_root(&space, window, &root);
                self.unanchored.entry(window).or_insert(root);
            }
        }
        let back: Vec<u64> = venue.unsettled(&space).iter().map(|a| a.window).collect();
        self.refused
            .retain(|window| kept.contains(window) || back.contains(window));
        Ok(())
    }

    /// Hand the venue the anchors this leadership has not settled, in
    /// window order, until one waits: a window the venue's clock has not
    /// yet closed, an anchor no key of this node's can sign, or one the
    /// venue will not take until its controller acts (a key registered, the
    /// space resumed). The next batch tries again, or an idle leader a
    /// recheck later ([`Leader::anchor_wait`]), with the later ones behind
    /// it, so none passes it. A window past `MaxRootAge` by the venue's
    /// time (this node's while the venue's client cannot say) is settled
    /// here, unsent: no venue takes it. One taken, or refused for good, is
    /// settled; the close goes on either way, and a statement over an
    /// unanchored root is refused at the venue.
    fn anchor_due(&mut self) {
        let (_, clock) = self.inner.space_and_clock();
        if self.unanchored.is_empty() {
            return;
        }
        let now = self
            .inner
            .venue
            .as_ref()
            .and_then(|venue| venue.time())
            .unwrap_or_else(|| (self.inner.clock)());
        while let Some((&window, &root)) = self.unanchored.first_key_value() {
            let aged = clock
                .boundary(window)
                .is_some_and(|boundary| now.saturating_sub(boundary) > MAX_ROOT_AGE_MS);
            if aged {
                tracing::error!(
                    window,
                    "the space's root waited past `MaxRootAge`; no venue takes it now"
                );
                self.refused.insert(window);
            } else if !self.anchor(window, &root) {
                self.anchor_tried = Some(Instant::now());
                return;
            }
            self.unanchored.remove(&window);
            self.anchored.insert(window);
        }
    }

    /// Sign the anchor of the space's root `root` of window `window` (`S_w`,
    /// over the representative's root at its cut), with the newest of this
    /// node's anchor keys the venue lists, and hand it to the venue:
    /// whether that settled it, taken or refused for good. With no key of
    /// this node's listed it signs nothing, and alerts. Synchronous, inside
    /// the batch: a venue's client queues and answers at once.
    fn anchor(&mut self, window: u64, root: &[u8; 32]) -> bool {
        let Some(venue) = self.inner.venue.clone() else {
            return true;
        };
        let (space, clock) = self.inner.space_and_clock();
        if venue.status(&space).waits() {
            self.alert(
                window,
                "the space is suspended or blocked at the venue; its anchors wait, unsent, until \
                 its controller resumes it (after removing both equivocating keys) or the venue \
                 unblocks it",
            );
            return false;
        }
        let listing = venue.anchor_keys(&space);
        let now = (self.inner.clock)();
        let refused_again = self.key_refused.as_ref().is_some_and(|(listed, at)| {
            *listed == listing && now.saturating_sub(*at) < clock.length_ms
        });
        if refused_again {
            return false;
        }
        let Some(key) = self.inner.anchor_keys.listed(&listing) else {
            self.alert(
                window,
                "the venue lists none of this node's anchor keys; the space's root is not signed \
                 until it lists one: replace this replica of the representative, or list one of \
                 its keys (`vos node anchor-key rotate`, then the controller's `add_authority`)",
            );
            return false;
        };
        let mut anchor = Anchor {
            space,
            window,
            kind: RootKind::Space,
            root: *root,
            signer: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        anchor.signature = key.sign(&anchor.digest(&venue.id())).to_bytes();
        let answer = venue.anchor(&anchor);
        self.key_refused = None;
        match answer {
            Ok(anchored) => {
                tracing::debug!(window, ?anchored, "anchored the space's root");
                true
            }
            Err(AnchorRefusal::Open) => {
                tracing::info!(
                    window,
                    "the venue has not closed the window yet; anchoring again"
                );
                false
            }
            Err(AnchorRefusal::Key) => {
                self.key_refused = Some((listing, now));
                self.alert(
                    window,
                    "the venue no longer lists the anchor key signed with; anchoring again once \
                     its listing changes, or a window later",
                );
                false
            }
            Err(AnchorRefusal::Suspended) => {
                self.alert(
                    window,
                    "the space is suspended at the venue, for an equivocation, until its \
                     controller removes both keys and resumes it; anchoring again",
                );
                false
            }
            Err(AnchorRefusal::Unregistered) => {
                self.alert(
                    window,
                    "the space is not registered at the venue, or its client has not read the \
                     registration yet; anchoring again",
                );
                false
            }
            Err(refusal) => {
                tracing::error!(window, ?refusal, "the venue refused the space's root");
                self.refused.insert(window);
                true
            }
        }
    }

    /// Alert, once a window, that `window`'s anchor waits.
    fn alert(&mut self, window: u64, why: &str) {
        if self.alerted != Some(window) {
            self.alerted = Some(window);
            tracing::error!(window, "{why}");
        }
    }
}

/// The closes `snapshot` holds whose paths are not all sent, in window
/// order, each with the paths past the close mark: none but the
/// representative's.
fn unsent(snapshot: &Snapshot, agent: AgentId, represents: bool) -> Result<Vec<Unsent>, Fault> {
    if !represents {
        return Ok(Vec::new());
    }
    let mark = read::<(u64, Option<AgentId>)>(snapshot, agent, &keys::close_mark())?;
    let mut unsent = Vec::new();
    for row in snapshot.scan(agent, &keys::closings(), None) {
        let (key, _) = row?;
        let Some(window) = keys::closing_entry(&key) else {
            continue;
        };
        let Some(mut closing) = roots::closing_of(snapshot, agent, window).map_err(fault)? else {
            continue;
        };
        match mark {
            Some((closed, _)) if closed > window => continue,
            Some((closed, None)) if closed == window => continue,
            Some((closed, Some(last))) if closed == window => {
                closing.paths.retain(|(of, ..)| *of > last);
                if closing.paths.is_empty() {
                    continue;
                }
            }
            _ => {}
        }
        unsent.push((window, closing));
    }
    Ok(unsent)
}
