//! A window's close, as the leaders drive it. An agent's leader, once its
//! replica has built a window's cut, reports its root there to the space's
//! representative ([`Input::Report`]), saying whether reads wait on the
//! close. The representative's leader, once its replica has built its own
//! cut of the window, which closes it, signs the anchor of the space's
//! root `S_w` with this node's key and hands it to the venue, then sends
//! each agent that asked its path ([`Input::Close`]). Both are proposed
//! from the replica's state, never queued, and sent once: refine sends
//! nothing for a window its mark has passed ([`keys::reported`],
//! [`keys::close_mark`]).

use ed25519_dalek::Signer;
use vos_venue::AnchorRefusal;
use vos_wire::batch::Input;
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::served::Closing;
use vos_wire::vos_anchor::{Anchor, RootKind, space_root};
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
        let unsent = unsent(snapshot, self.id, self.represents())?;
        let first = unsent.first().map(|(window, _)| *window);
        self.anchored
            .retain(|window| first.is_some_and(|first| *window >= first));
        for (window, closing) in &unsent {
            if !self.anchored.contains(window) {
                self.unanchored.entry(*window).or_insert(closing.root);
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

    /// Hand the venue the anchors this leadership has not settled, in
    /// window order, until one is refused for now: a window the venue's
    /// clock has not yet closed, which the next batch tries again, with the
    /// later ones behind it, so none passes it. One taken, or refused for
    /// good, is settled; the close goes on either way, and a statement over
    /// an unanchored root is refused at the venue.
    fn anchor_due(&mut self) {
        while let Some((&window, &root)) = self.unanchored.first_key_value() {
            if !self.anchor(window, &root) {
                return;
            }
            self.unanchored.remove(&window);
            self.anchored.insert(window);
        }
    }

    /// Sign the anchor of the space's root of window `window`, over the
    /// representative's root at its cut `rep_root`, with this node's key,
    /// and hand it to the venue: whether that settled it, taken or refused
    /// for good. Synchronous, inside the batch: a venue's client queues and
    /// answers at once.
    fn anchor(&self, window: u64, rep_root: &[u8; 32]) -> bool {
        let Some(venue) = &self.inner.venue else {
            return true;
        };
        let (space, _) = self.inner.space_and_clock();
        let mut anchor = Anchor {
            space,
            window,
            kind: RootKind::Space,
            root: space_root(&space, window, rep_root),
            signer: self.inner.node_key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        anchor.signature = self
            .inner
            .node_key
            .sign(&anchor.digest(&venue.id()))
            .to_bytes();
        match venue.anchor(&anchor) {
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
            Err(refusal) => {
                tracing::error!(window, ?refusal, "the venue refused the space's root");
                true
            }
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
