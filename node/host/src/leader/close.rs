//! A window's close, as the leaders drive it. An agent's leader, once its
//! replica has built a window's cut, reports its root there to the space's
//! representative ([`Input::Report`]), saying whether reads wait on the
//! close. The representative's leader, once its replica has built its own
//! cut of the window, which closes it (and writes the space's root `S_w`,
//! which its anchoring signs), sends each agent that asked its path
//! ([`Input::Close`]). Both are proposed
//! from the replica's state, never queued, and sent once: refine sends
//! nothing for a window its mark has passed ([`keys::reported`],
//! [`keys::close_mark`]).

use vos_wire::batch::Input;
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::served::Closing;
use vos_wire::{Decode, defaults};

use super::Leader;
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

impl Leader {
    /// Whether a report or a close waits on this replica's state.
    pub(super) fn duties_due(&self) -> bool {
        let snapshot = self.inner.store.snapshot();
        self.reports(&snapshot)
            .is_ok_and(|reports| !reports.is_empty())
            || unsent(&snapshot, self.id, self.represents()).is_ok_and(|unsent| !unsent.is_empty())
    }

    /// Whether this agent is its space's representative.
    pub(super) fn represents(&self) -> bool {
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
        for (window, (root, _)) in roots::cut_roots(snapshot, self.id)? {
            if reported.is_some_and(|reported| window <= reported) {
                continue;
            }
            if !self.inner.hooks.report(self.id, window) {
                break;
            }
            let pending = !roots::requests_at(snapshot, self.id, window)?.is_empty();
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
    /// in window order.
    pub(super) fn closes(&self, snapshot: &Snapshot) -> Result<Closes, Fault> {
        let unsent = unsent(snapshot, self.id, self.represents())?;
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
}

/// The closes `snapshot` holds whose paths are not all sent, in window
/// order, each with the paths past the close mark: none but the
/// representative's.
fn unsent(
    snapshot: &Snapshot,
    agent: AgentId,
    represents: bool,
) -> Result<Vec<(u64, Closing)>, Fault> {
    if !represents {
        return Ok(Vec::new());
    }
    let mark = read::<(u64, Option<AgentId>)>(snapshot, agent, &keys::close_mark())?;
    let mut unsent = Vec::new();
    for row in snapshot.scan(agent, &keys::closings(), None) {
        let (key, value) = row?;
        let Some(window) = keys::closing_entry(&key) else {
            continue;
        };
        let mut closing = Closing::decode_exact(&value).ok_or(roots::Error::Corrupt("a close"))?;
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
