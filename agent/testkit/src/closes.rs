//! A window's close in the model: an agent's report of its root at the
//! window's cut, the representative storing it, the representative's
//! close, and an agent's `Closed`. A row of these that does not decode is
//! quarantined, read as absent, the step going on.

use std::collections::BTreeMap;

use vos_wire::batch::Body;
use vos_wire::ids::AgentId;
use vos_wire::result::{Outcome, Outgoing, Write};
use vos_wire::served::{
    AgentRoot, ClosedRow, REPORTS_KEPT, REPRESENTATIVE, representative_ask, representative_row,
};
use vos_wire::vos_anchor::RootKind;
use vos_wire::{Decode, Encode, SpaceId, defaults, keys};

use crate::{Step, Testkit};

/// A step's writes over the rows it quarantines, as the agent makes them.
#[derive(Default)]
struct Writes(BTreeMap<Vec<u8>, Option<Vec<u8>>>);

impl Writes {
    /// A row of `kit`'s state, decoded; one that does not decode
    /// quarantined, its bytes moved aside, and read as absent.
    fn read<T: Decode>(&mut self, kit: &Testkit, key: &[u8]) -> Option<T> {
        let held = kit.state.get(key)?;
        if let Some(value) = T::decode_exact(held) {
            return Some(value);
        }
        self.0.insert(keys::quarantined(key), Some(held.clone()));
        self.0.insert(key.to_vec(), None);
        None
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.0.insert(key, Some(value));
    }
}

impl Testkit {
    /// A step that runs nothing and writes `writes`, applied.
    fn written(&mut self, writes: Vec<Write>, messages: Vec<Outgoing>) -> Step {
        self.applied(Step {
            writes,
            messages,
            ..Step::consumed(Outcome::Done(Vec::new()))
        })
    }

    /// `step`, which runs nothing, counted and applied.
    fn applied(&mut self, step: Step) -> Step {
        self.steps += 1;
        self.apply(&step, Vec::new());
        step
    }

    /// The step of the agent's statement `id` of window `window`'s cut
    /// proved, its final proof the
    /// blob `proof`: its row written unless the agent holds one for the id.
    pub fn proven(&mut self, window: u64, id: [u8; 32], proof: [u8; 32]) -> Step {
        let key = keys::proven(window, &id);
        if self.state.contains_key(&key) {
            return self.written(Vec::new(), Vec::new());
        }
        let row = Write {
            key,
            value: Some(proof.to_vec()),
        };
        self.written(vec![row], Vec::new())
    }

    /// The step of the agent's report of `root`, its root at window
    /// `window`'s cut, to its space's representative `to`: a call of its
    /// `report` and the report's mark, unless the agent belongs to no
    /// space, reports to itself, or has reported the window or a later one.
    pub fn report(&mut self, to: AgentId, window: u64, root: [u8; 32]) -> Step {
        let mut writes = Writes::default();
        let reported = writes.read::<(u64, AgentId)>(self, &keys::reported());
        let spaced = self.space.is_some_and(|(space, _)| space != SpaceId::NONE);
        let mut messages = Vec::new();
        if spaced && to != self.agent && reported.is_none_or(|(last, _)| last < window) {
            messages.push(Outgoing {
                to,
                body: Body::Report(AgentRoot {
                    kind: RootKind::Space as u8,
                    window,
                    root,
                }),
            });
            writes.put(keys::reported(), (window, to).encode());
        }
        let (writes, _) = crate::split_writes(writes.0);
        self.written(writes, messages)
    }

    /// The step of the representative's close of window `window` at
    /// `rep_root`: a `Closed` to each agent of `paths` past its close mark,
    /// at most [`defaults::CLOSE_PATHS`] of them in agent order, and the
    /// mark moved to the last.
    pub fn close(
        &mut self,
        window: u64,
        rep_root: [u8; 32],
        paths: Vec<(AgentId, [u8; 16], Vec<u8>)>,
    ) -> Step {
        let mut writes = Writes::default();
        let mark = writes.read::<(u64, Option<AgentId>)>(self, &keys::close_mark());
        let after = match mark {
            Some((closed, _)) if closed > window => None,
            Some((closed, Some(agent))) if closed == window => Some(Some(agent)),
            Some((closed, None)) if closed == window => None,
            _ => Some(None),
        };
        let mut messages = Vec::new();
        if let Some(after) = after {
            let mut last: Option<AgentId> = None;
            for (agent, rep_salt, space_path) in paths
                .into_iter()
                .filter(|(agent, ..)| after.is_none_or(|after| *agent > after))
                .take(defaults::CLOSE_PATHS)
            {
                if last.is_some_and(|last| agent <= last) {
                    continue;
                }
                last = Some(agent);
                messages.push(Outgoing {
                    to: agent,
                    body: Body::Closed {
                        window,
                        rep_root,
                        rep_salt,
                        space_path,
                    },
                });
            }
            if last.is_some() || after.is_none() {
                writes.put(keys::close_mark(), (window, last).encode());
            }
        }
        let (writes, _) = crate::split_writes(writes.0);
        self.written(writes, messages)
    }

    /// The step of a `Closed` from agent `from` of window `window`: its row,
    /// when `from` is the representative the agent reported to and the
    /// agent holds the window's cut and no close of it.
    pub(crate) fn closed(&mut self, from: AgentId, window: u64, row: ClosedRow) -> Step {
        let mut writes = Writes::default();
        let reported = writes.read::<(u64, AgentId)>(self, &keys::reported());
        let held = writes.read::<ClosedRow>(self, &keys::closed(window));
        if reported.is_some_and(|(_, to)| to == from)
            && held.is_none()
            && self.state.contains_key(&keys::cut(window))
        {
            writes.put(keys::closed(window), row.encode());
        }
        let (writes, _) = crate::split_writes(writes.0);
        self.written(writes, Vec::new())
    }

    /// The step of agent `from`'s report in this agent, its space's
    /// representative: the root under `representative_row(from, Space, w)`
    /// and its ask; the sender's rows and asks of windows before
    /// `w −` [`REPORTS_KEPT`] gone; its last report's mark; the window as
    /// the latest a read waits on, when past it. Nothing
    /// for a report of another kind, from itself, of a window at or before
    /// its last, or past the one after the open window; nor in an agent of
    /// no space or without the representative installed.
    pub(crate) fn stored(&mut self, from: AgentId, report: AgentRoot) -> Step {
        let Some((space, clock)) = self.space else {
            return self.written(Vec::new(), Vec::new());
        };
        let window = report.window;
        let ahead = window
            > clock
                .window(self.time)
                .map_or(0, |open| open.saturating_add(1));
        if space == SpaceId::NONE
            || report.kind != RootKind::Space as u8
            || from == self.agent
            || !self.instances.contains_key(&REPRESENTATIVE)
            || ahead
        {
            return self.written(Vec::new(), Vec::new());
        }
        let mut writes = Writes::default();
        let last = writes.read::<u64>(self, &keys::reports(from));
        if last.is_none_or(|last| window > last) {
            if let (Some(last), Some(oldest)) = (last, window.checked_sub(REPORTS_KEPT)) {
                for at in (last.saturating_sub(REPORTS_KEPT)..=last).filter(|at| *at < oldest) {
                    for key in [
                        representative_row(from, RootKind::Space, at),
                        representative_ask(at, from),
                    ] {
                        if self.state.contains_key(&key) {
                            writes.0.insert(key, None);
                        }
                    }
                }
            }
            writes.put(
                representative_row(from, RootKind::Space, window),
                report.root.to_vec(),
            );
            writes.put(representative_ask(window, from), Vec::new());
            writes.put(keys::reports(from), window.encode());
            if writes
                .read::<u64>(self, &keys::reading())
                .is_none_or(|reading| reading < window)
            {
                writes.put(keys::reading(), window.encode());
            }
        }
        let (writes, committed) = crate::split_writes(writes.0);
        self.applied(Step {
            writes,
            committed,
            ..Step::consumed(Outcome::Done(Vec::new()))
        })
    }
}
