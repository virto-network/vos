//! A window's close in the model: an agent's report of its root at the
//! window's cut, the representative storing it, the representative's
//! close, and an agent's `Closed`.

use vos_wire::batch::Body;
use vos_wire::ids::AgentId;
use vos_wire::result::{Outcome, Outgoing, Write};
use vos_wire::served::{
    AgentRoot, ClosedRow, REPORTS_KEPT, REPRESENTATIVE, representative_ask, representative_row,
};
use vos_wire::vos_anchor::RootKind;
use vos_wire::{Decode, Encode, SpaceId, defaults, keys};

use crate::{Step, Testkit};

impl Testkit {
    /// A row of applied state, decoded.
    fn held<T: Decode>(&self, key: &[u8]) -> Option<T> {
        T::decode_exact(self.state.get(key)?)
    }

    /// A step that runs nothing and writes `writes`, applied.
    fn written(&mut self, writes: Vec<Write>, messages: Vec<Outgoing>) -> Step {
        self.steps += 1;
        let mut step = Step::consumed(Outcome::Done(Vec::new()));
        step.writes = writes;
        step.messages = messages;
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
    pub fn report(&mut self, to: AgentId, window: u64, root: [u8; 32], pending: bool) -> Step {
        let reported = self.held::<(u64, AgentId)>(&keys::reported());
        let spaced = self.space.is_some_and(|(space, _)| space != SpaceId::NONE);
        if !spaced || to == self.agent || reported.is_some_and(|(last, _)| last >= window) {
            return self.written(Vec::new(), Vec::new());
        }
        let call = Outgoing {
            to,
            body: Body::Report(AgentRoot {
                kind: RootKind::Space as u8,
                window,
                root,
                pending,
            }),
        };
        let mark = Write {
            key: keys::reported(),
            value: Some((window, to).encode()),
        };
        self.written(vec![mark], vec![call])
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
        let after = match self.held::<(u64, Option<AgentId>)>(&keys::close_mark()) {
            Some((closed, _)) if closed > window => return self.written(Vec::new(), Vec::new()),
            Some((closed, None)) if closed == window => {
                return self.written(Vec::new(), Vec::new());
            }
            Some((closed, agent)) if closed == window => agent,
            _ => None,
        };
        let mut last: Option<AgentId> = None;
        let mut messages = Vec::new();
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
        if last.is_none() && after.is_some() {
            return self.written(Vec::new(), Vec::new());
        }
        let mark = Write {
            key: keys::close_mark(),
            value: Some((window, last).encode()),
        };
        self.written(vec![mark], messages)
    }

    /// The step of a `Closed` from agent `from` of window `window`: its row,
    /// when `from` is the representative the agent reported to and the
    /// agent holds no close of the window and keeps its rows.
    pub(crate) fn closed(&mut self, from: AgentId, window: u64, row: ClosedRow) -> Step {
        let to = self
            .held::<(u64, AgentId)>(&keys::reported())
            .map(|(_, to)| to);
        let kept = self
            .held::<u64>(&keys::serving())
            .is_none_or(|serving| window + defaults::CUT_KEEP >= serving);
        let held = self.state.contains_key(&keys::closed(window));
        let writes = if to == Some(from) && kept && !held {
            vec![Write {
                key: keys::closed(window),
                value: Some(row.encode()),
            }]
        } else {
            Vec::new()
        };
        self.written(writes, Vec::new())
    }

    /// The step of agent `from`'s report in this agent, its space's
    /// representative: the root under `representative_row(from, Space, w)`
    /// and, with `pending`, an ask; the sender's rows and asks of windows
    /// before `w −` [`REPORTS_KEPT`] gone; its last report's mark. Nothing
    /// for a report of another kind, from itself, of a window at or before
    /// its last, or past the one after the open window; nor in an agent of
    /// no space or without the representative installed.
    pub(crate) fn stored(&mut self, from: AgentId, report: AgentRoot) -> Step {
        let Some((space, clock)) = self.space else {
            return self.written(Vec::new(), Vec::new());
        };
        let last = self.held::<u64>(&keys::reports(from));
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
            || last.is_some_and(|last| window <= last)
        {
            return self.written(Vec::new(), Vec::new());
        }
        let mut overlay = std::collections::BTreeMap::new();
        if let (Some(last), Some(oldest)) = (last, window.checked_sub(REPORTS_KEPT)) {
            for at in (last.saturating_sub(REPORTS_KEPT)..=last).filter(|at| *at < oldest) {
                for key in [
                    representative_row(from, RootKind::Space, at),
                    representative_ask(at, from),
                ] {
                    if self.state.contains_key(&key) {
                        overlay.insert(key, None);
                    }
                }
            }
        }
        overlay.insert(
            representative_row(from, RootKind::Space, window),
            Some(report.root.to_vec()),
        );
        if report.pending {
            overlay.insert(representative_ask(window, from), Some(Vec::new()));
        }
        overlay.insert(keys::reports(from), Some(window.encode()));
        let (writes, committed) = crate::split_writes(overlay);
        self.steps += 1;
        let mut step = Step::consumed(Outcome::Done(Vec::new()));
        step.writes = writes;
        step.committed = committed;
        self.apply(&step, Vec::new());
        step
    }
}
