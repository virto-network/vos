//! A window's close in the model: an agent's report of its root at the
//! window's cut, the representative's close, and an agent's `Closed`.

use vos_wire::batch::Body;
use vos_wire::ids::AgentId;
use vos_wire::result::{Outcome, Outgoing, Write};
use vos_wire::served::{AgentRoot, ClosedRow, REPORT, REPRESENTATIVE};
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
        let arguments = AgentRoot {
            kind: RootKind::Space as u8,
            window,
            root,
            pending,
        }
        .encode();
        let call = Outgoing {
            to,
            body: Body::Call {
                instance: REPRESENTATIVE,
                method: REPORT,
                arguments,
                awaiting: None,
            },
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
}
