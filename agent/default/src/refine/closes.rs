//! A window's close: an agent's report of its root at the window's cut to
//! its space's representative, the representative storing it, the
//! representative's close sending each agent that reported the window its
//! path, and an agent taking its `Closed`. A row of these that does not
//! decode is quarantined: moved aside ([`keys::quarantined`]) and read as
//! absent, the step going on; the node alerts.

use alloc::vec::Vec;

use vos_wire::batch::Body;
use vos_wire::ids::AgentId;
use vos_wire::result::{CommittedWrite, InputRef, Outcome, Outgoing, Run, Write};
use vos_wire::served::{
    AgentRoot, ClosedRow, REPORTS_KEPT, REPRESENTATIVE, representative_ask, representative_row,
};
use vos_wire::vos_anchor::RootKind;
use vos_wire::{Decode, Encode, SpaceId, WindowClock, defaults, keys};

use super::Overlay;
use super::base::{Base, Corrupt};
use super::inputs::{consumed, split_writes};

/// A row through the refine's earlier steps, decoded.
fn read<T: Decode>(base: &Base, key: &[u8]) -> Result<Option<T>, Corrupt> {
    match base.read(key)? {
        Some(bytes) => T::decode_exact(&bytes).map(Some).ok_or(Corrupt),
        None => Ok(None),
    }
}

/// A step's writes over the rows it quarantines.
struct Writes(Overlay);

impl Writes {
    fn new() -> Self {
        Self(Overlay::new())
    }

    /// A row through the refine's earlier steps, decoded; one that does
    /// not decode quarantined, its bytes moved aside, and read as absent.
    fn read<T: Decode>(&mut self, base: &Base, key: &[u8]) -> Option<T> {
        let held = match base.read(key) {
            Ok(None) => return None,
            Ok(Some(bytes)) => match T::decode_exact(&bytes) {
                Some(value) => return Some(value),
                None => bytes,
            },
            Err(Corrupt) => base.stored(key).unwrap_or_default(),
        };
        self.0.insert(keys::quarantined(key), Some(held));
        self.0.insert(key.to_vec(), None);
        None
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.0.insert(key, Some(value));
    }

    fn delete(&mut self, key: Vec<u8>) {
        self.0.insert(key, None);
    }

    /// The writes, those to committed maps apart.
    fn split(self) -> (Vec<Write>, Vec<CommittedWrite>) {
        split_writes(self.0)
    }
}

/// The step of an agent's report of `root`, its root at window `window`'s
/// cut, to its space's representative `to`: a [`Body::Report`], and the
/// report's mark ([`keys::reported`]). A window at or before the mark, an agent of
/// no space, or one reporting to itself sends nothing.
pub(crate) fn report(base: &Base, to: AgentId, window: u64, root: [u8; 32]) -> Run {
    let input = InputRef::Report { window };
    let mut run = consumed(input, Outcome::Done(Vec::new()));
    let Ok(Some(space)) = read::<SpaceId>(base, &keys::space()) else {
        return run;
    };
    let mut writes = Writes::new();
    let reported = writes.read::<(u64, AgentId)>(base, &keys::reported());
    if space != SpaceId::NONE
        && to != base.agent
        && reported.is_none_or(|(last, _)| last < window)
    {
        run.messages.push(Outgoing {
            to,
            body: Body::Report(AgentRoot {
                kind: RootKind::Space as u8,
                window,
                root,
            }),
        });
        writes.put(keys::reported(), (window, to).encode());
    }
    (run.writes, _) = writes.split();
    run
}

/// The step of the representative's close of window `window` at its root
/// `rep_root`: each agent of `paths` past the close mark
/// ([`keys::close_mark`]) sent its `Closed`, at most
/// [`defaults::CLOSE_PATHS`], in agent order, and the mark moved to the
/// last. A close of a window the mark has passed sends nothing.
pub(crate) fn close(
    base: &Base,
    window: u64,
    rep_root: [u8; 32],
    paths: Vec<(AgentId, [u8; 16], Vec<u8>)>,
) -> Run {
    let input = InputRef::Close { window };
    let mut run = consumed(input, Outcome::Done(Vec::new()));
    let mut writes = Writes::new();
    let mark = writes.read::<(u64, Option<AgentId>)>(base, &keys::close_mark());
    let after = match mark {
        Some((closed, _)) if closed > window => None,
        Some((closed, Some(agent))) if closed == window => Some(Some(agent)),
        Some((closed, None)) if closed == window => None,
        _ => Some(None),
    };
    if let Some(after) = after {
        let mut last = None;
        for (agent, rep_salt, space_path) in paths
            .into_iter()
            .filter(|(agent, ..)| after.is_none_or(|after| *agent > after))
            .take(defaults::CLOSE_PATHS)
        {
            if last.is_some_and(|last| agent <= last) {
                continue;
            }
            last = Some(agent);
            run.messages.push(Outgoing {
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
    (run.writes, _) = writes.split();
    run
}

/// What a `Closed` from agent `from` of window `window` writes: its row
/// ([`keys::closed`]), when `from` is the representative the agent
/// reported to, the agent holds the window's cut ([`keys::cut`]), and no
/// close of it.
pub(crate) fn closed(base: &Base, from: AgentId, window: u64, row: ClosedRow) -> Vec<Write> {
    let mut writes = Writes::new();
    let reported = writes.read::<(u64, AgentId)>(base, &keys::reported());
    let held = writes.read::<ClosedRow>(base, &keys::closed(window));
    if reported.is_some_and(|(_, to)| to == from)
        && held.is_none()
        && base.holds(&keys::cut(window))
    {
        writes.put(keys::closed(window), row.encode());
    }
    writes.split().0
}

/// What agent `from`'s report writes in this agent, its space's
/// representative: the root at `representative_row(from, Space, w)`, as a
/// bare 32-byte value, and its ask for its path ([`representative_ask`]);
/// the sender's rows of windows before `w −` [`REPORTS_KEPT`] go, and its
/// asks of them, no other agent's; the sender's last report
/// ([`keys::reports`]); and the window, as one a read waits on
/// ([`keys::reading`]), when past the latest. Nothing for a report of
/// another kind than the space's, from itself, of a window at or before
/// the sender's last, or past the one after this agent's open window; nor
/// in an agent of no space or without the representative installed, nor
/// when its record does not decode.
pub(crate) fn stored(
    base: &Base,
    from: AgentId,
    report: AgentRoot,
) -> (Vec<Write>, Vec<CommittedWrite>) {
    let nothing = (Vec::new(), Vec::new());
    let space = read::<SpaceId>(base, &keys::space());
    let clock = read::<WindowClock>(base, &keys::clock());
    let (Ok(Some(space)), Ok(Some(clock))) = (space, clock) else {
        return nothing;
    };
    let window = report.window;
    let open = clock.window(base.time);
    let ahead = window > open.map_or(0, |open| open.saturating_add(1));
    if space == SpaceId::NONE
        || report.kind != RootKind::Space as u8
        || from == base.agent
        || !base.holds(&keys::installed(REPRESENTATIVE))
        || ahead
    {
        return nothing;
    }
    let mut writes = Writes::new();
    let last = writes.read::<u64>(base, &keys::reports(from));
    if last.is_some_and(|last| window <= last) {
        return writes.split();
    }
    if let (Some(last), Some(oldest)) = (last, window.checked_sub(REPORTS_KEPT)) {
        // The sender's rows are of its last report's window and the
        // `REPORTS_KEPT` before it: the rest went with earlier reports.
        for at in (last.saturating_sub(REPORTS_KEPT)..=last).filter(|at| *at < oldest) {
            for key in [
                representative_row(from, RootKind::Space, at),
                representative_ask(at, from),
            ] {
                if base.holds(&key) {
                    writes.delete(key);
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
        .read::<u64>(base, &keys::reading())
        .is_none_or(|reading| reading < window)
    {
        writes.put(keys::reading(), window.encode());
    }
    writes.split()
}
