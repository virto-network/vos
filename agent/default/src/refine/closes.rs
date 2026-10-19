//! A window's close: an agent's report of its root at the window's cut to
//! its space's representative, the representative's close sending each
//! agent that asked its path, and an agent taking its `Closed`.

use alloc::vec::Vec;

use vos_wire::batch::Body;
use vos_wire::ids::AgentId;
use vos_wire::result::{InputRef, Outcome, Outgoing, Run, Write};
use vos_wire::served::{AgentRoot, ClosedRow, REPORT, REPRESENTATIVE};
use vos_wire::vos_anchor::RootKind;
use vos_wire::{Decode, Encode, SpaceId, defaults, keys};

use super::base::{Base, Corrupt};
use super::inputs::consumed;

/// A row through the refine's earlier steps, decoded.
fn read<T: Decode>(base: &Base, key: &[u8]) -> Result<Option<T>, Corrupt> {
    match base.read(key)? {
        Some(bytes) => T::decode_exact(&bytes).map(Some).ok_or(Corrupt),
        None => Ok(None),
    }
}

/// The step of an agent's report of `root`, its root at window `window`'s
/// cut, to its space's representative `to`: a call of the
/// representative's `report`, which awaits no answer, and the report's
/// mark ([`keys::reported`]). A window at or before the mark, an agent of
/// no space, or one reporting to itself sends nothing.
pub(crate) fn report(base: &Base, to: AgentId, window: u64, root: [u8; 32], pending: bool) -> Run {
    let input = InputRef::Report { window };
    let mut run = consumed(input, Outcome::Done(Vec::new()));
    let reported = read::<(u64, AgentId)>(base, &keys::reported());
    let space = read::<SpaceId>(base, &keys::space());
    let (Ok(reported), Ok(Some(space))) = (reported, space) else {
        return run;
    };
    if space == SpaceId::NONE
        || to == base.agent
        || reported.is_some_and(|(last, _)| last >= window)
    {
        return run;
    }
    let arguments = AgentRoot {
        kind: RootKind::Space as u8,
        window,
        root,
        pending,
    }
    .encode();
    run.messages.push(Outgoing {
        to,
        body: Body::Call {
            instance: REPRESENTATIVE,
            method: REPORT,
            arguments,
            awaiting: None,
        },
    });
    run.writes.push(Write {
        key: keys::reported(),
        value: Some((window, to).encode()),
    });
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
    let Ok(mark) = read::<(u64, Option<AgentId>)>(base, &keys::close_mark()) else {
        return run;
    };
    let after = match mark {
        Some((closed, _)) if closed > window => return run,
        Some((closed, Some(agent))) if closed == window => Some(agent),
        Some((closed, None)) if closed == window => return run,
        _ => None,
    };
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
    if last.is_none() && after.is_some() {
        return run;
    }
    run.writes.push(Write {
        key: keys::close_mark(),
        value: Some((window, last).encode()),
    });
    run
}

/// What a `Closed` from agent `from` of window `window` writes: its row
/// ([`keys::closed`]), when `from` is the representative the agent
/// reported to, the window is not one it holds a close of, and it is not
/// past the rows the agent keeps.
pub(crate) fn closed(base: &Base, from: AgentId, window: u64, row: ClosedRow) -> Vec<Write> {
    let reported = read::<(u64, AgentId)>(base, &keys::reported());
    let serving = read::<u64>(base, &keys::serving());
    let held = base.read(&keys::closed(window));
    let (Ok(Some((_, to))), Ok(serving), Ok(None)) = (reported, serving, held) else {
        return Vec::new();
    };
    let kept = serving.is_none_or(|serving| window + defaults::CUT_KEEP >= serving);
    if to != from || !kept {
        return Vec::new();
    }
    alloc::vec![Write {
        key: keys::closed(window),
        value: Some(row.encode()),
    }]
}
