//! Reads at a window's cut served: once this replica has built the cut of
//! the window a pending request was asked in ([`keys::request`]) and the
//! agent holds the representative's close of that window
//! ([`keys::closed`]), the request goes into a batch as a
//! [`Input::Resume`]: its rows and their proof as the cut's build
//! persisted them ([`roots::cut_proof`]), with the close's root, salt and
//! path of the agent's root at the cut to the space's root. A request
//! whose rows pass its target's [`Limits::served`] goes unserved, so its
//! workflow learns at once. One not closed waits until its deadline ends
//! it.

use vos_wire::abi::cap::{Limits, Target};
use vos_wire::batch::Input;
use vos_wire::ids::{AgentId, RequestId};
use vos_wire::keys;
use vos_wire::records::{PendingRead, unstored};
use vos_wire::served::{ClosedRow, Served};
use vos_wire::{Decode, Encode, SpaceId};

use super::Leader;
use crate::fault::{Fault, read};
use crate::node::Pending;
use crate::roots::{self, CutProof};
use crate::store::Snapshot;

/// The most reads one batch serves: each step holds its kernel's whole
/// witness, the served rows among it.
const RESUMES: usize = 8;

/// A pending request this replica can serve: the window it was asked in,
/// and its id.
struct Ready {
    asked: u64,
    request: RequestId,
}

impl Leader {
    /// Whether a read this replica has proved at a cut, and the agent holds
    /// the close of, waits to be served.
    pub(super) fn serve_due(&self) -> bool {
        proved(&self.inner.store.snapshot(), self.id).is_ok_and(|ready| !ready.is_empty())
    }

    /// The reads `snapshot` holds proved at their cuts and closed, served,
    /// at most [`RESUMES`].
    pub(super) fn resumes(&self, snapshot: &Snapshot) -> Result<Vec<Pending>, Fault> {
        let ready = proved(snapshot, self.id)?;
        if ready.is_empty() {
            return Ok(Vec::new());
        }
        let space = read::<SpaceId>(snapshot, self.id, &keys::space())?.unwrap_or(SpaceId::NONE);
        let target = read::<Target>(snapshot, self.id, &keys::target())?.unwrap_or_default();
        ready
            .into_iter()
            .map(|ready| {
                let served = served(snapshot, self.id, space, target.limits(), &ready)?;
                Ok(Pending::Duty(Input::Resume {
                    window: ready.asked,
                    request: ready.request,
                    served,
                }))
            })
            .collect()
    }
}

/// The pending requests whose cut `snapshot`'s replica has built, the
/// agent holding its close, at most [`RESUMES`], in the order of the
/// windows they were asked in.
fn proved(snapshot: &Snapshot, agent: AgentId) -> Result<Vec<Ready>, Fault> {
    let Some(latest) = roots::latest_built(snapshot, agent)? else {
        return Ok(Vec::new());
    };
    let mut ready = Vec::new();
    for row in snapshot.scan(agent, &keys::request_prefix(), None) {
        let (key, _) = row?;
        // A key that does not read is skipped, as the cut's build skips it.
        let Some((asked, request)) = keys::request_entry(&key) else {
            continue;
        };
        if asked > latest || ready.len() == RESUMES {
            break;
        }
        let proved = snapshot.get(agent, &keys::closed(asked))?.is_some()
            && snapshot
                .get(agent, &keys::cut_proof(request, asked))?
                .is_some();
        if proved {
            ready.push(Ready { asked, request });
        }
    }
    Ok(ready)
}

/// The encoded rows of `ready`'s request as served at its window's cut,
/// within `limits`, with the close of that window; `None` when they pass
/// the cap.
fn served(
    snapshot: &Snapshot,
    agent: AgentId,
    space: SpaceId,
    limits: &Limits,
    ready: &Ready,
) -> Result<Option<Vec<u8>>, Fault> {
    let proof = roots::cut_proof(snapshot, agent, ready.request)?;
    let Some(CutProof {
        window,
        agent_root,
        rows,
        rows_proof,
        ..
    }) = proof
    else {
        return Ok(None);
    };
    let asked = snapshot
        .get(agent, &keys::request(ready.asked, ready.request))?
        .as_deref()
        .and_then(unstored)
        .and_then(PendingRead::decode_exact);
    let closed = read::<ClosedRow>(snapshot, agent, &keys::closed(window))?;
    let (Some(asked), Some(closed)) = (asked, closed) else {
        return Ok(None);
    };
    let served = Served {
        space,
        window,
        agent,
        instance: asked.instance,
        agent_root,
        rep_root: closed.rep_root,
        rep_salt: closed.rep_salt,
        space_path: closed.space_path,
        rows,
        rows_proof,
    }
    .encode();
    Ok((served.len() <= limits.served).then_some(served))
}
