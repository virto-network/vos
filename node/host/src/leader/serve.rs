//! Reads at a window's cut served: once this replica has built a window's
//! cut, each pending request of it ([`keys::request`]) goes into a batch as
//! a [`Pending::Resume`], its rows and their proof as the cut's build
//! persisted them ([`roots::cut_proof`]), with the path of the agent's root
//! at the cut to the space's root. A request the cut could not prove, or
//! whose rows pass its target's [`Limits::served`], goes unserved, so its
//! workflow learns at once.
//!
//! The path is the representative's: a node holds none but the stand-in a
//! test's hook asks for ([`crate::Hooks::stand_in_representative`]).
//! Without it, no read is served, and each ends at its deadline.

use vos_wire::abi::cap::{Limits, Target};
use vos_wire::ids::{AgentId, RequestId};
use vos_wire::keys;
use vos_wire::records::{PendingRead, unstored};
use vos_wire::served::Served;
use vos_wire::{Decode, Encode, SpaceId};

use super::Leader;
use crate::fault::{Fault, read};
use crate::node::Pending;
use crate::roots::{self, CutProof};
use crate::store::Snapshot;

/// The most reads one batch serves: each step holds its kernel's whole
/// witness, the served rows among it.
const RESUMES: usize = 8;

impl Leader {
    /// Whether a read this replica has proved at a cut waits to be served.
    pub(super) fn serve_due(&self) -> bool {
        self.inner.hooks.stand_in_representative()
            && proved(&self.inner.store.snapshot(), self.id).is_ok_and(|ready| !ready.is_empty())
    }

    /// The reads `snapshot` holds proved at their cuts, served, at most
    /// [`RESUMES`]: none unless the node can serve them.
    pub(super) fn resumes(&self, snapshot: &Snapshot) -> Result<Vec<Pending>, Fault> {
        if !self.inner.hooks.stand_in_representative() {
            return Ok(Vec::new());
        }
        let ready = proved(snapshot, self.id)?;
        if ready.is_empty() {
            return Ok(Vec::new());
        }
        let space = read::<SpaceId>(snapshot, self.id, &keys::space())?.unwrap_or(SpaceId::NONE);
        let target = read::<Target>(snapshot, self.id, &keys::target())?.unwrap_or_default();
        ready
            .into_iter()
            .map(|(window, request)| {
                let served = served(snapshot, self.id, space, target.limits(), window, request)?;
                Ok(Pending::Resume {
                    window,
                    request,
                    served,
                })
            })
            .collect()
    }
}

/// The pending requests of windows whose cuts `snapshot`'s replica has
/// built, at most [`RESUMES`], in window order.
fn proved(snapshot: &Snapshot, agent: AgentId) -> Result<Vec<(u64, RequestId)>, Fault> {
    let Some(latest) = roots::latest_built(snapshot, agent).map_err(fault)? else {
        return Ok(Vec::new());
    };
    let mut ready = Vec::new();
    for row in snapshot.scan(agent, &keys::request_prefix(), None) {
        let (key, _) = row?;
        // A key that does not read is skipped, as the cut's build skips it.
        let Some((window, request)) = keys::request_entry(&key) else {
            continue;
        };
        if window > latest || ready.len() == RESUMES {
            break;
        }
        ready.push((window, request));
    }
    Ok(ready)
}

/// The encoded rows of `request`, of window `window`, as served at its cut,
/// within `limits`; `None` when its cut did not prove them, or they pass
/// the cap.
fn served(
    snapshot: &Snapshot,
    agent: AgentId,
    space: SpaceId,
    limits: &Limits,
    window: u64,
    request: RequestId,
) -> Result<Option<Vec<u8>>, Fault> {
    let Some(CutProof {
        agent_root,
        rows,
        rows_proof,
        ..
    }) = roots::cut_proof(snapshot, agent, request).map_err(fault)?
    else {
        return Ok(None);
    };
    let asked = snapshot
        .get(agent, &keys::request(window, request))?
        .as_deref()
        .and_then(unstored)
        .and_then(|bytes| PendingRead::decode(bytes).ok());
    let Some((asked, _)) = asked else {
        return Ok(None);
    };
    let (rep_root, rep_salt, space_path) =
        roots::stand_in(agent, window, &agent_root).map_err(fault)?;
    let served = Served {
        space,
        window,
        agent,
        instance: asked.instance,
        agent_root,
        rep_root,
        rep_salt,
        space_path,
        rows,
        rows_proof,
    }
    .encode();
    Ok((served.len() <= limits.served).then_some(served))
}

/// A root builder's error, as the leader's fault.
fn fault(error: roots::Error) -> Fault {
    Fault::Infrastructure(format!("a cut's proofs: {error}"))
}
