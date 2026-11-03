//! An agent's admission at ingress (`light-node.md` §3.3,
//! `node-api.md` §3): what the agent asks of the requests it takes, read
//! from its applied state as the credential ring is, and checked before
//! any signature or proof.
//!
//! - **Onion only:** a request the gateway did not mark as received on its
//!   onion service is refused; an unmarked one (the socket's tools, a
//!   driver) counts as clearnet. The mark is the gateway's word, trusted as
//!   any API client is: defence in depth, the client's routing the
//!   enforcement.
//! - **Known keys only:** a call that would create a session (its session
//!   row absent) is refused unless its key is a row of the declaring
//!   actor's admitted table. The key is only an index into the rows, so an
//!   unknown key costs three point reads (the agent's admission, the
//!   session's row, the key's) and no verification, and writes nothing.
//!   A call in a session the agent holds is not looked up: admission
//!   covers the creation of sessions, the actor's handlers the rest.
//!
//! A replica reads its own applied state: a key admitted in the latest
//! batch may be refused until the replica applies it, and its client
//! retries.

use vos_api::Mark;
use vos_wire::ids::{AgentId, Session};
use vos_wire::ingress::{AdmissionRefusal, Rejection, Response};
use vos_wire::keys;
use vos_wire::records::{Admitting, unstored};

use crate::fault::{Fault, read};
use crate::node::Inner;
use crate::store::Snapshot;

impl Inner {
    /// Whether `agent` admits a request marked `mark`, and, for a call,
    /// `session`'s: by this replica's applied state, before any signature
    /// or proof is checked. An agent this replica holds nothing of admits
    /// it here, and is answered where it is.
    pub(crate) fn admits(
        &self,
        agent: AgentId,
        mark: Mark,
        session: Option<&Session>,
    ) -> Result<(), Response> {
        let snapshot = self.store.snapshot();
        admits(&snapshot, agent, mark, session)
            .map_err(|_| Response::Unavailable)?
            .map_err(|refusal| Response::Rejected(Rejection::Admission(refusal)))
    }
}

fn admits(
    snapshot: &Snapshot,
    agent: AgentId,
    mark: Mark,
    session: Option<&Session>,
) -> Result<Result<(), AdmissionRefusal>, Fault> {
    let Some(Admitting {
        instance,
        admission,
    }) = read::<Admitting>(snapshot, agent, &keys::admission())?
    else {
        return Ok(Ok(()));
    };
    if admission.onion_only && !mark.onion() {
        return Ok(Err(AdmissionRefusal::OnionOnly));
    }
    let Some(session) = session.filter(|_| admission.known_keys) else {
        return Ok(Ok(()));
    };
    if snapshot
        .get(agent, &keys::session_index(session))?
        .is_some()
    {
        return Ok(Ok(()));
    }
    let admitted = snapshot
        .get(agent, &keys::admitted(instance, &session.key))?
        .is_some_and(|bytes| unstored(&bytes).is_some());
    Ok(if admitted {
        Ok(())
    } else {
        Err(AdmissionRefusal::UnknownKey)
    })
}
