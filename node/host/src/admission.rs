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
//!
//! **The space's own** ([`OnionPolicy`], the node's configuration, alike
//! on every node of a space): its proven calls only through the onion, or
//! every request read of any of its agents so, checked from the frame's
//! kind and mark before its body is decoded.

use vos_api::{Kind, Mark};
use vos_wire::ids::{AgentId, Session};
use vos_wire::ingress::{AdmissionRefusal, Rejection, Response};
use vos_wire::keys;
use vos_wire::records::{Admitting, unstored};

use crate::fault::{Fault, read};
use crate::node::Inner;
use crate::store::Snapshot;

/// What every agent of a space asks of the gateway's mark, beside what an
/// agent asks of its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OnionPolicy {
    /// Nothing: an agent asks for itself.
    #[default]
    Any,
    /// A proven call (`Credentialed`), the anonymous kind, is refused
    /// unless the gateway received it on its onion service; key-signed
    /// requests may come over the clearnet.
    Anonymous,
    /// The space is onion only: every request read of an agent (a call, a
    /// query, a workflow read, a proven call; a schema or device window,
    /// answered none) is refused without the onion's mark, as an onion-only
    /// agent's is. An agent's record and the node's own kinds stay open.
    All,
}

impl OnionPolicy {
    /// Whether a request of `kind` marked `mark` passes: an unmarked one
    /// counts as clearnet.
    pub fn admits(self, kind: Kind, mark: Mark) -> bool {
        let guarded = match self {
            OnionPolicy::Any => false,
            OnionPolicy::Anonymous => kind == Kind::Credentialed,
            OnionPolicy::All => matches!(
                kind,
                Kind::Schema
                    | Kind::Devices
                    | Kind::Call
                    | Kind::Query
                    | Kind::Workflow
                    | Kind::Credentialed
            ),
        };
        !guarded || mark.onion()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_space_asks_the_onion_of_its_anonymous_calls_or_of_everything() {
        let reads = [
            Kind::Schema,
            Kind::Devices,
            Kind::Call,
            Kind::Query,
            Kind::Workflow,
            Kind::Credentialed,
        ];
        for kind in Kind::ALL {
            for mark in [Mark::Unmarked, Mark::Clearnet, Mark::Onion] {
                assert!(OnionPolicy::Any.admits(kind, mark));
                let onion = mark == Mark::Onion;
                assert_eq!(
                    OnionPolicy::Anonymous.admits(kind, mark),
                    onion || kind != Kind::Credentialed,
                    "{kind:?} {mark:?}"
                );
                assert_eq!(
                    OnionPolicy::All.admits(kind, mark),
                    onion || !reads.contains(&kind),
                    "{kind:?} {mark:?}"
                );
            }
        }
    }
}
