//! Credentialed calls at ingress (`identity-and-authority.md` §5): a call
//! whose authority is a credential proof, with no session and no
//! signature. Ingress runs every check on this replica's applied state,
//! cheapest first, each refusal its own code in check order; then, holding
//! one of the node's verification slots, verifies the proof on an
//! executor, the PoW before any decommitment. A call that passes goes to
//! the agent's leader carrying the origin the proof proved, never the
//! proof, and is answered once this replica has applied it.
//!
//! There is no bucket per scope or method for an attacker to drain: what
//! bounds the node's work is its connections and its verification budget
//! ([`crate::node::Config::verifications`]), past which a call is answered
//! `Busy` before any proof byte is read.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use vos_pvm_final_verifier::credential::{self as verifier, CredentialKind};
use vos_wire::abi::cap;
use vos_wire::batch::CredentialedInput;
use vos_wire::credentials::{self, Bound, Ring, tables};
use vos_wire::ids::{AgentId, InstanceId, derive_id};
use vos_wire::ingress::{CredentialPublic, CredentialRefusal, Credentialed, Rejection, Response};
use vos_wire::keys::{self, Transform};
use vos_wire::records::{Installed, unstored};
use vos_wire::schema::CredentialGuard;
use vos_wire::{Decode, Encode, SpaceId, defaults};

use crate::calls::Forwardable;
use crate::fault::{Fault, read};
use crate::node::Inner;
use crate::store::Snapshot;

/// The proof formats ingress admits for a credential, each with its
/// proof's cap: the credential format the proof registry names, as the
/// final verifier pins it. A device proof's (1.5 MiB) joins it once a
/// device kernel is admitted.
const ADMITTED: [(u32, usize); 1] = [(verifier::FORMAT, verifier::MAX_PROOF_BYTES)];

/// A verification's place among those in flight, given back when it ends,
/// however it ends.
pub(crate) struct Verifying<'a>(&'a AtomicUsize);

impl<'a> Verifying<'a> {
    /// A place, if fewer than `most` verifications are in flight.
    fn take(in_flight: &'a AtomicUsize, most: usize) -> Option<Self> {
        in_flight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                (held < most).then_some(held + 1)
            })
            .ok()
            .map(|_| Verifying(in_flight))
    }
}

impl Drop for Verifying<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A credentialed call that passed every check but the proof's: what the
/// verifier takes, and the input the log carries once it verifies.
struct Checked {
    kind: CredentialKind,
    words: Option<Vec<u32>>,
    proof: Vec<u8>,
    input: CredentialedInput,
}

/// Why a check refused: a code, or the node could not read its state.
enum Refused {
    Code(CredentialRefusal),
    Unavailable,
}

impl From<CredentialRefusal> for Refused {
    fn from(code: CredentialRefusal) -> Self {
        Refused::Code(code)
    }
}

impl From<Fault> for Refused {
    fn from(_: Fault) -> Self {
        Refused::Unavailable
    }
}

impl From<fjall::Error> for Refused {
    fn from(_: fjall::Error) -> Self {
        Refused::Unavailable
    }
}

impl From<Refused> for Response {
    fn from(refused: Refused) -> Self {
        match refused {
            Refused::Code(code) => Response::Rejected(Rejection::Credential(code)),
            Refused::Unavailable => Response::Unavailable,
        }
    }
}

impl Inner {
    /// A credentialed call to `agent`, as ingress takes it: checked, then
    /// verified, then run at the agent's leader, here or forwarded.
    pub(crate) async fn credentialed(
        self: &Arc<Self>,
        agent: AgentId,
        call: Credentialed,
    ) -> Response {
        let run = match self.present(agent) {
            Ok(run) => run,
            Err(error) => return error.into(),
        };
        let checked = match self.check(agent, call) {
            Ok(checked) => checked,
            Err(refused) => return refused.into(),
        };
        let Some(place) = Verifying::take(&self.calls.verifying, self.settings.verifications)
        else {
            return Response::Busy;
        };
        let Checked {
            kind,
            words,
            proof,
            input,
        } = checked;
        let stats = Arc::clone(&self.stats);
        let verified = self
            .offload(move || {
                let started = Instant::now();
                let verified =
                    words.is_some_and(|words| verifier::verify_bytes(kind, &words, &proof).is_ok());
                stats.credential.took(started.elapsed());
                verified
            })
            .await;
        drop(place);
        match verified {
            Some(true) => {}
            Some(false) => {
                return Response::Rejected(Rejection::Credential(CredentialRefusal::Proof));
            }
            None => return Response::Unavailable,
        }
        if let Err(error) = self.settled(agent).await {
            return error.into();
        }
        if run.agent.leading() {
            self.credentialed_call(agent, input).await
        } else {
            self.forward(&run, agent, Forwardable::Credentialed(input))
                .await
        }
    }

    /// Every check of `call` but the proof's, in order, on this replica's
    /// applied state.
    fn check(&self, agent: AgentId, call: Credentialed) -> Result<Checked, Refused> {
        let snapshot = self.store.snapshot();
        let space = read::<SpaceId>(&snapshot, agent, &keys::space())?
            .filter(|space| *space != SpaceId::NONE)
            .ok_or(CredentialRefusal::NoSpace)?;
        let (_, cap) = ADMITTED
            .into_iter()
            .find(|(format, _)| *format == call.format)
            .ok_or(CredentialRefusal::Format)?;
        if call.proof.len() > cap || call.arguments.len() > cap::REQUEST {
            return Err(CredentialRefusal::Size.into());
        }
        let now = (self.clock)();
        if call.expires_ms < now || call.expires_ms > now + defaults::CREDENTIAL_HORIZON_MS {
            return Err(CredentialRefusal::Expiry { now }.into());
        }
        let guard = guard(&snapshot, agent, call.instance, &call)?;
        let kind = match (&guard, &call.public) {
            (CredentialGuard::Auth { .. }, CredentialPublic::Auth { .. }) => CredentialKind::Auth,
            (CredentialGuard::Owner, CredentialPublic::Owner { .. }) => CredentialKind::Owner,
            _ => return Err(CredentialRefusal::Kind.into()),
        };
        if let (CredentialGuard::Auth { name, .. }, CredentialPublic::Auth { scope, .. }) =
            (&guard, &call.public)
            && credentials::scope(&space, agent, call.instance, name) != *scope
        {
            return Err(CredentialRefusal::Scope.into());
        }
        let binding = Bound {
            space: &space,
            agent,
            instance: call.instance,
            method: call.method,
            program: verifier::program(kind),
            kind: call.public.kind(),
            arguments: &call.arguments,
            nonce: &call.nonce,
            expires_ms: call.expires_ms,
        }
        .digest();
        if credentials::binding(&binding) != *call.public.binding() {
            return Err(CredentialRefusal::Binding.into());
        }
        if snapshot.get(agent, &keys::binding(&binding))?.is_some() {
            return Err(CredentialRefusal::Replayed.into());
        }
        let root = match call.public {
            CredentialPublic::Auth {
                map_root,
                scope,
                nullifier,
                ..
            } => {
                let once = matches!(guard, CredentialGuard::Auth { once: true, .. });
                if once
                    && snapshot
                        .get(agent, &keys::once(&scope, &nullifier))?
                        .is_some()
                {
                    return Err(CredentialRefusal::Once.into());
                }
                fresh(&snapshot, agent, &map_root)?;
                Some(map_root)
            }
            CredentialPublic::Owner { .. } => None,
        };
        Ok(Checked {
            kind,
            words: call.public.words(),
            proof: call.proof,
            input: CredentialedInput {
                origin: call.public.origin(),
                instance: call.instance,
                method: call.method,
                arguments: call.arguments,
                binding,
                expires_ms: call.expires_ms,
                root,
            },
        })
    }
}

/// The credential guard of `call`'s method of `instance`, if both exist
/// and it has one.
fn guard(
    snapshot: &Snapshot,
    agent: AgentId,
    instance: InstanceId,
    call: &Credentialed,
) -> Result<CredentialGuard, Refused> {
    let installed = snapshot
        .get(agent, &keys::installed(instance))?
        .and_then(|bytes| Installed::decode_exact(unstored(&bytes)?));
    installed
        .and_then(|installed| {
            installed
                .schema
                .method(call.method)?
                .credential
                .as_deref()
                .cloned()
        })
        .ok_or(CredentialRefusal::Method.into())
}

/// That `root` is in the credential actor's ring and fresh by this
/// replica's latest applied batch time: `RootUnknown` (retryable) when the
/// ring does not hold it, or the agent has no credential actor; `RootStale`
/// when it was superseded more than [`defaults::ROOT_MAX_AGE`] before.
fn fresh(snapshot: &Snapshot, agent: AgentId, root: &[u8; 32]) -> Result<(), Refused> {
    let ring = ring(snapshot, agent)?.ok_or(CredentialRefusal::RootUnknown)?;
    let time = read::<u64>(snapshot, agent, &keys::batch_time())?.unwrap_or(0);
    ring.accepts(root, time).map_err(|refusal| match refusal {
        credentials::RootRefusal::Unknown => CredentialRefusal::RootUnknown.into(),
        credentials::RootRefusal::Stale => CredentialRefusal::RootStale.into(),
    })
}

/// The ring of `agent`'s credential actor, if it has one.
fn ring(snapshot: &Snapshot, agent: AgentId) -> Result<Option<Ring>, Fault> {
    let Some(actor) = read::<InstanceId>(snapshot, agent, &keys::credentials())? else {
        return Ok(None);
    };
    let rows = vos_wire::abi::Rows::Table {
        tag: derive_id("vos/table/", tables::RING),
        transform: Transform::Hashed,
    };
    let Ok(key) = keys::row(actor, rows, &tables::RING_KEY.encode()) else {
        return Ok(None);
    };
    Ok(snapshot
        .get(agent, &key)?
        .and_then(|bytes| Ring::decode_exact(unstored(&bytes)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verification takes a place while fewer than the budget hold one,
    /// and gives it back when it ends.
    #[test]
    fn the_verification_budget_is_held_and_given_back() {
        let in_flight = AtomicUsize::new(0);
        let first = Verifying::take(&in_flight, 2).expect("a place");
        let second = Verifying::take(&in_flight, 2).expect("a place");
        assert!(Verifying::take(&in_flight, 2).is_none(), "the budget spent");
        drop(first);
        assert!(Verifying::take(&in_flight, 2).is_some());
        drop(second);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert!(
            Verifying::take(&in_flight, 0).is_none(),
            "no budget, no place"
        );
    }
}
