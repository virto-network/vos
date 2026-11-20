//! The link to the personal agent: sealed sync's [`Link`] and the pass's
//! [`Control`], every request through the [`Host`] to the home under one
//! purpose (`Personal` for what the user does, `Background` for the job's
//! pass), so the two never share a circuit or an SSH key.
//!
//! A call is signed by a key in a session the link keeps for it: the sync
//! key's in-process, the admin key's in the UI process behind its strong
//! biometric (the [`Sign`] a flow lends). A call refused with `Settling` is
//! sent again after a `wake`. A read is a query signed by the sync key.
//! Every round trip blocks the calling thread: sealed sync and the pass
//! are synchronous.

use std::time::Instant;

use super::Host;
use crate::job::{Control, Post};
use crate::personal::{Answer, Frontier, Link, WAKES};
use crate::route::{Purpose, Route};
use crate::wire;
use ed25519_dalek::{Signer as _, SigningKey};
use vos_abi::ids::{AgentId, InstanceId, MethodId, Session};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_api::Kind;
use vos_wire::defaults::SESSION_EXPIRY_MS;
use vos_wire::ingress::{self, Consistency, QueryCall, Response};
use vos_wire::personal::{
    DeviceView, Entry, Envelope, Overview, PersonalError, Pushed, Scope, Woken, method,
};

/// How long a query is good for, by the node's clock.
const QUERY_MS: u64 = 60_000;

/// A signature over a call's message by a key the link does not hold: the
/// admin key's, made in the UI process.
pub type Sign<'a> = &'a dyn Fn(&[u8]) -> Result<[u8; 64], String>;

/// What a call's caller keeps of its signed message before the call
/// leaves: a commit's, so its evidence is posted again after a crash.
pub type Hold<'a> = &'a mut dyn FnMut(&[u8], &[u8; 64]) -> Result<(), String>;

/// The key a call is signed by: the sync key, in the link's own session,
/// which every wake shares; or a key the link does not hold, in its
/// caller's session.
pub enum Key<'k> {
    Sync,
    Lent(&'k mut Signer, Sign<'k>),
}

/// A key's session at the agent, and its next call's sequence.
#[derive(Clone, Copy, Debug, Default)]
pub struct Signer {
    pub key: [u8; 32],
    session: Option<Session>,
    /// The agent the session is at: another agent's calls start one anew.
    agent: u32,
    next: u64,
}

impl Signer {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            session: None,
            agent: 0,
            next: 1,
        }
    }
}

/// The agent a link reaches: its id, the identity calls to it are signed
/// for, and `Personal`'s instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Agent {
    pub agent: u32,
    pub identity: [u8; 32],
    pub instance: InstanceId,
}

/// A call's answer: its outcome, and the message and signature an admin
/// call's evidence carries.
pub struct Called {
    pub outcome: Outcome,
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

/// The handler's answer in `outcome`: its reply, or `Personal`'s error.
pub fn answer<T: Decode>(outcome: &Outcome) -> Result<Result<T, PersonalError>, String> {
    wire::answer(outcome).map_err(|_| format!("the agent answered {outcome:?}"))
}

/// A link to the personal agent at the home `space`.
pub struct AgentLink<'a, H: Host> {
    host: &'a H,
    space: [u8; 32],
    purpose: Purpose,
    agent: Agent,
    sync: &'a SigningKey,
    signer: &'a mut Signer,
    /// The node's time read last, and when.
    clock: Option<(u64, Instant)>,
}

impl<'a, H: Host> AgentLink<'a, H> {
    pub fn new(
        host: &'a H,
        space: [u8; 32],
        purpose: Purpose,
        agent: Agent,
        sync: &'a SigningKey,
        signer: &'a mut Signer,
    ) -> Self {
        Self {
            host,
            space,
            purpose,
            agent,
            sync,
            signer,
            clock: None,
        }
    }

    pub fn agent(&self) -> Agent {
        self.agent
    }

    /// `request`'s answer body, sent under the link's purpose.
    pub fn send(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        self.host.request(&self.space, self.purpose, request)
    }

    /// The node's time now: read once a link, then counted on.
    pub fn now(&mut self) -> Result<u64, String> {
        if let Some((node, at)) = self.clock
            && at.elapsed().as_millis() < u128::from(QUERY_MS / 2)
        {
            return Ok(node + at.elapsed().as_millis() as u64);
        }
        let node = wire::time_answer(&self.send(&wire::time_request())?)
            .map_err(|error| error.to_string())?;
        self.clock = Some((node, Instant::now()));
        Ok(node)
    }

    /// The call of `method` with `arguments` at the agent, signed by `key`
    /// in its session, its message and signature given to `hold` before
    /// the call is sent (a call `hold` refuses is not): its outcome, and
    /// what was signed. A call whose answer was lost keeps its sequence, so
    /// it is sent again as it was.
    fn signed(
        &mut self,
        key: &mut Key<'_>,
        method: MethodId,
        arguments: Vec<u8>,
        hold: Hold<'_>,
    ) -> Result<Called, String> {
        let now = self.now()?;
        let agent = self.agent;
        let signer = match key {
            Key::Sync => &mut *self.signer,
            Key::Lent(signer, _) => &mut **signer,
        };
        let stale = signer.agent != agent.agent
            || signer
                .session
                .is_none_or(|session| session.t0 + SESSION_EXPIRY_MS / 2 < now);
        if stale {
            let mut session_name = [0; 16];
            getrandom::getrandom(&mut session_name).map_err(|error| error.to_string())?;
            signer.session = Some(Session {
                key: signer.key,
                name: session_name,
                t0: now,
            });
            signer.agent = agent.agent;
            signer.next = 1;
        }
        let mut call = ingress::Call {
            session: signer.session.expect("a session"),
            sequence: signer.next,
            instance: agent.instance,
            method,
            arguments,
            signature: [0; 64],
        };
        let message = call.message(&agent.identity);
        call.signature = match key {
            Key::Sync => self.sync.sign(&message).to_bytes(),
            Key::Lent(_, sign) => sign(&message)?,
        };
        hold(&message, &call.signature)?;
        let request = wire::request(Kind::Call as u16, (AgentId(agent.agent), call.clone()));
        match Response::decode_exact(&self.send(&request)?) {
            Some(Response::Ran { outcome, .. }) => {
                match key {
                    Key::Sync => self.signer.next += 1,
                    Key::Lent(signer, _) => signer.next += 1,
                }
                Ok(Called {
                    outcome,
                    message,
                    signature: call.signature,
                })
            }
            Some(other) => Err(format!("the node answered {other:?}")),
            None => Err("the node's answer does not decode".into()),
        }
    }

    /// The sync key's call of `name`, sent again after a `wake` while the
    /// agent answers `Settling`.
    pub fn call<T: Decode>(&mut self, method: MethodId, arguments: Vec<u8>) -> Answer<T, String> {
        let called = self.settled(&mut Key::Sync, method, arguments, &mut |_, _| Ok(()))?;
        answer(&called.outcome)
    }

    /// `method` signed by `key` in its session, sent again after a `wake`
    /// (the sync key's) while the agent answers `Settling`, at most
    /// [`WAKES`] times, each call's message held before it is sent (as
    /// `AgentLink::signed` holds): a call signed again after `Settling` is
    /// held again.
    pub fn settled(
        &mut self,
        key: &mut Key<'_>,
        method: MethodId,
        arguments: Vec<u8>,
        hold: Hold<'_>,
    ) -> Result<Called, String> {
        for woken in 0..=WAKES {
            let called = self.signed(key, method, arguments.clone(), &mut *hold)?;
            let settling = matches!(
                answer::<()>(&called.outcome),
                Ok(Err(PersonalError::Settling))
            );
            if !settling {
                return Ok(called);
            }
            if woken < WAKES {
                self.wake().map_err(|error| error.to_string())?.ok();
            }
        }
        Err("the agent is still settling".into())
    }

    /// What fell due settled at the agent, through a bounded number of wakes.
    pub fn settle(&mut self) -> Answer<(), String> {
        for _ in 0..WAKES {
            match self.wake()? {
                Ok(woken) if !woken.settled => {}
                other => return Ok(other.map(drop)),
            }
        }
        Ok(Ok(()))
    }

    /// The sync key's query of `name` with `arguments`.
    pub fn query<T: Decode>(
        &mut self,
        method: MethodId,
        arguments: impl Encode,
    ) -> Answer<T, String> {
        let not_after = self.now()? + QUERY_MS;
        let mut query = QueryCall {
            key: self.sync.verifying_key().to_bytes(),
            not_after,
            consistency: Consistency::Applied { at: 0 },
            instance: self.agent.instance,
            method,
            arguments: arguments.encode(),
            signature: [0; 64],
        };
        query.signature = self
            .sync
            .sign(&query.message(&self.agent.identity))
            .to_bytes();
        let request = wire::request(Kind::Query as u16, (AgentId(self.agent.agent), query));
        let outcome = wire::outcome(&self.send(&request)?).map_err(|error| error.to_string())?;
        answer(&outcome)
    }
}

impl<H: Host> Link for AgentLink<'_, H> {
    type Error = String;

    fn route(&self) -> Route {
        self.host.route(&self.space, self.purpose)
    }

    fn push(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, String> {
        envelopes
            .iter()
            .map(|envelope| self.call::<Pushed>(method::PUSH, envelope.encode()))
            .collect()
    }

    fn since(&mut self, scope: Scope, position: u64) -> Answer<Vec<Envelope>, String> {
        self.query(method::SINCE, (scope, position))
    }

    fn wake(&mut self) -> Answer<Woken, String> {
        let called = self.signed(&mut Key::Sync, method::WAKE, Vec::new(), &mut |_, _| Ok(()))?;
        answer(&called.outcome)
    }

    fn frontier(&mut self, device: u32) -> Answer<Frontier, String> {
        self.query(method::FRONTIER, device)
    }
}

impl<H: Host> Control for AgentLink<'_, H> {
    fn log(&mut self, from: u64) -> Answer<Vec<(u64, Entry)>, String> {
        self.query(method::LOG, from)
    }

    fn overview(&mut self) -> Answer<Overview, String> {
        self.query(method::OVERVIEW, ())
    }

    fn devices(&mut self) -> Answer<Vec<DeviceView>, String> {
        self.query(method::DEVICES, ())
    }

    /// Sent once: [`crate::job`] wakes the agent and posts again while it
    /// answers `Settling`.
    fn post(&mut self, post: &Post) -> Answer<u64, String> {
        let called = self.signed(
            &mut Key::Sync,
            post.method(),
            post.arguments(),
            &mut |_, _| Ok(()),
        )?;
        Ok(match &called.outcome {
            Outcome::Done(reply) => {
                Ok(post.at(reply).ok_or("the agent's reply does not decode")?)
            }
            outcome => Err(answer::<()>(outcome)?.expect_err("a refusal")),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use vos_abi::abi::Failure;
    use vos_abi::ids::{InstanceId, Session};
    use vos_wire::credentials::Onion;

    use super::*;
    use crate::space::{Enrolled, Error, Proof};

    /// A home whose agent answers `Settling` to a call's first `settling`
    /// sendings and runs everything else, each call's session and
    /// sequence recorded.
    struct Recording {
        settling: usize,
        calls: Mutex<Vec<(Session, u64, MethodId)>>,
    }

    impl Recording {
        fn new(settling: usize) -> Self {
            Self {
                settling,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self, method: MethodId) -> usize {
            let calls = self.calls.lock().unwrap();
            let mut sent: Vec<_> = calls
                .iter()
                .map(|(session, sequence, _)| (session.name, *sequence))
                .collect();
            sent.sort();
            sent.dedup();
            assert_eq!(sent.len(), calls.len(), "a sequence sent twice: {calls:?}");
            calls.iter().filter(|(_, _, sent)| *sent == method).count()
        }
    }

    impl Host for Recording {
        fn request(&self, _: &[u8; 32], _: Purpose, request: &[u8]) -> Result<Vec<u8>, String> {
            let (kind, body) = request.split_at(2);
            if u16::from_le_bytes([kind[0], kind[1]]) == Kind::Time as u16 {
                return Ok(0u64.encode());
            }
            let (_, call) = <(AgentId, ingress::Call)>::decode_exact(body).ok_or("a call")?;
            let mut calls = self.calls.lock().unwrap();
            let before = calls
                .iter()
                .filter(|(_, _, sent)| *sent == call.method)
                .count();
            calls.push((call.session, call.sequence, call.method));
            let outcome = if call.method == method::WAKE {
                Outcome::Done(
                    Woken {
                        at: 0,
                        settled: true,
                    }
                    .encode(),
                )
            } else if before < self.settling {
                Outcome::Failed {
                    code: Failure::Handler,
                    detail: PersonalError::Settling.encode(),
                }
            } else if call.method == method::ALIVE {
                Outcome::Done(vos_wire::personal::Recorded { at: 0, index: 0 }.encode())
            } else {
                Outcome::Done(0u64.encode())
            };
            Ok(Response::Ran { outcome, at: 0 }.encode())
        }

        fn pin(&self, _: &[u8; 32], _: &[Onion]) {}

        fn route(&self, _: &[u8; 32], _: Purpose) -> Route {
            Route::Onion
        }

        fn prove(&self, _: Proof) -> Result<Vec<u8>, Error> {
            Err(Error::Failed("no prover".into()))
        }

        fn enrollments(&self) -> Result<Vec<Enrolled>, String> {
            Ok(Vec::new())
        }
    }

    fn link<'a>(
        host: &'a Recording,
        sync: &'a SigningKey,
        signer: &'a mut Signer,
    ) -> AgentLink<'a, Recording> {
        let agent = Agent {
            agent: 1,
            identity: [1; 32],
            instance: InstanceId(1),
        };
        AgentLink::new(host, [0; 32], Purpose::Personal, agent, sync, signer)
    }

    #[test]
    fn a_call_woken_through_settling_and_a_wake_never_reuse_a_sequence() {
        let host = Recording::new(1);
        let sync = SigningKey::from_bytes(&[7; 32]);
        let mut signer = Signer::new(sync.verifying_key().to_bytes());
        let mut link = link(&host, &sync, &mut signer);
        link.wake().unwrap().unwrap();
        let put: u64 = link.call(method::PUT, Vec::new()).unwrap().unwrap();
        assert_eq!(put, 0);
        link.wake().unwrap().unwrap();
        assert_eq!(signer.next, 6);
        assert_eq!(host.sent(method::PUT), 2);
    }

    /// A call is sent at most `WAKES + 1` times, a wake between each two;
    /// a post once by the link, its retries the pass's, as many.
    #[test]
    fn a_settling_agent_is_woken_a_bounded_number_of_times() {
        let host = Recording::new(usize::MAX);
        let sync = SigningKey::from_bytes(&[7; 32]);
        let mut signer = Signer::new(sync.verifying_key().to_bytes());
        let mut link = link(&host, &sync, &mut signer);
        let put = link.call::<u64>(method::PUT, Vec::new());
        assert_eq!(put, Err("the agent is still settling".into()));
        assert_eq!(
            Control::post(&mut link, &Post::Alive),
            Ok(Err(PersonalError::Settling))
        );
        assert!(matches!(
            crate::job::post_settled(&mut link, &Post::Alive),
            Err(crate::personal::SyncError::Settling)
        ));
        assert_eq!(host.sent(method::PUT), WAKES + 1);
        assert_eq!(host.sent(method::ALIVE), 1 + WAKES + 1);
        assert_eq!(host.sent(method::WAKE), 2 * WAKES);
    }
}
