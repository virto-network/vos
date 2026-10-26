//! What the planning and sending threads share: the agents, and each
//! user's session as the driver keeps it, its sequences planned ahead and
//! sent in order. A call refused before it ran gives its sequence to the
//! next; one whose fate is unknown ends the session, and the next call
//! starts another.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use vos_node::client::{signed_call, signed_query};
use vos_wire::Encode;
use vos_wire::abi::Refusal;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session};
use vos_wire::ingress::{Consistency, Rejection, Response};

use crate::load::{self, Kind, Planned, Users};

/// How long past its `not_after` a query is good: within the node's
/// horizon.
const QUERY_GOOD_MS: u64 = 60_000;
/// The identity writes are signed by these users, none of the model's, in
/// turn: each writer's calls go one at a time, so several keep the rate
/// whatever the latency.
const IDENTITY_WRITERS: u64 = 16;
const IDENTITY_WRITER: u64 = u64::MAX - IDENTITY_WRITERS;
/// The readers of agents are users of their own, one an agent, after the
/// model's.
const READER: u64 = 1 << 40;
/// What a transfer moves.
const AMOUNT: u64 = 1;
/// A session left this long unused is dropped from the driver's map: by
/// then the agent has collected it, a session expiring an hour after its
/// creation.
pub const FORGET: Duration = Duration::from_secs(55 * 60);

pub fn wall_ms() -> u64 {
    crate::now_ms()
}

/// The methods the load calls, by name in the shard actor's schema.
#[derive(Clone, Copy)]
pub struct Methods {
    pub transfer: MethodId,
    pub balance: MethodId,
    pub tally: MethodId,
    pub holds_at_cut: MethodId,
    pub set_identity: MethodId,
}

/// An agent the load calls: its id, its identity (which its calls are
/// signed for) and its replicas by node index.
pub struct Agent {
    pub id: AgentId,
    pub identity: [u8; 32],
    pub replicas: Vec<usize>,
    pub paths: [String; 3],
}

/// A user's session at its agent, as the driver keeps it.
pub struct UserSession {
    pub key: SigningKey,
    pub name: [u8; 16],
    pub t0: u64,
    /// Bumped at each new session: a call signed in an older one is
    /// signed again when its turn comes.
    pub generation: u32,
    /// The sequence the next planned call is signed at, and the next one
    /// sent: they differ by the calls planned and not yet sent.
    pub planned_next: u64,
    pub sent_next: u64,
    pub unsent: u64,
    pub floor: u64,
    pub busy: bool,
    pub queue: VecDeque<Op>,
    pub used: Instant,
}

impl UserSession {
    fn new(key: SigningKey, name: [u8; 16]) -> Self {
        Self {
            key,
            name,
            t0: 0,
            generation: 0,
            planned_next: 1,
            sent_next: 1,
            unsent: 0,
            floor: 0,
            busy: false,
            queue: VecDeque::new(),
            used: Instant::now(),
        }
    }

    /// The sequence a call planned now is signed at. A session's time is
    /// its first call's: one opened before the load, or long before its
    /// user acted, would be refused as stale.
    pub fn plan(&mut self, now: u64) -> u64 {
        if self.planned_next == 1 && self.unsent == 0 {
            self.t0 = now;
        }
        self.used = Instant::now();
        let sequence = self.planned_next;
        self.planned_next += 1;
        self.unsent += 1;
        sequence
    }

    /// A call signed in `generation` at `sequence` takes its turn: the
    /// sequence it goes at, and whether it must be signed again for it.
    pub fn turn(&mut self, generation: u32, sequence: u64) -> (u64, bool) {
        self.unsent -= 1;
        let again = generation != self.generation || sequence != self.sent_next;
        let at = self.sent_next;
        self.sent_next += 1;
        (at, again)
    }

    /// The session after the call sent at `sequence` met `fate`; `fresh`
    /// names a new session and its time, when one starts.
    pub fn settle(&mut self, fate: &Fate, sequence: u64, fresh: impl FnOnce() -> ([u8; 16], u64)) {
        match fate {
            Fate::Ran(at) => self.floor = self.floor.max(*at),
            Fate::NeverRan => {
                self.sent_next = sequence;
                self.planned_next = self.sent_next + self.unsent;
            }
            Fate::Renew => {
                self.generation += 1;
                (self.name, self.t0) = fresh();
                self.sent_next = 1;
                self.planned_next = 1 + self.unsent;
            }
        }
    }
}

/// What became of a call, for its session.
#[derive(Debug, PartialEq, Eq)]
pub enum Fate {
    /// It ran: its sequence is spent, its answer reflects state `at`.
    Ran(u64),
    /// It never ran: its sequence goes to the next call.
    NeverRan,
    /// It may have run, or its session is gone: the next call starts a
    /// new session.
    Renew,
}

pub fn fate(answer: &Result<Response, String>) -> Fate {
    match answer {
        Ok(Response::Ran { at, .. }) => Fate::Ran(*at),
        Ok(
            Response::Rejected(Rejection::StaleSession { .. })
            | Response::Refused(Refusal::Expired | Refusal::StaleSession),
        ) => Fate::Renew,
        Ok(
            Response::Rejected(_)
            | Response::Refused(Refusal::SessionsFull | Refusal::KeySessionsFull)
            | Response::Busy
            | Response::NotLeader { .. }
            | Response::Elsewhere { .. }
            | Response::Unavailable
            | Response::NoAgent
            | Response::NotConsumed,
        ) => Fate::NeverRan,
        _ => Fate::Renew,
    }
}

/// One operation, signed for its schedule.
pub struct Op {
    pub due: Instant,
    pub kind: Kind,
    pub user: u64,
    pub agent: usize,
    pub cross: bool,
    pub body: Body,
}

pub enum Body {
    Call {
        method: MethodId,
        arguments: Vec<u8>,
        generation: u32,
        sequence: u64,
        signed: Vec<u8>,
    },
    Query(Vec<u8>),
}

/// Each shard's distinct users and the sessions opened at it.
#[derive(Default)]
pub struct ShardCounts {
    pub users: Vec<u64>,
    pub sessions: Vec<u64>,
}

/// What every thread shares.
pub struct Shared {
    /// The ledger shards, the idle agents when readers read them, then
    /// the identity agent if there is one.
    pub agents: Vec<Agent>,
    pub shards: usize,
    pub identity_agent: Option<usize>,
    pub instance: InstanceId,
    pub methods: Methods,
    pub seed: u64,
    pub sessions: Mutex<HashMap<u64, UserSession>>,
    pub counts: Mutex<ShardCounts>,
    /// How far the agents' time runs ahead of this host's clock, as a
    /// node last said.
    pub offset_ms: AtomicI64,
}

impl Shared {
    pub fn agent_now(&self) -> u64 {
        wall_ms().saturating_add_signed(self.offset_ms.load(Ordering::Relaxed))
    }

    pub fn learn_time(&self, now: u64) {
        let offset = i128::from(now) - i128::from(wall_ms());
        self.offset_ms.store(
            offset.clamp(i64::MIN.into(), i64::MAX.into()) as i64,
            Ordering::Relaxed,
        );
    }

    fn key(&self, user: u64) -> SigningKey {
        SigningKey::from_bytes(&load::user(self.seed, user).0)
    }

    fn session_name(&self, user: u64, generation: u32) -> [u8; 16] {
        let mut input = b"vos-scale session".to_vec();
        input.extend(self.seed.to_le_bytes());
        input.extend(user.to_le_bytes());
        input.extend(generation.to_le_bytes());
        input.extend(wall_ms().to_le_bytes());
        vos_pvm::precompile::blake2b_256(&input)[..16]
            .try_into()
            .expect("16 bytes")
    }

    /// A session opened at `agent`, counted against it when a shard.
    fn opened(&self, agent: usize, new_user: bool) {
        if agent < self.shards {
            let mut counts = self.counts.lock().expect("counts");
            counts.sessions[agent] += 1;
            counts.users[agent] += u64::from(new_user);
        }
    }

    /// `user`'s session at `agent`, opened if it has none: its key derived
    /// outside the lock.
    pub fn open(&self, user: u64, agent: usize) {
        if self.sessions.lock().expect("sessions").contains_key(&user) {
            return;
        }
        let session = UserSession::new(self.key(user), self.session_name(user, 0));
        let opened = match self.sessions.lock().expect("sessions").entry(user) {
            std::collections::hash_map::Entry::Vacant(vacant) => {
                vacant.insert(session);
                true
            }
            std::collections::hash_map::Entry::Occupied(_) => false,
        };
        if opened {
            self.opened(agent, true);
        }
    }

    /// A new session's name and time, for `user` at `agent`.
    pub fn fresh(&self, user: u64, agent: usize, generation: u32) -> ([u8; 16], u64) {
        self.opened(agent, false);
        (self.session_name(user, generation), self.agent_now())
    }

    /// Drop the sessions unused for [`FORGET`] and idle: the users
    /// inactive that long.
    pub fn forget(&self) {
        self.sessions
            .lock()
            .expect("sessions")
            .retain(|_, session| {
                session.busy || session.unsent > 0 || session.used.elapsed() < FORGET
            });
    }

    pub fn call_body(
        &self,
        agent: usize,
        session: &UserSession,
        sequence: u64,
        method: MethodId,
        arguments: &[u8],
    ) -> Vec<u8> {
        signed_call(
            &self.agents[agent].identity,
            &session.key,
            Session {
                key: session.key.verifying_key().to_bytes(),
                name: session.name,
                t0: session.t0,
            },
            sequence,
            self.instance,
            method,
            arguments.to_vec(),
        )
        .encode()
    }

    /// The user an operation is signed by.
    pub fn signer(planned: &Planned) -> u64 {
        match (planned.kind, planned.agent) {
            (Kind::Identity, _) => IDENTITY_WRITER + planned.user % IDENTITY_WRITERS,
            (Kind::Reader, Some(agent)) => READER + agent as u64,
            _ => planned.user,
        }
    }

    /// The agent an operation calls.
    pub fn home(&self, planned: &Planned, users: &Users) -> usize {
        match (planned.kind, planned.agent) {
            (Kind::Identity, _) => self.identity_agent.expect("an identity agent"),
            (_, Some(agent)) => agent,
            _ => users.shard(planned.user),
        }
    }

    /// `planned` as an operation due at `due`, signed.
    pub fn operation(&self, planned: &Planned, users: &Users, due: Instant) -> Op {
        let account = load::account(self.seed, planned.user);
        let home = self.home(planned, users);
        let (method, arguments) = match planned.kind {
            Kind::Transfer => {
                let (payee, _) = planned.payee.expect("a transfer's payee");
                let to_agent = self.agents[users.shard(payee)].id.0;
                let arguments = [
                    &account[..],
                    &load::account(self.seed, payee)[..],
                    &to_agent.to_le_bytes(),
                    &AMOUNT.to_le_bytes(),
                ]
                .concat();
                (self.methods.transfer, arguments)
            }
            Kind::Query => (self.methods.balance, account.to_vec()),
            Kind::Workflow => (self.methods.tally, vec![1u64, 2, 3].encode()),
            Kind::Cut | Kind::Reader => (
                self.methods.holds_at_cut,
                [&1u64.to_le_bytes()[..], &account[..]].concat(),
            ),
            Kind::Identity => (
                self.methods.set_identity,
                [&planned.user.to_le_bytes()[..], &[0x1d; 32]].concat(),
            ),
        };
        let user = Self::signer(planned);
        let cross = planned.payee.is_some_and(|(_, cross)| cross);
        self.open(user, home);
        let mut sessions = self.sessions.lock().expect("sessions");
        let session = sessions.get_mut(&user).expect("an open session");
        if planned.kind == Kind::Query {
            session.used = Instant::now();
            let key = session.key.clone();
            let floor = session.floor;
            drop(sessions);
            let body = signed_query(
                &self.agents[home].identity,
                &key,
                self.agent_now() + QUERY_GOOD_MS,
                Consistency::Applied { at: floor },
                self.instance,
                method,
                arguments,
            )
            .encode();
            return Op {
                due,
                kind: planned.kind,
                user,
                agent: home,
                cross,
                body: Body::Query(body),
            };
        }
        let sequence = session.plan(self.agent_now());
        let generation = session.generation;
        let key = session.key.clone();
        let (name, t0) = (session.name, session.t0);
        drop(sessions);
        let signed = signed_call(
            &self.agents[home].identity,
            &key,
            Session {
                key: key.verifying_key().to_bytes(),
                name,
                t0,
            },
            sequence,
            self.instance,
            method,
            arguments.clone(),
        )
        .encode();
        Op {
            due,
            kind: planned.kind,
            user,
            agent: home,
            cross,
            body: Body::Call {
                method,
                arguments,
                generation,
                sequence,
                signed,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Fate, UserSession, fate};
    use ed25519_dalek::SigningKey;
    use vos_wire::abi::Refusal;
    use vos_wire::ingress::{Rejection, Response};
    use vos_wire::result::Outcome;

    #[test]
    fn a_call_refused_before_it_ran_gives_its_sequence_to_the_next() {
        let of = |answer: Response| fate(&Ok(answer));
        assert_eq!(
            of(Response::Ran {
                outcome: Outcome::Done(vec![]),
                at: 9
            }),
            Fate::Ran(9)
        );
        assert_eq!(of(Response::Busy), Fate::NeverRan);
        assert_eq!(of(Response::Refused(Refusal::SessionsFull)), Fate::NeverRan);
        assert_eq!(of(Response::TimedOut), Fate::Renew);
        assert_eq!(
            of(Response::Rejected(Rejection::StaleSession { now: 1 })),
            Fate::Renew
        );
        assert_eq!(fate(&Err("reset".into())), Fate::Renew);
    }

    /// Three calls planned ahead: the first sent as signed; refused before
    /// it ran, its sequence goes to the second, signed again for it; one of
    /// unknown fate starts a session where the third goes first.
    #[test]
    fn calls_planned_ahead_go_in_order_whatever_became_of_the_last() {
        let mut session = UserSession::new(SigningKey::from_bytes(&[1; 32]), [0; 16]);
        let planned: Vec<u64> = (0..3).map(|_| session.plan(1_000)).collect();
        assert_eq!((planned, session.t0), (vec![1, 2, 3], 1_000));
        assert_eq!(session.turn(0, 1), (1, false));
        session.settle(&Fate::NeverRan, 1, || unreachable!());
        assert_eq!(session.planned_next, 3);
        assert_eq!(session.turn(0, 2), (1, true));
        session.settle(&Fate::Renew, 1, || ([7; 16], 2_000));
        assert_eq!(
            (session.generation, session.name, session.t0),
            (1, [7; 16], 2_000)
        );
        assert_eq!(session.planned_next, 2, "the third, unsent, goes first");
        assert_eq!(session.turn(0, 3), (1, true));
        session.settle(&Fate::Ran(5), 1, || unreachable!());
        // The next planned is signed at the next sequence and goes as is.
        assert_eq!(session.plan(3_000), 2);
        assert_eq!(session.turn(1, 2), (2, false));
        assert_eq!((session.floor, session.unsent), (5, 0));
    }
}
