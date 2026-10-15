//! Workflows as the checker starts them: the rounds actor's tours, each
//! round asking the next agent's rounds to tally its amount and awaiting
//! the total, tallying it here, sending the next agent's other rounds it to
//! tally, a message, sleeping and computing; and their owners' signed
//! reads.
//!
//! A tour's every effect is a tally of an amount no other round has: how
//! often each applied is read at the end, exactly, a failed tour's amounts
//! once or not at all and every other once. Only one client's tours touch
//! those rounds, one tour at a time, so a tour's result is known before it
//! starts while none has failed: the totals after each of its amounts, and
//! its computations' digest.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use vos_node::client::post_within;
use vos_wire::ids::{AgentId, InstanceId, MethodId, WorkflowId};
use vos_wire::ingress::{
    Consistency, Install, Rejection, Response, WORKFLOW_READ_HORIZON_MS, WorkflowRead,
    WorkflowStatus, workflow_message, workflow_read_horizon,
};
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::{Client, Nodes};

/// The rounds instance at each agent whose tours start there, and which
/// tallies their amounts.
pub const ROUNDS: InstanceId = InstanceId(4);
/// The rounds instance the previous agent's tours ask to tally.
pub const ASKED: InstanceId = InstanceId(5);
/// The rounds instance the previous agent's tours' messages tally at.
pub const TOLD: InstanceId = InstanceId(6);
/// A tour's rounds.
pub const ROUNDS_A_TOUR: u64 = 3;

/// The rounds actor's methods a checker calls.
#[derive(Clone, Copy, Debug)]
pub struct TourMethods {
    pub tour: MethodId,
    pub rewrite: MethodId,
    pub total: MethodId,
    pub tallies: MethodId,
}

impl TourMethods {
    pub fn of(rounds: &[u8]) -> Self {
        let method = |name| crate::programs::method(rounds, name);
        Self {
            tour: method("tour"),
            rewrite: method("rewrite"),
            total: method("total"),
            tallies: method("tallies"),
        }
    }
}

/// The rounds actor's package and program, its workflows in it, and its
/// methods.
pub struct Rounds {
    /// Its package, the ELF its crate built.
    pub elf: Vec<u8>,
    pub program: Vec<u8>,
    pub methods: TourMethods,
}

impl Rounds {
    pub fn load() -> Self {
        let program = crate::programs::actor("rounds");
        Self {
            elf: crate::programs::package("rounds"),
            methods: TourMethods::of(&program),
            program,
        }
    }

    /// An operator's install of it as `instance`.
    pub fn install(&self, instance: InstanceId) -> Install {
        Install {
            instance,
            elf: self.elf.clone(),
            roles: Vec::new(),
        }
    }
}

/// The tallies a rounds instance holds, each amount and how often it
/// applied, and its total, checked against what a touring client's tours
/// tallied there: every amount of a tour that ended done once, every amount
/// of one that failed once or not at all, no other, and the total their
/// sum. How many applied, or why not.
pub fn check_tallies(touring: &Touring, tallies: &[(u64, u64)], total: u64) -> Result<u64, String> {
    let ended = touring.ended.lock().unwrap();
    let of_a_tour = |amount: u64| {
        (1..=ROUNDS_A_TOUR).contains(&(amount % 10)) && ended.contains_key(&(amount / 10))
    };
    if let Some((amount, count)) = tallies
        .iter()
        .find(|(amount, count)| !of_a_tour(*amount) || *count != 1)
    {
        return Err(format!("amount {amount} tallied {count} times"));
    }
    let tallied = |amount: u64| tallies.iter().any(|(tally, _)| *tally == amount);
    let untallied = ended.iter().find(|(request, done)| {
        **done && !(1..=ROUNDS_A_TOUR).all(|round| tallied(*request * 10 + round))
    });
    if let Some((request, _)) = untallied {
        return Err(format!(
            "tour {request} ended done, its amounts not all tallied"
        ));
    }
    let sum: u64 = tallies.iter().map(|(amount, _)| amount).sum();
    if sum != total {
        return Err(format!(
            "a total of {total}, its tallies adding up to {sum}"
        ));
    }
    Ok(tallies.len() as u64)
}

/// A tour's arguments.
#[derive(Clone, Debug)]
pub struct Tour {
    /// The agent its rounds ask and tell.
    pub other: AgentId,
    pub amounts: Vec<u64>,
    /// How long each round sleeps, in milliseconds of batch time.
    pub nap: u64,
    pub words: u32,
    pub passes: u32,
}

impl Tour {
    /// Its arguments as a request carries them: each field's encoding in
    /// turn.
    pub fn arguments(&self) -> Vec<u8> {
        let mut bytes = (self.other.0, ASKED.0, TOLD.0).encode();
        self.amounts.encode_to(&mut bytes);
        (self.nap, self.words, self.passes).encode_to(&mut bytes);
        bytes
    }

    /// What the tour ends with when the asked rounds' total stood at
    /// `base`: the totals after each amount, and its computations' digest.
    pub fn result(&self, base: u64) -> Vec<u8> {
        let totals: Vec<u64> = self
            .amounts
            .iter()
            .scan(base, |total, amount| {
                *total += amount;
                Some(*total)
            })
            .collect();
        let digest = self.amounts.iter().fold(0, |digest, amount| {
            digest ^ churn(*amount, self.words, self.passes)
        });
        (totals, digest).encode()
    }

    /// What its amounts add up to.
    pub fn sum(&self) -> u64 {
        self.amounts.iter().sum()
    }
}

/// The rounds actor's `churn`, on the host: `passes` passes over `words`
/// pseudo-random words drawn from `seed`, each word mixed with the next.
/// Their digest.
pub fn churn(seed: u64, words: u32, passes: u32) -> u64 {
    let mut data = vec![0u64; words.max(1) as usize];
    let mut state = seed | 1;
    for value in data.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *value = state;
    }
    let len = data.len();
    for pass in 0..passes {
        for index in 0..len {
            let next = data[(index + 1) % len];
            data[index] =
                data[index].rotate_left(pass % 63 + 1) ^ next.wrapping_mul(0x2545_f491_4f6c_dd1d);
        }
    }
    data.iter()
        .fold(0, |digest, value| digest.rotate_left(7) ^ value)
}

/// A read of `workflow` at the agent whose identity is `identity`, signed
/// by `key`, good until `not_after`, waiting up to `wait_ms` for it to end.
pub fn signed_read(
    identity: &[u8; 32],
    key: &SigningKey,
    not_after: u64,
    consistency: Consistency,
    workflow: WorkflowId,
    wait_ms: u64,
) -> Vec<u8> {
    let public = key.verifying_key().to_bytes();
    let message = workflow_message(identity, &public, not_after, consistency, workflow, wait_ms);
    WorkflowRead {
        key: public,
        not_after,
        consistency,
        workflow,
        wait_ms,
        signature: key.sign(&message).to_bytes(),
    }
    .encode()
}

/// How long past the agents' time a read waiting `wait_ms` is signed to
/// be good: half the horizon a node allows, so a node whose clock jumps
/// either way takes it.
fn signed_for(wait_ms: u64) -> u64 {
    workflow_read_horizon(wait_ms) - WORKFLOW_READ_HORIZON_MS / 2
}

/// How long a tour may take to end once started, through every failure.
pub const TOUR_ENDS: Duration = Duration::from_secs(120);
/// How long a read of a tour waits for it to end, within an attempt.
const READ_WAIT: Duration = Duration::from_millis(1000);

/// The tour request `request` of a touring client starts, asking and
/// telling `other`: three rounds of amounts no other request uses, each
/// sleeping a few milliseconds, then computing for a few of its steps'
/// shares.
pub fn tour(other: AgentId, request: u64) -> Tour {
    Tour {
        other,
        amounts: (1..=ROUNDS_A_TOUR)
            .map(|round| request * 10 + round)
            .collect(),
        nap: 5,
        words: 128,
        passes: 400,
    }
}

/// A tour's start, as it was answered.
#[derive(Clone, Copy)]
struct Started {
    workflow: WorkflowId,
    /// The secret of the key that owns it: its session's.
    secret: [u8; 32],
    /// The applied index the start was answered at.
    at: u64,
}

/// What a touring client knows of its tours: each request starts one,
/// which it reads to its end before its next.
pub struct Touring {
    pub methods: TourMethods,
    /// Each request's tour once its start was answered.
    started: Mutex<BTreeMap<u64, Started>>,
    /// The workflow in flight, for faults aimed at it.
    current: Mutex<Option<WorkflowId>>,
    /// The asked rounds' total once every tour so far ended: unknown once
    /// one failed, whose rounds may or may not have run, or run later.
    base: Mutex<Option<u64>>,
    /// Each tour that ended, by its request: whether done, as a straight
    /// run ends it, or failed.
    ended: Mutex<BTreeMap<u64, bool>>,
}

impl Touring {
    pub fn new(methods: TourMethods) -> Self {
        Self {
            methods,
            started: Mutex::new(BTreeMap::new()),
            current: Mutex::new(None),
            base: Mutex::new(Some(0)),
            ended: Mutex::new(BTreeMap::new()),
        }
    }

    /// The tour in flight, if one is.
    pub fn current(&self) -> Option<WorkflowId> {
        *self.current.lock().unwrap()
    }

    /// The tours ended done, and those failed.
    pub fn ended(&self) -> (u64, u64) {
        let ended = self.ended.lock().unwrap();
        let done = ended.values().filter(|done| **done).count() as u64;
        (done, ended.len() as u64 - done)
    }
}

impl Client {
    /// Its tours, if it is a touring client.
    pub fn tours(&self) -> Option<&Touring> {
        self.touring.as_ref()
    }

    /// The start of request `request`'s tour answered with `workflow`, at
    /// the session `timed` sent it in: recorded, the same workflow for
    /// every answer, so no request starts two.
    pub(crate) fn tour_started(
        &self,
        request: u64,
        workflow: WorkflowId,
        at: u64,
        timed: &crate::Timed,
    ) {
        let touring = self.touring.as_ref().expect("a touring client");
        let mut started = touring.started.lock().unwrap();
        match started.get(&request) {
            Some(first) => assert_eq!(
                first.workflow, workflow,
                "client {}: request {request} started two workflows",
                self.number
            ),
            None => {
                let secret = timed.secret;
                started.insert(
                    request,
                    Started {
                        workflow,
                        secret,
                        at,
                    },
                );
                *touring.current.lock().unwrap() = Some(workflow);
            }
        }
    }

    /// Read request `request`'s tour at every node in turn until it ends,
    /// by its owner's key, and check its result: the totals and digest a
    /// straight run gives, or a failure, which leaves the tours' effects
    /// bounded rather than known.
    pub(crate) fn finish_tour(&self, nodes: &dyn Nodes, request: u64) {
        let touring = self.touring.as_ref().expect("a touring client");
        let Started {
            workflow,
            secret,
            at: mut floor,
        } = touring.started.lock().unwrap()[&request];
        let key = SigningKey::from_bytes(&secret);
        let tour = tour(self.next_agent().expect("the next agent"), request);
        let path = format!("/agents/{}/workflows", self.agent.0);
        let until = Instant::now() + TOUR_ENDS;
        let count = nodes.count();
        let mut at = 1 + ((request + u64::from(self.number)) % u64::from(count)) as NodeNumber;
        let mut turn = 0u64;
        let outcome = loop {
            assert!(
                Instant::now() < until,
                "client {}: tour {request} (workflow {}) never ended\n{}",
                self.number,
                workflow.0,
                nodes.report(self.agent)
            );
            turn += 1;
            let consistency = if turn.is_multiple_of(3) {
                Consistency::Linearizable
            } else {
                Consistency::Applied { at: floor }
            };
            let wait = READ_WAIT.as_millis() as u64;
            let not_after = nodes.time() + signed_for(wait);
            let body = signed_read(&self.identity, &key, not_after, consistency, workflow, wait);
            match post_within(nodes.target(at), &path, &body, crate::ATTEMPT + READ_WAIT) {
                Ok(Response::Workflow {
                    status: WorkflowStatus::Ended(outcome),
                    ..
                }) => break outcome,
                Ok(Response::Workflow {
                    status: WorkflowStatus::Unknown,
                    ..
                }) => panic!(
                    "client {}: node {at} knows no tour {request} (workflow {}), its owner reading\n{}",
                    self.number,
                    workflow.0,
                    nodes.report(self.agent)
                ),
                Ok(Response::Workflow { at: read_at, .. }) => {
                    nodes.log().saw("tour read before its end");
                    floor = floor.max(read_at);
                }
                Ok(
                    Response::Rejected(Rejection::Behind | Rejection::StaleQuery { .. })
                    | Response::TimedOut
                    | Response::Stopped
                    | Response::Unavailable
                    | Response::Busy
                    | Response::NotLeader { .. }
                    | Response::Elsewhere { .. },
                )
                | Err(_) => {
                    nodes.log().saw("tour read unanswered");
                    at = at % count + 1;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(other) => panic!(
                    "client {}: a read of tour {request} at node {at}: {other:?}",
                    self.number
                ),
            }
        };
        *touring.current.lock().unwrap() = None;
        // Another key reads nothing of it.
        if request.is_multiple_of(4) {
            let stranger = SigningKey::from_bytes(&[0xee; 32]);
            let consistency = Consistency::Applied { at: floor };
            let body = signed_read(
                &self.identity,
                &stranger,
                nodes.time() + signed_for(0),
                consistency,
                workflow,
                0,
            );
            if let Ok(Response::Workflow { status, .. }) =
                post_within(nodes.target(at), &path, &body, crate::ATTEMPT)
            {
                assert_eq!(
                    status,
                    WorkflowStatus::Unknown,
                    "client {}: another key read tour {request}",
                    self.number
                );
                nodes.log().saw("tour unknown to another key");
            }
        }
        let mut base = touring.base.lock().unwrap();
        match outcome {
            Outcome::Done(result) => {
                match *base {
                    Some(total) => assert_eq!(
                        result,
                        tour.result(total),
                        "client {}: tour {request} (workflow {}) ended unlike a straight run",
                        self.number,
                        workflow.0
                    ),
                    // Rounds of a failed tour may have run since: its
                    // digest is known, and each total holds its amount.
                    None => {
                        let decode = |bytes: &[u8]| <(Vec<u64>, u64)>::decode(bytes).unwrap().0;
                        let ((totals, digest), (_, expected)) =
                            (decode(&result), decode(&tour.result(0)));
                        assert_eq!(
                            digest, expected,
                            "client {}: tour {request}'s digest",
                            self.number
                        );
                        let rises = totals.windows(2).zip(&tour.amounts[1..]);
                        assert!(
                            rises
                                .into_iter()
                                .all(|(pair, amount)| pair[1] >= pair[0] + amount),
                            "client {}: tour {request}'s totals {totals:?}",
                            self.number
                        );
                    }
                }
                *base = base.map(|total| total + tour.sum());
                touring.ended.lock().unwrap().insert(request, true);
                nodes.log().saw("tour ended as a straight run");
            }
            failed => {
                nodes.log().event(format!(
                    "client {} tour {request} (workflow {}) failed: {failed:?}",
                    self.number, workflow.0
                ));
                nodes.log().saw("tour failed");
                *base = None;
                touring.ended.lock().unwrap().insert(request, false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A touring client's record of tours 1 (done) and 2 (failed).
    fn touring() -> Touring {
        let id = MethodId(0);
        let methods = TourMethods {
            tour: id,
            rewrite: id,
            total: id,
            tallies: id,
        };
        let touring = Touring::new(methods);
        touring
            .ended
            .lock()
            .unwrap()
            .extend([(1, true), (2, false)]);
        touring
    }

    /// Every amount of a done tour once, any of a failed tour's once or not
    /// at all, and nothing else: a duplicate, a lost amount or a stray one
    /// shows, whatever failed.
    #[test]
    fn tallies_are_exact_through_a_failed_tour() {
        let touring = touring();
        let check = |tallies: &[(u64, u64)]| {
            let total = tallies.iter().map(|(amount, count)| amount * count).sum();
            check_tallies(&touring, tallies, total)
        };
        let done = [(11, 1), (12, 1), (13, 1)];
        assert_eq!(check(&done), Ok(3));
        assert_eq!(check(&[&done[..], &[(22, 1)]].concat()), Ok(4));
        assert!(check(&[(11, 2), (12, 1), (13, 1)]).is_err(), "a duplicate");
        assert!(
            check(&[(11, 1), (12, 1), (22, 2)]).is_err(),
            "a failed tour's twice"
        );
        assert!(check(&[(11, 1), (12, 1)]).is_err(), "a done tour's lost");
        assert!(
            check(&[&done[..], &[(31, 1)]].concat()).is_err(),
            "no tour's"
        );
        assert!(check_tallies(&touring, &done, 35).is_err(), "a total off");
    }
}
