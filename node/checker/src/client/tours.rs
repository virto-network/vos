//! A touring client's tours: each started, read to its end by its owner,
//! and checked; and the tallies they leave.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use vos_node::client::{post_within, workflow_read_not_after};
use vos_wire::Decode;
use vos_wire::ids::WorkflowId;
use vos_wire::ingress::{Consistency, Rejection, Response, WorkflowStatus};
use vos_wire::result::Outcome;

use super::Client;
use crate::model::Nodes;
use crate::rounds::{ROUNDS_A_TOUR, TourMethods, signed_read, tour};

/// How long a tour may take to end once started, through every failure.
pub(crate) const TOUR_ENDS: Duration = Duration::from_secs(120);
/// How long a read of a tour waits for it to end, within an attempt.
const READ_WAIT: Duration = Duration::from_millis(1000);

/// The tallies a rounds instance holds, each amount and how often it
/// applied, and its total, checked against what a touring client's tours
/// tallied there: every amount of a tour that ended done once, every amount
/// of one that failed once or not at all, no other, and the total their
/// sum. How many applied, or why not.
pub fn check_tallies(touring: &Touring, tallies: &[(u64, u64)], total: u64) -> Result<u64, String> {
    let tours = touring.tours();
    let ended = &tours.ended;
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
    tours: Mutex<Tours>,
}

/// A touring client's tours, as far as it knows them.
struct Tours {
    /// Each request's tour once its start was answered.
    started: BTreeMap<u64, Started>,
    /// The workflow in flight, for faults aimed at it.
    current: Option<WorkflowId>,
    /// The asked rounds' total once every tour so far ended: unknown once
    /// one failed, whose rounds may or may not have run, or run later.
    base: Option<u64>,
    /// Each tour that ended, by its request: whether done, as a straight
    /// run ends it, or failed.
    ended: BTreeMap<u64, bool>,
}

impl Touring {
    pub(crate) fn new(methods: TourMethods) -> Self {
        Self {
            methods,
            tours: Mutex::new(Tours {
                started: BTreeMap::new(),
                current: None,
                base: Some(0),
                ended: BTreeMap::new(),
            }),
        }
    }

    fn tours(&self) -> std::sync::MutexGuard<'_, Tours> {
        self.tours.lock().unwrap()
    }

    /// The tour in flight, if one is.
    pub fn current(&self) -> Option<WorkflowId> {
        self.tours().current
    }

    /// The tours ended done, and those failed.
    pub fn ended(&self) -> (u64, u64) {
        let ended = &self.tours().ended;
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
    pub(super) fn tour_started(
        &self,
        request: u64,
        workflow: WorkflowId,
        at: u64,
        timed: &super::Timed,
    ) {
        let touring = self.touring.as_ref().expect("a touring client");
        let mut tours = touring.tours();
        match tours.started.get(&request) {
            Some(first) => assert_eq!(
                first.workflow, workflow,
                "client {}: request {request} started two workflows",
                self.number
            ),
            None => {
                let secret = timed.secret;
                tours.started.insert(
                    request,
                    Started {
                        workflow,
                        secret,
                        at,
                    },
                );
                tours.current = Some(workflow);
            }
        }
    }

    /// Read request `request`'s tour at every node in turn until it ends,
    /// by its owner's key, and check its result: the totals and digest a
    /// straight run gives, or a failure, which leaves the tours' effects
    /// bounded rather than known.
    pub(super) fn finish_tour(&self, nodes: &dyn Nodes, request: u64) {
        let touring = self.touring.as_ref().expect("a touring client");
        let Started {
            workflow,
            secret,
            at: mut floor,
        } = touring.tours().started[&request];
        let key = SigningKey::from_bytes(&secret);
        let tour = tour(self.next_agent().expect("the next agent"), request);
        let path = format!("/agents/{}/workflows", self.agent.0);
        let until = Instant::now() + TOUR_ENDS;
        let count = nodes.count();
        let mut at = super::node_at(request + u64::from(self.number), count);
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
            let not_after = workflow_read_not_after(nodes.time(), wait);
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
        touring.tours().current = None;
        // Another key reads nothing of it.
        if request.is_multiple_of(4) {
            let stranger = SigningKey::from_bytes(&[0xee; 32]);
            let consistency = Consistency::Applied { at: floor };
            let body = signed_read(
                &self.identity,
                &stranger,
                workflow_read_not_after(nodes.time(), 0),
                consistency,
                workflow,
                0,
            );
            if let Ok(Response::Workflow { status, .. }) = super::post(nodes, at, &path, &body) {
                assert_eq!(
                    status,
                    WorkflowStatus::Unknown,
                    "client {}: another key read tour {request}",
                    self.number
                );
                nodes.log().saw("tour unknown to another key");
            }
        }
        let mut tours = touring.tours();
        match outcome {
            Outcome::Done(result) => {
                match tours.base {
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
                tours.base = tours.base.map(|total| total + tour.sum());
                tours.ended.insert(request, true);
                nodes.log().saw("tour ended as a straight run");
            }
            failed => {
                nodes.log().event(format!(
                    "client {} tour {request} (workflow {}) failed: {failed:?}",
                    self.number, workflow.0
                ));
                nodes.log().saw("tour failed");
                tours.base = None;
                tours.ended.insert(request, false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use vos_wire::ids::MethodId;

    use super::*;

    /// A touring client's record of tours 1 (done) and 2 (failed).
    fn touring() -> Touring {
        let id = MethodId(0);
        let methods = TourMethods {
            tour: id,
            total: id,
            tallies: id,
        };
        let touring = Touring::new(methods);
        touring.tours().ended.extend([(1, true), (2, false)]);
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
