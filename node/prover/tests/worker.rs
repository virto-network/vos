//! The worker over a model of its node, its prover and its venue: a
//! restart mid-proof leaves one proof, a stop's not counted when the node
//! was stopping, a submission made twice is accepted once, a leader change
//! proves nothing twice, a dead statement is skipped, jobs age out and go
//! with their agent, an unfinished job's kernel is held and one never
//! fetched refused, a record whose re-run is not its statement is refused,
//! and a refusal that may not hold later is submitted again, a venue's
//! failures to judge it counted across restarts.

mod support;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_node_prover::{
    Jobs, MAX_ATTEMPTS, MAX_RESUBMITS, Options, REFUSED_KERNEL, REFUSED_RERUN, REFUSED_ROOTLESS,
    REFUSED_UNWITNESSED, State,
};
use vos_venue::vos_statement::ProgramId;
use vos_wire::result::Attest;
use vos_wire::vos_anchor::MAX_ROOT_AGE_MS;

use support::*;

/// A node stopping while it proves leaves its job proving and no proof;
/// opened again, it proves the statement once, keeps one proof, records it
/// and has it accepted.
#[test]
fn a_restart_mid_proof_leaves_one_proof() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    venue.anchor(3);
    prover.stop.store(true, Ordering::SeqCst);
    let mut first = worker(&node, &jobs, &prover, &venue);
    // The node stops mid-proof: its worker never returns.
    std::thread::spawn(move || first.step());
    while states(&jobs) != [State::Proving] {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(node.blobs(), 0, "no proof kept");

    let mut second = worker(&node, &jobs, &prover, &venue);
    assert_eq!(states(&jobs), [State::Queued], "queued again on opening");
    let stepped = second.step().unwrap();
    assert!(stepped.proved);
    second.step().unwrap();
    assert_eq!(states(&jobs), [State::Accepted]);
    assert_eq!(prover.made.load(Ordering::SeqCst), 1, "proved once");
    assert_eq!(node.blobs(), 1, "one proof kept");
    assert_eq!(proofs_held(&node), 0, "its pin gone once accepted");
    assert_eq!(agent.lock().unwrap().proven.len(), 1, "one proof recorded");
    assert_eq!(venue.accepted(), 1);
    // Read once: the record makes no second job.
    second.step().unwrap();
    assert_eq!(jobs.all().unwrap().len(), 1);
}

/// A submission whose answer is lost stays submitted and goes again; the
/// venue holds it once and answers the second a repeat, counted as
/// accepted. A statement the agent has not recorded proved waits for the
/// record, and one whose roots are not anchored for the anchor.
#[test]
fn a_duplicate_submission_is_accepted_once() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    let retry = Duration::from_millis(300);
    let options = Options { retry, ..options() };
    let mut worker = worker_with(&node, &jobs, &prover, &venue, options);
    worker.step().unwrap();
    let held = |state: &State| {
        state
            .proof()
            .is_some_and(|proof| node.pins.lock().unwrap().contains(&proof))
    };
    assert!(matches!(states(&jobs)[..], [State::Proved { .. }]));
    assert!(held(&states(&jobs)[0]), "its proof pinned once proved");
    worker.step().unwrap();
    assert_eq!(
        venue.submissions.load(Ordering::SeqCst),
        0,
        "not anchored yet"
    );
    venue.anchor(3);
    venue.lose.store(true, Ordering::SeqCst);
    worker.step().unwrap();
    assert!(
        matches!(states(&jobs)[..], [State::Submitted { .. }]),
        "its answer lost"
    );
    worker.step().unwrap();
    assert_eq!(
        venue.submissions.load(Ordering::SeqCst),
        1,
        "not again before its wait"
    );
    std::thread::sleep(retry);
    worker.step().unwrap();
    assert_eq!(states(&jobs), [State::Accepted]);
    assert_eq!(venue.submissions.load(Ordering::SeqCst), 2);
    assert_eq!(venue.accepted(), 1, "accepted once");
    assert_eq!(prover.made.load(Ordering::SeqCst), 1);
    assert_eq!(proofs_held(&node), 0, "its pin gone once accepted");
}

/// A prover that panics on a statement is caught: the job is queued again,
/// its attempts counted across restarts, and refused after three.
#[test]
fn a_prover_that_panics_gives_up_after_three_attempts() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    prover.panics.store(true, Ordering::SeqCst);
    for attempt in 1..=MAX_ATTEMPTS {
        let mut worker = worker(&node, &jobs, &prover, &venue);
        worker.step().unwrap();
        let (_, job) = jobs.all().unwrap().pop().unwrap();
        assert_eq!((job.state, job.attempts), (State::Queued, attempt));
    }
    let mut worker = worker(&node, &jobs, &prover, &venue);
    worker.step().unwrap();
    assert_eq!(states(&jobs), [State::Refused(REFUSED_KERNEL)]);
    assert_eq!(venue.submissions.load(Ordering::SeqCst), 0);
}

/// Leadership moves after the first leader proved and recorded a statement,
/// before its roots were anchored: the new leader proves nothing again,
/// fetches the proof from the first and submits it; the first, no longer
/// leading, submits nothing. A statement recorded after the change is
/// proved by the new leader. Without the proofs, a leader whose records
/// kept no witness once recorded proved refuses each for that.
#[test]
fn a_leader_change_proves_nothing_twice() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let (a, b) = (Node::new(&agent, true), Node::new(&agent, false));
    b.peer(&a);
    let (prover, venue) = (Arc::new(Proofs::default()), Venue::at(after(3)));
    let (a_jobs, b_jobs) = (MemoryJobs::default(), MemoryJobs::default());
    let mut on_a = worker(&a, &a_jobs, &prover, &venue);
    let mut on_b = worker(&b, &b_jobs, &prover, &venue);
    on_a.step().unwrap();
    on_b.step().unwrap();
    assert!(
        matches!(states(&b_jobs)[..], [State::Proved { .. }]),
        "a follower reads the record, the leader's proof recorded"
    );
    assert_eq!(agent.lock().unwrap().proven.len(), 1);

    a.leads.store(false, Ordering::SeqCst);
    b.leads.store(true, Ordering::SeqCst);
    venue.anchor(3);
    agent.lock().unwrap().attests(vec![attest(4, 2)]);
    venue.now.store(after(4), Ordering::SeqCst);
    venue.anchor(4);
    for _ in 0..4 {
        on_a.step().unwrap();
        on_b.step().unwrap();
    }
    assert!(
        states(&a_jobs)
            .iter()
            .all(|state| matches!(state, State::Queued | State::Proved { .. })),
        "the old leader reads both, submits neither: {:?}",
        states(&a_jobs)
    );
    assert_eq!(states(&b_jobs), [State::Accepted, State::Accepted]);
    assert_eq!(
        prover.made.load(Ordering::SeqCst),
        2,
        "each statement proved once"
    );
    assert_eq!(venue.accepted(), 2);
    assert_eq!(b.blobs(), 2, "the first's proof fetched, the second's made");

    // A third statement proved by a leader whose proof then is lost: its
    // record kept no witness once recorded proved, so a new leader that
    // never fetches the proofs refuses each for that, proving none again.
    agent.lock().unwrap().attests(vec![attest(5, 3)]);
    venue.now.store(after(5), Ordering::SeqCst);
    on_b.step().unwrap();
    b.blobs.lock().unwrap().clear();
    b.leads.store(false, Ordering::SeqCst);
    let c = Node::new(&agent, true);
    let c_jobs = MemoryJobs::default();
    let impatient = Options {
        patience: Duration::ZERO,
        ..options()
    };
    let mut on_c = worker_with(&c, &c_jobs, &prover, &venue, impatient);
    venue.anchor(5);
    for _ in 0..6 {
        on_c.step().unwrap();
    }
    assert_eq!(
        states(&c_jobs),
        [State::Refused(REFUSED_UNWITNESSED); 3],
        "{:?}",
        states(&c_jobs)
    );
    assert_eq!(prover.made.load(Ordering::SeqCst), 3, "none proved again");
}

/// A statement whose anchor would pass `MaxRootAge` by the venue's time
/// before its proof ends is dead, never proved; one proved whose anchor
/// then ages is dead, never submitted.
#[test]
fn a_dead_statement_is_skipped() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let deadline = CLOCK.boundary(3).unwrap() + MAX_ROOT_AGE_MS;
    let expected = options().expected.as_millis() as u64;
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(deadline - expected + 1),
    );
    venue.anchor(3);
    let mut worker = worker(&node, &jobs, &prover, &venue);
    worker.step().unwrap();
    assert_eq!(states(&jobs), [State::Dead]);
    assert_eq!(prover.made.load(Ordering::SeqCst), 0, "never proved");

    agent.lock().unwrap().attests(vec![attest(4, 2)]);
    let deadline = CLOCK.boundary(4).unwrap() + MAX_ROOT_AGE_MS;
    venue.now.store(deadline - expected, Ordering::SeqCst);
    worker.step().unwrap();
    let proved = |state: &State| matches!(state, State::Proved { .. });
    assert!(states(&jobs).iter().any(proved));
    venue.now.store(deadline + 1, Ordering::SeqCst);
    venue.anchor(4);
    worker.step().unwrap();
    assert_eq!(states(&jobs), [State::Dead, State::Dead]);
    assert_eq!(
        venue.submissions.load(Ordering::SeqCst),
        0,
        "never submitted"
    );
    let backlog = worker.backlog().unwrap();
    assert_eq!((backlog.dead, backlog.pending()), (2, 0));
    assert_eq!(worker.prune().unwrap(), 2, "pruned once aged");
}

/// Jobs age out: an unfinished job whose roots aged past `MaxRootAge` by
/// the venue's time is dead, a finished one removed, their proofs held no
/// longer, and a refused record stating no root ages by its window. The
/// jobs of an agent the node does not replicate now are kept as they are,
/// the agent perhaps back soon, until they age.
#[test]
fn jobs_age_out_and_outlast_their_agents_absence() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    let rootless = Attest {
        roots: Vec::new(),
        ..attest(3, 9)
    };
    agent
        .lock()
        .unwrap()
        .attests(vec![attest(3, 1), attest(4, 2), rootless]);
    let node = Node::new(&agent, false);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(4)),
    );
    let mut worker = worker(&node, &jobs, &prover, &venue);
    worker.step().unwrap();
    let count = |jobs: &MemoryJobs, wanted: State| {
        states(jobs)
            .into_iter()
            .filter(|state| *state == wanted)
            .count()
    };
    assert_eq!(count(&jobs, State::Queued), 2);
    assert_eq!(count(&jobs, State::Refused(REFUSED_ROOTLESS)), 1);
    let aged = CLOCK.boundary(3).unwrap() + MAX_ROOT_AGE_MS + 1;
    venue.now.store(aged, Ordering::SeqCst);
    assert_eq!(worker.prune().unwrap(), 1, "the rootless one, of window 3");
    assert_eq!(count(&jobs, State::Dead), 1, "window 3's aged, 4's not");
    assert_eq!(worker.prune().unwrap(), 1, "the dead job removed once aged");

    node.replicates.store(false, Ordering::SeqCst);
    assert_eq!(worker.prune().unwrap(), 0);
    assert_eq!(states(&jobs), [State::Queued], "kept, its agent absent");
}

/// An unfinished job's kernel is held while the job waits, and no longer
/// once it finishes; a record whose kernel this node lacks waits for it,
/// however long, and once it arrives its statement is proved under its own
/// program's id.
#[test]
fn a_kernel_is_held_and_one_fetched_late_proves() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    venue.anchor(3);
    let kernel = hash(KERNEL);
    let mut worker = worker(&node, &jobs, &prover, &venue);
    worker.step().unwrap();
    assert!(
        node.pins.lock().unwrap().contains(&kernel),
        "held while proved"
    );
    worker.step().unwrap();
    assert_eq!(states(&jobs), [State::Accepted]);
    worker.step().unwrap();
    assert!(!node.pins.lock().unwrap().contains(&kernel), "no longer");

    node.no_kernel.store(true, Ordering::SeqCst);
    agent.lock().unwrap().attests(vec![attest(3, 2)]);
    let impatient = Options {
        patience: Duration::from_millis(100),
        ..options()
    };
    let mut worker = worker_with(&node, &jobs, &prover, &venue, impatient);
    worker.step().unwrap();
    assert_eq!(
        states(&jobs),
        [State::Accepted],
        "its record waits for the kernel"
    );
    std::thread::sleep(Duration::from_millis(150));
    worker.step().unwrap();
    assert_eq!(
        states(&jobs),
        [State::Accepted],
        "past its patience, waiting"
    );
    node.no_kernel.store(false, Ordering::SeqCst);
    for _ in 0..3 {
        worker.step().unwrap();
    }
    assert_eq!(states(&jobs), [State::Accepted, State::Accepted]);
    assert_eq!(prover.made.load(Ordering::SeqCst), 2);
    let program = ProgramId([KERNEL.len() as u32; 8]);
    let id = vos_node_prover::statement(&attest(3, 2), program).id();
    assert!(venue.accepted.lock().unwrap().contains(&id.0), "its own id");
}

/// A statement recorded proved whose proof never arrives, its record
/// without its witness, is refused for that reason, its kernel never run.
#[test]
fn a_witnessless_record_is_refused_for_it() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    let proved = Attest {
        witness_input: Vec::new(),
        ..attest(3, 1)
    };
    let program = ProgramId([KERNEL.len() as u32; 8]);
    let id = vos_node_prover::statement(&proved, program).id();
    {
        let mut agent = agent.lock().unwrap();
        agent.attests(vec![proved]);
        agent.proven.insert(id.0, [0xee; 32]);
    }
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    venue.anchor(3);
    let impatient = Options {
        patience: Duration::ZERO,
        ..options()
    };
    let mut worker = worker_with(&node, &jobs, &prover, &venue, impatient);
    for _ in 0..4 {
        worker.step().unwrap();
    }
    assert_eq!(states(&jobs), [State::Refused(REFUSED_UNWITNESSED)]);
    assert_eq!(prover.made.load(Ordering::SeqCst), 0);
}

/// A proof under way when the node stops is not counted against its
/// statement when the node was stopping then, as its operator stops it;
/// it is when the node was not, as a kernel that kills it would.
#[test]
fn a_stop_mid_proof_counts_only_when_the_node_was_not_stopping() {
    for stopping in [true, false] {
        let agent = Arc::new(Mutex::new(Agent::default()));
        agent.lock().unwrap().attests(vec![attest(3, 1)]);
        let node = Node::new(&agent, true);
        let (jobs, prover, venue) = (
            MemoryJobs::default(),
            Arc::new(Proofs::default()),
            Venue::at(after(3)),
        );
        prover.stop.store(true, Ordering::SeqCst);
        let mut first = worker(&node, &jobs, &prover, &venue);
        std::thread::spawn(move || first.step());
        while states(&jobs) != [State::Proving] {
            std::thread::sleep(Duration::from_millis(5));
        }
        jobs.set_stopping(stopping).unwrap();
        worker(&node, &jobs, &prover, &venue);
        let (_, job) = jobs.all().unwrap().pop().unwrap();
        assert_eq!(job.state, State::Queued);
        assert_eq!(job.attempts, u32::from(!stopping), "stopping: {stopping}");
        assert!(!jobs.stopping().unwrap(), "running again");
    }
}

/// A record whose re-run is not its statement (its io-hash not the
/// record's) is refused by the prover, never kept, recorded or submitted;
/// the next record is proved.
#[test]
fn an_io_hash_mismatch_is_refused() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent
        .lock()
        .unwrap()
        .attests(vec![attest(3, 1), attest(3, 2)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    venue.anchor(3);
    *prover.refused.lock().unwrap() = Some(vec![1]);
    let mut worker = worker(&node, &jobs, &prover, &venue);
    for _ in 0..3 {
        worker.step().unwrap();
    }
    let mut states = states(&jobs);
    states.sort_by_key(|state| matches!(state, State::Accepted));
    assert_eq!(states, [State::Refused(REFUSED_RERUN), State::Accepted]);
    assert_eq!(node.blobs(), 1);
    assert_eq!(agent.lock().unwrap().proven.len(), 1);
    assert_eq!(venue.accepted(), 1);
    let backlog = worker.backlog().unwrap();
    assert_eq!((backlog.refused, backlog.accepted), (1, 1));
}

/// A statement refused for now, a root not anchored (5) and then a refine
/// out of gas (`0x1001`), is submitted again after a backoff, doubled, and
/// accepted; one refused for good (3, another program) stays refused.
#[test]
fn a_transient_refusal_is_submitted_again() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    let retry = Duration::from_millis(200);
    let options = Options { retry, ..options() };
    let mut worker = worker_with(&node, &jobs, &prover, &venue, options);
    // Proved and recorded, its root not anchored yet.
    while agent.lock().unwrap().proven.is_empty() {
        worker.step().unwrap();
    }
    venue.anchor(3);
    let submitted = |states: Vec<State>| matches!(states[..], [State::Submitted { .. }]);
    *venue.refuse.lock().unwrap() = vec![5, 0x1001];
    worker.step().unwrap();
    assert!(submitted(states(&jobs)), "5: kept");
    std::thread::sleep(retry);
    worker.step().unwrap();
    assert!(submitted(states(&jobs)), "0x1001: kept");
    worker.step().unwrap();
    assert_eq!(
        venue.submissions.load(Ordering::SeqCst),
        2,
        "not again before its doubled wait"
    );
    std::thread::sleep(retry * 2);
    worker.step().unwrap();
    assert_eq!(states(&jobs), [State::Accepted]);
    assert_eq!(venue.accepted(), 1);

    agent.lock().unwrap().attests(vec![attest(3, 2)]);
    *venue.refuse.lock().unwrap() = vec![3];
    while venue.submissions.load(Ordering::SeqCst) < 4 {
        worker.step().unwrap();
    }
    let finished = states(&jobs);
    assert!(finished.contains(&State::Refused(3)), "3: final");
    assert!(finished.contains(&State::Accepted));
}

/// A venue that fails to judge a statement every time (`0x1001`) refuses
/// it after [`MAX_RESUBMITS`] more submissions.
#[test]
fn resubmissions_are_bounded() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    venue.anchor(3);
    let retry = Duration::from_millis(1);
    let options = Options { retry, ..options() };
    let mut worker = worker_with(&node, &jobs, &prover, &venue, options);
    *venue.refuse.lock().unwrap() = vec![0x1001; 64];
    let start = std::time::Instant::now();
    while states(&jobs) != [State::Refused(0x1001)] {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{:?}",
            states(&jobs)
        );
        worker.step().unwrap();
    }
    assert_eq!(
        venue.submissions.load(Ordering::SeqCst),
        MAX_RESUBMITS as usize + 1
    );
}

/// A statement survives a venue unfunded for longer than
/// [`MAX_RESUBMITS`] submissions, which the operator's to fix; and one
/// whose acceptance's answer is lost every time is accepted, its last
/// submission answered a repeat.
#[test]
fn a_statement_outlasts_a_pause_and_a_lost_answer() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    venue.anchor(3);
    let retry = Duration::from_millis(1);
    let options = Options { retry, ..options() };
    let mut worker = worker_with(&node, &jobs, &prover, &venue, options);
    venue
        .unfunded
        .store(3 * MAX_RESUBMITS as usize, Ordering::SeqCst);
    let start = std::time::Instant::now();
    while states(&jobs) != [State::Accepted] {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{:?}",
            states(&jobs)
        );
        worker.step().unwrap();
    }
    assert!(venue.submissions.load(Ordering::SeqCst) > 3 * MAX_RESUBMITS as usize);

    venue.lose_landed.store(true, Ordering::SeqCst);
    agent.lock().unwrap().attests(vec![attest(3, 2)]);
    while states(&jobs) != [State::Accepted, State::Accepted] {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{:?}",
            states(&jobs)
        );
        worker.step().unwrap();
    }
    assert_eq!(venue.accepted(), 2);
}

/// The count of a venue's failures to judge a statement is the job's: a
/// restart between submissions does not reset it, and the statement is
/// refused after [`MAX_RESUBMITS`] more all the same.
#[test]
fn resubmissions_are_counted_across_restarts() {
    let agent = Arc::new(Mutex::new(Agent::default()));
    agent.lock().unwrap().attests(vec![attest(3, 1)]);
    let node = Node::new(&agent, true);
    let (jobs, prover, venue) = (
        MemoryJobs::default(),
        Arc::new(Proofs::default()),
        Venue::at(after(3)),
    );
    venue.anchor(3);
    let retry = Duration::from_millis(1);
    let options = Options { retry, ..options() };
    *venue.refuse.lock().unwrap() = vec![0x1001; 64];
    let start = std::time::Instant::now();
    while states(&jobs) != [State::Refused(0x1001)] {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{:?}",
            states(&jobs)
        );
        // A fresh worker each step: a restart.
        let mut worker = worker_with(&node, &jobs, &prover, &venue, options);
        worker.step().unwrap();
        std::thread::sleep(retry);
    }
    assert_eq!(
        venue.submissions.load(Ordering::SeqCst),
        MAX_RESUBMITS as usize + 1
    );
}
