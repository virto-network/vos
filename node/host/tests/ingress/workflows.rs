//! Workflows started by clients and read by their owners: their results,
//! reads that wait within their bounds, and results collected.

use super::*;

/// The rounds actor at the served agent, its tours asking a second agent's
/// rounds.
struct Tours {
    other: AgentId,
    methods: TourMethods,
}

impl Served {
    /// Install the rounds actor with its workflows, and at a second agent
    /// the rounds its tours ask and tell.
    fn tours(&self) -> Tours {
        let operator = Operator::new(&self.target, &self.token);
        let Ok(Response::Created(other)) = operator.create_agent(Vec::new()) else {
            panic!("another agent")
        };
        let rounds = Rounds::load();
        for (agent, instance) in [(other, ASKED), (other, TOLD), (self.agent, ROUNDS)] {
            installed(operator.install(agent, &rounds.install(instance)).unwrap());
        }
        Tours {
            other,
            methods: rounds.methods,
        }
    }

    /// A tour of one round that then sleeps ten minutes of batch time,
    /// started as `client`, once it sleeps: its id.
    fn napping(&self, client: &mut Client, tours: &Tours) -> WorkflowId {
        let tour = Tour::light(tours.other, vec![7], 600_000);
        let workflow = self.start_tour(client, tours, &tour);
        wait_until("the tour sleeps", || {
            matches!(
                client.workflow(self.agent, workflow, Duration::ZERO),
                Ok(Response::Workflow {
                    status: WorkflowStatus::Sleeping { .. },
                    ..
                })
            )
        });
        workflow
    }

    /// Start `tour` as `client`: the workflow's id.
    fn start_tour(&self, client: &mut Client, tours: &Tours, tour: &Tour) -> WorkflowId {
        let answer = client
            .call(self.agent, ROUNDS, tours.methods.tour, &tour.arguments())
            .unwrap();
        match answer {
            Response::Ran {
                outcome: Outcome::Started(workflow),
                ..
            } => workflow,
            other => panic!("{other:?}"),
        }
    }
}

/// The status an answer to a workflow's read carries.
#[track_caller]
fn status(answer: Response) -> WorkflowStatus {
    match answer {
        Response::Workflow { status, .. } => status,
        other => panic!("{other:?}"),
    }
}

/// A client's request starts a workflow, answered `Started` with its id;
/// its owner reads its result by the id, waiting for it to end, and every
/// effect of its rounds applied once. Any other key, and an id no
/// workflow has, read nothing, at once.
#[test]
fn a_started_workflows_owner_reads_its_result_by_its_id() {
    let served = Served::plain();
    let tours = served.tours();
    let mut client = served.client(1);
    let tour = Tour::light(tours.other, vec![3, 4, 5], 0);
    let workflow = served.start_tour(&mut client, &tours, &tour);
    assert_eq!(
        status(
            client
                .workflow(served.agent, workflow, Duration::from_secs(20))
                .unwrap()
        ),
        WorkflowStatus::Ended(Outcome::Done(tour.result(0)))
    );
    let read = |agent: AgentId, instance: InstanceId, method: MethodId| {
        done(
            client
                .query(
                    agent,
                    instance,
                    method,
                    &[],
                    vos_node::wall_clock() + 10_000,
                )
                .unwrap(),
        )
    };
    let total = tours.methods.total;
    assert_eq!(read(tours.other, ASKED, total), 12);
    assert_eq!(read(served.agent, ROUNDS, total), 12);
    wait_until("the messages apply", || {
        read(tours.other, TOLD, total) == 12
    });

    // Another key: nothing, however long it would wait.
    let stranger = served.client(2);
    let asked = std::time::Instant::now();
    let unknown = stranger
        .workflow(served.agent, workflow, Duration::from_secs(20))
        .unwrap();
    assert_eq!(status(unknown), WorkflowStatus::Unknown);
    assert!(asked.elapsed() < Duration::from_secs(5), "answered at once");
    assert_eq!(
        status(
            client
                .workflow(served.agent, WorkflowId(workflow.0 + 1), Duration::ZERO)
                .unwrap()
        ),
        WorkflowStatus::Unknown
    );
    // Read at a later floor, linearizably, the result stays.
    assert_eq!(
        status(
            client
                .workflow_with(
                    served.agent,
                    workflow,
                    Duration::ZERO,
                    Consistency::Linearizable
                )
                .unwrap()
        ),
        WorkflowStatus::Ended(Outcome::Done(tour.result(0)))
    );
}

/// A read waits no longer than it asks, answering where the workflow
/// stands; one waiting while it sleeps answers once it ends, well within
/// its bound. Reads are signed by the key that reads, and good until their
/// time.
#[test]
fn a_read_waits_for_its_workflow_within_its_bound() {
    let served = Served::plain();
    let tours = served.tours();
    let mut client = served.client(1);
    let tour = Tour::light(tours.other, vec![7], 600_000);
    let workflow = served.start_tour(&mut client, &tours, &tour);
    let asked = std::time::Instant::now();
    let sleeping = loop {
        match status(
            client
                .workflow(served.agent, workflow, Duration::from_millis(300))
                .unwrap(),
        ) {
            // Awaiting the other agent's answer, which has yet to apply.
            WorkflowStatus::Awaiting { agent, .. } => assert_eq!(agent, tours.other),
            sleeping => break sleeping,
        }
    };
    assert!(
        matches!(sleeping, WorkflowStatus::Sleeping { until } if until >= served.now() + 590_000),
        "{sleeping:?}"
    );
    assert!(asked.elapsed() >= Duration::from_millis(300), "it waited");

    let waiting = {
        let target = served.target.clone();
        let agent = served.agent;
        let mut kept = client.sessions();
        kept.clear();
        let identities = client.identities();
        std::thread::spawn(move || {
            let client =
                Client::resume(&target, SigningKey::from_bytes(&[1; 32]), kept, identities);
            let started = std::time::Instant::now();
            let answer = client.workflow(agent, workflow, Duration::from_secs(25));
            (answer, started.elapsed())
        })
    };
    std::thread::sleep(Duration::from_millis(200));
    // The sleep comes due, and the next batch, here a call's, steps it.
    served.clock.fetch_add(600_000, Ordering::SeqCst);
    let mut other = served.client(3);
    done(served.call(&mut other, 1));
    let (answer, waited) = waiting.join().unwrap();
    assert_eq!(
        status(answer.unwrap()),
        WorkflowStatus::Ended(Outcome::Done(tour.result(0)))
    );
    assert!(
        waited < Duration::from_secs(15),
        "answered at its end: {waited:?}"
    );

    // Signed by the key that reads, good until its time.
    let identity = client.identity(served.agent).unwrap();
    let key = SigningKey::from_bytes(&[1; 32]);
    let path = format!("/agents/{}/workflows", served.agent.0);
    let now = served.now();
    let consistency = Consistency::Applied { at: 0 };
    let body = signed_read(&identity, &key, now + 10_000, consistency, workflow, 0);
    let (mut read, _) = WorkflowRead::decode(&body).unwrap();
    read.workflow = WorkflowId(workflow.0 + 1);
    assert_eq!(
        served.post(&path, &read.encode()),
        Response::Rejected(Rejection::BadSignature)
    );
    let stale = signed_read(&identity, &key, now - 1, consistency, workflow, 0);
    assert_eq!(
        served.post(&path, &stale),
        Response::Rejected(Rejection::StaleQuery { now })
    );
    // Good no longer than the horizon past its wait: a read captured
    // replays only that long.
    let far = now + workflow_read_horizon(1_000) + 1;
    let ahead = signed_read(&identity, &key, far, consistency, workflow, 1_000);
    assert_eq!(
        served.post(&path, &ahead),
        Response::Rejected(Rejection::StaleQuery { now })
    );
    let within = signed_read(&identity, &key, far - 1, consistency, workflow, 1_000);
    assert!(matches!(
        served.post(&path, &within),
        Response::Workflow { .. }
    ));
    assert!(matches!(
        served.post(&path, &body),
        Response::Workflow {
            status: WorkflowStatus::Ended(_),
            ..
        }
    ));
}

/// A read waits no longer than its node allows, however long it asks; and
/// only so many wait at once: one past them answers at once, and once one
/// ends, the next waits again.
#[test]
fn reads_wait_within_the_nodes_bounds() {
    assert_eq!(
        Config::new(Vec::new()).workflow_wait,
        Duration::from_millis(MAX_WORKFLOW_WAIT_MS)
    );
    let served = Arc::new(Served::start_with(Arc::new(vos_node::NoHooks), |config| {
        config.workflow_wait = Duration::from_secs(3);
        config.workflow_waits = 2;
    }));
    let tours = served.tours();
    let mut client = served.client(1);
    let workflow = served.napping(&mut client, &tours);
    let client = Arc::new(client);
    let read = |wait: Duration| {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let answer = client.workflow(served.agent, workflow, wait).unwrap();
            assert!(matches!(status(answer), WorkflowStatus::Sleeping { .. }));
            started.elapsed()
        })
    };
    let waiting = [read(Duration::from_secs(20)), read(Duration::from_secs(20))];
    std::thread::sleep(Duration::from_millis(500));
    let past = read(Duration::from_secs(20)).join().unwrap();
    assert!(
        past < Duration::from_millis(1_500),
        "answered at once: {past:?}"
    );
    for waited in waiting.map(|reader| reader.join().unwrap()) {
        assert!(
            (Duration::from_millis(2_900)..Duration::from_secs(10)).contains(&waited),
            "waited as long as the node allows: {waited:?}"
        );
    }
    let again = read(Duration::from_secs(1)).join().unwrap();
    assert!(
        again >= Duration::from_millis(950),
        "waits again: {again:?}"
    );
}

/// A read waiting when its node stops ends with it, never waiting out its
/// bound.
#[test]
fn a_read_waiting_ends_when_its_node_stops() {
    let served = Served::plain();
    let tours = served.tours();
    let mut client = served.client(1);
    let workflow = served.napping(&mut client, &tours);
    let agent = served.agent;
    let reading = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let answer = client.workflow(agent, workflow, Duration::from_secs(25));
        (answer, started.elapsed())
    });
    std::thread::sleep(Duration::from_millis(300));
    let Served { node, _dir, .. } = served;
    node.shutdown();
    let (answer, waited) = reading.join().unwrap();
    assert!(waited < Duration::from_secs(10), "{waited:?}: {answer:?}");
    assert!(
        !matches!(
            answer,
            Ok(Response::Workflow {
                status: WorkflowStatus::Ended(_),
                ..
            })
        ),
        "{answer:?}"
    );
}

/// An ended workflow's result is kept for its owner about an hour, then
/// collected: its owner reads it unknown, as a stranger does.
#[test]
fn a_collected_workflow_reads_unknown() {
    let served = Served::plain();
    let tours = served.tours();
    let mut client = served.client(1);
    let tour = Tour::light(tours.other, vec![2], 0);
    let workflow = served.start_tour(&mut client, &tours, &tour);
    let ended = client
        .workflow(served.agent, workflow, Duration::from_secs(20))
        .unwrap();
    assert_eq!(
        status(ended),
        WorkflowStatus::Ended(Outcome::Done(tour.result(0)))
    );
    // Its collection comes due, and the next batch, here a call's, sweeps.
    served
        .clock
        .fetch_add(defaults::WORKFLOW_KEPT_MS + 1, Ordering::SeqCst);
    let mut other = served.client(3);
    done(served.call(&mut other, 1));
    wait_until("the workflow is collected", || {
        let read = client.workflow(served.agent, workflow, Duration::ZERO);
        matches!(
            read,
            Ok(Response::Workflow {
                status: WorkflowStatus::Unknown,
                ..
            })
        )
    });
}
