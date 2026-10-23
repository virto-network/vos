//! The run, its verdicts, its measurements and its audit.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_checker::carriers::{self, Audit, Kind, Logs, Reach, Tapped};
use vos_node::{Config, Node};
use vos_node_prover::{FORMAT, Prover};
use vos_statement_service::state::keys as jam_keys;
use vos_venue::kreivo::KreivoVenue;
use vos_venue::kreivo::mock::Origin;
use vos_venue::vos_statement::{Pin, ProgramId, Statement};
use vos_venue::{NotAccepted, VenueClient};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::keys;
use vos_wire::package::SLOT_MS;
use vos_wire::peer::NodeNumber;
use vos_wire::records::{Workflow, WorkflowState};
use vos_wire::result::{Attest, Outcome};
use vos_wire::vos_anchor::{
    MAX_ROOT_AGE_MS, MIN_LENGTH_MS, RootKind, SpaceId, WindowClock, blake2b_256,
};

use crate::agents::{Agents, Asked, READ_ENDS};
use crate::common::Cluster;
use crate::cuts::results;
use crate::jam::Testnet;
use crate::kreivo::{self, Kreivo, UNITS};
use crate::record::Record;
use crate::representative::{attests, delay, replica};
use crate::venues::{Jam, Judgement, Migrating, Recorded, Serial, hex};

/// The space's windows: the shortest a venue registers.
const LENGTH_MS: u64 = MIN_LENGTH_MS;
/// How far the chain's clock moves at the end: past `MaxRootAge` by an
/// hour, so every row the service queued to drop by its hour may go.
const PAST_MAX_ROOT_AGE: i64 = MAX_ROOT_AGE_MS as i64 + 3_600_000;
/// The gate's margin past `L + D + t_prove`.
const MARGIN_MS: u64 = 30_000;
/// How long the run waits for every statement to be accepted.
const ACCEPTED_WITHIN: Duration = Duration::from_secs(1_200);

/// A kernel the run's statements are of: its blob, and its program id
/// recomputed from it.
struct Kernel {
    blob: Vec<u8>,
    program: ProgramId,
}

impl Kernel {
    fn load(prover: &Serial, actor: &str, method: &str) -> Self {
        let blob = vos_testkit::programs::kernel(actor, method);
        let program = prover.program(&blob).expect("the kernel's program id");
        Self { blob, program }
    }

    fn pin(&self, venue_bound: bool) -> Pin {
        Pin {
            program: self.program,
            venue_bound,
        }
    }

    fn statement(&self, attest: &Attest) -> Statement {
        Statement {
            format: FORMAT,
            program: self.program,
            space: attest
                .roots
                .first()
                .map_or(SpaceId::NONE, |root| root.space),
            public_args: attest.public_args.clone(),
            output: attest.output.clone(),
            roots: attest.roots.clone(),
        }
    }
}

struct Kernels {
    balance: Kernel,
    window: Kernel,
    stamped: Kernel,
    ordered: Kernel,
}

impl Kernels {
    fn of(&self, attest: &Attest) -> &Kernel {
        [&self.balance, &self.window, &self.stamped, &self.ordered]
            .into_iter()
            .find(|kernel| ProgramHash::of(&kernel.blob) == attest.program)
            .expect("a kernel of the run")
    }
}

/// Sleep until the host's clock reads `at`.
fn until(at: u64) {
    let now = vos_node::wall_clock();
    if at > now {
        std::thread::sleep(Duration::from_millis(at - now));
    }
}

/// How workflow `read` of `asked` ended, once it has, on a replica.
fn ended(cluster: &Cluster, asked: &Asked) -> Outcome {
    let mut ended = None;
    vos_checker::wait_until(
        &format!("{}'s read in window {} ends", asked.what, asked.window),
        READ_ENDS,
        || {
            ended = cluster
                .running()
                .filter(|(_, node)| node.applied(asked.agent).is_some())
                .find_map(|(_, node)| {
                    let record: Workflow = vos_checker::applied(
                        node.store(),
                        asked.agent,
                        &keys::workflow(asked.read.workflow),
                    )?;
                    match record.state {
                        WorkflowState::Ended(outcome) => Some(outcome),
                        _ => None,
                    }
                });
            ended.is_some()
        },
    );
    ended.unwrap()
}

/// The judgement a venue gave `statement` that accepted it, if one did.
fn accepted<'a>(judged: &'a [Judgement], statement: &Statement) -> Option<&'a Judgement> {
    let id = statement.id();
    judged
        .iter()
        .find(|judgement| judgement.statement.id() == id && judgement.answer == Ok(id))
}

/// Every entry `agent`'s log holds on `node`, its body as the log keeps it.
fn log_entries(node: &Node, agent: AgentId) -> Vec<u8> {
    let through = node.applied(agent).unwrap_or(0);
    (1..=through)
        .filter_map(|index| node.store().log_entry(agent, index).ok().flatten())
        .flat_map(|entry| entry.body)
        .collect()
}

/// Every frame between the nodes, by its destination and class.
type Frames = Arc<Mutex<BTreeMap<(NodeNumber, String), Vec<u8>>>>;

/// Each node's Kreivo client, by number: itself, as recorded, and as
/// tapped.
type KreivoClients =
    Arc<Mutex<BTreeMap<NodeNumber, (Arc<KreivoVenue>, Arc<Recorded>, Arc<Tapped>)>>>;

#[test]
fn a_space_moves_from_kreivo_to_jam_and_no_carrier_holds_its_internals() {
    let testnet = Testnet::from_env();
    let mut record = Record::new(&testnet.run);
    // Every debug output on, as an operator could set it: none prints in a
    // build without `debug-internals`.
    for name in carriers::DEBUG_ENVIRONMENT {
        // SAFETY: before the run starts any thread that reads the
        // environment.
        unsafe { std::env::set_var(name, "1") };
    }
    let stderr = carriers::Stderr::capture(&testnet.run);
    let logs = Logs::install();

    let prover = Arc::new(Serial::default());
    let kernels = Kernels {
        balance: Kernel::load(&prover, "balance", "at_least"),
        window: Kernel::load(&prover, "window", "settle"),
        stamped: Kernel::load(&prover, "reader", "stamped"),
        ordered: Kernel::load(&prover, "reader", "ordered"),
    };

    // The JAM service twice: `a`, where the space anchors once it
    // migrates, and `b`, another venue.
    let pins = vec![
        kernels.balance.pin(false),
        kernels.window.pin(false),
        kernels.stamped.pin(true),
        kernels.ordered.pin(false),
    ];
    let jam_a = Arc::new(testnet.deploy("a", pins.clone()));
    let jam_b = Arc::new(testnet.deploy("b", pins));
    for (name, jam) in [("a", &jam_a), ("b", &jam_b)] {
        record.note(format!(
            "JAM service {name}: id {}, venue {}",
            jam.venue.statements.service,
            hex(&jam.id().0)
        ));
    }
    let kreivo = Arc::new(Kreivo::new(&[
        kernels.balance.program,
        kernels.window.program,
    ]));

    // The space, its windows two minutes long from now; each node's venue
    // its Kreivo client until the space moves, then the JAM service.
    let origin_ms = vos_node::wall_clock() - 1_000;
    let clock = WindowClock {
        origin_ms,
        length_ms: LENGTH_MS,
    };
    let d = delay(&clock);
    let moved = Arc::new(AtomicBool::new(false));
    let jam_recorded = Arc::new(Recorded::new(jam_a.clone()));
    let jam_tapped = Arc::new(Tapped::new(jam_recorded.clone()));
    let kreivo_clients = KreivoClients::default();
    let cluster = {
        let (kreivo, clients, jam, moved) = (
            Arc::clone(&kreivo),
            Arc::clone(&kreivo_clients),
            Arc::clone(&jam_tapped),
            Arc::clone(&moved),
        );
        let prover: Arc<dyn Prover> = prover.clone();
        Cluster::in_space(
            3,
            Some(clock),
            move |number: NodeNumber, config: &mut Config| {
                let space = vos_wire::vos_anchor::space_id(
                    config.space.as_ref().unwrap().genesis().unwrap(),
                );
                let (.., before) = clients
                    .lock()
                    .unwrap()
                    .entry(number)
                    .or_insert_with(|| {
                        let client = Arc::new(kreivo.client(number, space));
                        let recorded = Arc::new(Recorded::new(client.clone()));
                        (client, recorded.clone(), Arc::new(Tapped::new(recorded)))
                    })
                    .clone();
                let after: Arc<dyn VenueClient> = jam.clone();
                config.venue = Some(Arc::new(Migrating {
                    before,
                    after,
                    moved: Arc::clone(&moved),
                }));
                config.prover = Some(Arc::clone(&prover));
            },
        )
    };
    let frames = Frames::default();
    let framed = Arc::clone(&frames);
    cluster.hub.tap(Arc::new(move |_, to, class, frame| {
        framed
            .lock()
            .unwrap()
            .entry((to, format!("{class:?}")))
            .or_default()
            .extend_from_slice(frame);
    }));
    let space = cluster.space.id();
    let genesis = cluster.space.genesis().unwrap().clone();
    record.note(format!(
        "the space {}: windows of {} s from {origin_ms}, D {} s, three nodes",
        hex(&space.0[..8]),
        LENGTH_MS / 1_000,
        d / 1_000
    ));

    // Kreivo: registered from window 0 with a founder's signature, each node
    // an authority paired with its anchor key.
    let founder = cluster
        .node(1)
        .sign_registration(&kreivo::VENUE, &kreivo::controller(), 0);
    kreivo.register(&genesis, 0, founder, &genesis.nodes);
    let sovereign = kreivo.sovereign_of(&space);
    let registered = kreivo.account(&sovereign);
    record.note(format!(
        "Kreivo: registered from window 0, 3 authorities; the sovereign account free {}, \
         held for the registration {}",
        registered.free, registered.held_registration
    ));
    let kreivo_judged = || -> Vec<Judgement> {
        kreivo_clients
            .lock()
            .unwrap()
            .values()
            .flat_map(|(_, recorded, _)| recorded.judged())
            .collect()
    };
    let agents = Agents::install(&cluster);

    // A balance read at Kreivo, in window `first`; the space migrates at
    // window k.
    let first = clock.window(vos_node::wall_clock()).unwrap() + 1;
    let k = first + 2;
    let boundary = |w: u64| clock.boundary(w).unwrap();
    until(boundary(first - 1) + 2_000);
    let mut asked = vec![agents.ask_balance(&cluster, first)];
    record.note(format!("window {first}: a balance read asked, at Kreivo"));

    // In window k − 1: registered at the JAM service from k, by a founder's
    // signature, under an ed25519 controller; migrated away from Kreivo
    // from k.
    until(boundary(k - 2) + 30_000);
    let jam_controller = SigningKey::from_bytes(&blake2b_256(&[b"vos/e2e-chain/jam/controller"]));
    let controller = jam_controller.verifying_key().to_bytes();
    let (key, signature) = cluster
        .node(1)
        .sign_registration(&jam_a.id(), &controller, k);
    let code = jam_a
        .venue
        .register_signed(&genesis, controller, k, key, signature)
        .expect("the registration lands");
    assert_eq!(code, 0, "registered at the JAM service from window {k}");
    let migrated = kreivo.migrate(&space, jam_a.id(), k);
    record.note(format!(
        "window {}: registered at JAM from window {k} (code {code}); migrated away from Kreivo \
         from window {k}: {:?}",
        k - 1,
        migrated.events
    ));

    // The nodes move to the JAM service once window k − 1 is anchored at
    // Kreivo and the balance statement accepted there: before window k
    // closes, so its anchor goes to the service.
    ended(&cluster, &asked[0]);
    let attest = attests(
        replica(&cluster, agents.balance),
        agents.balance,
        asked[0].read,
    );
    let balance_at_kreivo = kernels.balance.statement(&attest[0]);
    vos_checker::wait_until(
        "window k − 1 anchored at Kreivo and the balance statement accepted there",
        Duration::from_millis((boundary(k) + d - 10_000).saturating_sub(vos_node::wall_clock())),
        || kreivo.holds(&space, k - 1) && accepted(&kreivo_judged(), &balance_at_kreivo).is_some(),
    );
    moved.store(true, Ordering::SeqCst);
    let moved_at = vos_node::wall_clock();
    assert!(
        moved_at + 5_000 < boundary(k) + d,
        "the nodes moved before window {k} closes"
    );
    record.note(format!(
        "the nodes' venue moved to JAM {} s before window {k} closes",
        (boundary(k) + d - moved_at) / 1_000
    ));

    // At JAM: a balance and a window read in each of windows k to k + 2.
    for w in k..k + 3 {
        until(boundary(w - 1) + 2_000);
        asked.push(agents.ask_balance(&cluster, w));
        asked.push(agents.ask_window(&cluster, w));
        record.note(format!(
            "window {w}: a balance and a window read asked, at JAM"
        ));
    }
    let stated: Vec<(Asked, Attest, Statement)> = asked
        .iter()
        .map(|asked| {
            let outcome = ended(&cluster, asked);
            assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
            let attest =
                attests(replica(&cluster, asked.agent), asked.agent, asked.read)[0].clone();
            assert_eq!(attest.window, Some(asked.window));
            let statement = kernels.of(&attest).statement(&attest);
            (*asked, attest, statement)
        })
        .collect();
    vos_checker::wait_until("every statement accepted", ACCEPTED_WITHIN, || {
        let (kreivo, jam) = (kreivo_judged(), jam_recorded.judged());
        stated.iter().all(|(asked, _, statement)| {
            let judged = if asked.window < k { &kreivo } else { &jam };
            accepted(judged, statement).is_some()
        })
    });
    for (asked, _, statement) in &stated {
        let venue = if asked.window < k { "Kreivo" } else { "JAM" };
        record.note(format!(
            "accepted at {venue}: {}'s statement at window {}'s cut, format {}, {}",
            asked.what,
            asked.window,
            statement.format,
            hex(&statement.id().0[..8])
        ));
    }

    // A statement of window k, accepted at JAM, refused at Kreivo: its
    // root is not of Kreivo's range.
    let (moved_statement, moved_proof) = jam_tapped
        .submitted()
        .into_iter()
        .find(|(statement, _)| statement.roots[0].window == k)
        .expect("a statement of window k submitted at JAM");
    let node_1 = kreivo_clients.lock().unwrap()[&1].2.clone();
    let refused = node_1.submit(&moved_statement, &moved_proof);
    record.note(format!(
        "window {k}'s statement at Kreivo, past its migration: {refused:?}"
    ));
    assert_eq!(
        refused,
        Err(NotAccepted::Refused(5)),
        "unanchored at Kreivo"
    );

    // The rootless statements: `stamped` bound to JAM `a`, `ordered` of no
    // venue, proved by the run.
    let (stamped, ordered) = agents.plain(&cluster, jam_a.id());
    let rootless: Vec<(Statement, Vec<u8>)> = [&stamped, &ordered]
        .into_iter()
        .map(|attest| {
            let kernel = kernels.of(attest);
            let proof = prover
                .prove(&kernel.blob, attest)
                .expect("a rootless proof");
            (kernel.statement(attest), proof)
        })
        .collect();
    let [(bound, bound_proof), (free, free_proof)] = &rootless[..] else {
        unreachable!()
    };
    let jam_b_recorded = Arc::new(Recorded::new(jam_b.clone()));
    let jam_b_tapped = Arc::new(Tapped::new(jam_b_recorded.clone()));
    let rootless_verdicts = [
        (
            "venue-bound, at its venue",
            jam_tapped.submit(bound, bound_proof),
            Ok(bound.id()),
        ),
        (
            "venue-bound, at another venue",
            jam_b_tapped.submit(bound, bound_proof),
            Err(NotAccepted::Refused(7)),
        ),
        (
            "unbound, at JAM a",
            jam_tapped.submit(free, free_proof),
            Ok(free.id()),
        ),
        (
            "unbound, at JAM b",
            jam_b_tapped.submit(free, free_proof),
            Ok(free.id()),
        ),
    ];
    for (what, verdict, expected) in &rootless_verdicts {
        record.note(format!("a rootless statement, {what}: {verdict:?}"));
        assert_eq!(verdict, expected, "{what}");
    }

    // Both venues' anchor chains, read before the chain's clock moves.
    let jam_anchors: Vec<u8> = (k..k + 3)
        .flat_map(|w| {
            jam_a
                .venue
                .statements
                .value(&jam_keys::anchor(&space, RootKind::Space, w))
                .unwrap()
                .unwrap_or_else(|| panic!("window {w} anchored at JAM"))
        })
        .chain(
            jam_a
                .venue
                .statements
                .value(&jam_keys::space(&space))
                .unwrap()
                .unwrap(),
        )
        .collect();
    for w in 0..k {
        assert!(kreivo.holds(&space, w), "window {w} anchored at Kreivo");
    }
    assert!(
        !kreivo.holds(&space, k),
        "window {k} not anchored at Kreivo"
    );

    // What each node holds and sent, collected before they stop.
    let mut audit = Audit::default();
    for ((to, class), bytes) in frames.lock().unwrap().iter() {
        audit.carrier(
            format!("frames to node {to}: {class}"),
            Reach::Role,
            bytes.clone(),
        );
    }
    let all = [
        agents.representative,
        agents.balance,
        agents.window,
        agents.reader,
    ];
    for (number, node) in cluster.running() {
        for agent in all {
            audit.carrier(
                format!("node {number}: agent {}'s log", agent.0),
                Reach::Role,
                log_entries(node, agent),
            );
            let results: Vec<u8> = results(node, agent, 0)
                .iter()
                .flat_map(|(_, result)| result.encode())
                .collect();
            audit.carrier(
                format!("node {number}: agent {}'s work results", agent.0),
                Reach::Role,
                results,
            );
        }
        let jobs: Vec<u8> = node
            .store()
            .prover_jobs()
            .unwrap()
            .into_iter()
            .flat_map(|(_, id, job)| [id.to_vec(), job].concat())
            .collect();
        audit.carrier(
            format!("node {number}: the prover's table"),
            Reach::Role,
            jobs,
        );
        audit.carrier(
            format!("node {number}: the store's rows"),
            Reach::Role,
            carriers::store(node.store()),
        );
    }
    for (at, dir) in cluster.dirs.iter().enumerate() {
        let number = at as NodeNumber + 1;
        for (path, bytes) in carriers::directory(dir.path()) {
            audit.carrier(format!("node {number}: {path}"), Reach::Role, bytes);
        }
    }
    let mut cluster = cluster;
    for number in 1..=3 {
        cluster.stop(number);
    }

    // The JAM service's work reports of what the run landed so far.
    let mut reports = Vec::new();
    collect_reports("a", &jam_a, &mut reports);
    collect_reports("b", &jam_b, &mut reports);

    // Past `MaxRootAge` by the chain's clock: each accepted rootless
    // statement replayed is a repeat, the rooted one unanchored.
    let latest = jam_a
        .landed()
        .iter()
        .map(|landed| landed.outcome.time)
        .max()
        .unwrap();
    testnet.shift(PAST_MAX_ROOT_AGE);
    vos_checker::wait_until(
        "the chain's clock past MaxRootAge",
        Duration::from_secs(120),
        || {
            jam_a
                .venue
                .statements
                .now()
                .is_ok_and(|now| now > latest + MAX_ROOT_AGE_MS)
        },
    );
    record.note(format!(
        "the chain's clock moved {} h ahead: JAM's time {}",
        PAST_MAX_ROOT_AGE / 3_600_000,
        jam_a.venue.statements.now().unwrap()
    ));
    let rooted = stated
        .iter()
        .find(|(asked, ..)| asked.window == k)
        .map(|(_, _, statement)| statement.clone())
        .unwrap();
    let rooted_proof = jam_tapped
        .submitted()
        .into_iter()
        .find(|(statement, _)| statement.id() == rooted.id())
        .unwrap()
        .1;
    // The chain skipped a day of epochs: its guarantors take packages
    // again once finality has caught up with it, a few slots on.
    let jumped = jam_a.venue.statements.now().unwrap();
    vos_checker::wait_until(
        "five slots finalized past the clock's move",
        Duration::from_secs(180),
        || {
            jam_a
                .venue
                .statements
                .now()
                .is_ok_and(|now| now >= jumped + 5 * SLOT_MS)
        },
    );
    let replays = [
        (
            "venue-bound, at JAM a",
            replay(&jam_a, bound, bound_proof),
            6,
        ),
        ("unbound, at JAM a", replay(&jam_a, free, free_proof), 6),
        ("unbound, at JAM b", replay(&jam_b, free, free_proof), 6),
        (
            "rooted, at JAM a",
            replay(&jam_a, &rooted, &rooted_proof),
            5,
        ),
    ];
    for (what, code, expected) in replays {
        record.note(format!("replayed past MaxRootAge, {what}: code {code:#x}"));
        assert_eq!(code, expected, "{what}, replayed past MaxRootAge");
    }
    let replayed = reports.len();
    collect_reports("a", &jam_a, &mut reports);
    collect_reports("b", &jam_b, &mut reports);
    record.note(format!(
        "the JAM service's work reports: {} before the clock moved, {} of the replays",
        replayed,
        reports.len() - replayed
    ));

    let alerts: Vec<String> = kreivo_clients
        .lock()
        .unwrap()
        .values()
        .flat_map(|(client, ..)| client.alerts())
        .map(|alert| format!("{alert:?}"))
        .collect();
    record.note(format!("the Kreivo clients' alerts: {alerts:?}"));
    measure(
        &mut record,
        &clock,
        k,
        &stated,
        &prover,
        &kreivo_judged(),
        &jam_recorded.judged(),
        &jam_a,
        &kreivo,
        &space,
    );

    // The audit's needles: each proof's internals, each record's private
    // parts, the debug outputs.
    audit.needles.debug_outputs();
    let made = prover.made();
    assert!(made.len() >= stated.len() + 2, "each statement proved");
    for (n, (attest, internals)) in made.iter().enumerate() {
        assert!(!internals.proofs.is_empty() && !internals.memory_roots.is_empty());
        let name = format!("statement {n}");
        audit.needles.internals(&name, internals);
        let arguments = stated
            .iter()
            .find(|(_, stated, _)| stated == attest)
            .map_or(attest.witness_input.len(), |(asked, ..)| asked.arguments);
        audit.needles.attest(&name, attest, arguments);
    }

    // What left the prover role: each venue's calls and items, the work
    // reports, the mock's envelopes, the anchor chains, the testnet.
    jam_tapped.carriers(&mut audit);
    jam_b_tapped.carriers(&mut audit);
    for (number, (.., tapped)) in kreivo_clients.lock().unwrap().iter() {
        let mut node = Audit::default();
        tapped.carriers(&mut node);
        for carrier in node.carriers {
            audit.carrier(
                format!("node {number} at Kreivo: {}", carrier.name),
                carrier.reach,
                carrier.bytes,
            );
        }
    }
    for (name, bytes) in reports {
        audit.carrier(name, Reach::Leaves, bytes);
    }
    for (n, envelope) in kreivo.envelopes().into_iter().enumerate() {
        audit.carrier(format!("Kreivo's extrinsic {n}"), Reach::Leaves, envelope);
    }
    audit.carrier("Kreivo's storage", Reach::Leaves, kreivo.storage());
    audit.carrier("JAM's anchor chain", Reach::Leaves, jam_anchors);
    audit.carrier(
        "the testnet's log",
        Reach::Recorded,
        std::fs::read(&testnet.log).unwrap_or_default(),
    );
    if let Some(chain) = testnet.chain() {
        for (path, bytes) in carriers::directory(&chain) {
            audit.carrier(
                format!("the testnet's chain: {path}"),
                Reach::Recorded,
                bytes,
            );
        }
    }
    std::thread::sleep(Duration::from_secs(1));
    audit.carrier("the logs, every level", Reach::Leaves, logs.bytes());
    audit.carrier("standard error", Reach::Leaves, stderr.finish());

    let summary = audit.summary();
    let kinds: Vec<&str> = summary
        .lines()
        .filter(|line| line.ends_with(" needles"))
        .collect();
    record.note(format!(
        "the audit: {} carriers; {}",
        audit.carriers.len(),
        kinds.join(", ")
    ));
    std::fs::write(testnet.run.join("audit.txt"), &summary).unwrap();
    audit.assert_searchable(&[
        Kind::NodeProof,
        Kind::ServedRow,
        Kind::PrivateHash,
        Kind::StepCount,
        Kind::MemoryRoot,
        Kind::Register,
        Kind::DebugOutput,
    ]);
    audit.assert_clean();
    record.note("the audit clean; every verdict as expected");
}

/// `statement` submitted again at `jam` and landed, its package sent
/// again while no guarantor takes it: its code.
fn replay(jam: &Jam, statement: &Statement, proof: &[u8]) -> u32 {
    let mut tries = 0;
    loop {
        match jam.judge(statement, proof) {
            Ok(outcome) => return outcome.code,
            Err(error) if tries < 10 => {
                tries += 1;
                eprintln!("a replay not taken ({error:?}); again in a slot");
                std::thread::sleep(Duration::from_millis(SLOT_MS));
            }
            Err(error) => panic!("the replay never landed: {error:?}"),
        }
    }
}

/// The work reports of what `jam` landed since the last collected, as
/// carriers.
fn collect_reports(name: &str, jam: &Jam, reports: &mut Vec<(String, Vec<u8>)>) {
    let prefix = format!("JAM {name}'s work report, ");
    let done = reports
        .iter()
        .filter(|(carrier, _)| carrier.starts_with(&prefix))
        .count();
    for (n, landed) in jam.landed().into_iter().enumerate().skip(done) {
        let report = landed
            .report(Duration::from_secs(60))
            .unwrap_or_else(|| panic!("the work report of {}", landed.what));
        reports.push((format!("{prefix}{n}: {}", landed.what), report));
    }
}

/// The run's measurements, noted: each statement's latency against pin
/// D's and the gate's, the JAM service's gas, the mock's charges to the
/// sovereign account, and the prover's throughput.
#[allow(clippy::too_many_arguments)]
fn measure(
    record: &mut Record,
    clock: &WindowClock,
    k: u64,
    stated: &[(Asked, Attest, Statement)],
    prover: &Serial,
    kreivo_judged: &[Judgement],
    jam_judged: &[Judgement],
    jam: &Jam,
    kreivo: &Kreivo,
    space: &SpaceId,
) {
    let (l, d) = (clock.length_ms, delay(clock));
    let proved = prover.proved();
    record.note(format!(
        "latency from B_w to acceptance (L {} s, D {} s): pin D's estimate L/2 + D + t_prove + \
         inclusion, the gate L + D + t_prove + 30 s",
        l / 1_000,
        d / 1_000
    ));
    for (asked, _, statement) in stated {
        let (venue, judged) = if asked.window < k {
            ("Kreivo", kreivo_judged)
        } else {
            ("JAM", jam_judged)
        };
        let judgement = accepted(judged, statement).expect("accepted");
        let proof = proved
            .iter()
            .find(|proved| proved.of(statement))
            .expect("proved");
        let boundary = clock.boundary(asked.window).unwrap();
        let latency = judgement.at_ms - boundary;
        let t_prove = proof.took.as_millis() as u64;
        let inclusion = judgement.at_ms.saturating_sub(proof.ended_ms);
        let gate = l + d + t_prove + MARGIN_MS;
        record.note(format!(
            "  {venue}, window {}, {}: {:.1} s (t_prove {:.1} s, after its proof {:.1} s); \
             pin D {:.1} s; gate {:.1} s",
            asked.window,
            asked.what,
            latency as f64 / 1e3,
            t_prove as f64 / 1e3,
            inclusion as f64 / 1e3,
            (l / 2 + d + t_prove + inclusion) as f64 / 1e3,
            gate as f64 / 1e3,
        ));
        assert!(
            latency <= gate,
            "{venue}'s {} statement of window {}: {latency} ms past B_w, over {gate} ms",
            asked.what,
            asked.window
        );
    }

    record.note("the JAM service's refine gas, by its own count:");
    for landed in jam.landed() {
        record.note(format!(
            "  {}: code {:#x}, refine {} gas",
            landed.what, landed.outcome.code, landed.outcome.refine_gas
        ));
    }
    if let Ok(Some(gas)) = jam.venue.statements.accumulate_gas() {
        record.note(format!("  the last accumulate: {gas} gas"));
    }

    let sovereign = kreivo.sovereign_of(space);
    let account = kreivo.account(&sovereign);
    let (fee, deposit, budget) = kreivo.chain.with(|chain| {
        let constants = &chain.constants;
        (
            constants.fee_bound,
            constants.submit_deposit,
            constants.default_spend_per_window,
        )
    });
    let (mut anchors, mut submits) = (0u128, 0u128);
    for (origin, call) in kreivo.included() {
        let authority = (1..=3).any(|n| origin == Origin::Signed(kreivo::node_account(n)));
        match &call[..2] {
            [90, 7] if authority => anchors += 1,
            [90, 8] if authority => submits += 1,
            _ => {}
        }
    }
    let charged = kreivo::FUNDING - account.free - account.held_registration - account.held_submit;
    record.note(format!(
        "Kreivo's sovereign account, funded {} UNITS: {anchors} anchors and {submits} submits by \
         the authorities, each a fee of {} UNITS; one deposit of {} UNITS forfeited (the \
         statement refused); {} UNITS held for the registration, none for submits; charged {} \
         UNITS in all; the budget {} UNITS a window",
        kreivo::FUNDING / UNITS,
        fee as f64 / UNITS as f64,
        deposit as f64 / UNITS as f64,
        account.held_registration as f64 / UNITS as f64,
        charged as f64 / UNITS as f64,
        budget as f64 / UNITS as f64,
    ));
    assert_eq!(account.held_submit, 0, "every submit's deposit settled");
    assert_eq!(
        charged,
        (anchors + submits) * fee + deposit,
        "the sovereign paid each authority's fee, and the refused statement's deposit"
    );

    let node_proofs: Vec<_> = proved
        .iter()
        .filter(|proved| proved.attest.window.is_some())
        .collect();
    let total: Duration = node_proofs.iter().map(|proved| proved.took).sum();
    let average = total / node_proofs.len().max(1) as u32;
    record.note(format!(
        "the prover: {} statements at cuts in {:.1} s, {:.1} s each on average; at that rate \
         {:.0} a 10-minute window, {:.0} a {}-second one",
        node_proofs.len(),
        total.as_secs_f64(),
        average.as_secs_f64(),
        600.0 / average.as_secs_f64(),
        l as f64 / 1e3 / average.as_secs_f64(),
        l / 1_000,
    ));
    for proved in &proved {
        record.note(format!(
            "  {} statement: {:.1} s",
            match proved.attest.window {
                Some(w) => format!("window {w}'s"),
                None => "a rootless".into(),
            },
            proved.took.as_secs_f64()
        ));
    }
}
