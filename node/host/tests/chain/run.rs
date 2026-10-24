//! The run, phase by phase: the space at Kreivo, its migration, the JAM
//! leg, the rootless statements and their replays past `MaxRootAge`; then
//! its measurements and its audit.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_checker::carriers::{self, Canary, Frames, Logs, Tapped};
use vos_jam_dev::JamVenue;
use vos_node::{Config, Hooks};
use vos_node_prover::Prover;
use vos_statement_service::item::Item;
use vos_statement_service::state::{Outcome as Judged, keys as jam_keys};
use vos_venue::kreivo::KreivoVenue;
use vos_venue::vos_statement::Statement;
use vos_venue::{NotAccepted, VenueClient};
use vos_wire::SpaceGenesis;
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
use crate::jam::Testnet;
use crate::kernels::Kernels;
use crate::kreivo::{self, Kreivo};
use crate::record::Record;
use crate::support::{attests, delay, replica};
use crate::venues::{Judgement, Migrating, Recorded, Serial, Wire, hex};
use crate::{collect, measure};

/// The space's windows: the shortest a venue registers.
const LENGTH_MS: u64 = MIN_LENGTH_MS;
/// How far the chain's clock moves at the end: past `MaxRootAge` by an
/// hour, so every row the service queued to drop by its hour may go.
const PAST_MAX_ROOT_AGE: i64 = MAX_ROOT_AGE_MS as i64 + 3_600_000;
/// How long the run waits for every statement to be accepted.
const ACCEPTED_WITHIN: Duration = Duration::from_secs(1_200);

/// What each capture path of the process is sent once, to show it
/// captures: a log line from a node's thread, a line on standard error.
pub const CANARY: &str = "e2e-chain-canary";

/// Each node's Kreivo client, by number: itself, as recorded, and as
/// tapped.
pub type KreivoClients =
    Arc<Mutex<BTreeMap<NodeNumber, (Arc<KreivoVenue>, Arc<Recorded>, Arc<Tapped>)>>>;

/// A JAM deployment: its client, as the run records and taps it, and every
/// package the client sent.
pub struct Jam {
    pub name: &'static str,
    pub venue: Arc<JamVenue>,
    pub recorded: Arc<Recorded>,
    pub tapped: Arc<Tapped>,
    pub wire: Arc<Wire>,
    /// The items its account counted at deployment, its storage empty.
    pub baseline: u32,
}

impl Jam {
    fn deploy(testnet: &Testnet, name: &'static str, kernels: &Kernels) -> Self {
        let wire = Arc::new(Wire::default());
        let venue = Arc::new(testnet.deploy(name, kernels.pins(), &wire));
        let baseline = venue.statements.entries(0).expect("the service's account");
        let recorded = Arc::new(Recorded::new(venue.clone()));
        let tapped = Arc::new(Tapped::new(recorded.clone()));
        Self {
            name,
            venue,
            recorded,
            tapped,
            wire,
            baseline,
        }
    }

    /// The outcome the service keeps of `statement`'s submission.
    pub fn judged(&self, statement: &Statement) -> Option<Judged> {
        self.wire
            .outcome(&self.venue, &Item::Submit(statement.encode()).encode())
    }
}

/// A statement at a cut, as the run asked for it and its record made it.
pub struct Stated {
    pub asked: Asked,
    pub attest: Attest,
    pub statement: Statement,
}

/// The reader's rootless statements, each with its proof.
pub struct Rootless {
    pub bound: (Statement, Vec<u8>),
    pub free: (Statement, Vec<u8>),
}

/// The run's parts, phase to phase.
pub struct Run {
    pub testnet: Testnet,
    pub record: Record,
    pub logs: Logs,
    pub stderr: Option<carriers::Stderr>,
    pub prover: Arc<Serial>,
    pub kernels: Kernels,
    pub jam_a: Jam,
    pub jam_b: Jam,
    pub kreivo: Arc<Kreivo>,
    pub kreivo_clients: KreivoClients,
    moved: Arc<AtomicBool>,
    pub cluster: Cluster,
    pub frames: Frames,
    pub clock: WindowClock,
    pub space: SpaceId,
    genesis: SpaceGenesis,
    pub agents: Agents,
    /// The window the space migrates at.
    pub k: u64,
}

/// Sleep until the host's clock reads `at`.
fn until(at: u64) {
    let now = vos_node::wall_clock();
    if at > now {
        std::thread::sleep(Duration::from_millis(at - now));
    }
}

/// The judgement a venue gave `statement` that accepted it, if one did.
pub fn accepted<'a>(judged: &'a [Judgement], statement: &Statement) -> Option<&'a Judgement> {
    let id = statement.id();
    judged
        .iter()
        .find(|judgement| judgement.statement.id() == id && judgement.answer == Ok(id))
}

#[test]
fn a_space_moves_from_kreivo_to_jam_and_no_carrier_holds_its_internals() {
    let mut run = Run::start();
    let first = run.kreivo_leg();
    run.migrate(&first);
    let stated = run.jam_leg(first);
    let rootless = run.rootless();
    let judged = run.judged(&stated, &rootless);
    let mut audit = collect::nodes(&mut run);
    run.replays(&stated, &rootless);
    measure::all(&mut run, &stated, &judged);
    collect::rest(&mut run, &mut audit, &stated);
}

impl Run {
    /// The testnet's two deployments of the JAM service, the Kreivo mock
    /// and the space's three nodes, its agents installed; the space
    /// registered at Kreivo from window 0, each node its authority.
    fn start() -> Self {
        let testnet = Testnet::from_env();
        let mut record = Record::new(&testnet.run);
        // SAFETY: before the run starts any thread that reads the
        // environment.
        unsafe { carriers::debug_environment_on() };
        let stderr = carriers::Stderr::capture(&testnet.run);
        let logs = Logs::install();
        let prover = Arc::new(Serial::default());
        let kernels = Kernels::load(&prover);

        // `a`, where the space anchors once it migrates, and `b`, another
        // venue.
        let jam_a = Jam::deploy(&testnet, "a", &kernels);
        let jam_b = Jam::deploy(&testnet, "b", &kernels);
        for jam in [&jam_a, &jam_b] {
            record.note(format!(
                "JAM service {}: id {}, venue {}",
                jam.name,
                jam.venue.statements.service,
                hex(&jam.venue.id().0)
            ));
        }
        let kreivo = Arc::new(Kreivo::new(&[
            kernels.balance.program,
            kernels.window.program,
        ]));

        // Windows two minutes long from now; each node's venue its Kreivo
        // client until the space moves, then the JAM service.
        let clock = WindowClock {
            origin_ms: vos_node::wall_clock() - 1_000,
            length_ms: LENGTH_MS,
        };
        let moved = Arc::new(AtomicBool::new(false));
        let kreivo_clients = KreivoClients::default();
        let canary = Arc::new(Canary::new(CANARY));
        let cluster = {
            let (kreivo, clients, jam, moved) = (
                Arc::clone(&kreivo),
                Arc::clone(&kreivo_clients),
                Arc::clone(&jam_a.tapped),
                Arc::clone(&moved),
            );
            let prover: Arc<dyn Prover> = prover.clone();
            let hooks: Arc<dyn Hooks> = canary;
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
                    config.hooks = Arc::clone(&hooks);
                },
            )
        };
        let frames = carriers::tap_frames(&cluster.hub);
        let space = cluster.space.id();
        let genesis = cluster.space.genesis().unwrap().clone();
        record.note(format!(
            "the space {}: windows of {} s from {}, D {} s, three nodes",
            hex(&space.0[..8]),
            LENGTH_MS / 1_000,
            clock.origin_ms,
            delay(&clock) / 1_000
        ));

        // Registered from window 0 with a founder's signature, each node an
        // authority paired with its anchor key.
        let founder = cluster
            .node(1)
            .sign_registration(&kreivo::VENUE, &kreivo::controller(), 0)
            .expect("node 1 founded the space");
        kreivo.register(&genesis, 0, founder, &genesis.nodes);
        let registered = kreivo.account(&kreivo.sovereign_of(&space));
        record.note(format!(
            "Kreivo: registered from window 0, 3 authorities; the sovereign account free {}, \
             held for the registration {}",
            registered.free, registered.held_registration
        ));
        let agents = Agents::install(&cluster);
        Self {
            testnet,
            record,
            logs,
            stderr: Some(stderr),
            prover,
            kernels,
            jam_a,
            jam_b,
            kreivo,
            kreivo_clients,
            moved,
            cluster,
            frames,
            clock,
            space,
            genesis,
            agents,
            k: 0,
        }
    }

    fn boundary(&self, window: u64) -> u64 {
        self.clock.boundary(window).unwrap()
    }

    /// Every judgement the nodes' Kreivo clients were given.
    pub fn kreivo_judged(&self) -> Vec<Judgement> {
        self.kreivo_clients
            .lock()
            .unwrap()
            .values()
            .flat_map(|(_, recorded, _)| recorded.judged())
            .collect()
    }

    /// A balance read at Kreivo, in the next window, `first`: the space
    /// migrates two windows later.
    fn kreivo_leg(&mut self) -> Asked {
        let first = self.clock.window(vos_node::wall_clock()).unwrap() + 1;
        self.k = first + 2;
        until(self.boundary(first - 1) + 2_000);
        let asked = self.agents.ask_balance(&self.cluster, first);
        self.record
            .note(format!("window {first}: a balance read asked, at Kreivo"));
        asked
    }

    /// In window k − 1: registered at JAM `a` from k by a founder's
    /// signature, under an ed25519 controller, and migrated away from
    /// Kreivo from k. The nodes move to the service once window k − 1 is
    /// anchored at Kreivo and `first`'s balance statement accepted there,
    /// before window k closes, so its anchor goes to the service.
    fn migrate(&mut self, first: &Asked) {
        let k = self.k;
        until(self.boundary(k - 2) + 30_000);
        let controller = SigningKey::from_bytes(&blake2b_256(&[b"vos/e2e-chain/jam/controller"]))
            .verifying_key()
            .to_bytes();
        let jam = &self.jam_a.venue;
        let (key, signature) = self
            .cluster
            .node(1)
            .sign_registration(&jam.id(), &controller, k)
            .expect("node 1 founded the space");
        let code = jam
            .register_signed(&self.genesis, controller, k, key, signature)
            .expect("the registration lands");
        assert_eq!(code, 0, "registered at the JAM service from window {k}");
        let migrated = self.kreivo.migrate(&self.space, jam.id(), k);
        self.record.note(format!(
            "window {}: registered at JAM from window {k} (code {code}); migrated away from \
             Kreivo from window {k}: {} event",
            k - 1,
            migrated.events.len()
        ));

        let statement = self.stated(first).statement;
        let d = delay(&self.clock);
        let within = (self.boundary(k) + d - 10_000).saturating_sub(vos_node::wall_clock());
        vos_checker::wait_until(
            "window k − 1 anchored at Kreivo and the balance statement accepted there",
            Duration::from_millis(within),
            || {
                self.kreivo.holds(&self.space, k - 1)
                    && accepted(&self.kreivo_judged(), &statement).is_some()
            },
        );
        self.moved.store(true, Ordering::SeqCst);
        let moved_at = vos_node::wall_clock();
        assert!(
            moved_at + 5_000 < self.boundary(k) + d,
            "the nodes moved before window {k} closes"
        );
        self.record.note(format!(
            "the nodes' venue moved to JAM {} s before window {k} closes",
            (self.boundary(k) + d - moved_at) / 1_000
        ));
    }

    /// `asked`'s read once it ended, and the statement its record makes.
    fn stated(&self, asked: &Asked) -> Stated {
        let mut ended = None;
        vos_checker::wait_until(
            &format!("{}'s read in window {} ends", asked.what, asked.window),
            READ_ENDS,
            || {
                ended = self
                    .cluster
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
        let outcome = ended.unwrap();
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
        let node = replica(&self.cluster, asked.agent);
        let attest = attests(node, asked.agent, asked.read)[0].clone();
        assert_eq!(attest.window, Some(asked.window));
        let statement = self.kernels.of(&attest).statement(&attest);
        Stated {
            asked: *asked,
            attest,
            statement,
        }
    }

    /// At JAM: a balance and a window read in each of windows k to k + 2,
    /// every statement, `first`'s at Kreivo among them, accepted; then
    /// window k's statement refused at Kreivo, past its range there.
    fn jam_leg(&mut self, first: Asked) -> Vec<Stated> {
        let k = self.k;
        let mut asked = vec![first];
        for w in k..k + 3 {
            until(self.boundary(w - 1) + 2_000);
            asked.push(self.agents.ask_balance(&self.cluster, w));
            asked.push(self.agents.ask_window(&self.cluster, w));
            self.record.note(format!(
                "window {w}: a balance and a window read asked, at JAM"
            ));
        }
        let stated: Vec<Stated> = asked.iter().map(|asked| self.stated(asked)).collect();
        vos_checker::wait_until("every statement accepted", ACCEPTED_WITHIN, || {
            let (kreivo, jam) = (self.kreivo_judged(), self.jam_a.recorded.judged());
            stated.iter().all(|stated| {
                let judged = if stated.asked.window < k {
                    &kreivo
                } else {
                    &jam
                };
                accepted(judged, &stated.statement).is_some()
            })
        });
        for stated in &stated {
            let venue = if stated.asked.window < k {
                "Kreivo"
            } else {
                "JAM"
            };
            self.record.note(format!(
                "accepted at {venue}: {}'s statement at window {}'s cut, format {}, {}",
                stated.asked.what,
                stated.asked.window,
                stated.statement.format,
                hex(&stated.statement.id().0[..8])
            ));
        }

        let (statement, proof) = self.submitted(&self.at_k(&stated).statement);
        let node_1 = self.kreivo_clients.lock().unwrap()[&1].2.clone();
        let refused = node_1.submit(&statement, &proof);
        self.record.note(format!(
            "window {k}'s statement at Kreivo, past its migration: {refused:?}"
        ));
        assert_eq!(
            refused,
            Err(NotAccepted::Refused(5)),
            "unanchored at Kreivo"
        );
        stated
    }

    /// The first statement of window k, the first of JAM's.
    fn at_k<'a>(&self, stated: &'a [Stated]) -> &'a Stated {
        stated
            .iter()
            .find(|stated| stated.asked.window == self.k)
            .expect("a statement of window k")
    }

    /// `statement` and the proof the nodes submitted it with at JAM `a`.
    fn submitted(&self, statement: &Statement) -> (Statement, Vec<u8>) {
        self.jam_a
            .tapped
            .submitted()
            .into_iter()
            .find(|(submitted, _)| submitted.id() == statement.id())
            .expect("submitted at JAM")
    }

    /// The reader's rootless statements, proved by the run: `stamped`,
    /// bound to JAM `a`, accepted there and refused at `b`; `ordered`, of
    /// no venue, accepted at both.
    fn rootless(&mut self) -> Rootless {
        let (stamped, ordered) = self.agents.plain(&self.cluster, self.jam_a.venue.id());
        let prove = |attest: &Attest| {
            let kernel = self.kernels.of(attest);
            let proof = self
                .prover
                .prove(&kernel.blob, attest)
                .expect("a rootless proof");
            (kernel.statement(attest), proof)
        };
        let rootless = Rootless {
            bound: prove(&stamped),
            free: prove(&ordered),
        };
        let ((bound, bound_proof), (free, free_proof)) = (&rootless.bound, &rootless.free);
        let (a, b) = (&self.jam_a.tapped, &self.jam_b.tapped);
        let verdicts = [
            (
                "venue-bound, at its venue",
                a.submit(bound, bound_proof),
                Ok(bound.id()),
            ),
            (
                "venue-bound, at another venue",
                b.submit(bound, bound_proof),
                Err(NotAccepted::Refused(7)),
            ),
            (
                "unbound, at JAM a",
                a.submit(free, free_proof),
                Ok(free.id()),
            ),
            (
                "unbound, at JAM b",
                b.submit(free, free_proof),
                Ok(free.id()),
            ),
        ];
        for (what, verdict, expected) in verdicts {
            self.record
                .note(format!("a rootless statement, {what}: {verdict:?}"));
            assert_eq!(verdict, expected, "{what}");
        }
        rootless
    }

    /// What each JAM deployment keeps of each statement submitted there,
    /// read before the chain's clock moves and its outcomes age out: by
    /// deployment and statement, the outcome.
    fn judged(&self, stated: &[Stated], rootless: &Rootless) -> Vec<(String, Judged)> {
        let mut judged = Vec::new();
        let at_jam = stated.iter().filter(|stated| stated.asked.window >= self.k);
        for statement in at_jam.map(|stated| &stated.statement) {
            judged.push((self.jam_a.name, statement));
        }
        for jam in [&self.jam_a, &self.jam_b] {
            judged.push((jam.name, &rootless.bound.0));
            judged.push((jam.name, &rootless.free.0));
        }
        judged
            .into_iter()
            .map(|(name, statement)| {
                let jam = if name == "a" {
                    &self.jam_a
                } else {
                    &self.jam_b
                };
                let outcome = jam.judged(statement).expect("an outcome kept");
                (
                    format!("JAM {name}, statement {}", hex(&statement.id().0[..8])),
                    outcome,
                )
            })
            .collect()
    }

    /// The anchor records JAM `a` holds of windows k to k + 2, and the
    /// space's record there; every window before k anchored at Kreivo, k
    /// not.
    pub fn anchor_chains(&self) -> Vec<u8> {
        let k = self.k;
        for w in 0..k {
            assert!(self.kreivo.holds(&self.space, w), "window {w} at Kreivo");
        }
        assert!(
            !self.kreivo.holds(&self.space, k),
            "window {k} not at Kreivo"
        );
        let statements = &self.jam_a.venue.statements;
        (k..k + 3)
            .map(|w| jam_keys::anchor(&self.space, RootKind::Space, w))
            .chain([jam_keys::space(&self.space)])
            .flat_map(|key| {
                statements
                    .value(&key)
                    .unwrap()
                    .expect("anchored at JAM, the space registered")
            })
            .collect()
    }

    /// Past `MaxRootAge` by the chain's clock, each accepted rootless
    /// statement replayed is a repeat, window k's rooted one unanchored.
    fn replays(&mut self, stated: &[Stated], rootless: &Rootless) {
        let statements = &self.jam_a.venue.statements;
        let latest = statements.now().unwrap();
        self.testnet.shift(PAST_MAX_ROOT_AGE);
        vos_checker::wait_until(
            "the chain's clock past MaxRootAge",
            Duration::from_secs(120),
            || {
                statements
                    .now()
                    .is_ok_and(|now| now > latest + MAX_ROOT_AGE_MS)
            },
        );
        // The chain skipped a day of epochs: its guarantors take packages
        // again once finality has caught up with it, a few slots on.
        let jumped = statements.now().unwrap();
        vos_checker::wait_until(
            "five slots finalized past the clock's move",
            Duration::from_secs(180),
            || {
                statements
                    .now()
                    .is_ok_and(|now| now >= jumped + 5 * SLOT_MS)
            },
        );
        self.record.note(format!(
            "the chain's clock moved {} h ahead: JAM's time {jumped}",
            PAST_MAX_ROOT_AGE / 3_600_000
        ));
        let rooted = self.submitted(&self.at_k(stated).statement);
        let ((bound, bound_proof), (free, free_proof)) = (&rootless.bound, &rootless.free);
        let replays = [
            ("venue-bound, at JAM a", &self.jam_a, bound, bound_proof, 6),
            ("unbound, at JAM a", &self.jam_a, free, free_proof, 6),
            ("unbound, at JAM b", &self.jam_b, free, free_proof, 6),
            ("rooted, at JAM a", &self.jam_a, &rooted.0, &rooted.1, 5),
        ];
        let mut codes = Vec::new();
        for (what, jam, statement, proof, expected) in replays {
            let code = replay(jam, statement, proof);
            codes.push((what, code, expected));
        }
        for (what, code, expected) in codes {
            self.record
                .note(format!("replayed past MaxRootAge, {what}: code {code:#x}"));
            assert_eq!(code, expected, "{what}, replayed past MaxRootAge");
        }
    }
}

/// `statement` submitted again at `jam`: its code, once a package of it
/// lands. A package a guarantor refused, or one not landed in time, is
/// sent again; one sent earlier that landed late counts, and every package
/// sent is kept by the deployment's wire, its work report with it.
fn replay(jam: &Jam, statement: &Statement, proof: &[u8]) -> u32 {
    let payload = Item::Submit(statement.encode()).encode();
    let since = jam.wire.sent().len();
    for _ in 0..10 {
        match jam.venue.land(payload.clone(), vec![proof.to_vec()]) {
            Ok(outcome) => return outcome.code,
            Err(error) => {
                eprintln!("a replay not landed ({error:?}); again in a slot");
                std::thread::sleep(Duration::from_millis(SLOT_MS));
            }
        }
        let landed = jam.wire.sent()[since..].iter().find_map(|sent| {
            jam.venue
                .statements
                .outcome(&vos_wire::result::digest(&sent.package), &payload)
                .ok()
                .flatten()
        });
        if let Some(outcome) = landed {
            return outcome.code;
        }
    }
    panic!("the replay never landed");
}
