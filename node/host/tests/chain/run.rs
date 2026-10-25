//! The run, phase by phase: a space at Kreivo and a space at JAM, each at
//! its one venue; their statements refused where their roots are not
//! anchored, and a rootless one refused at JAM; the replays past
//! `MaxRootAge`; then its measurements and its audit.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_checker::carriers::{self, Canary, Frames, Logs, Tapped};
use vos_jam_dev::JamVenue;
use vos_node::{Config, Hooks};
use vos_node_prover::Prover;
use vos_statement_service::item::Item;
use vos_statement_service::state::{Outcome as Judged, keys as jam_keys};
use vos_venue::VenueClient;
use vos_venue::kreivo::KreivoVenue;
use vos_venue::vos_statement::{Refusal, Statement};
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
use crate::venues::{Judgement, Recorded, Serial, Wire};
use crate::{collect, measure};

/// The spaces' windows: the shortest a venue registers.
const LENGTH_MS: u64 = MIN_LENGTH_MS;
/// How far the chain's clock moves at the end: past `MaxRootAge` by an
/// hour, so every row the service queued to drop by its hour may go.
const PAST_MAX_ROOT_AGE: i64 = MAX_ROOT_AGE_MS as i64 + 3_600_000;
/// How long the run waits for every statement to be accepted.
const ACCEPTED_WITHIN: Duration = Duration::from_secs(1_200);

/// What each capture path of the process is sent once, to show it
/// captures: a log line from a node's thread, a line on standard error.
pub const CANARY: &str = "e2e-chain-canary";

/// Each Kreivo node's client, by number: itself, as recorded, and as
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

/// Where a space anchors: Kreivo's mock, or the JAM service `a`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Venue {
    Kreivo,
    Jam,
}

/// A space of three nodes at its one venue: its nodes, the frames between
/// them, its agents.
pub struct Space {
    pub venue: Venue,
    pub cluster: Cluster,
    pub frames: Frames,
    pub id: SpaceId,
    pub agents: Agents,
}

/// A statement at a cut, as the run asked for it and its record made it.
pub struct Stated {
    pub venue: Venue,
    pub asked: Asked,
    pub attest: Attest,
    pub statement: Statement,
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
    pub clock: WindowClock,
    /// The space at Kreivo, and the space at JAM `a`.
    pub at_kreivo: Space,
    pub at_jam: Space,
    /// The first window the run reads.
    pub first: u64,
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
fn each_space_anchors_at_its_one_venue_and_no_carrier_holds_its_internals() {
    let mut run = Run::start();
    let stated = run.reads();
    run.elsewhere(&stated);
    let rootless = run.rootless();
    let judged = run.judged(&stated, &rootless);
    let mut audit = collect::nodes(&mut run);
    run.replays(&stated);
    measure::all(&mut run, &stated, &judged);
    collect::rest(&mut run, &mut audit, &stated);
}

impl Run {
    /// The testnet's two deployments of the JAM service, the Kreivo mock,
    /// and two spaces of three nodes, their agents installed: one at
    /// Kreivo, each node its authority, and one at JAM `a`; each
    /// registered by a founder's signature, anchoring from its venue's next
    /// window.
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

        // `a`, where a space anchors, and `b`, another venue.
        let jam_a = Jam::deploy(&testnet, "a", &kernels);
        let jam_b = Jam::deploy(&testnet, "b", &kernels);
        for jam in [&jam_a, &jam_b] {
            record.note(format!(
                "JAM service {}: id {}, venue {}",
                jam.name,
                jam.venue.statements.service,
                hex::encode(jam.venue.id().0)
            ));
        }
        let kreivo = Arc::new(Kreivo::new(&[
            kernels.balance.program,
            kernels.window.program,
        ]));

        // Windows two minutes long from now.
        let clock = WindowClock {
            origin_ms: vos_node::wall_clock() - 1_000,
            length_ms: LENGTH_MS,
        };
        let kreivo_clients = KreivoClients::default();
        let canary: Arc<dyn Hooks> = Arc::new(Canary::new(CANARY));
        let tune =
            |venue: Arc<dyn Fn(NodeNumber, SpaceId) -> Arc<dyn VenueClient> + Send + Sync>| {
                let (prover, hooks): (Arc<dyn Prover>, _) = (prover.clone(), Arc::clone(&canary));
                move |number: NodeNumber, config: &mut Config| {
                    let space = vos_wire::vos_anchor::space_id(
                        config.space.as_ref().unwrap().genesis().unwrap(),
                    );
                    config.venue = Some(venue(number, space));
                    config.prover = Some(Arc::clone(&prover));
                    config.hooks = Arc::clone(&hooks);
                }
            };
        let at_kreivo = {
            let (kreivo, clients) = (Arc::clone(&kreivo), Arc::clone(&kreivo_clients));
            let venue = move |number: NodeNumber, space: SpaceId| -> Arc<dyn VenueClient> {
                let (.., tapped) = clients
                    .lock()
                    .unwrap()
                    .entry(number)
                    .or_insert_with(|| {
                        let client = Arc::new(kreivo.client(number, space));
                        let recorded = Arc::new(Recorded::new(client.clone()));
                        (client, recorded.clone(), Arc::new(Tapped::new(recorded)))
                    })
                    .clone();
                tapped
            };
            Cluster::in_space(3, Some(clock), tune(Arc::new(venue)))
        };
        let at_jam = {
            let tapped = Arc::clone(&jam_a.tapped);
            let venue = move |_: NodeNumber, _: SpaceId| -> Arc<dyn VenueClient> { tapped.clone() };
            Cluster::in_space(3, Some(clock), tune(Arc::new(venue)))
        };

        // At Kreivo: registered with a founder's signature, each node an
        // authority paired with its anchor key.
        let genesis = at_kreivo.space.genesis().unwrap().clone();
        let founder = at_kreivo
            .node(1)
            .sign_registration(&kreivo::VENUE, &kreivo::controller())
            .expect("node 1 founded the space");
        kreivo.register(&genesis, founder, &genesis.nodes);
        let id = at_kreivo.space.id();
        let registered = kreivo.account(&kreivo.sovereign_of(&id));
        record.note(format!(
            "the space {} at Kreivo: windows of {} s from {}, D {} s, three nodes; registered \
             from window {}, 3 authorities; the sovereign account free {}, held for the \
             registration {}",
            hex::encode(&id.0[..8]),
            LENGTH_MS / 1_000,
            clock.origin_ms,
            delay(&clock) / 1_000,
            kreivo.start(&id),
            registered.free,
            registered.held_registration
        ));

        // At JAM `a`: registered with a founder's signature under an
        // ed25519 controller.
        let genesis = at_jam.space.genesis().unwrap().clone();
        let controller = SigningKey::from_bytes(&blake2b_256(&[b"vos/e2e-chain/jam/controller"]))
            .verifying_key()
            .to_bytes();
        let jam = &jam_a.venue;
        let (key, signature) = at_jam
            .node(1)
            .sign_registration(&jam.id(), &controller)
            .expect("node 1 founded the space");
        let code = jam
            .register_signed(&genesis, controller, key, signature)
            .expect("the registration lands");
        assert_eq!(code, 0, "registered at the JAM service");
        let id = at_jam.space.id();
        let start = jam.space(&id).unwrap().expect("registered").start;
        record.note(format!(
            "the space {} at JAM a: the same clock, three nodes; registered from window {start}",
            hex::encode(&id.0[..8]),
        ));

        let space = |venue, cluster: Cluster| {
            let frames = carriers::tap_frames(&cluster.hub);
            let id = cluster.space.id();
            let agents = Agents::install(&cluster);
            Space {
                venue,
                cluster,
                frames,
                id,
                agents,
            }
        };
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
            clock,
            at_kreivo: space(Venue::Kreivo, at_kreivo),
            at_jam: space(Venue::Jam, at_jam),
            first: 0,
        }
    }

    fn boundary(&self, window: u64) -> u64 {
        self.clock.boundary(window).unwrap()
    }

    /// Every judgement the Kreivo space's clients were given.
    pub fn kreivo_judged(&self) -> Vec<Judgement> {
        self.kreivo_clients
            .lock()
            .unwrap()
            .values()
            .flat_map(|(_, recorded, _)| recorded.judged())
            .collect()
    }

    /// The judgements given at `venue`.
    pub fn judged_at(&self, venue: Venue) -> Vec<Judgement> {
        match venue {
            Venue::Kreivo => self.kreivo_judged(),
            Venue::Jam => self.jam_a.recorded.judged(),
        }
    }

    /// The space at `venue`.
    pub fn space(&self, venue: Venue) -> &Space {
        match venue {
            Venue::Kreivo => &self.at_kreivo,
            Venue::Jam => &self.at_jam,
        }
    }

    /// From the next window on: a balance read at Kreivo in the first; a
    /// balance and a window read at JAM in each of three; every statement
    /// accepted at its space's venue.
    fn reads(&mut self) -> Vec<Stated> {
        let first = self.clock.window(vos_node::wall_clock()).unwrap() + 1;
        self.first = first;
        let mut asked = Vec::new();
        for w in first..first + 3 {
            until(self.boundary(w - 1) + 2_000);
            if w == first {
                let space = &self.at_kreivo;
                asked.push((Venue::Kreivo, space.agents.ask_balance(&space.cluster, w)));
                self.record
                    .note(format!("window {w}: a balance read asked, at Kreivo"));
            }
            let space = &self.at_jam;
            asked.push((Venue::Jam, space.agents.ask_balance(&space.cluster, w)));
            asked.push((Venue::Jam, space.agents.ask_window(&space.cluster, w)));
            self.record.note(format!(
                "window {w}: a balance and a window read asked, at JAM"
            ));
        }
        let stated: Vec<Stated> = asked
            .iter()
            .map(|(venue, asked)| self.stated(*venue, asked))
            .collect();
        vos_checker::wait_until("every statement accepted", ACCEPTED_WITHIN, || {
            let (kreivo, jam) = (self.kreivo_judged(), self.jam_a.recorded.judged());
            stated.iter().all(|stated| {
                let judged = match stated.venue {
                    Venue::Kreivo => &kreivo,
                    Venue::Jam => &jam,
                };
                accepted(judged, &stated.statement).is_some()
            })
        });
        for stated in &stated {
            self.record.note(format!(
                "accepted at {:?}: {}'s statement at window {}'s cut, format {}, {}",
                stated.venue,
                stated.asked.what,
                stated.asked.window,
                stated.statement.format,
                hex::encode(&stated.statement.id().0[..8])
            ));
        }
        stated
    }

    /// `asked`'s read in the space at `venue` once it ended, and the
    /// statement its record makes.
    fn stated(&self, venue: Venue, asked: &Asked) -> Stated {
        let cluster = &self.space(venue).cluster;
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
        let outcome = ended.unwrap();
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
        let node = replica(cluster, asked.agent);
        let attest = attests(node, asked.agent, asked.read)[0].clone();
        assert_eq!(attest.window, Some(asked.window));
        let statement = self.kernels.of(&attest).statement(&attest);
        Stated {
            venue,
            asked: *asked,
            attest,
            statement,
        }
    }

    /// The first statement of the JAM space's.
    fn first_at_jam<'a>(&self, stated: &'a [Stated]) -> &'a Stated {
        stated
            .iter()
            .find(|stated| stated.venue == Venue::Jam)
            .expect("a statement at JAM")
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

    /// The JAM space's first statement, accepted at JAM `a`, is refused
    /// where its space's roots are not anchored: at Kreivo, by the Kreivo
    /// space's client, and at JAM `b`.
    fn elsewhere(&mut self, stated: &[Stated]) {
        let (statement, proof) = self.submitted(&self.first_at_jam(stated).statement);
        let node_1 = self.kreivo_clients.lock().unwrap()[&1].2.clone();
        let verdicts = [
            ("at Kreivo", node_1.submit(&statement, &proof)),
            ("at JAM b", self.jam_b.tapped.submit(&statement, &proof)),
        ];
        for (what, verdict) in verdicts {
            self.record.note(format!(
                "the JAM space's statement {what}, where its roots are not anchored: \
                 {verdict:?}"
            ));
            assert_eq!(verdict, Err(Refusal::Unanchored.into()), "{what}");
        }
    }

    /// The JAM space reader's rootless `ordered`, proved by the run and
    /// refused at JAM `a`, its program pinned there: a venue judges rooted
    /// statements alone.
    fn rootless(&mut self) -> (Statement, Vec<u8>) {
        let space = &self.at_jam;
        let (_, ordered) = space.agents.plain(&space.cluster, self.jam_a.venue.id());
        let kernel = self.kernels.of(&ordered);
        let proof = self
            .prover
            .prove(&kernel.blob, &ordered)
            .expect("a rootless proof");
        let statement = kernel.statement(&ordered);
        let verdict = self.jam_a.tapped.submit(&statement, &proof);
        self.record
            .note(format!("a rootless statement at JAM a: {verdict:?}"));
        assert_eq!(
            verdict,
            Err(Refusal::Space.into()),
            "rooted statements only"
        );
        (statement, proof)
    }

    /// What each JAM deployment keeps of each statement submitted there,
    /// read before the chain's clock moves and its outcomes age out: by
    /// deployment and statement, the outcome.
    fn judged(&self, stated: &[Stated], rootless: &(Statement, Vec<u8>)) -> Vec<(String, Judged)> {
        let mut judged: Vec<(&Jam, &Statement)> = stated
            .iter()
            .filter(|stated| stated.venue == Venue::Jam)
            .map(|stated| (&self.jam_a, &stated.statement))
            .collect();
        judged.push((&self.jam_b, &self.first_at_jam(stated).statement));
        judged.push((&self.jam_a, &rootless.0));
        judged
            .into_iter()
            .map(|(jam, statement)| {
                let outcome = jam.judged(statement).expect("an outcome kept");
                (
                    format!(
                        "JAM {}, statement {}",
                        jam.name,
                        hex::encode(&statement.id().0[..8])
                    ),
                    outcome,
                )
            })
            .collect()
    }

    /// The Kreivo space's anchors at Kreivo, from its first window through
    /// the run's first; the JAM space's at JAM `a`, of the run's three
    /// windows, and its record there.
    pub fn anchor_chains(&self) -> Vec<u8> {
        let first = self.first;
        let kreivo = &self.at_kreivo.id;
        for w in self.kreivo.start(kreivo)..=first {
            assert!(self.kreivo.holds(kreivo, w), "window {w} at Kreivo");
        }
        let jam = &self.at_jam.id;
        let statements = &self.jam_a.venue.statements;
        (first..first + 3)
            .map(|w| jam_keys::anchor(jam, RootKind::Space, w))
            .chain([jam_keys::space(jam)])
            .flat_map(|key| {
                statements
                    .value(&key)
                    .unwrap()
                    .expect("anchored at JAM, the space registered")
            })
            .collect()
    }

    /// Past `MaxRootAge` by the chain's clock, the JAM space's first
    /// statement, replayed, is unanchored.
    fn replays(&mut self, stated: &[Stated]) {
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
        let (statement, proof) = self.submitted(&self.first_at_jam(stated).statement);
        let code = replay(&self.jam_a, &statement, &proof);
        self.record
            .note(format!("replayed past MaxRootAge at JAM a: code {code:#x}"));
        assert_eq!(code, Refusal::Unanchored.code(), "replayed past MaxRootAge");
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
