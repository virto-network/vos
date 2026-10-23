//! The nodes' anchor keys at the model venue: a rotation, the new key
//! signing once the venue lists it and no window missed; a single-founder
//! space resumed after an equivocation by rotating its only key; a leader
//! whose keys the venue does not list signing nothing; a node that did not
//! found the space replicating the representative once its key is
//! registered, and anchoring after a failover; anchors waiting through a
//! long wait taken up after a failover; a rotation whose process
//! is killed before the venue lists the key, which the node keeps; windows
//! refused while the venue's client answers the space unregistered,
//! anchored once it reads the registration; and a
//! queued anchor whose key the venue stops listing before it lands, signed
//! again by the new key.
//!
//! The windows are an hour long (`cuts::clock`), and the tests move the
//! nodes' clocks and the venue's past each window's close, `B_w + D`.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use vos_node::{Config, ReplaceError, roots};
use vos_venue::queue::{AnchorQueue, AnchorSend, Fate};
use vos_venue::vos_statement::{Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, ModelVenue, NotAccepted, Status, VenueClient};
use vos_wire::WindowClock;
use vos_wire::ids::AgentId;
use vos_wire::ingress::Unplaced;
use vos_wire::keys;
use vos_wire::vos_anchor::{Anchor, RootRead, SpaceId, VenueId};

use crate::common::{Cluster, wait_until};
use crate::cuts::{clock, set_clock};
use crate::representative::{Anchoring, delay};

/// The anchor of `window` the venue holds, once the clocks have passed
/// its close and the representative's leader has anchored it.
fn anchored(anchoring: &Anchoring, cluster: &Cluster, clock: &WindowClock, window: u64) -> Anchor {
    anchoring.set_clocks(
        cluster,
        clock.boundary(window).unwrap() + delay(clock) + 1_000,
    );
    let space = cluster.space.id();
    let mut anchor = None;
    wait_until(&format!("the venue holds window {window}'s anchor"), || {
        anchor = anchoring
            .venue
            .anchors(&space)
            .into_iter()
            .find(|anchor| anchor.window == window);
        anchor.is_some()
    });
    anchor.unwrap()
}

/// Set the clocks past `window`'s close and wait until node `number`'s
/// replica of the representative has sent it, anchored or not.
fn closed(
    anchoring: &Anchoring,
    cluster: &Cluster,
    clock: &WindowClock,
    (number, representative): (u8, AgentId),
    window: u64,
) {
    anchoring.set_clocks(
        cluster,
        clock.boundary(window).unwrap() + delay(clock) + 1_000,
    );
    wait_until(
        &format!("the representative closes window {window}"),
        || {
            vos_checker::applied::<(u64, Option<AgentId>)>(
                cluster.node(number).store(),
                representative,
                &keys::close_mark(),
            )
            .is_some_and(|(closed, _)| closed >= window)
        },
    );
}

/// The windows the venue holds anchored, in order.
fn windows(anchoring: &Anchoring, cluster: &Cluster) -> Vec<u64> {
    anchoring
        .venue
        .anchors(&cluster.space.id())
        .iter()
        .map(|anchor| anchor.window)
        .collect()
}

/// A space of `count` nodes, each anchoring at the venue, its space
/// registered there, and its representative on every node.
fn space(count: u8) -> (Anchoring, Cluster, WindowClock, AgentId) {
    let clock = clock();
    let anchoring = Anchoring::new();
    let cluster = Cluster::in_space(count, Some(clock), anchoring.tuning());
    anchoring.register(&cluster);
    let replicas: Vec<u8> = (1..=count).collect();
    let representative = cluster.representative(&replicas);
    (anchoring, cluster, clock, representative)
}

/// A rotation end to end: each node's first anchor key is the one the
/// genesis names; each makes a new one, and signs with its old key while
/// the venue does not list the new, with the new once it does, and with
/// the new alone once the old is removed. Every window is anchored, in
/// order, and none twice.
#[test]
fn a_rotation_anchors_every_window() {
    let (anchoring, cluster, clock, _) = space(3);
    let space = cluster.space.id();
    let venue = &anchoring.venue;
    let genesis: Vec<[u8; 32]> = cluster
        .space
        .genesis()
        .unwrap()
        .nodes
        .iter()
        .map(|(_, key)| *key)
        .collect();
    let old: Vec<[u8; 32]> = (1..=3)
        .map(|number| cluster.node(number).anchor_keys()[0])
        .collect();
    assert_eq!(old, genesis, "the first anchor keys the genesis's");
    let signer = |window| anchored(&anchoring, &cluster, &clock, window).signer;
    assert!(old.contains(&signer(0)), "before");
    let new: Vec<[u8; 32]> = (1..=3)
        .map(|number| cluster.node(number).rotate_anchor_key().unwrap())
        .collect();
    for (number, key) in (1..=3).zip(&new) {
        assert_eq!(
            cluster.node(number).anchor_keys(),
            [old[number as usize - 1], *key]
        );
    }
    assert!(
        old.contains(&signer(1)),
        "made, not yet listed: the old key"
    );
    for key in &new {
        assert!(venue.add_anchor_key(&space, *key));
    }
    assert!(new.contains(&signer(2)), "listed: the new key");
    for key in &old {
        assert!(venue.remove_anchor_key(&space, key));
    }
    assert!(new.contains(&signer(3)), "the old removed");
    assert_eq!(windows(&anchoring, &cluster), [0, 1, 2, 3], "none missed");
    assert!(venue.evidence().is_empty());
}

/// A leader whose keys the venue does not list signs nothing: it closes
/// the window all the same, and the venue holds no anchor of it. Once a
/// key it rotates to is listed, the window it held back is anchored, then
/// the next, both by that key.
#[test]
fn an_unlisted_leader_signs_nothing() {
    let (anchoring, cluster, clock, representative) = space(1);
    let space = cluster.space.id();
    let venue = &anchoring.venue;
    let founding = cluster.node(1).anchor_keys()[0];
    let stranger = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    assert!(venue.add_anchor_key(&space, stranger));
    assert!(venue.remove_anchor_key(&space, &founding));
    closed(&anchoring, &cluster, &clock, (1, representative), 0);
    assert!(windows(&anchoring, &cluster).is_empty(), "nothing signed");
    let key = cluster.node(1).rotate_anchor_key().unwrap();
    assert!(venue.add_anchor_key(&space, key));
    assert_eq!(anchored(&anchoring, &cluster, &clock, 1).signer, key);
    let anchors = venue.anchors(&space);
    assert_eq!(
        windows(&anchoring, &cluster),
        [0, 1],
        "window 0 held back, then taken"
    );
    assert!(anchors.iter().all(|anchor| anchor.signer == key));
}

/// An anchor left waiting survives a leader change: the leader's keys are
/// not listed, the other replicas' are; it closes window 0, signing
/// nothing, and stops. The new leader takes up window 0 from its replica's
/// cut, and anchors it, then window 1, with its own key.
#[test]
fn a_waiting_anchor_survives_a_leader_change() {
    let (anchoring, mut cluster, clock, representative) = space(3);
    let space = cluster.space.id();
    let leader = cluster.leader(representative);
    let unlisted = cluster.node(leader).anchor_keys()[0];
    assert!(anchoring.venue.remove_anchor_key(&space, &unlisted));
    closed(&anchoring, &cluster, &clock, (leader, representative), 0);
    assert!(windows(&anchoring, &cluster).is_empty(), "nothing signed");
    cluster.stop(leader);
    let next = cluster.leader(representative);
    let key = cluster.node(next).anchor_keys()[0];
    assert_eq!(anchored(&anchoring, &cluster, &clock, 1).signer, key);
    let anchors = anchoring.venue.anchors(&space);
    assert_eq!(windows(&anchoring, &cluster), [0, 1], "window 0 taken up");
    assert!(anchors.iter().all(|anchor| anchor.signer == key));
}

/// Anchors left waiting through a long wait survive a failover: the venue
/// lists no replica's key, so windows 0 to 2 close unsigned, past the two
/// cut roots an agent keeps; every replica has built their cuts; the
/// leader stops. Once the venue lists the new leader's key, it anchors
/// every one of them, then window 3.
#[test]
fn waiting_anchors_survive_a_failover_through_a_long_wait() {
    let (anchoring, mut cluster, clock, representative) = space(3);
    let space = cluster.space.id();
    let venue = &anchoring.venue;
    for number in 1..=3 {
        assert!(venue.remove_anchor_key(&space, &cluster.node(number).anchor_keys()[0]));
    }
    let leader = cluster.leader(representative);
    for window in 0..3 {
        closed(
            &anchoring,
            &cluster,
            &clock,
            (leader, representative),
            window,
        );
    }
    assert!(windows(&anchoring, &cluster).is_empty(), "nothing signed");
    wait_until("every replica built window 2's cut", || {
        (1..=3).all(|number| {
            roots::latest_built(&cluster.node(number).store().snapshot(), representative)
                .unwrap()
                .is_some_and(|built| built >= 2)
        })
    });
    cluster.stop(leader);
    let next = cluster.leader(representative);
    let key = cluster.node(next).anchor_keys()[0];
    assert!(venue.add_anchor_key(&space, key));
    assert_eq!(anchored(&anchoring, &cluster, &clock, 3).signer, key);
    assert_eq!(
        windows(&anchoring, &cluster),
        [0, 1, 2, 3],
        "every waiting window taken up"
    );
    assert!(venue.evidence().is_empty());
}

/// An equivocation in a space of one founder: a second root of window 0,
/// signed by its only anchor key, suspends the space. The node, stopped,
/// rotates its key as `vos node anchor-key rotate` does; the controller
/// registers the new key, cannot resume while the equivocating key is
/// registered, and removes it. The window that closes while the space is
/// suspended waits, unanchored; once resumed, it is anchored by the new key,
/// then the next.
#[test]
fn a_single_founder_resumes_after_an_equivocation() {
    let (anchoring, mut cluster, clock, representative) = space(1);
    let space = cluster.space.id();
    let venue = &anchoring.venue;
    let founding = cluster.node(1).anchor_keys()[0];
    let first = anchored(&anchoring, &cluster, &clock, 0);
    assert_eq!(first.signer, founding);
    cluster.stop(1);
    let data = cluster.dirs[0].path().to_path_buf();
    let secret = vos_node::store::Fjall::open(data.join(vos_node::STORE))
        .unwrap()
        .node_secret()
        .unwrap()
        .unwrap();
    let key = SigningKey::from_bytes(&secret);
    assert_eq!(key.verifying_key().to_bytes(), founding);
    let mut second = Anchor {
        root: [0xee; 32],
        ..first
    };
    second.signature = key.sign(&second.digest(&venue.id())).to_bytes();
    assert_eq!(venue.anchor(&second), Err(AnchorRefusal::Equivocation));
    assert!(venue.suspended(&space));
    let rotated = vos_node::rotate_anchor_key(&data).unwrap();
    cluster.start(1);
    assert_eq!(cluster.node(1).anchor_keys(), [founding, rotated]);
    assert!(venue.add_anchor_key(&space, rotated));
    assert!(!venue.resume(&space), "the equivocating key is registered");
    assert!(venue.remove_anchor_key(&space, &founding));
    closed(&anchoring, &cluster, &clock, (1, representative), 1);
    assert_eq!(
        windows(&anchoring, &cluster),
        [0],
        "suspended: window 1 waits"
    );
    assert!(venue.resume(&space));
    assert_eq!(anchored(&anchoring, &cluster, &clock, 2).signer, rotated);
    assert!(!venue.suspended(&space));
    let anchors = venue.anchors(&space);
    assert_eq!(windows(&anchoring, &cluster), [0, 1, 2]);
    assert_eq!(anchors[1].signer, rotated);
}

/// A node that did not found the space replicates the representative once
/// it holds a registered anchor key: refused before, as it holds none;
/// it rotates to one, the controller registers it, it replaces a founding
/// replica, and, its founding replicas failing over until it leads,
/// anchors the next window with that key.
#[test]
fn a_registered_node_that_did_not_found_the_space_represents_it() {
    let clock = clock();
    let anchoring = Anchoring::new();
    let mut cluster = Cluster::founded_by(4, &[1, 2, 3], clock, anchoring.tuning());
    anchoring.register(&cluster);
    let space = cluster.space.id();
    let representative = cluster.representative(&[1, 2, 3]);
    let leader = cluster.leader(representative);
    let out = [1, 2, 3]
        .into_iter()
        .find(|number| *number != leader)
        .unwrap();
    assert!(
        matches!(
            cluster.node(leader).replace(representative, out, 4),
            Err(ReplaceError::Unplaced(Unplaced::CannotRun))
        ),
        "node 4 holds no registered key"
    );
    let key = cluster.node(4).rotate_anchor_key().unwrap();
    assert!(anchoring.venue.add_anchor_key(&space, key));
    let replicas = cluster.replace(leader, representative, &[1, 2, 3], out, 4);
    wait_until("node 4 runs the representative", || {
        cluster.node(4).applied(representative).is_some()
    });
    cluster.caught_up(4, representative, leader);
    // Each round stops the founding leader, the one stopped before back
    // and caught up: node 4 wins one of them.
    let mut stopped: Option<u8> = None;
    for _ in 0..20 {
        let leader = cluster.leader(representative);
        if leader == 4 {
            break;
        }
        if let Some(back) = stopped.take() {
            cluster.start(back);
            cluster.caught_up(back, representative, leader);
        }
        cluster.stop(leader);
        stopped = Some(leader);
    }
    assert_eq!(cluster.leader(representative), 4, "replicas {replicas:?}");
    assert_eq!(anchored(&anchoring, &cluster, &clock, 0).signer, key);
}

/// The variable that makes the test binary the rotation killed: the data
/// directory it rotates.
const ROTATING: &str = "VOS_ANCHOR_KEY_ROTATING";
/// What the rotation prints before the key it made.
const MADE: &str = "anchor key ";

/// Rotate the stopped node's anchor key at `data` in a child, as
/// `vos node anchor-key rotate` does, and kill it once it prints the key:
/// that key.
fn rotate_and_kill(data: &Path) -> [u8; 32] {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "anchor_keys::a_rotation_survives_its_crash",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROTATING, data)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut key = None;
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        // The harness may print the test's name before it, on its line.
        if let Some((_, hex)) = line.unwrap().split_once(MADE) {
            key = Some(std::array::from_fn(|at| {
                u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).unwrap()
            }));
            break;
        }
    }
    child.kill().unwrap();
    child.wait().unwrap();
    key.expect("the child printed its key")
}

/// A rotation whose process is killed once it shows the key, before any
/// venue lists it: the node keeps the key, signs with its old one until
/// the venue lists the new, then with the new; no window missed.
#[test]
fn a_rotation_survives_its_crash() {
    if let Some(data) = std::env::var_os(ROTATING) {
        let key = vos_node::rotate_anchor_key(Path::new(&data)).unwrap();
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut out = std::io::stdout();
        writeln!(out, "{MADE}{hex}").unwrap();
        out.flush().unwrap();
        loop {
            std::thread::park();
        }
    }
    let (anchoring, mut cluster, clock, _) = space(1);
    let space = cluster.space.id();
    let founding = cluster.node(1).anchor_keys()[0];
    assert_eq!(anchored(&anchoring, &cluster, &clock, 0).signer, founding);
    cluster.stop(1);
    let rotated = rotate_and_kill(cluster.dirs[0].path());
    cluster.start(1);
    assert_eq!(cluster.node(1).anchor_keys(), [founding, rotated], "kept");
    assert_eq!(
        anchored(&anchoring, &cluster, &clock, 1).signer,
        founding,
        "not yet listed"
    );
    assert!(anchoring.venue.add_anchor_key(&space, rotated));
    assert_eq!(anchored(&anchoring, &cluster, &clock, 2).signer, rotated);
    assert!(anchoring.venue.remove_anchor_key(&space, &founding));
    assert_eq!(anchored(&anchoring, &cluster, &clock, 3).signer, rotated);
    assert_eq!(windows(&anchoring, &cluster), [0, 1, 2, 3]);
}

/// A founding node signs the space's registration by its node key, over
/// pin D's registration digest; a node the genesis does not name, or a
/// node of no space, signs none.
#[test]
fn only_a_founding_node_signs_the_registration() {
    let venue = vos_wire::vos_anchor::VenueId([0x5e; 32]);
    let cluster = Cluster::founded_by(3, &[1, 2], clock(), |_, _| {});
    let space = cluster.space.id();
    let (key, signature) = cluster
        .node(2)
        .sign_registration(&venue, &[9; 32], 4)
        .expect("a founder signs");
    let digest = vos_wire::vos_anchor::register_digest(&venue, &space, &[9; 32], 4);
    assert_eq!(key, cluster.node(2).id().0, "by its node key");
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&signature))
        .expect("over the registration digest");
    assert!(
        cluster
            .node(3)
            .sign_registration(&venue, &[9; 32], 4)
            .is_none(),
        "not a founder"
    );
    let spaceless = Cluster::in_space(1, None, |_, _| {});
    assert!(
        spaceless
            .node(1)
            .sign_registration(&venue, &[9; 32], 4)
            .is_none(),
        "of no space"
    );
}

/// The model venue as a client that has not read the space's registration
/// yet answers it: each anchor refused `Unregistered` until `read`, as
/// Kreivo's client answers from what it last read.
struct Unread {
    venue: Arc<ModelVenue>,
    read: AtomicBool,
}

impl VenueClient for Unread {
    fn id(&self) -> VenueId {
        self.venue.id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        if !self.read.load(Ordering::SeqCst) {
            return Err(AnchorRefusal::Unregistered);
        }
        self.venue.anchor(anchor)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        self.venue.submit(statement, proof)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.venue.anchored(root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.venue.anchor_keys(space)
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.venue.status(space)
    }

    fn time(&self) -> Option<u64> {
        self.venue.time()
    }
}

/// Windows 0 and 1 close while the venue answers the space unregistered,
/// its client not having read the registration: each anchor waits. Once
/// the client reads it, the same leader anchors both, then window 2.
#[test]
fn windows_refused_unregistered_are_anchored_once_registered() {
    let clock = clock();
    let anchoring = Anchoring::new();
    let unread = Arc::new(Unread {
        venue: Arc::clone(&anchoring.venue),
        read: AtomicBool::new(false),
    });
    let client: Arc<dyn VenueClient> = unread.clone();
    let cluster = Cluster::in_space(1, Some(clock), move |_, config: &mut Config| {
        config.venue = Some(Arc::clone(&client));
    });
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1]);
    for window in 0..2 {
        closed(&anchoring, &cluster, &clock, (1, representative), window);
    }
    assert!(windows(&anchoring, &cluster).is_empty(), "unregistered");
    unread.read.store(true, Ordering::SeqCst);
    anchored(&anchoring, &cluster, &clock, 2);
    assert_eq!(windows(&anchoring, &cluster), [0, 1, 2]);
}

/// The model venue reached through an [`AnchorQueue`], as a client of a
/// chain reaches its venue: an anchor queued and answered at once, then
/// sent until the venue takes it; one refused as signed handed back.
struct Queued {
    venue: Arc<ModelVenue>,
    queue: AnchorQueue,
}

struct Sending(Arc<ModelVenue>);

impl AnchorSend for Sending {
    fn send(&self, anchor: &Anchor) -> Fate {
        match self.0.anchor(anchor) {
            Ok(_) => Fate::Done,
            Err(AnchorRefusal::Open | AnchorRefusal::Unregistered | AnchorRefusal::Suspended) => {
                Fate::Again(Duration::from_millis(50))
            }
            Err(AnchorRefusal::Key | AnchorRefusal::Signature) => Fate::Resign,
            Err(_) => Fate::Dead,
        }
    }
}

impl VenueClient for Queued {
    fn id(&self) -> VenueId {
        self.venue.id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        self.queue.push(anchor);
        Ok(Anchored::Queued)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        self.venue.submit(statement, proof)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.venue.anchored(root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.venue.anchor_keys(space)
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.venue.status(space)
    }

    fn time(&self) -> Option<u64> {
        self.venue.time()
    }

    fn unsettled(&self, space: &SpaceId) -> Vec<u64> {
        self.queue.unsettled(space)
    }
}

/// The node's anchor of window 0 is queued while the venue's clock has not
/// closed the window; before it lands, the node rotates its key and the
/// controller lists the new one and removes the old. The venue refuses the
/// queued anchor's key, the client hands the window back, and the same
/// leader signs it again with the new key, which the venue takes.
#[test]
fn a_queued_anchor_whose_key_is_removed_is_signed_again() {
    let clock = clock();
    let anchoring = Anchoring::new();
    let queued = Arc::new(Queued {
        venue: Arc::clone(&anchoring.venue),
        queue: AnchorQueue::spawn("test-queued-anchors", Sending(Arc::clone(&anchoring.venue))),
    });
    let client: Arc<dyn VenueClient> = queued.clone();
    let cluster = Cluster::in_space(1, Some(clock), move |_, config: &mut Config| {
        config.venue = Some(Arc::clone(&client));
    });
    anchoring.register(&cluster);
    cluster.representative(&[1]);
    let space = cluster.space.id();
    let venue = &anchoring.venue;
    let old = cluster.node(1).anchor_keys()[0];
    // The venue's clock a minute into window 0, the node's past its close.
    let close = clock.boundary(0).unwrap() + delay(&clock) + 1_000;
    set_clock(&cluster, 1, close);
    wait_until("window 0's anchor queued", || queued.queue.holds(&space, 0));
    assert!(windows(&anchoring, &cluster).is_empty(), "the window open");
    let new = cluster.node(1).rotate_anchor_key().unwrap();
    assert!(venue.add_anchor_key(&space, new));
    assert!(venue.remove_anchor_key(&space, &old));
    anchoring.set_venue(close);
    wait_until("window 0 anchored", || {
        !windows(&anchoring, &cluster).is_empty()
    });
    assert_eq!(venue.anchors(&space)[0].signer, new, "signed again");
    assert!(venue.evidence().is_empty());
}
