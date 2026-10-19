//! The nodes' anchor keys at the model venue: a rotation, the new key
//! signing once the venue lists it and no window missed; a single-founder
//! space resumed after an equivocation by rotating its only key; a leader
//! whose keys the venue does not list signing nothing; a node that did not
//! found the space replicating the representative once its key is
//! registered, and anchoring after a failover; and a rotation whose process
//! is killed before the venue lists the key, which the node keeps.
//!
//! The windows are an hour long (`cuts::clock`), and the tests move the
//! nodes' clocks and the venue's past each window's close, `B_w + D`.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use ed25519_dalek::{Signer, SigningKey};
use vos_node::ReplaceError;
use vos_venue::{AnchorRefusal, VenueClient};
use vos_wire::WindowClock;
use vos_wire::ids::AgentId;
use vos_wire::ingress::Unplaced;
use vos_wire::keys;
use vos_wire::vos_anchor::Anchor;

use crate::common::{Cluster, wait_until};
use crate::cuts::clock;
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
    anchoring.set_clocks(&cluster, clock.boundary(0).unwrap() + delay(&clock) + 1_000);
    wait_until("the representative closes window 0", || {
        vos_checker::applied::<(u64, Option<AgentId>)>(
            cluster.node(1).store(),
            representative,
            &keys::close_mark(),
        )
        .is_some()
    });
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

/// An equivocation in a space of one founder: a second root of window 0,
/// signed by its only anchor key, suspends the space. The node, stopped,
/// rotates its key as `vos node anchor-key rotate` does; the controller
/// registers the new key, cannot resume while the equivocating key is
/// registered, removes it and resumes; the node's next window is
/// anchored by the new key.
#[test]
fn a_single_founder_resumes_after_an_equivocation() {
    let (anchoring, mut cluster, clock, _) = space(1);
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
    assert!(venue.resume(&space));
    assert_eq!(anchored(&anchoring, &cluster, &clock, 1).signer, rotated);
    assert!(!venue.suspended(&space));
    assert_eq!(windows(&anchoring, &cluster), [0, 1]);
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
