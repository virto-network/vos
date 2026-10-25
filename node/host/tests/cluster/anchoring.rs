//! The representative's anchoring at the model venue, each node signing
//! with its node key: a leader whose key the venue does not list signing
//! nothing; a node that did not found the space replicating the
//! representative once its key is registered, and anchoring after a
//! failover; anchors waiting through a long wait taken up after a
//! failover; windows refused while the venue's client answers the space
//! unregistered, anchored once it reads the registration; and anchors a
//! client hands back that the node never signed, not signed again.
//!
//! The windows are an hour long (`support::clock`), and the tests move the
//! nodes' clocks and the venue's past each window's close, `B_w + D`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use vos_node::{Config, ReplaceError, roots};
use vos_venue::queue::{AnchorQueue, AnchorSend, Fate};
use vos_venue::{AnchorRefusal, Anchored, ModelVenue, Status, VenueClient};
use vos_wire::WindowClock;
use vos_wire::ids::AgentId;
use vos_wire::ingress::Unplaced;
use vos_wire::vos_anchor::{Anchor, MAX_ROOT_AGE_MS, SpaceId};

use crate::common::{Cluster, wait_until};
use crate::support::Anchoring;
use crate::support::clock;
use crate::support::{closed_on, past_close};

/// The anchor of `window` the venue holds, once the clocks have passed
/// its close and the representative's leader has anchored it.
fn anchored(anchoring: &Anchoring, cluster: &Cluster, clock: &WindowClock, window: u64) -> Anchor {
    anchoring.set_clocks(cluster, past_close(clock, window));
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
    anchoring.set_clocks(cluster, past_close(clock, window));
    wait_until(
        &format!("the representative closes window {window}"),
        || closed_on(cluster.node(number), representative, window),
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

/// A leader whose key the venue does not list signs nothing: it closes
/// the window all the same, and the venue holds no anchor of it. Once its
/// key is listed again, the window it held back is anchored, then the
/// next, both by that key.
#[test]
fn an_unlisted_leader_signs_nothing() {
    let (anchoring, cluster, clock, representative) = space(1);
    let space = cluster.space.id();
    let venue = &anchoring.venue;
    let key = cluster.node(1).id().0;
    let stranger = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    assert!(venue.add_anchor_key(&space, stranger));
    assert!(venue.remove_anchor_key(&space, &key));
    closed(&anchoring, &cluster, &clock, (1, representative), 0);
    assert!(windows(&anchoring, &cluster).is_empty(), "nothing signed");
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

/// An anchor left waiting survives a leader change: the leader's key is
/// not listed, the other replicas' are; it closes window 0, signing
/// nothing, and stops. The new leader takes up window 0 from its replica's
/// cut, and anchors it, then window 1, with its own key.
#[test]
fn a_waiting_anchor_survives_a_leader_change() {
    let (anchoring, mut cluster, clock, representative) = space(3);
    let space = cluster.space.id();
    let leader = cluster.leader(representative);
    let unlisted = cluster.node(leader).id().0;
    assert!(anchoring.venue.remove_anchor_key(&space, &unlisted));
    closed(&anchoring, &cluster, &clock, (leader, representative), 0);
    assert!(windows(&anchoring, &cluster).is_empty(), "nothing signed");
    cluster.stop(leader);
    let next = cluster.leader(representative);
    let key = cluster.node(next).id().0;
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
        assert!(venue.remove_anchor_key(&space, &cluster.node(number).id().0));
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
    let key = cluster.node(next).id().0;
    assert!(venue.add_anchor_key(&space, key));
    assert_eq!(anchored(&anchoring, &cluster, &clock, 3).signer, key);
    assert_eq!(
        windows(&anchoring, &cluster),
        [0, 1, 2, 3],
        "every waiting window taken up"
    );
    assert!(venue.evidence().is_empty());
}

/// A node that did not found the space replicates the representative once
/// the controller registers its node key: refused before; then it
/// replaces a founding replica, and, its founding replicas failing over
/// until it leads, anchors the next window with its key.
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
        "node 4's key is not registered"
    );
    let key = cluster.node(4).id().0;
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

/// A founding node signs the space's registration by its node key, over
/// `vos-anchor`'s registration digest; a node the genesis does not name, or
/// a node of no space, signs none.
#[test]
fn only_a_founding_node_signs_the_registration() {
    let venue = vos_wire::vos_anchor::VenueId([0x5e; 32]);
    let cluster = Cluster::founded_by(3, &[1, 2], clock(), |_, _| {});
    let space = cluster.space.id();
    let (key, signature) = cluster
        .node(2)
        .sign_registration(&venue, &[9; 32])
        .expect("a founder signs");
    let digest = vos_wire::vos_anchor::register_digest(&venue, &space, &[9; 32]);
    assert_eq!(key, cluster.node(2).id().0, "by its node key");
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&signature))
        .expect("over the registration digest");
    assert!(
        cluster
            .node(3)
            .sign_registration(&venue, &[9; 32])
            .is_none(),
        "not a founder"
    );
    let spaceless = Cluster::in_space(1, None, |_, _| {});
    assert!(
        spaceless
            .node(1)
            .sign_registration(&venue, &[9; 32])
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

vos_venue::forward_venue!(Unread => venue; forward [id, submit, anchored, anchor_keys, status, time, unsettled] {
    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        if !self.read.load(Ordering::SeqCst) {
            return Err(AnchorRefusal::Unregistered);
        }
        self.venue.anchor(anchor)
    }
});

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
/// sent until the venue takes it; one whose key the venue does not list
/// handed back. Its listing of anchor keys may be held at an older read
/// (`stale`), as a client's lags the chain.
struct Queued {
    venue: Arc<ModelVenue>,
    queue: AnchorQueue,
    sends: Arc<AtomicUsize>,
    stale: Mutex<Option<Vec<[u8; 32]>>>,
    /// Anchors it hands back beside its queue's, as a faulty client would.
    injected: Mutex<Vec<Anchor>>,
}

impl Queued {
    fn over(venue: &Arc<ModelVenue>) -> Arc<Self> {
        let sends = Arc::new(AtomicUsize::new(0));
        let sending = Sending(Arc::clone(venue), Arc::clone(&sends));
        Arc::new(Self {
            venue: Arc::clone(venue),
            queue: AnchorQueue::spawn("test-queued-anchors", sending),
            sends,
            stale: Mutex::new(None),
            injected: Mutex::default(),
        })
    }

    /// A single node anchoring through `self`.
    fn cluster(self: &Arc<Self>, clock: WindowClock) -> Cluster {
        let client: Arc<dyn VenueClient> = self.clone();
        Cluster::in_space(1, Some(clock), move |_, config: &mut Config| {
            config.venue = Some(Arc::clone(&client));
        })
    }
}

/// How the queue sends to the model venue, counting each send.
struct Sending(Arc<ModelVenue>, Arc<AtomicUsize>);

impl AnchorSend for Sending {
    fn send(&self, anchor: &Anchor) -> Fate {
        self.1.fetch_add(1, Ordering::SeqCst);
        match self.0.anchor(anchor) {
            Ok(_) => Fate::Done,
            Err(AnchorRefusal::Open | AnchorRefusal::Unregistered | AnchorRefusal::Stopped) => {
                Fate::Again(Duration::from_millis(50))
            }
            Err(AnchorRefusal::Key) => Fate::Resign,
            Err(_) => Fate::Dead,
        }
    }

    /// The venue's last anchored window at or past it, or aged.
    fn settled(&self, anchor: &Anchor) -> bool {
        let passed = self
            .0
            .anchors(&anchor.space)
            .iter()
            .any(|held| held.window >= anchor.window);
        let aged = self
            .0
            .time()
            .zip(self.0.clock(&anchor.space))
            .is_some_and(|(now, clock)| {
                clock
                    .boundary(anchor.window)
                    .is_some_and(|boundary| now.saturating_sub(boundary) > MAX_ROOT_AGE_MS)
            });
        passed || aged
    }
}

vos_venue::forward_venue!(Queued => venue; forward [id, submit, anchored, status, time] {
    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        if !self.queue.push(anchor) {
            return Err(AnchorRefusal::Key);
        }
        Ok(Anchored::Queued)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        let stale = self.stale.lock().unwrap().clone();
        stale.unwrap_or_else(|| self.venue.anchor_keys(space))
    }

    fn unsettled(&self, space: &SpaceId) -> Vec<Anchor> {
        let injected = self.injected.lock().unwrap().clone();
        [self.queue.unsettled(space), injected].concat()
    }
});

/// Set node `number`'s clock past `window`'s close, leaving the venue's,
/// and wait until its replica of the representative has closed it.
fn node_closed(cluster: &Cluster, clock: &WindowClock, representative: AgentId, window: u64) {
    cluster.set_clock(1, past_close(clock, window));
    wait_until(
        &format!("the representative closes window {window}"),
        || closed_on(cluster.node(1), representative, window),
    );
}

/// A client hands back anchors this node never signed: window 0's, once
/// it is anchored, of another root signed by the node's key, and of a root
/// signed by a key not the node's. The leader signs neither again: the
/// venue is sent nothing more, holds window 0's root as anchored, and keeps
/// no evidence.
#[test]
fn an_anchor_handed_back_that_this_node_did_not_make_is_not_signed() {
    let clock = clock();
    let anchoring = Anchoring::new();
    let queued = Queued::over(&anchoring.venue);
    let mut cluster = queued.cluster(clock);
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1]);
    let space = cluster.space.id();
    let venue = &anchoring.venue;
    anchoring.set_venue(past_close(&clock, 0));
    node_closed(&cluster, &clock, representative, 0);
    wait_until("window 0 anchored", || windows(&anchoring, &cluster) == [0]);
    let held = venue.anchors(&space)[0];
    cluster.stop(1);
    let secret = vos_node::store::Fjall::open(cluster.dirs[0].path().join(vos_node::STORE))
        .unwrap()
        .node_secret()
        .unwrap()
        .unwrap();
    cluster.start(1);
    let sign = |key: &SigningKey, root: [u8; 32]| {
        let mut anchor = Anchor {
            root,
            signer: key.verifying_key().to_bytes(),
            ..held
        };
        anchor.signature = key.sign(&anchor.digest(&venue.id())).to_bytes();
        anchor
    };
    let ours = sign(&SigningKey::from_bytes(&secret), [0xee; 32]);
    assert_eq!(ours.signer, held.signer, "the node's key");
    let foreign = sign(&SigningKey::from_bytes(&[9; 32]), [0xef; 32]);
    *queued.injected.lock().unwrap() = vec![ours, foreign];
    cluster.leader(representative);
    let sent = queued.sends.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(queued.sends.load(Ordering::SeqCst), sent, "nothing sent");
    assert_eq!(venue.anchors(&space), [held]);
    assert!(venue.evidence().is_empty());
    assert_eq!(venue.status(&space), Status::Active);
}
