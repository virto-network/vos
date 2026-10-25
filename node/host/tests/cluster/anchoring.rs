//! The representative's anchoring at the model venue, each node signing
//! with its node key: a leader whose key the venue does not list signing
//! nothing; a node that did not found the space replicating the
//! representative once its key is registered, and anchoring after a
//! failover; anchors waiting through a long wait taken up after a
//! failover; windows refused while the venue's client answers the space
//! unregistered, anchored once it reads the registration.
//!
//! The windows are an hour long (`support::clock`), and the tests move the
//! nodes' clocks and the venue's past each window's close, `B_w + D`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::SigningKey;
use vos_node::{Config, ReplaceError, roots};
use vos_venue::{AnchorOutcome, ModelVenue, VenueClient};
use vos_wire::WindowClock;
use vos_wire::ids::AgentId;
use vos_wire::ingress::Unplaced;
use vos_wire::vos_anchor::Anchor;

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
/// yet answers it: each anchor not yet taken until `read`, as
/// Kreivo's client answers from what it last read.
struct Unread {
    venue: Arc<ModelVenue>,
    read: AtomicBool,
}

vos_venue::forward_venue!(Unread => venue; forward [id, submit, anchored, anchor_keys, status, held, time] {
    fn anchor(&self, anchor: &Anchor) -> AnchorOutcome {
        if !self.read.load(Ordering::SeqCst) {
            return AnchorOutcome::NotYet;
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
