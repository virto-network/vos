//! The representative's anchoring at the model venue, each node signing
//! with its node key the space's root its close wrote: anchors in order
//! across a leader change; a deposed leader and a successor whose clock
//! lags anchoring one root; the divergence guard, a quorum's majority
//! sending the evidence over a dissenting replica and no quorum sending
//! nothing, and an equivocation, the replicas agreeing, ending the space; an unlisted leader handing off to a listed
//! replica, once a window, and with none listed alerting and waiting; a
//! delisted node refused the representative and replaced; a node that did
//! not found the space representing it once its key is registered;
//! anchors waiting through a long wait taken up after a failover; an aged
//! window settled unsent; windows refused while the venue's client answers
//! the space unregistered, anchored once it reads the registration.
//!
//! The windows are an hour long (`support::clock`), and the tests move the
//! nodes' clocks and the venue's past each window's close, `B_w + D`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use vos_node::store::PersistMode;
use vos_node::{AnchorAlert, Config, Hooks, ReplaceError, roots};
use vos_venue::{AnchorOutcome, Held, ModelVenue, Status, VenueClient};
use vos_wire::WindowClock;
use vos_wire::ids::AgentId;
use vos_wire::ingress::Unplaced;
use vos_wire::keys;
use vos_wire::peer::NodeNumber;
use vos_wire::result::Write;
use vos_wire::vos_anchor::{Anchor, MAX_ROOT_AGE_MS, RootKind, SpaceId};

use crate::common::{Cluster, wait_until};
use crate::support::Anchoring;
use crate::support::clock;
use crate::support::{close_with, closed_on, delay};

/// Window `window` closed: the clocks past its boundary until the
/// representative holds a report of it, then past its close.
fn close(anchoring: &Anchoring, cluster: &Cluster, clock: &WindowClock, window: u64) {
    close_with(cluster, clock, window, |at| {
        anchoring.set_clocks(cluster, at)
    });
}

/// The anchor of `window` the venue holds, once the clocks have passed
/// its close and the representative's leader has anchored it.
fn anchored(anchoring: &Anchoring, cluster: &Cluster, clock: &WindowClock, window: u64) -> Anchor {
    close(anchoring, cluster, clock, window);
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
    close(anchoring, cluster, clock, window);
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
/// registered there, its representative on every node, and an agent on
/// every node reporting every window, so each is anchored.
fn space(count: u8) -> (Anchoring, Cluster, WindowClock, AgentId) {
    let clock = clock();
    let anchoring = Anchoring::new();
    let cluster = Cluster::in_space(count, Some(clock), anchoring.tuning());
    anchoring.register(&cluster);
    let replicas: Vec<u8> = (1..=count).collect();
    let representative = cluster.representative(&replicas);
    cluster.issuer(&replicas);
    (anchoring, cluster, clock, representative)
}

/// The model venue as node `node`'s client reaches it: each anchor
/// offered recorded with its node; the roots held unread until `read`,
/// and, `blind`, never seen held, so a leader offers every window.
struct Offering {
    venue: Arc<ModelVenue>,
    node: NodeNumber,
    offers: Arc<Mutex<Vec<(NodeNumber, Anchor)>>>,
    read: Arc<AtomicBool>,
    blind: bool,
}

vos_venue::forward_venue!(Offering => venue; forward [id, submit, anchored, anchor_keys, status, time] {
    fn anchor(&self, anchor: &Anchor) -> AnchorOutcome {
        self.offers.lock().unwrap().push((self.node, *anchor));
        self.venue.anchor(anchor)
    }

    fn held(&self, space: &SpaceId, window: u64) -> Held {
        if !self.read.load(Ordering::SeqCst) {
            Held::Unread
        } else if self.blind {
            Held::Nothing
        } else {
            self.venue.held(space, window)
        }
    }
});

/// What the nodes' clients share: the anchors offered, and whether they
/// have read the roots held.
#[derive(Clone, Default)]
struct Offers {
    offers: Arc<Mutex<Vec<(NodeNumber, Anchor)>>>,
    read: Arc<AtomicBool>,
}

impl Offers {
    /// Each node's config: anchoring at `anchoring`'s venue through an
    /// [`Offering`] of its own; `hooks` its hooks, when given.
    fn tuning(
        &self,
        anchoring: &Anchoring,
        blind: bool,
        hooks: Option<Arc<dyn Hooks>>,
    ) -> impl Fn(NodeNumber, &mut Config) + Send + Sync + 'static {
        let (venue, shared) = (Arc::clone(&anchoring.venue), self.clone());
        move |node, config| {
            config.venue = Some(Arc::new(Offering {
                venue: Arc::clone(&venue),
                node,
                offers: Arc::clone(&shared.offers),
                read: Arc::clone(&shared.read),
                blind,
            }));
            if let Some(hooks) = &hooks {
                config.hooks = Arc::clone(hooks);
            }
        }
    }

    /// The anchors of `window` offered, by node.
    fn of(&self, window: u64) -> Vec<(NodeNumber, Anchor)> {
        let offers = self.offers.lock().unwrap();
        offers
            .iter()
            .filter(|(_, anchor)| anchor.window == window)
            .copied()
            .collect()
    }
}

/// Node `number`'s alerts.
fn alerts(cluster: &Cluster, number: NodeNumber) -> Vec<AnchorAlert> {
    cluster.node(number).anchor_alerts()
}

/// Wait until every running replica of `representative` holds its row of
/// `window`: the root, the same on each.
fn rows(cluster: &Cluster, representative: AgentId, window: u64) -> [u8; 32] {
    let mut root = None;
    wait_until(
        &format!("every replica writes its row of window {window}"),
        || {
            let held: Vec<_> = cluster
                .running()
                .filter(|(_, node)| node.applied(representative).is_some())
                .map(|(_, node)| {
                    roots::anchor_of(&node.store().snapshot(), representative, window).unwrap()
                })
                .collect();
            root = held.first().copied().flatten();
            held.iter().all(|row| row.is_some() && *row == root)
        },
    );
    root.unwrap()
}

/// `root` anchored at window `window` of `space` at `venue`, signed by
/// `key`, a key the venue lists.
fn anchor_by(venue: &ModelVenue, space: SpaceId, window: u64, root: [u8; 32], key: &SigningKey) {
    let mut anchor = Anchor {
        space,
        window,
        kind: RootKind::Space,
        root,
        signer: key.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    anchor.signature = key.sign(&anchor.digest(&venue.id())).to_bytes();
    assert_eq!(venue.anchor(&anchor), AnchorOutcome::Taken);
}

/// Anchors go in window order across a leader change: window 0 by the
/// first leader, 1 and 2 by the next, each once, with no evidence.
#[test]
fn anchors_go_in_order_across_a_leader_change() {
    let (anchoring, mut cluster, clock, representative) = space(3);
    let first = cluster.leader(representative);
    assert_eq!(
        anchored(&anchoring, &cluster, &clock, 0).signer,
        cluster.node(first).id().0
    );
    cluster.stop(first);
    let next = cluster.leader(representative);
    for window in 1..=2 {
        assert_eq!(
            anchored(&anchoring, &cluster, &clock, window).signer,
            cluster.node(next).id().0
        );
    }
    assert_eq!(windows(&anchoring, &cluster), [0, 1, 2]);
    assert!(anchoring.venue.evidence().is_empty());
}

/// Stops the representative's leader before it proposes its close of
/// window 0, once.
#[derive(Default)]
struct StopBeforeClose {
    representative: Mutex<Option<AgentId>>,
    stopped: AtomicBool,
}

impl Hooks for StopBeforeClose {
    fn close(&self, agent: AgentId, window: u64) -> bool {
        let ours = *self.representative.lock().unwrap() == Some(agent) && window == 0;
        !ours || self.stopped.swap(true, Ordering::SeqCst)
    }
}

/// A deposed leader with a close not committed, and a successor whose
/// clock lags, both anchor window 0: each signs the row its close wrote,
/// never a root of a batch under proposal, so the venue takes the
/// successor's as a repeat of the same root, keeps no evidence, and the
/// space stays active.
#[test]
fn a_deposed_leader_and_a_lagging_successor_anchor_one_root() {
    let clock = clock();
    let anchoring = Anchoring::new();
    let offers = Offers::default();
    offers.read.store(true, Ordering::SeqCst);
    let hook = Arc::new(StopBeforeClose::default());
    let hooks: Arc<dyn Hooks> = hook.clone();
    let mut cluster =
        Cluster::in_space(3, Some(clock), offers.tuning(&anchoring, true, Some(hooks)));
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    cluster.issuer(&[1, 2, 3]);
    *hook.representative.lock().unwrap() = Some(representative);
    let deposed = cluster.leader(representative);
    close(&anchoring, &cluster, &clock, 0);
    wait_until("the hook stops the leader before its close", || {
        hook.stopped.load(Ordering::SeqCst)
    });
    // The successor's clock lags: before the close by its own reading.
    let lagging = clock.boundary(0).unwrap() + delay(&clock) / 2;
    for number in (1..=3).filter(|number| *number != deposed) {
        cluster.set_clock(number, lagging);
    }
    cluster.stop(deposed);
    let successor = cluster.leader(representative);
    wait_until("the successor offers window 0", || {
        offers.of(0).iter().any(|(node, _)| *node == successor)
    });
    let offered = offers.of(0);
    assert!(
        offered.iter().any(|(node, _)| *node == deposed),
        "{offered:?}"
    );
    let root = offered[0].1.root;
    assert!(
        offered.iter().all(|(_, anchor)| anchor.root == root),
        "one root: {offered:?}"
    );
    let held = anchoring.venue.anchors(&cluster.space.id());
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].root, root);
    assert!(anchoring.venue.evidence().is_empty());
    assert_eq!(anchoring.venue.status(&cluster.space.id()), Status::Active);
}

/// A space of three nodes whose venue holds a stolen listed key's root at
/// window 0 before its representative's leader anchors it, that leader's
/// client reading the roots held once the replicas' rows are written: the
/// venue, the cluster, the representative, its leader, its row of window
/// 0, and the clients' offers.
fn overtaken() -> (Anchoring, Cluster, AgentId, NodeNumber, [u8; 32], Offers) {
    let clock = clock();
    let anchoring = Anchoring::new();
    let offers = Offers::default();
    let cluster = Cluster::in_space(3, Some(clock), offers.tuning(&anchoring, false, None));
    anchoring.register(&cluster);
    let space = cluster.space.id();
    let representative = cluster.representative(&[1, 2, 3]);
    cluster.issuer(&[1, 2, 3]);
    let stolen = SigningKey::from_bytes(&[0x66; 32]);
    assert!(
        anchoring
            .venue
            .add_anchor_key(&space, stolen.verifying_key().to_bytes())
    );
    anchoring.set_venue(clock.boundary(0).unwrap() + 1_000);
    anchor_by(&anchoring.venue, space, 0, [9; 32], &stolen);
    close(&anchoring, &cluster, &clock, 0);
    let root = rows(&cluster, representative, 0);
    let leader = cluster.leader(representative);
    (anchoring, cluster, representative, leader, root, offers)
}

/// Write `root` as `representative`'s row of window 0 on node `number`, as
/// an apply bug, a cloned store or a compromise would leave it.
fn forge_row(cluster: &Cluster, number: NodeNumber, representative: AgentId, root: [u8; 32]) {
    let store = cluster.node(number).store();
    let epoch = store.snapshot().epoch(representative).unwrap();
    let mut batch = store.batch();
    let forged = Write {
        key: keys::anchor(0),
        value: Some(root.to_vec()),
    };
    batch.rows(representative, epoch, [&forged]);
    batch.commit(PersistMode::SyncAll).unwrap();
}

/// The majority decides (S34): a compromised replica anchored a forged
/// root at window 0 with its listed key and answers the guard with it as
/// its row. A quorum, the leader and the other replica, holds the leader's
/// row, so the evidence goes all the same and the space ends; the
/// dissenter is alerted by name, its root the venue's held one, which
/// names it the equivocator.
#[test]
fn a_dissenting_replica_does_not_block_the_evidence() {
    let (anchoring, cluster, representative, leader, root, offers) = overtaken();
    let compromised = (1..=3).find(|number| *number != leader).unwrap();
    forge_row(&cluster, compromised, representative, [9; 32]);
    offers.read.store(true, Ordering::SeqCst);
    let space = cluster.space.id();
    wait_until("the evidence ends the space", || {
        anchoring.venue.status(&space) == Status::Ended
    });
    let evidence = anchoring.venue.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].1.root, root);
    // The leader alerts the evidence once the venue took it: a moment after
    // the space ended.
    wait_until("the evidence alerted", || {
        alerts(&cluster, leader).contains(&AnchorAlert::Evidence { window: 0 })
    });
    let alerts = alerts(&cluster, leader);
    assert!(
        alerts.contains(&AnchorAlert::Divergent {
            window: 0,
            replica: compromised,
            root: [9; 32],
        }),
        "{alerts:?}"
    );
}

/// Without a quorum nothing is sent and nothing settled: both other
/// replicas hold another row of window 0 than the leader's, so the leader
/// sends no evidence, alerts each by name, and asks again; once their rows
/// hold the leader's again, the evidence goes.
#[test]
fn without_a_quorum_the_guard_waits() {
    let (anchoring, cluster, representative, leader, root, offers) = overtaken();
    let others: Vec<NodeNumber> = (1..=3).filter(|number| *number != leader).collect();
    for number in &others {
        forge_row(&cluster, *number, representative, [0xd1; 32]);
    }
    offers.read.store(true, Ordering::SeqCst);
    wait_until("the leader alerts both", || {
        let alerts = alerts(&cluster, leader);
        others.iter().all(|replica| {
            alerts.contains(&AnchorAlert::Divergent {
                window: 0,
                replica: *replica,
                root: [0xd1; 32],
            })
        })
    });
    std::thread::sleep(Duration::from_secs(3));
    assert!(offers.of(0).is_empty(), "nothing sent");
    assert!(anchoring.venue.evidence().is_empty());
    assert_eq!(anchoring.venue.status(&cluster.space.id()), Status::Active);
    for number in &others {
        forge_row(&cluster, *number, representative, root);
    }
    wait_until("the evidence goes once a quorum holds the row", || {
        anchoring.venue.status(&cluster.space.id()) == Status::Ended
    });
}

/// An equivocation ends the space: the venue holds a stolen key's root at
/// window 0, every replica holds the leader's own row, so the guard passes
/// and the leader's anchor goes as the evidence. The venue keeps both
/// roots, the space ends, and the leader alerts it stopped.
#[test]
fn an_equivocation_ends_the_space() {
    let (anchoring, cluster, _, leader, root, offers) = overtaken();
    offers.read.store(true, Ordering::SeqCst);
    let space = cluster.space.id();
    wait_until("the evidence ends the space", || {
        anchoring.venue.status(&space) == Status::Ended
    });
    let evidence = anchoring.venue.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].0.root, [9; 32]);
    assert_eq!(evidence[0].1.root, root);
    assert_eq!(evidence[0].1.signer, cluster.node(leader).id().0);
    wait_until("the leader alerts the space stopped", || {
        alerts(&cluster, leader)
            .iter()
            .any(|alert| matches!(alert, AnchorAlert::Stopped { window: 0, .. }))
    });
}

/// An unlisted leader hands off: the venue does not list the leader's
/// key, so it hands its leadership to a replica whose key it lists, which
/// anchors window 0, then window 1.
#[test]
fn an_unlisted_leader_hands_off_to_a_listed_replica() {
    let (anchoring, cluster, clock, representative) = space(3);
    let space = cluster.space.id();
    let leader = cluster.leader(representative);
    assert!(
        anchoring
            .venue
            .remove_anchor_key(&space, &cluster.node(leader).id().0)
    );
    let held = anchored(&anchoring, &cluster, &clock, 0);
    let next = cluster.leader(representative);
    assert_ne!(next, leader, "handed off");
    assert_eq!(held.signer, cluster.node(next).id().0);
    // The handoff names a listed replica; under load an election may
    // move leadership on from it to the other before the anchor.
    let listed = anchoring.venue.anchor_keys(&space);
    assert!(
        alerts(&cluster, leader).iter().any(|alert| matches!(
            alert,
            AnchorAlert::Unlisted {
                window: 0,
                code: 3,
                to: Some(to),
            } if listed.contains(&cluster.node(*to).id().0)
        )),
        "{:?}",
        alerts(&cluster, leader)
    );
    assert_eq!(
        anchored(&anchoring, &cluster, &clock, 1).signer,
        held.signer
    );
    assert_eq!(windows(&anchoring, &cluster), [0, 1]);
}

/// One handoff a window: the leader and a second replica are unlisted, and
/// the one listed replica is down, so the handoff fails; the leader hands
/// off no more within the window, and waits. Once the listed replica is
/// back and the next window has opened, it hands off again (its alert
/// raised once a leadership), and that replica anchors windows 0 and 1.
#[test]
fn one_handoff_a_window() {
    let (anchoring, mut cluster, clock, representative) = space(3);
    let space = cluster.space.id();
    let leader = cluster.leader(representative);
    let mut others = (1..=3).filter(|number| *number != leader);
    let (listed, unlisted) = (others.next().unwrap(), others.next().unwrap());
    for number in [leader, unlisted] {
        assert!(
            anchoring
                .venue
                .remove_anchor_key(&space, &cluster.node(number).id().0)
        );
    }
    cluster.stop(listed);
    close(&anchoring, &cluster, &clock, 0);
    let handed = |cluster: &Cluster| {
        alerts(cluster, leader)
            .iter()
            .filter(|alert| matches!(alert, AnchorAlert::Unlisted { to: Some(_), .. }))
            .count()
    };
    wait_until("the leader hands off", || handed(&cluster) == 1);
    wait_until("then alerts it waits", || {
        alerts(&cluster, leader).contains(&AnchorAlert::Unlisted {
            window: 0,
            code: 3,
            to: None,
        })
    });
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(handed(&cluster), 1, "once a window");
    assert_eq!(cluster.leader(representative), leader);
    assert!(windows(&anchoring, &cluster).is_empty());
    cluster.start(listed);
    cluster.caught_up(listed, representative, leader);
    let held = anchored(&anchoring, &cluster, &clock, 1);
    assert_eq!(held.signer, cluster.node(listed).id().0);
    assert_eq!(windows(&anchoring, &cluster), [0, 1]);
    assert_eq!(cluster.leader(representative), listed, "handed off again");
}

/// With no replica listed, an unlisted leader signs nothing: it closes the
/// window all the same, alerts that no replica is listed to hand off to,
/// and waits. Once its key is listed again, the window it held back is
/// anchored, then the next, both by that key.
#[test]
fn an_unlisted_leader_with_no_listed_replica_alerts_and_waits() {
    let (anchoring, cluster, clock, representative) = space(1);
    let space = cluster.space.id();
    let venue = &anchoring.venue;
    let key = cluster.node(1).id().0;
    let stranger = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    assert!(venue.add_anchor_key(&space, stranger));
    assert!(venue.remove_anchor_key(&space, &key));
    closed(&anchoring, &cluster, &clock, (1, representative), 0);
    let waits = AnchorAlert::Unlisted {
        window: 0,
        code: 3,
        to: None,
    };
    wait_until("the alert", || alerts(&cluster, 1).contains(&waits));
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

/// A delisted node's replica is refused and replaced: the controller
/// removes node 3's key and registers node 4's; node 4 replaces node 3 as
/// a replica of the representative, and node 3 is refused it back.
#[test]
fn a_delisted_nodes_replica_is_refused_and_replaced() {
    let clock = clock();
    let anchoring = Anchoring::new();
    let cluster = Cluster::founded_by(4, &[1, 2, 3], clock, anchoring.tuning());
    anchoring.register(&cluster);
    let space = cluster.space.id();
    let representative = cluster.representative(&[1, 2, 3]);
    cluster.issuer(&[1, 2]);
    assert!(
        anchoring
            .venue
            .remove_anchor_key(&space, &cluster.node(3).id().0)
    );
    assert!(
        anchoring
            .venue
            .add_anchor_key(&space, cluster.node(4).id().0)
    );
    let leader = cluster.leader(representative);
    let replicas = cluster.replace(leader, representative, &[1, 2, 3], 3, 4);
    assert_eq!(replicas, [1, 2, 4]);
    let leader = cluster.leader(representative);
    let out = [1, 2].into_iter().find(|number| *number != leader).unwrap();
    assert!(
        matches!(
            cluster.node(leader).replace(representative, out, 3),
            Err(ReplaceError::Unplaced(Unplaced::CannotRun))
        ),
        "node 3's key is not listed"
    );
    let leader = cluster.leader(representative);
    assert_ne!(
        anchored(&anchoring, &cluster, &clock, 0).signer,
        cluster.node(3).id().0
    );
    assert_ne!(leader, 3);
}

/// Anchors left waiting through a long wait survive a failover: the venue
/// lists no replica's key, so windows 0 to 2 close unsigned, past the two
/// cut roots an agent keeps, the leader alerting it has none to hand off
/// to; every replica has written their rows; the leader stops. Once the
/// venue lists the new leader's key, it anchors every one of them, then
/// window 3.
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
    assert!(alerts(&cluster, leader).iter().any(|alert| matches!(
        alert,
        AnchorAlert::Unlisted {
            window: 0,
            to: None,
            ..
        }
    )));
    rows(&cluster, representative, 2);
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
    cluster.issuer(&[1, 2, 3]);
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

/// An aged window is settled unsent: windows 0 and 1 close while the
/// leader's client has not read the roots held; by the time it has, the
/// venue's clock is past window 0's `MaxRootAge`. The leader alerts it
/// never anchors window 0, sends nothing for it, and anchors window 1.
#[test]
fn an_aged_window_is_settled_unsent() {
    let clock = clock();
    let anchoring = Anchoring::new();
    let offers = Offers::default();
    let cluster = Cluster::in_space(1, Some(clock), offers.tuning(&anchoring, false, None));
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1]);
    cluster.issuer(&[1]);
    for window in 0..2 {
        closed(&anchoring, &cluster, &clock, (1, representative), window);
    }
    rows(&cluster, representative, 1);
    let b0 = clock.boundary(0).unwrap();
    anchoring.set_venue(b0 + MAX_ROOT_AGE_MS + clock.length_ms / 2);
    offers.read.store(true, Ordering::SeqCst);
    wait_until("window 1 anchored", || windows(&anchoring, &cluster) == [1]);
    assert!(offers.of(0).is_empty(), "window 0 sent nothing");
    assert!(alerts(&cluster, 1).contains(&AnchorAlert::Never {
        window: 0,
        code: None
    }));
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
    cluster.issuer(&[1]);
    for window in 0..2 {
        closed(&anchoring, &cluster, &clock, (1, representative), window);
    }
    assert!(windows(&anchoring, &cluster).is_empty(), "unregistered");
    unread.read.store(true, Ordering::SeqCst);
    anchored(&anchoring, &cluster, &clock, 2);
    assert_eq!(windows(&anchoring, &cluster), [0, 1, 2]);
}
