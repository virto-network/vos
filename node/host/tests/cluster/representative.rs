//! The space's representative and its anchors, on three nodes: each agent's
//! leader reports its root at a window's cut, the representative's own cut
//! at `B_w + D` closes the window, its leader anchors `S_w` at the model
//! venue and sends each agent that asked its path, and the agents' reads
//! are served and stated against `S_w`. An agent whose clock leads, an
//! agent that misses the close, the representative failing over between
//! the reports and the close, and its leader changing between its cut's
//! build and the close.
//!
//! Each space has windows of an hour (`cuts::clock`), so `D` is two
//! minutes; the tests move the nodes' clocks, and the venue's, across
//! `B_0` and `B_0 + D`.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vos_node::roots::{self, CutProof};
use vos_node::{Config, Hooks, Node};
use vos_venue::{ModelVenue, VenueClient};
use vos_wire::ids::{AgentId, RequestId};
use vos_wire::keys;
use vos_wire::peer::NodeNumber;
use vos_wire::records::{Workflow, WorkflowState};
use vos_wire::result::{Attest, InputRef, Outcome, Step};
use vos_wire::served::{ClosedRow, Served, representative_row};
use vos_wire::vos_anchor::{MIN_LENGTH_MS, RootKind, RootRead, VenueId, space_root};
use vos_wire::{Encode, WindowClock};

use crate::common::{Cluster, wait_until};
use crate::cuts::{READER, ask_keys, clock, reader_agent, results, set_clock, write};

/// The venue the space anchors at, timed by its own clock, which the
/// tests move with the nodes'.
pub(crate) struct Anchoring {
    pub(crate) venue: Arc<ModelVenue>,
    offset: Arc<AtomicI64>,
}

impl Anchoring {
    pub(crate) fn new() -> Self {
        let offset = Arc::new(AtomicI64::new(0));
        let read = Arc::clone(&offset);
        let now = Arc::new(move || {
            vos_node::wall_clock().saturating_add_signed(read.load(Ordering::SeqCst))
        });
        Self {
            venue: Arc::new(ModelVenue::new(VenueId([0x7e; 32]), now)),
            offset,
        }
    }

    /// Each node's config: anchoring at the venue.
    pub(crate) fn tuning(&self) -> impl Fn(NodeNumber, &mut Config) + Send + Sync + 'static {
        let venue: Arc<dyn VenueClient> = self.venue.clone();
        move |_, config| config.venue = Some(Arc::clone(&venue))
    }

    /// The cluster's space registered at the venue, from window 0.
    pub(crate) fn register(&self, cluster: &Cluster) {
        self.venue
            .register(cluster.space.genesis().expect("a genesis"), 0);
    }

    /// Every node's clock and the venue's set to read `at` about now.
    pub(crate) fn set_clocks(&self, cluster: &Cluster, at: u64) {
        for number in 1..=cluster.offsets.len() as NodeNumber {
            set_clock(cluster, number, at);
        }
        self.set_venue(at);
    }

    /// The venue's clock set to read `at` about now.
    pub(crate) fn set_venue(&self, at: u64) {
        self.offset
            .store(at as i64 - vos_node::wall_clock() as i64, Ordering::SeqCst);
    }
}

/// The representative's delay `D` on `clock`.
pub(crate) fn delay(clock: &WindowClock) -> u64 {
    clock.representative().unwrap().origin_ms - clock.origin_ms
}

/// The representative's root at its cut of `window`, once every running
/// replica of it has built that cut: the same on each.
pub(crate) fn rep_root(cluster: &Cluster, representative: AgentId, window: u64) -> [u8; 32] {
    let mut root = None;
    wait_until("every replica of the representative builds its cut", || {
        let built: Vec<_> = cluster
            .running()
            .filter(|(_, node)| node.applied(representative).is_some())
            .map(|(_, node)| {
                roots::cut_root(&node.store().snapshot(), representative, window).unwrap()
            })
            .collect();
        let all = built.iter().all(Option::is_some) && !built.is_empty();
        if all {
            assert!(
                built.windows(2).all(|pair| pair[0] == pair[1]),
                "the replicas' roots at the cut differ: {built:?}"
            );
            root = built[0].map(|(root, _)| root);
        }
        all
    });
    root.unwrap()
}

/// The space's root of `window` over the representative's `rep_root`.
fn stated(cluster: &Cluster, window: u64, rep_root: &[u8; 32]) -> RootRead {
    let space = cluster.space.id();
    RootRead {
        kind: RootKind::Space,
        space,
        window,
        root: space_root(&space, window, rep_root),
    }
}

/// How workflow `id` of `agent` ended, once it has, on a replica of it.
fn ended(cluster: &Cluster, agent: AgentId, id: RequestId) -> Outcome {
    let mut ended = None;
    wait_until("the read is served and its workflow ends", || {
        ended = cluster
            .running()
            .filter(|(_, node)| node.applied(agent).is_some())
            .find_map(|(_, node)| {
                let record: Workflow =
                    vos_checker::applied(node.store(), agent, &keys::workflow(id.workflow))?;
                match record.state {
                    WorkflowState::Ended(outcome) => Some(outcome),
                    _ => None,
                }
            });
        ended.is_some()
    });
    ended.unwrap()
}

/// The attests of the steps `request`'s `Resume`s made in `agent`'s log
/// on `node`, once its log holds one: the workflow's end, the last.
fn attests(node: &Node, agent: AgentId, request: RequestId) -> Vec<Attest> {
    let mut attests = Vec::new();
    wait_until("the replica applies the read's statement", || {
        attests = logged(node, agent, request);
        !attests.is_empty()
    });
    attests
}

/// The attests of the steps `request`'s `Resume`s made in `agent`'s log
/// on `node` so far.
fn logged(node: &Node, agent: AgentId, request: RequestId) -> Vec<Attest> {
    results(node, agent, 0)
        .into_iter()
        .flat_map(|(_, result)| result.steps)
        .filter_map(|step| match step {
            Step::Ran(run) if run.input == (InputRef::Resume { request }) => Some(run.attests),
            _ => None,
        })
        .flatten()
        .collect()
}

/// A node running `agent`.
fn replica(cluster: &Cluster, agent: AgentId) -> &Node {
    cluster
        .running()
        .find(|(_, node)| node.applied(agent).is_some())
        .map(|(_, node)| node)
        .expect("a replica")
}

/// Whether `representative`'s replica on `node` holds `agent`'s root at
/// `window`'s cut.
fn holds(node: &Node, representative: AgentId, agent: AgentId, window: u64) -> bool {
    node.store()
        .snapshot()
        .get(
            representative,
            &representative_row(agent, RootKind::Space, window),
        )
        .unwrap()
        .is_some()
}

/// Every agent reports, and each read is served at one close. Three
/// agents on three nodes each ask to read at window 0; past `B_0` each
/// reports its root to the representative, which holds the three; past
/// `B_0 + D` its cut closes the window. Every replica of the
/// representative builds the same root there, `S_0` is anchored once, and
/// each read is served and stated against it, the one root.
#[test]
fn every_agent_reports_and_one_close_serves_their_reads() {
    let clock = clock();
    let b0 = clock.boundary(0).unwrap();
    let anchoring = Anchoring::new();
    let cluster = Cluster::in_space(3, Some(clock), anchoring.tuning());
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    let agents: Vec<AgentId> = (0..3).map(|_| reader_agent(&cluster, &[1, 2, 3])).collect();
    let reads: Vec<RequestId> = agents
        .iter()
        .map(|agent| {
            write(&cluster, *agent, 1..=20);
            ask_keys(&cluster, *agent, 21).0
        })
        .collect();
    anchoring.set_clocks(&cluster, b0 + 1_000);
    for agent in &agents {
        wait_until("the representative holds each agent's root", || {
            holds(replica(&cluster, representative), representative, *agent, 0)
        });
    }
    anchoring.set_clocks(&cluster, b0 + delay(&clock) + 1_000);
    let rep_root = rep_root(&cluster, representative, 0);
    let root = stated(&cluster, 0, &rep_root);
    for (agent, read) in agents.iter().zip(&reads) {
        assert!(matches!(ended(&cluster, *agent, *read), Outcome::Done(_)));
        let attests = attests(replica(&cluster, *agent), *agent, *read);
        assert_eq!(attests.len(), 1, "stated once");
        assert_eq!(attests[0].window, Some(0));
        assert_eq!(attests[0].roots, [root]);
    }
    assert!(anchoring.venue.anchored(&root));
    let anchors = anchoring.venue.anchors(&cluster.space.id());
    assert_eq!(anchors.len(), 1, "{anchors:?}");
    assert_eq!((anchors[0].window, anchors[0].root), (0, root.root));
    assert!(anchoring.venue.evidence().is_empty());
}

/// An agent whose clock leads the representative's by more than `L − D`
/// cuts window 1 and reports it before the representative closes window
/// 0: its window-1 root is a row of its own, so its window-0 row stays in
/// `A_rep(0)` and `S_0` holds it as it was. Its read of window 0, re-cut at
/// window 1 by that cut before the close came, is served at window 0 all
/// the same once the close comes, stated against `S_0`, which the venue
/// holds anchored.
#[test]
fn a_leading_clock_reports_its_next_window_apart() {
    let clock = clock();
    let b0 = clock.boundary(0).unwrap();
    let length = clock.length_ms;
    let d = delay(&clock);
    let anchoring = Anchoring::new();
    let cluster = Cluster::in_space(3, Some(clock), anchoring.tuning());
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1, 2]);
    let agent = reader_agent(&cluster, &[3]);
    write(&cluster, agent, 1..=20);
    let (read, ..) = ask_keys(&cluster, agent, 21);
    anchoring.set_clocks(&cluster, b0 + 1_000);
    let rep = || replica(&cluster, representative);
    wait_until("the representative holds window 0's root", || {
        holds(rep(), representative, agent, 0)
    });
    // Node 3 leads by `L − D + 10 s`: past `B_1` while the others are before
    // `B_0 + D`.
    set_clock(&cluster, 3, b0 + d - 2_000 + length - d + 10_000);
    wait_until("the representative holds window 1's root", || {
        holds(rep(), representative, agent, 1)
    });
    let moved: Option<u64> =
        vos_checker::applied(replica(&cluster, agent).store(), agent, &keys::moved(0));
    assert_eq!(moved, Some(1), "re-cut before the close");
    assert!(
        holds(rep(), representative, agent, 0),
        "its window-0 row kept"
    );
    for number in [1, 2] {
        set_clock(&cluster, number, b0 + d + 1_000);
    }
    anchoring.set_venue(b0 + d + 1_000);
    let rep_root = rep_root(&cluster, representative, 0);
    assert!(matches!(ended(&cluster, agent, read), Outcome::Done(_)));
    let attests = attests(replica(&cluster, agent), agent, read);
    assert_eq!(attests.len(), 1);
    assert_eq!(attests[0].window, Some(0));
    let root = stated(&cluster, 0, &rep_root);
    assert_eq!(attests[0].roots, [root]);
    assert!(anchoring.venue.anchored(&root));
}

/// Holds an agent's reports of the windows a test lists, and stops the
/// representative's leader before its close of a window once.
#[derive(Default)]
struct Holds {
    reports: Mutex<BTreeSet<(AgentId, u64)>>,
    stop: Mutex<Option<(AgentId, u64)>>,
    stopped: AtomicBool,
}

impl Hooks for Holds {
    fn report(&self, agent: AgentId, window: u64) -> bool {
        !self.reports.lock().unwrap().contains(&(agent, window))
    }

    fn close(&self, agent: AgentId, window: u64) -> bool {
        if *self.stop.lock().unwrap() == Some((agent, window))
            && !self.stopped.swap(true, Ordering::SeqCst)
        {
            return false;
        }
        true
    }
}

/// An agent that misses the close: its report of window 0 held past
/// `B_0 + D`, the representative's cut of window 0 holds no row of it, so
/// no path from `S_0` reaches its root there and the kernel's prologue
/// refuses its statement at window 0, served the path of another agent's
/// row. Its read, re-cut at window 1, is served at window 1's close and
/// stated against `S_1`, which the venue holds anchored.
#[test]
fn an_agent_that_misses_the_close_is_served_at_the_next() {
    let clock = clock();
    let b0 = clock.boundary(0).unwrap();
    let length = clock.length_ms;
    let d = delay(&clock);
    let anchoring = Anchoring::new();
    let holds_hook = Arc::new(Holds::default());
    let hooks: Arc<dyn Hooks> = holds_hook.clone();
    let tuning = anchoring.tuning();
    let cluster = Cluster::in_space(3, Some(clock), move |number, config| {
        tuning(number, config);
        config.hooks = Arc::clone(&hooks);
    });
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    let (late, on_time) = (
        reader_agent(&cluster, &[1, 2, 3]),
        reader_agent(&cluster, &[1, 2, 3]),
    );
    holds_hook.reports.lock().unwrap().insert((late, 0));
    write(&cluster, late, 1..=20);
    write(&cluster, on_time, 1..=20);
    let (missed, _, keys) = ask_keys(&cluster, late, 21);
    let (served, ..) = ask_keys(&cluster, on_time, 21);
    anchoring.set_clocks(&cluster, b0 + 1_000);
    let mut proof: Option<CutProof> = None;
    wait_until("the late agent proves its read at window 0's cut", || {
        proof = roots::cut_proof(&replica(&cluster, late).store().snapshot(), late, missed)
            .unwrap()
            .filter(|proof| proof.window == 0);
        proof.is_some()
    });
    let proof = proof.unwrap();
    wait_until("the representative holds the on-time agent's root", || {
        holds(
            replica(&cluster, representative),
            representative,
            on_time,
            0,
        )
    });
    anchoring.set_clocks(&cluster, b0 + d + 1_000);
    let rep_root_0 = rep_root(&cluster, representative, 0);
    assert!(matches!(ended(&cluster, on_time, served), Outcome::Done(_)));
    let rep = replica(&cluster, representative);
    assert!(
        !holds(rep, representative, late, 0),
        "no row of the late agent"
    );
    holds_hook.reports.lock().unwrap().clear();

    // Its statement at window 0, with the path the on-time agent holds.
    let closed: ClosedRow = vos_checker::applied(
        replica(&cluster, on_time).store(),
        on_time,
        &keys::closed(0),
    )
    .expect("the on-time agent's close");
    assert_eq!(closed.rep_root, rep_root_0);
    let witness = Served {
        space: cluster.space.id(),
        window: 0,
        agent: late,
        instance: READER,
        agent_root: proof.agent_root,
        rep_root: closed.rep_root,
        rep_salt: closed.rep_salt,
        space_path: closed.space_path,
        rows: proof.rows.clone(),
        rows_proof: proof.rows_proof.clone(),
    };
    let derived = vos_checker::programs::derived("reader");
    let method = vos_checker::programs::method(&derived.actor, "sum_entries");
    let kernel = derived
        .kernels
        .iter()
        .find(|(id, _)| *id == method.0)
        .map(|(_, kernel)| kernel.clone())
        .unwrap();
    let input = [keys.encode(), witness.encode()].concat();
    assert_eq!(
        vos_testkit::run_kernel(&kernel, &input, 1 << 32).err(),
        Some(vos_wire::abi::Failure::Trapped),
        "the prologue refuses it at window 0"
    );

    anchoring.set_clocks(&cluster, b0 + length + 1_000);
    wait_until("the late read re-cut at window 1", || {
        vos_checker::applied::<u64>(replica(&cluster, late).store(), late, &keys::moved(0))
            == Some(1)
    });
    wait_until(
        "the representative holds the late agent's window-1 root",
        || holds(replica(&cluster, representative), representative, late, 1),
    );
    anchoring.set_clocks(&cluster, b0 + length + d + 1_000);
    let rep_root_1 = rep_root(&cluster, representative, 1);
    assert!(matches!(ended(&cluster, late, missed), Outcome::Done(_)));
    let attests = attests(replica(&cluster, late), late, missed);
    assert_eq!(attests.len(), 1);
    assert_eq!(attests[0].window, Some(1));
    let root = stated(&cluster, 1, &rep_root_1);
    assert_eq!(attests[0].roots, [root]);
    assert!(anchoring.venue.anchored(&root));
    assert!(anchoring.venue.evidence().is_empty());
}

/// The representative fails over between the agents' reports and its
/// close: its leader stops after it applied the reports, before `B_0 + D`.
/// The new leader's cut closes window 0 at the same root on every replica,
/// the stopped one too once back; `S_0` is anchored once, with no second
/// root, and the agent's read is served against it.
#[test]
fn a_representative_failover_keeps_one_root() {
    let clock = clock();
    let b0 = clock.boundary(0).unwrap();
    let anchoring = Anchoring::new();
    let mut cluster = Cluster::in_space(3, Some(clock), anchoring.tuning());
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    let agent = reader_agent(&cluster, &[1, 2, 3]);
    write(&cluster, agent, 1..=20);
    let (read, ..) = ask_keys(&cluster, agent, 21);
    anchoring.set_clocks(&cluster, b0 + 1_000);
    let old = cluster.leader(representative);
    wait_until(
        "every replica of the representative holds the report",
        || {
            cluster
                .running()
                .all(|(_, node)| holds(node, representative, agent, 0))
        },
    );
    cluster.stop(old);
    let new = cluster.leader(representative);
    assert_ne!(new, old);
    anchoring.set_clocks(&cluster, b0 + delay(&clock) + 1_000);
    let rep_root = rep_root(&cluster, representative, 0);
    assert!(matches!(ended(&cluster, agent, read), Outcome::Done(_)));
    cluster.start(old);
    let back = cluster.node(old);
    wait_until("the old leader builds the cut", || {
        roots::cut_root(&back.store().snapshot(), representative, 0)
            .unwrap()
            .is_some()
    });
    assert_eq!(
        roots::cut_root(&back.store().snapshot(), representative, 0)
            .unwrap()
            .map(|(root, _)| root),
        Some(rep_root)
    );
    let root = stated(&cluster, 0, &rep_root);
    let anchors = anchoring.venue.anchors(&cluster.space.id());
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].root, root.root);
    assert!(anchoring.venue.evidence().is_empty());
    assert_eq!(
        attests(replica(&cluster, agent), agent, read)[0].roots,
        [root]
    );
}

/// The representative's leader changes between its cut's build and the
/// close: its leader anchors `S_0`, then a hook stops it before it sends
/// the close. The new leader anchors the same root again, which the venue
/// takes as a repeat, and sends the close once: the agent applies one
/// `Closed`, and its read resumes once, stated against `S_0`.
#[test]
fn a_representative_leader_change_before_the_close_sends_it_once() {
    let clock = clock();
    let b0 = clock.boundary(0).unwrap();
    let anchoring = Anchoring::new();
    let holds_hook = Arc::new(Holds::default());
    let hooks: Arc<dyn Hooks> = holds_hook.clone();
    let tuning = anchoring.tuning();
    let cluster = Cluster::in_space(3, Some(clock), move |number, config| {
        tuning(number, config);
        config.hooks = Arc::clone(&hooks);
    });
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    *holds_hook.stop.lock().unwrap() = Some((representative, 0));
    let agent = reader_agent(&cluster, &[1, 2, 3]);
    write(&cluster, agent, 1..=20);
    let (read, ..) = ask_keys(&cluster, agent, 21);
    anchoring.set_clocks(&cluster, b0 + 1_000);
    wait_until("the representative holds the report", || {
        holds(replica(&cluster, representative), representative, agent, 0)
    });
    let old = cluster.leader(representative);
    anchoring.set_clocks(&cluster, b0 + delay(&clock) + 1_000);
    let rep_root = rep_root(&cluster, representative, 0);
    assert!(matches!(ended(&cluster, agent, read), Outcome::Done(_)));
    assert!(
        holds_hook.stopped.load(Ordering::SeqCst),
        "the hook stopped a leader"
    );
    assert_ne!(cluster.leader(representative), old, "the leader changed");
    let root = stated(&cluster, 0, &rep_root);
    let node = replica(&cluster, agent);
    let attests = attests(node, agent, read);
    assert_eq!(attests.len(), 1, "resumed once");
    assert_eq!(attests[0].roots, [root]);
    let sent: Option<u64> = vos_checker::applied(
        replica(&cluster, representative).store(),
        representative,
        &keys::pair_out(agent),
    );
    assert_eq!(sent, Some(1), "one close sent the agent");
    let anchors = anchoring.venue.anchors(&cluster.space.id());
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].root, root.root);
    assert!(anchoring.venue.evidence().is_empty());
}

/// The latency of a read at a cut, at windows of two minutes (`L`), so
/// `D` is 24 s: the nodes' clocks and the venue's run on from two seconds
/// before `B_0`, past the agent's cut and report and the representative's
/// close at `B_0 + D`, and the read's `Attest`, stated against `S_0`, is in
/// the agent's log, and `S_0` anchored at the venue, each within
/// `D + 30 s` of `B_0`, a loaded host's lag included. A read asked at any
/// time in window 0 is then stated within `L + D + 30 s` of its asking.
#[test]
fn a_read_is_stated_within_a_window_and_its_close() {
    let clock = WindowClock {
        origin_ms: vos_node::wall_clock() - 60_000,
        length_ms: MIN_LENGTH_MS,
    };
    let b0 = clock.boundary(0).unwrap();
    let d = delay(&clock);
    assert_eq!(d, 24_000);
    let anchoring = Anchoring::new();
    let cluster = Cluster::in_space(3, Some(clock), anchoring.tuning());
    // Early in window 0 while the test sets up, which a loaded host may
    // take a minute or more for: its read must start before `B_0`.
    anchoring.set_clocks(&cluster, clock.origin_ms + 1_000);
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    let agent = reader_agent(&cluster, &[1, 2, 3]);
    write(&cluster, agent, 1..=20);
    let (read, ..) = ask_keys(&cluster, agent, 21);
    let space = cluster.space.id();
    anchoring.set_clocks(&cluster, b0 - 2_000);
    let boundary = Instant::now() + Duration::from_secs(2);
    let bound = Duration::from_millis(d + 30_000);
    let (mut attested, mut anchored) = (None, None);
    while (attested.is_none() || anchored.is_none())
        && Instant::now() < boundary + bound + Duration::from_secs(20)
    {
        if attested.is_none() && !logged(replica(&cluster, agent), agent, read).is_empty() {
            attested = Some(Instant::now());
        }
        if anchored.is_none() && !anchoring.venue.anchors(&space).is_empty() {
            anchored = Some(Instant::now());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let since = |at: Option<Instant>, what: &str| {
        at.unwrap_or_else(|| panic!("{what} never came"))
            .saturating_duration_since(boundary)
    };
    let (to_attest, to_anchor) = (since(attested, "the attest"), since(anchored, "the anchor"));
    eprintln!(
        "from B_0: the anchor in {:.2}s, the attest in {:.2}s (D {:.0}s, the bound {:.0}s)",
        to_anchor.as_secs_f64(),
        to_attest.as_secs_f64(),
        d as f64 / 1e3,
        bound.as_secs_f64()
    );
    assert!(to_attest <= bound, "{to_attest:?}");
    assert!(to_anchor <= bound, "{to_anchor:?}");
    let rep_root = rep_root(&cluster, representative, 0);
    let root = stated(&cluster, 0, &rep_root);
    assert_eq!(
        attests(replica(&cluster, agent), agent, read)[0].roots,
        [root]
    );
    assert!(anchoring.venue.anchored(&root));
}
