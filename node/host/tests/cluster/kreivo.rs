//! The representative's anchors through the Kreivo client
//! (`vos_venue::kreivo::KreivoVenue`) over the mock of Kreivo's spaces
//! pallet, with its fee pipeline, a second an extrinsic: each node's
//! client signing as its own account, the space registered with every
//! node its authority, paired with its genesis key, the sovereign account
//! paying. Anchors land once a window, in order, while the leader never
//! waits on the chain inside its batch; a suspended space is sent nothing;
//! a key the venue refuses is tried again once a window, or once the
//! venue's listing changes.
//!
//! The windows are an hour long (`cuts::clock`); the tests move the nodes'
//! clocks and the mock chain's past each window's close, `B_w + D`.

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vos_node::Config;
use vos_venue::kreivo::mock::transport::MockChain;
use vos_venue::kreivo::mock::types::{AuthorityInfo, SpaceInfo, SpaceStatus};
use vos_venue::kreivo::mock::{Account, Chain, Constants, Origin, keys};
use vos_venue::kreivo::{KreivoVenue, Options};
use vos_venue::vos_statement::{Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, NotAccepted, Status, VenueClient};
use vos_wire::ids::AgentId;
use vos_wire::keys as wire_keys;
use vos_wire::peer::NodeNumber;
use vos_wire::vos_anchor::{Anchor, RootRead, SpaceId, VenueId, WindowClock};

use crate::common::{Cluster, wait_until};
use crate::cuts::{clock, set_clock};
use crate::representative::delay;

const UNITS: u128 = 1_000_000_000_000;
const VENUE: VenueId = VenueId([0x6b; 32]);
const CONTROLLER: [u8; 32] = [0xc0; 32];

/// A node's client, as the leader reaches it: every anchor timed, and a
/// listing of anchor keys the test may lead with.
struct Watched {
    inner: KreivoVenue,
    anchors: AtomicUsize,
    /// The slowest anchor's answer, in microseconds.
    slowest: AtomicU64,
    extra: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl VenueClient for Watched {
    fn id(&self) -> VenueId {
        self.inner.id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        let start = Instant::now();
        let answer = self.inner.anchor(anchor);
        let took = start.elapsed().as_micros() as u64;
        self.slowest.fetch_max(took, Ordering::SeqCst);
        self.anchors.fetch_add(1, Ordering::SeqCst);
        answer
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        self.inner.submit(statement, proof)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.inner.anchored(root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        let mut keys = self.extra.lock().unwrap().clone();
        keys.extend(self.inner.anchor_keys(space));
        keys
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.inner.status(space)
    }

    fn time(&self) -> Option<u64> {
        self.inner.time()
    }

    fn unsettled(&self, space: &SpaceId) -> Vec<u64> {
        self.inner.unsettled(space)
    }
}

/// A node's client: its number, its account, the client.
type Client = (NodeNumber, [u8; 32], Arc<Watched>);

/// Node `number`'s Kreivo account: the mock's signer.
fn account_of(number: NodeNumber) -> [u8; 32] {
    vos_wire::vos_anchor::blake2b_256(&[b"test account", &[number]])
}

/// The mock Kreivo the space anchors at, timed by its own clock, which the
/// tests move with the nodes'; each node's client, by number.
struct Kreivo {
    chain: Arc<MockChain>,
    offset: Arc<AtomicI64>,
    clients: Arc<Mutex<Vec<Client>>>,
    extra: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl Kreivo {
    fn new() -> Self {
        let offset = Arc::new(AtomicI64::new(0));
        let read = Arc::clone(&offset);
        let now = Arc::new(move || {
            vos_node::wall_clock().saturating_add_signed(read.load(Ordering::SeqCst))
        });
        let chain = Chain::new(Constants::kreivo(VENUE)).with_fees(true);
        let chain = MockChain::with_clock(chain, Some(now));
        chain.set_latency(Duration::from_secs(1));
        Self {
            chain,
            offset,
            clients: Arc::default(),
            extra: Arc::default(),
        }
    }

    /// Each node's config: its client, signing as its account, made once
    /// per node however many configs are made for it.
    fn tuning(&self) -> impl Fn(NodeNumber, &mut Config) + Send + Sync + 'static {
        let (chain, clients, extra) = (
            Arc::clone(&self.chain),
            Arc::clone(&self.clients),
            Arc::clone(&self.extra),
        );
        move |number, config| {
            let space =
                vos_wire::vos_anchor::space_id(config.space.as_ref().unwrap().genesis().unwrap());
            let mut clients = clients.lock().unwrap();
            let made = clients
                .iter()
                .find(|(of, ..)| *of == number)
                .map(|(.., client)| Arc::clone(client));
            let client = made.unwrap_or_else(|| {
                let account = account_of(number);
                let options = Options {
                    refresh: Duration::from_millis(50),
                    backoff: Duration::from_millis(10),
                    ..Options::default()
                };
                let transport = chain.transport(Origin::Signed(account));
                let watched = Arc::new(Watched {
                    inner: KreivoVenue::over(transport, &[space], space, options),
                    anchors: AtomicUsize::new(0),
                    slowest: AtomicU64::new(0),
                    extra: Arc::clone(&extra),
                });
                clients.push((number, account, Arc::clone(&watched)));
                watched
            });
            config.venue = Some(client as Arc<dyn VenueClient>);
        }
    }

    /// The cluster's space registered from window 0, as `register` and the
    /// controller's `add_authority` leave it: each node's account an
    /// authority paired with its genesis key, the sovereign funded.
    fn register(&self, cluster: &Cluster) {
        let genesis = cluster.space.genesis().unwrap();
        let space = cluster.space.id().0;
        let clients = self.clients.lock().unwrap().clone();
        self.chain.with(|chain| {
            let constants = chain.constants.clone();
            let sovereign = constants.sovereign(&space);
            let info = SpaceInfo {
                sovereign,
                controller: CONTROLLER,
                origin_ms: genesis.clock.origin_ms,
                length_ms: genesis.clock.length_ms,
                start_window: 0,
                end_window: None,
                status: SpaceStatus::Active,
                authorities: clients.len() as u8,
                anchor_keys: genesis.nodes.len() as u8,
                registered_ms: 0,
                max_spend_per_window: constants.default_spend_per_window,
            };
            chain.set_storage(keys::spaces(&space), scale(&info));
            chain.set_storage(keys::sovereign_of(&sovereign), scale(&space));
            chain.set_account(
                sovereign,
                Account {
                    free: 1_000 * UNITS,
                    held_registration: constants.registration_deposit,
                    providers: 1,
                    ..Account::default()
                },
            );
            for (number, key) in &genesis.nodes {
                let account = clients
                    .iter()
                    .find(|(of, ..)| of == number)
                    .map(|(_, account, _)| *account);
                chain.set_storage(keys::anchor_keys(&space, key), scale(&account));
                if let Some(account) = account {
                    let paired = AuthorityInfo {
                        anchor_key: Some(*key),
                    };
                    chain.set_storage(keys::authorities(&space, &account), scale(&paired));
                    chain.set_account(
                        account,
                        Account {
                            providers: 1,
                            ..Account::default()
                        },
                    );
                }
            }
        });
        wait_until("every client reads the space", || {
            clients
                .iter()
                .all(|(_, _, client)| client.status(&cluster.space.id()) == Status::Active)
        });
    }

    fn set_status(&self, cluster: &Cluster, status: SpaceStatus) {
        let key = keys::spaces(&cluster.space.id().0);
        self.chain.with(|chain| {
            let mut info: SpaceInfo = unscale(&chain.storage()[&key]);
            info.status = status;
            chain.set_storage(key, scale(&info));
        });
    }

    /// Every node's clock and the chain's set to read `at` about now.
    fn set_clocks(&self, cluster: &Cluster, at: u64) {
        for number in 1..=cluster.offsets.len() as NodeNumber {
            set_clock(cluster, number, at);
        }
        self.offset
            .store(at as i64 - vos_node::wall_clock() as i64, Ordering::SeqCst);
    }

    /// The windows of the anchors the chain holds, from its storage.
    fn holds(&self, cluster: &Cluster, window: u64) -> bool {
        let key = keys::anchors(&cluster.space.id().0, 0, window);
        self.chain.with(|chain| chain.storage().contains_key(&key))
    }

    /// The windows of the anchor calls the nodes sent, in order, included
    /// or not.
    fn sent(&self) -> Vec<u64> {
        windows(&self.chain.sends())
    }

    /// The windows of the anchor calls the chain included, in order.
    fn included(&self) -> Vec<u64> {
        windows(&self.chain.included())
    }

    fn anchor_calls(&self) -> usize {
        let clients = self.clients.lock().unwrap();
        clients
            .iter()
            .map(|(_, _, client)| client.anchors.load(Ordering::SeqCst))
            .sum()
    }

    /// The slowest answer any node's client gave an anchor.
    fn slowest(&self) -> Duration {
        let clients = self.clients.lock().unwrap();
        let micros = clients
            .iter()
            .map(|(_, _, client)| client.slowest.load(Ordering::SeqCst))
            .max()
            .unwrap_or(0);
        Duration::from_micros(micros)
    }
}

fn scale<T: parity_scale_codec::Encode>(value: &T) -> Vec<u8> {
    value.encode()
}

fn unscale<T: parity_scale_codec::Decode>(bytes: &[u8]) -> T {
    T::decode(&mut &bytes[..]).unwrap()
}

/// The windows of the anchor calls among `calls`, in order.
fn windows(calls: &[(Origin, Vec<u8>)]) -> Vec<u64> {
    calls
        .iter()
        .filter(|(_, call)| call[..2] == [90, 7])
        .map(|(_, call)| u64::from_le_bytes(call[34..42].try_into().unwrap()))
        .collect()
}

/// A space of three nodes anchoring at the mock, registered there, its
/// representative on every node.
fn space() -> (Kreivo, Cluster, WindowClock, AgentId) {
    let clock = clock();
    let kreivo = Kreivo::new();
    let cluster = Cluster::in_space(3, Some(clock), kreivo.tuning());
    kreivo.register(&cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    (kreivo, cluster, clock, representative)
}

/// Set the clocks past `window`'s close.
fn close(kreivo: &Kreivo, cluster: &Cluster, clock: &WindowClock, window: u64) {
    kreivo.set_clocks(
        cluster,
        clock.boundary(window).unwrap() + delay(clock) + 1_000,
    );
}

/// Wait until the representative's replicas have closed `window`.
fn closed(cluster: &Cluster, representative: AgentId, window: u64) {
    wait_until(&format!("window {window} closes"), || {
        (1..=3).all(|number| {
            vos_checker::applied::<(u64, Option<AgentId>)>(
                cluster.node(number).store(),
                representative,
                &wire_keys::close_mark(),
            )
            .is_some_and(|(closed, _)| closed >= window)
        })
    });
}

/// Each window's anchor lands once, in window order, the sovereign
/// paying, while each answer the leader waits for inside its batch comes
/// well within the second the chain takes an extrinsic.
#[test]
fn anchors_land_once_a_window_and_never_hold_the_batch() {
    let (kreivo, cluster, clock, _) = space();
    for window in 0..3 {
        close(&kreivo, &cluster, &clock, window);
        wait_until(&format!("window {window} lands"), || {
            kreivo.holds(&cluster, window)
        });
    }
    assert_eq!(kreivo.included(), [0, 1, 2], "each window once, in order");
    assert_eq!(kreivo.sent(), [0, 1, 2], "nothing sent twice");
    assert!(
        kreivo.slowest() < Duration::from_millis(500),
        "an anchor's answer took {:?}",
        kreivo.slowest()
    );
}

/// A suspended space is sent no anchor: its windows close, their anchors
/// wait unsent, and land once the space is active again.
#[test]
fn a_suspended_space_is_sent_no_anchor() {
    let (kreivo, cluster, clock, representative) = space();
    close(&kreivo, &cluster, &clock, 0);
    wait_until("window 0 lands", || kreivo.holds(&cluster, 0));
    kreivo.set_status(&cluster, SpaceStatus::Suspended);
    let clients = kreivo.clients.lock().unwrap().clone();
    wait_until("every client reads the suspension", || {
        clients
            .iter()
            .all(|(_, _, client)| client.status(&cluster.space.id()) == Status::Suspended)
    });
    let calls = kreivo.anchor_calls();
    close(&kreivo, &cluster, &clock, 1);
    closed(&cluster, representative, 1);
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(kreivo.sent(), [0], "nothing sent while suspended");
    assert_eq!(kreivo.anchor_calls(), calls, "nothing handed over");
    kreivo.set_status(&cluster, SpaceStatus::Active);
    wait_until("window 1 lands once resumed", || kreivo.holds(&cluster, 1));
    assert_eq!(kreivo.included(), [0, 1]);
}

/// A key the venue refuses is tried again once a window, or once the
/// venue's listing changes: the leader's view of the listing leads with
/// the genesis keys, which the venue does not list. Its first anchor is
/// refused for the key, and not handed over again through the idle
/// leader's rechecks; a window later it is, once; and once the venue lists
/// the key, the listing changes and the window lands.
#[test]
fn a_refused_key_is_tried_once_a_window() {
    let (kreivo, cluster, clock, representative) = space();
    let space = cluster.space.id().0;
    let genesis: Vec<[u8; 32]> = cluster
        .space
        .genesis()
        .unwrap()
        .nodes
        .iter()
        .map(|(_, key)| *key)
        .collect();
    let removed: Vec<(Vec<u8>, Vec<u8>)> = kreivo.chain.with(|chain| {
        genesis
            .iter()
            .map(|key| {
                let at = keys::anchor_keys(&space, key);
                let value = chain.storage()[&at].clone();
                (at, value)
            })
            .collect()
    });
    kreivo.chain.with(|chain| {
        for (at, _) in &removed {
            chain.remove_storage(at);
        }
    });
    *kreivo.extra.lock().unwrap() = genesis.clone();
    let clients = kreivo.clients.lock().unwrap().clone();
    wait_until("every client reads the keys gone", || {
        clients
            .iter()
            .all(|(_, _, client)| client.inner.anchor_keys(&cluster.space.id()).is_empty())
    });
    close(&kreivo, &cluster, &clock, 0);
    closed(&cluster, representative, 0);
    wait_until("the key refused", || kreivo.anchor_calls() == 1);
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(kreivo.anchor_calls(), 1, "not again within the window");
    close(&kreivo, &cluster, &clock, 1);
    wait_until("tried again a window later", || kreivo.anchor_calls() == 2);
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(kreivo.anchor_calls(), 2, "once a window");
    assert!(kreivo.sent().is_empty(), "nothing sent for a refused key");
    kreivo.chain.with(|chain| {
        for (at, value) in removed {
            chain.set_storage(at, value);
        }
    });
    wait_until("windows 0 and 1 land once the key is listed", || {
        kreivo.holds(&cluster, 0) && kreivo.holds(&cluster, 1)
    });
    assert_eq!(kreivo.included(), [0, 1]);
}
