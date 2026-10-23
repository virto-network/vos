//! [`KreivoVenue`] over the mock: an anchor taken at once and sent in the
//! background; an open window, `WindowInFuture`, a suspension and a pause
//! sending nothing until they pass; the budget's refusal and a short
//! sovereign account alerting; a lost answer and a dropped send never
//! sending a call twice; statements judged through the client; every
//! pallet error mapped; and the production build refusing Kreivo.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use parity_scale_codec::Encode;
use vos_anchor::{
    Anchor, MIN_LENGTH_MS, RootKind, RootRead, SpaceGenesis, SpaceId, VenueId, WindowClock,
};

use super::calls::{self, Call, Error, Event, Failure, PALLET, SpaceInfo, SpaceStatus, keys};
use super::conformance::Fixtures;
use super::conformance::scenarios::{AUTHORITY_F, F, g7_chain};
use super::mock::transport::{Fault, MockChain};
use super::mock::{Account, Chain, Constants, Origin};
use super::transport::{Included, Lost, SendError, Sent, Signed, Transport};
use super::venue::{Answer, answer, judged};
use super::{Alert, KreivoVenue, Options, Sender};
use crate::{AnchorRefusal, Anchored, NotAccepted, Status, Unjudged, VenueClient};

const UNITS: u128 = 1_000_000_000_000;
const VENUE: VenueId = VenueId([0x7e; 32]);
const NODE: [u8; 32] = [0x11; 32];
const OPERATOR: [u8; 32] = [0x0a; 32];
const CONTROLLER: [u8; 32] = [0xc0; 32];
const CLOCK: WindowClock = WindowClock {
    origin_ms: 1_000_000,
    length_ms: MIN_LENGTH_MS,
};

/// A while in which the worker, had it been going to send, would have:
/// ten of its reads.
const A_WHILE: Duration = Duration::from_millis(200);

/// Wait until `venue` has read the chain twice more: it has seen a
/// change made before.
fn read_again(venue: &KreivoVenue) {
    let reads = venue.reads();
    wait_until("the client reads the chain again", || {
        venue.reads() >= reads + 2
    });
}

fn options() -> Options {
    Options {
        refresh: Duration::from_millis(20),
        backoff: Duration::from_millis(5),
        block_ms: 1_000,
        ..Options::default()
    }
}

/// Wait until `done`, a few seconds at most.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(10), "{what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A space of one founding key registered at the mock from window 2, the
/// node its authority paired with that key, the chain's time at the
/// boundary of window 5 (window 6 open).
struct Setup {
    chain: Arc<MockChain>,
    now: Arc<AtomicU64>,
    space: SpaceId,
    key: SigningKey,
}

impl Setup {
    fn new(fees: bool) -> Self {
        let key = SigningKey::from_bytes(&[1; 32]);
        let genesis = SpaceGenesis {
            version: vos_anchor::GENESIS_VERSION,
            nodes: vec![(1, key.verifying_key().to_bytes())],
            clock: CLOCK,
            time: 7,
            nonce: [3; 16],
        };
        let space = vos_anchor::space_id(&genesis);
        let mut chain = Chain::new(Constants::kreivo(VENUE)).with_fees(fees);
        let funded = Account {
            free: 100 * UNITS,
            providers: 1,
            ..Account::default()
        };
        for who in [OPERATOR, CONTROLLER, calls::sovereign(&space)] {
            chain.set_account(who, funded);
        }
        let now = Arc::new(AtomicU64::new(CLOCK.boundary(5).unwrap() + 10));
        let read = Arc::clone(&now);
        let clock = Arc::new(move || read.load(Ordering::SeqCst));
        let setup = Self {
            chain: MockChain::with_clock(chain, Some(clock)),
            now,
            space,
            key,
        };
        let digest = vos_anchor::register_digest(&VENUE, &space, &CONTROLLER, 2);
        setup.call(
            OPERATOR,
            Call::Register {
                genesis: genesis.encode(),
                controller: CONTROLLER,
                start_window: 2,
                founder_key: setup.key.verifying_key().to_bytes(),
                founder_sig: setup.key.sign(&digest).to_bytes(),
            },
        );
        setup.call(
            CONTROLLER,
            Call::AddAuthority {
                space: space.0,
                who: NODE,
                anchor_key: Some(setup.key.verifying_key().to_bytes()),
            },
        );
        setup
    }

    /// `call` sent by `who` through the client, Ok.
    fn call(&self, who: [u8; 32], call: Call) {
        let sender = Sender::new(self.chain.transport(Origin::Signed(who)), Duration::ZERO);
        match sender.call(&call.bytes()) {
            Ok(Sent::Included(outcome)) => assert_eq!(outcome.failure, None, "{call:?}"),
            other => panic!("{call:?}: {other:?}"),
        }
    }

    fn venue(&self) -> KreivoVenue {
        self.venue_over(self.chain.transport(Origin::Signed(NODE)))
    }

    fn venue_over(&self, transport: Arc<dyn Transport>) -> KreivoVenue {
        KreivoVenue::over(transport, &[self.space], self.space, options())
    }

    /// The space's root of `window`, signed by its key.
    fn anchor(&self, window: u64, root: u8) -> Anchor {
        let mut anchor = Anchor {
            space: self.space,
            window,
            kind: RootKind::Space,
            root: [root; 32],
            signer: self.key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        anchor.signature = self.key.sign(&anchor.digest(&VENUE)).to_bytes();
        anchor
    }

    fn set_now(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }

    /// The node's anchor calls the chain was sent, included or not.
    fn anchors_sent(&self) -> usize {
        self.chain
            .sends()
            .iter()
            .filter(|(origin, call)| *origin == Origin::Signed(NODE) && call[..2] == [PALLET, 7])
            .count()
    }

    fn anchored_window(&self, window: u64) -> bool {
        self.chain.with(|chain| {
            chain
                .storage()
                .contains_key(&keys::anchors(&self.space.0, 0, window))
        })
    }

    /// Set the space's status in the chain's storage, as an equivocation or
    /// a resumption leaves it.
    fn set_status(&self, status: SpaceStatus) {
        self.chain.with(|chain| {
            let key = keys::spaces(&self.space.0);
            let mut info: SpaceInfo = calls::read(&chain.storage()[&key]).unwrap();
            info.status = status;
            chain.set_storage(key, info.encode());
        });
    }
}

/// An anchor is taken at once while the chain takes its time, lands in
/// the background, and is then held; its window again is `Again`, the
/// open window `Open`.
#[test]
fn an_anchor_is_taken_at_once_and_lands() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    assert_eq!(venue.status(&setup.space), Status::Active);
    assert_eq!(
        venue.anchor_keys(&setup.space),
        [setup.key.verifying_key().to_bytes()]
    );
    setup.chain.set_latency(Duration::from_millis(300));
    let start = Instant::now();
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    assert!(start.elapsed() < Duration::from_millis(100), "no wait");
    wait_until("window 5 lands", || setup.anchored_window(5));
    wait_until("the queue empties", || venue.queued() == 0);
    assert_eq!(setup.anchors_sent(), 1);
    let read = RootRead {
        kind: RootKind::Space,
        space: setup.space,
        window: 5,
        root: [1; 32],
    };
    assert!(venue.anchored(&read));
    assert!(!venue.anchored(&RootRead {
        root: [2; 32],
        ..read
    }));
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Again));
    assert_eq!(
        venue.anchor(&setup.anchor(5, 2)),
        Err(AnchorRefusal::Window)
    );
    assert_eq!(venue.anchor(&setup.anchor(6, 1)), Err(AnchorRefusal::Open));
    assert_eq!(setup.anchors_sent(), 1);
    assert!(venue.alerts().is_empty(), "{:?}", venue.alerts());
}

/// An anchor for the venue's open window is not taken; once the venue's
/// time passes the window's boundary, it is, and lands.
#[test]
fn an_open_window_is_anchored_once_the_venue_closes_it() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    assert_eq!(venue.anchor(&setup.anchor(6, 1)), Err(AnchorRefusal::Open));
    setup.set_now(CLOCK.boundary(6).unwrap() + 1);
    wait_until("the venue's time is read again", || {
        venue.anchor(&setup.anchor(6, 1)) == Ok(Anchored::Queued)
    });
    wait_until("window 6 lands", || setup.anchored_window(6));
    assert_eq!(setup.anchors_sent(), 1);
}

/// A transport whose chain's clock lags: the first anchor it sends is
/// refused `WindowInFuture` without reaching the chain.
struct Lagging {
    inner: Arc<dyn Transport>,
    refused: AtomicUsize,
}

impl Transport for Lagging {
    fn account(&self) -> [u8; 32] {
        self.inner.account()
    }
    fn genesis(&self) -> Result<[u8; 32], Lost> {
        self.inner.genesis()
    }
    fn best(&self) -> Result<u64, Lost> {
        self.inner.best()
    }
    fn nonce(&self) -> Result<u64, Lost> {
        self.inner.nonce()
    }
    fn chain_nonce(&self) -> Result<u64, Lost> {
        self.inner.chain_nonce()
    }
    fn sign(&self, call: &[u8], nonce: u64) -> Result<Signed, SendError> {
        self.inner.sign(call, nonce)
    }
    fn send(&self, signed: &Signed) -> Result<Included, SendError> {
        if self.refused.fetch_add(1, Ordering::SeqCst) == 0 {
            let error = Error::WindowInFuture as u8;
            return Ok(Included {
                block: 0,
                events: Vec::new(),
                failure: Some(
                    Failure::Module {
                        pallet: PALLET,
                        error,
                    }
                    .encode(),
                ),
            });
        }
        self.inner.send(signed)
    }
    fn storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Lost> {
        self.inner.storage(key)
    }
    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Lost> {
        self.inner.keys(prefix)
    }
}

/// `WindowInFuture`: the anchor waits until the venue's time passes the
/// window's boundary by a block, then goes again and lands; never
/// skipped.
#[test]
fn window_in_future_waits_a_block_and_sends_again() {
    let setup = Setup::new(true);
    let lagging = Arc::new(Lagging {
        inner: setup.chain.transport(Origin::Signed(NODE)),
        refused: AtomicUsize::new(0),
    });
    let venue = setup.venue_over(lagging.clone());
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    wait_until("the venue refuses it once", || {
        lagging.refused.load(Ordering::SeqCst) == 1
    });
    read_again(&venue);
    assert_eq!(lagging.refused.load(Ordering::SeqCst), 1, "it waits");
    assert_eq!(venue.queued(), 1, "it is kept");
    setup.set_now(CLOCK.boundary(5).unwrap() + 1_001);
    wait_until("window 5 lands", || setup.anchored_window(5));
    assert_eq!(lagging.refused.load(Ordering::SeqCst), 2);
    assert!(venue.alerts().is_empty(), "{:?}", venue.alerts());
}

/// A suspended space is sent nothing: its anchors are refused at once,
/// and an anchor queued before a block waits until it is active again.
#[test]
fn a_suspended_space_is_sent_nothing() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    setup.set_status(SpaceStatus::Suspended);
    wait_until("the suspension is read", || {
        venue.status(&setup.space) == Status::Suspended
    });
    assert!(venue.status(&setup.space).waits());
    assert_eq!(
        venue.anchor(&setup.anchor(5, 1)),
        Err(AnchorRefusal::Suspended)
    );
    setup.set_status(SpaceStatus::Active);
    wait_until("the resumption is read", || {
        venue.status(&setup.space) == Status::Active
    });
    setup
        .chain
        .with(|chain| chain.set_storage(keys::paused(), vec![2]));
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    setup.set_status(SpaceStatus::Blocked);
    wait_until("the block is read", || {
        venue.status(&setup.space) == Status::Blocked
    });
    setup
        .chain
        .with(|chain| chain.set_storage(keys::paused(), vec![0]));
    read_again(&venue);
    std::thread::sleep(A_WHILE);
    assert_eq!(setup.anchors_sent(), 0, "nothing sent while blocked");
    assert_eq!(venue.queued(), 1, "kept");
    setup.set_status(SpaceStatus::Active);
    wait_until("window 5 lands", || setup.anchored_window(5));
    assert_eq!(setup.anchors_sent(), 1);
}

/// Paused anchors are not sent until the pause lifts.
#[test]
fn a_paused_venue_is_sent_no_anchor() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    setup
        .chain
        .with(|chain| chain.set_storage(keys::paused(), vec![2]));
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    read_again(&venue);
    std::thread::sleep(A_WHILE);
    assert_eq!(setup.anchors_sent(), 0);
    setup
        .chain
        .with(|chain| chain.set_storage(keys::paused(), vec![0]));
    wait_until("window 5 lands", || setup.anchored_window(5));
    assert_eq!(setup.anchors_sent(), 1);
}

/// The budget spent: the venue refuses the anchor's fee before inclusion,
/// which alerts and keeps it; a submit is not sent at all. A sovereign
/// account short of the funding floor alerts.
#[test]
fn the_budgets_refusal_raises_a_funding_alert() {
    let setup = Setup::new(true);
    setup.call(
        CONTROLLER,
        Call::SetBudget {
            space: setup.space.0,
            max_spend_per_window: 0,
        },
    );
    let venue = setup.venue();
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    wait_until("the funding alert", || {
        venue
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::Funding { .. }))
    });
    assert!(!setup.anchored_window(5));
    assert_eq!(venue.queued(), 1, "kept for the next window's budget");

    let statement = vos_statement::Statement {
        format: 39,
        program: vos_statement::ProgramId([5; 8]),
        space: SpaceId::NONE,
        public_args: Vec::new(),
        output: Vec::new(),
        roots: Vec::new(),
    };
    let active = calls::Active {
        from_ms: 0,
        until_ms: None,
    };
    setup.chain.with(|chain| {
        chain.set_storage(keys::formats(39), active.encode());
        let info = calls::ProgramInfo {
            handler: calls::Handler::Record,
            venue_bound: false,
            active,
        };
        chain.set_storage(keys::programs(&[5; 8]), info.encode());
    });
    let before = setup.chain.sends().len();
    assert_eq!(
        venue.submit(&statement, &[0]),
        Err(NotAccepted::Unjudged(Unjudged::Funding))
    );
    assert!(setup.chain.sends().len() - before <= 1, "no submit sent");
    assert!(
        setup
            .chain
            .sends()
            .iter()
            .all(|(_, call)| call[..2] != [PALLET, 8])
    );

    let short = Setup::new(true);
    short.chain.with(|chain| {
        let sovereign = calls::sovereign(&short.space);
        let mut account = chain.account(&sovereign);
        account.free = UNITS;
        chain.set_account(sovereign, account);
    });
    let venue = short.venue();
    assert!(
        venue
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::Funding { .. }))
    );
}

/// A send whose answer is lost after it landed is not sent again: the
/// signer's nonce says it landed, and the venue's storage that it is
/// held. A send dropped before it landed goes again as the same bytes,
/// and lands once.
#[test]
fn a_lost_connection_never_sends_a_call_twice() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    setup.chain.fault(Fault::LoseAnswer);
    assert_eq!(venue.anchor(&setup.anchor(4, 1)), Ok(Anchored::Queued));
    wait_until("the queue empties", || venue.queued() == 0);
    assert!(setup.anchored_window(4));
    assert_eq!(setup.anchors_sent(), 1, "not sent again");
    let read = RootRead {
        kind: RootKind::Space,
        space: setup.space,
        window: 4,
        root: [1; 32],
    };
    assert!(venue.anchored(&read));

    setup.chain.fault(Fault::Drop);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    wait_until("window 5 lands", || setup.anchored_window(5));
    assert_eq!(setup.anchors_sent(), 3, "the dropped one sent again");
    let included = setup
        .chain
        .included()
        .iter()
        .filter(|(origin, call)| *origin == Origin::Signed(NODE) && call[..2] == [PALLET, 7])
        .count();
    assert_eq!(included, 2, "each included once");
    assert!(venue.alerts().is_empty(), "{:?}", venue.alerts());
}

/// An anchor whose extrinsic waits in the pool is not taken as landed by
/// the pool's count: it stays queued, its same bytes sent again. Once the
/// pool is included, the nonce in the chain's state says it landed and
/// its record that it is held; one dropped from the pool goes again as the
/// same bytes and lands once.
#[test]
fn a_pooled_anchor_lands_once() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    setup.chain.fault(Fault::Pool);
    assert_eq!(venue.anchor(&setup.anchor(4, 1)), Ok(Anchored::Queued));
    wait_until("its bytes are sent again", || setup.anchors_sent() >= 3);
    assert!(!setup.anchored_window(4));
    assert_eq!(venue.queued(), 1, "kept while it may land");
    setup.chain.include_pool();
    wait_until("the queue empties", || venue.queued() == 0);
    assert!(setup.anchored_window(4));

    setup.chain.fault(Fault::Pool);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    wait_until("it waits in the pool", || setup.chain.pooled() == 1);
    setup.chain.drop_pool();
    wait_until("window 5 lands", || setup.anchored_window(5));
    let included = setup
        .chain
        .included()
        .iter()
        .filter(|(origin, call)| *origin == Origin::Signed(NODE) && call[..2] == [PALLET, 7])
        .count();
    assert_eq!(included, 2, "each included once");
}

/// A key removed after its anchor was queued: the venue refuses it
/// (`UnknownAnchorKey`), or the client, once it reads the listing, sends it
/// no more; it alerts, drops it and hands its window back to be signed
/// again; an anchor of the window signed by a listed key
/// is then sent and lands.
#[test]
fn a_refused_key_hands_the_window_back_to_be_signed_again() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    setup
        .chain
        .with(|chain| chain.set_storage(keys::paused(), vec![2]));
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    let key = keys::anchor_keys(&setup.space.0, &setup.key.verifying_key().to_bytes());
    let value = setup.chain.with(|chain| chain.storage()[&key].clone());
    setup.chain.with(|chain| {
        chain.remove_storage(&key);
        chain.set_storage(keys::paused(), vec![0]);
    });
    wait_until("the window handed back", || {
        venue.unsettled(&setup.space) == [5]
    });
    // Refused by the venue, or unsent once the client read the listing.
    let refused = setup.anchors_sent();
    assert!(refused <= 1);
    assert_eq!(venue.queued(), 0, "dropped");
    assert!(
        venue
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::Configuration { .. }))
    );
    setup.chain.with(|chain| chain.set_storage(key, value));
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    assert!(venue.unsettled(&setup.space).is_empty(), "queued again");
    wait_until("the anchor lands", || setup.anchored_window(5));
    assert_eq!(setup.anchors_sent(), refused + 1);
}

/// A venue whose chain cannot be reached at first: the client starts all
/// the same, every anchor `Open`; once reached, the anchor lands.
#[test]
fn a_venue_reached_late_anchors_once_reached() {
    let setup = Setup::new(true);
    let tries = Arc::new(AtomicUsize::new(0));
    let (chain, counted) = (Arc::clone(&setup.chain), Arc::clone(&tries));
    let connect: super::venue::Connect = Box::new(move || {
        if counted.fetch_add(1, Ordering::SeqCst) < 3 {
            return Err(Lost("down".into()));
        }
        Ok(chain.transport(Origin::Signed(NODE)) as Arc<dyn Transport>)
    });
    let venue = KreivoVenue::connect(connect, &[setup.space], setup.space, options());
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Err(AnchorRefusal::Open));
    assert_eq!(venue.status(&setup.space), Status::Unregistered);
    wait_until("reached and read", || {
        venue.status(&setup.space) == Status::Active
    });
    assert!(tries.load(Ordering::SeqCst) >= 4);
    assert_eq!(venue.id(), VENUE);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), Ok(Anchored::Queued));
    wait_until("window 5 lands", || setup.anchored_window(5));
}

/// A sender whose call's answer is lost, and whose era then runs out
/// before it lands, signs it again with the same nonce: it lands once.
#[test]
fn an_expired_send_is_signed_again_with_its_nonce() {
    let setup = Setup::new(true);
    let transport = setup.chain.transport(Origin::Signed(NODE));
    let signs = Arc::new(Mutex::new(Vec::new()));
    struct Counting {
        inner: Arc<dyn Transport>,
        signs: Arc<Mutex<Vec<u64>>>,
        chain: Arc<MockChain>,
    }
    impl Transport for Counting {
        fn account(&self) -> [u8; 32] {
            self.inner.account()
        }
        fn genesis(&self) -> Result<[u8; 32], Lost> {
            self.inner.genesis()
        }
        fn best(&self) -> Result<u64, Lost> {
            self.inner.best()
        }
        fn nonce(&self) -> Result<u64, Lost> {
            self.inner.nonce()
        }
        fn chain_nonce(&self) -> Result<u64, Lost> {
            self.inner.chain_nonce()
        }
        fn sign(&self, call: &[u8], nonce: u64) -> Result<Signed, SendError> {
            self.signs.lock().unwrap().push(nonce);
            self.inner.sign(call, nonce)
        }
        fn send(&self, signed: &Signed) -> Result<Included, SendError> {
            if self.signs.lock().unwrap().len() == 1 {
                self.chain.advance(100);
                return Err(SendError::Lost(Lost("lost".into())));
            }
            self.inner.send(signed)
        }
        fn storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Lost> {
            self.inner.storage(key)
        }
        fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Lost> {
            self.inner.keys(prefix)
        }
    }
    let counting = Arc::new(Counting {
        inner: transport,
        signs: Arc::clone(&signs),
        chain: Arc::clone(&setup.chain),
    });
    let sender = Sender::new(counting, Duration::from_millis(1));
    let sent = sender.call(&Call::anchor(&setup.anchor(5, 1)).bytes());
    assert!(matches!(sent, Ok(Sent::Included(_))), "{sent:?}");
    assert_eq!(*signs.lock().unwrap(), [0, 0], "signed again, same nonce");
    assert!(setup.anchored_window(5));
}

/// Statements through the client, at the conformance vectors' world (`F`
/// with its two roots anchored): the fixture accepted, its repeat
/// accepted without a send, a tampered proof refused with its class, and
/// a format the venue does not accept refused before paying.
#[test]
fn statements_are_judged_through_the_client() {
    let fx = Fixtures::load();
    let chain = MockChain::new(g7_chain(&fx));
    let venue = KreivoVenue::over(
        chain.transport(Origin::Signed(AUTHORITY_F)),
        &[SpaceId(F)],
        SpaceId(F),
        options(),
    );
    let statement = fx.statement();
    let id = statement.id();
    assert_eq!(venue.submit(statement, &fx.proof), Ok(id));
    let sent = chain.sends().len();
    assert_eq!(venue.submit(statement, &fx.proof), Ok(id), "a repeat");
    assert_eq!(chain.sends().len(), sent, "known accepted: not sent");
    let mut other = statement.clone();
    other.output.push(0);
    let refused = venue.submit(&other, &fx.proof);
    assert!(
        matches!(refused, Err(NotAccepted::Refused(code)) if code >= 0x100),
        "the proof refused against another statement: {refused:?}"
    );
    assert_eq!(
        venue.submit(statement, &fx.tampered),
        Ok(id),
        "known accepted, whatever the proof"
    );
    let mut format = statement.clone();
    format.format = 30;
    let sent = chain.sends().len();
    assert_eq!(
        venue.submit(&format, &fx.proof),
        Err(NotAccepted::Refused(2))
    );
    assert_eq!(chain.sends().len(), sent, "refused before paying");
    assert!(
        venue
            .alerts()
            .iter()
            .all(|alert| !matches!(alert, Alert::Unexpected(_)))
    );
}

/// A tampered proof of a fresh statement is refused with its class, its
/// deposit forfeited, through the client.
#[test]
fn a_refused_proof_reports_its_class() {
    let fx = Fixtures::load();
    let chain = MockChain::new(g7_chain(&fx));
    let venue = KreivoVenue::over(
        chain.transport(Origin::Signed(AUTHORITY_F)),
        &[SpaceId(F)],
        SpaceId(F),
        options(),
    );
    assert_eq!(
        venue.submit(fx.statement(), &fx.tampered),
        Err(NotAccepted::Refused(fx.tampered_code))
    );
    assert_eq!(
        venue.submit(fx.statement(), &fx.proof),
        Ok(fx.statement().id())
    );
}

/// Every pallet error has its fate (`spaces-pallet.md` §9), and a submit's
/// events their verdict: `Refused { 6 }` accepted.
#[test]
fn every_error_and_refusal_is_mapped() {
    use Error::*;
    for index in 0..=27 {
        let error = Error::from_index(index).unwrap();
        let expected = match error {
            AlreadyAnchored | WindowNotAfterLast => Answer::Done,
            WindowInFuture => Answer::Later,
            WindowTooOld | OutOfRange => Answer::Dead(error),
            SpaceNotActive | Paused => Answer::Wait,
            InsufficientSovereignBalance | OverBudget => Answer::Funding(error),
            UnknownAnchorKey | BadAnchorSignature => Answer::Resign(error),
            _ => Answer::Configuration,
        };
        assert_eq!(answer(Some(error)), expected, "{error:?}");
    }
    assert_eq!(answer(None), Answer::Configuration);
    let id = vos_statement::StatementId([7; 32]);
    let refused = |code| Event::Refused {
        payer: [0; 32],
        statement_hash: [0; 32],
        code,
    };
    let accepted = Event::Accepted {
        id: id.0,
        program: [0; 8],
        space: [0; 32],
        payer: [0; 32],
        output_hash: [0; 32],
    };
    assert_eq!(judged(&[accepted], id), Some(Ok(id)));
    assert_eq!(judged(&[refused(6)], id), Some(Ok(id)));
    for code in [1, 2, 3, 4, 5, 7, 0x101, 0x108] {
        assert_eq!(
            judged(&[refused(code)], id),
            Some(Err(NotAccepted::Refused(code)))
        );
    }
    assert_eq!(judged(&[], id), None);
}
