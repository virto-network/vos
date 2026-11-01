//! The mock under the venue rules' suite, and an ended space's deposit and
//! sovereign account; [`KreivoVenue`] over the mock: an anchor taken at
//! once and sent in the background, the pallet judging it; an anchor over
//! another root not sent until the leader, having read that root, offers
//! it again, then sent as the equivocation's evidence, which ends the
//! space; an open window sent again a block later; a block and a pause
//! sending nothing; the budget's refusal and a short sovereign account
//! alerting; a lost answer and a dropped send never sending a call twice;
//! a key the venue stops listing answered unlisted; statements judged
//! through the client; every pallet error mapped.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use parity_scale_codec::Encode;
use vos_anchor::{
    Anchor, MIN_LENGTH_MS, RootKind, RootRead, SpaceGenesis, SpaceId, VenueId, WindowClock,
};

use super::calls::{self, Call, Error, Event, PALLET, SpaceInfo, SpaceStatus, keys};
use super::conformance::Fixtures;
use super::conformance::submits::g7_chain;
use super::conformance::world::{AUTHORITY_F, F};
use super::mock::transport::{Fault, MockChain};
use super::mock::{Account, Chain, Constants, Origin, Verdict};
use super::send::{judged, outcome_of};
use super::transport::{Included, Lost, SendError, Sent, Signed, Transport};
use super::{Alert, KreivoVenue, Options, Sender};
use crate::{AnchorOutcome, Held, Status, SubmitOutcome, UNJUDGED, VenueClient};
use vos_statement::Refusal;

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

mod anchors;
mod judging;
mod sends;
mod suite;
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

/// A space of one founding key registered at the mock at its clock's
/// origin, so from window 1, the node its authority paired with that key,
/// the chain's time then at the boundary of window 5 (window 6 open).
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
        let now = Arc::new(AtomicU64::new(CLOCK.origin_ms));
        let read = Arc::clone(&now);
        let clock = Arc::new(move || read.load(Ordering::SeqCst));
        let setup = Self {
            chain: MockChain::with_clock(chain, Some(clock)),
            now,
            space,
            key,
        };
        let digest = vos_anchor::register_digest(&VENUE, &space, &CONTROLLER);
        setup.call(
            OPERATOR,
            Call::Register {
                genesis: genesis.encode(),
                controller: CONTROLLER,
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
        setup.set_now(CLOCK.boundary(5).unwrap() + 10);
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

    /// Set the space's status in the chain's storage, as governance or an
    /// equivocation leaves it.
    fn set_status(&self, status: SpaceStatus) {
        self.chain.with(|chain| {
            let key = keys::spaces(&self.space.0);
            let mut info: SpaceInfo = calls::read(&chain.storage()[&key]).unwrap();
            info.status = status;
            chain.set_storage(key, info.encode());
        });
    }
}

/// The client's status of the pallet's `status`.
fn calls_status(status: SpaceStatus) -> Status {
    status.into()
}
