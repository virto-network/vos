//! The venue rules' suite ([`run`]): every rule of [`crate::venue`] and
//! every refusal, driven through a venue's own calls ([`Harness`]), each
//! answer mapped back to the rules' terms. A venue passes it when it
//! judges as the rules do; the mapping is its code table, tested with it.
//! VOS runs it over its model venue, the JAM statements service and the
//! reference mock of Kreivo's pallet; the pallet may run it over its own
//! runtime.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a test suite: a venue that judges otherwise fails it"
)]

use alloc::vec;
use alloc::vec::Vec;

use crate::venue::{AnchorRefusal, RegisterRefusal, Status};
use crate::{
    Anchor, MAX_FOUNDING_KEYS, MAX_ROOT_AGE_MS, RootKind, RootRead, SpaceGenesis, SpaceId,
    WindowClock, register_digest, space_id,
};

/// What a venue answered an anchor, in the rules' terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Taken: the window's root now.
    New,
    /// The venue holds that root there already.
    Again,
    /// Another root held there: kept as evidence, the space ended.
    Evidence,
    Refused(AnchorRefusal),
}

/// A venue as the suite drives it, through its own calls.
pub trait Harness {
    /// The venue's id.
    fn venue(&self) -> crate::VenueId;
    /// Set the venue's time.
    fn set_now(&mut self, now: u64);
    /// Test key `seed`'s ed25519 public key.
    fn key(&self, seed: u8) -> [u8; 32];
    /// Test key `seed`'s signature over `digest`.
    fn sign(&self, seed: u8, digest: &[u8; 32]) -> [u8; 64];
    /// The controller the suite registers its spaces under: an account, or
    /// on JAM an ed25519 key, whose calls the harness signs.
    fn controller(&self) -> [u8; 32];
    /// The venue's registration of `genesis` under `controller`, signed
    /// by `founder_key`: its answer, mapped.
    fn register(
        &mut self,
        genesis: &SpaceGenesis,
        controller: &[u8; 32],
        founder_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), RegisterRefusal>;
    /// The first window `space` anchors at, as the venue records it.
    fn start(&self, space: &SpaceId) -> Option<u64>;
    /// The venue's anchor of `anchor`: its answer, mapped.
    fn anchor(&mut self, anchor: &Anchor) -> Answer;
    /// The controller's listing of `key` for `space`: whether the venue
    /// took it.
    fn add_key(&mut self, space: &SpaceId, key: [u8; 32]) -> bool;
    /// The controller's delisting of `key`: whether the venue took it.
    fn remove_key(&mut self, space: &SpaceId, key: [u8; 32]) -> bool;
    /// Where `space` stands, if registered.
    fn status(&self, space: &SpaceId) -> Option<Status>;
    /// Whether the venue counts `root` anchored.
    fn anchored(&self, root: &RootRead) -> bool;
}

/// The suite's clock: two-minute windows from a round origin.
const CLOCK: WindowClock = WindowClock {
    origin_ms: 1_800_000_000_000,
    length_ms: 120_000,
};

/// A genesis of the test keys `seeds`.
fn genesis(harness: &impl Harness, seeds: &[u8], nonce: u8) -> SpaceGenesis {
    SpaceGenesis {
        version: crate::GENESIS_VERSION,
        nodes: seeds
            .iter()
            .enumerate()
            .map(|(number, seed)| (number as u8, harness.key(*seed)))
            .collect(),
        clock: CLOCK,
        time: CLOCK.origin_ms,
        nonce: [nonce; 16],
    }
}

/// `genesis` registered by its key `seed` under the harness's controller.
fn register(
    harness: &mut impl Harness,
    genesis: &SpaceGenesis,
    seed: u8,
) -> Result<(), RegisterRefusal> {
    let controller = harness.controller();
    let digest = register_digest(&harness.venue(), &space_id(genesis), &controller);
    let signature = harness.sign(seed, &digest);
    harness.register(genesis, &controller, harness.key(seed), signature)
}

/// The anchor of `root` as `space`'s at `window`, signed by key `seed`.
fn signed(harness: &impl Harness, space: SpaceId, window: u64, root: u8, seed: u8) -> Anchor {
    let mut anchor = Anchor {
        space,
        window,
        kind: RootKind::Space,
        root: [root; 32],
        signer: harness.key(seed),
        signature: [0; 64],
    };
    anchor.signature = harness.sign(seed, &anchor.digest(&harness.venue()));
    anchor
}

fn read(anchor: &Anchor) -> RootRead {
    RootRead {
        kind: anchor.kind,
        space: anchor.space,
        window: anchor.window,
        root: anchor.root,
    }
}

/// The time `ms` into window `w`.
fn into(w: u64, ms: u64) -> u64 {
    CLOCK.origin_ms + w * CLOCK.length_ms + ms
}

/// Every rule and every refusal, each venue made fresh by `venue`.
pub fn run<H: Harness>(venue: impl Fn() -> H) {
    registration(&mut venue());
    anchoring(&mut venue());
    equivocation(&mut venue());
}

/// A registration's refusals, each alone; one taken, anchoring from the
/// venue's next window, or from window 0 before the clock's origin; and the
/// same registration again refused.
fn registration(h: &mut impl Harness) {
    h.set_now(into(10, 5_000));
    let refused = |h: &mut _, genesis: &SpaceGenesis| register(h, genesis, 1);
    let too_many: Vec<u8> = (1..=MAX_FOUNDING_KEYS as u8 + 1).collect();
    let twice = SpaceGenesis {
        nodes: vec![(0, h.key(1)), (1, h.key(1))],
        ..genesis(h, &[1], 1)
    };
    let small = SpaceGenesis {
        nodes: vec![(0, h.key(1)), (1, [0; 32])],
        ..genesis(h, &[1], 1)
    };
    for (name, genesis) in [
        ("more than MAX_FOUNDING_KEYS", genesis(h, &too_many, 1)),
        ("a key twice", twice),
        ("a key of small order", small),
    ] {
        assert_eq!(
            refused(h, &genesis),
            Err(RegisterRefusal::Genesis),
            "{name}"
        );
    }
    let short = SpaceGenesis {
        clock: WindowClock {
            length_ms: crate::MIN_LENGTH_MS - 1,
            ..CLOCK
        },
        ..genesis(h, &[1], 1)
    };
    assert_eq!(refused(h, &short), Err(RegisterRefusal::Clock));
    let one = genesis(h, &[1, 2], 1);
    assert_eq!(register(h, &one, 3), Err(RegisterRefusal::Founder));
    let space = space_id(&one);
    let foreign = register_digest(&h.venue(), &space, &[0xc1; 32]);
    let signature = h.sign(1, &foreign);
    assert_eq!(
        h.register(&one, &h.controller(), h.key(1), signature),
        Err(RegisterRefusal::Founder),
        "a signature under another controller"
    );
    assert_eq!(h.status(&space), None);

    assert_eq!(register(h, &one, 2), Ok(()));
    assert_eq!(h.status(&space), Some(Status::Active));
    assert_eq!(h.start(&space), Some(11), "the venue's next window");
    assert_eq!(register(h, &one, 1), Err(RegisterRefusal::Exists));

    let early = genesis(h, &[1], 2);
    h.set_now(CLOCK.origin_ms - 1);
    assert_eq!(register(h, &early, 1), Ok(()));
    assert_eq!(h.start(&space_id(&early)), Some(0), "before the origin");
}

/// The anchor rule's refusals, each alone, and what it takes: a gap
/// allowed, the same root again, the edges of the open window and of
/// `MaxRootAge`; what counts anchored; a key added and removed, one of
/// small order never listed.
fn anchoring(h: &mut impl Harness) {
    h.set_now(into(4, 0));
    let genesis = genesis(h, &[1, 2], 3);
    let space = space_id(&genesis);
    let unregistered = signed(h, space, 3, 0x33, 1);
    assert_eq!(
        h.anchor(&unregistered),
        Answer::Refused(AnchorRefusal::Unregistered)
    );
    register(h, &genesis, 1).expect("registered");
    assert_eq!(h.start(&space), Some(5));
    h.set_now(into(9, 1));

    let before = signed(h, space, 4, 0x44, 1);
    assert_eq!(h.anchor(&before), Answer::Refused(AnchorRefusal::Window));
    let unlisted = signed(h, space, 5, 0x55, 3);
    assert_eq!(h.anchor(&unlisted), Answer::Refused(AnchorRefusal::Key));
    let mut forged = signed(h, space, 5, 0x55, 1);
    forged.root[0] ^= 1;
    assert_eq!(h.anchor(&forged), Answer::Refused(AnchorRefusal::Signature));
    let open = signed(h, space, 9, 0x99, 1);
    assert_eq!(h.anchor(&open), Answer::Refused(AnchorRefusal::Open));
    let future = signed(h, space, 12, 0x12, 1);
    assert_eq!(h.anchor(&future), Answer::Refused(AnchorRefusal::Open));

    let first = signed(h, space, 5, 0x55, 1);
    assert_eq!(h.anchor(&first), Answer::New);
    assert!(h.anchored(&read(&first)));
    assert_eq!(h.anchor(&first), Answer::Again);
    assert_eq!(
        h.anchor(&signed(h, space, 5, 0x55, 2)),
        Answer::Again,
        "the same root by another listed key"
    );
    let mut other = read(&first);
    other.root[0] ^= 1;
    assert!(!h.anchored(&other), "another root at the window");
    let gap = signed(h, space, 7, 0x77, 2);
    assert_eq!(h.anchor(&gap), Answer::New);
    let skipped = signed(h, space, 6, 0x66, 1);
    assert_eq!(h.anchor(&skipped), Answer::Refused(AnchorRefusal::Window));

    // The open window at its boundary: closed exactly at B_w.
    h.set_now(into(10, 0) - 1);
    let nine = signed(h, space, 9, 0x99, 1);
    assert_eq!(h.anchor(&nine), Answer::Refused(AnchorRefusal::Open));
    h.set_now(into(10, 0));
    assert_eq!(h.anchor(&nine), Answer::New);

    // `MaxRootAge`: window 12 anchored at its last fresh millisecond, its
    // root counted then and not a millisecond later; window 13 refused.
    let twelve = signed(h, space, 12, 0x12, 1);
    let last = CLOCK.boundary(12).expect("a boundary") + MAX_ROOT_AGE_MS;
    h.set_now(last);
    assert_eq!(h.anchor(&twelve), Answer::New);
    assert!(h.anchored(&read(&twelve)));
    h.set_now(last + 1);
    assert!(!h.anchored(&read(&twelve)), "past MaxRootAge");
    let thirteen = signed(h, space, 13, 0x13, 1);
    h.set_now(CLOCK.boundary(13).expect("a boundary") + MAX_ROOT_AGE_MS + 1);
    assert_eq!(h.anchor(&thirteen), Answer::Refused(AnchorRefusal::Age));

    // A key listed, then delisted; one of small order never listed.
    let now = into(800, 0);
    h.set_now(now);
    assert!(h.add_key(&space, h.key(3)));
    assert_eq!(h.anchor(&signed(h, space, 798, 0x98, 3)), Answer::New);
    assert!(h.remove_key(&space, h.key(3)));
    assert_eq!(
        h.anchor(&signed(h, space, 799, 0x99, 3)),
        Answer::Refused(AnchorRefusal::Key)
    );
    let mut torsion = [0; 32];
    torsion[0] = 1;
    assert!(!h.add_key(&space, torsion), "small order");
}

/// A second root at a window held, by another listed key: the evidence,
/// which ends the space for good: no anchor taken, no root counted, the
/// registration refused again.
fn equivocation(h: &mut impl Harness) {
    h.set_now(into(20, 0));
    let genesis = genesis(h, &[1, 2], 4);
    let space = space_id(&genesis);
    register(h, &genesis, 1).expect("registered");
    h.set_now(into(25, 0));
    let held = signed(h, space, 22, 0x22, 1);
    assert_eq!(h.anchor(&held), Answer::New);
    let later = signed(h, space, 23, 0x23, 1);
    assert_eq!(h.anchor(&later), Answer::New);
    let other = signed(h, space, 22, 0xee, 2);
    assert_eq!(h.anchor(&other), Answer::Evidence);
    assert_eq!(h.status(&space), Some(Status::Ended));
    for root in [&held, &other, &later] {
        assert!(!h.anchored(&read(root)), "an ended space's roots");
    }
    assert_eq!(
        h.anchor(&signed(h, space, 24, 0x24, 1)),
        Answer::Refused(AnchorRefusal::Stopped)
    );
    assert_eq!(
        h.anchor(&other),
        Answer::Refused(AnchorRefusal::Stopped),
        "the evidence again"
    );
    assert_eq!(
        register(h, &genesis, 2),
        Err(RegisterRefusal::Exists),
        "the tombstone"
    );
    assert_eq!(h.status(&space), Some(Status::Ended));
}
