//! The model venue's anchor rule and its judgement before the proof.

use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use vos_anchor::{MIN_LENGTH_MS, RootKind};

use super::*;

const VENUE: VenueId = VenueId([0x7e; 32]);

/// A venue at a time a test moves, a space of two founding keys
/// registered from window 2, and the keys.
struct Fixture {
    venue: ModelVenue,
    now: Arc<AtomicU64>,
    space: SpaceId,
    clock: WindowClock,
    keys: [SigningKey; 2],
}

fn fixture() -> Fixture {
    let keys = [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
    ];
    let clock = WindowClock {
        origin_ms: 1_000_000,
        length_ms: MIN_LENGTH_MS,
    };
    let genesis = SpaceGenesis {
        version: vos_anchor::GENESIS_VERSION,
        nodes: vec![
            (1, keys[0].verifying_key().to_bytes()),
            (2, keys[1].verifying_key().to_bytes()),
        ],
        clock,
        time: 7,
        nonce: [3; 16],
    };
    let now = Arc::new(AtomicU64::new(clock.boundary(5).unwrap() + 10));
    let read = Arc::clone(&now);
    let venue = ModelVenue::new(VENUE, Arc::new(move || read.load(Ordering::SeqCst)));
    let space = venue.register(&genesis, 2);
    Fixture {
        venue,
        now,
        space,
        clock,
        keys,
    }
}

impl Fixture {
    /// `root` as the space's at `window`, signed by key `by`.
    fn anchor(&self, window: u64, root: u8, by: usize) -> Anchor {
        let mut anchor = Anchor {
            space: self.space,
            window,
            kind: RootKind::Space,
            root: [root; 32],
            signer: self.keys[by].verifying_key().to_bytes(),
            signature: [0; 64],
        };
        anchor.signature = self.keys[by].sign(&anchor.digest(&VENUE)).to_bytes();
        anchor
    }

    fn read(&self, window: u64, root: u8) -> RootRead {
        RootRead {
            kind: RootKind::Space,
            space: self.space,
            window,
            root: [root; 32],
        }
    }
}

/// An anchor past the last and before the open window is taken, by either
/// founding key, and again as `Again`; the windows it may not take: one at
/// or before the last, one before the start, and, until its boundary
/// passes, the open one; another
/// signer, a signature over another venue's digest, an unregistered space.
#[test]
fn the_anchor_rule() {
    let f = fixture();
    assert_eq!(f.venue.anchor(&f.anchor(3, 1, 0)), Ok(Anchored::New));
    assert!(f.venue.anchored(&f.read(3, 1)));
    assert_eq!(f.venue.anchor(&f.anchor(3, 1, 1)), Ok(Anchored::Again));
    assert_eq!(f.venue.anchor(&f.anchor(5, 1, 1)), Ok(Anchored::New));
    for window in [4, 1] {
        assert_eq!(
            f.venue.anchor(&f.anchor(window, 1, 0)),
            Err(AnchorRefusal::Window),
            "window {window}"
        );
    }
    assert_eq!(f.venue.anchor(&f.anchor(6, 1, 0)), Err(AnchorRefusal::Open));
    f.now
        .store(f.clock.boundary(6).unwrap() + 1, Ordering::SeqCst);
    assert_eq!(
        f.venue.anchor(&f.anchor(6, 1, 0)),
        Ok(Anchored::New),
        "once past"
    );
    let mut stranger = f.anchor(5, 2, 0);
    let other = SigningKey::from_bytes(&[9; 32]);
    stranger.signer = other.verifying_key().to_bytes();
    stranger.signature = other.sign(&stranger.digest(&VENUE)).to_bytes();
    assert_eq!(f.venue.anchor(&stranger), Err(AnchorRefusal::Key));
    let mut elsewhere = f.anchor(5, 2, 0);
    elsewhere.signature = f.keys[0]
        .sign(&elsewhere.digest(&VenueId([1; 32])))
        .to_bytes();
    assert_eq!(f.venue.anchor(&elsewhere), Err(AnchorRefusal::Signature));
    let mut unknown = f.anchor(5, 2, 0);
    unknown.space = SpaceId([8; 32]);
    assert_eq!(f.venue.anchor(&unknown), Err(AnchorRefusal::Unregistered));
}

/// A root older than `MaxRootAge` is not anchored, and an anchored one
/// stops being so once it is.
#[test]
fn a_root_past_its_age_is_refused() {
    let f = fixture();
    assert_eq!(f.venue.anchor(&f.anchor(4, 1, 0)), Ok(Anchored::New));
    let past = f.clock.boundary(4).unwrap() + MAX_ROOT_AGE_MS + 3 * MIN_LENGTH_MS;
    f.now.store(past, Ordering::SeqCst);
    assert!(!f.venue.anchored(&f.read(4, 1)));
    let late = f.clock.window(past).unwrap() - 1;
    assert!(f.clock.boundary(late).unwrap() + MAX_ROOT_AGE_MS >= past);
    let old = f.clock.window(past - MAX_ROOT_AGE_MS).unwrap() - 2;
    assert_eq!(
        f.venue.anchor(&f.anchor(old, 1, 0)),
        Err(AnchorRefusal::Age)
    );
    assert_eq!(f.venue.anchor(&f.anchor(late, 1, 0)), Ok(Anchored::New));
}

/// A second root for an anchored window, signed by a founding key, is an
/// equivocation: kept as evidence beside the first, the space suspended,
/// its roots no longer anchored and its next anchors refused.
#[test]
fn an_equivocation_is_caught() {
    let f = fixture();
    let first = f.anchor(3, 1, 0);
    assert_eq!(f.venue.anchor(&first), Ok(Anchored::New));
    let second = f.anchor(3, 2, 1);
    assert_eq!(f.venue.anchor(&second), Err(AnchorRefusal::Equivocation));
    assert_eq!(f.venue.evidence(), [(first, second)]);
    assert!(f.venue.suspended(&f.space));
    assert!(!f.venue.anchored(&f.read(3, 1)));
    assert_eq!(
        f.venue.anchor(&f.anchor(4, 1, 0)),
        Err(AnchorRefusal::Suspended)
    );
    assert_eq!(f.venue.anchors(&f.space), [first]);
}

/// A statement is judged against the venue's anchors: a program it pinned
/// none for is refused, a root not anchored is refused, and one anchored
/// passes every check before the proof, whose bytes are then judged.
#[test]
fn a_statement_is_judged_against_the_anchors() {
    let f = fixture();
    let program = ProgramId([5; 8]);
    let statement = Statement {
        format: vos_statement::LINKED[0],
        program,
        space: f.space,
        public_args: vec![1],
        output: vec![2],
        roots: vec![f.read(3, 1)],
    };
    let code = |verdict: Result<StatementId, Refusal>| vos_statement::code(&verdict);
    assert_eq!(code(f.venue.submit(&statement, &[0])), 3, "not pinned");
    f.venue.pin(Pin {
        program,
        venue_bound: false,
    });
    assert_eq!(code(f.venue.submit(&statement, &[0])), 5, "not anchored");
    f.venue.anchor(&f.anchor(3, 1, 0)).unwrap();
    assert!(
        code(f.venue.submit(&statement, &[0])) >= 0x100,
        "judged to the proof"
    );
}

/// A migration away ends the space's range: its anchors at or past the
/// migration's window are refused, and its roots there are not anchored,
/// those before still are. Refused: a migration from another venue, to
/// this one, of a space not registered, from a window anchored here or
/// before the venue's next, and a second one.
#[test]
fn a_migration_ends_the_range() {
    let f = fixture();
    assert_eq!(f.venue.anchor(&f.anchor(3, 1, 0)), Ok(Anchored::New));
    assert_eq!(f.venue.anchor(&f.anchor(4, 1, 0)), Ok(Anchored::New));
    // The venue's clock is in window 5: its next is 6.
    let away = |from: VenueId, to: VenueId, space: SpaceId, from_window: u64| Migrate {
        space,
        from,
        to,
        from_window,
    };
    let there = VenueId([0x55; 32]);
    for (migrate, refusal) in [
        (
            away(VenueId([1; 32]), there, f.space, 7),
            MigrateRefusal::Venue,
        ),
        (away(VENUE, VENUE, f.space, 7), MigrateRefusal::Venue),
        (
            away(VENUE, there, SpaceId([8; 32]), 7),
            MigrateRefusal::Unregistered,
        ),
        (away(VENUE, there, f.space, 4), MigrateRefusal::Window),
        (away(VENUE, there, f.space, 5), MigrateRefusal::Window),
    ] {
        assert_eq!(f.venue.migrate(&migrate), Err(refusal), "{migrate:?}");
    }
    assert_eq!(f.venue.migrate(&away(VENUE, there, f.space, 7)), Ok(()));
    assert_eq!(
        f.venue.migrate(&away(VENUE, there, f.space, 8)),
        Err(MigrateRefusal::AlreadyMigrated)
    );
    assert!(f.venue.anchored(&f.read(4, 1)));
    f.now
        .store(f.clock.boundary(7).unwrap() + 1, Ordering::SeqCst);
    assert_eq!(f.venue.anchor(&f.anchor(6, 1, 0)), Ok(Anchored::New));
    assert_eq!(
        f.venue.anchor(&f.anchor(7, 1, 0)),
        Err(AnchorRefusal::Window)
    );
    assert!(!f.venue.anchored(&f.read(7, 1)));
}
