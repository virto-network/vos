//! The model venue under the venue rules' suite, and its judgement of a
//! statement against its anchors.

use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use vos_anchor::suite::{self, Answer, Harness};
use vos_anchor::venue::{RegisterRefusal, Status as Standing};
use vos_anchor::{MIN_LENGTH_MS, RootKind};

use super::*;

const VENUE: VenueId = VenueId([0x7e; 32]);

/// The model venue at a time a test moves.
pub(crate) struct Model {
    pub(crate) venue: ModelVenue,
    now: Arc<AtomicU64>,
}

impl Model {
    pub(crate) fn new() -> Self {
        let now = Arc::new(AtomicU64::new(0));
        let read = Arc::clone(&now);
        let venue = ModelVenue::new(VENUE, Arc::new(move || read.load(Ordering::SeqCst)));
        Self { venue, now }
    }
}

/// Test key `seed`.
pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

impl Harness for Model {
    fn venue(&self) -> VenueId {
        VENUE
    }

    fn set_now(&mut self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }

    fn key(&self, seed: u8) -> [u8; 32] {
        key(seed).verifying_key().to_bytes()
    }

    fn sign(&self, seed: u8, digest: &[u8; 32]) -> [u8; 64] {
        key(seed).sign(digest).to_bytes()
    }

    fn controller(&self) -> [u8; 32] {
        [0xc0; 32]
    }

    fn register(
        &mut self,
        genesis: &SpaceGenesis,
        controller: &[u8; 32],
        founder_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), RegisterRefusal> {
        self.venue
            .register(genesis, controller, &founder_key, &signature)
            .map(|_| ())
    }

    fn start(&self, space: &SpaceId) -> Option<u64> {
        self.venue.start(space)
    }

    fn anchor(&mut self, anchor: &Anchor) -> Answer {
        match self.venue.answer(anchor) {
            Ok(Anchoring::New) => Answer::New,
            Ok(Anchoring::Again) => Answer::Again,
            Ok(Anchoring::Evidence(_)) => Answer::Evidence,
            Err(refusal) => Answer::Refused(refusal),
        }
    }

    fn add_key(&mut self, space: &SpaceId, key: [u8; 32]) -> bool {
        self.venue.add_anchor_key(space, key)
    }

    fn remove_key(&mut self, space: &SpaceId, key: [u8; 32]) -> bool {
        self.venue.remove_anchor_key(space, &key)
    }

    fn status(&self, space: &SpaceId) -> Option<Standing> {
        match self.venue.status(space) {
            Status::Unregistered => None,
            Status::Active => Some(Standing::Active),
            Status::Blocked => Some(Standing::Blocked),
            Status::Ended => Some(Standing::Ended),
        }
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.venue.anchored(root)
    }
}

/// The model venue judges as the venue rules do.
#[test]
fn the_model_passes_the_venue_rules_suite() {
    suite::run(Model::new);
}

/// The evidence an equivocation leaves: the anchor held and the other.
#[test]
fn an_equivocation_keeps_both_anchors() {
    let mut model = Model::new();
    let clock = WindowClock {
        origin_ms: 1_000_000,
        length_ms: MIN_LENGTH_MS,
    };
    let genesis = SpaceGenesis {
        nodes: vec![(1, model.key(1)), (2, model.key(2))],
        clock,
        time: 7,
        nonce: [3; 16],
    };
    let space = model.venue.seed(&genesis, 0);
    model.set_now(clock.boundary(5).unwrap());
    let signed = |seed: u8, root: u8| {
        let mut anchor = Anchor {
            space,
            window: 3,
            kind: RootKind::Space,
            root: [root; 32],
            signer: model.key(seed),
            signature: [0; 64],
        };
        anchor.signature = model.sign(seed, &anchor.digest(&VENUE));
        anchor
    };
    let (held, other) = (signed(1, 1), signed(2, 2));
    assert_eq!(model.venue.anchor(&held), AnchorOutcome::Taken);
    assert_eq!(model.venue.anchor(&other), AnchorOutcome::Stopped(8));
    assert_eq!(model.venue.evidence(), vec![(held, other)]);
    assert_eq!(model.venue.status(&space), Status::Ended);
}

/// A statement is judged against the venue's anchors: a program it pinned
/// none for is refused, a root not anchored is refused, and one anchored
/// passes every check before the proof, whose bytes are then judged.
#[test]
fn a_statement_is_judged_against_the_anchors() {
    let mut model = Model::new();
    let clock = WindowClock {
        origin_ms: 1_000_000,
        length_ms: MIN_LENGTH_MS,
    };
    let genesis = SpaceGenesis {
        nodes: vec![(1, model.key(1))],
        clock,
        time: 7,
        nonce: [3; 16],
    };
    let space = model.venue.seed(&genesis, 0);
    model.set_now(clock.boundary(5).unwrap());
    let program = ProgramId([5; 8]);
    let root = RootRead {
        kind: RootKind::Space,
        space,
        window: 3,
        root: [1; 32],
    };
    let statement = Statement {
        format: vos_statement::LINKED[0],
        program,
        space,
        public_args: vec![1],
        output: vec![2],
        roots: vec![root],
    };
    let code = |outcome: SubmitOutcome| outcome.code();
    assert_eq!(code(model.venue.submit(&statement, &[0])), 3, "not pinned");
    model.venue.pin(program);
    assert_eq!(
        code(model.venue.submit(&statement, &[0])),
        5,
        "not anchored"
    );
    let mut anchor = Anchor {
        space,
        window: 3,
        kind: RootKind::Space,
        root: [1; 32],
        signer: model.key(1),
        signature: [0; 64],
    };
    anchor.signature = model.sign(1, &anchor.digest(&VENUE));
    assert_eq!(model.venue.anchor(&anchor), AnchorOutcome::Taken);
    assert!(
        code(model.venue.submit(&statement, &[0])) >= 0x100,
        "judged to the proof"
    );
}

/// Every answer of the venue rules has its outcome: taken, not yet, never,
/// unlisted or stopped, each refusal's code kept.
#[test]
fn every_rule_answer_has_its_outcome() {
    use vos_anchor::venue::Held as Holding;
    let evidence = Anchoring::Evidence(Holding {
        root: [1; 32],
        signer: [2; 32],
    });
    for (answer, expected) in [
        (Ok(Anchoring::New), AnchorOutcome::Taken),
        (Ok(Anchoring::Again), AnchorOutcome::Taken),
        (Ok(evidence), AnchorOutcome::Stopped(8)),
        (Err(AnchorRefusal::Unregistered), AnchorOutcome::NotYet),
        (Err(AnchorRefusal::Stopped), AnchorOutcome::Stopped(2)),
        (Err(AnchorRefusal::Key), AnchorOutcome::Unlisted(3)),
        (Err(AnchorRefusal::Signature), AnchorOutcome::Never(4)),
        (Err(AnchorRefusal::Window), AnchorOutcome::Never(5)),
        (Err(AnchorRefusal::Open), AnchorOutcome::NotYet),
        (Err(AnchorRefusal::Age), AnchorOutcome::Never(7)),
    ] {
        assert_eq!(outcome(answer), expected, "{answer:?}");
    }
}
