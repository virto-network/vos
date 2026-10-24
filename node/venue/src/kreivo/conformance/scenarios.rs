//! G1–G18 (`spaces-pallet.md` §10), each a scenario run through the mock:
//! its setup unrecorded, then its pre-state taken and each step recorded,
//! the step's expected result asserted as the design's text gives it.
//!
//! **The world every vector starts from:** the fixtures' time (window 42's
//! boundary of the fixture space's clock); `format::MASKED_WRAP` and the fixtures' two
//! programs (venue-bound, `Record`) active from 0; the fixture space `F`
//! (the fixtures' statements' space, `[0xA1; 32]`, registered from window
//! 40 under the default clock, its one authority paired with its anchor
//! key) in the pre-state as storage, since no genesis hashes to the
//! fixtures' space id; the venue the fixtures' (their statements bind it).
//! A second space `B`, registered by call from a two-founder genesis, on a
//! clock of its own (origin 1,000,000 ms, ten-minute windows: window 41 at
//! the fixtures' time).

use ed25519_dalek::{Signer, SigningKey};
use parity_scale_codec::Encode;
use vos_anchor::{RootKind, SpaceGenesis, WindowClock};
use vos_statement::{RootRead, SpaceId, Statement};

use super::{ConstantsJson, File, Fixtures, Pre, Step, Vector, hex, parts, pre, step};
use crate::kreivo::mock::keys;
use crate::kreivo::mock::types::{
    AccountId, Active, AnchorArg, AuthorityInfo, BALANCES_INDEX, BalancesCall, Call, DispatchError,
    Error, Event, Handler, MultiAddress, PAUSE_ANCHOR, PAUSE_REGISTER, PAUSE_SUBMIT, ProgramInfo,
    RuntimeCall, Space, SpaceInfo, SpaceStatus,
};
use crate::kreivo::mock::{Account, Chain, Constants, Origin, Outcome, Payer, Verdict};

const UNITS: u128 = 1_000_000_000_000;
/// The fixtures' time: window 42's boundary of `F`'s clock.
const NOW: u64 = 43 * 600_000;
/// The fixture space.
pub const F: Space = [0xA1; 32];
const F_CLOCK: WindowClock = WindowClock::DEFAULT;
const B_CLOCK: WindowClock = WindowClock {
    origin_ms: 1_000_000,
    length_ms: 600_000,
};
/// `B`'s first window.
const B_START: u64 = 30;

const OPERATOR: AccountId = [0x0a; 32];
const CONTROLLER: AccountId = [0xc0; 32];
const CONTROLLER_2: AccountId = [0xc2; 32];
pub const AUTHORITY_F: AccountId = [0xaf; 32];
const AUTHORITY_1: AccountId = [0xa3; 32];
const AUTHORITY_2: AccountId = [0xa4; 32];
const AUTHORITY_3: AccountId = [0xa5; 32];
const STRANGER: AccountId = [0x5e; 32];
const RECIPIENT: AccountId = [0xd0; 32];

/// The anchor keys, by seed: `F`'s, `B`'s two founders', two more, and
/// one never listed.
const KEY_F: u8 = 0xf1;
const KEY_1: u8 = 1;
const KEY_2: u8 = 2;
const KEY_3: u8 = 3;
const KEY_4: u8 = 4;
const KEY_5: u8 = 5;
const KEY_6: u8 = 6;
const KEY_9: u8 = 9;

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> [u8; 32] {
    signing(seed).verifying_key().to_bytes()
}

/// A two-founder genesis on `clock`, told apart by `nonce`.
fn genesis(clock: WindowClock, nonce: u8) -> SpaceGenesis {
    SpaceGenesis {
        version: vos_anchor::GENESIS_VERSION,
        nodes: vec![(1, public(KEY_1)), (2, public(KEY_2))],
        clock,
        time: clock.origin_ms,
        nonce: [nonce; 16],
    }
}

/// A two-founder genesis on `B`'s clock, told apart by `nonce`.
fn genesis_of(nonce: u8) -> SpaceGenesis {
    genesis(B_CLOCK, nonce)
}

fn funded(free: u128) -> Account {
    Account {
        free,
        providers: 1,
        ..Account::default()
    }
}

fn space_of(genesis: &SpaceGenesis) -> Space {
    vos_anchor::space_id(genesis).0
}

fn b_genesis() -> SpaceGenesis {
    genesis(B_CLOCK, 0xb0)
}

fn b() -> Space {
    space_of(&b_genesis())
}

/// What a step must do.
#[derive(Clone, Copy, Debug)]
enum Expect {
    Ok,
    Err(Error),
    BadOrigin,
    Payment,
    Undecodable,
}

impl Expect {
    fn holds(self, verdict: &Verdict) -> bool {
        match (self, verdict) {
            (Self::Ok, Verdict::Ok) => true,
            (Self::Err(error), Verdict::Err(got)) => DispatchError::from(error) == *got,
            (Self::BadOrigin, Verdict::Err(DispatchError::BadOrigin)) => true,
            (Self::Payment, Verdict::Payment) => true,
            (Self::Undecodable, Verdict::Undecodable) => true,
            _ => false,
        }
    }
}

/// A scenario's chain, recording once its setup is done.
struct World<'f> {
    fx: &'f Fixtures,
    chain: Chain,
    pre: Option<Pre>,
    steps: Vec<Step>,
}

impl<'f> World<'f> {
    /// The world every vector starts from (the module's docs).
    fn new(fx: &'f Fixtures, fees: bool) -> Self {
        let constants = Constants::kreivo(fx.venue);
        let mut chain = Chain::new(constants.clone()).with_fees(fees);
        chain.set_now(NOW);
        for who in [OPERATOR, CONTROLLER, CONTROLLER_2, STRANGER] {
            chain.set_account(who, funded(100 * UNITS));
        }
        chain.set_account(RECIPIENT, funded(10 * UNITS));
        chain.set_account(constants.forfeit_to, funded(1_000 * UNITS));
        chain.set_account(constants.sovereign(&b()), funded(100 * UNITS));

        // `F`, as its registration and its authority's addition leave it.
        let sovereign = constants.sovereign(&F);
        let info = SpaceInfo {
            sovereign,
            controller: CONTROLLER,
            origin_ms: F_CLOCK.origin_ms,
            length_ms: F_CLOCK.length_ms,
            start_window: 40,
            end_window: None,
            status: SpaceStatus::Active,
            authorities: 1,
            anchor_keys: 1,
            registered_ms: 0,
            max_spend_per_window: constants.default_spend_per_window,
        };
        chain.set_storage(keys::spaces(&F), info.encode());
        chain.set_storage(keys::sovereign_of(&sovereign), F.encode());
        chain.set_storage(
            keys::authorities(&F, &AUTHORITY_F),
            AuthorityInfo {
                anchor_key: Some(public(KEY_F)),
            }
            .encode(),
        );
        chain.set_storage(
            keys::anchor_keys(&F, &public(KEY_F)),
            Some(AUTHORITY_F).encode(),
        );
        chain.set_account(
            sovereign,
            Account {
                free: 100 * UNITS,
                held_registration: constants.registration_deposit,
                held_submit: 0,
                providers: 2,
                consumers: 0,
            },
        );
        chain.set_account(
            AUTHORITY_F,
            Account {
                providers: 1,
                ..Account::default()
            },
        );
        let mut world = Self {
            fx,
            chain,
            pre: None,
            steps: Vec::new(),
        };
        let always = Active {
            from_ms: 0,
            until_ms: None,
        };
        world.call(
            Origin::Root,
            Call::SetFormat {
                format: vos_statement::vos_pvm_final_verifier::masked::FORMAT,
                active: always,
            },
            Expect::Ok,
        );
        for input in [&fx.valid, &fx.rootless] {
            let info = ProgramInfo {
                handler: Handler::Record,
                venue_bound: input.pin.venue_bound,
                active: always,
            };
            world.call(
                Origin::Root,
                Call::SetProgram {
                    program: input.pin.program.0,
                    info: Some(info),
                },
                Expect::Ok,
            );
        }
        world
    }

    fn constants(&self) -> &Constants {
        &self.chain.constants
    }

    /// The setup done: the pre-state taken, and every later step recorded.
    fn begin(&mut self) {
        self.pre = Some(pre(&self.chain));
    }

    fn at(&mut self, now_ms: u64) {
        self.chain.set_now(now_ms);
    }

    fn call(&mut self, origin: Origin, call: Call, expect: Expect) -> Outcome {
        let bytes = RuntimeCall::Spaces(call).encode();
        self.raw(origin, bytes, expect)
    }

    fn raw(&mut self, origin: Origin, bytes: Vec<u8>, expect: Expect) -> Outcome {
        let before = self.chain.clone();
        let outcome = self.chain.submit(origin, &bytes);
        assert!(
            expect.holds(&outcome.verdict),
            "step {} expected {expect:?}, got {:?}",
            self.steps.len(),
            outcome.verdict
        );
        if self.pre.is_some() {
            let parts = parts(&bytes, &self.fx.files);
            self.steps.push(step(
                &before,
                &self.chain,
                Some(origin),
                Some(parts),
                Some(&outcome),
            ));
        }
        outcome
    }

    fn on_idle(&mut self) {
        let before = self.chain.clone();
        self.chain.on_idle();
        self.steps
            .push(step(&before, &self.chain, None, None, None));
    }

    fn finish(self, id: &str, title: &str) -> Vector {
        Vector {
            id: id.to_string(),
            title: title.to_string(),
            fees: self.chain.fees(),
            pre: self.pre.expect("begun"),
            steps: self.steps,
        }
    }

    fn has(&self, key: &[u8]) -> bool {
        self.chain.storage().contains_key(key)
    }

    /// `space`'s root `root` at `window`, signed by the key of `seed`.
    fn anchor_arg(&self, space: Space, window: u64, root: [u8; 32], seed: u8) -> AnchorArg {
        let digest = vos_anchor::anchor_digest(
            &self.constants().venue,
            &SpaceId(space),
            window,
            RootKind::Space,
            &root,
        );
        AnchorArg {
            space,
            window,
            kind: 0,
            root,
            signer: public(seed),
            signature: signing(seed).sign(&digest).to_bytes(),
        }
    }

    fn anchor(
        &mut self,
        by: AccountId,
        space: Space,
        window: u64,
        root: [u8; 32],
        seed: u8,
        expect: Expect,
    ) -> Outcome {
        let anchor = self.anchor_arg(space, window, root, seed);
        self.call(Origin::Signed(by), Call::Anchor { anchor }, expect)
    }

    /// `F`'s two roots the fixtures' statement reads, anchored by its key.
    fn anchor_f(&mut self) {
        for root in self.fx.statement().roots.clone() {
            let outcome = self.anchor(AUTHORITY_F, F, root.window, root.root, KEY_F, Expect::Ok);
            assert!(matches!(outcome.events[..], [Event::Anchored { .. }]));
        }
    }

    fn submit(
        &mut self,
        by: AccountId,
        payer: Space,
        statement: Vec<u8>,
        proof: Vec<u8>,
        expect: Expect,
    ) -> Outcome {
        self.call(
            Origin::Signed(by),
            Call::Submit {
                payer,
                statement,
                proof,
            },
            expect,
        )
    }

    /// `statement` submitted by `F`'s authority with `proof`: refused with
    /// `code`, and its deposit forfeited unless it is a repeat.
    fn refused(&mut self, statement: Vec<u8>, proof: Vec<u8>, code: u32) {
        let outcome = self.submit(AUTHORITY_F, F, statement, proof, Expect::Ok);
        let forfeited = code != vos_statement::Refusal::Repeated.code();
        match &outcome.events[..] {
            [Event::Refused { code: got, .. }] => assert!(!forfeited && *got == code),
            [
                Event::Refused { code: got, .. },
                Event::DepositForfeited { .. },
            ] => {
                assert!(
                    forfeited && *got == code,
                    "refused {got:#x}, expected {code:#x}"
                )
            }
            events => panic!("refusal {code:#x}: {events:?}"),
        }
    }

    /// The fixtures' statement `S`, accepted.
    fn accept(&mut self, by: AccountId, payer: Space, rootless: bool) {
        let (input, proof) = if rootless {
            (&self.fx.rootless, self.fx.rootless_proof.clone())
        } else {
            (&self.fx.valid, self.fx.proof.clone())
        };
        let statement = input.statement.clone();
        let outcome = self.submit(by, payer, statement.encode(), proof, Expect::Ok);
        match &outcome.events[..] {
            [
                Event::Accepted {
                    id,
                    payer: paid,
                    space,
                    ..
                },
            ] => {
                assert_eq!(*id, statement.id().0);
                assert_eq!((*paid, *space), (payer, statement.space.0));
            }
            events => panic!("not accepted: {events:?}"),
        }
    }

    /// `genesis` registered by the operator under `CONTROLLER` from `start`,
    /// founder 1 signing.
    fn register(&mut self, genesis: &SpaceGenesis, start: u64, expect: Expect) -> Outcome {
        let call = self.registration(genesis, start, start, KEY_1, KEY_1);
        self.call(Origin::Signed(OPERATOR), call, expect)
    }

    /// A registration of `genesis` claiming `founder`'s key, signed by
    /// `signer` over `signed` as its first window, submitted with `start`.
    fn registration(
        &self,
        genesis: &SpaceGenesis,
        start: u64,
        signed: u64,
        founder: u8,
        signer: u8,
    ) -> Call {
        let digest = vos_anchor::register_digest(
            &self.constants().venue,
            &vos_anchor::space_id(genesis),
            &CONTROLLER,
            signed,
        );
        Call::Register {
            genesis: genesis.encode(),
            controller: CONTROLLER,
            start_window: start,
            founder_key: public(founder),
            founder_sig: signing(signer).sign(&digest).to_bytes(),
        }
    }

    /// `B` registered from `B_START`, `who` its authority paired with the
    /// key of `seed`.
    fn with_b(&mut self, who: AccountId, seed: u8) {
        self.register(&b_genesis(), B_START, Expect::Ok);
        self.add_authority(who, Some(public(seed)), Expect::Ok);
    }

    fn add_authority(&mut self, who: AccountId, key: Option<[u8; 32]>, expect: Expect) -> Outcome {
        let call = Call::AddAuthority {
            space: b(),
            who,
            anchor_key: key,
        };
        let controller = self
            .chain
            .space(&b())
            .map_or(CONTROLLER, |info| info.controller);
        self.call(Origin::Signed(controller), call, expect)
    }

    fn controller(&mut self, call: Call, expect: Expect) -> Outcome {
        self.call(Origin::Signed(CONTROLLER), call, expect)
    }
}

/// A statement of `space` reading its root `root` at `window`, of the
/// fixtures' program and venue: refused before its proof.
fn statement_of(fx: &Fixtures, space: Space, window: u64, root: [u8; 32]) -> Vec<u8> {
    Statement {
        space: SpaceId(space),
        roots: vec![RootRead {
            kind: RootKind::Space,
            space: SpaceId(space),
            window,
            root,
        }],
        ..fx.statement().clone()
    }
    .encode()
}

fn root(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn g1(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    // Window 1000 of `B`'s clock, so its earliest registrable start,
    // `now_w − MaxRootAge / length_ms`, is window 856.
    let now = B_CLOCK.boundary(999).unwrap() + 5_000;
    w.at(now);
    let now_w = B_CLOCK.window(now).unwrap();
    assert_eq!(now_w, 1_000);
    let earliest = now_w - w.constants().max_root_age_ms / B_CLOCK.length_ms;
    assert_eq!(earliest, 856);
    let genesis = b_genesis();
    // Two more spaces, their sovereigns funded, for the bounds' edges.
    let (latest, oldest) = (genesis_of(0xb5), genesis_of(0xb6));
    for edge in [&latest, &oldest] {
        let sovereign = w.constants().sovereign(&space_of(edge));
        w.chain.set_account(sovereign, funded(100 * UNITS));
    }
    w.begin();
    // The founder's signature over window 1000, resubmitted at 999.
    let resubmitted = w.registration(&genesis, now_w - 1, now_w, KEY_1, KEY_1);
    w.call(
        Origin::Signed(OPERATOR),
        resubmitted,
        Expect::Err(Error::BadFounder),
    );
    w.register(&genesis, now_w + 2, Expect::Err(Error::BadStartWindow));
    w.register(&genesis, earliest - 1, Expect::Err(Error::BadStartWindow));
    let outcome = w.register(&genesis, now_w, Expect::Ok);
    let sovereign = w.constants().sovereign(&b());
    assert_eq!(
        sovereign.to_vec(),
        [&b"modlkv/space"[..], &b()[..20]].concat(),
        "the sovereign address"
    );
    match &outcome.events[..] {
        [
            Event::SpaceRegistered {
                space,
                sovereign: paid_by,
                ..
            },
        ] => {
            assert_eq!((*space, *paid_by), (b(), sovereign))
        }
        events => panic!("{events:?}"),
    }
    let held = w.chain.account(&sovereign).held_registration;
    assert_eq!(held, w.constants().registration_deposit);
    w.register(&genesis, now_w, Expect::Err(Error::SpaceExists));
    w.register(&latest, now_w + 1, Expect::Ok);
    w.register(&oldest, earliest, Expect::Ok);
    w.finish(
        "G1",
        "register: the fixture genesis's space registered, its sovereign address \
         `modl ‖ kv/space ‖ space[..20]`, the deposit held; refused: the founder's signature \
         resubmitted with another start_window (BadFounder), a start_window past now_w + 1 or \
         before now_w − MaxRootAge / length_ms (BadStartWindow), a second registration \
         (SpaceExists); the edges taken, a start_window of now_w + 1 and of \
         now_w − MaxRootAge / length_ms",
    )
}

fn g2(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.register(&b_genesis(), B_START, Expect::Ok);
    w.begin();
    w.add_authority(AUTHORITY_1, Some(public(KEY_3)), Expect::Ok);
    w.add_authority(AUTHORITY_2, None, Expect::Ok);
    assert_eq!(w.chain.account(&AUTHORITY_1).providers, 1);
    let by_stranger = Call::AddAuthority {
        space: b(),
        who: AUTHORITY_3,
        anchor_key: None,
    };
    w.call(
        Origin::Signed(STRANGER),
        by_stranger,
        Expect::Err(Error::NotController),
    );
    let unknown = Call::AddAuthority {
        space: [0xee; 32],
        who: AUTHORITY_3,
        anchor_key: None,
    };
    w.controller(unknown, Expect::Err(Error::UnknownSpace));
    let remove = Call::RemoveAuthority {
        space: b(),
        who: AUTHORITY_1,
    };
    w.controller(remove.clone(), Expect::Ok);
    assert!(!w.has(&keys::anchor_keys(&b(), &public(KEY_3))));
    assert_eq!(w.chain.account(&AUTHORITY_1).providers, 0);
    w.controller(remove, Expect::Err(Error::NotAuthority));
    w.finish(
        "G2",
        "add_authority (with a paired anchor key, and without), remove_authority (its key \
         leaves AnchorKeys), each account's providers; refused: a non-controller \
         (NotController), an unknown space (UnknownSpace), a second removal (NotAuthority)",
    )
}

fn g3(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    w.begin();
    w.anchor(AUTHORITY_1, b(), 35, root(0x35), KEY_3, Expect::Ok);
    // Any signed account may hand in an anchor a listed key signed.
    w.anchor(STRANGER, b(), 37, root(0x37), KEY_1, Expect::Ok);
    let last: Option<Vec<u8>> = w.chain.storage().get(&keys::last(&b(), 0)).cloned();
    assert_eq!(last, Some(37u64.encode()));
    w.finish(
        "G3",
        "anchor at w, then w + 2 (a gap), by an authority and by any signed account; Last \
         follows",
    )
}

fn g4(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    // Window 30's root just past MaxRootAge.
    let now = B_CLOCK.boundary(B_START).unwrap() + w.constants().max_root_age_ms + 1;
    w.at(now);
    w.begin();
    let by = AUTHORITY_1;
    w.anchor(
        by,
        b(),
        B_START - 1,
        root(1),
        KEY_3,
        Expect::Err(Error::OutOfRange),
    );
    w.anchor(
        by,
        b(),
        B_START,
        root(2),
        KEY_3,
        Expect::Err(Error::WindowTooOld),
    );
    // Window 31's root exactly MaxRootAge old: taken.
    let now = B_CLOCK.boundary(B_START + 1).unwrap() + w.constants().max_root_age_ms;
    w.at(now);
    let now_w = B_CLOCK.window(now).unwrap();
    assert_eq!(now_w, 176);
    w.anchor(by, b(), B_START + 1, root(3), KEY_3, Expect::Ok);
    w.anchor(
        by,
        b(),
        B_START + 1,
        root(3),
        KEY_3,
        Expect::Err(Error::AlreadyAnchored),
    );
    w.anchor(
        by,
        b(),
        B_START,
        root(2),
        KEY_3,
        Expect::Err(Error::WindowNotAfterLast),
    );
    // The open window, then a later one.
    w.anchor(
        by,
        b(),
        now_w,
        root(4),
        KEY_3,
        Expect::Err(Error::WindowInFuture),
    );
    w.anchor(
        by,
        b(),
        now_w + 5,
        root(5),
        KEY_3,
        Expect::Err(Error::WindowInFuture),
    );
    // The venue's time past the open window's boundary: the same anchor
    // resubmitted is taken.
    w.at(B_CLOCK.boundary(now_w).unwrap());
    let outcome = w.anchor(by, b(), now_w, root(4), KEY_3, Expect::Ok);
    assert!(matches!(outcome.events[..], [Event::Anchored { window, .. }] if window == now_w));
    let mut bad = w.anchor_arg(b(), now_w + 1, root(6), KEY_3);
    bad.signature[0] ^= 1;
    w.call(
        Origin::Signed(by),
        Call::Anchor { anchor: bad },
        Expect::Err(Error::BadAnchorSignature),
    );
    let mut kind = w.anchor_arg(b(), now_w + 1, root(6), KEY_3);
    kind.kind = 1;
    w.call(
        Origin::Signed(by),
        Call::Anchor { anchor: kind },
        Expect::Err(Error::BadKind),
    );
    w.anchor(
        by,
        b(),
        now_w + 1,
        root(6),
        KEY_9,
        Expect::Err(Error::UnknownAnchorKey),
    );
    w.anchor(
        by,
        [0xee; 32],
        now_w - 1,
        root(6),
        KEY_3,
        Expect::Err(Error::UnknownSpace),
    );
    // The venue's time before the space's origin.
    w.at(B_CLOCK.origin_ms - 1);
    w.anchor(
        by,
        b(),
        now_w + 1,
        root(6),
        KEY_3,
        Expect::Err(Error::BadClock),
    );
    w.finish(
        "G4",
        "anchor refusals: before the space's start (OutOfRange), older than MaxRootAge \
         (WindowTooOld), exactly MaxRootAge old taken, the same root again (AlreadyAnchored), a stale w ≤ Last \
         (WindowNotAfterLast), the open window now_w and a later one (WindowInFuture), then \
         now_ms at B_w and the same anchor resubmitted (Anchored); a bad signature \
         (BadAnchorSignature), kind 1 (BadKind), an unlisted key (UnknownAnchorKey), an unknown \
         space (UnknownSpace), now_ms before the origin (BadClock)",
    )
}

fn g5(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    w.begin();
    let resume = Call::Resume { space: b() };
    // One key signs two roots of window 35.
    w.anchor(AUTHORITY_1, b(), 35, root(0x0a), KEY_1, Expect::Ok);
    let outcome = w.anchor(STRANGER, b(), 35, root(0x0b), KEY_1, Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [Event::Equivocated { first_signer, second_signer, .. }, Event::SpaceSuspended { .. }]
            if first_signer == public(KEY_1) && second_signer == public(KEY_1)
    ));
    w.anchor(
        AUTHORITY_1,
        b(),
        36,
        root(0x0c),
        KEY_2,
        Expect::Err(Error::SpaceNotActive),
    );
    w.controller(resume.clone(), Expect::Err(Error::StillEquivocating));
    let remove_1 = Call::RemoveAnchorKey {
        space: b(),
        key: public(KEY_1),
    };
    w.controller(remove_1, Expect::Ok);
    w.controller(resume.clone(), Expect::Ok);
    assert!(!w.has(&keys::equivocations(&b(), 0, 35)));
    // Two keys, the failover case.
    w.anchor(AUTHORITY_1, b(), 37, root(0x0d), KEY_2, Expect::Ok);
    let outcome = w.anchor(AUTHORITY_1, b(), 37, root(0x0e), KEY_3, Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [Event::Equivocated { first_signer, second_signer, .. }, Event::SpaceSuspended { .. }]
            if first_signer == public(KEY_2) && second_signer == public(KEY_3)
    ));
    w.controller(resume.clone(), Expect::Err(Error::StillEquivocating));
    let remove_2 = Call::RemoveAnchorKey {
        space: b(),
        key: public(KEY_2),
    };
    w.controller(remove_2, Expect::Ok);
    w.controller(resume.clone(), Expect::Err(Error::StillEquivocating));
    let remove_authority = Call::RemoveAuthority {
        space: b(),
        who: AUTHORITY_1,
    };
    w.controller(remove_authority, Expect::Ok);
    w.controller(resume.clone(), Expect::Ok);
    // Two fresh keys, the second signer's removed first: the first's still
    // listed holds the suspension.
    w.add_authority(AUTHORITY_2, Some(public(KEY_5)), Expect::Ok);
    w.add_authority(AUTHORITY_3, Some(public(KEY_6)), Expect::Ok);
    w.anchor(AUTHORITY_2, b(), 39, root(0x1a), KEY_5, Expect::Ok);
    w.anchor(AUTHORITY_3, b(), 39, root(0x1b), KEY_6, Expect::Ok);
    let remove = |who| Call::RemoveAuthority { space: b(), who };
    w.controller(remove(AUTHORITY_3), Expect::Ok);
    w.controller(resume.clone(), Expect::Err(Error::StillEquivocating));
    w.controller(remove(AUTHORITY_2), Expect::Ok);
    w.controller(resume, Expect::Ok);
    w.finish(
        "G5",
        "equivocation by one key: Equivocated and SpaceSuspended, the space's anchors refused \
         (SpaceNotActive), resume refused (StillEquivocating) until the key is removed; by two \
         keys (the failover case): Evidence names both, resume refused until both are removed \
         (the second with its authority); again with two fresh keys, the second signer's \
         removed first, resume refused until the first's is too",
    )
}

fn g6(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.begin();
    w.anchor_f();
    w.accept(AUTHORITY_F, F, false);
    let id = fx.statement().id().0;
    let expiry = vos_statement::seen_expiry(fx.statement(), &F_CLOCK);
    assert_eq!(
        w.chain.storage().get(&keys::seen(&id)),
        Some(&expiry.encode())
    );
    w.finish(
        "G6",
        "submit of the masked format-39 fixture: its two roots anchored, then Accepted { id }, \
         Seen[id] its newest root's B_w + MaxRootAge, the deposit held and released",
    )
}

/// G7's pre-state: the world, `F`'s two roots anchored.
pub fn g7_chain(fx: &Fixtures) -> Chain {
    let mut w = World::new(fx, false);
    w.anchor_f();
    w.chain
}

fn g7(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.anchor_f();
    w.begin();
    let s = fx.statement();
    let proof = &fx.proof;
    let mut truncated = s.encode();
    truncated.pop();
    w.refused(truncated, proof.clone(), 1);
    let changed = |change: &dyn Fn(&mut Statement)| {
        let mut statement = s.clone();
        change(&mut statement);
        statement.encode()
    };
    w.refused(changed(&|s| s.format = 30), proof.clone(), 2);
    w.refused(changed(&|s| s.program.0[0] += 1), proof.clone(), 3);
    w.refused(
        changed(&|s| s.space = SpaceId([0xb2; 32])),
        proof.clone(),
        4,
    );
    let unanchored = RootRead {
        window: 40,
        root: root(0x40),
        ..s.roots[0]
    };
    w.refused(changed(&|s| s.roots[0] = unanchored), proof.clone(), 5);
    w.refused(changed(&|s| s.public_args[0] ^= 1), proof.clone(), 7);
    assert_eq!(fx.tampered_code >> 8, 1);
    w.refused(s.encode(), fx.tampered.clone(), fx.tampered_code);
    // The activation windows: the fixture's own format and program stored,
    // but not active now.
    let format = vos_statement::vos_pvm_final_verifier::masked::FORMAT;
    let set_format = |from_ms, until_ms| Call::SetFormat {
        format,
        active: Active { from_ms, until_ms },
    };
    let set_program = |from_ms, until_ms| Call::SetProgram {
        program: fx.valid.pin.program.0,
        info: Some(ProgramInfo {
            handler: Handler::Record,
            venue_bound: fx.valid.pin.venue_bound,
            active: Active { from_ms, until_ms },
        }),
    };
    let (later, latest) = (NOW + 60_000, NOW + 120_000);
    w.call(Origin::Root, set_format(0, Some(NOW)), Expect::Ok);
    w.refused(s.encode(), proof.clone(), 2);
    w.call(Origin::Root, set_format(later, None), Expect::Ok);
    w.refused(s.encode(), proof.clone(), 2);
    w.at(later);
    w.call(Origin::Root, set_program(0, Some(later)), Expect::Ok);
    w.refused(s.encode(), proof.clone(), 3);
    w.call(Origin::Root, set_program(latest, None), Expect::Ok);
    w.refused(s.encode(), proof.clone(), 3);
    w.at(latest);
    w.accept(AUTHORITY_F, F, false);
    w.finish(
        "G7",
        "one mutant per refusal class, each Refused { code } and DepositForfeited: 1 (the \
         statement cut short), 2 (format 30), 3 (a program not in Programs), 4 (a space not its \
         roots'), 5 (a root not anchored), 7 (another venue's statement), 0x1xx (the proof's \
         byte flipped); 6 is G8's, its deposit released. Then the statement itself against \
         activation windows: 2 while Formats[39].until_ms is now (retired), and while its \
         from_ms is past now; 3 while its program's until_ms is now, and while its from_ms is \
         past now; accepted once now reaches it",
    )
}

fn g8(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.anchor_f();
    w.begin();
    w.accept(AUTHORITY_F, F, false);
    w.refused(fx.statement().encode(), fx.proof.clone(), 6);
    w.finish(
        "G8",
        "the same statement twice: Accepted, then Refused { 6 } with the deposit released",
    )
}

fn g9(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.anchor_f();
    w.begin();
    w.accept(AUTHORITY_F, F, true);
    w.accept(AUTHORITY_F, F, false);
    let past = F_CLOCK.boundary(42).unwrap() + w.constants().max_root_age_ms + 1;
    w.at(past);
    // Before the cursor prunes them: the anchors are held but stale.
    w.refused(fx.statement().encode(), fx.proof.clone(), 5);
    w.on_idle();
    assert!(!w.has(&keys::seen(&fx.statement().id().0)));
    assert!(w.has(&keys::seen(&fx.rootless.statement.id().0)));
    w.refused(fx.rootless.statement.encode(), fx.rootless_proof.clone(), 6);
    w.refused(fx.statement().encode(), fx.proof.clone(), 5);
    w.finish(
        "G9",
        "a rootless and a rooted statement accepted; at MaxRootAge + 1 past the newest root's \
         B_w, the rooted one resubmitted before on_idle refused 5 (its anchors held but past \
         MaxRootAge); on_idle prunes the rooted Seen entry and keeps the rootless one; resubmitted, the \
         rootless is refused 6 (released) and the rooted 5 (forfeited)",
    )
}

fn g10(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    // A space whose sovereign, once registered, cannot hold a deposit.
    let poor = genesis_of(0xc1);
    let constants = w.constants().clone();
    let free = constants.registration_deposit
        + constants.existential_deposit
        + constants.submit_deposit / 2;
    w.chain
        .set_account(constants.sovereign(&space_of(&poor)), funded(free));
    w.register(&poor, B_START, Expect::Ok);
    let add = Call::AddAuthority {
        space: space_of(&poor),
        who: AUTHORITY_2,
        anchor_key: None,
    };
    w.controller(add, Expect::Ok);
    w.begin();
    let s = fx.statement().encode();
    w.submit(
        AUTHORITY_2,
        space_of(&poor),
        s.clone(),
        fx.proof.clone(),
        Expect::Err(Error::InsufficientSovereignBalance),
    );
    w.submit(
        STRANGER,
        F,
        s.clone(),
        fx.proof.clone(),
        Expect::Err(Error::NotAuthority),
    );
    let pause = |flags| Call::SetPaused { flags };
    w.call(
        Origin::Signed(STRANGER),
        pause(PAUSE_SUBMIT),
        Expect::BadOrigin,
    );
    w.call(Origin::Emergency, pause(PAUSE_SUBMIT), Expect::Ok);
    w.submit(
        AUTHORITY_F,
        F,
        s,
        fx.proof.clone(),
        Expect::Err(Error::Paused),
    );
    let roots = fx.statement().roots.clone();
    w.anchor(
        AUTHORITY_F,
        F,
        roots[0].window,
        roots[0].root,
        KEY_F,
        Expect::Ok,
    );
    w.call(Origin::Emergency, pause(PAUSE_ANCHOR), Expect::Ok);
    w.anchor(
        AUTHORITY_F,
        F,
        roots[1].window,
        roots[1].root,
        KEY_F,
        Expect::Err(Error::Paused),
    );
    w.call(Origin::Emergency, pause(PAUSE_REGISTER), Expect::Ok);
    w.register(&b_genesis(), B_START, Expect::Err(Error::Paused));
    w.call(Origin::Root, pause(0), Expect::Ok);
    w.anchor(
        AUTHORITY_F,
        F,
        roots[1].window,
        roots[1].root,
        KEY_F,
        Expect::Ok,
    );
    w.register(&b_genesis(), B_START, Expect::Ok);
    w.finish(
        "G10",
        "a submit whose sovereign cannot hold the deposit (InsufficientSovereignBalance, nothing \
         moved); a non-authority's submit (NotAuthority); set_paused by a signed account (BadOrigin); \
         each pause flag, by the emergency origin, refusing its call (Paused): bit 0 submit, \
         bit 1 anchor, bit 2 register, each other call unpaused; cleared by Root",
    )
}

fn g11(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.begin();
    let delay = w.constants().program_change_delay_ms;
    let at = NOW + delay;
    let info = |from_ms, until_ms| ProgramInfo {
        handler: Handler::Record,
        venue_bound: false,
        active: Active { from_ms, until_ms },
    };
    let set = |program: [u32; 8], info| Call::SetProgram { program, info };
    let (p1, p2) = ([1, 2, 3, 4, 5, 6, 7, 8], [9; 8]);
    w.call(
        Origin::Programs,
        set(p1, Some(info(at - 1, None))),
        Expect::Err(Error::TooEarly),
    );
    w.call(Origin::Programs, set(p1, Some(info(at, None))), Expect::Ok);
    w.call(
        Origin::Programs,
        set(p1, Some(info(at, Some(at - 1)))),
        Expect::Err(Error::TooEarly),
    );
    w.call(Origin::Root, set(p2, Some(info(NOW, None))), Expect::Ok);
    w.call(Origin::Signed(STRANGER), set(p2, None), Expect::BadOrigin);
    w.call(Origin::Programs, set(p2, None), Expect::Ok);
    let stored = w.chain.storage().get(&keys::programs(&p2)).cloned();
    assert_eq!(
        stored,
        Some(info(NOW, Some(at)).encode()),
        "removed at now + delay"
    );
    w.call(Origin::Root, set(p2, None), Expect::Ok);
    assert!(!w.has(&keys::programs(&p2)));
    // `venue_bound` switched on an active program: not only `until_ms`.
    let p3 = [11; 8];
    let bound = |venue_bound| ProgramInfo {
        venue_bound,
        ..info(NOW, None)
    };
    w.call(Origin::Root, set(p3, Some(bound(true))), Expect::Ok);
    w.call(
        Origin::Programs,
        set(p3, Some(bound(false))),
        Expect::Err(Error::TooEarly),
    );
    // A handler other than `Record` does not decode.
    let mut bytes = RuntimeCall::Spaces(set(p1, Some(info(at, None)))).encode();
    let handler = 2 + 32 + 1;
    assert_eq!(bytes[handler], Handler::Record as u8);
    bytes[handler] = 1;
    w.raw(Origin::Root, bytes, Expect::Undecodable);
    w.finish(
        "G11",
        "set_program by ProgramsOrigin: from_ms before now + delay, or an until_ms set before \
         it, refused (TooEarly); at now + delay taken; Root at once; a signed account \
         (BadOrigin); a removal by ProgramsOrigin sets until_ms = now + delay, Root's removes \
         at once; a change other than setting or shortening until_ms (venue_bound on an active \
         program) needs from_ms ≥ now + delay (TooEarly); a handler other than Record does not \
         decode",
    )
}

fn g12(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, true);
    w.with_b(AUTHORITY_1, KEY_3);
    // `B`'s sovereign holds its fee and half a deposit.
    let sovereign = w.constants().sovereign(&b());
    let mut account = w.chain.account(&sovereign);
    account.free = w.constants().fee_bound + w.constants().submit_deposit / 2;
    w.chain.set_account(sovereign, account);
    w.begin();
    let garbage = vec![0];
    let outcome = w.submit(
        AUTHORITY_1,
        b(),
        garbage.clone(),
        Vec::new(),
        Expect::Payment,
    );
    assert_eq!(outcome.payer, None);
    let outcome = w.anchor(AUTHORITY_1, b(), 35, root(0x35), KEY_3, Expect::Ok);
    assert_eq!(outcome.payer, Some(Payer::Sovereign));
    let outcome = w.anchor(STRANGER, b(), 36, root(0x36), KEY_1, Expect::Ok);
    assert_eq!(outcome.payer, Some(Payer::Signer));
    let outcome = w.submit(AUTHORITY_F, F, garbage.clone(), Vec::new(), Expect::Ok);
    assert_eq!(outcome.payer, Some(Payer::Sovereign));
    let outcome = w.submit(
        STRANGER,
        F,
        garbage,
        Vec::new(),
        Expect::Err(Error::NotAuthority),
    );
    assert_eq!(outcome.payer, Some(Payer::Signer));
    w.finish(
        "G12",
        "fees, signs only: a submit whose sovereign cannot cover its fee and deposit refused in \
         validate (InvalidTransaction::Payment), nothing paid; an authority's anchor and submit \
         paid by the sovereign account, the authority unchanged; a non-authority's anchor and \
         submit paid by the signer",
    )
}

fn g13(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, true);
    w.with_b(AUTHORITY_1, KEY_3);
    w.anchor_f();
    w.begin();
    let constants = w.constants().clone();
    let each = constants.submit_deposit + constants.fee_bound;
    assert_eq!(constants.default_spend_per_window, 8 * each);
    // Statements that do not decode: each refused 1, its deposit
    // forfeited, so each spends a fee and a deposit.
    for n in 0..8u8 {
        w.submit(AUTHORITY_1, b(), vec![n], Vec::new(), Expect::Ok);
    }
    let sovereign = constants.sovereign(&b());
    let before = w.chain.account(&sovereign);
    w.submit(AUTHORITY_1, b(), vec![8], Vec::new(), Expect::Payment);
    assert_eq!(w.chain.account(&sovereign), before, "untouched");
    // The next window, by the venue's time.
    let next = B_CLOCK.boundary(B_CLOCK.window(NOW).unwrap()).unwrap();
    w.at(next);
    w.submit(AUTHORITY_1, b(), vec![8], Vec::new(), Expect::Ok);
    let budget = Call::SetBudget {
        space: b(),
        max_spend_per_window: 2 * each,
    };
    w.controller(budget, Expect::Ok);
    w.submit(AUTHORITY_1, b(), vec![9], Vec::new(), Expect::Ok);
    w.submit(AUTHORITY_1, b(), vec![10], Vec::new(), Expect::Payment);
    // An accepted submit's deposit, released, is credited back: at one
    // submit and one fee a window, the accepted one leaves room for one
    // forfeiting submit, which without the credit would not fit.
    let budget = Call::SetBudget {
        space: b(),
        max_spend_per_window: each + constants.fee_bound,
    };
    w.controller(budget, Expect::Ok);
    w.at(B_CLOCK.boundary(B_CLOCK.window(next).unwrap()).unwrap());
    w.accept(AUTHORITY_1, b(), false);
    w.submit(AUTHORITY_1, b(), vec![11], Vec::new(), Expect::Ok);
    w.submit(AUTHORITY_1, b(), vec![12], Vec::new(), Expect::Payment);
    w.finish(
        "G13",
        "the budget, fees: at 8 × (SubmitDeposit + FeeBound) a window, eight forfeiting \
         submits taken and the ninth refused in validate (InvalidTransaction::Payment; \
         OverBudget in the fallback), the sovereign untouched; the next window resets it; \
         set_budget to two submits' worth, the window's second taken and its third refused; \
         set_budget to SubmitDeposit + 2 × FeeBound, the next window's accepted submit, its \
         deposit credited back, leaving room for one forfeiting submit, and the next refused. \
         The model charges each fee at FeeBound, so eight fill the budget exactly",
    )
}

fn g14(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    w.anchor(AUTHORITY_1, b(), 35, root(0x35), KEY_3, Expect::Ok);
    w.begin();
    let now_w = B_CLOCK.window(NOW).unwrap();
    let migrate = |from_window| Call::Migrate {
        space: b(),
        to: [0x77; 32],
        from_window,
    };
    let here = Call::Migrate {
        space: b(),
        to: w.constants().venue.0,
        from_window: now_w + 1,
    };
    w.controller(here, Expect::Err(Error::SameVenue));
    w.controller(migrate(now_w), Expect::Err(Error::OutOfRange));
    w.controller(migrate(now_w + 1), Expect::Ok);
    w.controller(migrate(now_w + 2), Expect::Err(Error::AlreadyMigrated));
    w.at(B_CLOCK.boundary(now_w + 1).unwrap());
    w.anchor(
        AUTHORITY_1,
        b(),
        now_w + 1,
        root(1),
        KEY_3,
        Expect::Err(Error::OutOfRange),
    );
    w.anchor(AUTHORITY_1, b(), now_w, root(2), KEY_3, Expect::Ok);
    let past_end = statement_of(fx, b(), now_w + 1, root(1));
    let outcome = w.submit(AUTHORITY_1, b(), past_end, Vec::new(), Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [
            Event::Refused { code: 5, .. },
            Event::DepositForfeited { .. }
        ]
    ));
    w.finish(
        "G14",
        "migrate: to this venue refused (SameVenue); from a window before the next refused \
         (OutOfRange), from the next taken \
         (end_window set), a second refused (AlreadyMigrated); an anchor at w ≥ from_window \
         refused (OutOfRange), the window before it anchored; a statement whose root's window \
         is ≥ end_window refused 5",
    )
}

fn g15(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    w.add_authority(AUTHORITY_3, None, Expect::Ok);
    let mut account = w.chain.account(&AUTHORITY_3);
    account.consumers = 1;
    w.chain.set_account(AUTHORITY_3, account);
    w.begin();
    let set = Call::SetController {
        space: b(),
        controller: CONTROLLER_2,
    };
    w.controller(set, Expect::Ok);
    let budget = Call::SetBudget {
        space: b(),
        max_spend_per_window: 1,
    };
    w.controller(budget, Expect::Err(Error::NotController));
    let by_2 = |w: &mut World, call, expect| w.call(Origin::Signed(CONTROLLER_2), call, expect);
    let add = |who, key: u8| Call::AddAuthority {
        space: b(),
        who,
        anchor_key: Some(public(key)),
    };
    by_2(&mut w, add(AUTHORITY_1, KEY_4), Expect::Ok);
    assert!(!w.has(&keys::anchor_keys(&b(), &public(KEY_3))));
    by_2(
        &mut w,
        add(AUTHORITY_2, KEY_4),
        Expect::Err(Error::AnchorKeyInUse),
    );
    by_2(&mut w, add(AUTHORITY_2, KEY_1), Expect::Ok);
    let remove = |key: u8| Call::RemoveAnchorKey {
        space: b(),
        key: public(key),
    };
    by_2(&mut w, remove(KEY_4), Expect::Err(Error::AnchorKeyInUse));
    by_2(&mut w, remove(KEY_2), Expect::Ok);
    by_2(&mut w, remove(KEY_2), Expect::Err(Error::UnknownAnchorKey));
    let remove_3 = Call::RemoveAuthority {
        space: b(),
        who: AUTHORITY_3,
    };
    by_2(&mut w, remove_3, Expect::Ok);
    assert_eq!(
        w.chain.account(&AUTHORITY_3).providers,
        1,
        "a consumer keeps it"
    );
    w.finish(
        "G15",
        "the controller and keys: set_controller (the old controller then NotController); \
         add_authority updating a paired key (the old key leaves AnchorKeys); a key paired \
         elsewhere (AnchorKeyInUse); an unpaired founding key paired; remove_anchor_key of a \
         paired key (AnchorKeyInUse), of an unpaired founding key (removed), of an unlisted one \
         (UnknownAnchorKey); remove_authority with a consumer on the account, its provider kept \
         (best effort)",
    )
}

fn g16(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    w.anchor_f();
    w.begin();
    let transfer = RuntimeCall::Balances(BalancesCall::TransferKeepAlive {
        dest: MultiAddress::Id(RECIPIENT),
        value: 5 * UNITS,
    });
    assert_eq!(transfer.encode()[0], BALANCES_INDEX);
    let dispatch = Call::DispatchAsSovereign {
        space: b(),
        call: Box::new(transfer),
    };
    let outcome = w.controller(dispatch, Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [Event::SovereignDispatched { result: Ok(()), .. }]
    ));
    let status = |space, blocked| Call::SetStatus { space, blocked };
    w.call(
        Origin::Signed(CONTROLLER),
        status(b(), true),
        Expect::BadOrigin,
    );
    w.call(Origin::Status, status(b(), true), Expect::Ok);
    w.submit(
        AUTHORITY_1,
        b(),
        vec![0],
        Vec::new(),
        Expect::Err(Error::SpaceNotActive),
    );
    w.anchor(
        AUTHORITY_1,
        b(),
        35,
        root(0x35),
        KEY_3,
        Expect::Err(Error::SpaceNotActive),
    );
    w.call(Origin::Status, status(b(), false), Expect::Ok);
    // A blocked space's roots are not anchored (§13, question 11): `S`,
    // paid for by `B`, refused 5 while `F` is blocked.
    w.call(Origin::Status, status(F, true), Expect::Ok);
    let s = fx.statement().encode();
    let outcome = w.submit(AUTHORITY_1, b(), s, fx.proof.clone(), Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [
            Event::Refused { code: 5, .. },
            Event::DepositForfeited { .. }
        ]
    ));
    w.call(Origin::Status, status(F, false), Expect::Ok);
    // Blocked, then unblocked with equivocations: suspended.
    w.anchor(AUTHORITY_1, b(), 35, root(0x0a), KEY_3, Expect::Ok);
    w.anchor(AUTHORITY_1, b(), 35, root(0x0b), KEY_3, Expect::Ok);
    w.call(Origin::Status, status(b(), true), Expect::Ok);
    let outcome = w.call(Origin::Status, status(b(), false), Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [Event::SpaceStatusSet {
            status: SpaceStatus::Suspended,
            ..
        }]
    ));
    // `set_format` under the delay.
    let delay = w.constants().program_change_delay_ms;
    let format = |format, from_ms| Call::SetFormat {
        format,
        active: Active {
            from_ms,
            until_ms: None,
        },
    };
    w.call(
        Origin::Programs,
        format(41, NOW),
        Expect::Err(Error::TooEarly),
    );
    w.call(Origin::Programs, format(41, NOW + delay), Expect::Ok);
    w.call(Origin::Root, format(42, NOW), Expect::Ok);
    w.finish(
        "G16",
        "dispatch_as_sovereign: a transfer from the sovereign (SovereignDispatched); set_status \
         by a signed account (BadOrigin); blocked: its submits and anchors refused \
         (SpaceNotActive), unblocked back to Active; a blocked space's roots unanchored (5); \
         unblocked with equivocations: Suspended; set_format by ProgramsOrigin under the delay \
         (TooEarly), at now + delay taken, Root at once",
    )
}

fn g17(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    w.anchor_f();
    w.accept(AUTHORITY_F, F, true);
    w.accept(AUTHORITY_F, F, false);
    w.anchor(AUTHORITY_1, b(), 35, root(0x0a), KEY_3, Expect::Ok);
    w.anchor(AUTHORITY_1, b(), 35, root(0x0b), KEY_3, Expect::Ok);
    w.begin();
    let newest = F_CLOCK.boundary(42).unwrap() + w.constants().max_root_age_ms;
    w.at(newest);
    w.on_idle();
    assert!(!w.has(&keys::anchors(&F, 0, 41)));
    assert!(
        w.has(&keys::anchors(&F, 0, 42)),
        "at B_w + MaxRootAge, not past it"
    );
    assert!(w.has(&keys::seen(&fx.statement().id().0)));
    w.at(newest + 1);
    w.on_idle();
    assert!(!w.has(&keys::anchors(&F, 0, 42)));
    assert!(!w.has(&keys::seen(&fx.statement().id().0)));
    assert!(w.has(&keys::seen(&fx.rootless.statement.id().0)));
    assert!(w.has(&keys::last(&F, 0)));
    assert!(w.has(&keys::equivocations(&b(), 0, 35)));
    w.finish(
        "G17",
        "on_idle: at B_w + MaxRootAge of F's newest root, only older anchors pruned; one ms \
         later its anchor and the rooted Seen entry pruned, the rootless entry kept, Last and \
         Equivocations kept",
    )
}

fn g18(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.anchor_f();
    // A sovereign already listed: no registration makes this, so it is the
    // pre-state's.
    let taken = genesis(B_CLOCK, 0xb2);
    let sovereign = w.constants().sovereign(&space_of(&taken));
    w.chain
        .set_storage(keys::sovereign_of(&sovereign), [0xeeu8; 32].encode());
    w.chain.set_account(
        sovereign,
        Account {
            free: 100 * UNITS,
            providers: 1,
            ..Account::default()
        },
    );
    w.begin();
    let clock = |length_ms| WindowClock {
        origin_ms: B_CLOCK.origin_ms,
        length_ms,
    };
    let short = genesis(clock(w.constants().min_window_ms - 1), 0xb3);
    w.register(&short, B_START, Expect::Err(Error::BadClock));
    let long = genesis(clock(w.constants().max_window_ms + 1), 0xb3);
    w.register(&long, B_START, Expect::Err(Error::BadClock));
    let mut many = b_genesis();
    many.nodes = (1..=17).map(|n| (n, [n; 32])).collect();
    w.register(&many, B_START, Expect::Err(Error::BadGenesis));
    let call = Call::Register {
        genesis: vec![2],
        controller: CONTROLLER,
        start_window: B_START,
        founder_key: public(KEY_1),
        founder_sig: [0; 64],
    };
    w.call(
        Origin::Signed(OPERATOR),
        call,
        Expect::Err(Error::BadGenesis),
    );
    let stranger = w.registration(&b_genesis(), B_START, B_START, KEY_9, KEY_9);
    w.call(
        Origin::Signed(OPERATOR),
        stranger,
        Expect::Err(Error::BadFounder),
    );
    let forged = w.registration(&b_genesis(), B_START, B_START, KEY_1, KEY_2);
    w.call(
        Origin::Signed(OPERATOR),
        forged,
        Expect::Err(Error::BadFounder),
    );
    w.register(&taken, B_START, Expect::Err(Error::SovereignInUse));
    let unfunded = genesis(B_CLOCK, 0xb4);
    w.register(
        &unfunded,
        B_START,
        Expect::Err(Error::InsufficientSovereignBalance),
    );
    w.register(&b_genesis(), B_START, Expect::Ok);
    w.register(&b_genesis(), B_START, Expect::Err(Error::SpaceExists));
    // `S`, of `F`, paid for by `B`'s authority.
    w.add_authority(AUTHORITY_1, None, Expect::Ok);
    w.accept(AUTHORITY_1, b(), false);
    // Pin F's bounds: a genesis of 2 KiB, a statement of 64 KiB and a proof
    // of 256 KiB decode; a byte more does not.
    let bounds = w.constants().bounds;
    let genesis_of_len = |len: usize| Call::Register {
        genesis: vec![0; len],
        controller: CONTROLLER,
        start_window: B_START,
        founder_key: public(KEY_1),
        founder_sig: [0; 64],
    };
    let at_bound = genesis_of_len(bounds.genesis);
    w.call(
        Origin::Signed(OPERATOR),
        at_bound,
        Expect::Err(Error::BadGenesis),
    );
    let over = genesis_of_len(bounds.genesis + 1);
    w.call(Origin::Signed(OPERATOR), over, Expect::Undecodable);
    let s = fx.statement().encode();
    let long = vec![0; bounds.statement];
    w.refused(long.clone(), fx.proof.clone(), 1);
    let longer = [long, vec![0]].concat();
    w.submit(
        AUTHORITY_F,
        F,
        longer,
        fx.proof.clone(),
        Expect::Undecodable,
    );
    let proof = vec![0; bounds.proof];
    let outcome = w.submit(AUTHORITY_F, F, s.clone(), proof.clone(), Expect::Ok);
    assert!(
        matches!(outcome.events[..], [Event::Refused { .. }, ..]),
        "judged: {:?}",
        outcome.events
    );
    let proof = [proof, vec![0]].concat();
    w.submit(AUTHORITY_F, F, s, proof, Expect::Undecodable);
    w.finish(
        "G18",
        "registration refusals: a window length below MinWindowMs or above MaxWindowMs \
         (BadClock), 17 founding keys or a genesis that does not decode (BadGenesis), a key not \
         in the genesis or another founder's signature (BadFounder), a sovereign already listed \
         (SovereignInUse), an unfunded sovereign (InsufficientSovereignBalance), a second \
         registration (SpaceExists); a submit paid by a space other than the statement's: \
         accepted. The length bounds: a genesis of MaxGenesisLen (2,048) bytes decodes \
         (BadGenesis) and one of a byte more does not (undecodable); a statement of \
         MaxStatementLen (65,536) bytes decodes (refused 1) and a byte more does not; a proof \
         of MaxProofLen (262,144) bytes decodes (judged: S, accepted before, a repeat) and a \
         byte more does not",
    )
}

/// The vectors' file.
pub fn file(fx: &Fixtures) -> File {
    let constants = Constants::kreivo(fx.venue);
    let vectors = [
        g1, g2, g3, g4, g5, g6, g7, g8, g9, g10, g11, g12, g13, g14, g15, g16, g17, g18,
    ]
    .map(|scenario| scenario(fx))
    .to_vec();
    let accounts = [
        ("operator", OPERATOR),
        ("controller", CONTROLLER),
        ("controller 2", CONTROLLER_2),
        ("authority F", AUTHORITY_F),
        ("authority 1", AUTHORITY_1),
        ("authority 2", AUTHORITY_2),
        ("authority 3", AUTHORITY_3),
        ("stranger", STRANGER),
        ("recipient", RECIPIENT),
        ("treasury (ForfeitTo)", constants.forfeit_to),
        ("space F", F),
        ("space B", b()),
        ("sovereign F", constants.sovereign(&F)),
        ("sovereign B", constants.sovereign(&b())),
    ];
    let keys = [
        ("anchor key F", KEY_F),
        ("anchor key 1 (B's founder 1)", KEY_1),
        ("anchor key 2 (B's founder 2)", KEY_2),
        ("anchor key 3", KEY_3),
        ("anchor key 4", KEY_4),
        ("anchor key 5", KEY_5),
        ("anchor key 6", KEY_6),
        ("anchor key 9 (never listed)", KEY_9),
    ];
    let names = accounts
        .into_iter()
        .map(|(name, account)| (name.to_string(), hex(&account)))
        .chain(
            keys.into_iter()
                .map(|(name, seed)| (name.to_string(), hex(&public(seed)))),
        )
        .collect();
    let prune_cursor = [keys::twox128(keys::PALLET), keys::twox128(b"PruneCursor")].concat();
    File {
        about: ABOUT.iter().map(|line| line.to_string()).collect(),
        constants: ConstantsJson::of(&constants),
        unpinned: vec![hex(&prune_cursor)],
        names,
        vectors,
    }
}

const ABOUT: &[&str] = &[
    "VOS's conformance vectors G1–G18 for Kreivo's spaces pallet (docs/design/spaces-pallet.md §10), generated by VOS's reference mock (node/venue/src/kreivo) over the kit's golden fixtures; regenerate them in VOS (`just conformance`), never by hand.",
    "A vector: the constants (above), a pre-state and steps. The pre-state: now_ms (Timestamp.Now), each account's free and held balances (HoldReason Registration and Submit) and its providers and consumers, and the pallet's raw storage (key → SCALE value, hex). The venue (frame_system::block_hash(0)) is constants.venue, the fixtures' venue: their statements are venue-bound.",
    "A step: now_ms, then a call (origin: {\"signed\": account} or root, programs (ProgramsOrigin), emergency (EmergencyOrigin), status (StatusOrigin); call: the RuntimeCall's bytes, [90, call_index] ++ SCALE(args), as parts: hex, or {fixture, from, to}, bytes from..to of the kit's fixtures/<fixture>) or on_idle with ample weight.",
    "Each step's expectation: result (ok; {\"module\": i}, DispatchError::Module { index: 90, error: [i, 0, 0, 0] }; bad_origin; funds_unavailable; invalid_payment, InvalidTransaction::Payment in validate, never included; undecodable, the call's bytes refused before dispatch); events, the pallet's Event in SCALE, without the runtime's index; storage, every raw key of the pallet's whose value changed (null: removed); balances, each account's deltas (free, held_registration, held_submit, providers).",
    "fees: false vectors run in the pallet's own mock runtime, no fee pipeline: deposits pinned exactly. fees: true vectors run in Kreivo's runtime with ChargeSpaceFee: free deltas by sign only (+, -, 0; the signer always listed), payer who paid the fee (sovereign or signer), and Budget's writes pinned by key and window, the value's spent masked (each ? a nibble not compared: it sums fees, the teammate's weights). The mock charges every fee at fee_bound.",
    "A call's parts may also be {repeat, count}: the byte repeat (hex) count times. unpinned: raw keys a harness leaves out of every step's storage, items the design lets a pallet keep that the mock does not (PruneCursor, on_idle's cursor).",
    "Balances: in a pallet-level vector every account a step does not list is unchanged; in a fees vector the runtime's fee recipients (the block author, the treasury's share) are not pinned, and only the accounts listed are. A pre-state's consumers exclude the one FRAME's Balances takes for a hold (sovereign F's are 0 though it holds its registration deposit): the teammate's harness keeps its own; providers are pinned as deltas.",
    "Accounts: 'names' labels them. The fixture space F ([0xa1; 32], the fixtures' statements' space) is in every pre-state as storage, since no genesis hashes to its id; space B is registered by call from a genesis of two founders.",
];
