//! The world every vector starts from: the fixtures' time (window 42's
//! boundary of the fixture space's clock); `format::MASKED_WRAP` and the
//! fixtures' program (`Record`) active from 0; the fixture space `F` (the
//! fixtures' statements' space, `[0xA1; 32]`, registered from window 40
//! under the default clock, its one authority paired with its anchor key)
//! in the pre-state as storage, since no genesis hashes to the fixtures'
//! space id. A second space `B`, registered by call from a two-founder
//! genesis, on a clock of its own (origin 1,000,000 ms, ten-minute windows:
//! window 41 at the fixtures' time); a vector that anchors its early
//! windows registers it while its window 29 is open, so it anchors from
//! window 30.

use ed25519_dalek::{Signer, SigningKey};
use parity_scale_codec::Encode;
use vos_anchor::{RootKind, SpaceGenesis, WindowClock};
use vos_statement::{RootRead, SpaceId, Statement};

use super::{Fixtures, Pre, Step, Vector, parts, pre, step};
use crate::kreivo::mock::keys;
use crate::kreivo::mock::types::{
    AccountId, Active, AnchorArg, AuthorityInfo, Call, DispatchError, Error, Event, Handler,
    ProgramInfo, RuntimeCall, Space, SpaceInfo, SpaceStatus,
};
use crate::kreivo::mock::{Account, Chain, Constants, Origin, Outcome, Verdict};

pub(super) const UNITS: u128 = 1_000_000_000_000;
/// The fixtures' time: window 42's boundary of `F`'s clock.
pub(super) const NOW: u64 = 43 * 600_000;
/// The fixture space.
pub const F: Space = [0xA1; 32];
pub(super) const F_CLOCK: WindowClock = WindowClock::DEFAULT;
pub(super) const B_CLOCK: WindowClock = WindowClock {
    origin_ms: 1_000_000,
    length_ms: 600_000,
};
/// `B`'s first window.
pub(super) const B_START: u64 = 30;

pub(super) const OPERATOR: AccountId = [0x0a; 32];
pub(super) const CONTROLLER: AccountId = [0xc0; 32];
pub(super) const CONTROLLER_2: AccountId = [0xc2; 32];
pub const AUTHORITY_F: AccountId = [0xaf; 32];
pub(super) const AUTHORITY_1: AccountId = [0xa3; 32];
pub(super) const AUTHORITY_2: AccountId = [0xa4; 32];
pub(super) const AUTHORITY_3: AccountId = [0xa5; 32];
pub(super) const STRANGER: AccountId = [0x5e; 32];
pub(super) const RECIPIENT: AccountId = [0xd0; 32];

/// The anchor keys, by seed: `F`'s, `B`'s two founders', two more, and
/// one never listed.
pub(super) const KEY_F: u8 = 0xf1;
pub(super) const KEY_1: u8 = 1;
pub(super) const KEY_2: u8 = 2;
pub(super) const KEY_3: u8 = 3;
pub(super) const KEY_4: u8 = 4;
pub(super) const KEY_5: u8 = 5;
pub(super) const KEY_6: u8 = 6;
pub(super) const KEY_9: u8 = 9;

/// A key of small order (the identity's encoding), which no venue lists.
pub(super) const SMALL_ORDER_KEY: [u8; 32] = {
    let mut key = [0; 32];
    key[0] = 1;
    key
};

pub(super) fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(super) fn public(seed: u8) -> [u8; 32] {
    signing(seed).verifying_key().to_bytes()
}

/// A two-founder genesis on `clock`, told apart by `nonce`.
pub(super) fn genesis(clock: WindowClock, nonce: u8) -> SpaceGenesis {
    SpaceGenesis {
        nodes: vec![(1, public(KEY_1)), (2, public(KEY_2))],
        clock,
        time: clock.origin_ms,
        nonce: [nonce; 16],
    }
}

/// A two-founder genesis on `B`'s clock, told apart by `nonce`.
pub(super) fn genesis_of(nonce: u8) -> SpaceGenesis {
    genesis(B_CLOCK, nonce)
}

pub(super) fn funded(free: u128) -> Account {
    Account {
        free,
        providers: 1,
        ..Account::default()
    }
}

pub(super) fn space_of(genesis: &SpaceGenesis) -> Space {
    vos_anchor::space_id(genesis).0
}

pub(super) fn b_genesis() -> SpaceGenesis {
    genesis(B_CLOCK, 0xb0)
}

pub(super) fn b() -> Space {
    space_of(&b_genesis())
}

/// What a step must do.
#[derive(Clone, Copy, Debug)]
pub(super) enum Expect {
    Ok,
    Err(Error),
    BadOrigin,
    Payment,
    Undecodable,
}

impl Expect {
    pub(super) fn holds(self, verdict: &Verdict) -> bool {
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
pub(super) struct World<'f> {
    pub(super) fx: &'f Fixtures,
    pub(super) chain: Chain,
    pub(super) pre: Option<Pre>,
    pub(super) steps: Vec<Step>,
}

impl<'f> World<'f> {
    /// The world every vector starts from (the module's docs).
    pub(super) fn new(fx: &'f Fixtures, fees: bool) -> Self {
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
        let info = ProgramInfo {
            handler: Handler::Record,
            active: always,
        };
        world.call(
            Origin::Root,
            Call::SetProgram {
                program: fx.valid.program.0,
                info: Some(info),
            },
            Expect::Ok,
        );
        world
    }

    pub(super) fn constants(&self) -> &Constants {
        &self.chain.constants
    }

    /// The setup done: the pre-state taken, and every later step recorded.
    pub(super) fn begin(&mut self) {
        self.pre = Some(pre(&self.chain));
    }

    pub(super) fn at(&mut self, now_ms: u64) {
        self.chain.set_now(now_ms);
    }

    pub(super) fn call(&mut self, origin: Origin, call: Call, expect: Expect) -> Outcome {
        let bytes = RuntimeCall::Spaces(call).encode();
        self.raw(origin, bytes, expect)
    }

    pub(super) fn raw(&mut self, origin: Origin, bytes: Vec<u8>, expect: Expect) -> Outcome {
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

    pub(super) fn on_idle(&mut self) {
        let before = self.chain.clone();
        self.chain.on_idle();
        self.steps
            .push(step(&before, &self.chain, None, None, None));
    }

    pub(super) fn finish(self, id: &str, title: &str) -> Vector {
        Vector {
            id: id.to_string(),
            title: title.to_string(),
            fees: self.chain.fees(),
            pre: self.pre.expect("begun"),
            steps: self.steps,
        }
    }

    pub(super) fn has(&self, key: &[u8]) -> bool {
        self.chain.storage().contains_key(key)
    }

    /// `space`'s root `root` at `window`, signed by the key of `seed`.
    pub(super) fn anchor_arg(
        &self,
        space: Space,
        window: u64,
        root: [u8; 32],
        seed: u8,
    ) -> AnchorArg {
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

    pub(super) fn anchor(
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
    pub(super) fn anchor_f(&mut self) {
        for root in self.fx.statement().roots.clone() {
            let outcome = self.anchor(AUTHORITY_F, F, root.window, root.root, KEY_F, Expect::Ok);
            assert!(matches!(outcome.events[..], [Event::Anchored { .. }]));
        }
    }

    pub(super) fn submit(
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
    pub(super) fn refused(&mut self, statement: Vec<u8>, proof: Vec<u8>, code: u32) {
        self.refused_by(AUTHORITY_F, statement, proof, code);
    }

    /// [`World::refused`], submitted by `by`, an authority of `F`.
    pub(super) fn refused_by(
        &mut self,
        by: AccountId,
        statement: Vec<u8>,
        proof: Vec<u8>,
        code: u32,
    ) {
        let outcome = self.submit(by, F, statement, proof, Expect::Ok);
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
    pub(super) fn accept(&mut self, by: AccountId, payer: Space) {
        let statement = self.fx.statement().clone();
        let proof = self.fx.proof.clone();
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

    /// `genesis` registered by the operator under `CONTROLLER`, founder 1
    /// signing: it anchors from the venue's next window.
    pub(super) fn register(&mut self, genesis: &SpaceGenesis, expect: Expect) -> Outcome {
        let call = self.registration(genesis, CONTROLLER, KEY_1, KEY_1);
        self.call(Origin::Signed(OPERATOR), call, expect)
    }

    /// A registration of `genesis` under `CONTROLLER` claiming `founder`'s
    /// key, signed by `signer` over its digest under `signed_for`.
    pub(super) fn registration(
        &self,
        genesis: &SpaceGenesis,
        signed_for: AccountId,
        founder: u8,
        signer: u8,
    ) -> Call {
        let digest = vos_anchor::register_digest(
            &self.constants().venue,
            &vos_anchor::space_id(genesis),
            &signed_for,
        );
        Call::Register {
            genesis: genesis.encode(),
            controller: CONTROLLER,
            founder_key: public(founder),
            founder_sig: signing(signer).sign(&digest).to_bytes(),
        }
    }

    /// `B` registered while its window `B_START − 1` is open, so it anchors
    /// from `B_START`, then the venue's time back at the fixtures'; `who`
    /// its authority paired with the key of `seed`.
    pub(super) fn with_b(&mut self, who: AccountId, seed: u8) {
        let now = self.chain.now();
        self.at(B_CLOCK.boundary(B_START - 2).unwrap());
        self.register(&b_genesis(), Expect::Ok);
        self.at(now);
        self.add_authority(who, Some(public(seed)), Expect::Ok);
    }

    pub(super) fn add_authority(
        &mut self,
        who: AccountId,
        key: Option<[u8; 32]>,
        expect: Expect,
    ) -> Outcome {
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

    pub(super) fn controller(&mut self, call: Call, expect: Expect) -> Outcome {
        self.call(Origin::Signed(CONTROLLER), call, expect)
    }
}

/// A statement of `space` reading its root `root` at `window`, of the
/// fixtures' program: refused before its proof.
pub(super) fn statement_of(fx: &Fixtures, space: Space, window: u64, root: [u8; 32]) -> Vec<u8> {
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

pub(super) fn root(byte: u8) -> [u8; 32] {
    [byte; 32]
}
