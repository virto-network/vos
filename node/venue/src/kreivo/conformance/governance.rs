//! The vectors of registration, a space's control and governance: G1, G2,
//! G11, G14, G15 and G17.

use parity_scale_codec::Encode;
use vos_anchor::{SpaceGenesis, WindowClock};

use super::world::*;
use super::{Fixtures, Vector};
use crate::kreivo::mock::keys;
use crate::kreivo::mock::types::{
    Active, BALANCES_INDEX, BalancesCall, Call, Error, Event, Handler, MultiAddress, ProgramInfo,
    RuntimeCall, SpaceStatus,
};
use crate::kreivo::mock::{Account, Origin};

pub(super) fn g1(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    // Window 1000 of `B`'s clock.
    let now = B_CLOCK.boundary(999).unwrap() + 5_000;
    w.at(now);
    let now_w = B_CLOCK.window(now).unwrap();
    assert_eq!(now_w, 1_000);
    let genesis = b_genesis();
    // A space whose clock starts ten windows from now, its sovereign
    // funded.
    let early = SpaceGenesis {
        clock: WindowClock {
            origin_ms: now + 10 * B_CLOCK.length_ms,
            ..B_CLOCK
        },
        ..genesis_of(0xb5)
    };
    let sovereign = w.constants().sovereign(&space_of(&early));
    w.chain.set_account(sovereign, funded(100 * UNITS));
    w.begin();
    // The founder's signature under another controller, submitted under
    // `CONTROLLER`.
    let elsewhere = w.registration(&genesis, CONTROLLER_2, KEY_1, KEY_1);
    w.call(
        Origin::Signed(OPERATOR),
        elsewhere,
        Expect::Err(Error::BadFounder),
    );
    let outcome = w.register(&genesis, Expect::Ok);
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
                start_window,
                ..
            },
        ] => {
            assert_eq!((*space, *paid_by), (b(), sovereign));
            assert_eq!(*start_window, now_w + 1, "the venue's next window");
        }
        events => panic!("{events:?}"),
    }
    let held = w.chain.account(&sovereign).held_registration;
    assert_eq!(held, w.constants().registration_deposit);
    w.register(&genesis, Expect::Err(Error::SpaceExists));
    let outcome = w.register(&early, Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [Event::SpaceRegistered {
            start_window: 0,
            ..
        }]
    ));
    w.finish(
        "G1",
        "register: the fixture genesis's space registered, anchoring from the venue's next \
         window (start_window now_w + 1), its sovereign address `modl ‖ kv/space ‖ \
         space[..20]`, the deposit held; refused: the founder's signature under another \
         controller (BadFounder), a second registration (SpaceExists); a space whose clock has \
         not started registered from window 0",
    )
}

pub(super) fn g2(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.register(&b_genesis(), Expect::Ok);
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

pub(super) fn g11(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.begin();
    let delay = w.constants().program_change_delay_ms;
    let at = NOW + delay;
    let info = |from_ms, until_ms| ProgramInfo {
        handler: Handler::Record,
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
    // An active program's `from_ms` moved: not only `until_ms`.
    let p3 = [11; 8];
    w.call(Origin::Root, set(p3, Some(info(NOW, None))), Expect::Ok);
    w.call(
        Origin::Programs,
        set(p3, Some(info(NOW - 1, None))),
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
         at once; a change other than setting or shortening until_ms (an active program's \
         from_ms moved) needs from_ms ≥ now + delay (TooEarly); a handler other than Record does \
         not decode",
    )
}

pub(super) fn g14(fx: &Fixtures) -> Vector {
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
    let add = |who, key: [u8; 32]| Call::AddAuthority {
        space: b(),
        who,
        anchor_key: Some(key),
    };
    by_2(
        &mut w,
        add(AUTHORITY_1, public(KEY_4)),
        Expect::Err(Error::AuthorityExists),
    );
    by_2(
        &mut w,
        add(AUTHORITY_2, public(KEY_3)),
        Expect::Err(Error::AnchorKeyInUse),
    );
    by_2(
        &mut w,
        add(AUTHORITY_2, SMALL_ORDER_KEY),
        Expect::Err(Error::BadAnchorKey),
    );
    by_2(&mut w, add(AUTHORITY_2, public(KEY_1)), Expect::Ok);
    let remove = |key: u8| Call::RemoveAnchorKey {
        space: b(),
        key: public(key),
    };
    by_2(&mut w, remove(KEY_3), Expect::Err(Error::AnchorKeyInUse));
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
        "G14",
        "the controller and keys: set_controller (the old controller then NotController); \
         add_authority of an authority already (AuthorityExists: a node's key changes only by \
         replacing the node), of a key paired elsewhere (AnchorKeyInUse), of a key of small \
         order (BadAnchorKey); an unpaired founding key paired; remove_anchor_key of a paired \
         key (AnchorKeyInUse), of an unpaired founding key (removed), of an unlisted one \
         (UnknownAnchorKey); remove_authority with a consumer on the account, its provider kept \
         (best effort)",
    )
}

pub(super) fn g15(fx: &Fixtures) -> Vector {
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
    // An ended space is never blocked or unblocked: it stays ended.
    w.anchor(AUTHORITY_1, b(), 35, root(0x0a), KEY_3, Expect::Ok);
    w.anchor(AUTHORITY_1, b(), 35, root(0x0b), KEY_3, Expect::Ok);
    for blocked in [true, false] {
        w.call(
            Origin::Status,
            status(b(), blocked),
            Expect::Err(Error::SpaceNotActive),
        );
    }
    assert_eq!(w.chain.space(&b()).unwrap().status, SpaceStatus::Ended);
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
        "G15",
        "dispatch_as_sovereign: a transfer from the sovereign (SovereignDispatched); set_status \
         by a signed account (BadOrigin); blocked: its submits and anchors refused \
         (SpaceNotActive), unblocked back to Active; a blocked space's roots unanchored (5); an \
         ended space neither blocked nor unblocked (SpaceNotActive); set_format by \
         ProgramsOrigin under the delay (TooEarly), at now + delay taken, Root at once",
    )
}

pub(super) fn g17(fx: &Fixtures) -> Vector {
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
    let short = genesis(clock(vos_anchor::MIN_LENGTH_MS - 1), 0xb3);
    w.register(&short, Expect::Err(Error::BadClock));
    let long = genesis(clock(vos_anchor::MAX_LENGTH_MS + 1), 0xb3);
    w.register(&long, Expect::Err(Error::BadClock));
    let mut many = b_genesis();
    many.nodes = (1..=17).map(|n| (n, public(n))).collect();
    w.register(&many, Expect::Err(Error::BadGenesis));
    let mut twice = b_genesis();
    twice.nodes = vec![(1, public(KEY_1)), (2, public(KEY_1))];
    w.register(&twice, Expect::Err(Error::BadGenesis));
    let mut small = b_genesis();
    small.nodes = vec![(1, public(KEY_1)), (2, SMALL_ORDER_KEY)];
    w.register(&small, Expect::Err(Error::BadGenesis));
    let call = Call::Register {
        genesis: vec![2],
        controller: CONTROLLER,
        founder_key: public(KEY_1),
        founder_sig: [0; 64],
    };
    w.call(
        Origin::Signed(OPERATOR),
        call,
        Expect::Err(Error::BadGenesis),
    );
    let stranger = w.registration(&b_genesis(), CONTROLLER, KEY_9, KEY_9);
    w.call(
        Origin::Signed(OPERATOR),
        stranger,
        Expect::Err(Error::BadFounder),
    );
    let forged = w.registration(&b_genesis(), CONTROLLER, KEY_1, KEY_2);
    w.call(
        Origin::Signed(OPERATOR),
        forged,
        Expect::Err(Error::BadFounder),
    );
    w.register(&taken, Expect::Err(Error::SovereignInUse));
    let unfunded = genesis(B_CLOCK, 0xb4);
    w.register(&unfunded, Expect::Err(Error::InsufficientSovereignBalance));
    w.register(&b_genesis(), Expect::Ok);
    w.register(&b_genesis(), Expect::Err(Error::SpaceExists));
    // `S`, of `F`, paid for by `B`'s authority.
    w.add_authority(AUTHORITY_1, None, Expect::Ok);
    w.accept(AUTHORITY_1, b());
    // Pin F's bounds: a genesis of 2 KiB, a statement of 64 KiB and a proof
    // of 256 KiB decode; a byte more does not.
    let bounds = w.constants().bounds;
    let genesis_of_len = |len: usize| Call::Register {
        genesis: vec![0; len],
        controller: CONTROLLER,
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
        "G17",
        "registration refusals: a window length below vos_anchor::MIN_LENGTH_MS or above \
         MAX_LENGTH_MS (BadClock), 17 founding keys, one key twice, a key of small order or a \
         genesis that does not decode (BadGenesis), a key not in the genesis or another \
         founder's signature (BadFounder), a sovereign already listed \
         (SovereignInUse), an unfunded sovereign (InsufficientSovereignBalance), a second \
         registration (SpaceExists); a submit paid by a space other than the statement's: \
         accepted. The length bounds: a genesis of MaxGenesisLen (2,048) bytes decodes \
         (BadGenesis) and one of a byte more does not (undecodable); a statement of \
         MaxStatementLen (65,536) bytes decodes (refused 1) and a byte more does not; a proof \
         of MaxProofLen (262,144) bytes decodes (judged: S, accepted before, a repeat) and a \
         byte more does not",
    )
}
