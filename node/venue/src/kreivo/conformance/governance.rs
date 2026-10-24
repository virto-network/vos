//! The vectors of registration, a space's control and governance: G1, G2,
//! G11, G14–G16 and G18.

use parity_scale_codec::Encode;
use vos_anchor::WindowClock;

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

pub(super) fn g2(fx: &Fixtures) -> Vector {
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

pub(super) fn g11(fx: &Fixtures) -> Vector {
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

pub(super) fn g14(fx: &Fixtures) -> Vector {
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

pub(super) fn g15(fx: &Fixtures) -> Vector {
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

pub(super) fn g16(fx: &Fixtures) -> Vector {
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

pub(super) fn g18(fx: &Fixtures) -> Vector {
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
