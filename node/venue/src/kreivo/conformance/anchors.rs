//! The anchors' vectors: G3–G5 and G16.

use parity_scale_codec::Encode;

use super::world::*;
use super::{Fixtures, Vector};
use crate::kreivo::mock::Origin;
use crate::kreivo::mock::keys;
use crate::kreivo::mock::types::{
    BalancesCall, Call, Error, Event, MultiAddress, RuntimeCall, SpaceStatus,
};

pub(super) fn g3(fx: &Fixtures) -> Vector {
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

pub(super) fn g4(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    // Window 30's root just past MaxRootAge.
    let now = B_CLOCK.boundary(B_START).unwrap() + vos_anchor::MAX_ROOT_AGE_MS + 1;
    w.at(now);
    w.begin();
    let by = AUTHORITY_1;
    w.anchor(
        by,
        b(),
        B_START - 1,
        root(1),
        KEY_3,
        Expect::Err(Error::WindowNotAfterLast),
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
    let now = B_CLOCK.boundary(B_START + 1).unwrap() + vos_anchor::MAX_ROOT_AGE_MS;
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
    // The venue's time before the space's origin: no window is closed.
    w.at(B_CLOCK.origin_ms - 1);
    w.anchor(
        by,
        b(),
        now_w + 1,
        root(6),
        KEY_3,
        Expect::Err(Error::WindowInFuture),
    );
    w.finish(
        "G4",
        "anchor refusals: before the space's first window (WindowNotAfterLast), older than \
         MaxRootAge (WindowTooOld), exactly MaxRootAge old taken, the same root again \
         (AlreadyAnchored), a stale w ≤ Last (WindowNotAfterLast), the open window now_w and a \
         later one (WindowInFuture), then now_ms at B_w and the same anchor resubmitted \
         (Anchored); a bad signature (BadAnchorSignature), kind 1 (BadKind), an unlisted key \
         (UnknownAnchorKey), an unknown space (UnknownSpace), now_ms before the origin \
         (WindowInFuture)",
    )
}

pub(super) fn g5(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    w.anchor(AUTHORITY_1, b(), 34, root(0x34), KEY_3, Expect::Ok);
    w.begin();
    let sovereign = w.constants().sovereign(&b());
    let deposit = w.constants().registration_deposit;
    assert_eq!(w.chain.account(&sovereign).held_registration, deposit);
    // A founding key anchors window 35; the authority's key signs another
    // root of it, its node's anchor sent as the evidence: the failover
    // case, two keys.
    w.anchor(STRANGER, b(), 35, root(0x0a), KEY_2, Expect::Ok);
    let outcome = w.anchor(AUTHORITY_1, b(), 35, root(0x0b), KEY_3, Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [Event::Equivocated { first_signer, second_signer, .. }, Event::SpaceEnded { .. }]
            if first_signer == public(KEY_2) && second_signer == public(KEY_3)
    ));
    let info = w.chain.space(&b()).unwrap();
    assert_eq!(info.status, SpaceStatus::Ended);
    let account = w.chain.account(&sovereign);
    assert_eq!(account.held_registration, 0, "the deposit released");
    // No anchor taken, the evidence's included, and no root counted: a
    // statement over the window before, held, refused 5.
    w.anchor(
        AUTHORITY_1,
        b(),
        36,
        root(0x0c),
        KEY_3,
        Expect::Err(Error::SpaceNotActive),
    );
    w.anchor(
        STRANGER,
        b(),
        35,
        root(0x0b),
        KEY_3,
        Expect::Err(Error::SpaceNotActive),
    );
    assert!(w.has(&keys::anchors(&b(), 0, 34)));
    let over_34 = statement_of(fx, b(), 34, root(0x34));
    w.refused(
        over_34,
        Vec::new(),
        vos_statement::Refusal::Unanchored.code(),
    );
    // The tombstone: the registration replayed.
    w.register(&b_genesis(), Expect::Err(Error::SpaceExists));
    // The controller's `dispatch_as_sovereign`: the funds leave, the
    // existential deposit kept.
    let ed = w.constants().existential_deposit;
    let transfer = RuntimeCall::Balances(BalancesCall::TransferKeepAlive {
        dest: MultiAddress::Id(RECIPIENT),
        value: account.free - ed,
    });
    let dispatch = Call::DispatchAsSovereign {
        space: b(),
        call: Box::new(transfer),
    };
    let outcome = w.controller(dispatch, Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [Event::SovereignDispatched { result: Ok(()), .. }]
    ));
    assert_eq!(w.chain.account(&sovereign).free, ed);
    w.finish(
        "G5",
        "an equivocation ends a space: a second root of a window held, signed by another listed \
         key (the failover case: the honest node's anchor as the evidence), Equivocated naming \
         both signers and SpaceEnded, the status Ended (index 3), the registration deposit \
         released to the sovereign; then its anchors refused (SpaceNotActive), the evidence's \
         too, and its roots unanchored (a statement over a window held refused 5); the \
         registration replayed refused (SpaceExists: the space is never pruned); \
         dispatch_as_sovereign still the controller's, the sovereign's funds leaving, the \
         existential deposit kept",
    )
}

pub(super) fn g16(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.with_b(AUTHORITY_1, KEY_3);
    w.anchor_f();
    w.accept(AUTHORITY_F, F);
    w.anchor(AUTHORITY_1, b(), 35, root(0x0a), KEY_3, Expect::Ok);
    w.anchor(AUTHORITY_1, b(), 35, root(0x0b), KEY_3, Expect::Ok);
    w.begin();
    let newest = F_CLOCK.boundary(42).unwrap() + vos_anchor::MAX_ROOT_AGE_MS;
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
    assert!(w.has(&keys::last(&F, 0)));
    assert!(w.has(&keys::equivocations(&b(), 0, 35)));
    assert!(w.has(&keys::spaces(&b())), "an ended space's record");
    w.finish(
        "G16",
        "on_idle: at B_w + MaxRootAge of F's newest root, only older anchors pruned; one ms \
         later its anchor and the Seen entry pruned; Last, Equivocations and an ended space's \
         record kept",
    )
}
