//! The anchors' vectors: G3–G5, G17 and G19.

use parity_scale_codec::Encode;

use super::world::*;
use super::{Fixtures, Vector};
use crate::kreivo::mock::Origin;
use crate::kreivo::mock::keys;
use crate::kreivo::mock::types::{Call, Error, Event};

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

pub(super) fn g5(fx: &Fixtures) -> Vector {
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

pub(super) fn g17(fx: &Fixtures) -> Vector {
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

pub(super) fn g19(fx: &Fixtures) -> Vector {
    let mut w = World::new(fx, false);
    w.anchor_f();
    let add = |who, seed| Call::AddAuthority {
        space: F,
        who,
        anchor_key: Some(public(seed)),
    };
    w.controller(add(AUTHORITY_1, KEY_1), Expect::Ok);
    w.begin();
    let disputed = fx.statement().roots[0];
    let window = disputed.window;
    // A second listed key signs another root of a window held.
    let outcome = w.anchor(AUTHORITY_1, F, window, root(0x0b), KEY_1, Expect::Ok);
    assert!(matches!(
        outcome.events[..],
        [Event::Equivocated { first, second, .. }, Event::SpaceSuspended { .. }]
            if first == disputed.root && second == root(0x0b)
    ));
    assert!(!w.has(&keys::anchors(&F, 0, window)), "the disputed root");
    // Both signers removed, a fresh key listed, the space resumed.
    let remove = |who| Call::RemoveAuthority { space: F, who };
    w.controller(remove(AUTHORITY_1), Expect::Ok);
    w.controller(remove(AUTHORITY_F), Expect::Ok);
    w.controller(add(AUTHORITY_2, KEY_5), Expect::Ok);
    w.controller(Call::Resume { space: F }, Expect::Ok);
    // The statement over the disputed window's first root: unanchored.
    let statement = fx.statement().encode();
    w.refused_by(
        AUTHORITY_2,
        statement,
        fx.proof.clone(),
        vos_statement::Refusal::Unanchored.code(),
    );
    // Neither root is anchored at the window again.
    for again in [disputed.root, root(0x0b)] {
        w.anchor(
            AUTHORITY_2,
            F,
            window,
            again,
            KEY_5,
            Expect::Err(Error::WindowNotAfterLast),
        );
    }
    // The space anchors on from the window after its last.
    let next = 43;
    w.at(F_CLOCK.boundary(next).unwrap());
    let outcome = w.anchor(AUTHORITY_2, F, next, root(0x43), KEY_5, Expect::Ok);
    assert!(matches!(outcome.events[..], [Event::Anchored { .. }]));
    w.finish(
        "G19",
        "after resume, a disputed window stays unusable: a second root of F's window held \
         (Equivocated, SpaceSuspended) drops the window's anchor; both signers removed, a fresh \
         key listed, resumed; the statement over the window's first root refused 5 \
         (Unanchored), either root anchored again refused (WindowNotAfterLast); the next \
         window anchored",
    )
}
