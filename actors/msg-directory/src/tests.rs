use super::*;
use vos::Message;
use vos::actors::context::ServiceId;

/// Handler futures never await anything external, so a single
/// poll with a no-op waker resolves them — no executor (or
/// vos `std` feature) needed in this crate's unit tests.
fn run<F: core::future::Future>(fut: F) -> F::Output {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker {
            raw()
        }
        fn noop(_: *const ()) {}
        RawWaker::new(
            core::ptr::null(),
            &RawWakerVTable::new(clone, noop, noop, noop),
        )
    }
    let waker = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = core::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("actor handler future was not immediately ready"),
    }
}

fn dispatch<M>(d: &mut MsgDirectory, msg: M) -> <MsgDirectory as Message<M>>::Output
where
    MsgDirectory: Message<M>,
{
    let mut ctx: vos::Context<MsgDirectory> = vos::Context::new(ServiceId(0));
    run(<MsgDirectory as Message<M>>::handle(d, msg, &mut ctx))
}

fn publish(d: &mut MsgDirectory, owner: &str, kp: &[u8]) -> Status {
    dispatch(
        d,
        PublishKp {
            owner: owner.into(),
            kp: kp.to_vec(),
        },
    )
}

fn claim(d: &mut MsgDirectory, owner: &str) -> Vec<u8> {
    dispatch(
        d,
        ClaimKp {
            owner: owner.into(),
        },
    )
}

#[test]
fn each_published_kp_is_claimable_exactly_once() {
    let mut d = MsgDirectory::new();
    assert_eq!(publish(&mut d, "bob", b"kp-one"), Status::Ok);
    assert_eq!(publish(&mut d, "bob", b"kp-two"), Status::Ok);
    assert_eq!(
        dispatch(
            &mut d,
            KpCount {
                owner: "bob".into()
            }
        ),
        2
    );

    let first = claim(&mut d, "bob");
    let second = claim(&mut d, "bob");
    assert!(!first.is_empty() && !second.is_empty());
    assert_ne!(first, second, "each claim must consume a distinct package");
    assert!(
        claim(&mut d, "bob").is_empty(),
        "an exhausted member yields no package"
    );
    assert_eq!(
        dispatch(
            &mut d,
            KpCount {
                owner: "bob".into()
            }
        ),
        0
    );
}

#[test]
fn publish_is_idempotent_by_content() {
    let mut d = MsgDirectory::new();
    assert_eq!(publish(&mut d, "bob", b"same"), Status::Ok);
    assert_eq!(publish(&mut d, "bob", b"same"), Status::Ok);
    assert_eq!(
        dispatch(
            &mut d,
            KpCount {
                owner: "bob".into()
            }
        ),
        1
    );
}

#[test]
fn publish_validates_shape_and_quota() {
    let mut d = MsgDirectory::new();
    assert_eq!(publish(&mut d, "", b"kp"), Status::InvalidInput);
    assert_eq!(publish(&mut d, "bob", b""), Status::InvalidInput);
    let huge = vec![0u8; MAX_KP_BYTES + 1];
    assert_eq!(publish(&mut d, "bob", &huge), Status::TooLarge);
    for i in 0..MAX_KPS_PER_MEMBER {
        assert_eq!(
            publish(&mut d, "bob", format!("kp-{i}").as_bytes()),
            Status::Ok
        );
    }
    assert_eq!(
        publish(&mut d, "bob", b"one-too-many"),
        Status::QuotaExceeded
    );
    // Quota is per member.
    assert_eq!(publish(&mut d, "carol", b"kp"), Status::Ok);
    // Oversized owner / channel names are refused.
    let long = "x".repeat(MAX_NAME_BYTES + 1);
    assert_eq!(publish(&mut d, &long, b"kp"), Status::InvalidInput);
    assert_eq!(
        dispatch(
            &mut d,
            AnnounceChannel {
                name: long,
                creator: "alice".into(),
            },
        ),
        Status::InvalidInput,
    );
}

#[test]
fn spent_packages_free_quota_for_replenishment() {
    // The quota bounds live inventory, not lifetime publishes —
    // a member who claimed all their packages must be able to
    // publish more. Otherwise a long-lived member locks out
    // after MAX_KPS_PER_MEMBER total invites.
    let mut d = MsgDirectory::new();
    for i in 0..MAX_KPS_PER_MEMBER {
        assert_eq!(
            publish(&mut d, "bob", format!("kp-{i}").as_bytes()),
            Status::Ok
        );
    }
    assert_eq!(publish(&mut d, "bob", b"blocked"), Status::QuotaExceeded);
    // Consume one; a slot frees up.
    assert!(!claim(&mut d, "bob").is_empty());
    assert_eq!(publish(&mut d, "bob", b"replenished"), Status::Ok);
}

#[test]
fn released_kp_is_claimable_again() {
    let mut d = MsgDirectory::new();
    publish(&mut d, "bob", b"the-kp");
    let claimed = claim(&mut d, "bob");
    assert_eq!(claimed, b"the-kp");
    assert!(claim(&mut d, "bob").is_empty(), "single-use after claim");

    let hash = kp_hash(&claimed);
    assert_eq!(
        dispatch(
            &mut d,
            ReleaseKp {
                owner: "bob".into(),
                hash: hash.to_vec(),
            },
        ),
        Status::Ok,
    );
    assert_eq!(
        dispatch(
            &mut d,
            KpCount {
                owner: "bob".into()
            }
        ),
        1,
        "released package counts as live inventory again"
    );
    assert_eq!(claim(&mut d, "bob"), b"the-kp", "released → claimable");
}

#[test]
fn release_is_idempotent_and_tolerates_unknown_rows() {
    let mut d = MsgDirectory::new();
    publish(&mut d, "bob", b"kp");
    let hash = kp_hash(b"kp").to_vec();
    // Releasing an UNCLAIMED row is a no-op success.
    assert_eq!(
        dispatch(
            &mut d,
            ReleaseKp {
                owner: "bob".into(),
                hash: hash.clone(),
            },
        ),
        Status::Ok,
    );
    // Unknown owner/hash: still OK (retry-safe).
    assert_eq!(
        dispatch(
            &mut d,
            ReleaseKp {
                owner: "nobody".into(),
                hash,
            },
        ),
        Status::Ok,
    );
    // Malformed hash length is the one refused input.
    assert_eq!(
        dispatch(
            &mut d,
            ReleaseKp {
                owner: "bob".into(),
                hash: vec![0u8; 7],
            },
        ),
        Status::InvalidInput,
    );
    // Inventory unchanged throughout.
    assert_eq!(
        dispatch(
            &mut d,
            KpCount {
                owner: "bob".into()
            }
        ),
        1
    );
}

#[test]
fn claims_are_scoped_to_the_owner() {
    let mut d = MsgDirectory::new();
    publish(&mut d, "bob", b"bobs-kp");
    assert!(claim(&mut d, "carol").is_empty());
    assert_eq!(claim(&mut d, "bob"), b"bobs-kp");
}

#[test]
fn channel_announcements_are_first_wins() {
    let mut d = MsgDirectory::new();
    assert_eq!(
        dispatch(
            &mut d,
            AnnounceChannel {
                name: "general".into(),
                creator: "alice".into(),
            },
        ),
        Status::Ok,
    );
    assert_eq!(
        dispatch(
            &mut d,
            AnnounceChannel {
                name: "general".into(),
                creator: "mallory".into(),
            },
        ),
        Status::Exists,
    );
    let rows = dispatch(&mut d, Channels { from: 0, limit: 10 });
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].creator, "alice");
}
