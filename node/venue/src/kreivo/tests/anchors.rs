use super::*;

/// An anchor is taken at once while the chain takes its time, lands in
/// the background, and is then held. The client does not judge anchors:
/// the same anchor again is taken unsent, the venue holding its root; one
/// of a window behind the last, at which it holds none, is never taken,
/// without an alert.
#[test]
fn an_anchor_is_taken_at_once_and_lands() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    assert_eq!(venue.status(&setup.space), Status::Active);
    assert_eq!(
        venue.anchor_keys(&setup.space),
        [setup.key.verifying_key().to_bytes()]
    );
    // The chain takes a second a call; both answers come well within it,
    // on a loaded host too.
    setup.chain.set_latency(Duration::from_secs(1));
    let start = Instant::now();
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    let took = start.elapsed();
    assert!(took < Duration::from_millis(500), "no wait: {took:?}");
    wait_until("window 5 lands", || setup.anchored_window(5));
    wait_until("the queue empties", || venue.queued() == 0);
    assert_eq!(setup.anchors_sent(), 1);
    let read = RootRead {
        kind: RootKind::Space,
        space: setup.space,
        window: 5,
        root: [1; 32],
    };
    assert!(venue.anchored(&read));
    assert!(!venue.anchored(&RootRead {
        root: [2; 32],
        ..read
    }));
    setup.chain.set_latency(Duration::ZERO);
    assert_eq!(venue.held(&setup.space, 5), Held::Root([1; 32]));
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    assert_eq!(venue.queued(), 0, "held: not queued");
    wait_until("window 4 read", || {
        venue.held(&setup.space, 4) == Held::Nothing
    });
    assert_eq!(
        venue.anchor(&setup.anchor(4, 1)),
        AnchorOutcome::Never(Error::WindowNotAfterLast as u32)
    );
    assert_eq!(venue.held(&setup.space, 6), Held::Nothing, "past the last");
    assert_eq!(setup.anchors_sent(), 1);
    assert!(!setup.anchored_window(4), "a window behind the last");
    assert!(venue.alerts().is_empty(), "{:?}", venue.alerts());
}

/// A second anchor key the space lists, stolen: the attacker's account,
/// its authority, anchors window 5's root `[9; 32]` before the node.
const ATTACKER: [u8; 32] = [0x66; 32];

impl Setup {
    pub(super) fn stolen(&self) -> SigningKey {
        let stolen = SigningKey::from_bytes(&[0x66; 32]);
        self.call(
            CONTROLLER,
            Call::AddAuthority {
                space: self.space.0,
                who: ATTACKER,
                anchor_key: Some(stolen.verifying_key().to_bytes()),
            },
        );
        stolen
    }

    /// The attacker's anchor of window 5, dispatched on the chain.
    pub(super) fn attack(&self, chain: &mut Chain, stolen: &SigningKey) {
        let mut anchor = Anchor {
            signer: stolen.verifying_key().to_bytes(),
            ..self.anchor(5, 9)
        };
        anchor.signature = stolen.sign(&anchor.digest(&VENUE)).to_bytes();
        let outcome = chain.submit(Origin::Signed(ATTACKER), &Call::anchor(&anchor).bytes());
        assert!(
            outcome.events.iter().any(|event| matches!(
                event,
                crate::kreivo::mock::types::Event::Anchored { window: 5, .. }
            )),
            "{outcome:?}"
        );
    }

    /// The node's anchor of window 5 made the equivocation's evidence: the
    /// space ended, the evidence naming the attacker's key first and the
    /// node's second, neither root anchored, the client alerting.
    pub(super) fn evidence_lands(&self, venue: &KreivoVenue, stolen: &SigningKey) {
        wait_until("the evidence ends the space", || {
            venue.status(&self.space) == Status::Ended
        });
        let evidence = self.chain.with(|chain| {
            chain
                .storage()
                .get(&keys::equivocations(&self.space.0, 0, 5))
                .cloned()
        });
        let evidence: crate::kreivo::mock::types::Evidence =
            calls::read(&evidence.expect("the evidence")).unwrap();
        assert_eq!(evidence.first_signer, stolen.verifying_key().to_bytes());
        assert_eq!(evidence.second_signer, self.key.verifying_key().to_bytes());
        assert_eq!((evidence.first, evidence.second), ([9; 32], [1; 32]));
        for root in [[9; 32], [1; 32]] {
            let read = RootRead {
                kind: RootKind::Space,
                space: self.space,
                window: 5,
                root,
            };
            assert!(!venue.anchored(&read), "an ended space's root");
        }
        assert_eq!(self.anchors_sent(), 1);
        assert!(
            venue.alerts().contains(&Alert::Equivocation {
                space: self.space,
                window: 5
            }),
            "{:?}",
            venue.alerts()
        );
    }
}

impl Setup {
    /// `venue` offered the node's anchor of window 5 while the venue holds
    /// the attacker's root there: not sent, the root read; offered again
    /// once read, as the leader does once its divergence guard passed, it
    /// goes as the evidence.
    pub(super) fn offer_over(&self, venue: &KreivoVenue, stolen: &SigningKey) {
        wait_until("the attacker's root read", || {
            venue.held(&self.space, 5) == Held::Root([9; 32])
        });
        wait_until("nothing queued", || venue.queued() == 0);
        assert_eq!(self.anchors_sent(), 0, "not sent over another root");
        assert_eq!(venue.anchor(&self.anchor(5, 1)), AnchorOutcome::Taken);
        self.evidence_lands(venue, stolen);
    }
}

/// A listed key stolen anchors another root first: the node's anchor is
/// not sent over it until the leader, having read that root, offers it
/// again; then the pallet keeps it as the evidence, which ends the space;
/// its anchors are then stopped.
#[test]
fn an_anchor_over_another_root_goes_as_evidence() {
    let setup = Setup::new(false);
    let stolen = setup.stolen();
    setup.chain.with(|chain| setup.attack(chain, &stolen));
    let venue = setup.venue();
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    setup.offer_over(&venue, &stolen);
    assert_eq!(
        venue.anchor(&setup.anchor(6, 1)),
        AnchorOutcome::Stopped(Error::SpaceNotActive as u32)
    );
}

/// A listed key stolen anchors another root after the node's anchor was
/// queued, before it went: the node's is not sent until offered again,
/// then goes as the evidence.
#[test]
fn a_queued_anchor_overtaken_goes_as_evidence() {
    let setup = Setup::new(false);
    let stolen = setup.stolen();
    let venue = setup.venue();
    setup
        .chain
        .with(|chain| chain.set_storage(keys::paused(), vec![2]));
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::NotYet);
    setup.chain.with(|chain| {
        chain.set_storage(keys::paused(), vec![0]);
        setup.attack(chain, &stolen);
    });
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    setup.offer_over(&venue, &stolen);
    wait_until("the queue empties", || venue.queued() == 0);
}

/// The node's anchor lands first and a stolen key equivocates: once the
/// client reads the space ended, the root it saw held is not anchored.
#[test]
fn a_root_seen_held_is_not_anchored_once_its_space_ends() {
    let setup = Setup::new(false);
    let stolen = setup.stolen();
    let venue = setup.venue();
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    wait_until("window 5 lands", || setup.anchored_window(5));
    let read = RootRead {
        kind: RootKind::Space,
        space: setup.space,
        window: 5,
        root: [1; 32],
    };
    wait_until("the root seen held", || venue.anchored(&read));
    let mut other = Anchor {
        signer: stolen.verifying_key().to_bytes(),
        ..setup.anchor(5, 9)
    };
    other.signature = stolen.sign(&other.digest(&VENUE)).to_bytes();
    setup.call(ATTACKER, Call::anchor(&other));
    wait_until("the end is read", || {
        venue.status(&setup.space) == Status::Ended
    });
    assert!(!venue.anchored(&read), "an ended space's root");
}

/// An anchor of the venue's open window is sent, refused
/// `WindowInFuture`, kept, and sent again a block of the venue's time
/// later: once the venue has closed the window, it lands.
#[test]
fn an_open_window_is_sent_again_a_block_later() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    assert_eq!(venue.anchor(&setup.anchor(6, 1)), AnchorOutcome::Taken);
    wait_until("refused once", || setup.anchors_sent() == 1);
    read_again(&venue);
    assert_eq!(setup.anchors_sent(), 1, "it waits a block");
    assert_eq!(venue.queued(), 1, "it is kept");
    setup.set_now(CLOCK.boundary(6).unwrap() + 1);
    wait_until("window 6 lands", || setup.anchored_window(6));
    assert_eq!(setup.anchors_sent(), 2);
    assert!(venue.alerts().is_empty(), "{:?}", venue.alerts());
}
