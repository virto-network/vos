use super::*;

/// A transport that forwards to `inner`: `on_sign` sees each nonce signed
/// first, and `on_send` answers a send in `inner`'s place when it
/// returns an answer.
struct Hooked {
    inner: Arc<dyn Transport>,
    on_sign: Box<dyn Fn(u64) + Send + Sync>,
    on_send: Box<dyn Fn() -> Option<Result<Included, SendError>> + Send + Sync>,
}

impl Transport for Hooked {
    fn account(&self) -> [u8; 32] {
        self.inner.account()
    }
    fn genesis(&self) -> Result<[u8; 32], Lost> {
        self.inner.genesis()
    }
    fn best(&self) -> Result<u64, Lost> {
        self.inner.best()
    }
    fn nonce(&self) -> Result<u64, Lost> {
        self.inner.nonce()
    }
    fn chain_nonce(&self) -> Result<u64, Lost> {
        self.inner.chain_nonce()
    }
    fn sign(&self, call: &[u8], nonce: u64) -> Result<Signed, SendError> {
        (self.on_sign)(nonce);
        self.inner.sign(call, nonce)
    }
    fn send(&self, signed: &Signed) -> Result<Included, SendError> {
        (self.on_send)().unwrap_or_else(|| self.inner.send(signed))
    }
    fn storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Lost> {
        self.inner.storage(key)
    }
    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Lost> {
        self.inner.keys(prefix)
    }
}

/// A blocked or ended space is sent nothing: its anchors are stopped at
/// once, and an anchor queued before a block is dropped unsent; offered
/// again once the space is active, it lands.
#[test]
fn a_stopped_space_is_sent_nothing() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    for status in [SpaceStatus::Ended, SpaceStatus::Blocked] {
        setup.set_status(status);
        wait_until("the status is read", || {
            venue.status(&setup.space) == calls_status(status)
        });
        assert!(venue.status(&setup.space).waits());
        assert_eq!(
            venue.anchor(&setup.anchor(5, 1)),
            AnchorOutcome::Stopped(Error::SpaceNotActive as u32)
        );
    }
    setup.set_status(SpaceStatus::Active);
    wait_until("the unblock is read", || {
        venue.status(&setup.space) == Status::Active
    });
    // The open window's anchor, refused `WindowInFuture`, waits a block.
    assert_eq!(venue.anchor(&setup.anchor(6, 1)), AnchorOutcome::Taken);
    wait_until("refused once", || setup.anchors_sent() == 1);
    setup.set_status(SpaceStatus::Blocked);
    wait_until("the block is read", || {
        venue.status(&setup.space) == Status::Blocked
    });
    setup.set_now(CLOCK.boundary(6).unwrap() + 1);
    wait_until("dropped", || venue.queued() == 0);
    assert_eq!(setup.anchors_sent(), 1, "nothing sent while blocked");
    setup.set_status(SpaceStatus::Active);
    wait_until("the unblock is read", || {
        venue.status(&setup.space) == Status::Active
    });
    assert_eq!(venue.anchor(&setup.anchor(6, 1)), AnchorOutcome::Taken);
    wait_until("window 6 lands", || setup.anchored_window(6));
    assert_eq!(setup.anchors_sent(), 2);
}

/// Paused anchors are not taken, and not sent, until the pause lifts.
#[test]
fn a_paused_venue_is_sent_no_anchor() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    setup
        .chain
        .with(|chain| chain.set_storage(keys::paused(), vec![2]));
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::NotYet);
    std::thread::sleep(A_WHILE);
    assert_eq!(setup.anchors_sent(), 0);
    setup
        .chain
        .with(|chain| chain.set_storage(keys::paused(), vec![0]));
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    wait_until("window 5 lands", || setup.anchored_window(5));
    assert_eq!(setup.anchors_sent(), 1);
}

/// The budget spent: the venue refuses the anchor's fee before inclusion,
/// which alerts and keeps it; a submit is not sent at all. A sovereign
/// account short of the funding floor alerts.
#[test]
fn the_budgets_refusal_raises_a_funding_alert() {
    let setup = Setup::new(true);
    setup.call(
        CONTROLLER,
        Call::SetBudget {
            space: setup.space.0,
            max_spend_per_window: 0,
        },
    );
    let venue = setup.venue();
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    wait_until("the funding alert", || {
        venue
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::Funding { .. }))
    });
    assert!(!setup.anchored_window(5));
    assert_eq!(venue.queued(), 1, "kept for the next window's budget");

    let statement = vos_statement::Statement {
        format: 39,
        program: vos_statement::ProgramId([5; 8]),
        space: SpaceId::NONE,
        public_args: Vec::new(),
        output: Vec::new(),
        roots: Vec::new(),
    };
    let active = calls::Active {
        from_ms: 0,
        until_ms: None,
    };
    setup.chain.with(|chain| {
        chain.set_storage(keys::formats(39), active.encode());
        let info = calls::ProgramInfo {
            handler: calls::Handler::Record,
            active,
        };
        chain.set_storage(keys::programs(&[5; 8]), info.encode());
    });
    let before = setup.chain.sends().len();
    assert_eq!(
        venue.submit(&statement, &[0]),
        SubmitOutcome::Retry(UNJUDGED)
    );
    assert!(setup.chain.sends().len() - before <= 1, "no submit sent");
    assert!(
        setup
            .chain
            .sends()
            .iter()
            .all(|(_, call)| call[..2] != [PALLET, 8])
    );

    let short = Setup::new(true);
    short.chain.with(|chain| {
        let sovereign = calls::sovereign(&short.space);
        let mut account = chain.account(&sovereign);
        account.free = UNITS;
        chain.set_account(sovereign, account);
    });
    let venue = short.venue();
    assert!(
        venue
            .alerts()
            .iter()
            .any(|alert| matches!(alert, Alert::Funding { .. }))
    );
}

/// A send whose answer is lost after it landed is not sent again: the
/// signer's nonce says it landed, and the venue's storage that it is
/// held. A send dropped before it landed goes again as the same bytes,
/// and lands once.
#[test]
fn a_lost_connection_never_sends_a_call_twice() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    setup.chain.fault(Fault::LoseAnswer);
    assert_eq!(venue.anchor(&setup.anchor(4, 1)), AnchorOutcome::Taken);
    wait_until("the queue empties", || venue.queued() == 0);
    assert!(setup.anchored_window(4));
    assert_eq!(setup.anchors_sent(), 1, "not sent again");
    let read = RootRead {
        kind: RootKind::Space,
        space: setup.space,
        window: 4,
        root: [1; 32],
    };
    assert!(venue.anchored(&read));

    setup.chain.fault(Fault::Drop);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    wait_until("window 5 lands", || setup.anchored_window(5));
    assert_eq!(setup.anchors_sent(), 3, "the dropped one sent again");
    let included = setup
        .chain
        .included()
        .iter()
        .filter(|(origin, call)| *origin == Origin::Signed(NODE) && call[..2] == [PALLET, 7])
        .count();
    assert_eq!(included, 2, "each included once");
    assert!(venue.alerts().is_empty(), "{:?}", venue.alerts());
}

/// An anchor whose extrinsic waits in the pool is not taken as landed by
/// the pool's count: it stays queued, its same bytes sent again. Once the
/// pool is included, the nonce in the chain's state says it landed and
/// its record that it is held; one dropped from the pool goes again as the
/// same bytes and lands once.
#[test]
fn a_pooled_anchor_lands_once() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    setup.chain.fault(Fault::Pool);
    assert_eq!(venue.anchor(&setup.anchor(4, 1)), AnchorOutcome::Taken);
    wait_until("its bytes are sent again", || setup.anchors_sent() >= 3);
    assert!(!setup.anchored_window(4));
    assert_eq!(venue.queued(), 1, "kept while it may land");
    setup.chain.include_pool();
    wait_until("the queue empties", || venue.queued() == 0);
    assert!(setup.anchored_window(4));

    setup.chain.fault(Fault::Pool);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    wait_until("it waits in the pool", || setup.chain.pooled() == 1);
    setup.chain.drop_pool();
    wait_until("window 5 lands", || setup.anchored_window(5));
    let included = setup
        .chain
        .included()
        .iter()
        .filter(|(origin, call)| *origin == Origin::Signed(NODE) && call[..2] == [PALLET, 7])
        .count();
    assert_eq!(included, 2, "each included once");
}

/// A key removed after its anchor was queued: the venue refuses it
/// (`UnknownAnchorKey`), or the client, once it reads the listing, sends
/// it no more; it drops it, and answers the anchor unlisted. Listed again,
/// the anchor is taken, sent and lands.
#[test]
fn a_refused_key_is_answered_unlisted() {
    let setup = Setup::new(true);
    let venue = setup.venue();
    assert_eq!(venue.anchor(&setup.anchor(6, 1)), AnchorOutcome::Taken);
    wait_until("refused once, for its open window", || {
        setup.anchors_sent() == 1
    });
    let key = keys::anchor_keys(&setup.space.0, &setup.key.verifying_key().to_bytes());
    let value = setup.chain.with(|chain| chain.storage()[&key].clone());
    setup.chain.with(|chain| chain.remove_storage(&key));
    setup.set_now(CLOCK.boundary(6).unwrap() + 1);
    wait_until("dropped", || venue.queued() == 0);
    assert_eq!(
        venue.anchor(&setup.anchor(6, 1)),
        AnchorOutcome::Unlisted(Error::UnknownAnchorKey as u32),
        "its key not listed"
    );
    // Refused by the venue, or unsent once the client read the listing.
    let refused = setup.anchors_sent();
    assert!(refused <= 2);
    assert!(!setup.anchored_window(6));
    setup.chain.with(|chain| chain.set_storage(key, value));
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(6, 1)), AnchorOutcome::Taken);
    wait_until("the anchor lands", || setup.anchored_window(6));
    assert_eq!(setup.anchors_sent(), refused + 1);
}

/// A key `AnchorKeys` still lists while its account is no authority: the
/// venue refuses the anchor `NotAuthority`, a fee each time. The client
/// answers the signer unlisted, unsent, while it reads the same listing;
/// once the listing changes it sends again, and the anchor lands.
#[test]
fn a_refused_signer_is_not_sent_again_under_the_same_listing() {
    let setup = Setup::new(true);
    let refusing = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let refused = Arc::new(AtomicUsize::new(0));
    let (refuse, count) = (Arc::clone(&refusing), Arc::clone(&refused));
    let hooked = Arc::new(Hooked {
        inner: setup.chain.transport(Origin::Signed(NODE)),
        on_sign: Box::new(|_| {}),
        on_send: Box::new(move || {
            refuse.load(Ordering::SeqCst).then(|| {
                count.fetch_add(1, Ordering::SeqCst);
                let failure = calls::Failure::Module {
                    pallet: PALLET,
                    error: Error::NotAuthority as u8,
                };
                Ok(Included {
                    block: 0,
                    events: Vec::new(),
                    failure: Some(failure.encode()),
                })
            })
        }),
    });
    let venue = setup.venue_over(hooked);
    let unlisted = AnchorOutcome::Unlisted(Error::NotAuthority as u32);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    wait_until("answered unlisted", || {
        venue.anchor(&setup.anchor(5, 1)) == unlisted
    });
    read_again(&venue);
    assert_eq!(
        venue.anchor(&setup.anchor(5, 1)),
        unlisted,
        "the same listing"
    );
    std::thread::sleep(A_WHILE);
    assert_eq!(refused.load(Ordering::SeqCst), 1, "not sent again");
    refusing.store(false, Ordering::SeqCst);
    let other = SigningKey::from_bytes(&[0x42; 32])
        .verifying_key()
        .to_bytes();
    setup.chain.with(|chain| {
        chain.set_storage(
            keys::anchor_keys(&setup.space.0, &other),
            None::<[u8; 32]>.encode(),
        )
    });
    read_again(&venue);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    wait_until("the anchor lands", || setup.anchored_window(5));
}

/// A venue whose chain cannot be reached at first: the client starts all
/// the same, every anchor `Open`; once reached, the anchor lands.
#[test]
fn a_venue_reached_late_anchors_once_reached() {
    let setup = Setup::new(true);
    let tries = Arc::new(AtomicUsize::new(0));
    let (chain, counted) = (Arc::clone(&setup.chain), Arc::clone(&tries));
    let connect: crate::kreivo::venue::Connect = Box::new(move || {
        if counted.fetch_add(1, Ordering::SeqCst) < 3 {
            return Err(Lost("down".into()));
        }
        Ok(chain.transport(Origin::Signed(NODE)) as Arc<dyn Transport>)
    });
    let venue = KreivoVenue::connect(connect, &[setup.space], setup.space, options());
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::NotYet);
    assert_eq!(venue.status(&setup.space), Status::Unregistered);
    wait_until("reached and read", || {
        venue.status(&setup.space) == Status::Active
    });
    assert!(tries.load(Ordering::SeqCst) >= 4);
    assert_eq!(venue.id(), VENUE);
    assert_eq!(venue.anchor(&setup.anchor(5, 1)), AnchorOutcome::Taken);
    wait_until("window 5 lands", || setup.anchored_window(5));
}

/// A sender whose call's answer is lost, and whose era then runs out
/// before it lands, signs it again with the same nonce: it lands once.
#[test]
fn an_expired_send_is_signed_again_with_its_nonce() {
    let setup = Setup::new(true);
    let transport = setup.chain.transport(Origin::Signed(NODE));
    let signs = Arc::new(Mutex::new(Vec::new()));
    let signed = Arc::clone(&signs);
    let sent = Arc::clone(&signs);
    let chain = Arc::clone(&setup.chain);
    let counting = Arc::new(Hooked {
        inner: transport,
        on_sign: Box::new(move |nonce| signed.lock().unwrap().push(nonce)),
        on_send: Box::new(move || {
            (sent.lock().unwrap().len() == 1).then(|| {
                chain.advance(100);
                Err(SendError::Lost(Lost("lost".into())))
            })
        }),
    });
    let sender = Sender::new(counting, Duration::from_millis(1));
    let sent = sender.call(&Call::anchor(&setup.anchor(5, 1)).bytes());
    assert!(matches!(sent, Ok(Sent::Included(_))), "{sent:?}");
    assert_eq!(*signs.lock().unwrap(), [0, 0], "signed again, same nonce");
    assert!(setup.anchored_window(5));
}
