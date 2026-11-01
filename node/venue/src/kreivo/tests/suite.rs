use super::*;

/// The mock driven by the venue rules' suite, through its calls: each
/// error mapped back to the rules' refusal.
struct Pallet {
    chain: Chain,
}

impl Pallet {
    fn new() -> Self {
        let mut chain = Chain::new(Constants::kreivo(VENUE));
        let funded = Account {
            free: 100 * UNITS,
            providers: 1,
            ..Account::default()
        };
        chain.set_account(OPERATOR, funded);
        chain.set_account(CONTROLLER, funded);
        Self { chain }
    }

    /// `call` by `who`: Ok, its events; or its pallet error.
    fn call(
        &mut self,
        who: [u8; 32],
        call: Call,
    ) -> Result<Vec<crate::kreivo::mock::types::Event>, Error> {
        let outcome = self.chain.submit(Origin::Signed(who), &call.bytes());
        match outcome.verdict {
            Verdict::Ok => Ok(outcome.events),
            Verdict::Err(crate::kreivo::mock::types::DispatchError::Module(module)) => {
                Err(Error::from_index(module.error[0]).expect("a pallet error"))
            }
            other => panic!("{call:?}: {other:?}"),
        }
    }
}

impl vos_anchor::suite::Harness for Pallet {
    fn venue(&self) -> VenueId {
        VENUE
    }

    fn set_now(&mut self, now: u64) {
        self.chain.set_now(now);
    }

    fn key(&self, seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn sign(&self, seed: u8, digest: &[u8; 32]) -> [u8; 64] {
        SigningKey::from_bytes(&[seed; 32]).sign(digest).to_bytes()
    }

    fn controller(&self) -> [u8; 32] {
        CONTROLLER
    }

    fn register(
        &mut self,
        genesis: &SpaceGenesis,
        controller: &[u8; 32],
        founder_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), vos_anchor::venue::RegisterRefusal> {
        use vos_anchor::venue::RegisterRefusal as Rule;
        let sovereign = calls::sovereign(&vos_anchor::space_id(genesis));
        if self.chain.account(&sovereign).free == 0 {
            let funded = Account {
                free: 10 * UNITS,
                ..Account::default()
            };
            self.chain.set_account(sovereign, funded);
        }
        let register = Call::Register {
            genesis: genesis.encode(),
            controller: *controller,
            founder_key,
            founder_sig: signature,
        };
        self.call(OPERATOR, register)
            .map(|_| ())
            .map_err(|error| match error {
                Error::BadGenesis => Rule::Genesis,
                Error::BadClock => Rule::Clock,
                Error::BadFounder => Rule::Founder,
                Error::SpaceExists => Rule::Exists,
                other => panic!("{other:?}"),
            })
    }

    fn start(&self, space: &SpaceId) -> Option<u64> {
        self.chain.space(&space.0).map(|info| info.start_window)
    }

    fn anchor(&mut self, anchor: &Anchor) -> vos_anchor::suite::Answer {
        use vos_anchor::suite::Answer;
        use vos_anchor::venue::AnchorRefusal as Rule;
        match self.call(OPERATOR, Call::anchor(anchor)) {
            Ok(events) => {
                let ended = events.iter().any(|event| {
                    matches!(event, crate::kreivo::mock::types::Event::SpaceEnded { .. })
                });
                if ended { Answer::Evidence } else { Answer::New }
            }
            Err(Error::AlreadyAnchored) => Answer::Again,
            Err(error) => Answer::Refused(match error {
                Error::UnknownSpace => Rule::Unregistered,
                Error::SpaceNotActive => Rule::Stopped,
                Error::UnknownAnchorKey => Rule::Key,
                Error::BadAnchorSignature => Rule::Signature,
                Error::WindowNotAfterLast => Rule::Window,
                Error::WindowInFuture => Rule::Open,
                Error::WindowTooOld => Rule::Age,
                other => panic!("{other:?}"),
            }),
        }
    }

    fn add_key(&mut self, space: &SpaceId, key: [u8; 32]) -> bool {
        let add = Call::AddAuthority {
            space: space.0,
            who: key,
            anchor_key: Some(key),
        };
        self.call(CONTROLLER, add).is_ok()
    }

    fn remove_key(&mut self, space: &SpaceId, key: [u8; 32]) -> bool {
        let remove = Call::RemoveAuthority {
            space: space.0,
            who: key,
        };
        self.call(CONTROLLER, remove).is_ok()
    }

    fn status(&self, space: &SpaceId) -> Option<vos_anchor::venue::Status> {
        self.chain.space(&space.0).map(|info| info.status.into())
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.chain.anchored(root)
    }
}

/// The mock judges as the venue rules do.
#[test]
fn the_mock_passes_the_venue_rules_suite() {
    vos_anchor::suite::run(Pallet::new);
}

/// An equivocation ends a space at the mock: its status stored as
/// `Ended`, index 3; its registration deposit released to its sovereign
/// account, its existential deposit kept; its controller's
/// `dispatch_as_sovereign` still callable, so the funds leave.
#[test]
fn an_ended_spaces_deposit_is_released_and_its_funds_leave() {
    let setup = Setup::new(false);
    let stolen = setup.stolen();
    let sovereign = calls::sovereign(&setup.space);
    let before = setup.chain.with(|chain| chain.account(&sovereign));
    let deposit = Constants::kreivo(VENUE).registration_deposit;
    assert_eq!(before.held_registration, deposit);
    setup.chain.with(|chain| setup.attack(chain, &stolen));
    setup.call(NODE, Call::anchor(&setup.anchor(5, 1)));
    let (stored, after) = setup.chain.with(|chain| {
        let info = chain.storage()[&keys::spaces(&setup.space.0)].clone();
        (info, chain.account(&sovereign))
    });
    let info: SpaceInfo = calls::read(&stored).unwrap();
    assert_eq!(info.status, SpaceStatus::Ended);
    assert_eq!(SpaceStatus::Ended.encode(), [3]);
    assert_eq!(after.held_registration, 0);
    assert_eq!(after.free, before.free + deposit);

    let ed = Constants::kreivo(VENUE).existential_deposit;
    let transfer = calls::RuntimeCall::Balances(calls::BalancesCall::TransferKeepAlive {
        dest: calls::MultiAddress::Id(OPERATOR),
        value: after.free - ed,
    });
    setup.call(
        CONTROLLER,
        Call::DispatchAsSovereign {
            space: setup.space.0,
            call: Box::new(transfer),
        },
    );
    assert_eq!(setup.chain.with(|chain| chain.account(&sovereign)).free, ed);
}
