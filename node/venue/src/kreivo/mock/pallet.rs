//! The spaces pallet's calls (`spaces-pallet.md` §6), each dispatched
//! on the chain transactionally.

use vos_anchor::venue::{self as rules, AnchorRefusal, Anchoring, RegisterRefusal};
use vos_anchor::{Anchor, RootKind, SpaceGenesis, SpaceId};
use vos_statement::{Refusal, Statement, StatementId};

use super::chain::{Chain, Dispatched, Origin};
use super::keys;
use super::types::{
    AccountId, Active, AnchorArg, AnchorRecord, AuthorityInfo, Balance, Call, DispatchError, Error,
    Event, Evidence, PAUSE_ANCHOR, PAUSE_REGISTER, PAUSE_SUBMIT, ProgramInfo, RuntimeCall, Space,
    SpaceInfo, SpaceStatus, StorageVenue,
};

impl Chain {
    pub(super) fn spaces(
        &mut self,
        origin: Origin,
        call: Call,
        events: &mut Vec<Event>,
    ) -> Dispatched {
        match call {
            Call::Register {
                genesis,
                controller,
                founder_key,
                founder_sig,
            } => {
                signed(origin)?;
                self.register(&genesis, controller, &founder_key, &founder_sig, events)
            }
            Call::SetController { space, controller } => {
                let mut info = self.controlled(origin, &space)?;
                info.controller = controller;
                self.put(keys::spaces(&space), &info);
                events.push(Event::ControllerSet { space, controller });
                Ok(())
            }
            Call::AddAuthority {
                space,
                who,
                anchor_key,
            } => self.add_authority(origin, space, who, anchor_key, events),
            Call::RemoveAuthority { space, who } => {
                self.remove_authority(origin, space, who, events)
            }
            Call::RemoveAnchorKey { space, key } => {
                self.remove_anchor_key(origin, space, key, events)
            }
            Call::Anchor { anchor } => {
                signed(origin)?;
                self.anchor(&anchor, events)
            }
            Call::Submit {
                payer,
                statement,
                proof,
            } => {
                let who = signed(origin)?;
                self.submit_statement(&who, payer, &statement, &proof, events)
            }
            Call::DispatchAsSovereign { space, call } => {
                self.dispatch_as_sovereign(origin, space, *call, events)
            }
            Call::SetBudget {
                space,
                max_spend_per_window,
            } => self.set_budget(origin, space, max_spend_per_window, events),
            Call::SetFormat { format, active } => {
                let stored: Option<Active> = self.get(&keys::formats(format));
                self.governed(origin, &active, stored.as_ref(), true)?;
                self.put(keys::formats(format), &active);
                events.push(Event::FormatSet { format, active });
                Ok(())
            }
            Call::SetProgram { program, info } => self.set_program(origin, program, info, events),
            Call::SetPaused { flags } => {
                if !matches!(origin, Origin::Emergency | Origin::Root) {
                    return Err(DispatchError::BadOrigin);
                }
                self.put(keys::paused(), &flags);
                events.push(Event::PausedSet { flags });
                Ok(())
            }
            Call::SetStatus { space, blocked } => self.set_status(origin, space, blocked, events),
        }
    }

    fn remove_anchor_key(
        &mut self,
        origin: Origin,
        space: Space,
        key: [u8; 32],
        events: &mut Vec<Event>,
    ) -> Dispatched {
        let mut info = self.controlled(origin, &space)?;
        match self.get::<Option<AccountId>>(&keys::anchor_keys(&space, &key)) {
            None => return Err(Error::UnknownAnchorKey.into()),
            Some(Some(_)) => return Err(Error::AnchorKeyInUse.into()),
            Some(None) => {}
        }
        self.storage.remove(&keys::anchor_keys(&space, &key));
        info.anchor_keys -= 1;
        self.put(keys::spaces(&space), &info);
        events.push(Event::AnchorKeyRemoved { space, key });
        Ok(())
    }

    fn dispatch_as_sovereign(
        &mut self,
        origin: Origin,
        space: Space,
        call: RuntimeCall,
        events: &mut Vec<Event>,
    ) -> Dispatched {
        let info = self.controlled(origin, &space)?;
        let mut inner = Vec::new();
        let result = self.transactional(|chain| {
            chain.dispatch(Origin::Signed(info.sovereign), call, &mut inner)
        });
        if result.is_ok() {
            events.append(&mut inner);
        }
        events.push(Event::SovereignDispatched { space, result });
        Ok(())
    }

    fn set_budget(
        &mut self,
        origin: Origin,
        space: Space,
        max_spend_per_window: Balance,
        events: &mut Vec<Event>,
    ) -> Dispatched {
        let mut info = self.controlled(origin, &space)?;
        info.max_spend_per_window = max_spend_per_window;
        self.put(keys::spaces(&space), &info);
        events.push(Event::BudgetSet {
            space,
            max_spend_per_window,
        });
        Ok(())
    }

    fn set_status(
        &mut self,
        origin: Origin,
        space: Space,
        blocked: bool,
        events: &mut Vec<Event>,
    ) -> Dispatched {
        if !matches!(origin, Origin::Status | Origin::Root) {
            return Err(DispatchError::BadOrigin);
        }
        let mut info = self.space(&space).ok_or(Error::UnknownSpace)?;
        if info.status == SpaceStatus::Ended {
            return Err(Error::SpaceNotActive.into());
        }
        info.status = if blocked {
            SpaceStatus::Blocked
        } else {
            SpaceStatus::Active
        };
        self.put(keys::spaces(&space), &info);
        events.push(Event::SpaceStatusSet {
            space,
            status: info.status,
        });
        Ok(())
    }

    fn paused(&self, bit: u8) -> Dispatched {
        let flags: u8 = self.get(&keys::paused()).unwrap_or(0);
        if flags & bit != 0 {
            return Err(Error::Paused.into());
        }
        Ok(())
    }

    /// The space `origin` controls: a signed origin, the space known, the
    /// signer its controller.
    fn controlled(&self, origin: Origin, space: &Space) -> Result<SpaceInfo, DispatchError> {
        let who = signed(origin)?;
        let info = self.space(space).ok_or(Error::UnknownSpace)?;
        if info.controller != who {
            return Err(Error::NotController.into());
        }
        Ok(info)
    }

    /// `spaces-pallet.md` §6.2: the venue rules' registration, then the
    /// sovereign account's.
    fn register(
        &mut self,
        genesis: &[u8],
        controller: AccountId,
        founder_key: &[u8; 32],
        founder_sig: &[u8; 64],
        events: &mut Vec<Event>,
    ) -> Dispatched {
        self.paused(PAUSE_REGISTER)?;
        let genesis = SpaceGenesis::decode(genesis).map_err(|_| Error::BadGenesis)?;
        let refused = |refusal| match refusal {
            RegisterRefusal::Genesis => Error::BadGenesis,
            RegisterRefusal::Clock => Error::BadClock,
            RegisterRefusal::Founder => Error::BadFounder,
            RegisterRefusal::Exists => Error::SpaceExists,
        };
        let registration = rules::registration(
            &self.constants.venue,
            &genesis,
            &controller,
            founder_key,
            founder_sig,
            crate::verify,
        )
        .map_err(refused)?;
        let start_window =
            rules::register(&StorageVenue { chain: self }, &registration).map_err(refused)?;
        let space = registration.space.0;
        let sovereign = self.constants.sovereign(&space);
        if self.storage.contains_key(&keys::sovereign_of(&sovereign)) {
            return Err(Error::SovereignInUse.into());
        }
        let deposit = self.constants.registration_deposit;
        if !self.can_hold(&sovereign, deposit) {
            return Err(Error::InsufficientSovereignBalance.into());
        }
        let account = self.account_mut(&sovereign);
        account.free -= deposit;
        account.held_registration += deposit;
        account.providers += 1;
        let clock = registration.clock;
        let info = SpaceInfo {
            sovereign,
            controller,
            origin_ms: clock.origin_ms,
            length_ms: clock.length_ms,
            start_window,
            status: SpaceStatus::Active,
            authorities: 0,
            anchor_keys: registration.keys.len() as u8,
            registered_ms: self.now_ms,
            max_spend_per_window: self.constants.default_spend_per_window,
        };
        self.put(keys::spaces(&space), &info);
        self.put(keys::sovereign_of(&sovereign), &space);
        for key in &registration.keys {
            self.put(keys::anchor_keys(&space, key), &None::<AccountId>);
        }
        events.push(Event::SpaceRegistered {
            space,
            sovereign,
            controller,
            origin_ms: clock.origin_ms,
            length_ms: clock.length_ms,
            start_window,
        });
        Ok(())
    }

    fn add_authority(
        &mut self,
        origin: Origin,
        space: Space,
        who: AccountId,
        anchor_key: Option<[u8; 32]>,
        events: &mut Vec<Event>,
    ) -> Dispatched {
        let mut info = self.controlled(origin, &space)?;
        if self.storage.contains_key(&keys::authorities(&space, &who)) {
            return Err(Error::AuthorityExists.into());
        }
        if info.authorities >= self.constants.max_authorities {
            return Err(Error::TooManyAuthorities.into());
        }
        if let Some(key) = anchor_key {
            if rules::small_order(&key) {
                return Err(Error::BadAnchorKey.into());
            }
            match self.get::<Option<AccountId>>(&keys::anchor_keys(&space, &key)) {
                Some(Some(_)) => return Err(Error::AnchorKeyInUse.into()),
                Some(None) => {}
                None => {
                    if info.anchor_keys >= self.constants.max_anchor_keys {
                        return Err(Error::TooManyAnchorKeys.into());
                    }
                    info.anchor_keys += 1;
                }
            }
            self.put(keys::anchor_keys(&space, &key), &Some(who));
        }
        info.authorities += 1;
        self.account_mut(&who).providers += 1;
        self.put(keys::spaces(&space), &info);
        self.put(
            keys::authorities(&space, &who),
            &AuthorityInfo { anchor_key },
        );
        events.push(Event::AuthorityAdded {
            space,
            who,
            anchor_key,
        });
        Ok(())
    }

    fn remove_authority(
        &mut self,
        origin: Origin,
        space: Space,
        who: AccountId,
        events: &mut Vec<Event>,
    ) -> Dispatched {
        let mut info = self.controlled(origin, &space)?;
        let authority: AuthorityInfo = self
            .get(&keys::authorities(&space, &who))
            .ok_or(Error::NotAuthority)?;
        self.storage.remove(&keys::authorities(&space, &who));
        if let Some(key) = authority.anchor_key {
            self.storage.remove(&keys::anchor_keys(&space, &key));
            info.anchor_keys -= 1;
        }
        info.authorities -= 1;
        self.put(keys::spaces(&space), &info);
        // `dec_providers`, best effort: a `ConsumerRemaining` is ignored.
        let account = self.account_mut(&who);
        if account.providers > 1 || (account.providers == 1 && account.consumers == 0) {
            account.providers -= 1;
        }
        events.push(Event::AuthorityRemoved { space, who });
        Ok(())
    }

    /// `spaces-pallet.md` §6.1: the venue rules' anchor rule. A second
    /// root at a window held is the equivocation's evidence: kept, the
    /// space ended for good and its registration deposit released.
    fn anchor(&mut self, arg: &AnchorArg, events: &mut Vec<Event>) -> Dispatched {
        self.paused(PAUSE_ANCHOR)?;
        let kind = RootKind::from_u8(arg.kind).ok_or(Error::BadKind)?;
        let anchor = Anchor {
            space: SpaceId(arg.space),
            window: arg.window,
            kind,
            root: arg.root,
            signer: arg.signer,
            signature: arg.signature,
        };
        let anchoring = rules::anchor(&StorageVenue { chain: self }, &anchor).map_err(
            |refusal| match refusal {
                AnchorRefusal::Unregistered => Error::UnknownSpace,
                AnchorRefusal::Stopped => Error::SpaceNotActive,
                AnchorRefusal::Key => Error::UnknownAnchorKey,
                AnchorRefusal::Signature => Error::BadAnchorSignature,
                AnchorRefusal::Window => Error::WindowNotAfterLast,
                AnchorRefusal::Open => Error::WindowInFuture,
                AnchorRefusal::Age => Error::WindowTooOld,
            },
        )?;
        let (space, w) = (arg.space, arg.window);
        match anchoring {
            Anchoring::Again => Err(Error::AlreadyAnchored.into()),
            Anchoring::New => {
                let record = AnchorRecord {
                    root: arg.root,
                    at_ms: self.now_ms,
                    signer: arg.signer,
                };
                self.put(keys::anchors(&space, arg.kind, w), &record);
                self.put(keys::last(&space, arg.kind), &w);
                events.push(Event::Anchored {
                    space,
                    kind: arg.kind,
                    window: w,
                    root: arg.root,
                });
                Ok(())
            }
            Anchoring::Evidence(held) => {
                let evidence = Evidence {
                    first: held.root,
                    second: arg.root,
                    first_signer: held.signer,
                    second_signer: arg.signer,
                };
                self.put(keys::equivocations(&space, arg.kind, w), &evidence);
                let mut info = self.space(&space).ok_or(Error::UnknownSpace)?;
                info.status = SpaceStatus::Ended;
                self.put(keys::spaces(&space), &info);
                if !self.keeps_deposit() {
                    let account = self.account_mut(&info.sovereign);
                    let held = account.held_registration;
                    account.held_registration = 0;
                    account.free += held;
                }
                events.push(Event::Equivocated {
                    space,
                    kind: arg.kind,
                    window: w,
                    first: evidence.first,
                    second: evidence.second,
                    first_signer: evidence.first_signer,
                    second_signer: evidence.second_signer,
                });
                events.push(Event::SpaceEnded { space });
                Ok(())
            }
        }
    }

    /// `spaces-pallet.md` §6.3, in its order.
    fn submit_statement(
        &mut self,
        who: &AccountId,
        payer: Space,
        bytes: &[u8],
        proof: &[u8],
        events: &mut Vec<Event>,
    ) -> Dispatched {
        self.paused(PAUSE_SUBMIT)?;
        let info = self.space(&payer).ok_or(Error::UnknownSpace)?;
        if info.status != SpaceStatus::Active {
            return Err(Error::SpaceNotActive.into());
        }
        if !self.storage.contains_key(&keys::authorities(&payer, who)) {
            return Err(Error::NotAuthority.into());
        }
        let deposit = self.constants.submit_deposit;
        if !self.can_hold(&info.sovereign, deposit) {
            return Err(Error::InsufficientSovereignBalance.into());
        }
        let sovereign = self.account_mut(&info.sovereign);
        sovereign.free -= deposit;
        sovereign.held_submit += deposit;

        let verdict = self.judge(bytes, proof);
        let statement_hash = vos_anchor::blake2b_256(&[bytes]);
        match verdict {
            Ok((statement, id)) => {
                let expiry = self.space(&statement.space.0).map_or(u64::MAX, |space| {
                    vos_statement::seen_expiry(&statement, &Self::clock(&space))
                });
                self.put(keys::seen(&id.0), &expiry);
                self.release(&info.sovereign, deposit);
                events.push(Event::Accepted {
                    id: id.0,
                    program: statement.program.0,
                    space: statement.space.0,
                    payer,
                    output_hash: vos_anchor::blake2b_256(&[&statement.output]),
                });
            }
            Err(code) if code == Refusal::Repeated.code() => {
                self.release(&info.sovereign, deposit);
                events.push(Event::Refused {
                    payer,
                    statement_hash,
                    code,
                });
            }
            Err(code) => {
                let sovereign = self.account_mut(&info.sovereign);
                sovereign.held_submit -= deposit;
                let to = self.constants.forfeit_to;
                self.account_mut(&to).free += deposit;
                events.push(Event::Refused {
                    payer,
                    statement_hash,
                    code,
                });
                events.push(Event::DepositForfeited {
                    space: payer,
                    amount: deposit,
                });
            }
        }
        Ok(())
    }

    fn release(&mut self, who: &AccountId, deposit: Balance) {
        let account = self.account_mut(who);
        account.held_submit -= deposit;
        account.free += deposit;
    }

    /// Steps 6–9 of `spaces-pallet.md` §6.3: the statement decoded, its format
    /// and program active now, then `judge`. The statement and its id, or the
    /// refusal's code.
    fn judge(&self, bytes: &[u8], proof: &[u8]) -> Result<(Statement, StatementId), u32> {
        let statement =
            Statement::decode(bytes).map_err(|error| Refusal::Statement(error).code())?;
        let format: Option<Active> = self.get(&keys::formats(statement.format));
        if !format.is_some_and(|active| self.active(&active)) {
            return Err(Refusal::Format.code());
        }
        self.get::<ProgramInfo>(&keys::programs(&statement.program.0))
            .filter(|info| self.active(&info.active))
            .ok_or(Refusal::Program.code())?;
        let program = statement.program;
        let id = vos_statement::judge(&StorageVenue { chain: self }, &program, &statement, proof)
            .map_err(|refusal| refusal.code())?;
        Ok((statement, id))
    }

    fn set_program(
        &mut self,
        origin: Origin,
        program: [u32; 8],
        info: Option<ProgramInfo>,
        events: &mut Vec<Event>,
    ) -> Dispatched {
        let key = keys::programs(&program);
        let stored: Option<ProgramInfo> = self.get(&key);
        match info {
            Some(info) => {
                let rest_same = stored.is_some_and(|stored| stored.handler == info.handler);
                self.governed(
                    origin,
                    &info.active,
                    stored.as_ref().map(|stored| &stored.active),
                    rest_same,
                )?;
                self.put(key, &info);
            }
            None => match origin {
                Origin::Root => {
                    self.storage.remove(&key);
                }
                Origin::Programs => {
                    if let Some(mut stored) = stored {
                        let at = self
                            .now_ms
                            .saturating_add(self.constants.program_change_delay_ms);
                        stored.active.until_ms =
                            Some(stored.active.until_ms.map_or(at, |until| until.min(at)));
                        self.put(key, &stored);
                    }
                }
                _ => return Err(DispatchError::BadOrigin),
            },
        }
        events.push(Event::ProgramSet { program, info });
        Ok(())
    }

    /// `spaces-pallet.md` §6.4: Root at any time; `ProgramsOrigin` only with a
    /// delay. A change that only sets or shortens a stored entry's `until_ms`,
    /// the rest of it unchanged (`rest_same`), needs that `until_ms` no earlier
    /// than `now + ProgramChangeDelay`; any other, a new entry among them,
    /// needs its `from_ms` (and any `until_ms`) no earlier than that.
    fn governed(
        &self,
        origin: Origin,
        active: &Active,
        stored: Option<&Active>,
        rest_same: bool,
    ) -> Dispatched {
        match origin {
            Origin::Root => Ok(()),
            Origin::Programs => {
                let at = self
                    .now_ms
                    .saturating_add(self.constants.program_change_delay_ms);
                let shortened = stored
                    .filter(|stored| rest_same && stored.from_ms == active.from_ms)
                    .and_then(|stored| {
                        active
                            .until_ms
                            .filter(|until| stored.until_ms.is_none_or(|was| *until <= was))
                    });
                let early = match shortened {
                    Some(until) => until < at,
                    None => active.from_ms < at || active.until_ms.is_some_and(|until| until < at),
                };
                if early {
                    return Err(Error::TooEarly.into());
                }
                Ok(())
            }
            _ => Err(DispatchError::BadOrigin),
        }
    }

    /// Whether `root` is anchored here, by the venue rules over the
    /// pallet's storage (§3's `Venue::anchored`).
    pub fn anchored(&self, root: &vos_anchor::RootRead) -> bool {
        rules::anchored(&StorageVenue { chain: self }, root)
    }

    /// `spaces-pallet.md` §6.5, with weight enough for every entry: anchors
    /// past `MaxRootAge` (`vos_anchor::venue::aged`) and `Seen` entries past
    /// their expiry pruned; `Spaces`, `Last` and `Equivocations` kept.
    pub fn on_idle(&mut self) {
        let now = self.now_ms;
        for key in self.keys_under(&keys::Item::Anchors.prefix()) {
            let Some((space, window)) = keys::anchors_parts(&key) else {
                continue;
            };
            let aged = self
                .space(&space)
                .is_some_and(|info| rules::aged(&Self::clock(&info), window, now));
            if aged {
                self.storage.remove(&key);
            }
        }
        for key in self.keys_under(&keys::Item::Seen.prefix()) {
            let expiry: u64 = self.get(&key).expect("a Seen entry");
            if expiry < now {
                self.storage.remove(&key);
            }
        }
    }
}

fn signed(origin: Origin) -> Result<AccountId, DispatchError> {
    match origin {
        Origin::Signed(who) => Ok(who),
        _ => Err(DispatchError::BadOrigin),
    }
}
