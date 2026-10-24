//! The spaces pallet's calls (`spaces-pallet.md` §6), each dispatched
//! on the chain transactionally.

use ed25519_dalek::{Signature, VerifyingKey};
use vos_anchor::{RootKind, SpaceGenesis};
use vos_statement::{Pin, ProgramId, Refusal, Statement, StatementId};

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
                start_window,
                founder_key,
                founder_sig,
            } => {
                signed(origin)?;
                self.register(
                    &genesis,
                    controller,
                    start_window,
                    &founder_key,
                    &founder_sig,
                    events,
                )
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
            Call::Migrate {
                space,
                to,
                from_window,
            } => self.migrate(origin, space, to, from_window, events),
            Call::Resume { space } => self.resume(origin, space, events),
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

    fn migrate(
        &mut self,
        origin: Origin,
        space: Space,
        to: [u8; 32],
        from_window: u64,
        events: &mut Vec<Event>,
    ) -> Dispatched {
        let mut info = self.controlled(origin, &space)?;
        if to == self.constants.venue.0 {
            return Err(Error::SameVenue.into());
        }
        if info.end_window.is_some() {
            return Err(Error::AlreadyMigrated.into());
        }
        let now_w = Self::clock(&info)
            .window(self.now_ms)
            .ok_or(Error::BadClock)?;
        if from_window < now_w.saturating_add(1) {
            return Err(Error::OutOfRange.into());
        }
        info.end_window = Some(from_window);
        self.put(keys::spaces(&space), &info);
        events.push(Event::Migrated {
            space,
            to,
            from_window,
        });
        Ok(())
    }

    fn resume(&mut self, origin: Origin, space: Space, events: &mut Vec<Event>) -> Dispatched {
        let mut info = self.controlled(origin, &space)?;
        if info.status != SpaceStatus::Suspended {
            return Err(Error::SpaceNotActive.into());
        }
        let evidence = self.keys_under(&keys::equivocations_of(&space));
        let listed = |chain: &Self, key: &[u8; 32]| {
            chain.storage.contains_key(&keys::anchor_keys(&space, key))
        };
        for key in &evidence {
            let held: Evidence = self.get(key).expect("listed");
            if listed(self, &held.first_signer) || listed(self, &held.second_signer) {
                return Err(Error::StillEquivocating.into());
            }
        }
        for key in evidence {
            self.storage.remove(&key);
        }
        info.status = SpaceStatus::Active;
        self.put(keys::spaces(&space), &info);
        events.push(Event::SpaceResumed { space });
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
        info.status = if blocked {
            SpaceStatus::Blocked
        } else if self.keys_under(&keys::equivocations_of(&space)).is_empty() {
            SpaceStatus::Active
        } else {
            SpaceStatus::Suspended
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

    /// `spaces-pallet.md` §6.2.
    fn register(
        &mut self,
        genesis: &[u8],
        controller: AccountId,
        start_window: u64,
        founder_key: &[u8; 32],
        founder_sig: &[u8; 64],
        events: &mut Vec<Event>,
    ) -> Dispatched {
        self.paused(PAUSE_REGISTER)?;
        let genesis = SpaceGenesis::decode(genesis).map_err(|_| Error::BadGenesis)?;
        let founders = genesis.nodes.len();
        if founders > vos_anchor::MAX_FOUNDING_KEYS
            || founders > self.constants.max_anchor_keys.into()
        {
            return Err(Error::BadGenesis.into());
        }
        let clock = genesis.clock;
        if !(self.constants.min_window_ms..=self.constants.max_window_ms).contains(&clock.length_ms)
        {
            return Err(Error::BadClock.into());
        }
        let space = vos_anchor::space_id(&genesis).0;
        if self.storage.contains_key(&keys::spaces(&space)) {
            return Err(Error::SpaceExists.into());
        }
        let digest = vos_anchor::register_digest(
            &self.constants.venue,
            &vos_anchor::SpaceId(space),
            &controller,
            start_window,
        );
        let founding = genesis.nodes.iter().any(|(_, key)| key == founder_key);
        if !founding || !verifies(founder_key, &digest, founder_sig) {
            return Err(Error::BadFounder.into());
        }
        let now_w = clock.window(self.now_ms).ok_or(Error::BadClock)?;
        let earliest = now_w.saturating_sub(self.constants.max_root_age_ms / clock.length_ms);
        if start_window < earliest || start_window > now_w.saturating_add(1) {
            return Err(Error::BadStartWindow.into());
        }
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
        let info = SpaceInfo {
            sovereign,
            controller,
            origin_ms: clock.origin_ms,
            length_ms: clock.length_ms,
            start_window,
            end_window: None,
            status: SpaceStatus::Active,
            authorities: 0,
            anchor_keys: founders as u8,
            registered_ms: self.now_ms,
            max_spend_per_window: self.constants.default_spend_per_window,
        };
        self.put(keys::spaces(&space), &info);
        self.put(keys::sovereign_of(&sovereign), &space);
        for (_, key) in &genesis.nodes {
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
        let existing: Option<AuthorityInfo> = self.get(&keys::authorities(&space, &who));
        if existing.is_none() && info.authorities >= self.constants.max_authorities {
            return Err(Error::TooManyAuthorities.into());
        }
        let old = existing.and_then(|existing| existing.anchor_key);
        let mut count = info.anchor_keys;
        if let Some(old) = old.filter(|old| Some(*old) != anchor_key) {
            self.storage.remove(&keys::anchor_keys(&space, &old));
            count -= 1;
        }
        if let Some(key) = anchor_key {
            match self.get::<Option<AccountId>>(&keys::anchor_keys(&space, &key)) {
                Some(Some(paired)) if paired != who => return Err(Error::AnchorKeyInUse.into()),
                Some(_) => {}
                None => {
                    if count >= self.constants.max_anchor_keys {
                        return Err(Error::TooManyAnchorKeys.into());
                    }
                    count += 1;
                }
            }
            self.put(keys::anchor_keys(&space, &key), &Some(who));
        }
        info.anchor_keys = count;
        if existing.is_none() {
            info.authorities += 1;
            self.account_mut(&who).providers += 1;
        }
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

    /// `spaces-pallet.md` §6.1, the anchor rule. A second root at a window
    /// held is the equivocation's evidence: the space suspended, and the
    /// window's anchor dropped, so neither root counts again, after a
    /// resume as before it.
    fn anchor(&mut self, anchor: &AnchorArg, events: &mut Vec<Event>) -> Dispatched {
        self.paused(PAUSE_ANCHOR)?;
        let space = anchor.space;
        let mut info = self.space(&space).ok_or(Error::UnknownSpace)?;
        if info.status != SpaceStatus::Active {
            return Err(Error::SpaceNotActive.into());
        }
        let kind = RootKind::from_u8(anchor.kind).ok_or(Error::BadKind)?;
        if !self
            .storage
            .contains_key(&keys::anchor_keys(&space, &anchor.signer))
        {
            return Err(Error::UnknownAnchorKey.into());
        }
        let digest = vos_anchor::anchor_digest(
            &self.constants.venue,
            &vos_anchor::SpaceId(space),
            anchor.window,
            kind,
            &anchor.root,
        );
        if !verifies(&anchor.signer, &digest, &anchor.signature) {
            return Err(Error::BadAnchorSignature.into());
        }
        let at = keys::anchors(&space, anchor.kind, anchor.window);
        if let Some(held) = self.get::<AnchorRecord>(&at) {
            if held.root == anchor.root {
                return Err(Error::AlreadyAnchored.into());
            }
            let evidence = Evidence {
                first: held.root,
                second: anchor.root,
                first_signer: held.signer,
                second_signer: anchor.signer,
            };
            self.put(
                keys::equivocations(&space, anchor.kind, anchor.window),
                &evidence,
            );
            if !self.keeps_disputed_root() {
                self.storage.remove(&at);
            }
            info.status = SpaceStatus::Suspended;
            self.put(keys::spaces(&space), &info);
            events.push(Event::Equivocated {
                space,
                kind: anchor.kind,
                window: anchor.window,
                first: evidence.first,
                second: evidence.second,
                first_signer: evidence.first_signer,
                second_signer: evidence.second_signer,
            });
            events.push(Event::SpaceSuspended { space });
            return Ok(());
        }
        let w = anchor.window;
        if w < info.start_window || info.end_window.is_some_and(|end| w >= end) {
            return Err(Error::OutOfRange.into());
        }
        let last: Option<u64> = self.get(&keys::last(&space, anchor.kind));
        if last.is_some_and(|last| w <= last) {
            return Err(Error::WindowNotAfterLast.into());
        }
        let clock = Self::clock(&info);
        let now_w = clock.window(self.now_ms).ok_or(Error::BadClock)?;
        if w >= now_w {
            return Err(Error::WindowInFuture.into());
        }
        let fresh = clock.boundary(w).is_some_and(|boundary| {
            self.now_ms.saturating_sub(boundary) <= self.constants.max_root_age_ms
        });
        if !fresh {
            return Err(Error::WindowTooOld.into());
        }
        let record = AnchorRecord {
            root: anchor.root,
            at_ms: self.now_ms,
            signer: anchor.signer,
        };
        self.put(at, &record);
        self.put(keys::last(&space, anchor.kind), &w);
        events.push(Event::Anchored {
            space,
            kind: anchor.kind,
            window: w,
            root: anchor.root,
        });
        Ok(())
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
        let program = self
            .get::<ProgramInfo>(&keys::programs(&statement.program.0))
            .filter(|info| self.active(&info.active))
            .ok_or(Refusal::Program.code())?;
        let pin = Pin {
            program: ProgramId(statement.program.0),
            venue_bound: program.venue_bound,
        };
        let id = vos_statement::judge(&StorageVenue { chain: self }, &pin, &statement, proof)
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
                let rest_same = stored.is_some_and(|stored| {
                    stored.handler == info.handler && stored.venue_bound == info.venue_bound
                });
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

    /// `spaces-pallet.md` §6.5, with weight enough for every entry: anchors
    /// past `MaxRootAge` and `Seen` entries past their expiry pruned; `Last`,
    /// `Equivocations` and a rootless statement's entry kept.
    pub fn on_idle(&mut self) {
        let now = self.now_ms;
        for key in self.keys_under(&keys::Item::Anchors.prefix()) {
            let Some((space, window)) = keys::anchors_parts(&key) else {
                continue;
            };
            let expired = self
                .space(&space)
                .and_then(|info| Self::clock(&info).boundary(window))
                .and_then(|boundary| boundary.checked_add(self.constants.max_root_age_ms))
                .is_some_and(|last| last < now);
            if expired {
                self.storage.remove(&key);
            }
        }
        for key in self.keys_under(&keys::Item::Seen.prefix()) {
            let expiry: u64 = self.get(&key).expect("a Seen entry");
            if expiry != u64::MAX && expiry < now {
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

/// Whether `signature` is `key`'s over `digest`, strictly.
fn verifies(key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(digest, &Signature::from_bytes(signature))
            .is_ok()
    })
}
