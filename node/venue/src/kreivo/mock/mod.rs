//! A plain-Rust model of Kreivo's spaces pallet (`spaces-pallet.md` §4–§8),
//! not a FRAME pallet: the reference the conformance vectors are generated
//! from, and the chain the Kreivo client is tested against.
//!
//! - **Storage** is raw, a map from the pinned keys ([`keys`]) to SCALE
//!   values ([`types`]), so what a call writes is FRAME's bytes.
//! - **Calls** arrive as bytes, `[90, call_index] ++ SCALE(args)` (or
//!   another pallet's call for `dispatch_as_sovereign`), decoded whole; a
//!   call that does not decode, or a bounded vector past its bound, is
//!   [`Verdict::Undecodable`].
//! - **A call is transactional**, as FRAME dispatches it: an error leaves
//!   no write and no event; only its fee stays paid.
//! - **Balances:** each account's free balance, its holds (registration,
//!   submit) and its provider and consumer counts. A hold keeps the
//!   existential deposit free.
//! - **Fees** ([`Chain::with_fees`]): off, the pallet's own mock runtime,
//!   with no fee pipeline; on, Kreivo's runtime with `ChargeSpaceFee`
//!   (§7): an authority's `anchor` or `submit` of an active space paid by
//!   its sovereign account within the window's budget, every other signed
//!   call by its signer. The model charges every fee at `FeeBound`, the
//!   most one can be: the vectors pin fees by sign only.
//! - **Time** is a settable `now_ms` (Kreivo's `Timestamp.Now`); verdicts
//!   are `vos_statement::judge`'s, over [`StorageVenue`].

pub mod keys;
pub mod transport;
pub mod types;

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use parity_scale_codec::{Decode, DecodeAll, Encode};
use vos_anchor::{RootKind, RootRead, SpaceGenesis, VenueId, WindowClock};
use vos_statement::{Pin, ProgramId, Refusal, Statement, StatementId, Venue};

use types::{
    AccountId, Active, AnchorArg, AnchorRecord, AuthorityInfo, Balance, BalancesCall, Bounds, Call,
    DispatchError, Error, Event, Evidence, MultiAddress, ProgramInfo, RuntimeCall, Space,
    SpaceInfo, SpaceStatus, Spend, TokenError,
};

/// The pallet's constants (§4) and the runtime's the mock needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constants {
    /// Kreivo's genesis hash, every anchor's and registration's venue.
    pub venue: VenueId,
    /// `PalletId`, the sovereign accounts' derivation.
    pub pallet_id: [u8; 8],
    pub existential_deposit: Balance,
    pub registration_deposit: Balance,
    pub submit_deposit: Balance,
    pub fee_bound: Balance,
    pub default_spend_per_window: Balance,
    /// `ForfeitTo`: Kreivo's treasury.
    pub forfeit_to: AccountId,
    pub max_root_age_ms: u64,
    pub program_change_delay_ms: u64,
    pub min_window_ms: u64,
    pub max_window_ms: u64,
    pub max_authorities: u8,
    pub max_anchor_keys: u8,
    pub bounds: Bounds,
}

impl Constants {
    /// The design's suggested values (§4, `UNITS = 10^12`), at `venue`.
    pub fn kreivo(venue: VenueId) -> Self {
        const UNITS: Balance = 1_000_000_000_000;
        let deposit = UNITS / 2;
        let fee_bound = UNITS;
        Self {
            venue,
            pallet_id: *b"kv/space",
            existential_deposit: UNITS / 1_000,
            registration_deposit: deposit,
            submit_deposit: deposit,
            fee_bound,
            default_spend_per_window: 8 * (deposit + fee_bound),
            forfeit_to: account_of(b"py/trsry", &[]),
            max_root_age_ms: vos_anchor::MAX_ROOT_AGE_MS,
            program_change_delay_ms: 604_800_000,
            min_window_ms: vos_anchor::MIN_LENGTH_MS,
            max_window_ms: vos_anchor::MAX_LENGTH_MS,
            max_authorities: 16,
            max_anchor_keys: 16,
            bounds: Bounds {
                genesis: 2_048,
                statement: 65_536,
                proof: 262_144,
            },
        }
    }

    /// A space's sovereign account: `b"modl" ‖ PalletId ‖ space`, cut to
    /// 32 bytes (`into_sub_account_truncating`).
    pub fn sovereign(&self, space: &Space) -> AccountId {
        account_of(&self.pallet_id, space)
    }
}

/// `PalletId(id).into_sub_account_truncating(sub)`.
fn account_of(id: &[u8; 8], sub: &[u8]) -> AccountId {
    let mut account = [0; 32];
    let bytes = [b"modl", &id[..], sub].concat();
    let n = bytes.len().min(32);
    account[..n].copy_from_slice(&bytes[..n]);
    account
}

/// An account's balances and reference counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub free: Balance,
    /// Held for `HoldReason::Registration`.
    pub held_registration: Balance,
    /// Held for `HoldReason::Submit`.
    pub held_submit: Balance,
    pub providers: u32,
    pub consumers: u32,
}

/// Who dispatches a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Signed(AccountId),
    Root,
    /// `ProgramsOrigin`, the Virto community.
    Programs,
    /// `EmergencyOrigin`.
    Emergency,
    /// `StatusOrigin`, Kreivo's governance.
    Status,
}

/// A call's outcome, as the chain reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Dispatched and Ok.
    Ok,
    /// Dispatched, and refused: its writes and events dropped.
    Err(DispatchError),
    /// Refused in `validate` (`InvalidTransaction::Payment`): never
    /// included, nothing paid.
    Payment,
    /// The call's bytes do not decode: never included.
    Undecodable,
}

/// Who paid a call's fee, in the fees model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payer {
    /// The space's sovereign account, for its authority.
    Sovereign,
    /// The signer.
    Signer,
}

/// A call's verdict, its pallet events, and who paid its fee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub verdict: Verdict,
    pub events: Vec<Event>,
    pub payer: Option<Payer>,
}

/// A fee charged before dispatch.
struct Charge {
    /// The space whose sovereign paid it, and the deposit its budget took.
    sovereign: Option<(Space, Balance)>,
}

/// The chain: the pallet's storage, the accounts, the time.
#[derive(Clone, Debug)]
pub struct Chain {
    pub constants: Constants,
    now_ms: u64,
    storage: BTreeMap<Vec<u8>, Vec<u8>>,
    accounts: BTreeMap<AccountId, Account>,
    fees: bool,
    /// A broken pallet, for the vectors' own tests.
    #[cfg(test)]
    broken: Option<Broken>,
}

/// How a pallet the vectors must fail is broken.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Broken {
    /// Every stored format and program taken as active, whatever its
    /// window.
    Activation,
    /// An accepted submit's released deposit not credited back to its
    /// window's budget.
    CreditBack,
}

type Dispatched = Result<(), DispatchError>;

impl Chain {
    /// An empty chain at time 0, with no fee pipeline.
    pub fn new(constants: Constants) -> Self {
        Self {
            constants,
            now_ms: 0,
            storage: BTreeMap::new(),
            accounts: BTreeMap::new(),
            fees: false,
            #[cfg(test)]
            broken: None,
        }
    }

    /// The chain as a pallet broken by `broken` would be: one the vectors
    /// must fail.
    #[cfg(test)]
    pub(crate) fn broken(mut self, broken: Broken) -> Self {
        self.broken = Some(broken);
        self
    }

    #[cfg(test)]
    fn is_broken(&self, broken: Broken) -> bool {
        self.broken == Some(broken)
    }

    /// Whether `active` holds now.
    fn active(&self, active: &Active) -> bool {
        #[cfg(test)]
        if self.is_broken(Broken::Activation) {
            return true;
        }
        active.at(self.now_ms)
    }

    /// The chain with Kreivo's fee pipeline, `ChargeSpaceFee`, or without.
    pub fn with_fees(mut self, fees: bool) -> Self {
        self.fees = fees;
        self
    }

    pub fn fees(&self) -> bool {
        self.fees
    }

    pub fn now(&self) -> u64 {
        self.now_ms
    }

    /// `Timestamp.Now`.
    pub fn set_now(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// The pallet's storage, raw.
    pub fn storage(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.storage
    }

    /// A raw entry set, as a test's genesis sets one.
    pub fn set_storage(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.storage.insert(key, value);
    }

    /// A raw entry removed, as a test's setup removes one.
    pub fn remove_storage(&mut self, key: &[u8]) {
        self.storage.remove(key);
    }

    pub fn accounts(&self) -> &BTreeMap<AccountId, Account> {
        &self.accounts
    }

    pub fn account(&self, who: &AccountId) -> Account {
        self.accounts.get(who).copied().unwrap_or_default()
    }

    pub fn set_account(&mut self, who: AccountId, account: Account) {
        self.accounts.insert(who, account);
    }

    fn get<T: Decode>(&self, key: &[u8]) -> Option<T> {
        let value = self.storage.get(key)?;
        Some(T::decode_all(&mut &value[..]).expect("the mock stores what it decodes"))
    }

    fn put<T: Encode>(&mut self, key: Vec<u8>, value: &T) {
        self.storage.insert(key, value.encode());
    }

    fn keys_under(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.storage
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.clone())
            .collect()
    }

    pub fn space(&self, space: &Space) -> Option<SpaceInfo> {
        self.get(&keys::spaces(space))
    }

    fn clock(info: &SpaceInfo) -> WindowClock {
        WindowClock {
            origin_ms: info.origin_ms,
            length_ms: info.length_ms,
        }
    }

    fn account_mut(&mut self, who: &AccountId) -> &mut Account {
        self.accounts.entry(*who).or_default()
    }

    /// Whether `who` can hold `amount` and keep the existential deposit
    /// free.
    fn can_hold(&self, who: &AccountId, amount: Balance) -> bool {
        self.account(who)
            .free
            .checked_sub(amount)
            .is_some_and(|left| left >= self.constants.existential_deposit)
    }

    /// The call `bytes` encode, submitted by `origin`.
    pub fn submit(&mut self, origin: Origin, bytes: &[u8]) -> Outcome {
        let refused = |verdict| Outcome {
            verdict,
            events: Vec::new(),
            payer: None,
        };
        let call = match RuntimeCall::decode_all(&mut &bytes[..]) {
            Ok(call) if call.within(&self.constants.bounds) => call,
            _ => return refused(Verdict::Undecodable),
        };
        let charge = match (self.fees, origin) {
            (true, Origin::Signed(who)) => match self.charge(&who, &call) {
                Some(charge) => Some(charge),
                None => return refused(Verdict::Payment),
            },
            _ => None,
        };
        let mut events = Vec::new();
        let result = self.transactional(|chain| chain.dispatch(origin, call, &mut events));
        if result.is_err() {
            events.clear();
        }
        if let Some(Charge {
            sovereign: Some((space, deposit)),
        }) = &charge
        {
            let forfeited = events
                .iter()
                .any(|event| matches!(event, Event::DepositForfeited { .. }));
            if !forfeited && *deposit > 0 {
                self.credit_budget(space, *deposit);
            }
        }
        Outcome {
            verdict: match result {
                Ok(()) => Verdict::Ok,
                Err(error) => Verdict::Err(error),
            },
            events,
            payer: charge.map(|charge| match charge.sovereign {
                Some(_) => Payer::Sovereign,
                None => Payer::Signer,
            }),
        }
    }

    /// `f`, its writes and balance changes dropped on an error.
    fn transactional(&mut self, f: impl FnOnce(&mut Self) -> Dispatched) -> Dispatched {
        let storage = self.storage.clone();
        let accounts = self.accounts.clone();
        let result = f(self);
        if result.is_err() {
            self.storage = storage;
            self.accounts = accounts;
        }
        result
    }

    /// `ChargeSpaceFee`'s `validate` and `prepare` (§7): none when the
    /// transaction is refused as `InvalidTransaction::Payment`.
    fn charge(&mut self, who: &AccountId, call: &RuntimeCall) -> Option<Charge> {
        let fee = self.constants.fee_bound;
        let paid_for = match call {
            RuntimeCall::Spaces(Call::Anchor { anchor }) => Some((anchor.space, 0)),
            RuntimeCall::Spaces(Call::Submit { payer, .. }) => {
                Some((*payer, self.constants.submit_deposit))
            }
            _ => None,
        };
        let sovereign = paid_for.and_then(|(space, deposit)| {
            let info = self.space(&space)?;
            let authority = self.storage.contains_key(&keys::authorities(&space, who));
            (info.status == SpaceStatus::Active && authority).then_some((space, info, deposit))
        });
        let Some((space, info, deposit)) = sovereign else {
            if !self.can_hold(who, fee) {
                return None;
            }
            self.account_mut(who).free -= fee;
            return Some(Charge { sovereign: None });
        };
        let window = Self::clock(&info).window(self.now_ms).unwrap_or(0);
        let spend = self
            .get::<Spend>(&keys::budget(&space))
            .filter(|spend| spend.window == window)
            .unwrap_or(Spend { window, spent: 0 });
        let spent = spend.spent.checked_add(fee + deposit)?;
        if spent > info.max_spend_per_window || !self.can_hold(&info.sovereign, fee + deposit) {
            return None;
        }
        self.account_mut(&info.sovereign).free -= fee;
        self.put(keys::budget(&space), &Spend { window, spent });
        Some(Charge {
            sovereign: Some((space, deposit)),
        })
    }

    /// `post_dispatch`: a deposit the dispatch did not forfeit credited
    /// back to the window's budget.
    fn credit_budget(&mut self, space: &Space, deposit: Balance) {
        #[cfg(test)]
        if self.is_broken(Broken::CreditBack) {
            return;
        }
        if let Some(mut spend) = self.get::<Spend>(&keys::budget(space)) {
            spend.spent = spend.spent.saturating_sub(deposit);
            self.put(keys::budget(space), &spend);
        }
    }

    fn dispatch(
        &mut self,
        origin: Origin,
        call: RuntimeCall,
        events: &mut Vec<Event>,
    ) -> Dispatched {
        match call {
            RuntimeCall::Balances(BalancesCall::TransferKeepAlive {
                dest: MultiAddress::Id(dest),
                value,
            }) => {
                let Origin::Signed(from) = origin else {
                    return Err(DispatchError::BadOrigin);
                };
                self.transfer_keep_alive(&from, &dest, value)
            }
            RuntimeCall::Spaces(call) => self.spaces(origin, call, events),
        }
    }

    fn transfer_keep_alive(
        &mut self,
        from: &AccountId,
        to: &AccountId,
        value: Balance,
    ) -> Dispatched {
        if !self.can_hold(from, value) {
            return Err(DispatchError::Token(TokenError::FundsUnavailable));
        }
        self.account_mut(from).free -= value;
        let ed = self.constants.existential_deposit;
        let to = self.account_mut(to);
        let created = to.free < ed && to.free + value >= ed;
        to.free += value;
        if created {
            to.providers += 1;
        }
        Ok(())
    }

    fn spaces(&mut self, origin: Origin, call: Call, events: &mut Vec<Event>) -> Dispatched {
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
            Call::Migrate {
                space,
                to,
                from_window,
            } => {
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
            Call::Resume { space } => {
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
                let info = self.controlled(origin, &space)?;
                let mut inner = Vec::new();
                let result = self.transactional(|chain| {
                    chain.dispatch(Origin::Signed(info.sovereign), *call, &mut inner)
                });
                if result.is_ok() {
                    events.append(&mut inner);
                }
                events.push(Event::SovereignDispatched { space, result });
                Ok(())
            }
            Call::SetBudget {
                space,
                max_spend_per_window,
            } => {
                let mut info = self.controlled(origin, &space)?;
                info.max_spend_per_window = max_spend_per_window;
                self.put(keys::spaces(&space), &info);
                events.push(Event::BudgetSet {
                    space,
                    max_spend_per_window,
                });
                Ok(())
            }
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
            Call::SetStatus { space, blocked } => {
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
        }
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

    /// `spaces-pallet.md` §6.1, the anchor rule.
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

/// `Paused`'s flags.
pub const PAUSE_SUBMIT: u8 = 1;
pub const PAUSE_ANCHOR: u8 = 2;
pub const PAUSE_REGISTER: u8 = 4;

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

/// The `Venue` the pallet implements over its storage (§3).
pub struct StorageVenue<'a> {
    chain: &'a Chain,
}

impl Venue for StorageVenue<'_> {
    fn id(&self) -> VenueId {
        self.chain.constants.venue
    }

    fn accepts(&self, format: u32) -> bool {
        self.chain
            .get::<Active>(&keys::formats(format))
            .is_some_and(|active| self.chain.active(&active))
    }

    /// The root held at its space, kind and window; the space active (a
    /// suspended or blocked space's roots are not anchored), the window in
    /// its range and the root no older than `MaxRootAge`.
    fn anchored(&self, root: &RootRead) -> bool {
        let chain = self.chain;
        let Some(info) = chain.space(&root.space.0) else {
            return false;
        };
        let w = root.window;
        let in_range = info.start_window <= w && info.end_window.is_none_or(|end| w < end);
        let fresh = Chain::clock(&info).boundary(w).is_some_and(|boundary| {
            chain.now_ms.saturating_sub(boundary) <= chain.constants.max_root_age_ms
        });
        let held = chain
            .get::<AnchorRecord>(&keys::anchors(&root.space.0, root.kind as u8, w))
            .is_some_and(|held| held.root == root.root);
        info.status == SpaceStatus::Active && in_range && fresh && held
    }

    fn seen(&self, id: &StatementId) -> bool {
        self.chain.storage.contains_key(&keys::seen(&id.0))
    }
}
