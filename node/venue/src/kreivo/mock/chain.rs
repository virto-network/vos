//! The chain: its constants, accounts and storage, and a call's way from
//! its bytes, through its fee, to the pallet's dispatch.

use std::collections::BTreeMap;

use parity_scale_codec::{Decode, DecodeAll, Encode};
use vos_anchor::{VenueId, WindowClock};

use super::keys;
use super::types::{
    AccountId, Active, Balance, BalancesCall, Bounds, Call, DispatchError, Event, MultiAddress,
    RuntimeCall, Space, SpaceInfo, SpaceStatus, Spend, TokenError,
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
    pub program_change_delay_ms: u64,
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
            program_change_delay_ms: 604_800_000,
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
    pub(super) now_ms: u64,
    pub(super) storage: BTreeMap<Vec<u8>, Vec<u8>>,
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
    /// An equivocation's evidence stored and the space ended, but its
    /// registration deposit kept held.
    DepositKept,
}

pub(super) type Dispatched = Result<(), DispatchError>;

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

    /// Whether an ended space keeps its registration deposit held: never,
    /// but in a pallet broken so.
    pub(super) fn keeps_deposit(&self) -> bool {
        #[cfg(test)]
        if self.is_broken(Broken::DepositKept) {
            return true;
        }
        false
    }

    /// Whether `active` holds now.
    pub(super) fn active(&self, active: &Active) -> bool {
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

    pub(super) fn get<T: Decode>(&self, key: &[u8]) -> Option<T> {
        let value = self.storage.get(key)?;
        Some(T::decode_all(&mut &value[..]).expect("the mock stores what it decodes"))
    }

    pub(super) fn put<T: Encode>(&mut self, key: Vec<u8>, value: &T) {
        self.storage.insert(key, value.encode());
    }

    pub(super) fn keys_under(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.storage
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.clone())
            .collect()
    }

    pub fn space(&self, space: &Space) -> Option<SpaceInfo> {
        self.get(&keys::spaces(space))
    }

    pub(super) fn clock(info: &SpaceInfo) -> WindowClock {
        WindowClock {
            origin_ms: info.origin_ms,
            length_ms: info.length_ms,
        }
    }

    pub(super) fn account_mut(&mut self, who: &AccountId) -> &mut Account {
        self.accounts.entry(*who).or_default()
    }

    /// Whether `who` can hold `amount` and keep the existential deposit
    /// free.
    pub(super) fn can_hold(&self, who: &AccountId, amount: Balance) -> bool {
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
    pub(super) fn transactional(&mut self, f: impl FnOnce(&mut Self) -> Dispatched) -> Dispatched {
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

    pub(super) fn dispatch(
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
}
