//! `Payments`, the space's ledger paid from by owner proofs
//! (`light-node.md` §5.2): cipher-clerk's kernel in an actor, one account
//! per owner digest, so per device. Each
//! account has a name, its handle for a payee, kept in its row's
//! `user_data`; `transfer` runs under `#[msg(credential = Owner)]` and
//! pays from the account of the digest the caller proved, unless it is
//! frozen. Accounts come by an operator's invitation naming the name and
//! the digest, opened by any caller before it expires; the operator mints
//! from the space's issuance, moves an account to a new owner (lifting a
//! freeze) and freezes one. Pseudonymous and custodial by design: payers,
//! payees and amounts in clear to the operators, an account's owner digest
//! and balance readable by the agent's callers, and `rekey` an operator's
//! (`identity-and-authority.md` §7).

#![no_std]

extern crate alloc;

use cipher_clerk::codec;
use cipher_clerk::conventions::{AccountKind, BankCode, Holder};
use cipher_clerk::ids::ExternalId;
use cipher_clerk::kernel::TransferBuilder;
use cipher_clerk::{
    Account, AccountFlags, AccountId, Authority, Authorized, EventStatus, Journal, JournalId,
    Layer, LedgerState, PendingStatus, Transfer, TransferId, Value,
};
use vos_sdk::prelude::*;

/// An account's name: 1 to [`MAX_NAME`] ASCII letters, digits, `.`, `_` or
/// `-`, shown verbatim.
pub type Name = Vec<u8>;

/// An owner digest: eight M31 words, as little-endian `u32`s.
pub type Owner = [u8; 32];

/// The longest a name may be: its row's `user_data`.
pub const MAX_NAME: usize = 32;

/// The space's one journal and currency.
const JOURNAL: JournalId = JournalId([1; 16]);
const CURRENCY: u32 = 1;

/// The journal's registrar and the issuance's owner: words at or above
/// `p`, so no owner proof states either.
const REGISTRAR: Owner = [0xff; 32];
const ISSUER: Owner = [0xfe; 32];

/// The issuance, debit-normal: what the space minted.
const ISSUANCE: AccountId = AccountId([0xff; 16]);

/// An account as its owner and the operators read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Holding {
    pub owner: Owner,
    pub balance: u64,
    pub frozen: bool,
}

/// The account an owner digest holds, and whether its debits are refused
/// until a rekey.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Held {
    pub account: [u8; 16],
    pub frozen: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Invitation {
    pub owner: Owner,
    pub expires_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum PaymentError {
    /// A name empty, past [`MAX_NAME`] bytes, or of another character.
    #[codec(index = 0)]
    BadName,
    /// An account of that name, or of that owner, exists.
    #[codec(index = 1)]
    Exists,
    /// No account of that name.
    #[codec(index = 2)]
    NoAccount,
    /// No invitation of that name names that owner.
    #[codec(index = 3)]
    NotInvited,
    /// The invitation expired before the account was opened.
    #[codec(index = 4)]
    Expired,
    /// The digest the caller proved holds no account.
    #[codec(index = 5)]
    NotOwner,
    /// The payer's account is frozen: no debit until a rekey.
    #[codec(index = 6)]
    Frozen,
    /// The payer's account holds less than the amount.
    #[codec(index = 7)]
    Insufficient,
    /// An account's total credits or debits would pass `u64::MAX`: the
    /// issuance's debits cap all that is ever minted.
    #[codec(index = 8)]
    Overflow,
    /// The kernel refused the transfer for another reason: its
    /// `EventStatus` number.
    #[codec(index = 9)]
    Refused(u32),
    /// An owner that is not a digest: a word at or above `p`.
    #[codec(index = 10)]
    BadOwner,
    /// A payment to the payer's own account.
    #[codec(index = 11)]
    SamePayee,
    /// A transfer or a mint of nothing.
    #[codec(index = 12)]
    NoAmount,
}

#[actor]
pub struct Payments {
    /// cipher-clerk's rows, in its encoding, by their ids.
    accounts: Table<[u8; 16], Vec<u8>>,
    transfers: Table<[u8; 16], Vec<u8>>,
    names: Table<Name, [u8; 16]>,
    owners: Table<Owner, Held>,
    invites: Table<Name, Invitation>,
    /// The accounts and transfers made, each id the count before it.
    opened: u64,
    paid: u64,
}

fn named(name: &[u8]) -> Result<(), PaymentError> {
    let fits = (1..=MAX_NAME).contains(&name.len())
        && name
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
    fits.then_some(()).ok_or(PaymentError::BadName)
}

/// A counter's id: its little-endian bytes, never zero, never the
/// issuance's.
fn id(count: u64) -> [u8; 16] {
    let mut id = [0; 16];
    id[..8].copy_from_slice(&(count + 1).to_le_bytes());
    id
}

/// Whether `owner` is a digest, each word below `p = 2^31 - 1`.
fn canonical(owner: &Owner) -> bool {
    owner
        .chunks_exact(4)
        .all(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]) < 0x7fff_ffff)
}

fn refused(status: EventStatus) -> PaymentError {
    match status {
        EventStatus::BalanceMustNotBeNegative => PaymentError::Insufficient,
        EventStatus::OverflowsBalance => PaymentError::Overflow,
        other => PaymentError::Refused(other.code()),
    }
}

/// The kernel's view of the tables. Payments submits no transfer with an
/// external id, a void or a reservation, so those sets stay empty.
impl LedgerState for Payments {
    type Value = Value;

    fn get_account(&self, id: &AccountId) -> Option<Account<Value>> {
        let bytes = self.accounts.get(&id.0)?;
        Some(codec::from_bytes(&bytes).expect("an account as the kernel wrote it"))
    }

    fn put_account(&mut self, account: Account<Value>) {
        self.accounts
            .insert(&account.id.0, &codec::to_bytes(&account));
    }

    fn get_transfer(&self, id: &TransferId) -> Option<Transfer<Value>> {
        let bytes = self.transfers.get(&id.0)?;
        Some(codec::from_bytes(&bytes).expect("a transfer as the kernel wrote it"))
    }

    fn put_transfer(&mut self, transfer: Transfer<Value>) {
        self.transfers
            .insert(&transfer.id.0, &codec::to_bytes(&transfer));
    }

    fn get_journal(&self, id: &JournalId) -> Option<Journal> {
        (*id == JOURNAL).then(|| Journal::new(JOURNAL, REGISTRAR, 0))
    }

    fn external_id_seen(&self, _id: &ExternalId) -> bool {
        false
    }

    fn mark_external_id(&mut self, _id: &ExternalId) {
        unreachable!("no transfer names an external id")
    }

    fn transfer_voided(&self, _id: &TransferId) -> bool {
        false
    }

    fn mark_transfer_voided(&mut self, _id: &TransferId) {
        unreachable!("no transfer voids another")
    }

    fn pending_status(&self, _id: &TransferId) -> Option<PendingStatus> {
        None
    }

    fn mark_pending_status(&mut self, _id: &TransferId, _status: PendingStatus) {
        unreachable!("no transfer reserves")
    }
}

impl Payments {
    /// Create `account` under the registrar's authority.
    fn create(&mut self, now: u64, account: Account<Value>) -> Result<(), PaymentError> {
        let event = Authorized::new(account, Authority::of([REGISTRAR]));
        let result = cipher_clerk::apply_account_creations(self, &[event], now);
        match result[0].status {
            EventStatus::Created => Ok(()),
            status => Err(refused(status)),
        }
    }

    /// Move `amount` from `from` to `to` under `authority`, in one transfer.
    fn post(
        &mut self,
        now: u64,
        authority: Authority,
        from: &Account<Value>,
        to: &Account<Value>,
        amount: u64,
    ) -> Result<(), PaymentError> {
        if amount == 0 {
            return Err(PaymentError::NoAmount);
        }
        let transfer = TransferBuilder::new(TransferId(id(self.paid)), JOURNAL)
            .debit(from, Layer::Settled, Value(amount))
            .credit(to, Layer::Settled, Value(amount))
            .build();
        let event = Authorized::new(transfer, authority);
        let result = cipher_clerk::apply_batch(self, &[event], now);
        match result[0].status {
            EventStatus::Created => {
                self.paid += 1;
                Ok(())
            }
            status => Err(refused(status)),
        }
    }

    fn named_account(&self, name: &[u8]) -> Option<(AccountId, Account<Value>)> {
        let id = AccountId(self.names.get(&name.to_vec())?);
        Some((id, self.get_account(&id).expect("a named account")))
    }

    /// The issuance, opened at the first mint.
    fn issuance(&mut self, now: u64) -> Result<Account<Value>, PaymentError> {
        if let Some(issuance) = self.get_account(&ISSUANCE) {
            return Ok(issuance);
        }
        let issuance = Account::open(
            ISSUANCE,
            AccountKind::Asset,
            JOURNAL,
            Holder::Operator(ISSUER),
            CURRENCY,
            BankCode::Vault,
        )
        .expect("the operator holds an asset");
        self.create(now, issuance)?;
        Ok(self.get_account(&ISSUANCE).expect("the issuance"))
    }
}

/// An account's settled balance: what the space owes its owner, never
/// below zero (`BALANCE_MUST_NOT_BE_NEGATIVE`).
fn balance(account: &Account<Value>) -> u64 {
    let settled = account.balance(Layer::Settled);
    settled
        .cr
        .0
        .checked_sub(settled.dr.0)
        .expect("a user account never below zero")
}

#[messages]
impl Payments {
    pub fn new() -> Self {
        Self {
            accounts: Table::default(),
            transfers: Table::default(),
            names: Table::default(),
            owners: Table::default(),
            invites: Table::default(),
            opened: 0,
            paid: 0,
        }
    }

    /// Invite an account `name` for `owner`, which may open it until
    /// `expires_ms` included; a later invitation of the name replaces it.
    #[msg(role = "operator")]
    pub async fn invite(
        &mut self,
        name: Name,
        owner: Owner,
        expires_ms: u64,
    ) -> Result<(), PaymentError> {
        named(&name)?;
        if !canonical(&owner) {
            return Err(PaymentError::BadOwner);
        }
        if self.names.get(&name).is_some() || self.owners.get(&owner).is_some() {
            return Err(PaymentError::Exists);
        }
        self.invites
            .insert(&name, &Invitation { owner, expires_ms });
        Ok(())
    }

    /// Open the account `name` an invitation names `owner` for, with
    /// nothing in it: any caller, before the invitation expires, while
    /// `owner` holds no other.
    #[msg]
    pub async fn open(
        &mut self,
        ctx: &mut Command<Self>,
        name: Name,
        owner: Owner,
    ) -> Result<(), PaymentError> {
        let invitation = self.invites.get(&name).ok_or(PaymentError::NotInvited)?;
        if invitation.owner != owner {
            return Err(PaymentError::NotInvited);
        }
        if ctx.now() > invitation.expires_ms {
            return Err(PaymentError::Expired);
        }
        if self.names.get(&name).is_some() || self.owners.get(&owner).is_some() {
            return Err(PaymentError::Exists);
        }
        let account = AccountId(id(self.opened));
        let mut label = [0; 32];
        label[..name.len()].copy_from_slice(&name);
        let row = Account::open(
            account,
            AccountKind::Liability,
            JOURNAL,
            Holder::User(owner),
            CURRENCY,
            BankCode::Checking,
        )
        .expect("a user holds a liability")
        .with_flags(AccountFlags::BALANCE_MUST_NOT_BE_NEGATIVE)
        .with_user_data(label);
        self.create(ctx.now(), row)?;
        self.opened += 1;
        self.invites.remove(&name);
        self.names.insert(&name, &account.0);
        self.owners.insert(
            &owner,
            &Held {
                account: account.0,
                frozen: false,
            },
        );
        Ok(())
    }

    /// Credit `name` with `amount` from the space's issuance.
    #[msg(role = "operator")]
    pub async fn mint(
        &mut self,
        ctx: &mut Command<Self>,
        name: Name,
        amount: u64,
    ) -> Result<u64, PaymentError> {
        let (id, account) = self.named_account(&name).ok_or(PaymentError::NoAccount)?;
        let issuance = self.issuance(ctx.now())?;
        self.post(
            ctx.now(),
            Authority::of([ISSUER]),
            &issuance,
            &account,
            amount,
        )?;
        Ok(balance(&self.get_account(&id).expect("the account")))
    }

    /// Pay `amount` to the account `to` from the account of the digest the
    /// caller proved, unless it is frozen.
    #[msg(credential = Owner)]
    pub async fn transfer(
        &mut self,
        ctx: &mut Command<Self>,
        to: Name,
        amount: u64,
    ) -> Result<(), PaymentError> {
        let owner = ctx.owner().ok_or(PaymentError::NotOwner)?;
        let held = self.owners.get(&owner).ok_or(PaymentError::NotOwner)?;
        if held.frozen {
            return Err(PaymentError::Frozen);
        }
        let (payee, to) = self.named_account(&to).ok_or(PaymentError::NoAccount)?;
        if payee.0 == held.account {
            return Err(PaymentError::SamePayee);
        }
        let payer = self
            .get_account(&AccountId(held.account))
            .expect("a held account");
        self.post(ctx.now(), Authority::of([owner]), &payer, &to, amount)
    }

    /// The account `name`, if there is one.
    #[msg]
    pub async fn account(&self, name: Name) -> Option<Holding> {
        let (_, account) = self.named_account(&name)?;
        let held = self.owners.get(&account.owner).expect("an owned account");
        Some(Holding {
            owner: account.owner,
            balance: balance(&account),
            frozen: held.frozen,
        })
    }

    /// The name and the account the owner digest `owner` holds, if it
    /// holds one: what a device reads of its own.
    #[msg]
    pub async fn held(&self, owner: Owner) -> Option<(Name, Holding)> {
        let held = self.owners.get(&owner)?;
        let account = self
            .get_account(&AccountId(held.account))
            .expect("a held account");
        let name = account
            .user_data
            .iter()
            .copied()
            .take_while(|byte| *byte != 0)
            .collect();
        Some((
            name,
            Holding {
                owner,
                balance: balance(&account),
                frozen: held.frozen,
            },
        ))
    }

    /// The balance of `name`, if there is such an account.
    #[msg]
    pub async fn balance(&self, name: Name) -> Option<u64> {
        self.named_account(&name)
            .map(|(_, account)| balance(&account))
    }

    /// Move `name` to the owner digest `owner`, its balance kept, and lift
    /// a freeze: a lost secret's recovery, once its member enrolled again.
    #[msg(role = "operator")]
    pub async fn rekey(&mut self, name: Name, owner: Owner) -> Result<(), PaymentError> {
        if !canonical(&owner) {
            return Err(PaymentError::BadOwner);
        }
        let (id, mut account) = self.named_account(&name).ok_or(PaymentError::NoAccount)?;
        if account.owner == owner {
            self.owners.insert(
                &owner,
                &Held {
                    account: id.0,
                    frozen: false,
                },
            );
            return Ok(());
        }
        if self.owners.get(&owner).is_some() {
            return Err(PaymentError::Exists);
        }
        self.owners.remove(&account.owner);
        self.owners.insert(
            &owner,
            &Held {
                account: id.0,
                frozen: false,
            },
        );
        account.owner = owner;
        self.put_account(account);
        Ok(())
    }

    /// Refuse `name`'s debits until a rekey.
    #[msg(role = "operator")]
    pub async fn freeze(&mut self, name: Name) -> Result<(), PaymentError> {
        let (_, account) = self.named_account(&name).ok_or(PaymentError::NoAccount)?;
        let mut held = self.owners.get(&account.owner).expect("an owned account");
        held.frozen = true;
        self.owners.insert(&account.owner, &held);
        Ok(())
    }
}
