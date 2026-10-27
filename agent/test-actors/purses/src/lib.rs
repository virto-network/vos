//! A ledger of named rows, each paid from by its owner's proof
//! (`slice-7-mobile.md` 7.11): a row is `(owner, balance, frozen)`, its
//! `owner` an owner digest, and `transfer` runs under
//! `#[msg(credential = Owner)]`, debiting a row only while its live owner
//! is the proof's digest and it is not frozen. Rows come by an operator's
//! invitation naming the digest, claimed by any caller before it expires;
//! the operator mints, rekeys a row to a new owner (lifting a freeze) and
//! freezes one. Custodial by design (`identity-and-authority.md` §7).

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

/// A row's name: 1 to [`MAX_NAME`] bytes of UTF-8, shown verbatim.
pub type Name = Vec<u8>;

/// An owner digest: eight M31 words, as little-endian `u32`s.
pub type Owner = [u8; 32];

/// The longest a row's name may be.
pub const MAX_NAME: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Row {
    pub owner: Owner,
    pub balance: u64,
    pub frozen: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Invitation {
    pub owner: Owner,
    pub expires_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum PurseError {
    /// A name empty, past [`MAX_NAME`] bytes, or not UTF-8.
    #[codec(index = 0)]
    BadName,
    /// A row of that name exists.
    #[codec(index = 1)]
    Exists,
    /// No row of that name.
    #[codec(index = 2)]
    NoRow,
    /// No invitation of that name names that owner.
    #[codec(index = 3)]
    NotInvited,
    /// The invitation expired before the claim.
    #[codec(index = 4)]
    Expired,
    /// The caller proved another owner than the row's.
    #[codec(index = 5)]
    NotOwner,
    /// The row is frozen: no debit until a rekey.
    #[codec(index = 6)]
    Frozen,
    /// The row holds less than the amount.
    #[codec(index = 7)]
    Insufficient,
    /// A balance would pass `u64::MAX`.
    #[codec(index = 8)]
    Overflow,
}

#[actor]
pub struct Purses {
    rows: Table<Name, Row>,
    invites: Table<Name, Invitation>,
}

fn named(name: &[u8]) -> Result<(), PurseError> {
    let fits = (1..=MAX_NAME).contains(&name.len()) && core::str::from_utf8(name).is_ok();
    fits.then_some(()).ok_or(PurseError::BadName)
}

#[messages]
impl Purses {
    pub fn new() -> Self {
        Self {
            rows: Table::default(),
            invites: Table::default(),
        }
    }

    /// Invite a row `name` for `owner`, claimable until `expires_ms`
    /// included; a later invitation of the name replaces it.
    #[msg(role = "operator")]
    pub async fn invite_row(
        &mut self,
        name: Name,
        owner: Owner,
        expires_ms: u64,
    ) -> Result<(), PurseError> {
        named(&name)?;
        if self.rows.get(&name).is_some() {
            return Err(PurseError::Exists);
        }
        self.invites
            .insert(&name, &Invitation { owner, expires_ms });
        Ok(())
    }

    /// Claim the row `name` an invitation names `owner` for, with nothing
    /// in it: any caller, before the invitation expires.
    #[msg]
    pub async fn claim_row(
        &mut self,
        ctx: &mut Command<Self>,
        name: Name,
        owner: Owner,
    ) -> Result<(), PurseError> {
        let invitation = self.invites.get(&name).ok_or(PurseError::NotInvited)?;
        if invitation.owner != owner {
            return Err(PurseError::NotInvited);
        }
        if ctx.now() > invitation.expires_ms {
            return Err(PurseError::Expired);
        }
        if self.rows.get(&name).is_some() {
            return Err(PurseError::Exists);
        }
        self.invites.remove(&name);
        let row = Row {
            owner,
            balance: 0,
            frozen: false,
        };
        self.rows.insert(&name, &row);
        Ok(())
    }

    /// Credit `name` with `amount`.
    #[msg(role = "operator")]
    pub async fn mint(&mut self, name: Name, amount: u64) -> Result<u64, PurseError> {
        let mut row = self.rows.get(&name).ok_or(PurseError::NoRow)?;
        row.balance = row
            .balance
            .checked_add(amount)
            .ok_or(PurseError::Overflow)?;
        self.rows.insert(&name, &row);
        Ok(row.balance)
    }

    /// Move `amount` from `from`, whose live owner the caller proved and
    /// which is not frozen, to `to`, which must exist.
    #[msg(credential = Owner)]
    pub async fn transfer(
        &mut self,
        ctx: &mut Command<Self>,
        from: Name,
        to: Name,
        amount: u64,
    ) -> Result<(), PurseError> {
        let mut payer = self.rows.get(&from).ok_or(PurseError::NoRow)?;
        if ctx.owner() != Some(payer.owner) {
            return Err(PurseError::NotOwner);
        }
        if payer.frozen {
            return Err(PurseError::Frozen);
        }
        let mut payee = self.rows.get(&to).ok_or(PurseError::NoRow)?;
        if from == to {
            return Ok(());
        }
        payer.balance = payer
            .balance
            .checked_sub(amount)
            .ok_or(PurseError::Insufficient)?;
        payee.balance = payee
            .balance
            .checked_add(amount)
            .ok_or(PurseError::Overflow)?;
        self.rows.insert(&from, &payer);
        self.rows.insert(&to, &payee);
        Ok(())
    }

    /// The row `name`, if there is one.
    #[msg]
    pub async fn row(&self, name: Name) -> Option<Row> {
        self.rows.get(&name)
    }

    /// The balance of `name`, if there is such a row.
    #[msg]
    pub async fn balance(&self, name: Name) -> Option<u64> {
        self.rows.get(&name).map(|row| row.balance)
    }

    /// Set `name`'s owner digest, its balance kept, and lift a freeze: a
    /// lost secret's recovery, once its member enrolled again.
    #[msg(role = "operator")]
    pub async fn rekey(&mut self, name: Name, owner: Owner) -> Result<(), PurseError> {
        let mut row = self.rows.get(&name).ok_or(PurseError::NoRow)?;
        row.owner = owner;
        row.frozen = false;
        self.rows.insert(&name, &row);
        Ok(())
    }

    /// Refuse `name`'s debits until a rekey.
    #[msg(role = "operator")]
    pub async fn freeze(&mut self, name: Name) -> Result<(), PurseError> {
        let mut row = self.rows.get(&name).ok_or(PurseError::NoRow)?;
        row.frozen = true;
        self.rows.insert(&name, &row);
        Ok(())
    }
}
