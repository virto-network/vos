//! The ledger's wire types (`light-node.md` §5.2): what its actor,
//! `Payments`, takes and answers, and its errors.

use alloc::vec::Vec;

use scale::{Decode, Encode};

/// An account's name: 1 to [`MAX_NAME`] ASCII letters, digits, `.`, `_` or
/// `-`, shown verbatim.
pub type Name = Vec<u8>;

/// An owner digest: eight M31 words, as little-endian `u32`s.
pub type Owner = [u8; 32];

/// The longest a name may be: its row's `user_data`.
pub const MAX_NAME: usize = 32;

/// An account as its owner and the operators read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Holding {
    pub owner: Owner,
    pub balance: u64,
    pub frozen: bool,
}

/// What `Payments` refuses, by its codec index.
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
    /// A transfer under a key this payer paid under already: the payment
    /// that key names was made, and is not made again.
    #[codec(index = 13)]
    Paid,
}

/// The key a payer names one payment by: drawn by its device per
/// confirmed form, and the same in every proof made for that form, so the
/// ledger pays it once.
pub type PaymentKey = [u8; 32];

/// The external id the ledger records a transfer under `key` of `owner`'s
/// by: cipher-clerk's `client_external_id`, BLAKE2b-256 under its domain.
/// A device reads `paid` by it, so the read names no owner.
pub fn external_id(owner: &Owner, key: &PaymentKey) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(b"cipher-clerk/external-id/client", &[owner, key])
}
