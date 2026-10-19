//! Balances read at a window's cut: whether an account held at least a
//! threshold there, stated against the space's root with the account
//! public only as a salted commitment to it.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;
use vos_tree::{Blake2b, Hasher};

/// An account: its key in the balances.
pub type Account = [u8; 32];
/// A balance.
pub type Balance = u64;
/// A salted commitment to an account ([`commitment`]).
pub type Commitment = [u8; 32];

/// The commitment's domain.
pub const COMMITMENT_DOMAIN: &[u8] = b"vos/test/balance/account";

/// `BLAKE2b-256(COMMITMENT_DOMAIN ‖ salt ‖ account)`: the account a
/// statement names, opened only by whoever holds the salt.
pub fn commitment(salt: &[u8; 16], account: &Account) -> Commitment {
    Blake2b.hash(COMMITMENT_DOMAIN, &[salt, account])
}

#[actor]
pub struct Balances {
    balances: CommittedMap<Account, Balance>,
}

#[messages(module = "balance")]
impl Balances {
    pub fn new() -> Self {
        Self {
            balances: CommittedMap::default(),
        }
    }

    /// Set each account's balance.
    #[msg(gas = 100_000_000)]
    pub async fn set(&mut self, balances: Vec<(Account, Balance)>) -> u32 {
        for (account, balance) in &balances {
            self.balances.insert(account, balance);
        }
        balances.len() as u32
    }

    /// Whether `account`, committed to by `commitment` under `salt`, held at
    /// least `threshold` at the cut of the window it asks in.
    #[workflow(gas = 100_000_000)]
    pub async fn at_least_at_cut(
        ctx: &mut Workflow<Self>,
        commitment: Commitment,
        threshold: u64,
        salt: [u8; 16],
        account: Account,
    ) -> Result<bool, AttestError> {
        ctx.attest_at_cut(balance::AtLeast {
            commitment,
            threshold,
            salt,
            account,
        })
        .reads(|balances: &Balances| alloc::vec![balances.balances.read(&account)])
        .await
    }

    /// Whether the account `commitment` names held at least `threshold`:
    /// the account and the salt private, the commitment checked against
    /// them, so a statement names no account but the committed one. An
    /// absent account holds nothing.
    #[attestable(gas = 10_000_000)]
    pub fn at_least(
        &self,
        #[public] commitment: Commitment,
        #[public] threshold: u64,
        salt: [u8; 16],
        account: Account,
    ) -> bool {
        assert!(
            self::commitment(&salt, &account) == commitment,
            "the commitment opens"
        );
        self.balances.get(&account).unwrap_or(0) >= threshold
    }
}
