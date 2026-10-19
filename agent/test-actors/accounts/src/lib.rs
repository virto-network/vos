//! Cipher-clerk accounts in a committed map, read at a window's cut: one
//! account's settled balance against a public threshold, and a window's
//! sixteen pseudo-accounts' balances summed, as the window kernel reads
//! them. The costs of a read's prologue, its rows' multiproof and the
//! agent's root's path to the space's root, are measured on these.

#![no_std]

extern crate alloc;

use cipher_clerk::codec;
use cipher_clerk::kernel::Value;
use cipher_clerk::types::{Account, Layer};
use vos_sdk::prelude::*;

#[actor]
pub struct Accounts {
    accounts: CommittedMap<[u8; 16], Vec<u8>>,
}

/// An account's settled balance, credits less debits; nothing when absent.
fn balance(account: Option<Vec<u8>>) -> i128 {
    let Some(bytes) = account else { return 0 };
    let account = codec::from_bytes::<Account<Value>>(&bytes).expect("an account");
    let settled = &account.balances[Layer::Settled.as_index()];
    i128::from(settled.cr.0) - i128::from(settled.dr.0)
}

#[messages]
impl Accounts {
    pub fn new() -> Self {
        Self {
            accounts: CommittedMap::default(),
        }
    }

    /// Whether account `id`'s settled balance was at least `threshold` at
    /// the cut of the window it asks in.
    #[workflow(gas = 100_000_000)]
    pub async fn holds_at_cut(
        ctx: &mut Workflow<Self>,
        threshold: u64,
        id: [u8; 16],
    ) -> Result<bool, AttestError> {
        ctx.attest_at_cut(accounts::Holds { threshold, id })
            .reads(|accounts: &Accounts| alloc::vec![accounts.accounts.read(&id)])
            .await
    }

    /// The accounts `ids`' settled balances at the cut, summed.
    #[workflow(gas = 100_000_000)]
    pub async fn window_at_cut(
        ctx: &mut Workflow<Self>,
        ids: Vec<[u8; 16]>,
    ) -> Result<(u32, i64), AttestError> {
        let reads = ids.clone();
        ctx.attest_at_cut(accounts::Window { ids })
            .reads(|accounts: &Accounts| {
                reads.iter().map(|id| accounts.accounts.read(id)).collect()
            })
            .await
    }

    /// The accounts `ids`' balances at the cut, summed, or, without
    /// `lookups`, their count alone: the prologue's cost apart from the
    /// view's reads, by difference.
    #[workflow(gas = 100_000_000)]
    pub async fn probe_at_cut(
        ctx: &mut Workflow<Self>,
        ids: Vec<[u8; 16]>,
        lookups: bool,
    ) -> Result<(u32, i64), AttestError> {
        let reads = ids.clone();
        ctx.attest_at_cut(accounts::Probe { ids, lookups })
            .reads(|accounts: &Accounts| {
                reads.iter().map(|id| accounts.accounts.read(id)).collect()
            })
            .await
    }

    #[attestable(gas = 10_000_000)]
    pub fn probe(&self, ids: Vec<[u8; 16]>, lookups: bool) -> (u32, i64) {
        if !lookups {
            return (ids.len() as u32, 0);
        }
        let total: i128 = ids.iter().map(|id| balance(self.accounts.get(id))).sum();
        (ids.len() as u32, total as i64)
    }

    #[attestable(gas = 10_000_000)]
    pub fn holds(&self, #[public] threshold: u64, id: [u8; 16]) -> bool {
        balance(self.accounts.get(&id)) >= i128::from(threshold)
    }

    #[attestable(gas = 10_000_000)]
    pub fn window(&self, ids: Vec<[u8; 16]>) -> (u32, i64) {
        let total: i128 = ids.iter().map(|id| balance(self.accounts.get(id))).sum();
        (ids.len() as u32, total as i64)
    }
}
