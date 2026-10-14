//! A ledger: balances in a table, a role-gated mint, transfers that fail
//! without funds, scans, and an attestable checksum.

#![no_std]

use vos_sdk::prelude::*;

#[actor]
pub struct Ledger {
    total: u64,
    #[table(name = "balances")]
    accounts: Table<u64, u64, Ordered>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum LedgerError {
    #[codec(index = 0)]
    InsufficientFunds,
}

#[messages]
impl Ledger {
    pub fn new() -> Self {
        Self {
            total: 0,
            accounts: Table::default(),
        }
    }

    /// Credit `to`; only a "minter" may.
    #[msg(role = "minter")]
    pub async fn mint(&mut self, to: u64, amount: u64) -> u64 {
        let balance = self.accounts.get(&to).unwrap_or(0) + amount;
        self.accounts.insert(&to, &balance);
        self.total += amount;
        balance
    }

    /// Credit each of `accounts`; only a "minter" may.
    #[msg(role = "minter", gas = 100_000_000)]
    pub async fn mint_all(&mut self, accounts: Vec<(u64, u64)>) -> u64 {
        for (to, amount) in &accounts {
            let balance = self.accounts.get(to).unwrap_or(0) + amount;
            self.accounts.insert(to, &balance);
            self.total += amount;
        }
        self.total
    }

    #[msg(gas = 2_000_000)]
    pub async fn transfer(&mut self, from: u64, to: u64, amount: u64) -> Result<(), LedgerError> {
        let source = self.accounts.get(&from).unwrap_or(0);
        if source < amount {
            return Err(LedgerError::InsufficientFunds);
        }
        self.accounts.insert(&from, &(source - amount));
        let target = self.accounts.get(&to).unwrap_or(0);
        self.accounts.insert(&to, &(target + amount));
        Ok(())
    }

    #[msg]
    pub async fn balance(&self, id: u64) -> u64 {
        self.accounts.get(&id).unwrap_or(0)
    }

    #[msg]
    pub async fn total(&self) -> u64 {
        self.total
    }

    /// Every non-empty account, in id order.
    #[msg]
    pub async fn holders(&self) -> Vec<(u64, u64)> {
        self.accounts
            .iter(None)
            .filter(|(_, balance)| *balance > 0)
            .collect()
    }

    /// Who called: the calling instance, for a nested call.
    #[msg]
    pub async fn whoami(&self, ctx: &Query<Self>) -> Principal {
        ctx.caller()
    }

    /// Send a message, then fail: the message must not survive.
    #[msg]
    pub async fn notify_then_fail(
        &mut self,
        ctx: &mut Command<Self>,
        agent: u32,
    ) -> Result<(), LedgerError> {
        ctx.send(
            AgentId(agent),
            Ref::<Ledger>::new(InstanceId(1)),
            ledger::Total {},
        );
        Err(LedgerError::InsufficientFunds)
    }

    /// Check `values` with the attestable `checksum`, run as its own
    /// program.
    #[msg]
    pub async fn audit(&mut self, ctx: &mut Command<Self>, values: Vec<u64>) -> u64 {
        ctx.attest(ledger::Checksum { values }).await.unwrap_or(0)
    }

    /// Attest `count` empty checksums, to measure what serving them costs.
    #[msg(gas = 100_000_000)]
    pub async fn audits(&mut self, ctx: &mut Command<Self>, count: u32) -> u64 {
        let mut total = 0;
        for _ in 0..count {
            total += ctx
                .attest(ledger::Checksum { values: Vec::new() })
                .await
                .unwrap_or(0);
        }
        total
    }

    #[attestable]
    pub fn checksum(values: Vec<u64>) -> u64 {
        values.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, value| {
            (hash ^ value).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }
}
