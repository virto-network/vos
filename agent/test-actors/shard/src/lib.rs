//! The scale test's actor. As a ledger shard: users' accounts in a
//! committed map, transfers within the shard or to a payee in another
//! shard by message, a workflow, and a balance read at a window's cut. As
//! the stand-in identity agent: a row of key bytes a user, written in bulk
//! and then one at a time.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

/// An account: a user's, by the id the load derives from its index.
pub type Account = [u8; 16];

/// What an account holds before anything moved it: a run's transfers of
/// one unit never empty it.
pub const OPENING: u64 = 1 << 40;

/// The instance each shard's actor is installed as, where a transfer to
/// another shard sends its credit.
pub const INSTANCE: InstanceId = InstanceId(1);

/// The most identity rows one call writes: well within a step's writes.
pub const FILL_MAX: u32 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum ShardError {
    #[codec(index = 0)]
    InsufficientFunds,
    #[codec(index = 1)]
    TooMany,
}

#[actor]
pub struct Shard {
    accounts: CommittedMap<Account, u64>,
    identities: Table<u64, [u8; 32]>,
}

impl Shard {
    fn balance_of(&self, id: &Account) -> u64 {
        self.accounts.get(id).unwrap_or(OPENING)
    }
}

/// User `index`'s stand-in identity row.
pub fn identity_row(index: u64) -> [u8; 32] {
    let mut row = [0u8; 32];
    for chunk in row.chunks_exact_mut(8) {
        chunk.copy_from_slice(&index.to_le_bytes());
    }
    row
}

#[messages]
impl Shard {
    pub fn new() -> Self {
        Self {
            accounts: CommittedMap::default(),
            identities: Table::default(),
        }
    }

    /// Move `amount` from `from` to `to`: here when `to_agent` is this
    /// shard, else by a credit sent to `to_agent`'s shard, delivered once
    /// this step commits. `from`'s balance after.
    #[msg(gas = 5_000_000)]
    pub async fn transfer(
        &mut self,
        ctx: &mut Command<Self>,
        from: Account,
        to: Account,
        to_agent: u32,
        amount: u64,
    ) -> Result<u64, ShardError> {
        let source = self.balance_of(&from);
        let left = source
            .checked_sub(amount)
            .ok_or(ShardError::InsufficientFunds)?;
        self.accounts.insert(&from, &left);
        let (me, _) = ctx.me();
        if me.0 == to_agent {
            let target = self.balance_of(&to).saturating_add(amount);
            self.accounts.insert(&to, &target);
        } else {
            ctx.send(
                AgentId(to_agent),
                Ref::<Shard>::new(INSTANCE),
                shard::Credit { to, amount },
            );
        }
        Ok(left)
    }

    /// Credit `to` with `amount`: another shard's transfer arriving.
    #[msg(gas = 5_000_000)]
    pub async fn credit(&mut self, to: Account, amount: u64) -> u64 {
        let target = self.balance_of(&to).saturating_add(amount);
        self.accounts.insert(&to, &target);
        target
    }

    #[msg]
    pub async fn balance(&self, id: Account) -> u64 {
        self.balance_of(&id)
    }

    /// The sum of `amounts`, as a workflow.
    #[workflow]
    pub fn tally(amounts: Vec<u64>) -> u64 {
        amounts.iter().sum()
    }

    /// Whether account `id` held at least `threshold` at the cut of the
    /// window it asks in.
    #[workflow(gas = 100_000_000)]
    pub async fn holds_at_cut(
        ctx: &mut Workflow<Self>,
        threshold: u64,
        id: Account,
    ) -> Result<bool, AttestError> {
        ctx.attest_at_cut(shard::Holds { threshold, id })
            .reads(|shard: &Shard| alloc::vec![shard.accounts.read(&id)])
            .await
    }

    /// An absent account holds its opening balance.
    #[attestable(gas = 10_000_000)]
    pub fn holds(&self, #[public] threshold: u64, id: Account) -> bool {
        self.accounts.get(&id).unwrap_or(OPENING) >= threshold
    }

    /// Write the identity rows of users `start..start + count`, at most
    /// [`FILL_MAX`]: the next user after them.
    #[msg(gas = 100_000_000)]
    pub async fn fill_identities(&mut self, start: u64, count: u32) -> Result<u64, ShardError> {
        if count > FILL_MAX {
            return Err(ShardError::TooMany);
        }
        let end = start.saturating_add(u64::from(count));
        for index in start..end {
            self.identities.insert(&index, &identity_row(index));
        }
        Ok(end)
    }

    /// Replace user `index`'s identity row.
    #[msg]
    pub async fn set_identity(&mut self, index: u64, row: [u8; 32]) -> u64 {
        self.identities.insert(&index, &row);
        index
    }

    #[msg]
    pub async fn identity(&self, index: u64) -> Option<[u8; 32]> {
        self.identities.get(&index)
    }
}
