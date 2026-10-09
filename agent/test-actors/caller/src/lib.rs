//! An actor that calls the ledger: nested commands and queries, a callee's
//! error returned to it, and a cycle.

#![no_std]

use ledger::{Ledger, LedgerError};
use vos_sdk::prelude::*;

#[actor]
pub struct Caller {
    calls: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum PayError {
    #[codec(index = 0)]
    Refused,
    #[codec(index = 1)]
    Unexpected,
}

#[messages]
impl Caller {
    pub fn new() -> Self {
        Self { calls: 0 }
    }

    /// Transfer through the ledger, then return the receiver's balance.
    #[msg]
    pub async fn pay(
        &mut self,
        ctx: &mut Command<Self>,
        ledger: u32,
        from: u64,
        to: u64,
        amount: u64,
    ) -> Result<u64, PayError> {
        let ledger = Ref::<Ledger>::new(InstanceId(ledger));
        self.calls += 1;
        match ctx
            .call(ledger, ledger::ledger::Transfer { from, to, amount })
            .await
        {
            Ok(()) => {}
            Err(CallError::Failed(LedgerError::InsufficientFunds)) => {
                return Err(PayError::Refused);
            }
            Err(_) => return Err(PayError::Unexpected),
        }
        ctx.call(ledger, ledger::ledger::Balance { id: to })
            .await
            .map_err(|_| PayError::Unexpected)
    }

    /// Ask the ledger who calls it.
    #[msg]
    pub async fn ask(&self, ctx: &Query<Self>, ledger: u32) -> Option<Principal> {
        ctx.call(
            Ref::<Ledger>::new(InstanceId(ledger)),
            ledger::ledger::Whoami {},
        )
        .await
        .ok()
    }

    /// Call a ledger method that sends and then fails; succeed anyway.
    #[msg]
    pub async fn relay(&mut self, ctx: &mut Command<Self>, ledger: u32) -> bool {
        self.calls += 1;
        ctx.call(
            Ref::<Ledger>::new(InstanceId(ledger)),
            ledger::ledger::NotifyThenFail { agent: 9 },
        )
        .await
        .is_err()
    }

    /// Call this very instance: a cycle, which fails the step.
    #[msg]
    pub async fn recurse(&mut self, ctx: &mut Command<Self>) -> u64 {
        let (_, me) = ctx.me();
        self.calls += 1;
        let _ = ctx.call(Ref::<Caller>::new(me), caller::Recurse {}).await;
        self.calls
    }
}
