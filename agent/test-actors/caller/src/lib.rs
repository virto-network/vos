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

    /// Call instance `next`, which hops on to `next + 1`, `remaining`
    /// times: past the inner machines, the step fails.
    #[msg]
    pub async fn hop(&mut self, ctx: &mut Command<Self>, next: u32, remaining: u32) -> u32 {
        if remaining == 0 {
            return 0;
        }
        ctx.call(
            Ref::<Caller>::new(InstanceId(next)),
            caller::Hop {
                next: next + 1,
                remaining: remaining - 1,
            },
        )
        .await
        .unwrap_or(0)
            + 1
    }

    /// Hop down `remaining` instances as `hop` does, then at the bottom make
    /// `count` gets of absent keys (`kind` 0) or 64-byte scans (`kind` 1):
    /// what an operation costs through every call frame.
    #[msg(gas = 100_000_000)]
    pub async fn dive(
        &mut self,
        ctx: &mut Command<Self>,
        next: u32,
        remaining: u32,
        kind: u8,
        count: u32,
    ) -> u64 {
        if remaining > 0 {
            let call = caller::Dive {
                next: next + 1,
                remaining: remaining - 1,
                kind,
                count,
            };
            return ctx
                .call(Ref::<Caller>::new(InstanceId(next)), call)
                .await
                .unwrap_or(0);
        }
        let mut rows = [0u8; 64];
        let mut total = 0;
        for index in 0..count {
            total += match kind {
                0 => u64::from(vos_sdk::host::get(&index.to_be_bytes()).is_some()),
                _ => vos_sdk::host::scan(&[3], &[], &mut rows),
            };
        }
        total
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
