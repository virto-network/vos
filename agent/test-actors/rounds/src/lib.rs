//! Rounds: a workflow whose every effect a checker can count, and one
//! that writes its memory at every step, for the node's exactly-once
//! checker and the snapshot bench. Each workflow is a program of its own
//! (`src/bin`).
//!
//! A tour's effects are tallies of its amounts, at rounds instances of its
//! own agent and of another: each amount's count says how often it
//! applied, so an effect applied twice shows, and one of a failed tour is
//! known applied once or not at all.

#![no_std]

extern crate alloc;

use alloc::vec;

use vos_sdk::prelude::*;

/// A round's await of another agent: past any clock jump a checker makes
/// while workflows run.
const DEADLINE: Duration = Duration::from_secs(1800);

#[actor]
pub struct Rounds {
    /// The amounts tallied, added up.
    total: u64,
    /// How often each amount was tallied.
    tallies: Table<u64, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum RoundsError {
    /// The other agent's tally failed, or did not run.
    #[codec(index = 0)]
    Rejected,
    #[codec(index = 1)]
    TimedOut,
    /// This agent's tally failed.
    #[codec(index = 2)]
    Untallied,
}

impl<E> From<RequestError<E>> for RoundsError {
    fn from(error: RequestError<E>) -> Self {
        match error {
            RequestError::TimedOut => RoundsError::TimedOut,
            _ => RoundsError::Rejected,
        }
    }
}

#[messages]
impl Rounds {
    pub fn new() -> Self {
        Self {
            total: 0,
            tallies: Table::default(),
        }
    }

    /// Tally `amount` once more: the total of the amounts tallied.
    #[msg]
    pub async fn tally(&mut self, amount: u64) -> u64 {
        let count = self.tallies.get(&amount).unwrap_or(0);
        self.tallies.insert(&amount, &(count + 1));
        self.total += amount;
        self.total
    }

    #[msg]
    pub async fn total(&self) -> u64 {
        self.total
    }

    /// Each amount tallied, and how often, in the table's order.
    #[msg(gas = 100_000_000)]
    pub async fn tallies(&self) -> Vec<(u64, u64)> {
        self.tallies.iter(None).collect()
    }

    /// For each of `amounts`, a round: ask agent `other`'s rounds at
    /// instance `asked` to tally it, awaiting its total; tally it here; send
    /// it to the rounds at instance `told` to tally, a message; sleep `nap`
    /// ms of batch time when `nap` is not 0; then `passes` passes over
    /// `words` words seeded by the amount, a computation the step's share
    /// preempts. The totals answered, and the computations' digests xored.
    #[workflow(gas = 2_000_000)]
    pub async fn tour(
        ctx: &mut Workflow<Self>,
        other: u32,
        asked: u32,
        told: u32,
        amounts: Vec<u64>,
        nap: u64,
        words: u32,
        passes: u32,
    ) -> Result<(Vec<u64>, u64), RoundsError> {
        let (_, me) = ctx.me();
        let other = AgentId(other);
        let mut totals = Vec::with_capacity(amounts.len());
        let mut digest = 0;
        for amount in amounts {
            let tally = rounds::Tally { amount };
            let total = ctx
                .request(other, Ref::<Rounds>::new(InstanceId(asked)), tally)
                .within(DEADLINE)
                .await?;
            ctx.call(Ref::<Rounds>::new(me), rounds::Tally { amount })
                .await
                .map_err(|_| RoundsError::Untallied)?;
            let tally = rounds::Tally { amount };
            ctx.send(other, Ref::<Rounds>::new(InstanceId(told)), tally);
            if nap > 0 {
                let until = ctx.now() + nap;
                ctx.sleep_until(until).await;
            }
            digest ^= churn(amount, words, passes);
            totals.push(total);
        }
        Ok((totals, digest))
    }

    /// `steps` steps, each writing every page of `bytes` of memory, then
    /// pausing: what capturing and restoring that much costs a step. The
    /// bytes' sum.
    #[workflow(gas = 100_000_000)]
    pub async fn rewrite(ctx: &mut Workflow<Self>, bytes: u32, steps: u32) -> u64 {
        let mut memory = core::hint::black_box(vec![0u8; bytes as usize]);
        for step in 0..steps {
            memory.fill(step as u8 + 1);
            core::hint::black_box(&mut memory);
            ctx.sleep_until(ctx.now()).await;
        }
        memory.iter().map(|byte| u64::from(*byte)).sum()
    }
}

/// `passes` passes over `words` pseudo-random words drawn from `seed`, each
/// word mixed with the next: their digest. A checker computes the same on
/// its host to know a tour's result.
pub fn churn(seed: u64, words: u32, passes: u32) -> u64 {
    let mut data = vec![0u64; words.max(1) as usize];
    let mut state = seed | 1;
    for value in data.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *value = state;
    }
    let len = data.len();
    for pass in 0..passes {
        for index in 0..len {
            let next = data[(index + 1) % len];
            data[index] =
                data[index].rotate_left(pass % 63 + 1) ^ next.wrapping_mul(0x2545_f491_4f6c_dd1d);
        }
        core::hint::black_box(&mut data);
    }
    data.iter()
        .fold(0, |digest, value| digest.rotate_left(7) ^ value)
}
