//! A shop: workflows that await other agents, call this agent's actors,
//! sleep, compute, fail, write their memory back and reach the shop's
//! state in sections, for the agent's workflow tests.

#![no_std]

extern crate alloc;

use alloc::vec;
use core::cell::UnsafeCell;

use caller::Caller;
use counter::Counter;
use ledger::Ledger;
use vos_sdk::prelude::*;

/// The counter a workflow asks at another agent, its "risk" agent.
const RISK: Ref<Counter> = Ref::new(InstanceId(1));

#[actor]
pub struct Shop {
    sales: u64,
    /// Orders by id, their amounts: what workflows record in sections.
    orders: Table<u64, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum ShopError {
    /// An awaited agent answered with an error, or did not run the call.
    #[codec(index = 0)]
    Rejected,
    #[codec(index = 1)]
    TimedOut,
    /// A call of this agent's failed.
    #[codec(index = 2)]
    Funds,
}

impl<E> From<RequestError<E>> for ShopError {
    fn from(error: RequestError<E>) -> Self {
        match error {
            RequestError::TimedOut => ShopError::TimedOut,
            _ => ShopError::Rejected,
        }
    }
}

/// A page of a workflow's memory.
#[repr(C, align(4096))]
struct Page(UnsafeCell<[u8; 4096]>);

// SAFETY: a workflow runs on one thread.
unsafe impl Sync for Page {}

impl Page {
    fn fill(&self, byte: u8) {
        // SAFETY: single-threaded, and no reference outlives the call.
        unsafe { (*self.0.get()).fill(byte) }
    }

    fn sum(&self) -> u64 {
        // SAFETY: as above.
        unsafe { (*self.0.get()).iter().map(|byte| u64::from(*byte)).sum() }
    }
}

/// A page starting zeroed, and one starting as the program's image, which
/// `scratch` writes and then puts back.
static ZEROED: Page = Page(UnsafeCell::new([0; 4096]));
static IMAGE: Page = Page(UnsafeCell::new([7; 4096]));
/// A page `digest` keeps its hash state in, which only the agent writes,
/// serving the compression.
static STATE: Page = Page(UnsafeCell::new([0; 4096]));

#[messages]
impl Shop {
    pub fn new() -> Self {
        Self {
            sales: 0,
            orders: Table::default(),
        }
    }

    /// Count a sale: what a workflow's calls change.
    #[msg]
    pub async fn sell(&mut self, amount: u64) -> u64 {
        self.sales += amount;
        self.sales
    }

    #[msg]
    pub async fn sales(&self) -> u64 {
        self.sales
    }

    /// Ask the risk agent about a transfer, awaiting one answer, then move
    /// the funds on this agent's ledger and count the sale: the risk
    /// agent's answer.
    #[workflow]
    pub async fn transfer(
        ctx: &mut Workflow<Self>,
        risk: u32,
        ledger: u32,
        from: u64,
        to: u64,
        amount: u64,
    ) -> Result<u64, ShopError> {
        let verdict = ctx
            .request(
                AgentId(risk),
                RISK,
                counter::counter::Increment { by: amount },
            )
            .within(Duration::from_secs(30))
            .await?;
        ctx.call(
            Ref::<Ledger>::new(InstanceId(ledger)),
            ledger::ledger::Transfer { from, to, amount },
        )
        .await
        .map_err(|_| ShopError::Funds)?;
        let (_, me) = ctx.me();
        ctx.call(Ref::<Shop>::new(me), shop::Sell { amount })
            .await
            .map_err(|_| ShopError::Funds)?;
        Ok(verdict)
    }

    /// `steps` requests of the risk agent in turn, each answer counted as
    /// a sale: the answers.
    #[workflow]
    pub async fn saga(
        ctx: &mut Workflow<Self>,
        risk: u32,
        steps: u32,
    ) -> Result<Vec<u64>, ShopError> {
        let (_, me) = ctx.me();
        let mut answers = Vec::new();
        for step in 0..steps {
            let by = u64::from(step) + 1;
            let answer = ctx
                .request(AgentId(risk), RISK, counter::counter::Increment { by })
                .await?;
            ctx.call(Ref::<Shop>::new(me), shop::Sell { amount: answer })
                .await
                .map_err(|_| ShopError::Funds)?;
            answers.push(answer);
        }
        Ok(answers)
    }

    /// A long computation: `words` pseudo-random words, sorted a chunk a
    /// round in `rounds` rounds, pausing once they are filled and after each
    /// round, then digested.
    #[workflow(gas = 100_000_000)]
    pub async fn compute(ctx: &mut Workflow<Self>, words: u32, rounds: u32) -> u64 {
        let mut data = vec![0u64; words as usize];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for value in data.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = state;
        }
        ctx.sleep_until(ctx.now()).await;
        let chunk = data.len() / rounds.max(1) as usize;
        for round in 0..rounds as usize {
            data[round * chunk..(round + 1) * chunk].sort_unstable();
            ctx.sleep_until(ctx.now()).await;
        }
        let mut digest = 0u64;
        for (index, value) in data.iter().enumerate().step_by(997) {
            digest = digest.rotate_left(5) ^ value ^ index as u64;
        }
        digest
    }

    /// Sleep `ms` past the batch's time: the time it woke at.
    #[workflow]
    pub async fn nap(ctx: &mut Workflow<Self>, ms: u64) -> u64 {
        let until = ctx.now() + ms;
        ctx.sleep_until(until).await;
        ctx.now()
    }

    /// Count a sale, ask the risk agent, count a larger one, and trap if
    /// it answered 1: the trapping step's sale goes, the first stays.
    #[workflow]
    pub async fn fragile(ctx: &mut Workflow<Self>, risk: u32) -> u64 {
        let (_, me) = ctx.me();
        let _ = ctx
            .call(Ref::<Shop>::new(me), shop::Sell { amount: 1 })
            .await;
        let answer = ctx
            .request(AgentId(risk), RISK, counter::counter::Increment { by: 1 })
            .await
            .unwrap_or(0);
        let _ = ctx
            .call(Ref::<Shop>::new(me), shop::Sell { amount: 100 })
            .await;
        assert!(answer != 1, "a verdict of one");
        answer
    }

    /// Write a zeroed page and a page of the image, await the risk agent,
    /// put both back, await again: the sum of both pages each time.
    #[workflow]
    pub async fn scratch(ctx: &mut Workflow<Self>, risk: u32) -> Result<(u64, u64), ShopError> {
        ZEROED.fill(0xab);
        IMAGE.fill(0x55);
        ctx.request(AgentId(risk), RISK, counter::counter::Increment { by: 1 })
            .await?;
        let written = ZEROED.sum() + IMAGE.sum();
        ZEROED.fill(0);
        IMAGE.fill(7);
        ctx.request(AgentId(risk), RISK, counter::counter::Increment { by: 1 })
            .await?;
        Ok((written, ZEROED.sum() + IMAGE.sum()))
    }

    /// Start the shop's `nap` at instance `instance` of agent `other`, then
    /// await its result.
    #[workflow]
    pub async fn delegate(
        ctx: &mut Workflow<Self>,
        other: u32,
        instance: u32,
        ms: u64,
    ) -> Result<(WorkflowId, u64), ShopError> {
        let to = Ref::<Shop>::new(InstanceId(instance));
        let workflow = ctx.start(AgentId(other), to, shop::Nap { ms }).await?;
        let woke = ctx
            .result::<shop::Nap>(AgentId(other), workflow)
            .within(Duration::from_secs(10))
            .await?;
        Ok((workflow, woke))
    }

    /// Fill `bytes` of memory, then pause: a step that writes that much.
    #[workflow(gas = 100_000_000)]
    pub async fn hog(ctx: &mut Workflow<Self>, bytes: u32) -> u32 {
        let memory = core::hint::black_box(vec![1u8; bytes as usize]);
        ctx.sleep_until(ctx.now()).await;
        memory.len() as u32
    }

    /// For each of `sizes`, fill that many more bytes of memory, keeping
    /// all, then await the risk agent, or sleep when `risk` is 0: steps
    /// that write and restore as many pages as a test asks. The bytes
    /// filled.
    #[workflow(gas = 100_000_000)]
    pub async fn fill(ctx: &mut Workflow<Self>, risk: u32, sizes: Vec<u32>) -> u64 {
        let mut kept = Vec::new();
        for size in sizes {
            kept.push(core::hint::black_box(vec![1u8; size as usize]));
            if risk == 0 {
                ctx.sleep_until(ctx.now()).await;
            } else {
                let _ = ctx
                    .request(AgentId(risk), RISK, counter::counter::Increment { by: 1 })
                    .await;
            }
        }
        kept.iter().map(|bytes| bytes.len() as u64).sum()
    }

    /// Compress `rounds` blocks into a state kept in a page the workflow
    /// itself never writes, which the agent writes serving each
    /// compression, pausing after each: the state's first 32 bytes.
    #[workflow]
    pub async fn digest(ctx: &mut Workflow<Self>, rounds: u32) -> Vec<u8> {
        // SAFETY: a workflow runs on one thread, and nothing else holds the
        // page.
        let state = unsafe { &mut *STATE.0.get() };
        let (h, _) = state
            .split_first_chunk_mut::<64>()
            .expect("a page holds a state");
        for round in 0..rounds {
            let block = [round as u8; 128];
            let counter = u128::from(round + 1) * 128;
            vos_pvm_precompiles::blake2b_compress(h, &block, counter, round + 1 == rounds);
            ctx.sleep_until(ctx.now()).await;
        }
        h[..32].to_vec()
    }

    /// Call the caller at instance `first`, which hops on through
    /// `remaining` more: a chain of `remaining + 1` nested calls.
    #[workflow(gas = 100_000_000)]
    pub async fn chain(ctx: &mut Workflow<Self>, first: u32, remaining: u32) -> u32 {
        let hop = caller::caller::Hop {
            next: first + 1,
            remaining,
        };
        ctx.call(Ref::<Caller>::new(InstanceId(first)), hop)
            .await
            .unwrap_or(0)
    }

    /// Have the ledger at instance `ledger` attest a checksum of `values`,
    /// then pause: the step's attest commits with its snapshot.
    #[workflow]
    pub async fn audit(ctx: &mut Workflow<Self>, ledger: u32, values: Vec<u64>) -> u64 {
        let checksum = ctx
            .call(
                Ref::<Ledger>::new(InstanceId(ledger)),
                ledger::ledger::Audit { values },
            )
            .await
            .unwrap_or(0);
        ctx.sleep_until(ctx.now()).await;
        checksum
    }

    /// `passes` passes over `words` pseudo-random words with no await
    /// between: a computation the step's share preempts, step after step.
    /// The words' digest.
    #[workflow(gas = 20_000_000)]
    pub async fn grind(ctx: &mut Workflow<Self>, words: u32, passes: u32) -> u64 {
        let _ = ctx;
        churn(words, passes)
    }

    /// `grind` with a limit that holds the whole computation: the run that
    /// never stops.
    #[workflow(gas = 100_000_000)]
    pub async fn grind_whole(ctx: &mut Workflow<Self>, words: u32, passes: u32) -> u64 {
        let _ = ctx;
        churn(words, passes)
    }

    /// Read the batch's time `rounds` times, then count a sale: a unit
    /// whose first effect, its call, comes after effect-free code costing
    /// some `price::OPERATION` a round. The shop's sales after it.
    #[workflow(gas = 50_000_000)]
    pub async fn settle(ctx: &mut Workflow<Self>, rounds: u32) -> u64 {
        for _ in 0..rounds {
            core::hint::black_box(ctx.now());
        }
        let (_, me) = ctx.me();
        let amount = u64::from(rounds % 100 + 1);
        ctx.call(Ref::<Shop>::new(me), shop::Sell { amount })
            .await
            .unwrap_or(0)
    }

    /// `times` times: read the batch's time `rounds` times, have this
    /// agent's counter echo `len` bytes, and count a sale of the echo's
    /// length. Each echo's call may spend what is left of the step's share,
    /// ending the step at its await. The shop's sales after them.
    #[workflow(gas = 5_000_000)]
    pub async fn relay(ctx: &mut Workflow<Self>, rounds: u32, len: u32, times: u32) -> u64 {
        let (_, me) = ctx.me();
        let mut sales = 0;
        for _ in 0..times {
            for _ in 0..rounds {
                core::hint::black_box(ctx.now());
            }
            let echo = counter::counter::Echo {
                bytes: vec![7u8; len as usize],
            };
            let echoed = ctx
                .call(Ref::<Counter>::new(InstanceId(1)), echo)
                .await
                .map_or(0, |bytes| bytes.len() as u64);
            sales = ctx
                .call(Ref::<Shop>::new(me), shop::Sell { amount: echoed })
                .await
                .unwrap_or(0);
        }
        sales
    }

    /// `digest` with no await, on a limit of a few hundred compressions:
    /// steps that end at a compression their share cannot pay, which the
    /// next serves first. The state's first 32 bytes.
    #[workflow(gas = 200_000)]
    pub async fn press(ctx: &mut Workflow<Self>, rounds: u32) -> Vec<u8> {
        let _ = ctx;
        // SAFETY: a workflow runs on one thread, and nothing else holds the
        // page.
        let state = unsafe { &mut *STATE.0.get() };
        let (h, _) = state
            .split_first_chunk_mut::<64>()
            .expect("a page holds a state");
        for round in 0..rounds {
            let block = [round as u8; 128];
            let counter = u128::from(round + 1) * 128;
            vos_pvm_precompiles::blake2b_compress(h, &block, counter, round + 1 == rounds);
        }
        h[..32].to_vec()
    }

    /// Nothing, with a limit no block of a program fits: a step that
    /// cannot move.
    #[workflow(gas = 1)]
    pub async fn stuck(ctx: &mut Workflow<Self>) -> u64 {
        let _ = ctx;
        0
    }

    /// Send the risk agent's counter an increment, then fill `bytes` of
    /// memory and pause: pages written after the unit's first effect.
    #[workflow(gas = 100_000_000)]
    pub async fn splurge(ctx: &mut Workflow<Self>, risk: u32, bytes: u32) -> u32 {
        ctx.send(AgentId(risk), RISK, counter::counter::Increment { by: 1 });
        let memory = core::hint::black_box(vec![1u8; bytes as usize]);
        ctx.sleep_until(ctx.now()).await;
        memory.len() as u32
    }

    /// Record order `id` of `amount` in one section, its row and the
    /// sales; then read both back in a second section of the same unit:
    /// the sales after, and the order's amount as read.
    #[workflow]
    pub async fn record(ctx: &mut Workflow<Self>, id: u64, amount: u64) -> (u64, Option<u64>) {
        ctx.update(|shop: &mut Shop| {
            shop.orders.insert(&id, &amount);
            shop.sales += amount;
        });
        ctx.read(|shop: &Shop| (shop.sales, shop.orders.get(&id)))
    }

    /// Read the sales, spend `rounds` reads of the time, then write what it
    /// read plus `by`, in one unit: from its first section the unit runs to
    /// its end within the step's limit, never preempted, so what it writes
    /// still holds what it read. The sales it wrote.
    #[workflow(gas = 5_000_000)]
    pub async fn bump(ctx: &mut Workflow<Self>, by: u64, rounds: u32) -> u64 {
        let sales = ctx.read(|shop: &Shop| shop.sales);
        for _ in 0..rounds {
            core::hint::black_box(ctx.now());
        }
        ctx.update(|shop: &mut Shop| {
            shop.sales = sales + by;
            shop.sales
        })
    }

    /// Add each of `orders`, sleeping between them, re-reading the sales in
    /// each section after a pause: the sales after each.
    #[workflow]
    pub async fn restock(ctx: &mut Workflow<Self>, orders: Vec<u64>) -> Vec<u64> {
        let mut seen = Vec::new();
        for amount in orders {
            let sales = ctx.update(|shop: &mut Shop| {
                shop.sales += amount;
                shop.sales
            });
            seen.push(sales);
            ctx.sleep_until(ctx.now()).await;
        }
        seen
    }

    /// Misuse a section, by `how`, each failing the step: inside one, 0 a
    /// call, 1 a send, 2 a request, 3 a wait for a result, 4 a sleep, 5 a
    /// second open, 6 the input; 7 an open of another instance; 8 a row
    /// read with none open; 9 a close with none open; 10 an end with one
    /// open.
    #[workflow]
    pub async fn misuse(ctx: &mut Workflow<Self>, how: u8) -> u8 {
        use vos_sdk::abi::Rows;
        use vos_sdk::context::Method;
        use vos_sdk::host;
        let (_, me) = ctx.me();
        match how {
            0..=6 => {
                host::open(me.0);
                match how {
                    0 => drop(host::call(me.0, shop::Sales::ID, &[])),
                    1 => host::send(9, 1, shop::Sales::ID, &[]),
                    2 => drop(host::request(9, 1, shop::Sales::ID, &[], 0)),
                    3 => drop(host::result(9, 1, 0)),
                    4 => host::sleep(host::now() + 1),
                    5 => host::open(me.0),
                    _ => drop(host::input()),
                }
                host::close();
            }
            7 => {
                host::open(me.0 + 1);
                host::close();
            }
            8 => drop(host::get(Rows::Struct, &[])),
            9 => host::close(),
            _ => host::open(me.0),
        }
        how
    }

    /// Open and close `count` empty sections: what a section costs the
    /// agent, apart.
    #[workflow(gas = 100_000_000)]
    pub async fn sections(ctx: &mut Workflow<Self>, count: u32) -> u32 {
        let (_, me) = ctx.me();
        for _ in 0..count {
            vos_sdk::host::open(me.0);
            vos_sdk::host::close();
        }
        count
    }

    /// Encode `len` bytes as the risk agent's counter's echo takes them,
    /// then pause by `kind`: 0 a sleep, 1 a request of the echo, 2 a wait
    /// for the result of the risk agent's workflow 1. Each step writes the
    /// same memory: what a pause costs the agent, apart.
    #[workflow]
    pub async fn probe(ctx: &mut Workflow<Self>, kind: u8, risk: u32, len: u32) -> u8 {
        let echo = counter::counter::Echo {
            bytes: core::hint::black_box(vec![7u8; len as usize]),
        };
        match kind {
            0 => {
                let encoded = core::hint::black_box(echo.encode());
                ctx.sleep_until(ctx.now()).await;
                drop(encoded);
            }
            1 => {
                let _ = ctx.request(AgentId(risk), RISK, echo).await;
            }
            _ => {
                let encoded = core::hint::black_box(echo.encode());
                let _ = ctx.result::<shop::Nap>(AgentId(risk), WorkflowId(1)).await;
                drop(encoded);
            }
        }
        kind
    }
}

/// `passes` passes over `words` pseudo-random words, each mixed with the
/// next: their digest.
fn churn(words: u32, passes: u32) -> u64 {
    let mut data = vec![0u64; words.max(1) as usize];
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for value in data.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *value = state;
    }
    let len = data.len();
    for pass in 0..passes {
        for index in 0..len {
            let next = if index + 1 < len {
                data[index + 1]
            } else {
                data[0]
            };
            data[index] =
                data[index].rotate_left(pass % 63 + 1) ^ next.wrapping_mul(0x2545_f491_4f6c_dd1d);
        }
    }
    data.iter()
        .fold(0, |digest, value| digest.rotate_left(7) ^ value)
}
