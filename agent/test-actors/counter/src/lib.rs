//! A counter: struct state, a query, and a command that can fail; and
//! probes of the agent's enforcement.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

/// Host call `0x5ff`: in the actor block, served by no one.
fn unserved_call() -> u64 {
    #[cfg(target_arch = "riscv64")]
    {
        let result: u64;
        // SAFETY: an ecalli with no arguments; the agent answers in a0.
        unsafe {
            core::arch::asm!(
                "li t0, 0x5ff",
                "csrw 0x801, zero",
                "ecall",
                lateout("t0") _,
                lateout("a0") result,
                options(nostack),
            );
        }
        result
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        0
    }
}

#[actor]
pub struct Counter {
    value: u64,
    blobs: Table<u32, Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum CounterError {
    #[codec(index = 0)]
    Overflow,
}

#[messages]
impl Counter {
    pub fn new() -> Self {
        Self {
            value: 0,
            blobs: Table::default(),
        }
    }

    #[msg]
    pub async fn increment(&mut self, by: u64) -> Result<u64, CounterError> {
        self.value = self.value.checked_add(by).ok_or(CounterError::Overflow)?;
        Ok(self.value)
    }

    #[msg]
    pub async fn value(&self) -> u64 {
        self.value
    }

    /// Add `by` to the counter at `instance` of agent `agent`, by message.
    #[msg]
    pub async fn forward(
        &mut self,
        ctx: &mut Command<Self>,
        agent: u32,
        instance: u32,
        by: u64,
    ) -> u64 {
        ctx.send(
            AgentId(agent),
            Ref::<Counter>::new(InstanceId(instance)),
            counter::Increment { by },
        );
        by
    }

    /// Write `keys`, then scan under `prefix` from `cursor`, any bytes the
    /// raw ABI allows, and return what the scan wrote.
    #[msg]
    pub async fn put_and_scan(
        &mut self,
        keys: Vec<Vec<u8>>,
        prefix: Vec<u8>,
        cursor: Vec<u8>,
    ) -> Vec<u8> {
        for key in &keys {
            vos_sdk::host::put(key, &[1]);
        }
        let mut out = [0u8; 1024];
        let written = vos_sdk::host::scan(&prefix, &cursor, &mut out) as usize;
        out.get(..written).unwrap_or_default().to_vec()
    }

    /// Its arguments back: a reply as large as a request.
    #[msg]
    pub async fn echo(&self, bytes: Vec<u8>) -> Vec<u8> {
        bytes
    }

    /// A query that writes through the raw ABI: the agent traps it.
    #[msg]
    pub async fn sneaky(&self) -> u64 {
        vos_sdk::host::put(&[9], &[1]);
        self.value
    }

    /// The result of an operation id the agent does not serve.
    #[msg]
    pub async fn unserved(&self) -> u64 {
        unserved_call()
    }

    /// Store `rows` rows of `size` bytes: past the step's write cap, the
    /// step fails. Writing that much takes more than the default gas.
    #[msg(gas = 50_000_000)]
    pub async fn fill(&mut self, rows: u32, size: u32) -> u32 {
        for row in 0..rows {
            self.blobs.insert(&row, &alloc::vec![7u8; size as usize]);
        }
        rows
    }

    /// Send `count` messages to agent 5's instance 1.
    #[msg]
    pub async fn spam(&mut self, ctx: &mut Command<Self>, count: u32) -> u32 {
        for _ in 0..count {
            ctx.send(
                AgentId(5),
                Ref::<Counter>::new(InstanceId(1)),
                counter::Value {},
            );
        }
        count
    }

    /// Phases of operations, to measure what serving them costs at a
    /// handler's limit. A phase `(kind, start, count)` is `count` operations
    /// of one kind on keys `start..start + count`: 0 an unserved id, 1 `now`, 2 `get`, 3 `put` of one byte,
    /// 4 a 64-byte `scan` from the start of those keys, 5 a `send`, 6 a
    /// `call` of `method` on `instance`, 7 a `put` of 4 KiB, 8 `random`, 9
    /// `caller`, 10 `log`, 11 `delete`, 12 `self_id`, 13 `input`, 14 `get`
    /// of a 1 KiB key, 15 `put` of one byte at a 1 KiB key.
    #[msg(gas = 100_000_000)]
    pub async fn ops(
        &mut self,
        ctx: &mut Command<Self>,
        phases: Vec<(u8, u32, u32)>,
        instance: u32,
        method: u32,
    ) -> u64 {
        let mut total = 0;
        let mut rows = [0u8; 64];
        let mut long = [8u8; 1024];
        for (kind, start, count) in phases {
            for index in start..start + count {
                let [_, a, b, c] = index.to_be_bytes();
                let short = [3, a, b, c];
                long[1..5].copy_from_slice(&index.to_be_bytes());
                total += match kind {
                    0 => unserved_call(),
                    1 => ctx.now(),
                    2 => u64::from(vos_sdk::host::get(&short).is_some()),
                    3 => {
                        vos_sdk::host::put(&short, &[1]);
                        0
                    }
                    4 => vos_sdk::host::scan(&[3], &[], &mut rows),
                    5 => {
                        vos_sdk::host::send(5, 1, method, &[]);
                        0
                    }
                    6 => vos_sdk::host::call(instance, method, &[]).map_or(1, |_| 0),
                    7 => {
                        vos_sdk::host::put(&short, &[9u8; 4096]);
                        0
                    }
                    8 => u64::from(ctx.random()[0]),
                    9 => vos_sdk::host::caller().len() as u64,
                    10 => {
                        vos_sdk::host::log(0, b"measuring");
                        0
                    }
                    11 => {
                        vos_sdk::host::delete(&short);
                        0
                    }
                    12 => u64::from(vos_sdk::host::self_id().0),
                    13 => vos_sdk::host::input().len() as u64,
                    14 => u64::from(vos_sdk::host::get(&long).is_some()),
                    _ => {
                        vos_sdk::host::put(&long, &[1]);
                        0
                    }
                };
            }
        }
        total
    }

    /// Set the counter to the batch time, and return a random draw.
    #[msg]
    pub async fn stamp(&mut self, ctx: &mut Command<Self>) -> [u8; 32] {
        self.value = ctx.now();
        ctx.random()
    }
}
