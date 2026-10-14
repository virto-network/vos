//! A counter: struct state, queries, one linearizable, and a command that
//! can fail; a committed map; and probes of the agent's enforcement.

#![no_std]

extern crate alloc;

use vos_sdk::abi::Rows;
use vos_sdk::keys::Transform;
use vos_sdk::prelude::*;

/// The table the raw operations below reach.
const RAW: Rows = Rows::Table {
    tag: 3,
    transform: Transform::Hashed,
};

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
    entries: CommittedMap<u64, u64>,
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
            entries: CommittedMap::default(),
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

    /// The value, read after a read index whatever consistency the client
    /// asks.
    #[msg(linearizable)]
    pub async fn latest(&self) -> u64 {
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

    /// Write `keys` into the rows the register `rows` names, then scan them
    /// after `after`, any bytes the raw ABI allows, and return what the
    /// scan wrote.
    #[msg]
    pub async fn put_and_scan(
        &mut self,
        rows: u64,
        keys: Vec<Vec<u8>>,
        after: Option<Vec<u8>>,
    ) -> Vec<u8> {
        for key in &keys {
            vos_sdk::host::put_raw(rows, key, &[1]);
        }
        let mut out = [0u8; 1024];
        let written = vos_sdk::host::scan_raw(rows, after.as_deref(), &mut out) as usize;
        out.get(..written).unwrap_or_default().to_vec()
    }

    /// Store a value of `size` bytes under `key` in the rows the register
    /// `rows` names.
    #[msg(gas = 50_000_000)]
    pub async fn store(&mut self, rows: u64, key: Vec<u8>, size: u32) -> u32 {
        vos_sdk::host::put_raw(rows, &key, &alloc::vec![7u8; size as usize]);
        size
    }

    /// Scan the rows the register `rows` names after `after` into an output
    /// of `capacity` bytes: what the scan returned, and each row it wrote as
    /// its key, its value's length and its bytes' sum.
    #[msg(gas = 50_000_000)]
    pub async fn scan_rows(
        &self,
        rows: u64,
        after: Option<Vec<u8>>,
        capacity: u32,
    ) -> (u64, Vec<(Vec<u8>, u32, u64)>) {
        let mut out = alloc::vec![0u8; capacity as usize];
        let written = vos_sdk::host::scan_raw(rows, after.as_deref(), &mut out);
        let mut listed = Vec::new();
        let mut rest = out.get(..written as usize).unwrap_or_default();
        while let Ok(((key, value), used)) = <(Vec<u8>, Vec<u8>)>::decode(rest) {
            let sum = value.iter().map(|&byte| u64::from(byte)).sum();
            listed.push((key, value.len() as u32, sum));
            rest = &rest[used..];
        }
        (written, listed)
    }

    /// The keys of `blobs`, a hashed table, in its order.
    #[msg(gas = 50_000_000)]
    pub async fn blob_keys(&self) -> Vec<u32> {
        self.blobs.iter(None).map(|(key, _)| key).collect()
    }

    /// Put or, with no value, delete each entry of the committed map.
    #[msg(gas = 100_000_000)]
    pub async fn set_entries(&mut self, writes: Vec<(u64, Option<u64>)>) -> u64 {
        for (key, value) in &writes {
            match value {
                Some(value) => self.entries.insert(key, value),
                None => self.entries.remove(key),
            }
        }
        writes.len() as u64
    }

    #[msg]
    pub async fn entry(&self, key: u64) -> Option<u64> {
        self.entries.get(&key)
    }

    /// The committed map's entries in its order, after `after` when given.
    #[msg]
    pub async fn entries(&self, after: Option<u64>) -> Vec<(u64, u64)> {
        self.entries.iter(after.as_ref()).collect()
    }

    /// Its arguments back: a reply as large as a request.
    #[msg]
    pub async fn echo(&self, bytes: Vec<u8>) -> Vec<u8> {
        bytes
    }

    /// A reply of `len` bytes.
    #[msg]
    pub async fn large(&self, len: u32) -> Vec<u8> {
        alloc::vec![5u8; len as usize]
    }

    /// A query that writes through the raw ABI: the agent traps it.
    #[msg]
    pub async fn sneaky(&self) -> u64 {
        vos_sdk::host::put(RAW, &[9], &[1]);
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
    /// of one kind on keys `start..start + count` of a hashed table: 0 an
    /// unserved id, 1 `now`, 2 `get`, 3 `put` of one byte, 4 a 64-byte
    /// `scan` from the table's first row, 5 a `send`, 6 a `call` of
    /// `method` on `instance`, 7 a `put` of 4 KiB, 8 `random`, 9 `caller`,
    /// 10 `log`, 11 `delete`, 12 `self_id`, 13 `input`, 14 `get` of a 1 KiB
    /// key, 15 `put` of one byte at a 1 KiB key; and at 1 KiB keys of zero
    /// bytes but the index, 16 `get`, 17 `put` of one byte, and 18 a `scan`
    /// as large as a scan may be, from the table's first row; and 19 a
    /// BLAKE2b compression, a precompile call.
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
        let mut zeros = [0u8; 1024];
        let mut full = alloc::vec![0u8; vos_sdk::abi::cap::SCAN];
        let mut h = [1u8; 64];
        for (kind, start, count) in phases {
            for index in start..start + count {
                let [_, a, b, c] = index.to_be_bytes();
                let short = [3, a, b, c];
                long[1..5].copy_from_slice(&index.to_be_bytes());
                zeros[1..5].copy_from_slice(&index.to_be_bytes());
                total += match kind {
                    0 => unserved_call(),
                    1 => ctx.now(),
                    2 => u64::from(vos_sdk::host::get(RAW, &short).is_some()),
                    3 => {
                        vos_sdk::host::put(RAW, &short, &[1]);
                        0
                    }
                    4 => vos_sdk::host::scan(RAW, None, &mut rows),
                    5 => {
                        vos_sdk::host::send(5, 1, method, &[]);
                        0
                    }
                    6 => vos_sdk::host::call(instance, method, &[]).map_or(1, |_| 0),
                    7 => {
                        vos_sdk::host::put(RAW, &short, &[9u8; 4096]);
                        0
                    }
                    8 => u64::from(ctx.random()[0]),
                    9 => vos_sdk::host::caller().len() as u64,
                    10 => {
                        vos_sdk::host::log(0, b"measuring");
                        0
                    }
                    11 => {
                        vos_sdk::host::delete(RAW, &short);
                        0
                    }
                    12 => u64::from(vos_sdk::host::self_id().0),
                    13 => vos_sdk::host::input().len() as u64,
                    14 => u64::from(vos_sdk::host::get(RAW, &long).is_some()),
                    15 => {
                        vos_sdk::host::put(RAW, &long, &[1]);
                        0
                    }
                    16 => u64::from(vos_sdk::host::get(RAW, &zeros).is_some()),
                    17 => {
                        vos_sdk::host::put(RAW, &zeros, &[1]);
                        0
                    }
                    18 => vos_sdk::host::scan(RAW, None, &mut full),
                    _ => {
                        vos_pvm_precompiles::blake2b_compress(&mut h, &[2; 128], 128, false);
                        u64::from(h[0])
                    }
                };
            }
        }
        total
    }

    /// BLAKE2b-256 of `data`, then of the digest, `rounds` times in all:
    /// each compression a precompile call the agent serves.
    #[msg(gas = 50_000_000)]
    pub async fn hash(&self, data: Vec<u8>, rounds: u32) -> [u8; 32] {
        let mut digest = [0u8; 32];
        for round in 0..rounds {
            let input: &[u8] = if round == 0 { &data } else { &digest };
            digest = vos_pvm_precompiles::blake2b_hash::<32>(b"vos/test", &[input]);
        }
        digest
    }

    /// Set the counter to the batch time, and return a random draw.
    #[msg]
    pub async fn stamp(&mut self, ctx: &mut Command<Self>) -> [u8; 32] {
        self.value = ctx.now();
        ctx.random()
    }
}
