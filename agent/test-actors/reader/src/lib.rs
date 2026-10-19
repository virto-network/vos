//! Reads at a window's cut: committed maps a workflow reads at its window's
//! cut through attestable `&self` methods, whose kernels check the served
//! rows against the space's root; and the public arguments' forms, a
//! venue's, the reader's and `#[public]` arguments', in order.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

#[actor]
pub struct Reader {
    statements: u64,
    notes: Table<u32, u32>,
    /// Each noted read's end, by its tag: 0 served, else its error's code.
    outcomes: Table<u64, u32>,
    entries: CommittedMap<u64, u64>,
    names: CommittedMap<u32, Vec<u8>, Ordered>,
}

#[messages]
impl Reader {
    pub fn new() -> Self {
        Self {
            statements: 0,
            notes: Table::default(),
            outcomes: Table::default(),
            entries: CommittedMap::default(),
            names: CommittedMap::default(),
        }
    }

    /// Put or, with no value, delete each entry.
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

    /// Put or, with none, delete a name.
    #[msg]
    pub async fn set_name(&mut self, key: u32, name: Option<Vec<u8>>) {
        match name {
            Some(name) => self.names.insert(&key, &name),
            None => self.names.remove(&key),
        }
    }

    /// The entries under `keys` at the cut of the window it asks in,
    /// summed: read at the cut through `sum_entries`.
    #[workflow]
    pub async fn sum_at_cut(ctx: &mut Workflow<Self>, keys: Vec<u64>) -> Result<u64, AttestError> {
        let reads = keys.clone();
        ctx.attest_at_cut(reader::SumEntries { keys })
            .reads(|reader: &Reader| reads.iter().map(|key| reader.entries.read(key)).collect())
            .await
    }

    /// `sum_entries` of `keys` at the cut, its read naming the rows of
    /// `reads` alone.
    #[workflow]
    pub async fn sum_reading(
        ctx: &mut Workflow<Self>,
        keys: Vec<u64>,
        reads: Vec<u64>,
    ) -> Result<u64, AttestError> {
        ctx.attest_at_cut(reader::SumEntries { keys })
            .reads(|reader: &Reader| reads.iter().map(|key| reader.entries.read(key)).collect())
            .await
    }

    /// The name under `key` and the entries under `keys` at the cut, read
    /// through `named` for `venue`, with `nonce`.
    #[workflow]
    pub async fn name_at_cut(
        ctx: &mut Workflow<Self>,
        venue: VenueId,
        nonce: u64,
        key: u32,
        keys: Vec<u64>,
    ) -> Result<(Option<Vec<u8>>, u64), AttestError> {
        let reads = keys.clone();
        ctx.attest_at_cut(reader::Named {
            venue,
            nonce,
            key,
            keys,
        })
        .reads(|reader: &Reader| {
            let mut rows: Vec<_> = reads.iter().map(|key| reader.entries.read(key)).collect();
            rows.push(reader.names.read(&key));
            rows
        })
        .await
    }

    /// Two reads at the cuts of the windows they ask in, one after the
    /// other: each answer.
    #[workflow]
    pub async fn sum_twice(
        ctx: &mut Workflow<Self>,
        keys: Vec<u64>,
    ) -> Result<(u64, u64), AttestError> {
        let reads = keys.clone();
        let first = ctx
            .attest_at_cut(reader::SumEntries { keys: keys.clone() })
            .reads(|reader: &Reader| reads.iter().map(|key| reader.entries.read(key)).collect())
            .await?;
        let second = ctx
            .attest_at_cut(reader::SumEntries { keys })
            .reads(|reader: &Reader| reads.iter().map(|key| reader.entries.read(key)).collect())
            .await?;
        Ok((first, second))
    }

    /// `sum_entries` of `keys` at the cut, then, in the step its answer
    /// resumes, `count` plain attests through `attest_many`: the sum and
    /// their count.
    #[workflow]
    pub async fn sum_then_attest(
        ctx: &mut Workflow<Self>,
        keys: Vec<u64>,
        count: u32,
    ) -> Result<(u64, u32), AttestError> {
        let reads = keys.clone();
        let sum = ctx
            .attest_at_cut(reader::SumEntries { keys })
            .reads(|reader: &Reader| reads.iter().map(|key| reader.entries.read(key)).collect())
            .await?;
        let (_, me) = ctx.me();
        let made = ctx
            .call(Ref::<Reader>::new(me), reader::AttestMany { count })
            .await
            .unwrap_or_default();
        Ok((sum, made))
    }

    /// `count` attests of `ordered`: how many it made.
    #[msg(gas = 100_000_000)]
    pub async fn attest_many(&mut self, ctx: &mut Command<Self>, count: u32) -> u32 {
        for index in 0..count {
            ctx.attest(reader::Ordered {
                a: 1,
                b: 2,
                c: index,
            })
            .await
            .unwrap_or_default();
        }
        count
    }

    /// `sum_at_cut`, its end noted under `tag` in the reader's state,
    /// which outlives the workflow's record: 0 served, else its error's
    /// code, which it returns. It ends with it, so the note commits.
    #[workflow]
    pub async fn sum_noted(ctx: &mut Workflow<Self>, tag: u64, keys: Vec<u64>) -> u32 {
        let reads = keys.clone();
        let read = ctx
            .attest_at_cut(reader::SumEntries { keys })
            .reads(|reader: &Reader| reads.iter().map(|key| reader.entries.read(key)).collect())
            .await;
        let code = read.map_or_else(|error| error.code(), |_| 0);
        ctx.update(|reader: &mut Reader| reader.outcomes.insert(&tag, &code));
        code
    }

    /// `spin` of `key` for `rounds` at the cut, on a step limit of 2M.
    #[workflow(gas = 2_000_000)]
    pub async fn spin_at_cut(
        ctx: &mut Workflow<Self>,
        key: u64,
        rounds: u64,
    ) -> Result<u64, AttestError> {
        ctx.attest_at_cut(reader::Spin { key, rounds })
            .reads(|reader: &Reader| alloc::vec![reader.entries.read(&key)])
            .await
    }

    /// Attest `padded` `count` times, each `len` bytes: how many.
    #[msg(gas = 100_000_000)]
    pub async fn attest_padded(&mut self, ctx: &mut Command<Self>, count: u32, len: u32) -> u32 {
        for index in 0..count {
            ctx.attest(reader::Padded {
                tag: index as u8,
                len,
            })
            .await
            .unwrap_or_default();
        }
        count
    }

    /// Attest `stamped` and `ordered`: their outputs.
    #[msg]
    #[allow(clippy::too_many_arguments)]
    pub async fn attest_plain(
        &mut self,
        ctx: &mut Command<Self>,
        venue: VenueId,
        nonce: u64,
        secret: u64,
        a: u8,
        b: u16,
        c: u32,
    ) -> (u64, u32) {
        let stamped = ctx
            .attest(reader::Stamped {
                venue,
                nonce,
                secret,
            })
            .await
            .unwrap_or_default();
        let ordered = ctx
            .attest(reader::Ordered { a, b, c })
            .await
            .unwrap_or_default();
        self.statements += 1;
        (stamped, ordered)
    }

    /// The entries under `keys`, public, summed, absent ones counting
    /// nothing.
    #[attestable]
    pub fn sum_entries(&self, #[public] keys: Vec<u64>) -> u64 {
        keys.iter()
            .filter_map(|key| self.entries.get(key))
            .fold(0, u64::wrapping_add)
    }

    /// The name under `key` and the entries under `keys` summed, for a
    /// venue, with a public `nonce`.
    #[attestable(venue_bound)]
    pub fn named(&self, #[public] nonce: u64, key: u32, keys: Vec<u64>) -> (Option<Vec<u8>>, u64) {
        let _ = nonce;
        let sum = keys
            .iter()
            .filter_map(|key| self.entries.get(key))
            .fold(0, u64::wrapping_add);
        (self.names.get(&key), sum)
    }

    /// A rootless statement for a venue: `secret`'s square, its `nonce`
    /// public.
    #[attestable(venue_bound)]
    pub fn stamped(#[public] nonce: u64, secret: u64) -> u64 {
        let _ = nonce;
        secret.wrapping_mul(secret)
    }

    /// The entry under `key` mixed `rounds` times: as long a kernel as
    /// asked.
    #[attestable]
    pub fn spin(&self, key: u64, rounds: u64) -> u64 {
        let mut x = self.entries.get(&key).unwrap_or(0);
        for round in 0..rounds {
            x = core::hint::black_box(x.wrapping_mul(31).wrapping_add(round));
        }
        x
    }

    /// A rootless statement `len` bytes long, its tag public.
    #[attestable]
    pub fn padded(#[public] tag: u8, len: u32) -> Vec<u8> {
        alloc::vec![tag; len as usize]
    }

    /// A rootless statement of two public arguments around a private one.
    #[attestable]
    pub fn ordered(#[public] a: u8, b: u16, #[public] c: u32) -> u32 {
        u32::from(a) + u32::from(b) + c
    }
}
