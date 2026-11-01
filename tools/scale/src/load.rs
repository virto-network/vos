//! The load model: `U` users, each a key derived from the seed and its
//! index (nothing stored), its account in one of `K` ledger shards by
//! hash. One rate drives everything: a share `a` of the users is active at
//! once, each making `r` calls a second while active, so the offered load
//! is `U·a·r`. Calls arrive open loop, as a Poisson process; who becomes
//! active is drawn Zipf(1.0) over the users, and an active user acts for
//! an exponentially distributed span, its session kept throughout. Each
//! call is one kind of the mix: a transfer (to a payee in another shard
//! with probability `x`), a query on a follower, a workflow, or a read at
//! a window's cut. Driver `d` of `D` runs the model on its users (those
//! whose index is `d` modulo `D`) at its share of the rate. Beside the mix,
//! a share of all the agents (the shards and the idle ones) read once at a
//! cut each window, at a uniform time within it; the first driver writes
//! the stand-in identity agent at a steady rate.

use std::collections::{HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::agents::Mix;

mod zipf;

pub use zipf::Zipf;

/// One kind of operation, each reported apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Transfer,
    Query,
    Workflow,
    Cut,
    /// A write to the stand-in identity agent: a steady stream beside the
    /// mix, outside its shares.
    Identity,
    /// An agent's read at its window's cut, by the readers' share: beside
    /// the mix, outside its shares.
    Reader,
}

impl Kind {
    /// The kinds the mix draws, in its order.
    pub const MIX: [Kind; 4] = [Kind::Transfer, Kind::Query, Kind::Workflow, Kind::Cut];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Transfer => "transfer",
            Kind::Query => "query",
            Kind::Workflow => "workflow",
            Kind::Cut => "cut",
            Kind::Identity => "identity",
            Kind::Reader => "reader",
        }
    }
}

/// The mix: each kind's share of the calls.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Shares {
    pub transfer: f64,
    pub query: f64,
    pub workflow: f64,
    pub cut: f64,
}

impl Default for Shares {
    fn default() -> Self {
        Self {
            transfer: 0.80,
            query: 0.15,
            workflow: 0.045,
            cut: 0.005,
        }
    }
}

impl Shares {
    pub fn of(&self, kind: Kind) -> f64 {
        match kind {
            Kind::Transfer => self.transfer,
            Kind::Query => self.query,
            Kind::Workflow => self.workflow,
            Kind::Cut => self.cut,
            Kind::Identity | Kind::Reader => 0.0,
        }
    }

    /// `transfer=0.8,query=0.15,workflow=0.045,cut=0.005`: every kind
    /// named once, the shares summing to 1.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut shares = [None; 4];
        for part in text.split(',') {
            let (name, value) = part
                .split_once('=')
                .ok_or_else(|| format!("{part:?}: kind=share"))?;
            let at = Kind::MIX
                .iter()
                .position(|kind| kind.name() == name.trim())
                .ok_or_else(|| format!("{name:?}: transfer, query, workflow or cut"))?;
            let value: f64 = value
                .trim()
                .parse()
                .map_err(|_| format!("{value:?}: a share"))?;
            if !(0.0..=1.0).contains(&value) || shares[at].replace(value).is_some() {
                return Err(format!("{part:?}: each kind once, a share in [0, 1]"));
            }
        }
        let [Some(transfer), Some(query), Some(workflow), Some(cut)] = shares else {
            return Err("the mix names transfer, query, workflow and cut".into());
        };
        let shares = Self {
            transfer,
            query,
            workflow,
            cut,
        };
        let sum: f64 = Kind::MIX.iter().map(|kind| shares.of(*kind)).sum();
        if (sum - 1.0).abs() > 1e-9 {
            return Err(format!("the mix's shares sum to {sum}, not 1"));
        }
        Ok(shares)
    }

    /// The kind a uniform draw `u` in [0, 1) picks.
    fn pick(&self, u: f64) -> Kind {
        let mut left = u;
        for kind in Kind::MIX {
            left -= self.of(kind);
            if left < 0.0 {
                return kind;
            }
        }
        Kind::Transfer
    }
}

/// The model's parameters: what every driver runs, each on its share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Model {
    /// `U`.
    pub users: u64,
    /// `a`: the share of users active at once.
    pub active: f64,
    /// `r`: calls a second an active user makes.
    pub per_user: f64,
    /// The mean span a user stays active, in seconds.
    pub active_s: f64,
    pub shares: Shares,
    /// `x`: the share of transfers whose payee is in another shard.
    pub cross: f64,
    /// The users' Zipf exponent.
    pub zipf: f64,
    /// Writes a second to the stand-in identity agent, by the first driver.
    pub identity_hz: f64,
    /// The share of all agents, shards and idle, that read at a cut once
    /// each window.
    #[serde(default)]
    pub readers: f64,
    pub seed: u64,
}

impl Model {
    /// The offered load, `U·a·r` calls a second.
    pub fn rate(&self) -> f64 {
        self.users as f64 * self.active * self.per_user
    }

    /// The share of transfers random payees give: `1 − 1/K`.
    pub fn random_cross(shards: usize) -> f64 {
        1.0 - 1.0 / shards.max(1) as f64
    }

    /// Whether the load reads at a cut: its mix's share or its readers'.
    pub fn reads_at_cuts(&self) -> bool {
        self.shares.cut > 0.0 || self.readers > 0.0
    }

    /// Refused when the load reads at a cut and the space has no
    /// representative: a read is served once the representative's close of
    /// its window applies, and without one no window closes, so every
    /// such read fails.
    pub fn check_representative(&self, representative: bool) -> Result<(), String> {
        if self.reads_at_cuts() && !representative {
            return Err(
                "the load reads at a cut (the mix's `cut` share or `--readers`), which \
                 the space's representative serves by closing each window, and the run has \
                 none: pass --representative, or a --mix with cut=0 and no --readers"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn validate(&self, shards: usize) -> Result<(), String> {
        if self.users == 0 || self.users > u64::from(u32::MAX) {
            return Err("users: from 1 to 2^32 - 1".into());
        }
        if !(self.active > 0.0 && self.active <= 1.0) {
            return Err("the active share: in (0, 1]".into());
        }
        if !(self.per_user > 0.0 && self.active_s > 0.0 && self.zipf > 0.0) {
            return Err("the rate a user, its active span and the Zipf exponent: positive".into());
        }
        if !(0.0..=1.0).contains(&self.cross) || (shards < 2 && self.cross > 0.0) {
            return Err("the cross-shard share: in [0, 1], and 0 with one shard".into());
        }
        if !(0.0..=1.0).contains(&self.readers) {
            return Err("the readers' share: in [0, 1]".into());
        }
        if shards == 0 {
            return Err("no ledger shards".into());
        }
        Ok(())
    }
}

/// User `index`'s key seed, and the hash that places its account.
pub fn user(seed: u64, index: u64) -> ([u8; 32], u64) {
    let mut input = b"vos-scale user".to_vec();
    input.extend(seed.to_le_bytes());
    input.extend(index.to_le_bytes());
    let digest = vos_pvm::precompile::blake2b_256(&input);
    let pick = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
    (digest, pick)
}

/// User `index`'s account id.
pub fn account(seed: u64, index: u64) -> [u8; 16] {
    let mut input = b"vos-scale account".to_vec();
    input.extend(seed.to_le_bytes());
    input.extend(index.to_le_bytes());
    vos_pvm::precompile::blake2b_256(&input)[..16]
        .try_into()
        .expect("16 bytes")
}

/// Every user's shard, by hash, and each shard's users.
pub struct Users {
    pub count: u64,
    pub shard_of: Vec<u16>,
    pub by_shard: Vec<Vec<u32>>,
}

impl Users {
    pub fn new(seed: u64, count: u64, shards: usize) -> Self {
        assert!(shards > 0 && shards <= usize::from(u16::MAX));
        let mut shard_of = Vec::with_capacity(count as usize);
        let mut by_shard = vec![Vec::new(); shards];
        for index in 0..count {
            let shard = (user(seed, index).1 % shards as u64) as usize;
            shard_of.push(shard as u16);
            by_shard[shard].push(index as u32);
        }
        Self {
            count,
            shard_of,
            by_shard,
        }
    }

    pub fn shard(&self, index: u64) -> usize {
        usize::from(self.shard_of[index as usize])
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Ranks to users: `(rank − 1)·step mod U`, `step` coprime to `U`, so the
/// hottest users are spread over the shards rather than by index.
fn stride(users: u64, seed: u64) -> u64 {
    if users <= 1 {
        return 1;
    }
    let mut step = (0x9e37_79b9_7f4a_7c15u64 ^ seed) % users;
    while step == 0 || gcd(step, users) != 1 {
        step = (step + 1) % users;
    }
    step
}

/// One planned operation, `t` seconds after the load's start.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Planned {
    pub t: f64,
    pub kind: Kind,
    pub user: u64,
    /// A transfer's payee, and whether its shard is another.
    pub payee: Option<(u64, bool)>,
    /// A reader's agent, among the shards then the idle agents.
    pub agent: Option<usize>,
}

/// The agents that may read, and the space's windows: each window a share
/// of them reads at a cut, at a uniform time within it.
#[derive(Clone, Copy, Debug)]
pub struct Readers {
    /// The shards and the idle agents.
    pub agents: usize,
    /// Window 0's start and each window's length, in ms since the epoch.
    pub origin_ms: u64,
    pub length_ms: u64,
    /// The load's start, in ms since the epoch.
    pub start_ms: u64,
}

/// An active user's slot: who holds it, and until when.
#[derive(Clone, Copy)]
struct Slot {
    user: u64,
    until: f64,
}

/// One driver's share of the model, as planned operations in time order.
pub struct Plan<'a> {
    model: &'a Model,
    users: &'a Users,
    driver: u64,
    drivers: u64,
    rate: f64,
    zipf: Zipf,
    step: u64,
    mix: Mix,
    slots: Vec<Option<Slot>>,
    active: HashSet<u64>,
    t: f64,
    /// The next identity write's time, for the first driver.
    identity_t: Option<f64>,
    identity_writes: u64,
    readers: Option<Readers>,
    /// The next window whose readers are drawn, and the reads drawn, in
    /// time order.
    reader_window: u64,
    reads: VecDeque<(f64, usize)>,
}

impl<'a> Plan<'a> {
    pub fn new(model: &'a Model, users: &'a Users, driver: u64, drivers: u64) -> Self {
        let drivers = drivers.max(1);
        let mine = users.count.div_ceil(drivers).max(1);
        let slots = ((model.active * users.count as f64 / drivers as f64).round() as u64)
            .clamp(1, mine) as usize;
        Self {
            model,
            users,
            driver,
            drivers,
            rate: model.rate() / drivers as f64,
            zipf: Zipf::new(users.count, model.zipf),
            step: stride(users.count, model.seed),
            mix: Mix(model.seed ^ (driver << 40) ^ 0x5ca1e),
            slots: vec![None; slots],
            active: HashSet::new(),
            t: 0.0,
            identity_t: (driver == 0 && model.identity_hz > 0.0).then_some(0.0),
            identity_writes: 0,
            readers: None,
            reader_window: 0,
            reads: VecDeque::new(),
        }
    }

    /// Read at a cut, by the readers' share of `readers.agents`, from the
    /// window the load starts in.
    pub fn with_readers(mut self, readers: Readers) -> Self {
        if self.model.readers > 0.0 && readers.length_ms > 0 && readers.agents > 0 {
            self.reader_window =
                readers.start_ms.saturating_sub(readers.origin_ms) / readers.length_ms;
            self.readers = Some(readers);
        }
        self
    }

    /// The window `w`'s reads in this driver's share: its agents drawn
    /// without replacement, each at a uniform time within the window, in
    /// seconds from the load's start.
    fn draw_reads(&mut self, readers: Readers, window: u64) {
        let count = (self.model.readers * readers.agents as f64).round() as usize;
        let mut mix = Mix(self.model.seed ^ window.rotate_left(17) ^ 0x7ead);
        let mut agents: Vec<usize> = (0..readers.agents).collect();
        let mut reads = Vec::new();
        for at in 0..count.min(readers.agents) {
            let pick = at + (mix.next() % (readers.agents - at) as u64) as usize;
            agents.swap(at, pick);
            let agent = agents[at];
            let start = readers.origin_ms + window * readers.length_ms;
            let when = start as f64 + mix.unit() * readers.length_ms as f64;
            let t = (when - readers.start_ms as f64) / 1e3;
            if agent as u64 % self.drivers == self.driver && t >= self.t {
                reads.push((t, agent));
            }
        }
        reads.sort_by(|a, b| a.0.total_cmp(&b.0));
        self.reads.extend(reads);
    }

    /// The next read's time, its window drawn once the plan reaches it.
    fn next_read(&mut self, before: f64) -> Option<(f64, usize)> {
        let readers = self.readers?;
        while self.reads.is_empty() {
            let start = readers.origin_ms + self.reader_window * readers.length_ms;
            if (start as f64 - readers.start_ms as f64) / 1e3 > before {
                return None;
            }
            let window = self.reader_window;
            self.reader_window += 1;
            self.draw_reads(readers, window);
        }
        self.reads.front().copied().filter(|(t, _)| *t <= before)
    }

    /// Fill every slot at the start: the users active then.
    pub fn fill(&mut self) -> Vec<u64> {
        for at in 0..self.slots.len() {
            if self.slots[at].is_none() {
                let user = self.draw_inactive();
                let until = self.exponential(self.model.active_s);
                self.active.insert(user);
                self.slots[at] = Some(Slot { user, until });
            }
        }
        self.slots.iter().flatten().map(|slot| slot.user).collect()
    }

    /// The users active at once in this driver's share.
    pub fn slots(&self) -> usize {
        self.slots.len()
    }

    /// A user of this driver's share, drawn Zipf by rank.
    fn draw_user(&mut self) -> u64 {
        loop {
            let rank = self.zipf.sample(&mut self.mix);
            let index = ((u128::from(rank - 1) * u128::from(self.step))
                % u128::from(self.users.count)) as u64;
            if index % self.drivers == self.driver {
                return index;
            }
        }
    }

    /// A user not active now, drawn Zipf; after a few tries, any.
    fn draw_inactive(&mut self) -> u64 {
        let mut user = self.draw_user();
        for _ in 0..64 {
            if !self.active.contains(&user) {
                break;
            }
            user = self.draw_user();
        }
        user
    }

    fn exponential(&mut self, mean: f64) -> f64 {
        -(1.0 - self.mix.unit()).ln() * mean
    }

    /// The user acting now: a slot drawn uniformly, its user replaced once
    /// its span ended.
    fn actor(&mut self) -> u64 {
        let at = (self.mix.next() % self.slots.len() as u64) as usize;
        match self.slots[at] {
            Some(slot) if slot.until > self.t => slot.user,
            held => {
                if let Some(slot) = held {
                    self.active.remove(&slot.user);
                }
                let user = self.draw_inactive();
                let until = self.t + self.exponential(self.model.active_s);
                self.active.insert(user);
                self.slots[at] = Some(Slot { user, until });
                user
            }
        }
    }

    /// A payee for `user`'s transfer: in another shard with probability
    /// `x`, else in its own; uniform among that shard's users.
    fn payee(&mut self, user: u64) -> (u64, bool) {
        let shards = self.users.by_shard.len();
        let home = self.users.shard(user);
        let cross = shards > 1 && self.mix.unit() < self.model.cross;
        let shard = if cross {
            let other = (self.mix.next() % (shards as u64 - 1)) as usize;
            if other >= home { other + 1 } else { other }
        } else {
            home
        };
        let candidates = &self.users.by_shard[shard];
        if candidates.is_empty() {
            return (user, false);
        }
        let payee = u64::from(candidates[(self.mix.next() % candidates.len() as u64) as usize]);
        (payee, cross)
    }
}

impl Iterator for Plan<'_> {
    type Item = Planned;

    fn next(&mut self) -> Option<Planned> {
        let gap = self.exponential(1.0 / self.rate);
        let next = self.t + gap;
        let identity = self.identity_t.unwrap_or(f64::INFINITY);
        if let Some((at, agent)) = self.next_read(next.min(identity)) {
            self.reads.pop_front();
            // The draw just made is spent: arrivals are memoryless.
            self.t = self.t.max(at);
            return Some(Planned {
                t: at,
                kind: Kind::Reader,
                user: agent as u64 % self.users.count,
                payee: None,
                agent: Some(agent),
            });
        }
        if let Some(at) = self.identity_t
            && at <= next
        {
            self.identity_writes += 1;
            self.identity_t = Some(self.identity_writes as f64 / self.model.identity_hz);
            // The draw just made is spent: arrivals are memoryless.
            self.t = self.t.max(at);
            return Some(Planned {
                t: at,
                kind: Kind::Identity,
                user: self.identity_writes % self.users.count,
                payee: None,
                agent: None,
            });
        }
        self.t = next;
        let user = self.actor();
        let kind = self.model.shares.pick(self.mix.unit());
        let payee = (kind == Kind::Transfer).then(|| self.payee(user));
        Some(Planned {
            t: self.t,
            kind,
            user,
            payee,
            agent: None,
        })
    }
}

#[cfg(test)]
mod tests;
