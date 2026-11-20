//! `Homes`, the home's actor (`light-node.md` §3.3): the pool of personal
//! agents and the claims that take them.
//!
//! - **Beside the credential actor:** an auth guard reads the ring of the
//!   agent it guards, so `Homes` is installed in the agent holding the
//!   home's credential actor. A claim and a re-proof are proven calls
//!   under `Auth("home")`; the caller's nullifier in that scope is its
//!   pseudonym here.
//! - **The pool:** the keeper creates agents with `Personal` installed,
//!   grants this agent `Personal`'s role `homes` in each, and hands their
//!   ids over with `stock`, an operator's call.
//! - **The claim:** a nullifier holds one agent, and a kit's key indexes
//!   one. The claiming device names the pooled agent it sealed its kit's
//!   `R1` to: a kit's seal binds the agent's identity, which the device
//!   learns of the agent [`Homes::pooled`] answers. `Homes` takes it,
//!   indexes it under the nullifier and under each kit entry's
//!   [`kit_index`], and sends it the claim with the home's policy. A send
//!   is one-way, so `Personal` answers `assigned` or `refused`; a refused
//!   claim's indexes are dropped and its agent pooled again. A claim still
//!   waiting for its answer is sent again when its nullifier claims again,
//!   and the operator may `release` one that never will be answered.
//! - **The lease:** `Personal` keeps it; any device whose nullifier is
//!   recorded here (the claiming one's at the claim, the others' as their
//!   adds are confirmed, `record`, until their removals mature, `forget`)
//!   renews it with `renew`, a re-proof.
//!
//! The actor's state is its tables and cells, so a later version adds
//! tables beside these.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use vos_personal::Personal;
use vos_personal::personal::{Claim, Renew};
use vos_sdk::prelude::*;
use vos_wire::homes::{AgentsPage, Counts, HomesError, PAGE, Standing, Terms};
use vos_wire::personal::{Kit, NewDevice, PersonalError, kit_index};

/// The most recovery entries a claim's kit brings, as `Personal` takes.
const KIT_ENTRIES: usize = vos_personal::KIT_ENTRIES;

/// A pool agent's row: its standing, the nullifier of the claim that took
/// it, and the indexes its kit holds.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Held {
    pub standing: Standing,
    pub nullifier: Option<[u8; 32]>,
    pub kit: Vec<[u8; 32]>,
}

#[actor]
pub struct Homes {
    /// Every agent stocked, by its id.
    agents: Table<u32, Held, Ordered>,
    /// The agents pooled, lowest first.
    pool: Table<u32, (), Ordered>,
    /// Each recorded nullifier's agent.
    nullifiers: Table<[u8; 32], u32>,
    /// Each kit entry's index's agent.
    kits: Table<[u8; 32], u32>,
    terms: Cell<Terms>,
    counts: Cell<Counts>,
}

#[messages]
impl Homes {
    // ===== The operator's =====

    /// Set where `Personal` is in the pool's agents, and the policy each
    /// is configured with before its claim.
    #[msg(role = "operator")]
    pub async fn configure(&mut self, terms: Terms) {
        self.terms.set(&terms);
    }

    /// Pool `agents`, each made by the keeper with `Personal` installed and
    /// this agent granted its role `homes`: the pooled count after. An
    /// agent stocked already is left as it is, so a keeper that lost the
    /// answer stocks the page again. 200 agents take 34.1M gas (the
    /// testkit's agent suite; gas is deterministic), so a page fits the 50M
    /// declared.
    #[msg(role = "operator", gas = 50_000_000)]
    pub async fn stock(&mut self, agents: Vec<u32>) -> Result<u32, HomesError> {
        if agents.len() > PAGE {
            return Err(HomesError::TooMany);
        }
        let fresh: BTreeSet<u32> = agents
            .into_iter()
            .filter(|agent| !self.agents.contains(agent))
            .collect();
        let held = Held {
            standing: Standing::Pooled,
            nullifier: None,
            kit: Vec::new(),
        };
        for agent in &fresh {
            self.agents.insert(agent, &held);
            self.pool.insert(agent, &());
        }
        let mut counts = self.counts.get_or_default();
        counts.pooled += fresh.len() as u32;
        self.counts.set(&counts);
        Ok(counts.pooled)
    }

    /// Release `agent`, sent a claim its `Personal` never answered (its
    /// role not granted, say): the claim's indexes dropped and the agent
    /// retired, never pooled again.
    #[msg(role = "operator")]
    pub async fn release(&mut self, agent: u32) -> Result<(), HomesError> {
        let held = self.agents.get(&agent).ok_or(HomesError::Unknown)?;
        if held.standing != Standing::Claimed {
            return Err(HomesError::Unknown);
        }
        self.drop_claim(agent, &held, Standing::Retired);
        Ok(())
    }

    // ===== Devices' =====

    /// Claim `agent`, a pooled agent, for `device`, the claiming device,
    /// with `kit`, whose `R1` is sealed to `agent`'s identity: its id. The
    /// device's nullifier must be the proof's; a nullifier holding an
    /// agent, or a kit entry indexing one, is refused, and so are keys
    /// `Personal` would refuse (one key twice); an agent another claim
    /// took is `Taken`, and the device seals its kit to the next. The same
    /// claim again while its answer is awaited is sent again.
    #[msg(credential = Auth("home"))]
    pub async fn claim(
        &mut self,
        ctx: &mut Command<Self>,
        device: NewDevice,
        kit: Kit,
        agent: u32,
    ) -> Result<u32, HomesError> {
        let nullifier = ctx.nullifier().ok_or(HomesError::Anonymous)?;
        let terms = self.terms.get().ok_or(HomesError::Unconfigured)?;
        if device.nullifier != nullifier {
            return Err(HomesError::Nullifier);
        }
        if kit.entries.len() > KIT_ENTRIES {
            return Err(HomesError::Malformed);
        }
        let mut keys = BTreeSet::from([device.sync, device.admin]);
        if keys.len() != 2 || !kit.entries.iter().all(|entry| keys.insert(entry.signing)) {
            return Err(HomesError::Malformed);
        }
        let indexes: Vec<[u8; 32]> = kit
            .entries
            .iter()
            .map(|entry| kit_index(&entry.signing))
            .collect();
        let (_, me) = ctx.me();
        let personal = Ref::<Personal>::new(InstanceId(terms.instance));
        let claim = Claim {
            device,
            kit,
            policy: terms.policy,
            homes: me.0,
        };
        if let Some(held_by) = self.nullifiers.get(&nullifier) {
            return match self.agents.get(&held_by) {
                Some(held)
                    if held_by == agent
                        && held.standing == Standing::Claimed
                        && held.kit == indexes =>
                {
                    ctx.send(AgentId(agent), personal, claim);
                    Ok(agent)
                }
                _ => Err(HomesError::Claimed),
            };
        }
        if indexes.iter().any(|index| self.kits.contains(index)) {
            return Err(HomesError::KitTaken);
        }
        if !self.pool.contains(&agent) {
            return Err(if self.pool.first().is_some() {
                HomesError::Taken
            } else {
                HomesError::PoolEmpty
            });
        }
        self.pool.remove(&agent);
        self.nullifiers.insert(&nullifier, &agent);
        for index in &indexes {
            self.kits.insert(index, &agent);
        }
        self.agents.insert(
            &agent,
            &Held {
                standing: Standing::Claimed,
                nullifier: Some(nullifier),
                kit: indexes,
            },
        );
        let mut counts = self.counts.get_or_default();
        counts.pooled -= 1;
        counts.claimed += 1;
        self.counts.set(&counts);
        ctx.send(AgentId(agent), personal, claim);
        Ok(agent)
    }

    /// A re-proof by a device whose nullifier is recorded for `agent`: its
    /// lease runs on from now.
    #[msg(credential = Auth("home"))]
    pub async fn renew(&mut self, ctx: &mut Command<Self>, agent: u32) -> Result<(), HomesError> {
        let nullifier = ctx.nullifier().ok_or(HomesError::Anonymous)?;
        let terms = self.terms.get().ok_or(HomesError::Unconfigured)?;
        if self.nullifiers.get(&nullifier) != Some(agent) {
            return Err(HomesError::NotRecorded);
        }
        match self.agents.get(&agent).map(|held| held.standing) {
            Some(Standing::Assigned) => {}
            _ => return Err(HomesError::Unknown),
        }
        ctx.send(
            AgentId(agent),
            Ref::<Personal>::new(InstanceId(terms.instance)),
            Renew {},
        );
        Ok(())
    }

    // ===== The pool's agents' =====

    /// `Personal` took the claim.
    #[msg]
    pub async fn assigned(&mut self, ctx: &mut Command<Self>) -> Result<(), HomesError> {
        let (agent, mut held) = self.claimed_by(ctx.caller())?;
        held.standing = Standing::Assigned;
        self.agents.insert(&agent, &held);
        let mut counts = self.counts.get_or_default();
        counts.claimed -= 1;
        counts.assigned += 1;
        self.counts.set(&counts);
        Ok(())
    }

    /// `Personal` refused the claim: its indexes dropped, and the agent
    /// pooled again unless it was assigned already.
    #[msg]
    pub async fn refused(
        &mut self,
        ctx: &mut Command<Self>,
        error: PersonalError,
    ) -> Result<(), HomesError> {
        let (agent, held) = self.claimed_by(ctx.caller())?;
        let standing = if error == PersonalError::Assigned {
            Standing::Retired
        } else {
            Standing::Pooled
        };
        self.drop_claim(agent, &held, standing);
        Ok(())
    }

    /// A device of the calling agent whose add was confirmed: its
    /// nullifier recorded for the agent's re-proofs, unless another agent
    /// holds it.
    #[msg]
    pub async fn record(
        &mut self,
        ctx: &mut Command<Self>,
        nullifier: [u8; 32],
    ) -> Result<(), HomesError> {
        let agent = self.assigned_caller(ctx.caller())?;
        match self.nullifiers.get(&nullifier) {
            Some(holder) if holder == agent => Ok(()),
            Some(_) => Err(HomesError::Claimed),
            None => {
                self.nullifiers.insert(&nullifier, &agent);
                Ok(())
            }
        }
    }

    /// A device of the calling agent whose removal matured: its nullifier
    /// re-proves the agent no more.
    #[msg]
    pub async fn forget(
        &mut self,
        ctx: &mut Command<Self>,
        nullifier: [u8; 32],
    ) -> Result<(), HomesError> {
        let agent = self.assigned_caller(ctx.caller())?;
        if self.nullifiers.get(&nullifier) == Some(agent) {
            self.nullifiers.remove(&nullifier);
        }
        Ok(())
    }

    /// The calling agent's kit after a rotation or a restore: its signing
    /// keys, indexed in place of the kit's before. A key indexing another
    /// agent is not taken.
    #[msg]
    pub async fn rekey(
        &mut self,
        ctx: &mut Command<Self>,
        keys: Vec<[u8; 32]>,
    ) -> Result<(), HomesError> {
        let agent = self.assigned_caller(ctx.caller())?;
        let mut held = self.agents.get(&agent).ok_or(HomesError::Unknown)?;
        for index in &held.kit {
            self.kits.remove(index);
        }
        held.kit = Vec::new();
        for key in keys.iter().take(KIT_ENTRIES) {
            let index = kit_index(key);
            if !self.kits.contains(&index) {
                self.kits.insert(&index, &agent);
                held.kit.push(index);
            }
        }
        self.agents.insert(&agent, &held);
        Ok(())
    }

    // ===== Reads =====

    /// The lowest pooled agent: the one a claiming device seals its kit
    /// to, learning its identity from the node; `None` once the pool is
    /// empty.
    #[msg]
    pub async fn pooled(&self) -> Option<u32> {
        self.pool.first().map(|(agent, ())| agent)
    }

    /// The agent `nullifier` is recorded for.
    #[msg]
    pub async fn agent(&self, nullifier: [u8; 32]) -> Option<u32> {
        self.nullifiers.get(&nullifier)
    }

    /// The agent a kit entry's index names: a restore's lookup.
    #[msg]
    pub async fn find(&self, index: [u8; 32]) -> Option<u32> {
        self.kits.get(&index)
    }

    /// `agent`'s standing.
    #[msg]
    pub async fn standing_of(&self, agent: u32) -> Option<Standing> {
        self.agents.get(&agent).map(|held| held.standing)
    }

    /// The pool's agents pooled, sent and assigned.
    #[msg]
    pub async fn tally(&self) -> Counts {
        self.counts.get_or_default()
    }

    /// The stocked agents by id, from after `after`, [`PAGE`] at most: the
    /// keeper's upgrade walks them.
    #[msg]
    pub async fn agents(&self, after: Option<u32>) -> AgentsPage {
        let mut rows = self.agents.iter(after.as_ref());
        let agents: Vec<(u32, Standing)> = rows
            .by_ref()
            .take(PAGE)
            .map(|(agent, held)| (agent, held.standing))
            .collect();
        let more = rows.next().is_some();
        AgentsPage { agents, more }
    }

    /// The terms `configure` set.
    #[msg]
    pub async fn configured(&self) -> Option<Terms> {
        self.terms.get()
    }
}

impl Homes {
    /// `agent`'s claim dropped: its nullifier and kit indexes, the agent
    /// left `standing`, pooled again when that is `Pooled`.
    fn drop_claim(&mut self, agent: u32, held: &Held, standing: Standing) {
        if let Some(nullifier) = held.nullifier {
            self.nullifiers.remove(&nullifier);
        }
        for index in &held.kit {
            self.kits.remove(index);
        }
        let mut counts = self.counts.get_or_default();
        counts.claimed -= 1;
        if standing == Standing::Pooled {
            self.pool.insert(&agent, &());
            counts.pooled += 1;
        }
        self.counts.set(&counts);
        self.agents.insert(
            &agent,
            &Held {
                standing,
                nullifier: None,
                kit: Vec::new(),
            },
        );
    }

    /// The calling agent's row, while a claim it was sent waits for its
    /// answer.
    fn claimed_by(&self, caller: Principal) -> Result<(u32, Held), HomesError> {
        let Principal::Agent(AgentId(agent)) = caller else {
            return Err(HomesError::Unknown);
        };
        match self.agents.get(&agent) {
            Some(held) if held.standing == Standing::Claimed => Ok((agent, held)),
            _ => Err(HomesError::Unknown),
        }
    }

    /// The calling agent, assigned.
    fn assigned_caller(&self, caller: Principal) -> Result<u32, HomesError> {
        let Principal::Agent(AgentId(agent)) = caller else {
            return Err(HomesError::Unknown);
        };
        match self.agents.get(&agent).map(|held| held.standing) {
            Some(Standing::Assigned) => Ok(agent),
            _ => Err(HomesError::Unknown),
        }
    }
}
