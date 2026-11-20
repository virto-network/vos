//! The home (`light-node.md` §3.3): its open claim's work, a device's
//! nullifier in its scope, the scope reserved, and the claim of a personal
//! agent.
//!
//! - **The open claim:** a home-only space admits anyone whose work meets
//!   its registrar's difficulty under the period's salt ([`work`], over
//!   the registrar's answer [`vos_wire::credentials::Open`]): a call of
//!   `claim_open(member, nonce)` in a session of its own
//!   ([`open_claim`]), made by the device that claims the agent.
//! - **The claim** ([`Claim`]): of the agent `Homes` answers `pooled` for,
//!   the kit's `R1` sealed to that agent's identity, proved in the scope
//!   "home". It is held in the store from before its call until the
//!   device's group starts from the agent's log ([`Claim::claimed`]), so
//!   a retry after a lost answer sends the same claim. A device that
//!   already holds a personal space's archive (its group, or a restore's)
//!   claims nothing ([`ClaimError::Held`]): a second device pairs.
//! - **The scope "home"** ([`SCOPE`]) is reserved: [`Prover::prove_auth`]
//!   refuses it, and [`Prover::prove_home`] proves in it only a claim of
//!   `Homes`, so no other call can be linked to the device's pseudonym
//!   there. A device's own nullifier in it, which its add
//!   records, is computed without a proof ([`nullifier`]).

use std::sync::atomic::{AtomicU64, Ordering};

use vos_abi::credentials::Digest as Bytes;
use vos_abi::ids::{InstanceId, MethodId};
use vos_abi::{Decode, Encode};
use vos_wire::credentials::{meets, open_work};
use vos_wire::homes;
use vos_wire::personal::{Body, Entry, Kit, NewDevice};
use zeroize::Zeroize;

pub use vos_wire::homes::SCOPE;

use crate::group::{Agent, DeviceGroup, GroupError};
use crate::kit::{KitKey, Split};
use crate::store::{Change, Store, StoreError};
use crate::{AuthWitness, Call, DeviceError, DeviceProgram, DeviceSecret, Proven, Prover};
use crate::{call, secret};

/// The claim's row in the group keyspace, from its preparation until the
/// device's group starts.
const CLAIM_ROW: &[u8] = b"c/claim";

/// A home as a device reaches it: its space, its stable handle, the agent
/// holding its credential actor and `Homes` with the identity calls to it
/// are signed for, and their instances. `Homes`' agent and instance are
/// the scope of every "home" nullifier.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Home {
    pub space: [u8; 32],
    pub handle: [u8; 32],
    pub agent: u32,
    pub identity: [u8; 32],
    pub homes: InstanceId,
    pub credentials: InstanceId,
}

impl Home {
    /// The nullifier of the device whose secret in this home is `secret`.
    pub fn nullifier(&self, secret: &DeviceSecret) -> [u8; 32] {
        nullifier(secret, &self.space, self.agent, self.homes.0)
    }

    fn call(
        &self,
        method: MethodId,
        arguments: Vec<u8>,
        expires_ms: u64,
    ) -> Result<Call, DeviceError> {
        Call::new(
            self.space,
            self.agent,
            self.homes.0,
            method.0,
            arguments,
            expires_ms,
        )
    }
}

/// The open claim of `member` at `home` by the work `nonce` ([`work`]), a
/// call in a session of its own at the node's time `now`: the request to
/// send, whose answer is the member's slot or the registrar's refusal
/// (`Work` past two periods: ask the terms again; `Cap`: try another day).
pub fn open_claim(
    home: &Home,
    member: &Bytes,
    nonce: u64,
    now: u64,
) -> Result<Vec<u8>, DeviceError> {
    crate::wire::call_request(
        home.agent,
        &home.identity,
        home.credentials.0,
        vos_wire::credentials::method::CLAIM_OPEN,
        (*member, nonce).encode(),
        now,
    )
}

/// Why a claim cannot go on.
#[derive(Debug)]
pub enum ClaimError {
    /// The store holds a personal space's archive already, or a claim
    /// waits: a device of a personal space pairs, it claims no second.
    Held,
    /// No kit key, or one no agreement is contributory with, or no
    /// randomness.
    Kit,
    /// The agent's log holds no assignment of this claim's device and
    /// kit: not yet assigned, or another claim's.
    Unassigned,
    Store(StoreError),
    Group(GroupError),
    Corrupt,
}

impl From<StoreError> for ClaimError {
    fn from(error: StoreError) -> Self {
        ClaimError::Store(error)
    }
}

impl From<GroupError> for ClaimError {
    fn from(error: GroupError) -> Self {
        ClaimError::Group(error)
    }
}

impl std::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimError::Held => f.write_str("the device holds a personal space already"),
            ClaimError::Kit => f.write_str("the kit's keys do not seal"),
            ClaimError::Unassigned => {
                f.write_str("the agent's log holds no assignment of this claim")
            }
            ClaimError::Store(error) => error.fmt(f),
            ClaimError::Group(error) => error.fmt(f),
            ClaimError::Corrupt => f.write_str("the claim's row does not read"),
        }
    }
}

impl std::error::Error for ClaimError {}

/// Whether `store` holds a personal space's archive: a device group, a
/// restore's drawn `R`, or keys of an earlier group. Such a device claims
/// no agent ([`ClaimError::Held`]).
pub fn holds_archive(store: &Store) -> Result<bool, StoreError> {
    if crate::group::grouped(store)? {
        return Ok(true);
    }
    let archive = store.archive()?;
    Ok(archive.recovery.is_some()
        || !archive.drawn.is_empty()
        || !archive.keys.is_empty()
        || !archive.previous.is_empty())
}

#[derive(Encode, Decode)]
struct Held {
    device: NewDevice,
    keys: Vec<KitKey>,
    kit: Kit,
    r: [u8; 32],
    agent: u32,
    identity: [u8; 32],
}

/// A claim of a personal agent, held in the store from before its call
/// until the device's group starts. Its `Debug` shows no `R` or `R2`.
pub struct Claim(Held);

impl Drop for Claim {
    fn drop(&mut self) {
        self.0.r.zeroize();
        self.0.kit.r2.zeroize();
    }
}

impl std::fmt::Debug for Claim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claim")
            .field("agent", &self.0.agent)
            .finish_non_exhaustive()
    }
}

impl Claim {
    /// The claim of the pooled `agent`, whose identity is `identity`, for
    /// `device` with the kit of `keys` (a phrase's, a security key's, or
    /// both): `R` split, `R1` sealed to each key at that agent, held in the
    /// store before this returns, with `rows` of the group keyspace written
    /// in the same batch: what the claim makes the device's beside it.
    /// Refused for a store that holds a personal space's archive or a claim
    /// already.
    pub fn prepare(
        store: &Store,
        device: NewDevice,
        keys: Vec<KitKey>,
        agent: u32,
        identity: [u8; 32],
        rows: Vec<Change>,
    ) -> Result<Self, ClaimError> {
        if holds_archive(store)? || store.group_row(CLAIM_ROW)?.is_some() {
            return Err(ClaimError::Held);
        }
        let split = Split::draw(&keys, &identity).ok_or(ClaimError::Kit)?;
        let claim = Claim(Held {
            device,
            kit: split.claim(),
            keys,
            r: *split.r(),
            agent,
            identity,
        });
        let mut writes = vec![(CLAIM_ROW.to_vec(), Some(claim.0.encode()))];
        writes.extend(rows);
        store.write_group_rows(writes)?;
        Ok(claim)
    }

    /// The claim held in `store`, if one waits: made again as it was.
    pub fn pending(store: &Store) -> Result<Option<Self>, ClaimError> {
        let Some(mut row) = store.group_row(CLAIM_ROW)? else {
            return Ok(None);
        };
        let held = Held::decode_exact(&row).ok_or(ClaimError::Corrupt);
        row.zeroize();
        Ok(Some(Claim(held?)))
    }

    /// The agent claimed, and its identity.
    pub fn agent(&self) -> (u32, [u8; 32]) {
        (self.0.agent, self.0.identity)
    }

    /// `Homes`' `claim(device, kit, agent)` at `home`, to prove in the
    /// scope "home" ([`Prover::prove_home`]) with this device's secret
    /// there. Its answer is the agent's id: then [`Claim::claimed`] once
    /// the agent's log shows it. `Claimed` for this held claim means an
    /// answer was lost and the agent may be assigned already: read its
    /// log and call [`Claim::claimed`], never [`Claim::abandon`].
    pub fn call(&self, home: &Home, expires_ms: u64) -> Result<Call, DeviceError> {
        let mut arguments = self.0.device.encode();
        self.0.kit.encode_to(&mut arguments);
        self.0.agent.encode_to(&mut arguments);
        let call = home.call(homes::method::CLAIM, arguments.clone(), expires_ms);
        arguments.zeroize();
        call
    }

    /// Drop the claim `Homes` refused (`Taken`, `PoolEmpty`, `KitTaken`):
    /// the device prepares another, at the agent `pooled` answers then;
    /// after `KitTaken`, with another kit, since the same key indexes the
    /// same agent again. `rows` are written in the same batch.
    pub fn abandon(self, store: &Store, rows: Vec<Change>) -> Result<(), ClaimError> {
        let mut writes = vec![(CLAIM_ROW.to_vec(), None)];
        writes.extend(rows);
        store.write_group_rows(writes)?;
        Ok(())
    }

    /// The log index of the entry assigning the agent to this claim, in
    /// its log `entries` from its start.
    fn assigned(&self, entries: &[(u64, Entry)]) -> Result<u64, ClaimError> {
        let signing: Vec<[u8; 32]> = self.0.keys.iter().map(|key| key.signing).collect();
        entries
            .iter()
            .find(|(_, entry)| matches!(&entry.body, Body::Assigned { device: 0, kit } if *kit == signing))
            .map(|(index, _)| *index)
            .ok_or(ClaimError::Unassigned)
    }

    /// The agent assigned: the device's group, from the agent's log
    /// `entries` from its start (`Personal` at `instance`), its `R` the
    /// kit's from the assignment's entry; the claim's row deleted. Again
    /// after a crash, the group already made is taken; a group of another
    /// agent is [`ClaimError::Held`].
    pub fn claimed(
        self,
        store: &Store,
        instance: InstanceId,
        entries: &[(u64, Entry)],
        now: u64,
    ) -> Result<DeviceGroup, ClaimError> {
        let since = self.assigned(entries)?;
        let agent = Agent {
            identity: self.0.identity,
            instance,
        };
        let mut group = match DeviceGroup::open(store)? {
            Some(group) if group.agent().identity == self.0.identity => group,
            Some(_) => return Err(ClaimError::Held),
            None => DeviceGroup::create(
                store,
                agent,
                self.0.device.clone(),
                self.0.keys.clone(),
                now,
            )?,
        };
        group.set_recovery(since, self.0.r)?;
        store.write_group_rows(vec![(CLAIM_ROW.to_vec(), None)])?;
        Ok(group)
    }
}

/// The device's nullifier in `Homes`' scope: the home's `space`, `Homes`'
/// `agent` and `instance`.
pub fn nullifier(secret: &DeviceSecret, space: &[u8; 32], agent: u32, instance: u32) -> [u8; 32] {
    let scope = call::scope(space, agent, instance, SCOPE).expect("the scope's name is in bounds");
    secret::nullifier(secret, &scope).to_bytes()
}

/// A nonce whose work for `member` in the space whose handle is `handle`
/// meets `difficulty` under `salt`, the least, searched on `threads`
/// threads: about `2^difficulty` hashes; `u64::MAX` if no nonce does.
pub fn work(
    handle: &[u8; 32],
    member: &Bytes,
    salt: &[u8; 32],
    difficulty: u8,
    threads: usize,
) -> u64 {
    let threads = threads.max(1) as u64;
    let nonce = AtomicU64::new(u64::MAX);
    std::thread::scope(|scope| {
        for start in 0..threads {
            let nonce = &nonce;
            scope.spawn(move || {
                // Each thread searches on below the least nonce found, so
                // the search finds the least on any number of threads.
                let mut at = start;
                while at < nonce.load(Ordering::Relaxed) {
                    if meets(&open_work(handle, member, salt, at), difficulty) {
                        nonce.fetch_min(at, Ordering::Relaxed);
                        return;
                    }
                    match at.checked_add(threads) {
                        Some(next) => at = next,
                        None => return,
                    }
                }
            });
        }
    });
    nonce.load(Ordering::Relaxed)
}

impl Prover {
    /// [`Prover::prove_auth`] in the scope "home", for `call` of `Homes`'
    /// `claim` alone; any other method is [`DeviceError::Reserved`].
    pub fn prove_home(
        &self,
        secret: &DeviceSecret,
        witness: &AuthWitness,
        call: &Call,
        program: &DeviceProgram,
    ) -> Result<Proven, DeviceError> {
        if call.method != homes::method::CLAIM.0 {
            return Err(DeviceError::Reserved);
        }
        self.prove_in_scope(secret, witness, SCOPE, call, program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The work found meets the difficulty, on one thread or several.
    #[test]
    fn the_work_found_meets_its_difficulty() {
        let (handle, member, salt) = ([1; 32], [2; 32], [3; 32]);
        for threads in [1, 4] {
            let nonce = work(&handle, &member, &salt, 10, threads);
            assert!(meets(&open_work(&handle, &member, &salt, nonce), 10));
        }
        assert_eq!(work(&handle, &member, &salt, 0, 2), 0);
    }
}
