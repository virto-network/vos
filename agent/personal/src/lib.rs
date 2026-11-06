//! `Personal`, the personal agent's actor (`light-node.md` §3.3–§3.7): it
//! orders the device group's commits, stores the user's sealed envelopes
//! and holds an inbox, for the devices of its device set alone.
//!
//! - **Admission:** `#[actor(known_keys, onion_only)]`. Ingress admits a
//!   session only from a key of `admitted` (a device's sync and admin
//!   keys, the kit's signing keys, an open pairing slot's key) and a
//!   request only through the onion. A key admitted no more keeps its
//!   sessions until they expire, so every handler checks its caller
//!   against the device set as well, and every query answers only keys it
//!   admits.
//! - **Admin calls** (commits and device-set operations) are client calls
//!   signed by a device's admin key, verified at ingress; the agent checks
//!   the origin, `Principal::Client(key)`, against the device set and
//!   verifies nothing. The device then posts the call's evidence, the
//!   signed message and its signature, stored as data beside it.
//! - **The commit log:** one candidate an epoch, the confirmed epoch plus
//!   one; its confirming set (the devices seen by a call in the window,
//!   less every matured removal) written into its log entry; the votes,
//!   signed by the devices' sync keys, decide it, the agent's verdict
//!   advisory. A commit carries every matured removal.
//! - **Sealed scopes:** envelopes stored opaque, deduplicated by id before
//!   the epoch check, numbered per scope in the order taken.
//! - **The lease:** past it the agent is in its grace, refusing pushes, the
//!   inbox and any commit but one carrying a removal.
//!
//! The device set's rules beyond what these need (vetoes, contests, the
//! kit's operations, seasoning, a restore) are added to these tables, not
//! in place of them: the layout is append-only across versions.

#![no_std]

extern crate alloc;

mod rows;
mod rules;

use alloc::vec::Vec;

use vos_sdk::context::Method;
use vos_sdk::prelude::*;
use vos_wire::ingress::CallMessage;
use vos_wire::personal::{
    Acknowledged, AdminCall, AdminClass, Author, Body, Candidacy, Device, DeviceId, DeviceView,
    Effect, Entry, Envelope, Header, Holder, InboxItem, Item, Kit, KitEntry, MAX_ENVELOPE,
    NewDevice, Overview, PersonalError, Policy, Pushed, RECOVERY, Recipient, Recorded, Removal,
    Scope, Status, Vote, Voted, commit_id, envelope_id, welcome_hash,
};

use rows::{Candidate, Charge, Group, Head, Lease, ONE, Share, Slot, Stored, Usage};

/// The layout's version, which `version` answers: the keeper upgrades
/// agents a batch at a time and reads it back.
pub const VERSION: u32 = if cfg!(feature = "next") { 2 } else { 1 };

/// The most recovery entries a claim brings.
pub const KIT_ENTRIES: usize = 4;

/// The expired inbox items, and the expired slots, a call deletes.
const SWEEP: usize = 8;

/// How often a device's `alive` is logged.
pub const ALIVE_EVERY_MS: u64 = 60 * 60 * 1000;

/// The pairing slots open at once: one an opener, and these an agent.
pub const OPEN_SLOTS: usize = 4;

/// The inbox items a pairing slot's holder writes.
pub const SLOT_ITEMS: u32 = 4;

#[actor(known_keys, onion_only)]
pub struct Personal {
    /// The keys ingress admits, and what each is.
    admitted: Table<[u8; 32], Holder>,
    devices: Table<DeviceId, Device, Ordered>,
    /// Each device's removal, pending, matured, then carried.
    removals: Table<DeviceId, Removal>,
    /// The pending removals by their maturity.
    maturing: Table<(u64, DeviceId), (), Ordered>,
    /// Each device's latest call, in batch time.
    seen: Table<DeviceId, u64>,
    /// Each device's last logged `alive`: its time and its log index.
    alive: Table<DeviceId, (u64, u64)>,
    /// The votes on each candidate, by its log index and the device.
    votes: Table<(u64, DeviceId), Vote, Ordered>,
    /// Each commit taken as a candidate, by its id: its log index.
    commits: Table<[u8; 32], u64>,
    /// Each admin call's evidence: its log index by the call's.
    evidenced: Table<u64, u64>,
    log: Table<u64, Entry, Ordered>,
    head: Table<u8, Head>,
    group: Table<u8, Group>,
    lease: Table<u8, Lease>,
    policy: Table<u8, Policy>,
    usage: Table<u8, Usage>,
    shares: Table<DeviceId, Share>,
    kit: Table<u8, KitEntry>,
    /// `R2`, served to no read.
    secrets: Table<u8, [u8; 32]>,
    /// Each scope's last position.
    scopes: Table<Scope, u64>,
    envelopes: Table<(Scope, u64), Stored, Ordered>,
    /// Each stored envelope's bytes.
    bodies: Table<(Scope, u64), Vec<u8>>,
    /// Each stored envelope's scope and position, by its id.
    ids: Table<[u8; 32], (Scope, u64)>,
    /// Each device's last position in each scope: a removed device's
    /// frontier.
    pushed: Table<(DeviceId, Scope), u64, Ordered>,
    /// Checkpoint acknowledgements: the checkpoint's hash by scope,
    /// position and device.
    acks: Table<(Scope, (u64, DeviceId)), [u8; 32], Ordered>,
    inbox: Table<(u64, [u8; 16]), Item, Ordered>,
    slots: Table<Scope, Slot>,
    /// Open slots by their expiry.
    closing: Table<(u64, Scope), (), Ordered>,
}

#[messages]
impl Personal {
    pub fn new() -> Self {
        Self {
            admitted: Table::default(),
            devices: Table::default(),
            removals: Table::default(),
            maturing: Table::default(),
            seen: Table::default(),
            alive: Table::default(),
            votes: Table::default(),
            commits: Table::default(),
            evidenced: Table::default(),
            log: Table::default(),
            head: Table::default(),
            group: Table::default(),
            lease: Table::default(),
            policy: Table::default(),
            usage: Table::default(),
            shares: Table::default(),
            kit: Table::default(),
            secrets: Table::default(),
            scopes: Table::default(),
            envelopes: Table::default(),
            bodies: Table::default(),
            ids: Table::default(),
            pushed: Table::default(),
            acks: Table::default(),
            inbox: Table::default(),
            slots: Table::default(),
            closing: Table::default(),
        }
    }

    // ===== The home's =====

    /// Set the space's policy for this agent: delays, windows and quotas.
    #[msg(role = "homes")]
    pub async fn configure(
        &mut self,
        ctx: &mut Command<Self>,
        policy: Policy,
    ) -> Result<Recorded, PersonalError> {
        let now = ctx.now();
        self.policy.insert(&ONE, &policy);
        let index = self.append(now, Body::Configured(policy));
        Ok(Recorded { at: now, index })
    }

    /// Assign the agent to a claim: its device, the first, active at once,
    /// and its recovery kit. The lease runs from now.
    #[msg(role = "homes")]
    pub async fn assign(
        &mut self,
        ctx: &mut Command<Self>,
        device: NewDevice,
        kit: Kit,
    ) -> Result<Recorded, PersonalError> {
        let now = ctx.now();
        if self.lease.contains(&ONE) {
            return Err(PersonalError::Assigned);
        }
        if kit.entries.len() > KIT_ENTRIES {
            return Err(PersonalError::Malformed);
        }
        let mut keys: Vec<[u8; 32]> = Vec::from([device.sync, device.admin]);
        keys.extend(kit.entries.iter().map(|entry| entry.signing));
        for (i, key) in keys.iter().enumerate() {
            if keys[..i].contains(key) {
                return Err(PersonalError::KeyTaken);
            }
        }
        let first = self.add_device(now, now, device)?;
        for (i, entry) in kit.entries.iter().enumerate() {
            self.admitted.insert(&entry.signing, &Holder::Kit(i as u8));
            self.kit.insert(&(i as u8), entry);
        }
        self.secrets.insert(&ONE, &kit.r2);
        let lease_ms = self.policy().lease_ms;
        self.lease.insert(
            &ONE,
            &Lease {
                until: now.saturating_add(lease_ms),
                reproved: false,
            },
        );
        self.seen.insert(&first, &now);
        let kit = kit.entries.iter().map(|entry| entry.signing).collect();
        let index = self.append(now, Body::Assigned { device: first, kit });
        Ok(Recorded { at: now, index })
    }

    /// A re-proof: the lease runs from now, and the larger quota holds.
    #[msg(role = "homes")]
    pub async fn renew(&mut self, ctx: &mut Command<Self>) -> Result<Recorded, PersonalError> {
        let now = ctx.now();
        self.assigned()?;
        let until = now.saturating_add(self.policy().lease_ms);
        self.lease.insert(
            &ONE,
            &Lease {
                until,
                reproved: true,
            },
        );
        let index = self.append(now, Body::Renewed { until });
        Ok(Recorded { at: now, index })
    }

    // ===== Admin calls =====

    /// Remove `target`: an admin call, pending until the policy's delay
    /// passes, then matured, from which the device has no voice and the
    /// next commit carries it.
    #[msg]
    pub async fn remove(
        &mut self,
        ctx: &mut Command<Self>,
        target: DeviceId,
    ) -> Result<Recorded, PersonalError> {
        let now = self.settle(ctx.now());
        self.assigned()?;
        let (origin, by) = self.admin_caller(ctx.caller(), now)?;
        let device = self
            .devices
            .get(&target)
            .ok_or(PersonalError::UnknownDevice)?;
        if device.status != Status::Live {
            return Err(PersonalError::Removed);
        }
        if self.removals.contains(&target) {
            return Err(PersonalError::Pending);
        }
        let matures = now.saturating_add(self.policy().removal_delay_ms);
        let call = AdminCall {
            origin,
            method: personal::Remove::ID,
            arguments: personal::Remove { target }.encode(),
        };
        let index = self.append(
            now,
            Body::Removal {
                call,
                by,
                target,
                matures,
            },
        );
        self.removals.insert(
            &target,
            &Removal {
                index,
                matures,
                committed: None,
            },
        );
        self.maturing.insert(&(matures, target), &());
        self.seen.insert(&by, &now);
        Ok(Recorded { at: now, index })
    }

    /// Propose `epoch`'s commit: an admin call by an active device, taken as
    /// the candidate when `epoch` is the confirmed epoch plus one and none
    /// is pending, its effect carrying every matured removal. A commit
    /// already taken answers as it did, or `Decided` once decided.
    #[msg]
    pub async fn commit(
        &mut self,
        ctx: &mut Command<Self>,
        epoch: u64,
        effect: Effect,
        handshake: Vec<u8>,
        welcome_hash: Option<[u8; 32]>,
    ) -> Result<Candidacy, PersonalError> {
        let now = self.settle(ctx.now());
        self.assigned()?;
        let (origin, by) = self.admin_caller(ctx.caller(), now)?;
        let id = commit_id(&handshake);
        let group = self.group();
        if let Some(index) = self.commits.get(&id) {
            return match group.candidate {
                Some(candidate) if candidate.index == index => Ok(Candidacy {
                    at: now,
                    index,
                    set: candidate.set,
                }),
                _ => Err(PersonalError::Decided),
            };
        }
        if self.lapsed(now) && (effect.remove.is_empty() || effect.add.is_some()) {
            return Err(PersonalError::Lapsed);
        }
        if group.candidate.is_some() {
            return Err(PersonalError::EpochTaken);
        }
        if epoch != group.confirmed + 1 {
            return Err(PersonalError::EpochGap {
                confirmed: group.confirmed,
            });
        }
        self.check_removals(now, &effect.remove)?;
        if let Some(added) = &effect.add {
            let committer = self.devices.get(&by).ok_or(PersonalError::UnknownDevice)?;
            if committer.keys.class != AdminClass::Strong {
                return Err(PersonalError::Delayed);
            }
            if added.sync == added.admin
                || self.admitted.contains(&added.sync)
                || self.admitted.contains(&added.admin)
            {
                return Err(PersonalError::KeyTaken);
            }
        }
        if effect.remove.is_empty() || effect.add.is_some() {
            self.charge(now, Some(by), 0, Charge::Commit)?;
        }
        self.seen.insert(&by, &now);
        let added = match &effect.add {
            Some(keys) => {
                let probation = self.policy().probation_ms;
                let added = self.add_device(now, now.saturating_add(probation), keys.clone())?;
                self.close_slots_of(by);
                if self.live_devices(now) == 2 {
                    self.restart_shares();
                }
                Some(added)
            }
            None => None,
        };
        let set = self.confirming_set(now, &effect.remove);
        let call = AdminCall {
            origin,
            method: personal::Commit::ID,
            arguments: personal::Commit {
                epoch,
                effect: effect.clone(),
                handshake,
                welcome_hash,
            }
            .encode(),
        };
        let index = self.append(
            now,
            Body::Candidate {
                call,
                by,
                epoch,
                added,
                set: set.clone(),
            },
        );
        self.commits.insert(&id, &index);
        let mut group = self.group();
        group.candidate = Some(Candidate {
            epoch,
            index,
            by,
            created: now,
            added,
            removes: effect.remove,
            set: set.clone(),
        });
        self.group.insert(&ONE, &group);
        Ok(Candidacy {
            at: now,
            index,
            set,
        })
    }

    // ===== Sync-key calls =====

    /// Post the evidence of the admin call at `index`: the exact call
    /// message its admin key signed and the signature, and a commit's
    /// Welcome. Stored as data; its arguments must be the call's recorded,
    /// byte for byte. Only the device that made the call posts it.
    #[msg]
    pub async fn evidence(
        &mut self,
        ctx: &mut Command<Self>,
        index: u64,
        message: Vec<u8>,
        signature: [u8; 64],
        welcome: Option<Vec<u8>>,
    ) -> Result<Recorded, PersonalError> {
        let now = self.settle(ctx.now());
        self.assigned()?;
        let device = self.sync_caller(ctx.caller(), now)?;
        let entry = self.log.get(&index).ok_or(PersonalError::NotAdminCall)?;
        let (call, by, named) = match entry.body {
            Body::Removal { call, by, .. } => (call, by, None),
            Body::Candidate { call, by, .. } => {
                let commit = personal::Commit::decode_exact(&call.arguments)
                    .ok_or(PersonalError::Malformed)?;
                (call, by, commit.welcome_hash)
            }
            _ => return Err(PersonalError::NotAdminCall),
        };
        if by != device {
            return Err(PersonalError::NotYours);
        }
        if self.evidenced.contains(&index) {
            return Err(PersonalError::Evidenced);
        }
        // The agent's identity, which the message names, is the devices' to
        // check: an actor does not read it.
        let signed = CallMessage::parse(&message).ok_or(PersonalError::Mismatch)?;
        let (_, me) = ctx.me();
        if signed.session.key != call.origin
            || signed.instance != me
            || signed.method.0 != call.method
            || signed.arguments != call.arguments
        {
            return Err(PersonalError::Mismatch);
        }
        match (named, &welcome) {
            (None, None) => {}
            (Some(named), Some(welcome)) if welcome_hash(welcome) == named => {}
            _ => return Err(PersonalError::Welcome),
        }
        self.seen.insert(&device, &now);
        let at = self.append(
            now,
            Body::Evidence {
                index,
                message,
                signature,
                welcome,
            },
        );
        self.evidenced.insert(&index, &at);
        Ok(Recorded { at: now, index: at })
    }

    /// Confirm `epoch`'s candidate with `h`, signed by the device's sync
    /// key over `vote_message`.
    #[msg]
    pub async fn confirm(
        &mut self,
        ctx: &mut Command<Self>,
        epoch: u64,
        h: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Voted, PersonalError> {
        self.vote(ctx, epoch, Vote::Confirm(h), signature)
    }

    /// Refuse `epoch`'s candidate, signed by the device's sync key over
    /// `vote_message`.
    #[msg]
    pub async fn nack(
        &mut self,
        ctx: &mut Command<Self>,
        epoch: u64,
        signature: [u8; 64],
    ) -> Result<Voted, PersonalError> {
        self.vote(ctx, epoch, Vote::Nack, signature)
    }

    /// The device is alive: logged at most once an [`ALIVE_EVERY_MS`] a
    /// device, the entry logged last answered between, so liveness grows
    /// the log by a bounded amount however often it is posted.
    #[msg]
    pub async fn alive(&mut self, ctx: &mut Command<Self>) -> Result<Recorded, PersonalError> {
        let now = self.settle(ctx.now());
        self.assigned()?;
        let device = self.sync_caller(ctx.caller(), now)?;
        self.seen.insert(&device, &now);
        let index = match self.alive.get(&device) {
            Some((at, index)) if now < at.saturating_add(ALIVE_EVERY_MS) => index,
            _ => {
                let index = self.append(now, Body::Alive { device });
                self.alive.insert(&device, &(now, index));
                index
            }
        };
        Ok(Recorded { at: now, index })
    }

    /// Store an envelope, sealed under the confirmed epoch its header
    /// names: one already stored answers where it is, before the epoch is
    /// checked.
    #[msg]
    pub async fn push(
        &mut self,
        ctx: &mut Command<Self>,
        envelope: Vec<u8>,
    ) -> Result<Pushed, PersonalError> {
        let now = self.settle(ctx.now());
        self.assigned()?;
        let device = self.sync_caller(ctx.caller(), now)?;
        if envelope.len() > MAX_ENVELOPE {
            return Err(PersonalError::TooLarge);
        }
        let header = Header::parse(&envelope).ok_or(PersonalError::Malformed)?;
        let id = envelope_id(&envelope);
        if let Some((_, position)) = self.ids.get(&id) {
            return Ok(Pushed {
                at: now,
                position,
                id,
            });
        }
        if header.scope != RECOVERY && self.lapsed(now) {
            return Err(PersonalError::Lapsed);
        }
        let confirmed = self.group().confirmed;
        if header.epoch != confirmed {
            return Err(PersonalError::StaleEpoch { confirmed });
        }
        self.charge(now, Some(device), envelope.len() as u64, Charge::Envelope)?;
        let position = self.scopes.get(&header.scope).unwrap_or(0) + 1;
        self.scopes.insert(&header.scope, &position);
        self.envelopes.insert(
            &(header.scope, position),
            &Stored {
                id,
                author: device,
                len: envelope.len() as u32,
            },
        );
        self.bodies.insert(&(header.scope, position), &envelope);
        self.ids.insert(&id, &(header.scope, position));
        self.pushed.insert(&(device, header.scope), &position);
        self.seen.insert(&device, &now);
        Ok(Pushed {
            at: now,
            position,
            id,
        })
    }

    /// Acknowledge the checkpoint at `scope`'s `position`, whose state the
    /// device recomputed to `hash`. Answers the batch time.
    #[msg]
    pub async fn acknowledge(
        &mut self,
        ctx: &mut Command<Self>,
        scope: Scope,
        position: u64,
        hash: [u8; 32],
    ) -> Result<u64, PersonalError> {
        let now = self.settle(ctx.now());
        self.assigned()?;
        let device = self.sync_caller(ctx.caller(), now)?;
        if position == 0 || position > self.scopes.get(&scope).unwrap_or(0) {
            return Err(PersonalError::NoPosition);
        }
        self.acks.insert(&(scope, (position, device)), &hash);
        self.seen.insert(&device, &now);
        Ok(now)
    }

    /// Open pairing slot `slot` for `key`, which the agent admits for that
    /// slot alone until the slot closes: at its expiry, by a device, or at
    /// its opener's next add. Answers the batch time.
    #[msg]
    pub async fn open_slot(
        &mut self,
        ctx: &mut Command<Self>,
        slot: Scope,
        key: [u8; 32],
    ) -> Result<u64, PersonalError> {
        let now = self.settle(ctx.now());
        self.assigned()?;
        let opener = self.sync_caller(ctx.caller(), now)?;
        if self.lapsed(now) {
            return Err(PersonalError::Lapsed);
        }
        let open: Vec<Slot> = self
            .slots
            .iter(None)
            .map(|(_, open)| open)
            .filter(|open| open.expires > now)
            .collect();
        if self.slots.contains(&slot)
            || open.len() >= OPEN_SLOTS
            || open.iter().any(|open| open.opener == opener)
        {
            return Err(PersonalError::SlotTaken);
        }
        if self.admitted.contains(&key) {
            return Err(PersonalError::KeyTaken);
        }
        let expires = now.saturating_add(self.policy().slot_ttl_ms);
        self.slots.insert(
            &slot,
            &Slot {
                opener,
                key,
                expires,
                items: 0,
            },
        );
        self.closing.insert(&(expires, slot), &());
        self.admitted.insert(&key, &Holder::Slot(slot));
        self.seen.insert(&opener, &now);
        Ok(now)
    }

    /// Close pairing slot `slot`. Answers the batch time.
    #[msg]
    pub async fn close_slot(
        &mut self,
        ctx: &mut Command<Self>,
        slot: Scope,
    ) -> Result<u64, PersonalError> {
        let now = self.settle(ctx.now());
        self.assigned()?;
        let device = self.sync_caller(ctx.caller(), now)?;
        let open = self.slots.get(&slot).ok_or(PersonalError::NoSlot)?;
        self.close_slot_row(slot, &open);
        self.seen.insert(&device, &now);
        Ok(now)
    }

    /// Leave `bytes` in the inbox for `to` until `expires`, as `id`: a
    /// device for its devices or a slot, a slot's key for its slot. Answers
    /// the batch time; the same item again is stored once.
    #[msg]
    pub async fn put(
        &mut self,
        ctx: &mut Command<Self>,
        to: Recipient,
        id: [u8; 16],
        expires: u64,
        bytes: Vec<u8>,
    ) -> Result<u64, PersonalError> {
        let now = self.settle(ctx.now());
        self.assigned()?;
        let from = match self.holder(ctx.caller()) {
            Some((_, Holder::Sync(_))) => Author::Device(self.sync_caller(ctx.caller(), now)?),
            Some((_, Holder::Slot(slot))) if to == Recipient::Slot(slot) => Author::Slot(slot),
            _ => return Err(PersonalError::NotAdmitted),
        };
        if self.lapsed(now) {
            return Err(PersonalError::Lapsed);
        }
        let policy = self.policy();
        if bytes.len() > policy.inbox_item_bytes as usize {
            return Err(PersonalError::TooLarge);
        }
        let latest = match to {
            Recipient::Devices => now.saturating_add(policy.inbox_ttl_ms),
            Recipient::Slot(slot) => {
                self.open_slot_row(slot, now)
                    .ok_or(PersonalError::NoSlot)?
                    .expires
            }
        };
        if expires <= now || expires > latest {
            return Err(PersonalError::Expiry);
        }
        let item = Item { to, from, bytes };
        if let Some(stored) = self.inbox.get(&(expires, id)) {
            return if stored == item {
                Ok(now)
            } else {
                Err(PersonalError::ItemTaken)
            };
        }
        if self.usage().items >= policy.inbox_items {
            return Err(PersonalError::InboxFull);
        }
        let author = match from {
            Author::Device(device) => Some(device),
            Author::Slot(slot) => {
                let mut open = self.open_slot_row(slot, now).ok_or(PersonalError::NoSlot)?;
                if open.items >= SLOT_ITEMS {
                    return Err(PersonalError::InboxFull);
                }
                open.items += 1;
                self.slots.insert(&slot, &open);
                None
            }
        };
        self.charge(now, author, item.bytes.len() as u64, Charge::Item)?;
        self.inbox.insert(&(expires, id), &item);
        if let Some(device) = author {
            self.seen.insert(&device, &now);
        }
        Ok(now)
    }

    // ===== Reads, each for the keys the agent admits =====

    /// The layout's version: any caller.
    #[msg]
    pub async fn version(&self) -> u32 {
        VERSION
    }

    /// The agent's epochs, candidate, log head and lease.
    #[msg]
    pub async fn overview(&self, ctx: &Query<Self>) -> Result<Overview, PersonalError> {
        let now = ctx.now();
        self.reader(ctx.caller(), now)?.device_or_kit()?;
        let group = self.group();
        let head = self.head.get(&ONE).unwrap_or_default();
        Ok(Overview {
            at: now,
            confirmed: group.confirmed,
            candidate: group.candidate.map(|candidate| candidate.pending()),
            next: head.next,
            chain: head.chain,
            lease_until: self.lease.get(&ONE).map_or(0, |lease| lease.until),
            lapsed: self.lapsed(now),
        })
    }

    /// The device set, each device's standing at the batch time.
    #[msg]
    pub async fn devices(&self, ctx: &Query<Self>) -> Result<Vec<DeviceView>, PersonalError> {
        let now = ctx.now();
        self.reader(ctx.caller(), now)?.device_or_kit()?;
        Ok(self
            .devices
            .iter(None)
            .map(|(id, device)| {
                let removal = self.removals.get(&id);
                DeviceView {
                    id,
                    standing: rules::standing(&device, removal.as_ref(), now),
                    device,
                    removal,
                }
            })
            .collect())
    }

    /// The control log from `from`, as much as one answer holds.
    #[msg]
    pub async fn log(
        &self,
        ctx: &Query<Self>,
        from: u64,
    ) -> Result<Vec<(u64, Entry)>, PersonalError> {
        self.reader(ctx.caller(), ctx.now())?.device_or_kit()?;
        let next = self.head.get(&ONE).unwrap_or_default().next;
        let rows = (from..next).filter_map(|index| Some((index, self.log.get(&index)?)));
        Ok(rules::bounded(rows, |row| row.encode().len()))
    }

    /// `scope`'s envelopes after `position`, in order, as much as one answer
    /// holds: for the devices, and for the kit the recovery scope's.
    #[msg]
    pub async fn since(
        &self,
        ctx: &Query<Self>,
        scope: Scope,
        position: u64,
    ) -> Result<Vec<Envelope>, PersonalError> {
        match self.reader(ctx.caller(), ctx.now())? {
            rules::Reader::Device(_) => {}
            rules::Reader::Kit if scope == RECOVERY => {}
            _ => return Err(PersonalError::NotAdmitted),
        }
        let rows = self
            .envelopes
            .iter(Some(&(scope, position)))
            .take_while(|((at, _), _)| *at == scope);
        let taken = rules::bounded(rows, |(_, stored)| Envelope::FRAMING + stored.len as usize);
        Ok(taken
            .into_iter()
            .map(|(key, stored)| Envelope {
                position: key.1,
                id: stored.id,
                bytes: self.bodies.get(&key).unwrap_or_default(),
            })
            .collect())
    }

    /// The inbox's items after `after`, unexpired: every item for a
    /// device, a slot's own for its key.
    #[msg]
    pub async fn inbox(
        &self,
        ctx: &Query<Self>,
        after: Option<(u64, [u8; 16])>,
    ) -> Result<Vec<InboxItem>, PersonalError> {
        let now = ctx.now();
        let slot = match self.reader(ctx.caller(), now)? {
            rules::Reader::Device(_) => None,
            rules::Reader::Slot(slot) => Some(slot),
            rules::Reader::Kit => return Err(PersonalError::NotAdmitted),
        };
        let rows = self
            .inbox
            .iter(after.as_ref())
            .filter(|((expires, _), item)| {
                *expires > now && slot.is_none_or(|slot| item.to == Recipient::Slot(slot))
            })
            .map(|((expires, id), item)| InboxItem { expires, id, item });
        Ok(rules::bounded(rows, |row| row.encode().len()))
    }

    /// The acknowledgements of `scope`'s checkpoints past `after`.
    #[msg]
    pub async fn acknowledgements(
        &self,
        ctx: &Query<Self>,
        scope: Scope,
        after: u64,
    ) -> Result<Vec<Acknowledged>, PersonalError> {
        self.reader(ctx.caller(), ctx.now())?.device_or_kit()?;
        let rows = self
            .acks
            .iter(Some(&(scope, (after, DeviceId::MAX))))
            .take_while(|((at, _), _)| *at == scope)
            .map(|((_, (position, device)), hash)| Acknowledged {
                position,
                device,
                hash,
            });
        Ok(rules::bounded(rows, |row| row.encode().len()))
    }

    /// `device`'s last position in each scope it pushed to: once its
    /// removal matured, its frontier, past which its envelopes are none.
    #[msg]
    pub async fn frontier(
        &self,
        ctx: &Query<Self>,
        device: DeviceId,
    ) -> Result<Vec<(Scope, u64)>, PersonalError> {
        self.reader(ctx.caller(), ctx.now())?.device_or_kit()?;
        let after = device.checked_sub(1).map(|before| (before, [0xff; 16]));
        let rows = self
            .pushed
            .iter(after.as_ref())
            .take_while(|((at, _), _)| *at == device)
            .map(|((_, scope), position)| (scope, position));
        Ok(rules::bounded(rows, |row| row.encode().len()))
    }
}
