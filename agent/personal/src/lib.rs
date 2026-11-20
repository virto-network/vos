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
//!   admits, bar `log`: a removed device's sync key reads it through its
//!   removal, so the device leaves on the log it verifies.
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
//! - **The device set** (`light-node.md` §3.5): operations signed by a
//!   device's admin key or the kit's, each pending for its signer's delay
//!   on batch time, vetoed, contested and resolved, made immediate by two
//!   seasoned devices; the kit's operations cancelled by any device's
//!   veto, a restore by any device's `alive` too. A device whose removal
//!   matured has no voice.
//! - **The lease:** past it the agent is in its grace, refusing pushes, the
//!   inbox and any commit but one carrying a removal.
//!
//! The layout is append-only across versions: a later version adds tables
//! beside these.

#![no_std]

extern crate alloc;

mod devices;
pub mod home;
mod rows;
mod rules;

use alloc::vec::Vec;

use vos_sdk::context::Method;
use vos_sdk::prelude::*;
use vos_wire::ingress::CallMessage;
use vos_wire::personal::{
    Acknowledged, AdminCall, AdminClass, Attached, Author, Body, Candidacy, Device, DeviceId,
    DeviceView, Effect, Entry, Envelope, Header, Holder, InboxItem, Item, Kit, KitEntry,
    MAX_ENVELOPE, NewAdmin, NewDevice, NewKit, Op, Operation, Overview, PersonalError, Policy,
    Pushed, RECOVERY, Recipient, Recorded, RecoveryView, Removal, Scope, Signer, Status, Vote,
    Voted, Woken, commit_id, envelope_id, r2_hash, welcome_hash,
};

use rows::{
    By, Candidate, Charge, Due, Gone, Group, Head, Kind, Lease, Recovery, Share, Slot, Stored,
    Usage,
};

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
    /// The devices whose status is live.
    live: Table<DeviceId, (), Ordered>,
    /// Each device's matured removal, then carried.
    removals: Table<DeviceId, Removal>,
    /// Each removed device's sync key: the log it reads.
    gone: Table<[u8; 32], Gone>,
    /// The device-set operations, by their log index.
    operations: Table<u64, Operation>,
    /// The operations pending or contested.
    open: Table<u64, (), Ordered>,
    /// What falls due, by its time: the pending operations by their
    /// maturity, and the chores of a removal and of a kit replaced.
    due: Table<(u64, Due), (), Ordered>,
    /// The open operations removing each device.
    against: Table<(DeviceId, u64), (), Ordered>,
    /// The open operation of each kind of which one is open at a time, by
    /// the kind and its target.
    kinds: Table<(Kind, DeviceId), u64>,
    /// The open operations by their signer: whether each counts against
    /// its signer's open operations, as all but a removal do.
    signed: Table<(By, u64), bool, Ordered>,
    /// The devices' vetoes of each operation, and by each device.
    vetoes: Table<(u64, DeviceId), (), Ordered>,
    vetoed: Table<(DeviceId, u64), (), Ordered>,
    /// Two removals aimed at each other, one contest: each one's rival.
    rivals: Table<u64, u64>,
    /// Each device's resolution of a contest, by the contest's lower
    /// operation: the operation it lets mature, if any.
    resolutions: Table<(u64, DeviceId), Option<u64>, Ordered>,
    /// Each frozen probation's time left.
    frozen: Table<DeviceId, u64>,
    /// The matured add operations no confirmed commit carried yet.
    ready: Table<u64, (), Ordered>,
    /// The keys open operations bring, and a matured add's until its
    /// commit: by the operation.
    claimed: Table<[u8; 32], u64>,
    /// A kit rotation's or a restore's `R2`, from its evidence, until it
    /// matures: served to no read.
    deposits: Table<u64, [u8; 32]>,
    recovery: Cell<Recovery>,
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
    head: Cell<Head>,
    group: Cell<Group>,
    lease: Cell<Lease>,
    policy: Cell<Policy>,
    usage: Cell<Usage>,
    shares: Table<DeviceId, Share>,
    kit: Table<u8, KitEntry>,
    /// `R2`, served to no read.
    secrets: Cell<[u8; 32]>,
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
    /// The home's `Homes` that claimed the agent: its agent and instance.
    home: Cell<(u32, u32)>,
}

#[messages]
impl Personal {
    // ===== The home's =====

    /// Set the space's policy for this agent: delays, windows and quotas.
    /// Once a claim assigned the agent, a configuration lowers no delay or
    /// window of the device set's rules ([`Policy::over`]): those are the
    /// claim's.
    #[msg(role = "homes")]
    pub async fn configure(
        &mut self,
        ctx: &mut Command<Self>,
        policy: Policy,
    ) -> Result<Recorded, PersonalError> {
        let now = ctx.now();
        let policy = if self.assigned().is_ok() {
            policy.over(&self.policy())
        } else {
            policy
        };
        self.policy.set(&policy);
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
        self.take(ctx.now(), device, kit)
    }

    /// [`Personal::configure`] then [`Personal::assign`] for the home's
    /// `Homes` at `homes` in the calling agent, answered by message (a send
    /// is one-way): `assigned`, or `refused` with the error, writing
    /// nothing. The same claim again, from the same home, is answered
    /// `assigned` again. From then on the agent tells `Homes` each device's
    /// nullifier as its add is confirmed and as its removal matures, and
    /// each new kit's keys.
    #[msg(role = "homes")]
    pub async fn claim(
        &mut self,
        ctx: &mut Command<Self>,
        device: NewDevice,
        kit: Kit,
        policy: Policy,
        homes: u32,
    ) -> Result<(), PersonalError> {
        let Principal::Agent(agent) = ctx.caller() else {
            return Err(PersonalError::NotAdmitted);
        };
        let to = Ref::<home::Homes>::new(InstanceId(homes));
        let again = self.home.get() == Some((agent.0, homes))
            && self
                .devices
                .get(&0)
                .is_some_and(|first| first.keys == device);
        if again {
            ctx.send(agent, to, home::Assigned {});
            return Ok(());
        }
        let previous = self.policy.get();
        self.policy.set(&policy);
        match self.take(ctx.now(), device, kit) {
            Ok(_) => {
                self.append(ctx.now(), Body::Configured(policy));
                self.home.set(&(agent.0, homes));
                ctx.send(agent, to, home::Assigned {});
            }
            Err(error) => {
                match previous {
                    Some(previous) => self.policy.set(&previous),
                    None => self.policy.clear(),
                }
                ctx.send(agent, to, home::Refused { error });
            }
        }
        Ok(())
    }

    /// A re-proof: the lease runs from now, and once five sixths of a lease
    /// passed since the claim, where the yearly prompt first falls, the
    /// larger quota holds; an earlier one lifts nothing.
    #[msg(role = "homes")]
    pub async fn renew(&mut self, ctx: &mut Command<Self>) -> Result<Recorded, PersonalError> {
        let now = ctx.now();
        self.assigned()?;
        let lease_ms = self.policy().lease_ms;
        let lease = self.lease.get().expect("an assigned agent's lease");
        let until = now.saturating_add(lease_ms);
        let ramp = lease_ms - lease_ms / 6;
        self.lease.set(&Lease {
            until,
            reproved: lease.reproved || now >= lease.claimed.saturating_add(ramp),
            ..lease
        });
        let index = self.append(now, Body::Renewed { until });
        Ok(Recorded { at: now, index })
    }

    // ===== Admin calls =====

    /// Remove `target`, signed by an active device or the kit: pending for
    /// the signer's delay, then matured unless vetoed, from which the
    /// device has no voice and the next commit carries it.
    #[msg(gas = 40_000_000)]
    pub async fn remove(
        &mut self,
        ctx: &mut Command<Self>,
        target: DeviceId,
    ) -> Result<Recorded, PersonalError> {
        let (now, call, by) = self.admin(ctx, &personal::Remove { target })?;
        self.open_operation(now, call, by, Op::Remove(target))
    }

    /// Add `device` as an operation, a delayed admin's add: once matured,
    /// a commit carries it.
    #[msg(gas = 40_000_000)]
    pub async fn add(
        &mut self,
        ctx: &mut Command<Self>,
        device: NewDevice,
    ) -> Result<Recorded, PersonalError> {
        let (now, call, by) = self.admin(
            ctx,
            &personal::Add {
                device: device.clone(),
            },
        )?;
        self.open_operation(now, call, by, Op::Add(device))
    }

    /// Replace `device`'s admin key, signed by another seasoned device or
    /// the kit: the device keeps its seasoning, and the new key signs from
    /// the operation's maturity, its probation.
    #[msg(gas = 40_000_000)]
    pub async fn replace(
        &mut self,
        ctx: &mut Command<Self>,
        device: DeviceId,
        admin: NewAdmin,
    ) -> Result<Recorded, PersonalError> {
        let (now, call, by) = self.admin(
            ctx,
            &personal::Replace {
                device,
                admin: admin.clone(),
            },
        )?;
        self.open_operation(now, call, by, Op::Replace { device, admin })
    }

    /// Rotate the kit to `kit`, signed by an active device or the kit: its
    /// `R2` in the evidence, the old one deleted at maturity.
    #[msg(gas = 40_000_000)]
    pub async fn rotate(
        &mut self,
        ctx: &mut Command<Self>,
        kit: NewKit,
    ) -> Result<Recorded, PersonalError> {
        let (now, call, by) = self.admin(ctx, &personal::Rotate { kit: kit.clone() })?;
        self.open_operation(now, call, by, Op::Rotate(kit))
    }

    /// Regroup, signed by a seasoned device: every other live device, each
    /// named in `remove`, removed and a new group started by it alone.
    #[msg(gas = 40_000_000)]
    pub async fn regroup(
        &mut self,
        ctx: &mut Command<Self>,
        remove: Vec<DeviceId>,
    ) -> Result<Recorded, PersonalError> {
        let (now, call, by) = self.admin(
            ctx,
            &personal::Regroup {
                remove: remove.clone(),
            },
        )?;
        self.open_operation(now, call, by, Op::Regroup(remove))
    }

    /// Restore, signed by the kit, every device asserted lost: after the
    /// kit's delay with no veto and no `alive`, every device is removed,
    /// `device` added alone and active, `kit` replaces the kit, and the
    /// previous `R2` is released to `device`.
    #[msg(gas = 40_000_000)]
    pub async fn restore(
        &mut self,
        ctx: &mut Command<Self>,
        device: NewDevice,
        kit: NewKit,
    ) -> Result<Recorded, PersonalError> {
        let (now, call, by) = self.admin(
            ctx,
            &personal::Restore {
                device: device.clone(),
                kit: kit.clone(),
            },
        )?;
        self.open_operation(now, call, by, Op::Restore { device, kit })
    }

    /// Veto the operation at `op`, signed by an active device, its target
    /// included: the kit's is cancelled, a device's contested. The kit
    /// vetoes nothing.
    #[msg(gas = 40_000_000)]
    pub async fn veto(
        &mut self,
        ctx: &mut Command<Self>,
        op: u64,
    ) -> Result<Recorded, PersonalError> {
        let now = self.settle(ctx.now())?;
        self.assigned()?;
        if let Some((_, Holder::Kit(_))) = self.holder(ctx.caller()) {
            return Err(PersonalError::KitVeto);
        }
        let (origin, device) = self.admin_caller(ctx.caller(), now)?;
        let call = AdminCall {
            origin,
            method: personal::Veto::ID,
            arguments: personal::Veto { op }.encode(),
        };
        self.veto_operation(now, call, device, op)
    }

    /// The second signature making the operation at `op` immediate.
    #[msg(gas = 40_000_000)]
    pub async fn cosign(
        &mut self,
        ctx: &mut Command<Self>,
        op: u64,
    ) -> Result<Recorded, PersonalError> {
        let (now, call, by) = self.admin(ctx, &personal::Cosign { op })?;
        self.cosign_operation(now, call, by, op)
    }

    /// Resolve the contest of the operation at `op`: `upheld`, it matures
    /// and its rival is dropped; else the reverse.
    #[msg(gas = 40_000_000)]
    pub async fn resolve(
        &mut self,
        ctx: &mut Command<Self>,
        op: u64,
        upheld: bool,
    ) -> Result<Recorded, PersonalError> {
        let (now, call, by) = self.admin(ctx, &personal::Resolve { op, upheld })?;
        self.resolve_operation(now, call, by, op, upheld)
    }

    /// Propose `epoch`'s commit: an admin call by an active device, taken as
    /// the candidate when `epoch` is the confirmed epoch plus one and none
    /// is pending, its effect carrying every matured removal, and with any
    /// removal the kit re-sealed under a new `R`, and adding inline for a
    /// strong admin or a matured add operation's device. A commit already
    /// taken answers as it did, or `Decided` once decided.
    #[msg(gas = 40_000_000)]
    pub async fn commit(
        &mut self,
        ctx: &mut Command<Self>,
        epoch: u64,
        effect: Effect,
        handshake: Vec<u8>,
        welcome_hash: Option<[u8; 32]>,
    ) -> Result<Candidacy, PersonalError> {
        let now = self.settle(ctx.now())?;
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
        self.check_removals(&effect.remove)?;
        match &effect.rekey {
            None if !effect.remove.is_empty() => return Err(PersonalError::Rekey),
            Some(rekey) if !self.kit_resealed(&rekey.entries) => {
                return Err(PersonalError::Rekey);
            }
            _ => {}
        }
        let carries = match &effect.add {
            Some(_) if self.live_devices() >= devices::DEVICES => {
                return Err(PersonalError::Devices);
            }
            Some(added) => {
                let carries = self.ready_add(added);
                let committer = self.devices.get(&by).ok_or(PersonalError::UnknownDevice)?;
                if carries.is_none() && committer.keys.class != AdminClass::Strong {
                    return Err(PersonalError::Delayed);
                }
                let taken = |key: &[u8; 32]| {
                    self.admitted.contains(key)
                        || self.claimed.get(key).is_some_and(|by| Some(by) != carries)
                };
                if added.sync == added.admin || taken(&added.sync) || taken(&added.admin) {
                    return Err(PersonalError::KeyTaken);
                }
                carries
            }
            None => None,
        };
        if effect.remove.is_empty() || effect.add.is_some() {
            self.charge(now, Some(by), 0, Charge::Commit)?;
        }
        self.seen.insert(&by, &now);
        let added = match &effect.add {
            Some(keys) => {
                let probation = self.policy().probation_ms;
                let added = self.add_device(now, now.saturating_add(probation), keys.clone())?;
                self.close_slots_of(by);
                if self.live_devices() == 2 {
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
            carries,
            removes: effect.remove,
            set: set.clone(),
            rekey: effect.rekey,
        });
        self.group.set(&group);
        Ok(Candidacy {
            at: now,
            index,
            set,
        })
    }

    // ===== Sync-key calls =====

    /// Post the evidence of the admin call at `index`: the exact call
    /// message its key signed and the signature, and what rides beside it
    /// bound by hash, a commit's Welcome and an `R2`. Stored as data, `R2`
    /// apart and logged nowhere; its arguments must be the call's
    /// recorded, byte for byte. Only the signer posts it: a device under
    /// its sync key, the kit under its own.
    #[msg(gas = 40_000_000)]
    pub async fn evidence(
        &mut self,
        ctx: &mut Command<Self>,
        index: u64,
        message: Vec<u8>,
        signature: [u8; 64],
        attached: Attached,
    ) -> Result<Recorded, PersonalError> {
        let now = self.settle(ctx.now())?;
        self.assigned()?;
        let caller = match self.holder(ctx.caller()) {
            Some((_, Holder::Kit(entry))) => Signer::Kit(entry),
            _ => Signer::Device(self.sync_caller(ctx.caller(), now)?),
        };
        let entry = self.log.get(&index).ok_or(PersonalError::NotAdminCall)?;
        let (call, by, welcome_named, r2_named) = match entry.body {
            Body::Operation { call, by, op, .. } => {
                let r2 = match op {
                    Op::Rotate(kit) | Op::Restore { kit, .. } => Some(kit.r2_hash),
                    _ => None,
                };
                (call, by, None, r2)
            }
            Body::Candidate { call, by, .. } => {
                let commit = personal::Commit::decode_exact(&call.arguments)
                    .ok_or(PersonalError::Malformed)?;
                let r2 = commit.effect.rekey.map(|kit| kit.r2_hash);
                (call, Signer::Device(by), commit.welcome_hash, r2)
            }
            Body::Veto { call, by, .. } => (call, Signer::Device(by), None, None),
            Body::Cosign { call, by, .. } | Body::Resolve { call, by, .. } => {
                (call, by, None, None)
            }
            _ => return Err(PersonalError::NotAdminCall),
        };
        let origin = match self.holder(ctx.caller()) {
            Some((key, Holder::Kit(_))) => Some(key),
            _ => None,
        };
        if by != caller || origin.is_some_and(|key| key != call.origin) {
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
        let Attached { welcome, r2 } = attached;
        let welcome = match (welcome_named, welcome) {
            (None, None) => None,
            (Some(named), Some(welcome)) if welcome_hash(&welcome) == named => Some(welcome),
            _ => return Err(PersonalError::Welcome),
        };
        match (r2_named, r2) {
            (None, None) => {}
            (Some(named), Some(r2)) if r2_hash(&r2) == named => {
                let candidate = self
                    .group()
                    .candidate
                    .is_some_and(|candidate| candidate.index == index);
                if self.open.contains(&index) || candidate {
                    self.deposits.insert(&index, &r2);
                }
            }
            _ => return Err(PersonalError::Welcome),
        }
        if let Signer::Device(device) = caller {
            self.seen.insert(&device, &now);
        }
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
    #[msg(gas = 40_000_000)]
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
    #[msg(gas = 40_000_000)]
    pub async fn nack(
        &mut self,
        ctx: &mut Command<Self>,
        epoch: u64,
        signature: [u8; 64],
    ) -> Result<Voted, PersonalError> {
        self.vote(ctx, epoch, Vote::Nack, signature)
    }

    /// The device is alive, which cancels a pending restore: logged at most
    /// once an [`ALIVE_EVERY_MS`] a device, the entry logged last answered
    /// between, so liveness grows the log by a bounded amount however often
    /// it is posted.
    #[msg(gas = 40_000_000)]
    pub async fn alive(&mut self, ctx: &mut Command<Self>) -> Result<Recorded, PersonalError> {
        let now = self.settle(ctx.now())?;
        self.assigned()?;
        let device = self.sync_caller(ctx.caller(), now)?;
        self.seen.insert(&device, &now);
        self.cancel_restore(now);
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
    #[msg(gas = 40_000_000)]
    pub async fn push(
        &mut self,
        ctx: &mut Command<Self>,
        envelope: Vec<u8>,
    ) -> Result<Pushed, PersonalError> {
        let now = self.settle(ctx.now())?;
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
    #[msg(gas = 40_000_000)]
    pub async fn acknowledge(
        &mut self,
        ctx: &mut Command<Self>,
        scope: Scope,
        position: u64,
        hash: [u8; 32],
    ) -> Result<u64, PersonalError> {
        let now = self.settle(ctx.now())?;
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
    #[msg(gas = 40_000_000)]
    pub async fn open_slot(
        &mut self,
        ctx: &mut Command<Self>,
        slot: Scope,
        key: [u8; 32],
    ) -> Result<u64, PersonalError> {
        let now = self.settle(ctx.now())?;
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
        self.fresh(&[key])?;
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
    #[msg(gas = 40_000_000)]
    pub async fn close_slot(
        &mut self,
        ctx: &mut Command<Self>,
        slot: Scope,
    ) -> Result<u64, PersonalError> {
        let now = self.settle(ctx.now())?;
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
    #[msg(gas = 40_000_000)]
    pub async fn put(
        &mut self,
        ctx: &mut Command<Self>,
        to: Recipient,
        id: [u8; 16],
        expires: u64,
        bytes: Vec<u8>,
    ) -> Result<u64, PersonalError> {
        let now = self.settle(ctx.now())?;
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

    /// Settle what batch time decided, a few operations at a time, for any
    /// device's or kit's key the agent admits until now: every other call
    /// refuses with `Settling` while operations are left due. A restore's
    /// device is admitted at ingress only once a call settles its restore,
    /// which the kit's wake does, though the restore replaces the kit.
    #[msg(gas = 40_000_000)]
    pub async fn wake(&mut self, ctx: &mut Command<Self>) -> Result<Woken, PersonalError> {
        self.assigned()?;
        let now = ctx.now();
        // Any key of a device still live, or of the kit: a removal only due
        // may yet be cancelled by what falls due before it.
        let live = |device: DeviceId| {
            self.devices
                .get(&device)
                .is_some_and(|found| found.status == Status::Live)
        };
        match self.holder(ctx.caller()) {
            Some((_, Holder::Sync(device) | Holder::Admin(device))) if live(device) => {}
            Some((_, Holder::Kit(_))) => {}
            _ => return Err(PersonalError::NotAdmitted),
        }
        let settled = self.settle_some(now);
        Ok(Woken { at: now, settled })
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
        let head = self.head.get_or_default();
        Ok(Overview {
            at: now,
            confirmed: group.confirmed,
            candidate: group.candidate.map(|candidate| candidate.pending()),
            next: head.next,
            chain: head.chain,
            lease_until: self.lease.get().map_or(0, |lease| lease.until),
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
            .map(|(id, device)| DeviceView {
                id,
                standing: self.standing(id, &device, now),
                seasoned: self.seasoned(id, now),
                removal: self.removals.get(&id),
                seen: self.seen.get(&id).unwrap_or(0),
                device,
            })
            .collect())
    }

    /// The operations pending or contested after `after`, as much as one
    /// answer holds.
    #[msg]
    pub async fn operations(
        &self,
        ctx: &Query<Self>,
        after: Option<u64>,
    ) -> Result<Vec<(u64, Operation)>, PersonalError> {
        self.reader(ctx.caller(), ctx.now())?.device_or_kit()?;
        let rows = self
            .open
            .iter(after.as_ref())
            .filter_map(|(index, ())| Some((index, self.operations.get(&index)?)));
        Ok(rules::bounded(rows, |row| row.encode().len()))
    }

    /// The operation at `index`, open or not.
    #[msg]
    pub async fn operation(
        &self,
        ctx: &Query<Self>,
        index: u64,
    ) -> Result<Operation, PersonalError> {
        self.reader(ctx.caller(), ctx.now())?.device_or_kit()?;
        self.operations
            .get(&index)
            .ok_or(PersonalError::NoOperation)
    }

    /// The recovery kit: its entries with `R1` sealed to each, where the
    /// recovery scope starts for it, and the previous `R2` and the entries
    /// it went with for the device a matured restore added, which alone
    /// reads them.
    #[msg]
    pub async fn recovery(&self, ctx: &Query<Self>) -> Result<RecoveryView, PersonalError> {
        let reader = self.reader(ctx.caller(), ctx.now())?;
        reader.device_or_kit()?;
        let recovery = self.recovery.get_or_default();
        let released = recovery
            .released
            .filter(|(device, _)| reader == rules::Reader::Device(*device))
            .map(|(_, r2)| r2);
        Ok(RecoveryView {
            entries: self.kit.iter(None).map(|(_, entry)| entry).collect(),
            from: recovery.from,
            previous: if released.is_some() {
                recovery.previous
            } else {
                Vec::new()
            },
            released,
        })
    }

    /// The control log from `from`, as much as one answer holds. A removed
    /// device's sync key reads it through its removal's entry and on while
    /// the entries are within the confirming window after the maturity,
    /// where the evidence its removal rests on is (a cosign's or a
    /// resolution's, posted after the call that matured it): so the device
    /// leaves on the log it verifies, not on a refusal.
    #[msg]
    pub async fn log(
        &self,
        ctx: &Query<Self>,
        from: u64,
    ) -> Result<Vec<(u64, Entry)>, PersonalError> {
        let next = self.head.get_or_default().next;
        let rows = (from..next).filter_map(|index| Some((index, self.log.get(&index)?)));
        match self.reader(ctx.caller(), ctx.now()) {
            Ok(reader) => {
                reader.device_or_kit()?;
                Ok(rules::bounded(rows, |row| row.encode().len()))
            }
            Err(PersonalError::NotAdmitted) => {
                let (logged, until) = self.gone_reach(ctx.caller())?;
                let rows = rows.take_while(|(index, entry)| *index <= logged || entry.at <= until);
                Ok(rules::bounded(rows, |row| row.encode().len()))
            }
            Err(error) => Err(error),
        }
    }

    /// `scope`'s envelopes after `position`, in order, as much as one answer
    /// holds: for the devices, and for the kit the recovery scope's sealed
    /// under its `R`, those after its rotation.
    #[msg]
    pub async fn since(
        &self,
        ctx: &Query<Self>,
        scope: Scope,
        position: u64,
    ) -> Result<Vec<Envelope>, PersonalError> {
        let position = match self.reader(ctx.caller(), ctx.now())? {
            rules::Reader::Device(_) => position,
            rules::Reader::Kit if scope == RECOVERY => {
                position.max(self.recovery.get_or_default().from)
            }
            _ => return Err(PersonalError::NotAdmitted),
        };
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
