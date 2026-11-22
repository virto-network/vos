//! What `Personal`'s handlers share: who the caller is to the device set,
//! the log, maturity and verdicts settled lazily on batch time, and the
//! quotas.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use vos_sdk::context::Method;
use vos_sdk::prelude::*;
use vos_wire::personal::{
    ANSWER_BYTES, Author, Body, DAY_MS, Device, DeviceId, Entry, Holder, Item, Kit, NewDevice,
    PersonalError, Policy, Recipient, Recorded, Scope, Standing, Status, Verdict, Void, Vote,
    Voted, chain,
};

use crate::Personal;
use crate::home::{self, Homes};
use crate::rows::{Charge, Group, Head, Lease, Share, Slot, Usage};

/// Rows while their encodings, `size` each, fit one answer: at least the
/// first.
pub fn bounded<T>(rows: impl Iterator<Item = T>, size: impl Fn(&T) -> usize) -> Vec<T> {
    let mut taken = Vec::new();
    let mut bytes = 0;
    for row in rows {
        bytes += size(&row);
        if bytes > ANSWER_BYTES && !taken.is_empty() {
            break;
        }
        taken.push(row);
    }
    taken
}

/// Who reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reader {
    Device(DeviceId),
    Kit,
    Slot(Scope),
}

impl Reader {
    pub fn device_or_kit(self) -> Result<(), PersonalError> {
        match self {
            Reader::Device(_) | Reader::Kit => Ok(()),
            Reader::Slot(_) => Err(PersonalError::NotAdmitted),
        }
    }
}

impl Personal {
    /// A claim's assignment at `now`: its device, the first, active at
    /// once, and its kit; checked whole before anything is written.
    pub(crate) fn take(
        &mut self,
        now: u64,
        device: NewDevice,
        kit: Kit,
    ) -> Result<Recorded, PersonalError> {
        if self.lease.is_set() {
            return Err(PersonalError::Assigned);
        }
        if kit.entries.len() > crate::KIT_ENTRIES {
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
        self.secrets.set(&kit.r2);
        let lease_ms = self.policy().lease_ms;
        self.lease.set(&Lease {
            until: now.saturating_add(lease_ms),
            reproved: false,
            claimed: now,
        });
        self.seen.insert(&first, &now);
        let kit = kit.entries.iter().map(|entry| entry.signing).collect();
        let index = self.append(now, Body::Assigned { device: first, kit });
        Ok(Recorded { at: now, index })
    }

    /// Tell the home's `Homes` `message`, if a claim through it assigned
    /// the agent; delivered once the step commits.
    pub(crate) fn tell_home<M: Method<Actor = Homes>>(&self, message: M) {
        if let Some((agent, instance)) = self.home.get() {
            vos_sdk::host::send(agent, instance, M::ID, &message.encode());
        }
    }

    pub(crate) fn policy(&self) -> Policy {
        self.policy.get().unwrap_or(Policy::DEFAULT)
    }

    pub(crate) fn group(&self) -> Group {
        self.group.get_or_default()
    }

    pub(crate) fn usage(&self) -> Usage {
        self.usage.get_or_default()
    }

    /// Refuse every call until a claim assigned the agent.
    pub(crate) fn assigned(&self) -> Result<(), PersonalError> {
        if self.lease.is_set() {
            Ok(())
        } else {
            Err(PersonalError::Unassigned)
        }
    }

    /// Whether the lease lapsed: the agent is in its grace.
    pub(crate) fn lapsed(&self, now: u64) -> bool {
        self.lease.get().is_some_and(|lease| lease.until < now)
    }

    /// Append `body` to the control log at `at`, an admin call's moving the
    /// floor past it: its index.
    pub(crate) fn append(&mut self, at: u64, body: Body) -> u64 {
        let mut head: Head = self.head.get_or_default();
        let index = head.next;
        let call = matches!(
            body,
            Body::Operation { .. }
                | Body::Candidate { .. }
                | Body::Veto { .. }
                | Body::Cosign { .. }
                | Body::Resolve { .. }
        );
        let linked = chain(&head.chain, index, at, &body);
        self.log.insert(
            &index,
            &Entry {
                at,
                body,
                chain: linked,
            },
        );
        head.next += 1;
        head.chain = linked;
        self.head.set(&head);
        if call {
            self.floor.set(&head.next);
        }
        index
    }

    /// Add a device, in probation until `active_from`, its keys admitted:
    /// its number.
    pub(crate) fn add_device(
        &mut self,
        now: u64,
        active_from: u64,
        keys: NewDevice,
    ) -> Result<DeviceId, PersonalError> {
        let mut group = self.group();
        let id = group.devices;
        group.devices = id.checked_add(1).ok_or(PersonalError::Malformed)?;
        self.group.set(&group);
        self.live.insert(&id, &());
        self.admitted.insert(&keys.sync, &Holder::Sync(id));
        self.admitted.insert(&keys.admin, &Holder::Admin(id));
        self.devices.insert(
            &id,
            &Device {
                keys,
                added: now,
                active_from,
                status: Status::Live,
            },
        );
        Ok(id)
    }

    /// The device a client key belongs to, and what the key is.
    pub(crate) fn holder(&self, caller: Principal) -> Option<([u8; 32], Holder)> {
        match caller {
            Principal::Client(key) => self.admitted.get(&key).map(|holder| (key, holder)),
            _ => None,
        }
    }

    /// How far a removed device's sync key reads the log: through the
    /// entry that logged its removal, and on to the end of the confirming
    /// window after its maturity; any other key is not admitted.
    pub(crate) fn gone_reach(&self, caller: Principal) -> Result<(u64, u64), PersonalError> {
        let Principal::Client(key) = caller else {
            return Err(PersonalError::NotAdmitted);
        };
        let gone = self.gone.get(&key).ok_or(PersonalError::NotAdmitted)?;
        let removal = self
            .removals
            .get(&gone.device)
            .ok_or(PersonalError::NotAdmitted)?;
        let window = self.policy().confirm_window_ms;
        Ok((gone.logged, removal.at.saturating_add(window)))
    }

    /// The device whose sync key calls, in probation or active.
    pub(crate) fn sync_caller(
        &self,
        caller: Principal,
        now: u64,
    ) -> Result<DeviceId, PersonalError> {
        match self.holder(caller) {
            Some((_, Holder::Sync(device))) => match self.standing_of(device, now) {
                Some(Standing::Probation | Standing::Active) => Ok(device),
                _ => Err(PersonalError::Removed),
            },
            _ => Err(PersonalError::NotAdmitted),
        }
    }

    /// The admin key that calls and its device, which must be active: a
    /// sync key, a device in probation or whose add is undecided, and one
    /// whose removal matured, sign no admin call.
    pub(crate) fn admin_caller(
        &self,
        caller: Principal,
        now: u64,
    ) -> Result<([u8; 32], DeviceId), PersonalError> {
        match self.holder(caller) {
            Some((_, Holder::Admin(device))) if self.undecided() == Some(device) => {
                Err(PersonalError::Undecided)
            }
            Some((key, Holder::Admin(device))) => match self.standing_of(device, now) {
                Some(Standing::Active) => Ok((key, device)),
                Some(Standing::Probation) => Err(PersonalError::Probation),
                _ => Err(PersonalError::Removed),
            },
            Some((_, Holder::Sync(_))) => Err(PersonalError::SyncKey),
            _ => Err(PersonalError::NotAdmitted),
        }
    }

    /// Who reads: a live device's sync or admin key, a kit's key, an open
    /// slot's key. Every other caller reads nothing.
    pub(crate) fn reader(&self, caller: Principal, now: u64) -> Result<Reader, PersonalError> {
        match self.holder(caller) {
            Some((_, Holder::Sync(device) | Holder::Admin(device))) => {
                match self.standing_of(device, now) {
                    Some(Standing::Probation | Standing::Active) => Ok(Reader::Device(device)),
                    _ => Err(PersonalError::Removed),
                }
            }
            Some((_, Holder::Kit(_))) => Ok(Reader::Kit),
            Some((_, Holder::Slot(slot))) if self.open_slot_row(slot, now).is_some() => {
                Ok(Reader::Slot(slot))
            }
            _ => Err(PersonalError::NotAdmitted),
        }
    }

    /// Settle what batch time decided since the last call, refusing with
    /// `Settling` while operations are left due: a call runs only on the
    /// device set as of its batch time. Answers `now`.
    pub(crate) fn settle(&mut self, now: u64) -> Result<u64, PersonalError> {
        if self.settle_some(now) {
            Ok(now)
        } else {
            Err(PersonalError::Settling)
        }
    }

    /// Settle a few of the operations due by `now` (a removal's device
    /// admitted no more, each logged) and, once none is left due, a few
    /// slots and inbox items that expired and the pending candidate's
    /// timeout: whether none is left due.
    pub(crate) fn settle_some(&mut self, now: u64) -> bool {
        if !self.mature_due(now, crate::devices::SETTLE) {
            return false;
        }
        for _ in 0..crate::SWEEP {
            let Some(((expires, slot), ())) = self.closing.first() else {
                break;
            };
            if expires > now {
                break;
            }
            match self.slots.get(&slot) {
                Some(open) => self.close_slot_row(slot, &open),
                None => self.closing.remove(&(expires, slot)),
            }
        }
        self.sweep_inbox(now);
        if let Some(candidate) = self.group().candidate
            && candidate
                .created
                .saturating_add(self.policy().confirm_window_ms)
                <= now
        {
            self.decide(now, Verdict::Void(Void::Timeout));
        }
        true
    }

    /// Slot `slot`, if it is open at `now`: an expired one is closed
    /// wherever it is read, whether a call has deleted it yet or not.
    pub(crate) fn open_slot_row(&self, slot: Scope, now: u64) -> Option<Slot> {
        self.slots.get(&slot).filter(|open| open.expires > now)
    }

    /// Close an open slot: its key admitted no more, its items deleted.
    pub(crate) fn close_slot_row(&mut self, slot: Scope, open: &Slot) {
        self.slots.remove(&slot);
        self.closing.remove(&(open.expires, slot));
        if self.admitted.get(&open.key) == Some(Holder::Slot(slot)) {
            self.admitted.remove(&open.key);
        }
        let items: Vec<((u64, [u8; 16]), Item)> = self
            .inbox
            .iter(None)
            .filter(|(_, item)| item.to == Recipient::Slot(slot))
            .collect();
        for (key, item) in items {
            self.drop_item(key, &item);
        }
    }

    /// Close every slot `opener` opened: its add closes them.
    pub(crate) fn close_slots_of(&mut self, opener: DeviceId) {
        let open: Vec<(Scope, Slot)> = self
            .slots
            .iter(None)
            .filter(|(_, slot)| slot.opener == opener)
            .collect();
        for (slot, row) in open {
            self.close_slot_row(slot, &row);
        }
    }

    /// Check that `remove` is exactly the matured removals no confirmed
    /// commit carried yet, each once.
    pub(crate) fn check_removals(&self, remove: &[DeviceId]) -> Result<(), PersonalError> {
        let named: BTreeSet<DeviceId> = remove.iter().copied().collect();
        if named.len() != remove.len() {
            return Err(PersonalError::Malformed);
        }
        let owed: BTreeSet<DeviceId> = self
            .removals
            .iter(None)
            .filter(|(device, removal)| {
                removal.committed.is_none()
                    && self
                        .devices
                        .get(device)
                        .is_some_and(|found| !matches!(found.status, Status::Dropped { .. }))
            })
            .map(|(device, _)| device)
            .collect();
        if let Some(device) = named.difference(&owed).next() {
            return Err(PersonalError::NotMatured(*device));
        }
        if let Some(device) = owed.difference(&named).next() {
            return Err(PersonalError::MissingRemoval(*device));
        }
        Ok(())
    }

    /// The confirming set at `now`: the devices seen by a call within the
    /// window, in probation or active, less those `removing`.
    pub(crate) fn confirming_set(&self, now: u64, removing: &[DeviceId]) -> Vec<DeviceId> {
        let since = now.saturating_sub(self.policy().confirm_window_ms);
        self.live
            .iter(None)
            .map(|(id, ())| id)
            .filter(|id| {
                !removing.contains(id) && self.seen.get(id).is_some_and(|seen| seen >= since)
            })
            .collect()
    }

    /// A vote on `epoch`'s candidate by the calling device's sync key, if
    /// the device is in its set and has a voice.
    pub(crate) fn vote(
        &mut self,
        ctx: &mut Command<Self>,
        epoch: u64,
        vote: Vote,
        signature: [u8; 64],
    ) -> Result<Voted, PersonalError> {
        let now = self.settle(ctx.now())?;
        self.assigned()?;
        let device = self.sync_caller(ctx.caller(), now)?;
        let candidate = self
            .group()
            .candidate
            .filter(|candidate| candidate.epoch == epoch)
            .ok_or(PersonalError::NoCandidate)?;
        if !candidate.set.contains(&device) {
            return Err(PersonalError::NotConfirming);
        }
        if self.votes.contains(&(candidate.index, device)) {
            return Err(PersonalError::Voted);
        }
        self.votes.insert(&(candidate.index, device), &vote);
        self.seen.insert(&device, &now);
        let index = self.append(
            now,
            Body::Vote {
                device,
                epoch,
                candidate: candidate.index,
                vote,
                signature,
            },
        );
        let verdict = self.verdict(now);
        if let Some(verdict) = verdict {
            self.decide(now, verdict);
        }
        Ok(Voted {
            at: now,
            index,
            verdict,
        })
    }

    /// The pending candidate's verdict at `at`, if its set decided it:
    /// counting only the devices of its set whose removal had not matured
    /// by `at`, a nack or a second `h` voids it, and one `h` from every one
    /// confirms it.
    pub(crate) fn verdict(&self, at: u64) -> Option<Verdict> {
        let candidate = self.group().candidate?;
        let mut confirmed = None;
        let mut complete = true;
        for device in &candidate.set {
            let removed = match self.devices.get(device).map(|found| found.status) {
                Some(Status::Removed { at: matured }) => matured <= at,
                _ => self
                    .removals
                    .get(device)
                    .is_some_and(|removal| removal.at <= at),
            };
            if removed {
                continue;
            }
            match self.votes.get(&(candidate.index, *device)) {
                Some(Vote::Nack) => return Some(Verdict::Void(Void::Nack)),
                Some(Vote::Confirm(h)) => match confirmed {
                    Some(other) if other != h => return Some(Verdict::Void(Void::Split)),
                    _ => confirmed = Some(h),
                },
                None => complete = false,
            }
        }
        confirmed.filter(|_| complete).map(Verdict::Confirmed)
    }

    /// Apply `verdict` to the pending candidate: confirmed, its epoch is
    /// the confirmed one and its removals and add operation are carried;
    /// void, the epoch is free again and a device it added is dropped.
    pub(crate) fn decide(&mut self, now: u64, verdict: Verdict) {
        let mut group = self.group();
        let Some(candidate) = group.candidate.take() else {
            return;
        };
        match verdict {
            Verdict::Confirmed(_) => {
                group.confirmed = candidate.epoch;
                for device in &candidate.removes {
                    if let Some(mut removal) = self.removals.get(device) {
                        removal.committed = Some(candidate.epoch);
                        self.removals.insert(device, &removal);
                    }
                }
                if let Some(index) = candidate.carries {
                    self.carried(index, candidate.epoch);
                }
                if let Some(device) = candidate.added.and_then(|added| self.devices.get(&added)) {
                    self.tell_home(home::Record {
                        nullifier: device.keys.nullifier,
                    });
                }
                // The previous R2 is released until the restore's device
                // commits a group of its own.
                let mut recovery = self.recovery.get_or_default();
                if recovery
                    .released
                    .is_some_and(|(device, _)| device == candidate.by)
                {
                    recovery.released = None;
                    recovery.previous = Vec::new();
                    self.recovery.set(&recovery);
                }
                if let Some(rekey) = &candidate.rekey
                    && let Some(r2) = self.deposits.get(&candidate.index)
                {
                    self.reseal(&rekey.entries, r2);
                }
                self.deposits.remove(&candidate.index);
            }
            Verdict::Void(_) => {
                self.deposits.remove(&candidate.index);
                if let Some(added) = candidate.added
                    && let Some(mut device) = self.devices.get(&added)
                {
                    device.status = Status::Dropped { at: now };
                    self.live.remove(&added);
                    self.silence(added, now);
                    self.admitted.remove(&device.keys.sync);
                    self.admitted.remove(&device.keys.admin);
                    self.devices.insert(&added, &device);
                }
            }
        }
        self.group.set(&group);
        self.append(
            now,
            Body::Verdict {
                epoch: candidate.epoch,
                verdict,
            },
        );
    }

    /// Count a call against the quotas: the agent's bytes held and its
    /// daily envelopes and commits, and the device's share of them, half
    /// the agent's while it has another device.
    pub(crate) fn charge(
        &mut self,
        now: u64,
        device: Option<DeviceId>,
        bytes: u64,
        charge: Charge,
    ) -> Result<(), PersonalError> {
        let policy = self.policy();
        let day = now / DAY_MS;
        let mut usage = self.usage().on(day);
        let reproved = self.lease.get().is_some_and(|lease| lease.reproved);
        let quota = if reproved {
            policy.bytes_full
        } else {
            policy.bytes_new
        };
        if usage.bytes.saturating_add(bytes) > quota {
            return Err(PersonalError::Quota);
        }
        match charge {
            Charge::Envelope if usage.envelopes >= policy.envelopes_per_day => {
                return Err(PersonalError::Quota);
            }
            Charge::Commit if usage.commits >= policy.commits_per_day => {
                return Err(PersonalError::Quota);
            }
            Charge::Envelope => usage.envelopes += 1,
            Charge::Commit => usage.commits += 1,
            Charge::Item => usage.items += 1,
        }
        usage.bytes += bytes;
        if let Some(device) = device {
            let mut share = self.shares.get(&device).unwrap_or_default();
            if share.day != day {
                share = Share {
                    day,
                    calls: 0,
                    ..share
                };
            }
            if self.live_devices() > 1 {
                let calls = (policy.envelopes_per_day + policy.commits_per_day) / 2;
                if share.bytes.saturating_add(bytes) > quota / 2 || share.calls >= calls {
                    return Err(PersonalError::Quota);
                }
            }
            share.bytes += bytes;
            share.calls += 1;
            self.shares.insert(&device, &share);
        }
        self.usage.set(&usage);
        Ok(())
    }

    /// Count one of the kit's operations against its daily allowance.
    pub(crate) fn charge_kit(&mut self, now: u64) -> Result<(), PersonalError> {
        let day = now / DAY_MS;
        let mut usage = self.usage().on(day);
        if usage.kit_operations >= self.policy().kit_operations_per_day {
            return Err(PersonalError::Quota);
        }
        usage.kit_operations += 1;
        self.usage.set(&usage);
        Ok(())
    }

    /// The devices in probation or active, once a call settled what was
    /// due.
    pub(crate) fn live_devices(&self) -> usize {
        self.live.iter(None).count()
    }

    /// Delete a few expired inbox items, their bytes released.
    pub(crate) fn sweep_inbox(&mut self, now: u64) {
        for _ in 0..crate::SWEEP {
            let Some(((expires, id), item)) = self.inbox.first() else {
                break;
            };
            if expires > now {
                break;
            }
            self.drop_item((expires, id), &item);
        }
    }

    /// Delete an inbox item, its bytes released.
    fn drop_item(&mut self, key: (u64, [u8; 16]), item: &Item) {
        self.inbox.remove(&key);
        let bytes = item.bytes.len() as u64;
        let mut usage = self.usage();
        usage.bytes = usage.bytes.saturating_sub(bytes);
        usage.items = usage.items.saturating_sub(1);
        self.usage.set(&usage);
        if let Author::Device(device) = item.from
            && let Some(mut share) = self.shares.get(&device)
        {
            share.bytes = share.bytes.saturating_sub(bytes);
            self.shares.insert(&device, &share);
        }
    }

    /// Start every device's share of the bytes held afresh: the agent has
    /// a second live device from now, and a share counts what its device
    /// adds while it has.
    pub(crate) fn restart_shares(&mut self) {
        let shares: Vec<(DeviceId, Share)> = self.shares.iter(None).collect();
        for (device, share) in shares {
            self.shares.insert(&device, &Share { bytes: 0, ..share });
        }
    }
}
