//! What `Personal`'s handlers share: who the caller is to the device set,
//! the log, maturity and verdicts settled lazily on batch time, and the
//! quotas.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use vos_sdk::prelude::*;
use vos_wire::personal::{
    ANSWER_BYTES, Author, Body, DAY_MS, Device, DeviceId, Entry, Holder, Item, NewDevice,
    PersonalError, Policy, Recipient, Removal, Scope, Standing, Status, Verdict, Void, Vote, Voted,
    chain,
};

use crate::Personal;
use crate::rows::{Charge, Group, Head, ONE, Share, Slot, Usage};

/// A device's standing at `now`: its status, then a matured removal, then
/// its probation.
pub fn standing(device: &Device, removal: Option<&Removal>, now: u64) -> Standing {
    match device.status {
        Status::Removed { .. } => Standing::Removed,
        Status::Dropped { .. } => Standing::Dropped,
        Status::Live if removal.is_some_and(|removal| removal.matures <= now) => Standing::Removed,
        Status::Live if now < device.active_from => Standing::Probation,
        Status::Live => Standing::Active,
    }
}

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
    pub(crate) fn policy(&self) -> Policy {
        self.policy.get(&ONE).unwrap_or(Policy::DEFAULT)
    }

    pub(crate) fn group(&self) -> Group {
        self.group.get(&ONE).unwrap_or_default()
    }

    pub(crate) fn usage(&self) -> Usage {
        self.usage.get(&ONE).unwrap_or_default()
    }

    /// Refuse every call until a claim assigned the agent.
    pub(crate) fn assigned(&self) -> Result<(), PersonalError> {
        if self.lease.contains(&ONE) {
            Ok(())
        } else {
            Err(PersonalError::Unassigned)
        }
    }

    /// Whether the lease lapsed: the agent is in its grace.
    pub(crate) fn lapsed(&self, now: u64) -> bool {
        self.lease.get(&ONE).is_some_and(|lease| lease.until < now)
    }

    /// Append `body` to the control log at `at`: its index.
    pub(crate) fn append(&mut self, at: u64, body: Body) -> u64 {
        let mut head: Head = self.head.get(&ONE).unwrap_or_default();
        let index = head.next;
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
        self.head.insert(&ONE, &head);
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
        self.group.insert(&ONE, &group);
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

    fn standing_of(&self, device: DeviceId, now: u64) -> Option<Standing> {
        let found = self.devices.get(&device)?;
        Some(standing(&found, self.removals.get(&device).as_ref(), now))
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
    /// sync key, a device in probation, and one whose removal matured, sign
    /// no admin call.
    pub(crate) fn admin_caller(
        &self,
        caller: Principal,
        now: u64,
    ) -> Result<([u8; 32], DeviceId), PersonalError> {
        match self.holder(caller) {
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

    /// Settle what batch time decided since the last call: removals that
    /// matured (their keys admitted no more, each logged), a few slots and
    /// inbox items that expired, and the pending candidate's verdict, as
    /// its window's end would have decided it. Answers `now`.
    pub(crate) fn settle(&mut self, now: u64) -> u64 {
        let mut matured = false;
        while let Some(((at, device), ())) = self.maturing.first() {
            if at > now {
                break;
            }
            self.maturing.remove(&(at, device));
            if let Some(mut found) = self.devices.get(&device)
                && found.status == Status::Live
            {
                found.status = Status::Removed { at };
                self.admitted.remove(&found.keys.sync);
                self.admitted.remove(&found.keys.admin);
                self.devices.insert(&device, &found);
                self.append(now, Body::Matured { device });
                matured = true;
            }
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
        if let Some(candidate) = self.group().candidate {
            let deadline = candidate
                .created
                .saturating_add(self.policy().confirm_window_ms);
            if matured && let Some(verdict) = self.verdict(now.min(deadline)) {
                self.decide(now, verdict);
            } else if deadline <= now {
                self.decide(now, Verdict::Void(Void::Timeout));
            }
        }
        now
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
    pub(crate) fn check_removals(
        &self,
        now: u64,
        remove: &[DeviceId],
    ) -> Result<(), PersonalError> {
        let named: BTreeSet<DeviceId> = remove.iter().copied().collect();
        if named.len() != remove.len() {
            return Err(PersonalError::Malformed);
        }
        let owed: BTreeSet<DeviceId> = self
            .removals
            .iter(None)
            .filter(|(device, removal)| {
                removal.matures <= now
                    && removal.committed.is_none()
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
        self.devices
            .iter(None)
            .filter(|(id, device)| {
                !removing.contains(id)
                    && matches!(
                        standing(device, self.removals.get(id).as_ref(), now),
                        Standing::Probation | Standing::Active
                    )
                    && self.seen.get(id).is_some_and(|seen| seen >= since)
            })
            .map(|(id, _)| id)
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
        let now = self.settle(ctx.now());
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
                    .is_some_and(|removal| removal.matures <= at),
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
    /// the confirmed one and its removals are carried; void, the epoch is
    /// free again and a device it added is dropped.
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
            }
            Verdict::Void(_) => {
                if let Some(added) = candidate.added
                    && let Some(mut device) = self.devices.get(&added)
                {
                    device.status = Status::Dropped { at: now };
                    self.admitted.remove(&device.keys.sync);
                    self.admitted.remove(&device.keys.admin);
                    self.devices.insert(&added, &device);
                }
            }
        }
        self.group.insert(&ONE, &group);
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
        let mut usage = self.usage();
        if usage.day != day {
            usage = Usage {
                day,
                envelopes: 0,
                commits: 0,
                ..usage
            };
        }
        let reproved = self.lease.get(&ONE).is_some_and(|lease| lease.reproved);
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
            if self.live_devices(now) > 1 {
                let calls = (policy.envelopes_per_day + policy.commits_per_day) / 2;
                if share.bytes.saturating_add(bytes) > quota / 2 || share.calls >= calls {
                    return Err(PersonalError::Quota);
                }
            }
            share.bytes += bytes;
            share.calls += 1;
            self.shares.insert(&device, &share);
        }
        self.usage.insert(&ONE, &usage);
        Ok(())
    }

    pub(crate) fn live_devices(&self, now: u64) -> usize {
        self.devices
            .iter(None)
            .filter(|(id, device)| {
                matches!(
                    standing(device, self.removals.get(id).as_ref(), now),
                    Standing::Probation | Standing::Active
                )
            })
            .count()
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
        self.usage.insert(&ONE, &usage);
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
