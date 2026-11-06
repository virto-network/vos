//! The device set's rules (`light-node.md` §3.5): standing and seasoning,
//! the operations and their delays, vetoes, contests and resolutions, a
//! probation frozen under a removal, and what each operation does when it
//! matures.
//!
//! Batch time decides lazily, as everywhere in `Personal`: each call first
//! matures what fell due, at most [`SETTLE`] operations, and refuses with
//! `Settling` while more are due, which `wake` settles a few at a time; a
//! read computes standing from the time it reads at. So no call's work
//! grows with what an adversary queued, and every operation matures at its
//! own time, however late the call that settles it.

use alloc::vec::Vec;

use vos_sdk::prelude::*;
use vos_wire::personal::{
    AdminCall, AdminClass, Body, Cancel, Device, DeviceId, Holder, KitEntry, NewDevice, Op,
    OpState, Operation, PersonalError, RECOVERY, Recorded, Removal, Signer, Standing, Status,
    Verdict, Void,
};

use crate::rows::{Charge, ONE, Recovery};
use crate::{KIT_ENTRIES, Personal};

/// The operations a call matures before it runs: with the one its own
/// work may mature, each bounded, within its gas.
pub const SETTLE: usize = 1;

/// The open operations a signer holds at once, removals aside: a device's,
/// or a kit entry's. A removal is one open a target.
pub const OPEN_OPERATIONS: usize = 2;

/// The live devices a set holds.
pub const DEVICES: usize = 8;

/// The kinds of operation of which one is open at a time, for a target or
/// for the agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Remove = 0,
    Replace = 1,
    /// A kit rotation or a restore.
    Kit = 2,
    Regroup = 3,
}

/// The kind an operation is one open of, and its target.
fn kind(op: &Op) -> Option<(u8, DeviceId)> {
    let (kind, target) = match op {
        Op::Remove(target) => (Kind::Remove, *target),
        Op::Replace { device, .. } => (Kind::Replace, *device),
        Op::Rotate(_) | Op::Restore { .. } => (Kind::Kit, 0),
        Op::Regroup(_) => (Kind::Regroup, 0),
        Op::Add(_) => return None,
    };
    Some((kind as u8, target))
}

/// The devices an operation acts on: a removal's and a regroup's targets,
/// and the device whose admin key a replacement replaces.
pub fn targets(op: &Op) -> Vec<DeviceId> {
    match op {
        Op::Replace { device, .. } => Vec::from([*device]),
        _ => removes(op),
    }
}

/// The devices an operation removes when it matures, bar a restore's
/// every one: these freeze a probation while it is open.
fn removes(op: &Op) -> Vec<DeviceId> {
    match op {
        Op::Remove(target) => Vec::from([*target]),
        Op::Regroup(named) => named.clone(),
        _ => Vec::new(),
    }
}

/// Whether an operation matures only with its evidence, which carries its
/// `R2`.
fn needs_r2(op: &Op) -> bool {
    matches!(op, Op::Rotate(_) | Op::Restore { .. })
}

/// A signer as the key of the operations it holds open.
fn signer_key(by: Signer) -> u64 {
    match by {
        Signer::Device(device) => u64::from(device),
        Signer::Kit(entry) => 1 << 32 | u64::from(entry),
    }
}

/// The rows of an ordered table keyed `(A, B)` whose first part is
/// `first`: their second parts and values.
macro_rules! prefixed {
    ($table:expr, $first:expr, $max:expr) => {{
        let first = $first;
        let after = first.checked_sub(1).map(|before| (before, $max));
        $table
            .iter(after.as_ref())
            .take_while(|((at, _), _)| *at == first)
            .map(|((_, second), value)| (second, value))
            .collect::<Vec<_>>()
    }};
}

impl Personal {
    // ===== Standing =====

    /// A device's standing at `now`: its status; then a removal against it
    /// pending and due by `now`, which a call matures; then its probation,
    /// frozen while a removal against it is open.
    pub(crate) fn standing(&self, id: DeviceId, device: &Device, now: u64) -> Standing {
        match device.status {
            Status::Removed { .. } => Standing::Removed,
            Status::Dropped { .. } => Standing::Dropped,
            Status::Live if self.removal_due(id, now) => Standing::Removed,
            Status::Live if self.frozen.contains(&id) || now < device.active_from => {
                Standing::Probation
            }
            Status::Live => Standing::Active,
        }
    }

    pub(crate) fn standing_of(&self, id: DeviceId, now: u64) -> Option<Standing> {
        let device = self.devices.get(&id)?;
        Some(self.standing(id, &device, now))
    }

    /// Whether an open operation that removes `id` is pending and due by
    /// `now`: none once a call settled what was due, so only a read between
    /// calls looks further.
    fn removal_due(&self, id: DeviceId, now: u64) -> bool {
        if self.due.first().is_none_or(|((at, _), ())| at > now) {
            return false;
        }
        let due = |index: u64| {
            self.operations.get(&index).is_some_and(|operation| {
                operation.state == OpState::Pending
                    && operation.matures <= now
                    && (!needs_r2(&operation.op) || self.deposits.contains(&index))
            })
        };
        let restore = self.kinds.get(&(Kind::Kit as u8, 0)).filter(|index| {
            self.operations
                .get(index)
                .is_some_and(|operation| matches!(operation.op, Op::Restore { .. }))
        });
        prefixed!(self.against, id, u64::MAX)
            .into_iter()
            .any(|(index, ())| due(index))
            || restore.is_some_and(due)
    }

    /// Active for the policy's seasoning.
    pub(crate) fn seasoned(&self, id: DeviceId, now: u64) -> bool {
        self.devices.get(&id).is_some_and(|device| {
            self.standing(id, &device, now) == Standing::Active
                && device
                    .active_from
                    .saturating_add(self.policy().seasoning_ms)
                    <= now
        })
    }

    /// Seasoned with a strong admin: one of the two the two-device rules
    /// need. A delayed admin's signature makes nothing immediate.
    fn two_device(&self, id: DeviceId, now: u64) -> bool {
        self.seasoned(id, now)
            && self
                .devices
                .get(&id)
                .is_some_and(|device| device.keys.class == AdminClass::Strong)
    }

    /// Who signs an admin call: an active device's admin key, or a kit
    /// entry's signing key.
    pub(crate) fn signer(
        &self,
        caller: Principal,
        now: u64,
    ) -> Result<([u8; 32], Signer), PersonalError> {
        match self.holder(caller) {
            Some((key, Holder::Kit(entry))) => Ok((key, Signer::Kit(entry))),
            _ => self
                .admin_caller(caller, now)
                .map(|(key, device)| (key, Signer::Device(device))),
        }
    }

    fn open_at(&self, index: u64) -> Result<Operation, PersonalError> {
        self.operations
            .get(&index)
            .filter(|_| self.open.contains(&index))
            .ok_or(PersonalError::NoOperation)
    }

    // ===== Opening =====

    /// Open `op`, signed by `by` in `call`, pending for its signer's delay:
    /// the kit's, a replacement's (its new key's probation), or a device's
    /// operation's. A removal aimed at a removal its target signed against
    /// its signer makes one contest of the two.
    pub(crate) fn open_operation(
        &mut self,
        now: u64,
        call: AdminCall,
        by: Signer,
        op: Op,
    ) -> Result<Recorded, PersonalError> {
        self.check_operation(now, by, &op)?;
        let removal = matches!(op, Op::Remove(_));
        let held = prefixed!(self.signed, signer_key(by), u64::MAX);
        if !removal && held.iter().filter(|(_, counted)| *counted).count() >= OPEN_OPERATIONS {
            return Err(PersonalError::Operations);
        }
        let device = match by {
            Signer::Device(device) => Some(device),
            Signer::Kit(_) => None,
        };
        if !removal {
            self.charge(now, device, 0, Charge::Commit)?;
        }
        let policy = self.policy();
        let delay = match (by, &op) {
            (Signer::Kit(_), _) => policy.kit_delay_ms,
            (_, Op::Replace { .. }) => policy.probation_ms,
            _ => policy.operation_delay_ms,
        };
        let matures = now.saturating_add(delay);
        let index = self.append(
            now,
            Body::Operation {
                call,
                by,
                op: op.clone(),
                matures,
            },
        );
        let rival = match (&op, device) {
            (Op::Remove(target), Some(signer)) => self
                .kinds
                .get(&(Kind::Remove as u8, signer))
                .filter(|rival| {
                    self.operations
                        .get(rival)
                        .is_some_and(|operation| operation.by == Signer::Device(*target))
                }),
            _ => None,
        };
        for target in removes(&op) {
            self.freeze(target, now);
            self.against.insert(&(target, index), &());
        }
        if let Some(key) = kind(&op) {
            self.kinds.insert(&key, &index);
        }
        self.signed.insert(&(signer_key(by), index), &!removal);
        self.operations.insert(
            &index,
            &Operation {
                by,
                op,
                at: now,
                matures,
                state: OpState::Pending,
            },
        );
        self.open.insert(&index, &());
        match rival {
            Some(rival) => {
                self.rivals.insert(&index, &rival);
                self.rivals.insert(&rival, &index);
                self.contest(index, now);
                self.contest(rival, now);
            }
            None => self.due.insert(&(matures, index), &()),
        }
        if let Some(device) = device {
            self.seen.insert(&device, &now);
        }
        Ok(Recorded { at: now, index })
    }

    /// Who may sign `op`, and whether the set allows it now.
    fn check_operation(&self, now: u64, by: Signer, op: &Op) -> Result<(), PersonalError> {
        if kind(op).is_some_and(|key| self.kinds.contains(&key)) {
            return Err(PersonalError::Pending);
        }
        match op {
            Op::Add(keys) => {
                if matches!(by, Signer::Kit(_)) {
                    return Err(PersonalError::NotSigner);
                }
                if self.lapsed(now) {
                    return Err(PersonalError::Lapsed);
                }
                self.fresh(&[keys.sync, keys.admin])
            }
            Op::Remove(target) => self.live(*target, now),
            Op::Replace { device, admin } => {
                self.live(*device, now)?;
                if let Signer::Device(signer) = by {
                    if signer == *device {
                        return Err(PersonalError::Targeted);
                    }
                    if !self.seasoned(signer, now) {
                        return Err(PersonalError::Unseasoned);
                    }
                }
                self.fresh(&[admin.key])
            }
            Op::Rotate(kit) => self.check_kit(&kit.entries, &[]),
            Op::Regroup(named) => {
                let Signer::Device(signer) = by else {
                    return Err(PersonalError::NotSigner);
                };
                if !self.seasoned(signer, now) {
                    return Err(PersonalError::Unseasoned);
                }
                if named.contains(&signer) {
                    return Err(PersonalError::Targeted);
                }
                for (i, device) in named.iter().enumerate() {
                    if named[..i].contains(device) {
                        return Err(PersonalError::Malformed);
                    }
                    self.live(*device, now)?;
                }
                Ok(())
            }
            Op::Restore { device, kit } => {
                if matches!(by, Signer::Device(_)) {
                    return Err(PersonalError::NotSigner);
                }
                self.check_kit(&kit.entries, &[device.sync, device.admin])
            }
        }
    }

    /// A device in probation or active.
    fn live(&self, device: DeviceId, now: u64) -> Result<(), PersonalError> {
        match self.standing_of(device, now) {
            None => Err(PersonalError::UnknownDevice),
            Some(Standing::Probation | Standing::Active) => Ok(()),
            Some(_) => Err(PersonalError::Removed),
        }
    }

    /// Keys distinct and admitted to no one.
    fn fresh(&self, keys: &[[u8; 32]]) -> Result<(), PersonalError> {
        for (i, key) in keys.iter().enumerate() {
            if keys[..i].contains(key) || self.admitted.contains(key) {
                return Err(PersonalError::KeyTaken);
            }
        }
        Ok(())
    }

    /// A new kit's entries, and with them `more` keys, fresh.
    fn check_kit(&self, entries: &[KitEntry], more: &[[u8; 32]]) -> Result<(), PersonalError> {
        if entries.is_empty() || entries.len() > KIT_ENTRIES {
            return Err(PersonalError::Malformed);
        }
        let mut keys = Vec::from(more);
        keys.extend(entries.iter().map(|entry| entry.signing));
        self.fresh(&keys)
    }

    /// Freeze `device`'s probation, if it is in one: what is left of it
    /// runs again once no removal against it is open.
    fn freeze(&mut self, device: DeviceId, now: u64) {
        if let Some(found) = self.devices.get(&device)
            && found.status == Status::Live
            && now < found.active_from
            && !self.frozen.contains(&device)
        {
            self.frozen.insert(&device, &(found.active_from - now));
        }
    }

    /// Let `device`'s frozen probation run again from `now` when no removal
    /// against it is open.
    fn thaw(&mut self, device: DeviceId, now: u64) {
        let Some(left) = self.frozen.get(&device) else {
            return;
        };
        if !prefixed!(self.against, device, u64::MAX).is_empty() {
            return;
        }
        self.frozen.remove(&device);
        if let Some(mut found) = self.devices.get(&device)
            && found.status == Status::Live
        {
            found.active_from = now.saturating_add(left);
            self.devices.insert(&device, &found);
        }
    }

    // ===== Vetoes, second signatures and resolutions =====

    /// `device`'s veto of the operation at `index`: the kit's is cancelled,
    /// a device's contested.
    pub(crate) fn veto_operation(
        &mut self,
        now: u64,
        call: AdminCall,
        device: DeviceId,
        index: u64,
    ) -> Result<Recorded, PersonalError> {
        let operation = self.open_at(index)?;
        if self.vetoes.contains(&(index, device)) {
            return Err(PersonalError::Vetoed);
        }
        let at = self.append(
            now,
            Body::Veto {
                call,
                by: device,
                op: index,
            },
        );
        match operation.by {
            Signer::Kit(_) => self.cancel(index, Cancel::Veto, now),
            Signer::Device(_) => {
                self.vetoes.insert(&(index, device), &());
                self.vetoed.insert(&(device, index), &());
                if operation.state == OpState::Pending {
                    self.contest(index, now);
                }
            }
        }
        self.seen.insert(&device, &now);
        Ok(Recorded { at: now, index: at })
    }

    /// The second signature that makes the operation at `index` immediate:
    /// a removal, a kit rotation or a regroup, signed by two seasoned
    /// devices with strong admins other than its targets, or a regroup by
    /// its device and the kit. It matures now, contested or not.
    pub(crate) fn cosign_operation(
        &mut self,
        now: u64,
        call: AdminCall,
        by: Signer,
        index: u64,
    ) -> Result<Recorded, PersonalError> {
        let operation = self.open_at(index)?;
        let Signer::Device(signer) = operation.by else {
            return Err(PersonalError::NotSigner);
        };
        let regroup = matches!(operation.op, Op::Regroup(_));
        let cosignable = regroup || matches!(operation.op, Op::Remove(_) | Op::Rotate(_));
        if by == operation.by || !cosignable {
            return Err(PersonalError::NotSigner);
        }
        let targets = targets(&operation.op);
        match by {
            Signer::Device(device) => {
                if targets.contains(&device) || targets.contains(&signer) {
                    return Err(PersonalError::Targeted);
                }
                if !self.two_device(device, now) || !self.two_device(signer, now) {
                    return Err(PersonalError::Unseasoned);
                }
                self.seen.insert(&device, &now);
            }
            Signer::Kit(_) if regroup => {
                if !self.seasoned(signer, now) {
                    return Err(PersonalError::Unseasoned);
                }
            }
            Signer::Kit(_) => return Err(PersonalError::NotSigner),
        }
        let at = self.append(
            now,
            Body::Cosign {
                call,
                by,
                op: index,
            },
        );
        self.mature(index, now, now);
        Ok(Recorded { at: now, index: at })
    }

    /// A resolution of the contest of the operation at `index`: `upheld`,
    /// it matures and its rival is dropped; else it is dropped and its
    /// rival matures. The kit's acts at once; a device's, one of two
    /// seasoned devices with strong admins other than the contest's
    /// targets, acts when the second agrees.
    pub(crate) fn resolve_operation(
        &mut self,
        now: u64,
        call: AdminCall,
        by: Signer,
        index: u64,
        upheld: bool,
    ) -> Result<Recorded, PersonalError> {
        let operation = self.open_at(index)?;
        if operation.state != OpState::Contested {
            return Err(PersonalError::Uncontested);
        }
        let rival = self.rivals.get(&index);
        let winner = if upheld { Some(index) } else { rival };
        let contest = rival.map_or(index, |rival| rival.min(index));
        let decided = match by {
            Signer::Kit(_) => true,
            Signer::Device(device) => {
                let mut targets = targets(&operation.op);
                if let Some(rival) = rival.and_then(|rival| self.operations.get(&rival)) {
                    targets.extend(removes(&rival.op));
                }
                if targets.contains(&device) {
                    return Err(PersonalError::Targeted);
                }
                if !self.two_device(device, now) {
                    return Err(PersonalError::Unseasoned);
                }
                self.resolutions.insert(&(contest, device), &winner);
                self.seen.insert(&device, &now);
                prefixed!(self.resolutions, contest, DeviceId::MAX)
                    .into_iter()
                    .filter(|(other, named)| *named == winner && self.two_device(*other, now))
                    .count()
                    >= 2
            }
        };
        let at = self.append(
            now,
            Body::Resolve {
                call,
                by,
                op: index,
                upheld,
            },
        );
        if decided {
            match winner {
                Some(winner) => self.mature(winner, now, now),
                None => self.cancel(index, Cancel::Resolved, now),
            }
        }
        Ok(Recorded { at: now, index: at })
    }

    /// A device's `alive` cancels a pending restore, which asserts every
    /// device lost.
    pub(crate) fn cancel_restore(&mut self, now: u64) {
        if let Some(index) = self.kinds.get(&(Kind::Kit as u8, 0))
            && let Some(operation) = self.operations.get(&index)
            && matches!(operation.op, Op::Restore { .. })
        {
            self.cancel(index, Cancel::Alive, now);
        }
    }

    // ===== Settling =====

    /// Mature at most `most` operations due by `now`, in the order they
    /// fell due: whether none is left due.
    pub(crate) fn mature_due(&mut self, now: u64, most: usize) -> bool {
        for _ in 0..most {
            let Some(((at, index), ())) = self.due.first() else {
                return true;
            };
            if at > now {
                return true;
            }
            self.due.remove(&(at, index));
            self.mature(index, at, now);
        }
        self.due.first().is_none_or(|((at, _), ())| at > now)
    }

    /// Contest the open operation at `index`: it waits on a resolution.
    fn contest(&mut self, index: u64, now: u64) {
        let Some(mut operation) = self.operations.get(&index) else {
            return;
        };
        self.due.remove(&(operation.matures, index));
        operation.state = OpState::Contested;
        self.operations.insert(&index, &operation);
        self.settled(now, index, OpState::Contested);
    }

    /// Lift a contest left with no veto of a device with a voice and no
    /// rival: pending again, due no sooner than `at`.
    fn reopen(&mut self, index: u64, at: u64, now: u64) {
        let Some(mut operation) = self.operations.get(&index) else {
            return;
        };
        if operation.state != OpState::Contested
            || self.rivals.contains(&index)
            || !prefixed!(self.vetoes, index, DeviceId::MAX).is_empty()
        {
            return;
        }
        operation.state = OpState::Pending;
        operation.matures = operation.matures.max(at);
        self.operations.insert(&index, &operation);
        self.due.insert(&(operation.matures, index), &());
        self.settled(now, index, OpState::Pending);
    }

    fn settled(&mut self, now: u64, op: u64, state: OpState) {
        self.append(now, Body::Settled { op, state });
    }

    /// Close an open operation: no longer due, its vetoes, resolutions and
    /// rivalry dropped, its targets' probations let run. Answers its rival.
    fn close(&mut self, index: u64, operation: &Operation, now: u64) -> Option<u64> {
        self.open.remove(&index);
        self.due.remove(&(operation.matures, index));
        self.signed.remove(&(signer_key(operation.by), index));
        if let Some(key) = kind(&operation.op) {
            self.kinds.remove(&key);
        }
        for (device, ()) in prefixed!(self.vetoes, index, DeviceId::MAX) {
            self.vetoes.remove(&(index, device));
            self.vetoed.remove(&(device, index));
        }
        let rival = self.rivals.get(&index);
        if let Some(rival) = rival {
            self.rivals.remove(&index);
            self.rivals.remove(&rival);
        }
        let contest = rival.map_or(index, |rival| rival.min(index));
        for (device, _) in prefixed!(self.resolutions, contest, DeviceId::MAX) {
            self.resolutions.remove(&(contest, device));
        }
        for target in removes(&operation.op) {
            self.against.remove(&(target, index));
            self.thaw(target, now);
        }
        rival
    }

    /// Cancel the open operation at `index`; its rival's contest is lifted.
    pub(crate) fn cancel(&mut self, index: u64, why: Cancel, now: u64) {
        let Ok(mut operation) = self.open_at(index) else {
            return;
        };
        let rival = self.close(index, &operation, now);
        self.deposits.remove(&index);
        operation.state = OpState::Cancelled { at: now, why };
        self.operations.insert(&index, &operation);
        self.settled(now, index, operation.state);
        if let Some(rival) = rival {
            self.reopen(rival, now, now);
        }
    }

    /// Mature the open operation at `index`, as of `at`: its rival is
    /// dropped, and it takes effect.
    fn mature(&mut self, index: u64, at: u64, now: u64) {
        let Ok(mut operation) = self.open_at(index) else {
            return;
        };
        let r2 = self.deposits.get(&index);
        let target_left = matches!(operation.op, Op::Remove(target) | Op::Replace { device: target, .. }
            if self.devices.get(&target).is_none_or(|device| device.status != Status::Live));
        if target_left {
            return self.cancel(index, Cancel::Moot, now);
        }
        if needs_r2(&operation.op) && r2.is_none() {
            return self.cancel(index, Cancel::Unevidenced, now);
        }
        if !self.applicable(&operation.op) {
            return self.cancel(index, Cancel::KeyTaken, now);
        }
        let rival = self.close(index, &operation, now);
        self.deposits.remove(&index);
        operation.state = OpState::Matured { at };
        self.operations.insert(&index, &operation);
        self.settled(now, index, operation.state);
        if let Some(rival) = rival {
            self.cancel(rival, Cancel::Resolved, now);
        }
        let r2 = r2.unwrap_or_default();
        match operation.op {
            Op::Add(_) => self.ready.insert(&index, &()),
            Op::Remove(target) => self.remove_device(target, index, at, now),
            Op::Replace { device, admin } => {
                if let Some(mut found) = self.devices.get(&device) {
                    self.admitted.remove(&found.keys.admin);
                    self.admitted.insert(&admin.key, &Holder::Admin(device));
                    found.keys.admin = admin.key;
                    found.keys.class = admin.class;
                    found.keys.attestation = admin.attestation;
                    self.devices.insert(&device, &found);
                }
            }
            Op::Rotate(kit) => {
                self.replace_kit(&kit.entries, r2);
                self.recovery.insert(
                    &ONE,
                    &Recovery {
                        from: self.scopes.get(&RECOVERY).unwrap_or(0),
                        released: None,
                    },
                );
            }
            Op::Regroup(named) => {
                for device in named {
                    self.remove_device(device, index, at, now);
                }
                self.new_group(now);
            }
            Op::Restore { device, kit } => {
                let previous = self.secrets.get(&ONE);
                let open: Vec<u64> = self.open.iter(None).map(|(index, ())| index).collect();
                for other in open {
                    self.cancel(other, Cancel::Restored, now);
                }
                let live: Vec<DeviceId> = self.live.iter(None).map(|(id, ())| id).collect();
                for id in live {
                    self.remove_device(id, index, at, now);
                }
                self.new_group(now);
                self.replace_kit(&kit.entries, r2);
                let added = self.add_device(at, at, device).ok();
                if let Some(added) = added {
                    self.seen.insert(&added, &now);
                }
                self.recovery.insert(
                    &ONE,
                    &Recovery {
                        from: self.scopes.get(&RECOVERY).unwrap_or(0),
                        released: added.zip(previous),
                    },
                );
            }
        }
    }

    /// Whether the keys an operation brings are still admitted to no one,
    /// those its own maturity releases aside: a restore's devices' and
    /// kit's, a rotation's kit's.
    fn applicable(&self, op: &Op) -> bool {
        let taken = |key: &[u8; 32]| match self.admitted.get(key) {
            None => false,
            Some(Holder::Kit(_)) => !matches!(op, Op::Restore { .. } | Op::Rotate(_)),
            Some(Holder::Sync(_) | Holder::Admin(_)) => !matches!(op, Op::Restore { .. }),
            Some(Holder::Slot(_)) => true,
        };
        match op {
            Op::Replace { admin, .. } => !taken(&admin.key),
            Op::Rotate(kit) => !kit.entries.iter().any(|entry| taken(&entry.signing)),
            Op::Restore { device, kit } => {
                !(taken(&device.sync)
                    || taken(&device.admin)
                    || kit.entries.iter().any(|entry| taken(&entry.signing)))
            }
            Op::Add(_) | Op::Remove(_) | Op::Regroup(_) => true,
        }
    }

    /// The kit replaced by `entries`, its `R2` by `r2`: the previous
    /// entries' keys admitted no more.
    fn replace_kit(&mut self, entries: &[KitEntry], r2: [u8; 32]) {
        let previous: Vec<(u8, KitEntry)> = self.kit.iter(None).collect();
        for (i, entry) in previous {
            if self.admitted.get(&entry.signing) == Some(Holder::Kit(i)) {
                self.admitted.remove(&entry.signing);
            }
            self.kit.remove(&i);
        }
        for (i, entry) in entries.iter().enumerate() {
            self.admitted.insert(&entry.signing, &Holder::Kit(i as u8));
            self.kit.insert(&(i as u8), entry);
        }
        self.secrets.insert(&ONE, &r2);
    }

    /// A regroup or a restore starts a new group: the pending candidate,
    /// the old group's, is void.
    fn new_group(&mut self, now: u64) {
        if self.group().candidate.is_some() {
            self.decide(now, Verdict::Void(Void::Regroup));
        }
    }

    /// `target`'s removal matured at `at` by the operation at `index`: its
    /// keys admitted no more, and it has no voice. Its open operations are
    /// cancelled and its vetoes count no more; a pending candidate it was
    /// to confirm is decided as of `at` by the others' votes.
    fn remove_device(&mut self, target: DeviceId, index: u64, at: u64, now: u64) {
        let Some(mut device) = self.devices.get(&target) else {
            return;
        };
        if device.status != Status::Live {
            return;
        }
        device.status = Status::Removed { at };
        self.admitted.remove(&device.keys.sync);
        self.admitted.remove(&device.keys.admin);
        self.devices.insert(&target, &device);
        self.live.remove(&target);
        self.removals.insert(
            &target,
            &Removal {
                index,
                at,
                committed: None,
            },
        );
        self.frozen.remove(&target);
        self.append(now, Body::Matured { device: target });
        for (other, _) in prefixed!(self.signed, signer_key(Signer::Device(target)), u64::MAX) {
            self.cancel(other, Cancel::Signer, now);
        }
        for (vetoed, ()) in prefixed!(self.vetoed, target, u64::MAX) {
            self.vetoed.remove(&(target, vetoed));
            self.vetoes.remove(&(vetoed, target));
            self.reopen(vetoed, at, now);
        }
        if let Some(candidate) = self.group().candidate
            && candidate.set.contains(&target)
            && at
                <= candidate
                    .created
                    .saturating_add(self.policy().confirm_window_ms)
            && let Some(verdict) = self.verdict(at)
        {
            self.decide(now, verdict);
        }
    }

    /// The matured add operation, not yet carried, whose device has `keys`.
    pub(crate) fn ready_add(&self, keys: &NewDevice) -> Option<u64> {
        self.ready.iter(None).find_map(|(index, ())| {
            let operation = self.operations.get(&index)?;
            (operation.op == Op::Add(keys.clone())).then_some(index)
        })
    }

    /// A confirmed commit carried the add operation at `index`.
    pub(crate) fn carried(&mut self, index: u64, epoch: u64) {
        self.ready.remove(&index);
        if let Some(mut operation) = self.operations.get(&index) {
            operation.state = OpState::Carried { epoch };
            self.operations.insert(&index, &operation);
        }
    }
}
