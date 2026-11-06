//! The device set's operations as a device checks them (`light-node.md`
//! §3.5): each admin call of the set checked against its signer and its
//! evidence, and each maturity the log asserts honoured only once the
//! evidence supports it: its delay passed unvetoed, or a second signature,
//! or a resolution, each verified.

use vos_wire::Encode;
use vos_wire::ingress::CallMessage;
use vos_wire::personal::{AdminCall, AdminClass, DeviceId, Op, Signer};

use super::follow::verifies;
use super::{Act, Alarm, Call, Check, Claim, DeviceGroup, Event, GroupError, Support};
use crate::call::method_id;

/// The method an operation's admin call names, and its arguments as the
/// agent encodes them.
fn signed_as(op: &Op) -> (&'static str, Vec<u8>) {
    match op {
        Op::Add(device) => ("add", device.encode()),
        Op::Remove(target) => ("remove", target.encode()),
        Op::Replace { device, admin } => ("replace", (*device, admin.clone()).encode()),
        Op::Rotate(kit) => ("rotate", kit.encode()),
        Op::Regroup(named) => ("regroup", named.encode()),
        Op::Restore { device, kit } => ("restore", (device.clone(), kit.clone()).encode()),
    }
}

/// The devices an operation removes when it matures, a restore's every
/// one aside.
pub(super) fn removes(op: &Op) -> &[DeviceId] {
    match op {
        Op::Remove(target) => core::slice::from_ref(target),
        Op::Regroup(named) => named,
        _ => &[],
    }
}

/// The devices an operation acts on, which sign none of its second
/// signatures or resolutions.
fn targets(op: &Op) -> &[DeviceId] {
    match op {
        Op::Replace { device, .. } => core::slice::from_ref(device),
        _ => removes(op),
    }
}

fn signer(by: Signer) -> Option<DeviceId> {
    match by {
        Signer::Device(device) => Some(device),
        Signer::Kit(_) => None,
    }
}

impl Call {
    fn op(&self) -> Option<(&Op, u64)> {
        match &self.act {
            Act::Op { op, matures } => Some((op, *matures)),
            _ => None,
        }
    }

    fn device(&self) -> Option<DeviceId> {
        signer(self.by)
    }
}

impl DeviceGroup {
    /// Whether `origin` is `by`'s key at `at`: an active device's admin
    /// key, or the kit entry's signing key.
    fn signer_holds(&self, by: Signer, origin: &[u8; 32], at: u64) -> bool {
        match by {
            Signer::Device(device) => {
                self.state.may_sign(device, at)
                    && self
                        .state
                        .known(device)
                        .is_some_and(|known| known.admin == *origin)
            }
            Signer::Kit(entry) => self.state.set.kit.get(usize::from(entry)) == Some(origin),
        }
    }

    /// Seasoned with a strong admin at `at`: one of the two the two-device
    /// rules need.
    fn two_device(&self, device: DeviceId, at: u64) -> bool {
        self.state.seasoned(device, at)
            && self.state.known(device).is_some_and(|known| known.strong)
    }

    /// An admin call of the device set the log holds at `index`: checked
    /// against its signer, what it may sign and the delay it must wait,
    /// and kept until it closes.
    pub(super) fn call(&mut self, index: u64, at: u64, call: AdminCall, by: Signer, act: Act) {
        let policy = &self.state.policy;
        let (name, arguments, allowed) = match &act {
            Act::Op { op, matures } => {
                let (name, arguments) = signed_as(op);
                let delay = match (by, op) {
                    (Signer::Kit(_), _) => policy.kit_delay_ms,
                    (_, Op::Replace { .. }) => policy.probation_ms,
                    _ => policy.operation_delay_ms,
                };
                let device = signer(by);
                let allowed = match op {
                    Op::Add(_) => device.is_some(),
                    Op::Restore { .. } => device.is_none(),
                    Op::Regroup(_) => device.is_some_and(|device| self.state.seasoned(device, at)),
                    Op::Replace { device: target, .. } => device
                        .is_none_or(|device| device != *target && self.state.seasoned(device, at)),
                    Op::Remove(_) | Op::Rotate(_) => true,
                } && device.is_none_or(|device| !targets(op).contains(&device))
                    && *matures >= at.saturating_add(delay);
                (name, arguments, allowed)
            }
            Act::Veto(op) => ("veto", op.encode(), matches!(by, Signer::Device(_))),
            Act::Cosign(op) => ("cosign", op.encode(), true),
            Act::Resolve { op, upheld } => ("resolve", (*op, *upheld).encode(), true),
        };
        let evidence = if allowed
            && call.method == method_id(name)
            && call.arguments == arguments
            && self.signer_holds(by, &call.origin, at)
        {
            Check::Missing
        } else {
            Check::Invalid
        };
        let mut call = Call {
            index,
            at,
            by,
            origin: call.origin,
            act,
            arguments: call.arguments,
            method: call.method,
            evidence,
            rival: None,
        };
        if evidence != Check::Invalid
            && let Some((op, _)) = call.op()
        {
            let targets = removes(op).to_vec();
            for target in &targets {
                self.freeze(*target, at);
            }
            call.rival = self.contest(&call, &targets);
            if let Some(rival) = call.rival
                && let Some(other) = self
                    .state
                    .set
                    .operations
                    .iter_mut()
                    .find(|other| other.index == rival)
            {
                other.rival = Some(index);
            }
        }
        self.state.set.operations.push(call);
    }

    /// The open removal `call`, removing `targets`, makes one contest with,
    /// as the agent pairs them: one of its targets' removal of its signer,
    /// open and in no contest yet.
    fn contest(&self, call: &Call, targets: &[DeviceId]) -> Option<u64> {
        let signer = call.device()?;
        let state = &self.state;
        state.set.operations.iter().find_map(|other| {
            let (theirs, _) = other.op()?;
            let by = other.device()?;
            (other.evidence != Check::Invalid
                && other.rival.is_none()
                && !state.set.closed.contains(&other.index)
                && targets.contains(&by)
                && removes(theirs).contains(&signer))
            .then_some(other.index)
        })
    }

    /// Freeze `device`'s probation, if it is in one, under a removal
    /// opened at `at`.
    fn freeze(&mut self, device: DeviceId, at: u64) {
        if let Some(known) = self.state.known_mut(device)
            && known.frozen.is_none()
            && at < known.active_from
        {
            known.frozen = Some(known.active_from - at);
            known.active_from = u64::MAX;
        }
    }

    /// Let the frozen probations of the targets of the closed operation at
    /// `index` run again from `now`, when no removal against them is open.
    fn thaw(&mut self, index: u64, now: u64) {
        let Some(targets) = self
            .state
            .call_at(index)
            .and_then(Call::op)
            .map(|(op, _)| removes(op).to_vec())
        else {
            return;
        };
        for target in targets {
            let state = &self.state;
            let open = state.set.operations.iter().any(|call| {
                call.evidence != Check::Invalid
                    && !state.set.closed.contains(&call.index)
                    && call
                        .op()
                        .is_some_and(|(op, _)| removes(op).contains(&target))
            });
            if let Some(known) = self.state.known_mut(target)
                && !open
                && let Some(left) = known.frozen.take()
            {
                known.active_from = now.saturating_add(left);
            }
        }
    }

    /// The evidence of the device-set call at `of`: valid when its message
    /// is the call as logged, signed by its origin, for this agent.
    pub(super) fn call_evidence(
        &mut self,
        of: u64,
        message: &[u8],
        signature: &[u8; 64],
        attached: bool,
        events: &mut Vec<Event>,
    ) -> Result<(), GroupError> {
        let agent = self.state.agent;
        let Some(call) = self
            .state
            .set
            .operations
            .iter_mut()
            .find(|call| call.index == of && call.evidence == Check::Missing)
        else {
            return Ok(());
        };
        let valid = !attached
            && CallMessage::parse(message).is_some_and(|signed| {
                signed.identity == agent.identity
                    && signed.session.key == call.origin
                    && signed.instance == agent.instance
                    && signed.method.0 == call.method
                    && signed.arguments == call.arguments
            })
            && verifies(&call.origin, message, signature);
        call.evidence = if valid { Check::Valid } else { Check::Invalid };
        self.support(events)
    }

    /// The log asserts the operation at `op` matured at `at`, in its entry
    /// at `entry`: unsupported if `at` is after the entry's own time.
    pub(super) fn claim(
        &mut self,
        entry: u64,
        op: u64,
        at: u64,
        events: &mut Vec<Event>,
    ) -> Result<(), GroupError> {
        self.state
            .set
            .claims
            .retain(|claim| claim.support == Support::Waiting);
        let operation = self.state.call_at(op).and_then(Call::op);
        let every = operation.is_some_and(|(op, _)| matches!(op, Op::Restore { .. }));
        let removes = operation.map_or_else(Vec::new, |(op, _)| removes(op).to_vec());
        let support = if at > self.state.time {
            events.push(Event::Alarm(Alarm::Unsigned { index: entry }));
            Support::Refused
        } else {
            Support::Waiting
        };
        let rival = self.rival(op);
        self.state.set.claims.push(Claim {
            entry,
            op,
            rival,
            at,
            every,
            removes,
            removed: Vec::new(),
            support,
        });
        self.support(events)
    }

    /// The log's entry at `index` says `device`'s removal matured: by the
    /// maturity the log asserted just before, as far as its evidence
    /// supports it.
    pub(super) fn matured(
        &mut self,
        index: u64,
        device: DeviceId,
        events: &mut Vec<Event>,
    ) -> Result<(), GroupError> {
        let claim = self
            .state
            .set
            .claims
            .last()
            .filter(|claim| claim.every || claim.removes.contains(&device));
        match claim.map(|claim| (claim.support, claim.at)) {
            Some((Support::Held, at)) => self.mature(device, at, events),
            Some((Support::Waiting, _)) => {
                let claim = self.state.set.claims.last_mut().expect("a claim");
                claim.removed.push(device);
                Ok(())
            }
            Some((Support::Refused, _)) => Ok(()),
            None => {
                events.push(Event::Alarm(Alarm::Unsigned { index }));
                Ok(())
            }
        }
    }

    /// `device` has no voice from `at`: what the next commit carries, and
    /// this device out if it is.
    fn mature(
        &mut self,
        device: DeviceId,
        at: u64,
        events: &mut Vec<Event>,
    ) -> Result<(), GroupError> {
        let Some(known) = self.state.known_mut(device) else {
            return Ok(());
        };
        if known.matured.is_some() || known.out {
            return Ok(());
        }
        known.matured = Some(at);
        if self.state.set.fresh == Some(device) {
            // A regrouper removed before its new group: the rule lapses.
            self.state.set.fresh = None;
        }
        if !self.state.set.owed.contains(&device) {
            self.state.set.owed.push(device);
        }
        if self.state.id == Some(device) {
            self.out(events)?;
        }
        Ok(())
    }

    /// Decide every waiting claim the evidence now decides, in the log's
    /// order: a supported one takes effect, an unsupported one alarms. A
    /// claim still waiting a confirm window after its maturity is
    /// unsupported.
    pub(super) fn support(&mut self, events: &mut Vec<Event>) -> Result<(), GroupError> {
        let now = self.state.time;
        let mut decided = Vec::new();
        for (i, claim) in self.state.set.claims.iter().enumerate() {
            if claim.support != Support::Waiting {
                continue;
            }
            let support = match self.supports(claim) {
                Support::Waiting
                    if claim.at.saturating_add(self.state.policy.confirm_window_ms) < now =>
                {
                    Support::Refused
                }
                support => support,
            };
            if support != Support::Waiting {
                decided.push((i, support));
            }
        }
        for (i, support) in decided {
            self.state.set.claims[i].support = support;
            let claim = self.state.set.claims[i].clone();
            match support {
                Support::Held => self.take_effect(&claim, events)?,
                _ => events.push(Event::Alarm(Alarm::Unsigned { index: claim.entry })),
            }
            self.state.set.closed.push(claim.op);
            self.thaw(claim.op, now);
        }
        self.prune();
        Ok(())
    }

    /// Whether the evidence supports `claim`: the operation's own, valid,
    /// and its delay passed with no verified veto of a device with a voice
    /// (and, for a restore, no `alive` since), or a verified second
    /// signature, or verified resolutions naming it.
    fn supports(&self, claim: &Claim) -> Support {
        let state = &self.state;
        if state.set.closed.contains(&claim.op) {
            return Support::Refused;
        }
        let Some(call) = state.call_at(claim.op) else {
            return Support::Refused;
        };
        let Some((op, matures)) = call.op() else {
            return Support::Refused;
        };
        match call.evidence {
            Check::Invalid => return Support::Refused,
            Check::Missing => return Support::Waiting,
            Check::Valid => {}
        }
        let mut waiting = false;
        let before = state
            .set
            .operations
            .iter()
            .filter(|other| other.index < claim.entry);
        let mut vetoed = false;
        for veto in before
            .clone()
            .filter(|other| other.act == Act::Veto(claim.op))
        {
            let voiced = veto
                .device()
                .and_then(|device| state.known(device))
                .is_some_and(|known| {
                    !known.out && known.matured.is_none_or(|matured| matured > claim.at)
                });
            match veto.evidence {
                Check::Valid if voiced => vetoed = true,
                Check::Missing if voiced => waiting = true,
                _ => {}
            }
        }
        let alive = matches!(op, Op::Restore { .. })
            && state.devices.iter().any(|(_, known)| {
                known.matured.is_none_or(|matured| matured > claim.at)
                    && !known.out
                    && known.alive > call.index
            });
        let contested = claim.rival.is_some();
        if matures <= claim.at && !vetoed && !contested && !alive && !waiting {
            return Support::Held;
        }
        for cosign in before
            .clone()
            .filter(|other| other.act == Act::Cosign(claim.op))
        {
            match cosign.evidence {
                Check::Valid if self.cosigns(cosign, call, op) => return Support::Held,
                Check::Missing => waiting = true,
                _ => {}
            }
        }
        // Each device's latest resolution of the contest counts, as the
        // agent keeps it.
        let rival = claim.rival;
        let mut latest: Vec<(DeviceId, Option<u64>, Check, u64)> = Vec::new();
        for resolve in before {
            let Act::Resolve { op: named, upheld } = resolve.act else {
                continue;
            };
            if named != claim.op && Some(named) != rival {
                continue;
            }
            let winner = match (upheld, named == claim.op) {
                (true, _) => Some(named),
                (false, true) => rival,
                (false, false) => Some(claim.op),
            };
            match resolve.by {
                Signer::Kit(_) => match resolve.evidence {
                    Check::Valid if winner == Some(claim.op) => return Support::Held,
                    Check::Missing => waiting = true,
                    _ => {}
                },
                Signer::Device(device) if resolve.evidence != Check::Invalid => {
                    latest.retain(|(other, ..)| *other != device);
                    latest.push((device, winner, resolve.evidence, resolve.at));
                }
                Signer::Device(_) => {}
            }
        }
        let mut resolvers = 0;
        for (device, winner, evidence, at) in latest {
            if winner != Some(claim.op) {
                continue;
            }
            match evidence {
                Check::Valid if self.resolves(device, at, claim) => resolvers += 1,
                Check::Missing => waiting = true,
                _ => {}
            }
        }
        if resolvers >= 2 {
            return Support::Held;
        }
        if waiting {
            Support::Waiting
        } else {
            Support::Refused
        }
    }

    /// Whether `cosign` is a second signature that makes `op`, signed in
    /// `call`, immediate: a removal, a rotation or a regroup by a device,
    /// cosigned by another seasoned device with a strong admin, neither a
    /// target, or a regroup cosigned by the kit.
    fn cosigns(&self, cosign: &Call, call: &Call, op: &Op) -> bool {
        let Some(signer) = call.device() else {
            return false;
        };
        let regroup = matches!(op, Op::Regroup(_));
        if !(regroup || matches!(op, Op::Remove(_) | Op::Rotate(_))) || cosign.by == call.by {
            return false;
        }
        match cosign.by {
            Signer::Device(device) => {
                !targets(op).contains(&device)
                    && !targets(op).contains(&signer)
                    && self.two_device(device, cosign.at)
                    && self.two_device(signer, cosign.at)
            }
            Signer::Kit(_) => regroup && self.state.seasoned(signer, cosign.at),
        }
    }

    /// The open removal contesting the one at `index`.
    fn rival(&self, index: u64) -> Option<u64> {
        let state = &self.state;
        state
            .call_at(index)?
            .rival
            .filter(|rival| !state.set.closed.contains(rival))
    }

    /// Whether `device` may resolve the contest `claim` matured from at
    /// `at`: seasoned with a strong admin, and a target of neither side.
    fn resolves(&self, device: DeviceId, at: u64, claim: &Claim) -> bool {
        let state = &self.state;
        let targeted = |index: u64| {
            state
                .call_at(index)
                .and_then(Call::op)
                .is_some_and(|(op, _)| targets(op).contains(&device))
        };
        self.two_device(device, at)
            && !targeted(claim.op)
            && claim.rival.is_none_or(|rival| !targeted(rival))
    }

    /// A supported maturity's effect on what this device knows.
    fn take_effect(&mut self, claim: &Claim, events: &mut Vec<Event>) -> Result<(), GroupError> {
        let Some(call) = self.state.call_at(claim.op).cloned() else {
            return Ok(());
        };
        let Some((op, _)) = call.op() else {
            return Ok(());
        };
        match op {
            Op::Add(keys) => self.state.set.adds.push(keys.clone()),
            Op::Remove(_) => {}
            Op::Replace { device, admin } => {
                if let Some(known) = self.state.known_mut(*device) {
                    known.admin = admin.key;
                    known.strong = admin.class == AdminClass::Strong;
                }
            }
            Op::Rotate(kit) | Op::Restore { kit, .. } => {
                self.state.set.kit = kit.entries.iter().map(|entry| entry.signing).collect();
            }
            Op::Regroup(_) => self.state.set.fresh = call.device(),
        }
        for device in &claim.removed {
            self.mature(*device, claim.at, events)?;
        }
        Ok(())
    }

    /// Drop the calls of the operations closed, once no claim waits on
    /// them.
    pub(super) fn prune(&mut self) {
        let state = &mut self.state;
        if state
            .set
            .claims
            .iter()
            .any(|claim| claim.support == Support::Waiting)
        {
            return;
        }
        let closed = std::mem::take(&mut state.set.closed);
        state.set.operations.retain(|call| {
            let of = match call.act {
                Act::Op { .. } => call.index,
                Act::Veto(op) | Act::Cosign(op) | Act::Resolve { op, .. } => op,
            };
            !closed.contains(&of)
        });
    }

    /// `device`'s voice at `cutoff`: no matured removal, and no open
    /// removal of it with verified evidence due by then, unvetoed and
    /// uncontested.
    pub(super) fn voiced_at(&self, device: DeviceId, cutoff: u64) -> bool {
        let state = &self.state;
        state.voiced(device)
            && !state.set.operations.iter().any(|call| {
                call.evidence == Check::Valid
                    && !state.set.closed.contains(&call.index)
                    && matches!(&call.act, Act::Op { op, matures }
                        if *matures <= cutoff && removes(op).contains(&device))
                    && self.rival(call.index).is_none()
                    && !state.set.operations.iter().any(|veto| {
                        veto.act == Act::Veto(call.index)
                            && veto.evidence != Check::Invalid
                            && veto.device().is_some_and(|device| state.voiced(device))
                    })
            })
    }

    /// The log closed the operation at `op` without its maturity.
    pub(super) fn cancelled(&mut self, op: u64) {
        self.state.set.closed.push(op);
        self.thaw(op, self.state.time);
        self.prune();
    }
}
