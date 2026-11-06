//! Following the control log: each entry checked against the chain, the
//! pending candidate's evidence and votes verified, the candidate
//! processed on a copy, this device's vote, and the verdict as this device
//! counts it.

use ed25519_dalek::{Signature, VerifyingKey};
use vos_mls::{Expected, Kind};
use vos_wire::Decode;
use vos_wire::ids::MethodId;
use vos_wire::ingress::CallMessage;
use vos_wire::personal::{
    AdminClass, Body, DeviceId, Effect, Entry, Op, Signer, Verdict, Void, Vote, chain, vote_message,
    welcome_hash,
};

use super::{
    Alarm, CONFIRM, Check, Course, DeviceGroup, Event, GroupError, Known, Pending, Processed,
    Remedy, Removal, Why, credential, rows,
};

/// A commit call's arguments: its epoch, effect, handshake and Welcome's
/// hash.
type CommitArguments = ((u64, Effect), (Vec<u8>, Option<[u8; 32]>));

fn verifies(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

impl DeviceGroup {
    /// Read `entries` of the control log, from the cursor on, in order:
    /// what the device must post, and what it saw. An entry that does not
    /// chain stops the reading with [`Alarm::Log`]; entries before the
    /// cursor are skipped, and the reading stops at a gap. The device's
    /// state is written once a confirmed epoch is swapped in and at the
    /// end, each time in one batch with its MLS state.
    pub fn follow(
        &mut self,
        entries: impl IntoIterator<Item = (u64, Entry)>,
    ) -> Result<Vec<Event>, GroupError> {
        let mut events = Vec::new();
        for (index, entry) in entries {
            if self.state.course != Course::Following {
                break;
            }
            if index < self.state.next {
                continue;
            }
            if index > self.state.next {
                break;
            }
            if chain(&self.state.chain, index, entry.at, &entry.body) != entry.chain {
                events.push(Event::Alarm(Alarm::Log { index }));
                break;
            }
            self.state.next += 1;
            self.state.chain = entry.chain;
            self.state.time = self.state.time.max(entry.at);
            self.deadline(entry.at, &mut events)?;
            self.entry(index, entry, &mut events)?;
            self.settle(&mut events)?;
        }
        self.reposts(&mut events);
        self.mls.write(rows(&self.state, Some(&self.archive)))?;
        Ok(events)
    }

    fn entry(
        &mut self,
        index: u64,
        entry: Entry,
        events: &mut Vec<Event>,
    ) -> Result<(), GroupError> {
        let at = entry.at;
        if let Body::Candidate { .. } = entry.body {
            return self.candidate(index, entry, events);
        }
        match entry.body {
            Body::Configured(policy) => self.state.policy = policy,
            Body::Operation {
                call,
                by: Signer::Device(by),
                op: Op::Remove(target),
                matures,
            } => {
                // Only a device with a voice, past its probation, removes
                // another.
                let evidence = if call.method == self.state.agent.remove.0
                    && by != target
                    && self.state.may_sign(by, at)
                {
                    Check::Missing
                } else {
                    Check::Invalid
                };
                self.state.removals.push(Removal {
                    index,
                    by,
                    target,
                    matures,
                    arguments: call.arguments,
                    origin: call.origin,
                    evidence,
                });
            }
            Body::Matured { device } => {
                let signed = self.state.removals.iter().any(|removal| {
                    removal.target == device
                        && removal.evidence == Check::Valid
                        && removal.matures <= at
                });
                if !signed {
                    events.push(Event::Alarm(Alarm::Unsigned { index }));
                    return Ok(());
                }
                if let Some(known) = self.state.known_mut(device) {
                    known.matured = true;
                }
                if self.state.id == Some(device) {
                    self.out(events)?;
                }
            }
            Body::Candidate { .. } => unreachable!("taken above"),
            Body::Evidence {
                index: of,
                message,
                signature,
                welcome,
            } => self.evidence(of, &message, &signature, welcome),
            Body::Vote {
                device,
                epoch,
                candidate,
                vote,
                signature,
            } => self.vote(device, epoch, candidate, vote, &signature, events),
            Body::Verdict { epoch, verdict } => self.verdict(epoch, verdict, events)?,
            Body::Assigned { .. }
            | Body::Renewed { .. }
            | Body::Alive { .. }
            | Body::Operation { .. }
            | Body::Veto { .. }
            | Body::Cosign { .. }
            | Body::Resolve { .. }
            | Body::Settled { .. } => {}
        }
        Ok(())
    }

    /// A candidate entry: its call decoded and checked against what the
    /// device knows of its committer and of the device it adds.
    fn candidate(
        &mut self,
        index: u64,
        entry: Entry,
        events: &mut Vec<Event>,
    ) -> Result<(), GroupError> {
        let Entry {
            at,
            chain,
            body:
                Body::Candidate {
                    call,
                    by,
                    epoch,
                    added,
                    set,
                },
        } = entry
        else {
            unreachable!("a candidate entry")
        };
        if let Some(pending) = &self.state.pending {
            // The agent took the next candidate while this device's count
            // of the last one is undecided: the agent counted votes this
            // device does not hold.
            let (epoch, committer) = (pending.epoch, pending.by);
            events.push(Event::Alarm(Alarm::Verdict { epoch }));
            return self.stick(epoch, committer, events);
        }
        let decoded = CommitArguments::decode_exact(&call.arguments)
            .filter(|((named, _), _)| *named == epoch && call.method == self.state.agent.commit.0);
        let (mut evidence, effect, handshake, welcome_hash) = match decoded {
            Some(((_, effect), (handshake, hash))) => (Check::Missing, effect, handshake, hash),
            None => (Check::Invalid, Effect::default(), Vec::new(), None),
        };
        // The committer has a voice past its probation, an add is a strong
        // admin's and names a new device by a new number.
        let state = &self.state;
        let strong = state
            .known(by)
            .is_some_and(|known| known.keys.class == AdminClass::Strong);
        let fresh = added.is_none_or(|id| state.known(id).is_none());
        if !state.may_sign(by, at)
            || added.is_some() != effect.add.is_some()
            || !fresh
            || (effect.add.is_some() && !strong)
        {
            evidence = Check::Invalid;
        }
        if let Some(own) = &mut self.state.own
            && Some(by) == self.state.id
            && own.index.is_none()
            && own.arguments == call.arguments
        {
            own.index = Some(index);
        }
        let window = self.state.policy.confirm_window_ms;
        if let Some(me) = self.state.id
            && self.state.voiced(me)
            && !set.contains(&me)
            && let Some(last_call) = self
                .state
                .calls
                .iter()
                .rev()
                .find(|call| **call <= at && call.saturating_add(window) >= at)
        {
            events.push(Event::Alarm(Alarm::NamedAbsent {
                epoch,
                last_call: *last_call,
            }));
        }
        self.state.pending = Some(Pending {
            index,
            at,
            epoch,
            by,
            set,
            chain,
            added,
            effect,
            handshake,
            welcome_hash,
            origin: call.origin,
            arguments: call.arguments,
            evidence,
            welcome: None,
            votes: Vec::new(),
            mine: None,
            logged: false,
        });
        Ok(())
    }

    /// Whether `message` and `signature` are the admin call `arguments` of
    /// `method` by `origin`, the admin key of `by`, at this agent.
    fn signed(
        &self,
        by: DeviceId,
        origin: &[u8; 32],
        method: MethodId,
        arguments: &[u8],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        let Some(known) = self.state.known(by) else {
            return false;
        };
        let agent = &self.state.agent;
        let Some(signed) = CallMessage::parse(message) else {
            return false;
        };
        known.keys.admin == *origin
            && signed.identity == agent.identity
            && signed.session.key == *origin
            && signed.instance == agent.instance
            && signed.method == method
            && signed.arguments == arguments
            && verifies(origin, message, signature)
    }

    fn evidence(
        &mut self,
        of: u64,
        message: &[u8],
        signature: &[u8; 64],
        welcome: Option<Vec<u8>>,
    ) {
        if let Some(pending) = &self.state.pending
            && pending.index == of
        {
            if pending.evidence != Check::Missing {
                return;
            }
            let valid = self.signed(
                pending.by,
                &pending.origin,
                self.state.agent.commit,
                &pending.arguments,
                message,
                signature,
            ) && welcome.as_deref().map(welcome_hash) == pending.welcome_hash;
            let pending = self.state.pending.as_mut().expect("pending");
            pending.evidence = if valid { Check::Valid } else { Check::Invalid };
            pending.welcome = welcome;
        } else if let Some(at) = self
            .state
            .removals
            .iter()
            .position(|removal| removal.index == of)
        {
            let removal = &self.state.removals[at];
            if removal.evidence != Check::Missing {
                return;
            }
            let valid = self.signed(
                removal.by,
                &removal.origin,
                self.state.agent.remove,
                &removal.arguments,
                message,
                signature,
            ) && DeviceId::decode_exact(&removal.arguments) == Some(removal.target);
            self.state.removals[at].evidence = if valid { Check::Valid } else { Check::Invalid };
        }
        if let Some(own) = &mut self.state.own
            && own.index == Some(of)
        {
            own.evidenced = true;
        }
    }

    fn vote(
        &mut self,
        device: DeviceId,
        epoch: u64,
        candidate: u64,
        vote: Vote,
        signature: &[u8; 64],
        events: &mut Vec<Event>,
    ) {
        let Some(pending) = &self.state.pending else {
            return;
        };
        if pending.index != candidate
            || pending.epoch != epoch
            || !pending.set.contains(&device)
            || !self.state.voiced(device)
            || pending.votes.iter().any(|(voter, _)| *voter == device)
        {
            return;
        }
        let Some(known) = self.state.known(device) else {
            return;
        };
        let message = vote_message(
            &self.state.agent.identity,
            epoch,
            candidate,
            &pending.chain,
            &vote,
        );
        if !verifies(&known.keys.sync, &message, signature) {
            events.push(Event::Alarm(Alarm::SplitLog { epoch, device }));
            return;
        }
        let me = self.state.id;
        let pending = self.state.pending.as_mut().expect("pending");
        pending.votes.push((device, vote));
        if me == Some(device) {
            pending.logged = true;
        }
    }

    fn verdict(
        &mut self,
        epoch: u64,
        verdict: Verdict,
        events: &mut Vec<Event>,
    ) -> Result<(), GroupError> {
        match &self.state.pending {
            Some(pending) if pending.epoch == epoch => match verdict {
                // A void moves no key: taken from the agent.
                Verdict::Void(void) => {
                    let why = match void {
                        Void::Timeout => Why::Timeout,
                        Void::Nack | Void::Split | Void::Regroup => Why::Agent,
                    };
                    self.void(why, events)?;
                }
                Verdict::Confirmed(_) => events.push(Event::Alarm(Alarm::Verdict { epoch })),
            },
            _ => {
                let confirmed = matches!(verdict, Verdict::Confirmed(_));
                if self
                    .state
                    .decided
                    .is_some_and(|(decided, by_me)| decided == epoch && by_me != confirmed)
                {
                    events.push(Event::Alarm(Alarm::Verdict { epoch }));
                }
            }
        }
        Ok(())
    }

    /// Act on the pending candidate as far as the log allows: process it
    /// once its evidence verifies, vote, and decide it as this device
    /// counts the set's votes, or void it at the window's end by the log's
    /// time.
    fn settle(&mut self, events: &mut Vec<Event>) -> Result<(), GroupError> {
        let Some(pending) = &self.state.pending else {
            return Ok(());
        };
        let index = pending.index;
        let fresh = self.processed.as_ref().is_none_or(|(at, _)| *at != index);
        if fresh && pending.evidence != Check::Missing {
            let processed = self.process()?;
            if matches!(processed, Processed::Refused) {
                let pending = self.state.pending.as_ref().expect("pending");
                events.push(Event::Alarm(Alarm::Refused {
                    epoch: pending.epoch,
                    committer: pending.by,
                }));
            }
            self.processed = Some((index, processed));
        }
        let me = self.state.id;
        let voice = me.filter(|me| self.state.voiced(*me));
        let pending = self.state.pending.as_mut().expect("pending");
        if let (Some(me), None, Some((_, processed))) = (voice, &pending.mine, &self.processed)
            && pending.set.contains(&me)
        {
            pending.mine = match processed {
                Processed::Copy { h: Some(h), .. } => Some(Vote::Confirm(*h)),
                Processed::Refused | Processed::Unable => Some(Vote::Nack),
                Processed::Copy { h: None, .. } | Processed::Ignored => None,
            };
        }
        match self.count(None) {
            Some(Verdict::Confirmed(h)) => self.confirm(h, events),
            Some(Verdict::Void(_)) => {
                let why = self.why();
                self.void(why, events)
            }
            None => Ok(()),
        }
    }

    /// An entry at `at` past the pending candidate's window: the candidate
    /// is decided as of the window's end first, as the agent decides it,
    /// its voices those whose verified removal had not matured by then.
    fn deadline(&mut self, at: u64, events: &mut Vec<Event>) -> Result<(), GroupError> {
        let Some(pending) = &self.state.pending else {
            return Ok(());
        };
        let deadline = pending
            .at
            .saturating_add(self.state.policy.confirm_window_ms);
        if at < deadline {
            return Ok(());
        }
        match self.count(Some(deadline)) {
            Some(Verdict::Confirmed(h)) => self.confirm(h, events),
            Some(Verdict::Void(_)) => {
                let why = self.why();
                self.void(why, events)
            }
            None => self.void(Why::Timeout, events),
        }
    }

    /// The pending candidate's verdict as this device counts the verified
    /// votes of its set's voices: a nack or a second `h` voids it, one `h`
    /// from each confirms it. At `cutoff`, a voice is one whose verified
    /// removal had not matured by then.
    fn count(&self, cutoff: Option<u64>) -> Option<Verdict> {
        let pending = self.state.pending.as_ref()?;
        let mut confirmed = None;
        let mut complete = true;
        let voice = |device: DeviceId| match cutoff {
            Some(cutoff) => self.state.voiced_at(device, cutoff),
            None => self.state.voiced(device),
        };
        for device in pending.set.iter().filter(|device| voice(**device)) {
            match pending.votes.iter().find(|(voter, _)| voter == device) {
                Some((_, Vote::Nack)) => return Some(Verdict::Void(Void::Nack)),
                Some((_, Vote::Confirm(h))) => match confirmed {
                    Some(other) if other != *h => return Some(Verdict::Void(Void::Split)),
                    _ => confirmed = Some(*h),
                },
                None => complete = false,
            }
        }
        confirmed.filter(|_| complete).map(Verdict::Confirmed)
    }

    /// Why the count voids the pending candidate: the first voice that
    /// nacked, else two `h`.
    fn why(&self) -> Why {
        let pending = self.state.pending.as_ref().expect("pending");
        pending
            .set
            .iter()
            .filter(|device| self.state.voiced(**device))
            .find(|device| pending.votes.contains(&(**device, Vote::Nack)))
            .map_or(Why::Split, |device| Why::Nack(*device))
    }

    /// Process the pending candidate on a copy: this device's own commit,
    /// the Welcome of its own add, or another device's commit checked
    /// against the log's operations and processed at the log's time under
    /// its logged effect.
    fn process(&self) -> Result<Processed, GroupError> {
        let pending = self.state.pending.as_ref().expect("pending");
        if pending.evidence != Check::Valid {
            return Ok(Processed::Refused);
        }
        let time = pending.at / 1000;
        let me = &self.state.me;
        let joining = self.state.id.is_none();
        let adds_me = pending
            .effect
            .add
            .as_ref()
            .is_some_and(|add| add.sync == me.sync && add.admin == me.admin);
        let candidate = if joining {
            if !adds_me {
                return Ok(Processed::Ignored);
            }
            let Some(welcome) = &pending.welcome else {
                return Ok(Processed::Refused);
            };
            match self.mls.join(welcome, time) {
                Ok(candidate) => candidate,
                Err(vos_mls::Error::Refused(_)) => return Ok(Processed::Refused),
                Err(error) => return Err(error.into()),
            }
        } else if pending.epoch != self.state.confirmed + 1 {
            return Ok(Processed::Unable);
        } else if self.state.id == Some(pending.by) {
            match self.mls.own(&pending.handshake) {
                Ok(candidate) => candidate,
                Err(vos_mls::Error::NotHeld) => return Ok(Processed::Unable),
                Err(error) => return Err(error.into()),
            }
        } else {
            let Some(expected) = self.expected(pending) else {
                return Ok(Processed::Refused);
            };
            match self.mls.process(&pending.handshake, time, expected) {
                Ok(candidate) => candidate,
                Err(vos_mls::Error::Refused(_)) => return Ok(Processed::Refused),
                Err(error) => return Err(error.into()),
            }
        };
        let candidate = Box::new(candidate);
        if candidate.kind() == Kind::Removed {
            return Ok(Processed::Copy { candidate, h: None });
        }
        if candidate.epoch() != pending.epoch || !self.roster_holds(pending, &candidate) {
            return Ok(Processed::Refused);
        }
        let authenticator = candidate.authenticator()?.ok_or(GroupError::Corrupt)?;
        let h = vos_mls::confirmation(
            CONFIRM,
            &self.state.agent.identity,
            pending.epoch,
            &authenticator,
        );
        Ok(Processed::Copy {
            candidate,
            h: Some(h),
        })
    }

    /// Whether `candidate`'s members are the device set after `pending`:
    /// every device in the group but those it removes, and the one it adds,
    /// each leaf the device's credential. A leaf whose keys changed is
    /// refused.
    fn roster_holds(&self, pending: &Pending, candidate: &vos_mls::Candidate) -> bool {
        let mut want: Vec<Vec<u8>> = self
            .state
            .devices
            .iter()
            .filter(|(id, known)| !known.out && !pending.effect.remove.contains(id))
            .map(|(_, known)| credential(&known.keys))
            .chain(pending.effect.add.iter().map(credential))
            .collect();
        let mut got: Vec<Vec<u8>> = candidate
            .credentials()
            .into_iter()
            .map(|(_, credential)| credential)
            .collect();
        want.sort();
        got.sort();
        want == got
    }

    /// The logged effect another device's commit must be, if its operations
    /// hold: its committer a voice, an add by a strong admin of a device
    /// not in the group, and its removals exactly the matured operations
    /// whose evidence verified.
    fn expected(&self, pending: &Pending) -> Option<Expected> {
        let state = &self.state;
        let committer = state
            .known(pending.by)
            .filter(|_| state.voiced(pending.by))?;
        let mut adds = Vec::new();
        if let Some(add) = &pending.effect.add {
            let known = state
                .devices
                .iter()
                .any(|(_, known)| known.keys.sync == add.sync || known.keys.admin == add.admin);
            if committer.keys.class != AdminClass::Strong || known || add.sync == add.admin {
                return None;
            }
            adds.push(credential(add));
        }
        let mut named = pending.effect.remove.clone();
        named.sort_unstable();
        if named != state.owed() {
            return None;
        }
        let mut removes = Vec::new();
        for device in &named {
            removes.push(credential(&state.known(*device)?.keys));
        }
        Some(Expected {
            committer: credential(&committer.keys),
            adds,
            removes,
        })
    }

    /// The pending candidate confirmed with `h`: its copy swapped in, its
    /// effect on the device set applied and the archive's keys of the new
    /// epoch recorded, in one batch; or, if this device cannot follow it,
    /// the alarm.
    fn confirm(&mut self, h: [u8; 32], events: &mut Vec<Event>) -> Result<(), GroupError> {
        let pending = self.state.pending.take().expect("pending");
        self.state.decided = Some((pending.epoch, true));
        let processed = match self.processed.take() {
            Some((index, processed)) if index == pending.index => Some(processed),
            _ => None,
        };
        let joining = self.state.id.is_none();
        match processed {
            Some(Processed::Copy {
                candidate,
                h: Some(mine),
            }) if mine == h => {
                if candidate.kind() == Kind::Joined {
                    self.state.id = pending.added;
                    self.state.renewed = pending.at;
                }
                if self.state.id == Some(pending.by) {
                    self.state.renewed = pending.at;
                }
                // Its epoch is decided: any commit of this device's for it
                // is void, the swap deleting the held one.
                if self
                    .state
                    .own
                    .as_ref()
                    .is_some_and(|own| own.epoch <= pending.epoch)
                {
                    self.state.own = None;
                }
                self.apply(&pending);
                for scope in self.archive.scopes.clone() {
                    let key = candidate
                        .export(super::archive::SCOPE_LABEL, &scope, 32)?
                        .and_then(|key| <[u8; 32]>::try_from(key).ok())
                        .ok_or(GroupError::Corrupt)?;
                    self.archive.record(pending.epoch, scope, key);
                }
                self.mls
                    .swap(*candidate, rows(&self.state, Some(&self.archive)))?;
                events.push(Event::Confirmed {
                    epoch: pending.epoch,
                });
                Ok(())
            }
            Some(Processed::Copy { candidate, h: None }) => {
                self.apply(&pending);
                self.state.course = Course::Out;
                self.mls.swap(*candidate, rows(&self.state, None))?;
                events.push(Event::Removed);
                Ok(())
            }
            Some(Processed::Ignored) | None if joining => {
                // Another device's commit before this device's add: its
                // operations verified, its effect is the device set's.
                if pending.evidence == Check::Valid {
                    self.apply(&pending);
                }
                Ok(())
            }
            _ => self.stick(pending.epoch, pending.by, events),
        }
    }

    /// A confirmed candidate's effect on the device set: the device it
    /// added known, the devices it removed out, the epoch confirmed.
    fn apply(&mut self, pending: &Pending) {
        if let (Some(id), Some(keys)) = (pending.added, &pending.effect.add) {
            self.state.devices.push((
                id,
                Known {
                    keys: keys.clone(),
                    active_from: pending.at.saturating_add(self.state.policy.probation_ms),
                    matured: false,
                    out: false,
                },
            ));
        }
        for device in &pending.effect.remove {
            if let Some(known) = self.state.known_mut(*device) {
                known.out = true;
            }
        }
        self.state.confirmed = pending.epoch;
    }

    /// The pending candidate void: its copy dropped, and this device's own
    /// commit, if it is, deleted.
    fn void(&mut self, why: Why, events: &mut Vec<Event>) -> Result<(), GroupError> {
        let pending = self.state.pending.take().expect("pending");
        self.state.decided = Some((pending.epoch, false));
        self.processed = None;
        if self.state.id == Some(pending.by) {
            self.state.own = None;
            self.mls.void(rows(&self.state, None))?;
        }
        events.push(Event::Voided {
            epoch: pending.epoch,
            committer: pending.by,
            why,
        });
        Ok(())
    }

    /// This device cannot follow `epoch`: it stops, deletes any commit it
    /// holds, and re-pairs from another live device or regroups.
    fn stick(
        &mut self,
        epoch: u64,
        committer: DeviceId,
        events: &mut Vec<Event>,
    ) -> Result<(), GroupError> {
        let me = self.state.id;
        let other =
            self.state.devices.iter().any(|(id, known)| {
                Some(*id) != me && *id != committer && !known.matured && !known.out
            });
        let remedy = if other {
            Remedy::RePair
        } else {
            Remedy::Regroup
        };
        self.state.course = Course::Stuck { epoch, committer };
        self.state.pending = None;
        self.state.own = None;
        self.processed = None;
        self.mls.void(rows(&self.state, None))?;
        events.push(Event::Alarm(Alarm::CannotFollow {
            epoch,
            committer,
            remedy,
        }));
        Ok(())
    }

    /// This device's removal matured: it has no voice.
    fn out(&mut self, events: &mut Vec<Event>) -> Result<(), GroupError> {
        self.state.course = Course::Out;
        self.state.pending = None;
        self.state.own = None;
        self.processed = None;
        self.mls.void(rows(&self.state, None))?;
        events.push(Event::Removed);
        Ok(())
    }

    /// What the device has to post again: its vote until the log holds it,
    /// and its own commit's evidence until the log holds it.
    fn reposts(&self, events: &mut Vec<Event>) {
        if let Some(pending) = &self.state.pending
            && let Some(vote) = pending.mine
            && !pending.logged
        {
            events.push(Event::Vote {
                epoch: pending.epoch,
                vote,
                message: vote_message(
                    &self.state.agent.identity,
                    pending.epoch,
                    pending.index,
                    &pending.chain,
                    &vote,
                ),
            });
        }
        if let Some(own) = &self.state.own
            && let (Some(index), Some((message, signature))) = (own.index, &own.signed)
            && !own.evidenced
        {
            events.push(Event::Evidence {
                index,
                message: message.clone(),
                signature: *signature,
                welcome: own.welcome.clone(),
            });
        }
    }
}
