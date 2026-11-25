//! Following the control log: each entry checked against the chain, the
//! pending candidate's evidence and votes verified, the candidate
//! processed on a copy, this device's vote, and the verdict as this device
//! counts it.

use ed25519_dalek::{Signature, VerifyingKey};
use vos_abi::Decode;
use vos_mls::{Expected, Kind};
use vos_wire::ingress::CallMessage;
use vos_wire::personal::{
    AdminCall, Attached, Body, DeviceId, Effect, Entry, Op, OpState, Place, Policy, Signer,
    Verdict, Void, Vote, chain, vote_message, welcome_hash,
};

use super::{
    Act, Alarm, CONFIRM, Check, Course, DeviceGroup, Event, GroupError, Known, Named, Passing,
    Pending, Processed, Remedy, Why,
};
use vos_wire::personal::method;

/// A commit call's arguments after its place: its epoch, effect,
/// handshake and Welcome's hash.
type CommitArguments = ((u64, Effect), (Vec<u8>, Option<[u8; 32]>));

/// The admin call an entry logs, if it logs one.
fn admin_call(body: &Body) -> Option<&AdminCall> {
    match body {
        Body::Operation { call, .. }
        | Body::Candidate { call, .. }
        | Body::Veto { call, .. }
        | Body::Cosign { call, .. }
        | Body::Resolve { call, .. } => Some(call),
        _ => None,
    }
}

pub(crate) fn verifies(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

impl DeviceGroup {
    /// Read `entries` of the control log, from the cursor on, in order:
    /// what the device must post, and what it saw. An entry that does not
    /// chain stops the reading with [`Alarm::Log`], and so does one before
    /// the cursor whose chain is not the one this device read there (a fork
    /// behind it); the reading stops at a gap. Each entry is checked
    /// against the writers' views waiting for it ([`Alarm::View`]) and this
    /// device's admin calls the agent took there ([`Alarm::Dropped`]). A
    /// device that cannot follow reads on for the device set's operations,
    /// its own regroup's among them, not for others' candidates. The
    /// device's state is written once a confirmed epoch is swapped in and
    /// at the end, each time in one batch with its MLS state.
    pub fn follow(
        &mut self,
        entries: impl IntoIterator<Item = (u64, Entry)>,
    ) -> Result<Vec<Event>, GroupError> {
        let mut events = Vec::new();
        for (index, entry) in entries {
            if self.state.course == Course::Out {
                break;
            }
            if index < self.state.next {
                let read = self.store.group_row(&super::chain_key(index + 1))?;
                if read.is_some_and(|read| read[..] != entry.chain[..]) {
                    events.push(Event::Alarm(Alarm::Log { index }));
                    break;
                }
                continue;
            }
            if index > self.state.next {
                break;
            }
            if chain(&self.state.chain, index, entry.at, &entry.body) != entry.chain {
                events.push(Event::Alarm(Alarm::Log { index }));
                break;
            }
            if entry.at < self.state.time {
                // Batch time goes back: a rewritten log.
                events.push(Event::Alarm(Alarm::Log { index }));
                break;
            }
            if !self.placed(index, &entry.body)? {
                // An admin call where its signer did not sign it: one the
                // agent took elsewhere, logged again on a fork.
                events.push(Event::Alarm(Alarm::Log { index }));
                break;
            }
            if admin_call(&entry.body).is_some() {
                self.state.floor = index + 1;
            }
            self.state.next += 1;
            self.state.chain = entry.chain;
            self.state.time = entry.at;
            self.chains.push((self.state.next, entry.chain));
            self.witness(index, &entry, &mut events);
            self.deadline(entry.at, &mut events)?;
            self.support(&mut events)?;
            self.entry(index, entry, &mut events)?;
            self.settle(&mut events)?;
        }
        self.reposts(&mut events);
        self.note(&events);
        let writes = self.writes(true)?;
        self.mls.write(writes)?;
        Ok(events)
    }

    /// The entry at `index`, just read, against what waits for it: the
    /// writers' views of the log through it, and this device's admin call
    /// the agent said it took there.
    fn witness(&mut self, index: u64, entry: &Entry, events: &mut Vec<Event>) {
        let next = self.state.next;
        if let Some(at) = self.state.views.iter().position(|(view, _)| *view == next) {
            let (_, chain) = self.state.views.remove(at);
            if chain != entry.chain {
                events.push(Event::Alarm(Alarm::View { index: next }));
            }
        }
        let call = admin_call(&entry.body);
        // A call held before it left and never answered (a kill, a lost
        // answer) is found here: its evidence is posted from now on.
        if let Some(call) = call
            && let Some(sent) = self
                .state
                .sent
                .iter_mut()
                .find(|sent| sent.index.is_none() && sent.is(call))
        {
            sent.index = Some(index);
        }
        let Some(at) = self.state.made.iter().position(|made| made.index == index) else {
            return;
        };
        let made = &self.state.made[at];
        let held = call.is_some_and(|call| {
            call.origin == made.origin
                && call.method == made.method
                && call.arguments == made.arguments
        });
        if held || made.method != method::VETO.0 {
            self.state.made.remove(at);
        } else {
            self.state.made[at].dropped = true;
        }
        if !held {
            events.push(Event::Alarm(Alarm::Dropped { index }));
        }
    }

    /// Whether the entry at `index`, about to be read, holds where it is:
    /// an admin call, a device-set call or a commit, names its place
    /// first, which must be at or after the floor (the entry after the last
    /// admin call read) and at or before `index`, its chain the one this device read there. Before
    /// a paired device's start, where it read no chain, the floor alone
    /// holds it: its pairing device read those entries.
    fn placed(&self, index: u64, body: &Body) -> Result<bool, GroupError> {
        let Some(call) = admin_call(body) else {
            return Ok(true);
        };
        let Some((place, _)) = Place::split(&call.arguments) else {
            return Ok(false);
        };
        if place.next < self.state.floor || place.next > index {
            return Ok(false);
        }
        let read = if place.next == index {
            Some(self.state.chain)
        } else if place.next == 0 {
            Some([0; 32])
        } else if let Some((_, chain)) = self.chains.iter().find(|(next, _)| *next == place.next) {
            Some(*chain)
        } else {
            self.store
                .group_row(&super::chain_key(place.next))?
                .map(|read| <[u8; 32]>::try_from(&read[..]).map_err(|_| GroupError::Corrupt))
                .transpose()?
        };
        Ok(read.is_none_or(|read| read == place.chain))
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
            Body::Configured(policy) => self.configure(index, policy, events),
            // The claim's kit is the claiming device's own, its sealing
            // keys with it. The claim's assignment is the first of device
            // 0 under the kit this device holds.
            Body::Assigned { device: 0, kit }
                if self.state.assigned.is_none()
                    && kit
                        .iter()
                        .eq(self.state.set.kit.iter().map(|key| &key.signing)) =>
            {
                self.state.assigned = Some(index);
            }
            Body::Assigned { .. } => {}
            Body::Operation {
                call,
                by,
                op,
                matures,
            } => self.call(index, at, call, by, Act::Op { op, matures }),
            Body::Veto { call, by, op } => {
                self.call(index, at, call, Signer::Device(by), Act::Veto(op))
            }
            Body::Cosign { call, by, op } => self.call(index, at, call, by, Act::Cosign(op)),
            Body::Resolve {
                call,
                by,
                op,
                upheld,
            } => self.call(index, at, call, by, Act::Resolve { op, upheld }),
            Body::Settled { op, state } => match state {
                // A cosign or a resolution that made it mature is held
                // until its own evidence is logged: the devices take the
                // maturity only with it.
                OpState::Matured { at } => {
                    self.state.sent.retain(|sent| sent.index != Some(op));
                    self.claim(index, op, at, events)?
                }
                OpState::Cancelled { .. } => {
                    self.state.sent.retain(|sent| !sent.about(op));
                    self.cancelled(op)
                }
                OpState::Pending | OpState::Contested | OpState::Carried { .. } => {}
            },
            Body::Matured { device } => self.matured(index, device, events)?,
            Body::Alive { device } => {
                if let Some(known) = self.state.known_mut(device) {
                    known.alive = index;
                }
            }
            Body::Candidate { .. } => unreachable!("taken above"),
            Body::Evidence {
                index: of,
                message,
                signature,
                welcome,
            } => {
                self.state.sent.retain(|sent| sent.index != Some(of));
                self.evidence(of, &message, &signature, welcome, events)?
            }
            Body::Vote {
                device,
                epoch,
                candidate,
                vote,
                signature,
            } => self.vote(device, epoch, candidate, vote, &signature, events),
            Body::Verdict { epoch, verdict } => self.verdict(index, epoch, verdict, events)?,
            Body::Renewed { .. } => {}
        }
        Ok(())
    }

    /// A configuration of the agent's policy at `index`: the claim's (one
    /// before its assignment, or the one beside it) taken whole; a later
    /// one takes the quotas, the lease and the inbox, and lowers no delay
    /// or window of the device set's rules ([`Policy::over`]), which it
    /// raises [`Alarm::Policy`] for.
    fn configure(&mut self, index: u64, policy: Policy, events: &mut Vec<Event>) {
        let kept = super::configure(self.state.assigned, index, policy, &self.state.policy);
        if kept != policy {
            events.push(Event::Alarm(Alarm::Policy { index }));
        }
        self.state.policy = kept;
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
        if let Some(pending) = self.state.pending.clone() {
            // The agent took the next candidate while this device's count
            // of the last one is undecided: the agent counted votes this
            // device does not hold.
            events.push(Event::Alarm(Alarm::Verdict {
                epoch: pending.epoch,
            }));
            if epoch > pending.epoch && pending.evidence == Check::Valid {
                self.apply(&pending);
            }
            self.stick(pending.epoch, pending.by, events)?;
        }
        let decoded = Place::split(&call.arguments)
            .and_then(|(_, arguments)| CommitArguments::decode_exact(arguments))
            .filter(|((named, _), _)| *named == epoch && call.method == method::COMMIT.0);
        let fresh = self.state.set.fresh;
        let regroup = fresh.is_some() && fresh == self.state.id && fresh == Some(by);
        if matches!(self.state.course, Course::Stuck { .. }) && !regroup {
            // A device that cannot follow takes no candidate but its own
            // regroup's: it follows the others' epochs and the removals
            // they carry by the agent's word, which moves no key.
            self.state.confirmed = self.state.confirmed.max(epoch.saturating_sub(1));
            self.state.passing = decoded.map(|((_, effect), _)| Passing {
                epoch,
                at,
                added,
                effect,
            });
            return Ok(());
        }
        let (mut evidence, effect, handshake, welcome_hash) = match decoded {
            Some(((_, effect), (handshake, hash))) => (Check::Missing, effect, handshake, hash),
            None => (Check::Invalid, Effect::default(), Vec::new(), None),
        };
        // The committer has a voice past its probation and its admin key
        // signed the call, an add is a strong admin's or a matured add
        // operation's and names a new device by a new number, and a matured
        // regroup's new group comes first.
        let awaits = match self.holds(Signer::Device(by), &call.origin, at) {
            super::set::Holds::Yes => None,
            super::set::Holds::Awaiting(replacement) => Some(replacement),
            super::set::Holds::No => {
                evidence = Check::Invalid;
                None
            }
        };
        // A removal re-seals the kit, the kit's own keys each with a new
        // `R1`.
        let rekey_holds = match &effect.rekey {
            Some(rekey) => self.state.kit_is(&rekey.entries),
            None => effect.remove.is_empty(),
        };
        let state = &self.state;
        let strong = state.known(by).is_some_and(|known| known.strong);
        let matured = effect
            .add
            .as_ref()
            .is_some_and(|add| state.set.adds.contains(add));
        let new = added.is_none_or(|id| state.known(id).is_none());
        if !rekey_holds
            || added.is_some() != effect.add.is_some()
            || !new
            || (effect.add.is_some() && !strong && !matured)
            || fresh.is_some_and(|fresh| fresh != by)
        {
            evidence = Check::Invalid;
        }
        if let Some(own) = &mut self.state.own
            && Some(by) == self.state.id
            && own.index.is_none()
            && Place::split(&call.arguments)
                .is_some_and(|(_, arguments)| arguments == own.arguments)
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
            awaits,
            welcome: None,
            votes: Vec::new(),
            mine: None,
            logged: false,
        });
        Ok(())
    }

    /// The evidence of the admin call at `of`: the pending candidate's,
    /// valid when it is the commit call as logged, signed by the
    /// committer's admin key for this agent, with the Welcome its hash
    /// names; or a device-set call's.
    fn evidence(
        &mut self,
        of: u64,
        message: &[u8],
        signature: &[u8; 64],
        welcome: Option<Vec<u8>>,
        events: &mut Vec<Event>,
    ) -> Result<(), GroupError> {
        if let Some(own) = &mut self.state.own
            && own.index == Some(of)
        {
            own.evidenced = true;
        }
        let agent = self.state.agent;
        let Some(pending) = self
            .state
            .pending
            .as_mut()
            .filter(|pending| pending.index == of)
        else {
            return self.call_evidence(of, message, signature, welcome.is_some(), events);
        };
        if pending.evidence != Check::Missing {
            return Ok(());
        }
        let valid = CallMessage::parse(message).is_some_and(|signed| {
            signed.identity == agent.identity
                && signed.session.key == pending.origin
                && signed.instance == agent.instance
                && signed.method == method::COMMIT
                && signed.arguments == pending.arguments
        }) && verifies(&pending.origin, message, signature)
            && welcome.as_deref().map(welcome_hash) == pending.welcome_hash;
        pending.evidence = if valid { Check::Valid } else { Check::Invalid };
        pending.welcome = welcome;
        Ok(())
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
        index: u64,
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
                        Void::Regroup => Why::Regroup,
                        Void::Nack | Void::Split => Why::Agent,
                    };
                    self.void(why, events)?;
                }
                Verdict::Confirmed(_) => events.push(Event::Alarm(Alarm::Verdict { epoch })),
            },
            _ if self
                .state
                .passing
                .as_ref()
                .is_some_and(|passing| passing.epoch == epoch) =>
            {
                let passing = self.state.passing.take().expect("passing");
                if let Verdict::Confirmed(_) = verdict {
                    // The device it added is the set's, by the agent's
                    // word: its nodes' author is known.
                    if let (Some(id), Some(keys)) = (passing.added, passing.effect.add)
                        && self.state.known(id).is_none()
                    {
                        let active_from = passing.at.saturating_add(self.state.policy.probation_ms);
                        self.state.devices.push((id, Known::new(keys, active_from)));
                    }
                    self.carried(passing.epoch, &passing.effect.remove);
                }
            }
            _ => {
                let confirmed = matches!(verdict, Verdict::Confirmed(_));
                if self
                    .state
                    .decided
                    .is_some_and(|(decided, by_me)| decided == epoch && by_me != confirmed)
                {
                    events.push(Event::Alarm(Alarm::Verdict { epoch }));
                }
                // The agent re-seals the kit at its verdict: from this entry
                // the commit's `R` is the kit's, once this device confirmed
                // it too. Any other verdict on the epoch whose commit
                // re-sealed it (or one this device did not confirm) leaves
                // its `R` unheld: the
                // agent installed no `R2` for it, and the `R` before is a
                // removed device's, so nothing is pushed under either and
                // the next commit, which the device asks its user for
                // ([`DeviceGroup::reseal_owed`]), re-seals the kit.
                if let Some((rekeyed, hash)) = self.state.rekeyed
                    && rekeyed == epoch
                {
                    if confirmed && self.state.decided == Some((epoch, true)) {
                        self.state.rekeyed = None;
                        self.name_recovery(index, hash, false);
                    } else {
                        self.state.reseal = true;
                    }
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
        if fresh && pending.evidence != Check::Missing && pending.awaits.is_none() {
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
            Some(cutoff) => self.voiced_at(device, cutoff),
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
        if pending.evidence != Check::Valid || pending.awaits.is_some() {
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
        // A matured regroup's first commit starts a new group: the
        // regrouper's restart, of it alone, every other device removed.
        let restart = self.state.set.fresh == Some(pending.by);
        let candidate = if restart && !joining {
            let mut owed = pending.effect.remove.clone();
            owed.sort_unstable();
            if pending.epoch != self.state.confirmed + 1
                || pending.effect.add.is_some()
                || owed != self.state.owed()
                || self.state.id != Some(pending.by)
            {
                return Ok(Processed::Refused);
            }
            match self.mls.own(&pending.handshake) {
                Ok(candidate) => candidate,
                Err(vos_mls::Error::Refused(_)) => return Ok(Processed::Refused),
                Err(vos_mls::Error::NotHeld) => return Ok(Processed::Unable),
                Err(error) => return Err(error.into()),
            }
        } else if joining {
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
        let epoch = if restart {
            1
        } else {
            pending.epoch.saturating_sub(self.state.offset)
        };
        if candidate.epoch() != epoch || !self.roster_holds(pending, &candidate, !restart) {
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
    /// each leaf the device's credential, the committer's renewed if its
    /// admin key was replaced and the commit `renews` (a restart keeps the
    /// leaf). A leaf whose keys changed otherwise is refused.
    fn roster_holds(
        &self,
        pending: &Pending,
        candidate: &vos_mls::Candidate,
        renews: bool,
    ) -> bool {
        let mut want: Vec<Vec<u8>> = self
            .state
            .devices
            .iter()
            .filter(|(id, known)| !known.out && !pending.effect.remove.contains(id))
            .map(|(id, known)| match known.renewal() {
                Some(renewed) if renews && *id == pending.by => renewed,
                _ => known.credential(),
            })
            .chain(pending.effect.add.iter().map(super::credential))
            .collect();
        let mut got = candidate.credentials();
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
            let known = state.devices.iter().any(|(_, known)| {
                known.keys.sync == add.sync
                    || known.keys.admin == add.admin
                    || known.admin == add.admin
            });
            let delayed = !committer.strong && !state.set.adds.contains(add);
            if delayed || known || add.sync == add.admin {
                return None;
            }
            adds.push(super::credential(add));
        }
        let mut named = pending.effect.remove.clone();
        named.sort_unstable();
        if named != state.owed() {
            return None;
        }
        // The removals of devices in the group: a restore's new group has
        // none of those before it.
        let members = self.mls.credentials().ok()?;
        let removes = named
            .iter()
            .filter_map(|device| state.known(*device))
            .map(Known::credential)
            .filter(|credential| members.contains(credential))
            .collect();
        Some(Expected {
            committer: committer.credential(),
            adds,
            removes,
            renewed: committer.renewal(),
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
                if joining {
                    self.state.id = pending.added;
                }
                // A restart keeps its regrouper's leaf; any other commit
                // renews a replaced admin key's.
                let restart = self.state.set.fresh == Some(pending.by);
                if self.state.set.fresh == Some(pending.by) {
                    // The regroup's new group: its epochs count on from
                    // the agent's, and a device that could not follow
                    // follows it.
                    self.state.set.fresh = None;
                    self.state.course = Course::Following;
                }
                self.state.offset = pending.epoch.saturating_sub(candidate.epoch());
                if !restart && let Some(committer) = self.state.known_mut(pending.by) {
                    committer.leaf = committer.admin;
                }
                if let Some(rekey) = &pending.effect.rekey
                    && self.state.kit_is(&rekey.entries)
                {
                    self.state.rekeyed = Some((pending.epoch, rekey.r_hash));
                    self.state.reseal = false;
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
                self.note(events);
                let writes = self.writes(true)?;
                self.mls.swap(*candidate, writes)?;
                events.push(Event::Confirmed {
                    epoch: pending.epoch,
                });
                Ok(())
            }
            Some(Processed::Copy { candidate, h: None }) => {
                self.apply(&pending);
                self.state.course = Course::Out;
                self.note(events);
                let writes = self.writes(false)?;
                self.mls.swap(*candidate, writes)?;
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
            _ => {
                // The agent confirmed it: its effect is the device set's.
                if pending.evidence == Check::Valid {
                    self.apply(&pending);
                }
                self.stick(pending.epoch, pending.by, events)
            }
        }
    }

    /// A confirmed candidate's effect on the device set: the device it
    /// added known, a matured add it carried done, the devices it removed
    /// out, the epoch confirmed.
    fn apply(&mut self, pending: &Pending) {
        if let (Some(id), Some(keys)) = (pending.added, &pending.effect.add) {
            let active_from = pending.at.saturating_add(self.state.policy.probation_ms);
            self.state
                .devices
                .push((id, Known::new(keys.clone(), active_from)));
            self.state.set.adds.retain(|add| add != keys);
        }
        self.carried(pending.epoch, &pending.effect.remove);
    }

    /// `epoch` confirmed, its commit carrying the removals of `removed`.
    fn carried(&mut self, epoch: u64, removed: &[DeviceId]) {
        for device in removed {
            if let Some(known) = self.state.known_mut(*device) {
                known.out = true;
            }
        }
        self.state
            .set
            .owed
            .retain(|device| !removed.contains(device));
        self.state.confirmed = epoch;
    }

    /// The pending candidate void: its copy dropped, and this device's own
    /// commit, if it is, deleted.
    fn void(&mut self, why: Why, events: &mut Vec<Event>) -> Result<(), GroupError> {
        let pending = self.state.pending.take().expect("pending");
        self.state.decided = Some((pending.epoch, false));
        self.processed = None;
        if self.state.id == Some(pending.by) {
            self.state.own = None;
            if let Some(rekey) = &pending.effect.rekey {
                self.archive.forget(&rekey.r_hash);
            }
            self.note(events);
            let writes = self.writes(true)?;
            self.mls.void(writes)?;
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
        let other = self.state.devices.iter().any(|(id, known)| {
            Some(*id) != me && *id != committer && known.matured.is_none() && !known.out
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
        events.push(Event::Alarm(Alarm::CannotFollow {
            epoch,
            committer,
            remedy,
        }));
        self.note(events);
        let writes = self.writes(false)?;
        self.mls.void(writes)?;
        Ok(())
    }

    /// This device's removal matured: it has no voice.
    pub(super) fn out(&mut self, events: &mut Vec<Event>) -> Result<(), GroupError> {
        self.state.course = Course::Out;
        self.state.pending = None;
        self.state.own = None;
        self.processed = None;
        self.note(events);
        let writes = self.writes(false)?;
        self.mls.void(writes)?;
        events.push(Event::Removed);
        Ok(())
    }

    /// What the device has to post again: `alive` first while a restore
    /// is open, its vote until the log holds it, its own commit's evidence
    /// and each held admin call's until the log holds them.
    fn reposts(&self, events: &mut Vec<Event>) {
        // A restore open asserts every device lost: a device with a voice
        // answers with `alive` until the log cancels it, whatever it makes
        // of the restore's evidence (liveness needs no judgement), and
        // before anything else it posts, which a refusal may stop.
        let state = &self.state;
        let me = state.id.filter(|me| state.voiced(*me));
        let restoring = state.set.operations.iter().find(|call| {
            !state.set.closed.contains(&call.index)
                && matches!(
                    &call.act,
                    Act::Op {
                        op: Op::Restore { .. },
                        ..
                    }
                )
        });
        if let (Some(me), Some(restore)) = (me, restoring)
            && state
                .known(me)
                .is_some_and(|known| known.alive < restore.index)
        {
            events.push(Event::Alive);
        }
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
                attached: Attached {
                    welcome: own.welcome.clone(),
                    r2: own.r2,
                },
            });
        }
        for sent in &self.state.sent {
            if let Some(index) = sent.index {
                events.push(Event::Evidence {
                    index,
                    message: sent.message.clone(),
                    signature: sent.signature,
                    attached: Attached {
                        welcome: None,
                        r2: sent.r2,
                    },
                });
            }
        }
    }

    /// The log made the `R` named `hash` the kit's at `since`: this
    /// device's, if it drew it; else an archive brings it.
    pub(super) fn name_recovery(&mut self, since: u64, hash: [u8; 32], by_kit: bool) {
        self.state.recovery = Some(Named {
            since,
            hash,
            by_kit,
        });
        self.archive.name(since, &hash);
    }
}
