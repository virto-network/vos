//! The claim of a personal agent at a home-only space, and a move home: a
//! leave and a claim at the new home.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use vos_abi::Decode;
use vos_abi::Encode;
use vos_abi::ids::MethodId;
use vos_abi::result::Outcome;
use vos_wire::credentials::{self, CredentialError, Open};
use vos_wire::homes::{self, HomesError};
use vos_wire::personal::{Body, Entry};

use super::link::Signer;
use super::{
    Claim, Claimed, EXPIRY_MS, Error, Held, Host, Kept, PERSONAL, POLL, Personal, Prompts, Proof,
    To, failed, new_kit, secret, store_failed,
};
use crate::home::{self, Claim as Claiming, Home};
use crate::route::Purpose;
use vos_wire::defaults::ROOT_GRACE_MS;
use crate::{AuthWitness, Call, Digest, TreeKeeper, wire};

/// The open claim's work, on this many threads.
const WORK_THREADS: usize = 2;
/// The kits a claim shows before it gives up on a home that keeps
/// refusing it after each was shown.
const KITS: usize = 3;
/// The longest drawn pause before each of the reads a claim makes while
/// its kit is written down.
const AHEAD_GAP: Duration = Duration::from_secs(4);
/// How long a claim counts on a reading of the node's clock, moved on by
/// the monotonic clock: a proof's expiry or a feed query's set from it.
const READING_LIFE: Duration = Duration::from_secs(300);
/// The most the device's clock may move apart from its monotonic clock
/// while a reading is counted on: past it the clock was set, or the
/// device slept, and the node's clock is read again.
const READING_STEP_MS: u64 = 2_000;

/// The node's time as one purpose's connection read it: the node's, the
/// device's and the monotonic clock's then.
#[derive(Clone, Copy)]
struct Reading {
    node: u64,
    wall: u64,
    at: Instant,
}

impl Reading {
    /// The node's time now, `wall` the device's clock: the reading moved on
    /// by the monotonic clock, none past `life` or once the device's clock
    /// moved apart from the monotonic one.
    fn now(&self, wall: u64, life: Duration) -> Option<u64> {
        let elapsed = self.at.elapsed();
        if elapsed >= life {
            return None;
        }
        let elapsed_ms = elapsed.as_millis() as u64;
        let moved = wall as i64 - self.wall as i64;
        if moved.abs_diff(elapsed_ms as i64) > READING_STEP_MS {
            return None;
        }
        Some(self.node + elapsed_ms)
    }
}

/// What a claim did while its kit was written down.
struct Ahead {
    /// The open claim's call, made or refused.
    open: Result<(), Error>,
    /// The tree as the feed read it, and the feed's reading of the node's
    /// time.
    tree: Option<(TreeKeeper, Reading)>,
    /// The fetch's reading of the node's time: the proof's expiry's.
    clock: Option<Reading>,
}

/// What the kit shown before a new one says: the home refused the backup
/// for `why`, so its words are void.
fn voided(why: &str) -> String {
    format!("The home refused the backup ({why}): the words shown before are void; write these new ones.")
}
/// The pages of a home's feed one read of its tree follows.
const FEED_PAGES: usize = 64;

impl<H: Host> Personal<H> {
    /// A query by a key drawn for it alone, of `method` at `instance` of
    /// the home's agent: `Homes`' and the registrar's terms.
    pub(super) fn home_query<T: Decode>(
        &self,
        home: &Home,
        purpose: Purpose,
        instance: u32,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<T, Error> {
        let now = self.time(To::Home(home.handle), purpose)?;
        let request = wire::query_request(
            home.agent,
            &home.identity,
            instance,
            method,
            arguments,
            now + EXPIRY_MS,
        )
        .map_err(failed)?;
        wire::query_answer(&self.ask(To::Home(home.handle), purpose, &request)?).map_err(failed)
    }

    /// The identity of `agent`, from its record, as the home's node says.
    pub(super) fn identity(&self, home: &Home, agent: u32) -> Result<[u8; 32], Error> {
        let answer = self.ask(
            To::Home(home.handle),
            Purpose::Personal,
            &wire::agent_request(agent),
        )?;
        wire::agent_answer(&answer)
            .map_err(failed)?
            .ok_or(Error::UnknownAgent)
    }

    /// The open claim of `member` at `home`: its terms, then its work and
    /// its call ([`Personal::claim_open`]).
    fn open_claim(&self, home: &Home, member: &[u8; 32]) -> Result<(), Error> {
        let terms = self.opening(home)?;
        self.claim_open(home, member, &terms)
    }

    /// The terms of the open claim the registrar at `home` serves.
    fn opening(&self, home: &Home) -> Result<Open, Error> {
        let terms: Option<Open> = self.home_query(
            home,
            Purpose::Member,
            home.credentials.0,
            credentials::method::OPENING,
            Vec::new(),
        )?;
        terms.ok_or(Error::NoOpenClaim)
    }

    /// The open claim of `member` at `home` for `terms`: its work, a call
    /// in a session of its own. A member already there is done.
    fn claim_open(&self, home: &Home, member: &[u8; 32], terms: &Open) -> Result<(), Error> {
        let nonce = home::work(
            &home.handle,
            member,
            &terms.salt,
            terms.difficulty,
            WORK_THREADS,
        );
        let now = self.time(To::Home(home.handle), Purpose::Member)?;
        let request = home::open_claim(home, member, nonce, now).map_err(failed)?;
        let outcome = wire::outcome(&self.ask(To::Home(home.handle), Purpose::Member, &request)?)
            .map_err(failed)?;
        match &outcome {
            Outcome::Done(_) => Ok(()),
            Outcome::Failed { detail, .. }
                if CredentialError::decode_exact(detail) == Some(CredentialError::Enrolled) =>
            {
                Ok(())
            }
            other => Err(Error::OpenClaimRefused(format!("{other:?}"))),
        }
    }

    /// What a claim does while its kit is written down, one at a time,
    /// each after a drawn pause while the user still writes (as a
    /// session's spares are built): the open claim of `member` for
    /// `terms`; the home's tree read from its feed; the node's time read
    /// on a fetch of its own, the proof's expiry's; and the connection
    /// the proof goes on opened ahead. Nothing after a refused open claim.
    fn behind_the_kit(
        &self,
        home: &Home,
        member: &[u8; 32],
        terms: &Open,
        written: &AtomicBool,
    ) -> Ahead {
        let mut ahead = Ahead {
            open: self.claim_open(home, member, terms),
            tree: None,
            clock: None,
        };
        if ahead.open.is_err() {
            return ahead;
        }
        if let Some(digest) = Digest::from_bytes(member) {
            self.pause(written);
            let mut keeper = TreeKeeper::new(digest);
            let mut feed = None;
            if self.read_tree(home, &mut keeper, &mut feed).is_ok() {
                ahead.tree = feed.map(|feed| (keeper, feed));
            }
        }
        self.pause(written);
        ahead.clock = self.reading(home, Purpose::Fetch).ok();
        self.pause(written);
        self.host
            .prepare(&To::Home(home.handle).routes(), Purpose::Proven);
        ahead
    }

    /// A pause drawn below [`AHEAD_GAP`], cut short once the kit is
    /// `written` down: from then on the claim waits for each step.
    fn pause(&self, written: &AtomicBool) {
        let mut draw = [0; 8];
        let _ = getrandom::getrandom(&mut draw);
        let gap = AHEAD_GAP.as_millis() as u64;
        let until = Instant::now() + Duration::from_millis(u64::from_le_bytes(draw) % gap.max(1));
        while Instant::now() < until && !written.load(Ordering::SeqCst) {
            self.host.sleep(Duration::from_millis(100));
        }
    }

    /// The node's time at `home` read now under `purpose`.
    fn reading(&self, home: &Home, purpose: Purpose) -> Result<Reading, Error> {
        let node = self.time(To::Home(home.handle), purpose)?;
        Ok(Reading {
            node,
            wall: self.host.now(),
            at: Instant::now(),
        })
    }

    /// `member`'s path at a root of `home`'s tree: the one `tree` read
    /// while the kit was written down, while that root's grace lasts
    /// (`ROOT_GRACE_MS` from any later root's time, so half of it from the
    /// reading on is safe); else the feed read on from there, under the
    /// feed's own reading of the node's time, until it holds the member's
    /// leaf.
    fn witness_after(
        &self,
        home: &Home,
        member: &[u8; 32],
        tree: Option<(TreeKeeper, Reading)>,
    ) -> Result<AuthWitness, Error> {
        let (mut keeper, mut feed) = match tree {
            Some((keeper, feed)) => (keeper, Some(feed)),
            None => {
                let member =
                    Digest::from_bytes(member).ok_or_else(|| failed("the member is no digest"))?;
                (TreeKeeper::new(member), None)
            }
        };
        let grace = Duration::from_millis(ROOT_GRACE_MS / 2);
        if let (Some(witness), Some(feed)) = (keeper.witness(), feed)
            && feed.at.elapsed() < grace
        {
            return Ok(witness);
        }
        let until = Instant::now() + self.wait();
        loop {
            self.read_tree(home, &mut keeper, &mut feed)?;
            if let Some(witness) = keeper.witness() {
                return Ok(witness);
            }
            if Instant::now() > until {
                return Err(Error::NoLeaf);
            }
            self.host.sleep(POLL);
        }
    }

    /// `home`'s tree read into `keeper` from the credential actor's feed,
    /// page by page, each query's expiry from `feed`, the feed's own
    /// reading of the node's time, while it lasts, else from one read now.
    fn read_tree(
        &self,
        home: &Home,
        keeper: &mut TreeKeeper,
        feed: &mut Option<Reading>,
    ) -> Result<(), Error> {
        for _ in 0..FEED_PAGES {
            let now = match feed.and_then(|feed| feed.now(self.host.now(), READING_LIFE)) {
                Some(now) => now,
                None => {
                    let reading = self.reading(home, Purpose::Feed)?;
                    *feed = Some(reading);
                    reading.node
                }
            };
            let query = keeper
                .request(
                    home.agent,
                    &home.identity,
                    home.credentials.0,
                    now + EXPIRY_MS,
                )
                .map_err(failed)?;
            let answer = self.ask(To::Home(home.handle), Purpose::Feed, &query)?;
            let read = keeper.ingest(&answer, self.host.now()).map_err(failed)?;
            if !read.more {
                break;
            }
        }
        Ok(())
    }

    /// `call` of `Homes` proved in the scope "home" with `secret`, sent as
    /// a proven call: `Homes`' answer.
    fn prove_home<T: Decode>(
        &self,
        home: &Home,
        secret: Box<crate::DeviceSecret>,
        witness: AuthWitness,
        call: Call,
    ) -> Result<Result<T, HomesError>, Error> {
        let request = self.host.prove(Proof::Home {
            secret,
            witness: Box::new(witness),
            call,
        })?;
        let outcome = self.proven(To::Home(home.handle), &request)?;
        wire::answer(&outcome).map_err(|_| failed(format!("`Homes` answered {outcome:?}")))
    }

    /// The proven call `request` sent `to` a home or a space: the outcome
    /// it ran to.
    pub(super) fn proven(&self, to: To, request: &[u8]) -> Result<Outcome, Error> {
        let answer = self.ask(to, Purpose::Proven, request)?;
        if wire::format_refused(&answer) {
            return Err(Error::Update);
        }
        match wire::credentialed_answer(&answer).map_err(failed)? {
            wire::Answer::Ran { outcome, .. } => Ok(outcome),
            other => Err(Error::Rejected(format!("{other:?}"))),
        }
    }

    /// The agent's log once it holds the assignment, read by the sync key.
    fn assigned(
        &self,
        held: &mut Held,
        kept: &Kept,
        agent: (u32, [u8; 32]),
    ) -> Result<Vec<(u64, Entry)>, Error> {
        let key = held.light.sync_key().clone();
        let mut sync = Signer::new(key.verifying_key().to_bytes());
        let until = std::time::Instant::now() + self.wait();
        loop {
            let mut link = self.link(kept, Purpose::Personal, agent, &key, &mut sync);
            if let Ok(entries) = super::logged(&mut link, 0)
                && entries
                    .iter()
                    .any(|(_, entry)| matches!(entry.body, Body::Assigned { .. }))
            {
                held.sync = sync;
                return Ok(entries);
            }
            if std::time::Instant::now() > until {
                return Err(Error::NotTakenYet);
            }
            self.host.sleep(POLL);
        }
    }

    /// The pooled agent `Homes` at `home` names, and its identity.
    fn pooled(&self, home: &Home) -> Result<(u32, [u8; 32]), Error> {
        let pooled: Option<u32> = self.home_query(
            home,
            Purpose::Personal,
            home.homes.0,
            homes::method::POOLED,
            Vec::new(),
        )?;
        let agent = pooled.ok_or(Error::NoAgentToGive)?;
        Ok((agent, self.identity(home, agent)?))
    }

    /// A personal agent at a home-only space, with a kit of the kind asked.
    /// The device's open claim first (its own work, a session of its own),
    /// then the claim of the agent `Homes` names, sealed to its identity,
    /// proved in the scope "home"; held until the agent's log shows it, so
    /// a retry sends the same claim.
    pub fn claim(&self, prompts: &dyn Prompts, request: Claim) -> Result<Claimed, Error> {
        self.claiming(&mut self.held(), prompts, request, None)
    }

    /// The claim of `request`, with the device's secret at its home if
    /// derived already (`ready`).
    fn claiming(
        &self,
        held: &mut Held,
        prompts: &dyn Prompts,
        request: Claim,
        ready: Option<Box<crate::DeviceSecret>>,
    ) -> Result<Claimed, Error> {
        if held.group.is_some() {
            return Err(Error::AlreadyHeld);
        }
        let kept = request.home.clone();
        let pending = Claiming::pending(held.light.store()).map_err(failed)?;
        if pending.is_none() && home::holds_archive(held.light.store()).map_err(failed)? {
            return Err(Error::HoldsKeys);
        }
        if pending.is_some()
            && let Some(at) = &held.state.home
            && at.home.handle != kept.home.handle
        {
            return Err(Error::ClaimElsewhere {
                home: at.home.handle,
            });
        }
        self.pin(&kept);
        let home = kept.home.clone();
        let secret = match ready {
            Some(secret) => secret,
            None => {
                let source = self.source(prompts, held)?;
                secret(prompts, &source, &home.handle)?
            }
        };
        let member = crate::member(&secret).to_bytes();
        let mut secret = Some(secret);
        // Why the kit shown last is void: the home refused the backup after
        // it was shown.
        let mut void: Option<String> = None;
        let mut kits = 0;
        let (agent, claim) = loop {
            let secret = match secret.take() {
                Some(secret) => secret,
                None => {
                    let source = self.source(prompts, held)?;
                    super::secret(prompts, &source, &home.handle)?
                }
            };
            let (claim, ahead) = match Claiming::pending(held.light.store()).map_err(failed)? {
                Some(claim) => {
                    self.open_claim(&home, &member)?;
                    (claim, None)
                }
                None => {
                    kits += 1;
                    match self.kit_and_open(held, prompts, &request, &secret, &member, void.as_deref())
                    {
                        Ok((claim, ahead)) => (claim, Some(ahead)),
                        Err(Error::OpenClaimRefused(why)) if kits < KITS => {
                            void = Some(voided(&why));
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
            };
            let agent = claim.agent();
            let (tree, clock) = ahead.map_or((None, None), |ahead| (ahead.tree, ahead.clock));
            let witness = self.witness_after(&home, &member, tree)?;
            // The proof's expiry from the fetch's reading while it lasts.
            let now = match clock.and_then(|clock| clock.now(self.host.now(), READING_LIFE)) {
                Some(now) => now,
                None => self.time(To::Home(home.handle), Purpose::Fetch)?,
            };
            let call = claim.call(&home, now + EXPIRY_MS).map_err(failed)?;
            match self.prove_home::<u32>(&home, secret, witness, call)? {
                Ok(_) | Err(HomesError::Claimed) => break (agent, claim),
                Err(error) => {
                    let mut next = held.state.clone();
                    (next.home, next.agent) = (None, None);
                    claim
                        .abandon(held.light.store(), next.rows())
                        .map_err(store_failed)?;
                    self.adopt(held, next);
                    if kits == 0 || kits >= KITS {
                        return Err(Error::HomeRefused(error));
                    }
                    // Shown this time: the home refused it, so new words.
                    self.pin(&kept);
                    void = Some(voided(&format!("{error:?}")));
                }
            }
        };
        let kept = held.state.home.clone().unwrap_or(kept);
        let entries = self.assigned(held, &kept, agent)?;
        let group = claim
            .claimed(held.light.store(), PERSONAL, &entries, self.host.now())
            .map_err(failed)?;
        let device = group.id().unwrap_or(0);
        held.group = Some(group);
        self.book(&held.light, device);
        self.follow(held)?;
        Ok(Claimed {
            agent: agent.0,
            device,
        })
    }

    /// The claim's first part at `home` with a new kit: the open claim's
    /// terms and an agent to give asked first, then the kit shown while
    /// the open claim's work and call run behind it, with the reads the
    /// proof takes ([`Personal::behind_the_kit`]); the claim held in the
    /// store once the kit is shown, so a retry after a lost answer sends
    /// the same one. An open claim the home refused once the kit was
    /// shown abandons it ([`Error::OpenClaimRefused`]: the words are
    /// void); one unreached leaves the claim held, its kit the one shown.
    fn kit_and_open(
        &self,
        held: &mut Held,
        prompts: &dyn Prompts,
        request: &Claim,
        secret: &crate::DeviceSecret,
        member: &[u8; 32],
        void: Option<&str>,
    ) -> Result<(Claiming, Ahead), Error> {
        let kept = &request.home;
        let home = &kept.home;
        let terms = self.opening(home)?;
        let agent = self.pooled(home)?;
        let device = self.device(held, prompts, home, secret, &request.label)?;
        let written = AtomicBool::new(false);
        let (kit, ahead) = std::thread::scope(|scope| {
            let behind = scope.spawn(|| self.behind_the_kit(home, member, &terms, &written));
            let kit = new_kit(prompts, request.kit, kept, void);
            written.store(true, Ordering::SeqCst);
            (kit, behind.join())
        });
        let ahead = ahead.map_err(|_| failed("the claim's reads stopped"))?;
        let kit = kit?;
        // The home and agent are the device's in the claim's batch.
        let mut next = held.state.clone();
        next.home = Some(kept.clone());
        next.agent = Some(agent);
        next.label = request.label.clone();
        let claim = Claiming::prepare(
            held.light.store(),
            device,
            vec![kit.key()],
            agent.0,
            agent.1,
            next.rows(),
        )
        .map_err(failed)?;
        self.adopt(held, next);
        let mut ahead = ahead;
        match std::mem::replace(&mut ahead.open, Ok(())) {
            Ok(()) => Ok((claim, ahead)),
            Err(Error::OpenClaimRefused(why)) => {
                let mut next = held.state.clone();
                (next.home, next.agent) = (None, None);
                claim
                    .abandon(held.light.store(), next.rows())
                    .map_err(store_failed)?;
                self.adopt(held, next);
                self.pin(kept);
                Err(Error::OpenClaimRefused(why))
            }
            Err(error) => Err(error),
        }
    }

    /// The personal space moved to another home, carrying nothing: once
    /// that home answers with an agent to give, this device leaves the
    /// space it holds, with no call to its old home (`Personal::leave`),
    /// and claims an agent there with a new kit, as a first claim does; the
    /// other devices leave and pair again from this one. Called again after
    /// a claim cut short, it finishes that claim.
    pub fn move_home(&self, prompts: &dyn Prompts, request: Claim) -> Result<Claimed, Error> {
        let mut held = self.held();
        let kept = request.home.clone();
        if held.group.is_some()
            && held
                .state
                .home
                .as_ref()
                .is_some_and(|at| at.home.handle == kept.home.handle)
        {
            return Err(Error::AtThatHome);
        }
        let store = held.light.store();
        let holds = held.group.is_some()
            || home::holds_archive(store).map_err(failed)?
            || held.state.restoring.is_some();
        let mut ready = None;
        if holds && Claiming::pending(store).map_err(failed)?.is_none() {
            // Everything the new home could refuse is asked before the
            // leave, which cannot be undone: its open claim, an agent to
            // give, and no agent under this device's nullifier there.
            self.pin(&kept);
            let home = &kept.home;
            let source = self.source(prompts, &mut held)?;
            let secret = secret(prompts, &source, &home.handle)?;
            self.open_claim(home, &crate::member(&secret).to_bytes())?;
            self.pooled(home)?;
            let holding: Option<u32> = self.home_query(
                home,
                Purpose::Personal,
                home.homes.0,
                homes::method::AGENT,
                home.nullifier(&secret).encode(),
            )?;
            if holding.is_some() {
                return Err(Error::HoldsAgentThere);
            }
            self.leave(&mut held)?;
            ready = Some(secret);
        }
        self.claiming(&mut held, prompts, request, ready)
    }
}
