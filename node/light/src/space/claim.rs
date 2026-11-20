//! The claim of a personal agent at a home-only space, and a move home: a
//! leave and a claim at the new home.

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
    To, failed, link, new_kit, secret, store_failed,
};
use crate::home::{self, Claim as Claiming, Home};
use crate::route::Purpose;
use crate::{AuthWitness, Call, Digest, TreeKeeper, wire};

/// The open claim's work, on this many threads.
const WORK_THREADS: usize = 2;
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

    /// The open claim of `member` at `home`: its work for the terms the
    /// registrar serves, a call in a session of its own. A member already
    /// there is done.
    fn open_claim(&self, home: &Home, member: &[u8; 32]) -> Result<(), Error> {
        let terms: Option<Open> = self.home_query(
            home,
            Purpose::Member,
            home.credentials.0,
            credentials::method::OPENING,
            Vec::new(),
        )?;
        let terms = terms.ok_or(Error::NoOpenClaim)?;
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

    /// `member`'s path at the newest root of `home`'s tree, read from its
    /// feed until it holds the member's leaf.
    fn home_witness(&self, home: &Home, member: &[u8; 32]) -> Result<AuthWitness, Error> {
        let member = Digest::from_bytes(member).ok_or_else(|| failed("the member is no digest"))?;
        let mut keeper = TreeKeeper::new(member);
        let until = std::time::Instant::now() + self.wait();
        loop {
            self.read_tree(home, &mut keeper)?;
            if let Some(witness) = keeper.witness() {
                return Ok(witness);
            }
            if std::time::Instant::now() > until {
                return Err(Error::NoLeaf);
            }
            self.host.sleep(POLL);
        }
    }

    /// `home`'s tree read into `keeper` from the credential actor's feed,
    /// page by page, each under a time the node gave.
    fn read_tree(&self, home: &Home, keeper: &mut TreeKeeper) -> Result<(), Error> {
        for _ in 0..FEED_PAGES {
            let now = self.time(To::Home(home.handle), Purpose::Feed)?;
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
            let mut link = link(&self.host, kept, Purpose::Personal, agent, &key, &mut sync);
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
        self.open_claim(&home, &member)?;
        let claim = match pending {
            Some(claim) => claim,
            None => {
                let agent = self.pooled(&home)?;
                let device = self.device(held, prompts, &home, &secret, &request.label)?;
                let kit = new_kit(prompts, request.kit, &kept)?;
                // The home and agent are the device's in the claim's batch.
                let mut next = held.state.clone();
                next.home = Some(kept.clone());
                next.agent = Some(agent);
                next.label = request.label;
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
                claim
            }
        };
        let agent = claim.agent();
        let witness = self.home_witness(&home, &member)?;
        let now = self.time(To::Home(home.handle), Purpose::Fetch)?;
        let call = claim.call(&home, now + EXPIRY_MS).map_err(failed)?;
        match self.prove_home::<u32>(&home, secret, witness, call)? {
            Ok(_) | Err(HomesError::Claimed) => {}
            Err(error) => {
                let mut next = held.state.clone();
                (next.home, next.agent) = (None, None);
                claim
                    .abandon(held.light.store(), next.rows())
                    .map_err(store_failed)?;
                self.adopt(held, next);
                return Err(Error::HomeRefused(error));
            }
        }
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
