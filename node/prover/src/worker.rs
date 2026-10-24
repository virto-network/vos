//! The worker: from the logs of the agents this node replicates, each
//! attest at a window's cut becomes a job; for the agents it leads, one job
//! at a time is proved, and each proof is kept, recorded in its agent, and
//! submitted once its roots are anchored.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_venue::vos_statement::{ProgramId, Refusal, Statement, StatementId};
use vos_venue::{NotAccepted, Unjudged, VenueClient};
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::result::Attest;
use vos_wire::{SpaceId, WindowClock};

use crate::job::{
    Job, MAX_ATTEMPTS, MAX_RESUBMITS, REFUSED_KERNEL, REFUSED_RERUN, State, deadline,
};

/// The final proofs' format: the masked wrap's.
pub const FORMAT: u32 = vos_venue::vos_statement::vos_pvm_final_verifier::masked::FORMAT;

/// What the worker reads of and does to the node it runs on.
pub trait Host {
    /// Whether this node leads `agent` now: only its leader proves its
    /// records and submits their statements.
    fn leads(&self, agent: AgentId) -> bool;
    /// The agents this node replicates: every replica reads its log into
    /// jobs, so a new leader holds them already.
    fn agents(&self) -> Vec<AgentId>;
    /// The last index of `agent`'s log this replica applied.
    fn applied(&self, agent: AgentId) -> u64;
    /// The last index compacted out of `agent`'s log: 0 for none.
    fn log_start(&self, agent: AgentId) -> Result<u64, String>;
    /// The attests the work result at `index` of `agent`'s log recorded:
    /// none for another kind of entry; `None` when the log no longer holds
    /// the entry.
    fn attests(&self, agent: AgentId, index: u64) -> Result<Option<Vec<Attest>>, String>;
    /// A program's blob, by its hash: a kernel an attest names.
    fn program(&self, hash: &ProgramHash) -> Option<Vec<u8>>;
    /// The proof `agent` holds recorded for statement `id` of window
    /// `window`'s cut (`vos_wire::keys::proven`), as this replica applied
    /// it.
    fn proven(&self, agent: AgentId, window: u64, id: &StatementId) -> Option<[u8; 32]>;
    /// Keep a final proof: its BLAKE2b-256.
    fn keep(&self, proof: &[u8]) -> Result<[u8; 32], String>;
    /// Keep the proof `hash` whatever its age (`held`), or no longer: a
    /// statement's proof is held from its proof until its job finishes.
    fn hold(&self, hash: &[u8; 32], held: bool);
    /// The proof `hash`, if this node holds it; when not, `agent`'s other
    /// replicas are asked for it.
    fn proof(&self, agent: AgentId, hash: &[u8; 32]) -> Option<Vec<u8>>;
    /// Have `agent`'s leader record statement `id` of window `window`'s cut
    /// proved by `proof` (`vos_wire::batch::Input::Proven`).
    fn record(&self, agent: AgentId, window: u64, id: StatementId, proof: [u8; 32]);
    /// The space's clock, which numbers the windows its roots are of.
    fn clock(&self) -> WindowClock;
}

/// The worker's table, durable: each statement's job by id, and how far
/// each agent's log has been read.
pub trait Jobs {
    fn get(&self, agent: AgentId, id: &StatementId) -> Result<Option<Job>, String>;
    /// Write `job`, durably before it returns.
    fn put(&self, id: &StatementId, job: &Job) -> Result<(), String>;
    /// Remove a job.
    fn remove(&self, agent: AgentId, id: &StatementId) -> Result<(), String>;
    /// Every job.
    fn all(&self) -> Result<Vec<(StatementId, Job)>, String>;
    /// The last index of `agent`'s log read into jobs: 0 for none.
    fn watermark(&self, agent: AgentId) -> Result<u64, String>;
    fn set_watermark(&self, agent: AgentId, index: u64) -> Result<(), String>;
}

/// Why a statement is not proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProveError {
    /// The kernel's re-run on the record's witness does not make the
    /// record's statement: refused for good.
    Rerun(String),
    /// The record names no kernel this prover proves: refused for good.
    Kernel(String),
    /// The prover failed: tried again. Its reason is static, so that it
    /// holds nothing of the run's values and may be logged.
    Failed(&'static str),
}

/// What proves a statement.
pub trait Prover: Send + Sync {
    /// The program id of `kernel`, a kernel's blob, recomputed from it.
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, ProveError>;
    /// The final proof of `attest`'s statement under [`FORMAT`], its
    /// bytes as the format lays them out: `kernel` re-run on its witness,
    /// checked against it, and proved.
    fn prove(&self, kernel: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError>;
}

/// The worker's settings.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// How long a proof is taken to last before the worker has timed one:
    /// a statement whose anchor would pass `MaxRootAge` by the venue's time
    /// before then is dead. The longest proof timed since raises it.
    pub expected: Duration,
    /// How long a proof another replica made is asked for before it is
    /// proved here.
    pub patience: Duration,
    /// How long a submission whose answer was lost, or that the venue
    /// refused for now ([`vos_venue::transient`]), waits before it goes
    /// again, doubled each time.
    pub retry: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            expected: Duration::from_secs(600),
            patience: Duration::from_secs(60),
            retry: Duration::from_secs(30),
        }
    }
}

/// The worker's jobs, counted by state: what a lagging worker reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Backlog {
    pub queued: usize,
    pub proving: usize,
    pub proved: usize,
    pub submitted: usize,
    pub accepted: usize,
    pub refused: usize,
    pub dead: usize,
    /// Records the log no longer held when read: never proved here.
    pub lost: u64,
    /// The earliest window a queued job's statement reads, if any.
    pub oldest: Option<u64>,
}

impl Backlog {
    /// The jobs still to prove or to submit.
    pub fn pending(&self) -> usize {
        self.queued + self.proving + self.proved + self.submitted
    }
}

/// What one step did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stepped {
    /// New jobs read from the logs.
    pub read: usize,
    /// A statement proved, or refused by the prover.
    pub proved: bool,
    /// Statements handed to the venue.
    pub submitted: usize,
    /// Work left: a statement to prove now.
    pub more: bool,
}

/// The statement `attest` makes, its kernel's program id `program`: of
/// the space its first root names, or of none.
pub fn statement(attest: &Attest, program: ProgramId) -> Statement {
    Statement {
        format: FORMAT,
        program,
        space: attest
            .roots
            .first()
            .map_or(SpaceId::NONE, |root| root.space),
        public_args: attest.public_args.clone(),
        output: attest.output.clone(),
        roots: attest.roots.clone(),
    }
}

/// The prover worker of one node.
pub struct Worker<H, J> {
    host: H,
    jobs: J,
    prover: Arc<dyn Prover>,
    venue: Arc<dyn VenueClient>,
    options: Options,
    /// Each kernel's program id, by its blob's hash.
    programs: HashMap<ProgramHash, ProgramId>,
    /// When each proof another replica made was first asked for.
    asked: HashMap<StatementId, Instant>,
    /// The statements whose proof another replica made never arrived:
    /// proved here.
    unfetched: std::collections::HashSet<StatementId>,
    /// When each submission whose answer was lost, or that was refused for
    /// now, goes again, the wait after that, and how often it went again.
    retries: HashMap<StatementId, (Instant, Duration, u32)>,
    /// The longest proof timed.
    longest: Duration,
    lost: u64,
}

impl<H: Host, J: Jobs> Worker<H, J> {
    /// A worker over `jobs`: a job a stopped worker was proving goes back
    /// to the queue, to be proved again.
    pub fn open(
        host: H,
        jobs: J,
        prover: Arc<dyn Prover>,
        venue: Arc<dyn VenueClient>,
        options: Options,
    ) -> Result<Self, String> {
        for (id, job) in jobs.all()? {
            match job.state {
                State::Proving => jobs.put(&id, &job.to(State::Queued))?,
                State::Proved { proof } | State::Submitted { proof } => {
                    host.hold(&proof, true);
                    if host.proven(job.agent, job.window, &id).is_none() {
                        host.record(job.agent, job.window, id, proof);
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            host,
            jobs,
            prover,
            venue,
            options,
            programs: HashMap::new(),
            asked: HashMap::new(),
            unfetched: Default::default(),
            retries: HashMap::new(),
            longest: Duration::ZERO,
            lost: 0,
        })
    }

    /// The host it runs on.
    pub fn host(&self) -> &H {
        &self.host
    }

    /// Its table.
    pub fn jobs(&self) -> &J {
        &self.jobs
    }

    /// One step: every replicated agent's new records read into jobs,
    /// through its applied index, the led agents' proved statements whose
    /// roots are anchored submitted, then one statement proved, the one
    /// whose anchor ages first.
    pub fn step(&mut self) -> Result<Stepped, String> {
        let mut stepped = Stepped::default();
        for agent in self.host.agents() {
            stepped.read += self.scan(agent)?;
        }
        let jobs = self.follow(self.jobs.all()?)?;
        stepped.submitted = self.submit(&jobs)?;
        if let Some((id, job)) = self.next(&jobs)
            && self.prove(id, job)?
        {
            stepped.proved = true;
            stepped.more = self.next(&self.jobs.all()?).is_some();
        }
        Ok(stepped)
    }

    /// The jobs counted by state.
    pub fn backlog(&self) -> Result<Backlog, String> {
        let mut backlog = Backlog {
            lost: self.lost,
            ..Backlog::default()
        };
        for (_, job) in self.jobs.all()? {
            match job.state {
                State::Queued => {
                    backlog.queued += 1;
                    let window = job.earliest_window();
                    backlog.oldest = match (backlog.oldest, window) {
                        (Some(oldest), Some(window)) => Some(oldest.min(window)),
                        (oldest, window) => oldest.or(window),
                    };
                }
                State::Proving => backlog.proving += 1,
                State::Proved { .. } => backlog.proved += 1,
                State::Submitted { .. } => backlog.submitted += 1,
                State::Accepted => backlog.accepted += 1,
                State::Refused(_) => backlog.refused += 1,
                State::Dead => backlog.dead += 1,
            }
        }
        Ok(backlog)
    }

    /// Remove the finished jobs whose roots no venue anchors any more:
    /// their records are read past, and their statements can be judged
    /// nowhere. A rootless statement, judged at no deadline, has its
    /// finished job removed once its record is read past and compacted out
    /// of its agent's log: no read of the log can make the job again.
    pub fn prune(&mut self) -> Result<usize, String> {
        let now = self.venue.time();
        let clock = self.host.clock();
        let mut removed = 0;
        for (id, job) in self.jobs.all()? {
            let Some(statement) = job.statement() else {
                continue;
            };
            if statement.roots.is_empty() {
                if job.state.finished() && self.read_past(&job)? {
                    self.jobs.remove(job.agent, &id)?;
                    removed += 1;
                }
                continue;
            }
            let aged = now
                .zip(deadline(&statement, &clock))
                .is_some_and(|(now, deadline)| now > deadline);
            if job.state.finished() && aged {
                self.jobs.remove(job.agent, &id)?;
                removed += 1;
            } else if aged && let Some(proof) = job.state.proof() {
                self.host.hold(&proof, false);
                self.jobs.put(&id, &job.to(State::Dead))?;
            }
        }
        Ok(removed)
    }

    /// Whether `job`'s record is behind its agent's watermark and compacted
    /// out of its log.
    fn read_past(&self, job: &Job) -> Result<bool, String> {
        Ok(self.jobs.watermark(job.agent)? >= job.index
            && self.host.log_start(job.agent)? >= job.index)
    }

    /// Read `agent`'s records past its watermark, through its applied
    /// index, into jobs: the new jobs.
    fn scan(&mut self, agent: AgentId) -> Result<usize, String> {
        let applied = self.host.applied(agent);
        let from = self.jobs.watermark(agent)?;
        let mut made = 0;
        let mut through = from;
        for index in from + 1..=applied {
            let Some(attests) = self.host.attests(agent, index)? else {
                self.lost += 1;
                through = index;
                continue;
            };
            for attest in attests.into_iter().filter(|attest| attest.window.is_some()) {
                let Some(statement) = self.statement(&attest)? else {
                    // Its kernel's blob is not here yet: read again later.
                    self.jobs.set_watermark(agent, through)?;
                    return Ok(made);
                };
                let id = statement.id();
                if self.jobs.get(agent, &id)?.is_some() {
                    continue;
                }
                let window = attest.window.unwrap_or(0);
                let state = match self.host.proven(agent, window, &id) {
                    Some(proof) => State::Proved { proof },
                    None => State::Queued,
                };
                self.jobs
                    .put(&id, &Job::new(agent, index, attest, &statement, state))?;
                made += 1;
            }
            through = index;
        }
        if through != from {
            self.jobs.set_watermark(agent, through)?;
        }
        Ok(made)
    }

    /// The statement `attest` makes: `None` while its kernel's blob is not
    /// here, or its program could not be computed for now; a kernel the
    /// prover cannot read makes a statement of no program, which the
    /// prover then refuses.
    fn statement(&mut self, attest: &Attest) -> Result<Option<Statement>, String> {
        let program = match self.programs.get(&attest.program) {
            Some(program) => *program,
            None => {
                let Some(blob) = self.host.program(&attest.program) else {
                    return Ok(None);
                };
                let program = match self.prover.program(&blob) {
                    Ok(program) => program,
                    Err(ProveError::Kernel(_)) => ProgramId([u32::MAX; 8]),
                    Err(_) => return Ok(None),
                };
                self.programs.insert(attest.program, program);
                program
            }
        };
        Ok(Some(statement(attest, program)))
    }

    /// `jobs`, each queued job of an agent this node follows that its agent
    /// now records proved taken as proved: a replica's table follows its
    /// leader's.
    fn follow(&self, jobs: Vec<(StatementId, Job)>) -> Result<Vec<(StatementId, Job)>, String> {
        jobs.into_iter()
            .map(|(id, job)| {
                if job.state != State::Queued || self.host.leads(job.agent) {
                    return Ok((id, job));
                }
                let Some(proof) = self.host.proven(job.agent, job.window, &id) else {
                    return Ok((id, job));
                };
                let job = job.to(State::Proved { proof });
                self.jobs.put(&id, &job)?;
                Ok((id, job))
            })
            .collect()
    }

    /// Submit `id` again no sooner than a wait from now, twice the last
    /// one, [`Options::retry`] the first time: the wait, and how often it
    /// has gone again for an answer `counted` towards [`MAX_RESUBMITS`],
    /// this time included if it is.
    fn retry_later(&mut self, id: StatementId, counted: bool) -> (Duration, u32) {
        let (wait, count) = self
            .retries
            .get(&id)
            .map_or((self.options.retry, 0), |(_, wait, count)| {
                (*wait * 2, *count)
            });
        let count = count + u32::from(counted);
        self.retries
            .insert(id, (Instant::now() + wait, wait, count));
        (wait, count)
    }

    /// Whether `statement`'s anchor passes `MaxRootAge` by the venue's time
    /// `ahead` from now; unknown, while the venue's time is, as not.
    fn dead(&self, statement: &Statement, ahead: Duration) -> bool {
        let Some(deadline) = deadline(statement, &self.host.clock()) else {
            return false;
        };
        self.venue
            .time()
            .is_some_and(|now| now.saturating_add(ahead.as_millis() as u64) > deadline)
    }

    /// The queued job of a led agent to prove next: the one whose anchor
    /// ages first, then the oldest record.
    fn next(&self, jobs: &[(StatementId, Job)]) -> Option<(StatementId, Job)> {
        jobs.iter()
            .filter(|(_, job)| job.state == State::Queued && self.host.leads(job.agent))
            .min_by_key(|(_, job)| {
                let deadline = job
                    .statement()
                    .and_then(|statement| deadline(&statement, &self.host.clock()));
                (deadline.unwrap_or(u64::MAX), job.agent, job.index)
            })
            .cloned()
    }

    /// Prove `job`: taken as proved when its agent records it proved by
    /// another replica; dead when its anchor would age past `MaxRootAge`
    /// before its proof ends; refused once [`MAX_ATTEMPTS`] proofs of it
    /// began; else proved, its proof kept, held and recorded, or refused.
    /// False when its kernel's blob is not here, or the prover failed: it
    /// waits, queued.
    fn prove(&mut self, id: StatementId, job: Job) -> Result<bool, String> {
        let agent = job.agent.0;
        if let Some(proof) = self.host.proven(job.agent, job.window, &id)
            && !self.unfetched.contains(&id)
        {
            self.jobs.put(&id, &job.to(State::Proved { proof }))?;
            return Ok(true);
        }
        let (Some(statement), Some(attest)) = (job.statement(), job.attest.clone()) else {
            self.jobs
                .put(&id, &job.to(State::Refused(REFUSED_KERNEL)))?;
            return Ok(true);
        };
        if self.dead(&statement, self.options.expected.max(self.longest)) {
            tracing::warn!(
                agent,
                "a statement's anchor ages before its proof would end: dead"
            );
            self.jobs.put(&id, &job.to(State::Dead))?;
            return Ok(true);
        }
        if job.attempts >= MAX_ATTEMPTS {
            tracing::error!(
                agent,
                attempts = job.attempts,
                "a statement's proof never ended: refused"
            );
            self.jobs
                .put(&id, &job.to(State::Refused(REFUSED_KERNEL)))?;
            return Ok(true);
        }
        let Some(kernel) = self.host.program(&attest.program) else {
            return Ok(false);
        };
        let mut job = job.to(State::Proving);
        job.attempts += 1;
        self.jobs.put(&id, &job)?;
        let started = Instant::now();
        let prover = Arc::clone(&self.prover);
        let proved = crate::redact::proving(|| prover.prove(&kernel, &attest))
            .unwrap_or(Err(ProveError::Failed("the prover panicked")));
        let took = started.elapsed();
        match proved {
            Ok(proof) => {
                self.longest = self.longest.max(took);
                self.unfetched.remove(&id);
                let proof = self.host.keep(&proof)?;
                self.host.hold(&proof, true);
                let (recorder, window) = (job.agent, job.window);
                self.jobs.put(&id, &job.to(State::Proved { proof }))?;
                tracing::info!(agent, seconds = took.as_secs_f64(), "a statement proved");
                self.host.record(recorder, window, id, proof);
            }
            Err(ProveError::Rerun(_)) => {
                tracing::error!(agent, "a record's re-run is not its statement: refused");
                self.jobs.put(&id, &job.to(State::Refused(REFUSED_RERUN)))?;
            }
            Err(ProveError::Kernel(_)) => {
                tracing::error!(agent, "a record's kernel is not provable: refused");
                self.jobs
                    .put(&id, &job.to(State::Refused(REFUSED_KERNEL)))?;
            }
            Err(ProveError::Failed(reason)) => {
                tracing::warn!(
                    agent,
                    attempts = job.attempts,
                    reason,
                    "a proof failed: queued again"
                );
                self.jobs.put(&id, &job.to(State::Queued))?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// `job`, holding `proof`, moved to `state`: the proof held no longer.
    fn release(
        &self,
        id: &StatementId,
        job: Job,
        proof: [u8; 32],
        state: State,
    ) -> Result<(), String> {
        self.host.hold(&proof, false);
        self.jobs.put(id, &job.to(state))
    }

    /// The proved jobs of the agents this node leads, in the order of
    /// their statements' earliest windows.
    fn submittable(&self, jobs: &[(StatementId, Job)]) -> Vec<(StatementId, Job)> {
        let mut by_window: BTreeMap<(u64, AgentId, u64), (StatementId, Job)> = BTreeMap::new();
        for (id, job) in jobs {
            if job.state.proof().is_some() && self.host.leads(job.agent) {
                let window = job.earliest_window().unwrap_or(0);
                by_window.insert((window, job.agent, job.index), (*id, job.clone()));
            }
        }
        by_window.into_values().collect()
    }

    /// Submit the led agents' proved statements that are recorded in their
    /// agents and whose roots the venue holds anchored: each handed over
    /// once its job says so, a repeat counted as accepted, a refusal that
    /// may not hold later ([`vos_venue::transient`]) submitted again after
    /// a backoff until its anchor ages. The number handed over.
    fn submit(&mut self, jobs: &[(StatementId, Job)]) -> Result<usize, String> {
        let mut handed = 0;
        for (id, job) in self.submittable(jobs) {
            let Some(proof) = job.state.proof() else {
                continue;
            };
            let Some(statement) = job.statement() else {
                self.jobs
                    .put(&id, &job.to(State::Refused(REFUSED_KERNEL)))?;
                continue;
            };
            if self.dead(&statement, Duration::ZERO) {
                tracing::warn!(
                    agent = job.agent.0,
                    "a proved statement's anchor aged: dead"
                );
                self.release(&id, job, proof, State::Dead)?;
                continue;
            }
            // Recorded in its agent first, so every replica knows it proved.
            if self.host.proven(job.agent, job.window, &id).is_none() {
                self.host.record(job.agent, job.window, id, proof);
                continue;
            }
            if self
                .retries
                .get(&id)
                .is_some_and(|(at, ..)| Instant::now() < *at)
            {
                continue;
            }
            if !statement.roots.iter().all(|root| self.venue.anchored(root)) {
                continue;
            }
            let Some(bytes) = self.host.proof(job.agent, &proof) else {
                let asked = *self.asked.entry(id).or_insert_with(Instant::now);
                if asked.elapsed() >= self.options.patience {
                    tracing::warn!(agent = job.agent.0, "a proof never arrived: proved here");
                    self.asked.remove(&id);
                    self.unfetched.insert(id);
                    let state = if job.attest.is_some() {
                        State::Queued
                    } else {
                        State::Refused(REFUSED_KERNEL)
                    };
                    self.release(&id, job, proof, state)?;
                }
                continue;
            };
            self.asked.remove(&id);
            self.host.hold(&proof, true);
            let job = job.to(State::Submitted { proof });
            self.jobs.put(&id, &job)?;
            handed += 1;
            let Some(state) = self.judged(id, &job, &statement, &bytes) else {
                continue;
            };
            self.retries.remove(&id);
            self.release(&id, job, proof, state)?;
        }
        Ok(handed)
    }

    /// The venue's verdict on `statement` with its proof's `bytes`, as
    /// `job`'s next state: none while it goes again later.
    fn judged(
        &mut self,
        id: StatementId,
        job: &Job,
        statement: &Statement,
        bytes: &[u8],
    ) -> Option<State> {
        let repeated = Refusal::Repeated.code();
        let state = match self.venue.submit(statement, bytes) {
            Ok(_) => State::Accepted,
            Err(NotAccepted::Refused(code)) if code == repeated => State::Accepted,
            Err(NotAccepted::Refused(code)) if vos_venue::transient(code) => {
                let unjudged = code >= vos_venue::UNJUDGED_FROM;
                let (wait, count) = self.retry_later(id, unjudged);
                // `Unanchored` goes again until the anchor ages; a
                // failure to judge a bounded number of times.
                if unjudged && count > MAX_RESUBMITS {
                    tracing::error!(
                        agent = job.agent.0,
                        code,
                        "a statement the venue failed to judge, every time: refused"
                    );
                    State::Refused(code)
                } else {
                    tracing::warn!(
                        agent = job.agent.0,
                        code,
                        seconds = wait.as_secs(),
                        "a statement refused for now: submitted again later"
                    );
                    return None;
                }
            }
            Err(NotAccepted::Refused(code)) => {
                tracing::error!(
                    agent = job.agent.0,
                    code,
                    "a statement refused by the venue"
                );
                State::Refused(code)
            }
            Err(NotAccepted::Unjudged(why)) => {
                // A rootless statement has no deadline: its answers
                // lost count, a bounded number of times, and then it
                // goes once more, a repeat (`Refusal::Repeated`)
                // counted as accepted, an acceptance whose answer was
                // lost. Funding and the configuration are the
                // operator's, and do not count.
                let lost = why == Unjudged::Unknown;
                let (wait, count) = self.retry_later(id, lost);
                if statement.roots.is_empty() && count > MAX_RESUBMITS {
                    match self.venue.submit(statement, bytes) {
                        Ok(_) => State::Accepted,
                        Err(NotAccepted::Refused(code)) if code == repeated => State::Accepted,
                        Err(NotAccepted::Refused(code)) => State::Refused(code),
                        Err(NotAccepted::Unjudged(why)) => {
                            tracing::error!(
                                agent = job.agent.0,
                                ?why,
                                "a rootless statement never judged: dead"
                            );
                            State::Dead
                        }
                    }
                } else {
                    tracing::warn!(
                        agent = job.agent.0,
                        ?why,
                        seconds = wait.as_secs(),
                        "a statement not judged: submitted again later"
                    );
                    return None;
                }
            }
        };
        Some(state)
    }
}
