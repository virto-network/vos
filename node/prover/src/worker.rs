//! The worker: from the records of the agents this node replicates, each
//! attest at a window's cut whose statement waits to be proved
//! (`vos_wire::keys::attested`, the same on every replica and carried by
//! its snapshots) becomes a job; for the agents it leads, one job at a time
//! is proved, and each proof is kept, recorded in its agent, and submitted
//! once its roots are anchored. Each unfinished job's kernel is held.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_venue::vos_statement::{ProgramId, Statement, StatementId};
use vos_venue::{SubmitOutcome, VenueClient};
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::result::Attest;
use vos_wire::{SpaceId, WindowClock};

use vos_wire::defaults::READ_WINDOWS;

use crate::job::{
    Job, MAX_ATTEMPTS, MAX_RESUBMITS, REFUSED_KERNEL, REFUSED_RERUN, REFUSED_ROOTLESS,
    REFUSED_UNWITNESSED, State, deadline,
};

/// The longest wait before a statement not accepted goes again: the
/// longest window a space's clock registers.
const RETRY_MAX: Duration = Duration::from_millis(vos_wire::vos_anchor::MAX_LENGTH_MS);

/// The final proofs' format: the masked wrap's.
pub const FORMAT: u32 = vos_venue::vos_statement::vos_pvm_final_verifier::masked::FORMAT;

/// What the worker reads of and does to the node it runs on.
pub trait Host {
    /// Whether this node leads `agent` now: only its leader proves its
    /// records and submits their statements.
    fn leads(&self, agent: AgentId) -> bool;
    /// The agents this node replicates: every replica reads their records
    /// into jobs, so a new leader holds them already.
    fn agents(&self) -> Vec<AgentId>;
    /// The records of `agent`'s attests at the cuts of window `from` and
    /// later (`vos_wire::keys::attested`), as this replica applied them, in
    /// window order.
    fn attested(&self, agent: AgentId, from: u64) -> Result<Vec<Record>, String>;
    /// A program's blob, by its hash: a kernel an attest names. When this
    /// node does not hold it, `agent`'s other replicas are asked for it.
    fn program(&self, agent: AgentId, hash: &ProgramHash) -> Option<Vec<u8>>;
    /// The proof `agent` holds recorded for statement `id` of window
    /// `window`'s cut (`vos_wire::keys::proven`), as this replica applied
    /// it.
    fn proven(&self, agent: AgentId, window: u64, id: &StatementId) -> Option<[u8; 32]>;
    /// Keep a final proof: its BLAKE2b-256.
    fn keep(&self, proof: &[u8]) -> Result<[u8; 32], String>;
    /// Keep the blob `hash` whatever its age (`held`), or no longer: a
    /// statement's proof from its proof until its job finishes, and each
    /// unfinished job's kernel.
    fn hold(&self, hash: &[u8; 32], held: bool);
    /// The blobs this node holds whatever their age, as [`Host::hold`]
    /// holds them.
    fn held(&self) -> Vec<[u8; 32]>;
    /// The proof `hash`, if this node holds it; when not, `agent`'s other
    /// replicas are asked for it.
    fn proof(&self, agent: AgentId, hash: &[u8; 32]) -> Option<Vec<u8>>;
    /// Have `agent`'s leader record statement `id` of window `window`'s cut
    /// proved by `proof`, of the record `attested`
    /// (`vos_wire::batch::Input::Proven`).
    fn record(
        &self,
        agent: AgentId,
        window: u64,
        id: StatementId,
        proof: [u8; 32],
        attested: [u8; 32],
    );
    /// The space's clock, which numbers the windows its roots are of.
    fn clock(&self) -> WindowClock;
}

/// The record of an attest at a window's cut: its window, its digest
/// ([`Attest::digest`]) and the attest, its witness gone once its
/// statement is recorded proved.
pub type Record = (u64, [u8; 32], Attest);

/// The worker's table, durable: each statement's job by id.
pub trait Jobs {
    fn get(&self, agent: AgentId, id: &StatementId) -> Result<Option<Job>, String>;
    /// Write `job`, durably before it returns.
    fn put(&self, id: &StatementId, job: &Job) -> Result<(), String>;
    /// Remove a job.
    fn remove(&self, agent: AgentId, id: &StatementId) -> Result<(), String>;
    /// Every job.
    fn all(&self) -> Result<Vec<(StatementId, Job)>, String>;
    /// Whether the node was stopping when it last ran: a proof it ended
    /// then was ended by its operator, not by its kernel.
    fn stopping(&self) -> Result<bool, String>;
    /// Mark the node stopping, or (`false`) running, durably.
    fn set_stopping(&self, stopping: bool) -> Result<(), String>;
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
    /// refused for now ([`SubmitOutcome::Retry`]), waits before it goes
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
    /// Each kernel's program id, by its blob's hash, once computed.
    programs: HashMap<ProgramHash, ProgramId>,
    /// The kernels asked of the replicas, not here when a record named
    /// them: alerted once each.
    fetching: HashSet<ProgramHash>,
    /// The kernels held for the unfinished jobs.
    kernels: BTreeSet<ProgramHash>,
    /// Each agent's earliest window a record not yet read into a job may
    /// be of: the window of the reads still served, or of a record whose
    /// kernel was not here.
    from: HashMap<AgentId, u64>,
    /// The proofs another replica made, asked for or never arrived.
    fetches: HashMap<StatementId, Fetch>,
    /// When each submission whose answer was lost, or that was refused for
    /// now, goes again, and the wait after that.
    retries: HashMap<StatementId, (Instant, Duration)>,
    /// The longest proof timed.
    longest: Duration,
}

/// A proof another replica made, as this node fetches it.
#[derive(Clone, Copy)]
enum Fetch {
    /// Asked for since then.
    Asked(Instant),
    /// Never arrived: proved here.
    Lost,
}

impl<H: Host, J: Jobs> Worker<H, J> {
    /// A worker over `jobs`: a job a stopped worker was proving goes back
    /// to the queue, to be proved again, the attempt not counted when the
    /// node was stopping then. Of the blobs the node holds, those no job
    /// wants any more (a crash between a job's end and the next step) are
    /// held no longer.
    pub fn open(
        host: H,
        jobs: J,
        prover: Arc<dyn Prover>,
        venue: Arc<dyn VenueClient>,
        options: Options,
    ) -> Result<Self, String> {
        let stopping = jobs.stopping()?;
        let mut wanted = HashSet::new();
        for (id, job) in jobs.all()? {
            if let Some(proof) = job.state.proof() {
                wanted.insert(proof);
            }
            if let Some(attest) = job.attest.as_ref().filter(|_| !job.state.finished()) {
                wanted.insert(attest.program.0);
            }
            match job.state {
                State::Proving => {
                    let attempts = job.attempts.saturating_sub(u32::from(stopping));
                    let job = Job {
                        attempts,
                        ..job.to(State::Queued)
                    };
                    jobs.put(&id, &job)?;
                }
                State::Proved { proof } | State::Submitted { proof } => {
                    host.hold(&proof, true);
                    if host.proven(job.agent, job.window, &id).is_none() {
                        host.record(job.agent, job.window, id, proof, job.attested);
                    }
                }
                _ => {}
            }
        }
        for held in host.held() {
            if !wanted.contains(&held) {
                host.hold(&held, false);
            }
        }
        jobs.set_stopping(false)?;
        Ok(Self {
            host,
            jobs,
            prover,
            venue,
            options,
            programs: HashMap::new(),
            fetching: HashSet::new(),
            kernels: BTreeSet::new(),
            from: HashMap::new(),
            fetches: HashMap::new(),
            retries: HashMap::new(),
            longest: Duration::ZERO,
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

    /// One step: every replicated agent's new records read into jobs, the
    /// unfinished jobs' kernels held, the led agents' proved statements
    /// whose roots are anchored submitted, then one statement proved, the
    /// one whose anchor ages first of those whose kernel is here.
    pub fn step(&mut self) -> Result<Stepped, String> {
        let mut stepped = Stepped::default();
        for agent in self.host.agents() {
            stepped.read += self.scan(agent)?;
        }
        let jobs = self.follow(self.jobs.all()?)?;
        self.hold_kernels(&jobs);
        stepped.submitted = self.submit(&jobs)?;
        let mut tried = HashSet::new();
        while let Some((id, job)) = self.next(&jobs, &tried) {
            tried.insert(id);
            if self.prove(id, job)? {
                stepped.proved = true;
                stepped.more = self.next(&self.jobs.all()?, &HashSet::new()).is_some();
                break;
            }
        }
        Ok(stepped)
    }

    /// The jobs counted by state.
    pub fn backlog(&self) -> Result<Backlog, String> {
        let mut backlog = Backlog::default();
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

    /// Age out the jobs whose roots no venue anchors any more: a finished
    /// one removed, an unfinished one dead, its proof held no longer; and
    /// remove the finished jobs of agents this node does not replicate now
    /// (an unfinished one, of an agent absent for a while only, ages out).
    pub fn prune(&mut self) -> Result<usize, String> {
        let now = self.venue.time();
        let clock = self.host.clock();
        let agents: HashSet<AgentId> = self.host.agents().into_iter().collect();
        let mut removed = 0;
        for (id, job) in self.jobs.all()? {
            let aged = job
                .statement()
                .and_then(|statement| deadline(&statement, &clock))
                .zip(now)
                .is_some_and(|(deadline, now)| now > deadline);
            if job.state.finished() && (aged || !agents.contains(&job.agent)) {
                if let Some(proof) = job.state.proof() {
                    self.host.hold(&proof, false);
                }
                self.jobs.remove(job.agent, &id)?;
                removed += 1;
            } else if aged {
                if let Some(proof) = job.state.proof() {
                    self.host.hold(&proof, false);
                }
                self.jobs.put(&id, &job.to(State::Dead))?;
            }
        }
        self.from.retain(|agent, _| agents.contains(agent));
        Ok(removed)
    }

    /// Read `agent`'s records into jobs, from the earliest window one not
    /// yet read may be of: the new jobs. A record already a job (by its
    /// statement's id) makes none; one whose kernel is not here is read
    /// again later; a rootless one, which no venue takes, makes a refused
    /// job. A new record is of a window at most [`READ_WINDOWS`] before the
    /// latest, the windows of the reads still served.
    fn scan(&mut self, agent: AgentId) -> Result<usize, String> {
        let from = self.from.get(&agent).copied().unwrap_or(0);
        let mut latest = None;
        let mut waiting: Option<u64> = None;
        let mut made = 0;
        for (window, digest, attest) in self.host.attested(agent, from)? {
            latest = Some(window);
            let Some(statement) = self.statement(agent, &attest)? else {
                waiting = Some(waiting.map_or(window, |earliest| earliest.min(window)));
                continue;
            };
            let id = statement.id();
            if self.jobs.get(agent, &id)?.is_some() {
                continue;
            }
            let state = match (
                attest.roots.is_empty(),
                self.host.proven(agent, window, &id),
            ) {
                (true, _) => {
                    tracing::warn!(agent = agent.0, "a record at a cut states no root: refused");
                    State::Refused(REFUSED_ROOTLESS)
                }
                (false, Some(proof)) => State::Proved { proof },
                (false, None) => State::Queued,
            };
            let job = Job::new(agent, digest, attest, &statement, state);
            self.jobs.put(&id, &job)?;
            made += 1;
        }
        if let Some(latest) = latest {
            let next = latest.saturating_sub(READ_WINDOWS);
            let next = waiting.map_or(next, |waiting| waiting.min(next));
            self.from.insert(agent, next.max(from));
        }
        Ok(made)
    }

    /// The statement `attest` makes: `None` while its kernel's blob is not
    /// here (asked of the replicas, alerted once), or its program could not
    /// be computed for now; a kernel the prover cannot read makes a
    /// statement of no program, which the prover then refuses.
    fn statement(&mut self, agent: AgentId, attest: &Attest) -> Result<Option<Statement>, String> {
        let program = match self.programs.get(&attest.program) {
            Some(program) => *program,
            None => {
                let Some(blob) = self.host.program(agent, &attest.program) else {
                    if self.fetching.insert(attest.program) {
                        tracing::warn!(
                            agent = agent.0,
                            "a record's kernel is not here: asked of the replicas, its record waiting"
                        );
                    }
                    return Ok(None);
                };
                self.fetching.remove(&attest.program);
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

    /// Hold the kernel of each unfinished job, and no longer those of none.
    fn hold_kernels(&mut self, jobs: &[(StatementId, Job)]) {
        let wanted: BTreeSet<ProgramHash> = jobs
            .iter()
            .filter(|(_, job)| !job.state.finished())
            .filter_map(|(_, job)| job.attest.as_ref().map(|attest| attest.program))
            .collect();
        for kernel in wanted.difference(&self.kernels) {
            self.host.hold(&kernel.0, true);
        }
        for kernel in self.kernels.difference(&wanted) {
            self.host.hold(&kernel.0, false);
        }
        self.kernels = wanted;
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
    /// one, [`Options::retry`] the first time, at most [`RETRY_MAX`]: the
    /// wait.
    fn retry_later(&mut self, id: StatementId) -> Duration {
        let wait = self
            .retries
            .get(&id)
            .map_or(self.options.retry, |(_, wait)| {
                wait.saturating_mul(2).min(RETRY_MAX)
            });
        self.retries.insert(id, (Instant::now() + wait, wait));
        wait
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

    /// The queued job of a led agent to prove next, of those not `tried`:
    /// the one whose anchor ages first, then by agent and record.
    fn next(
        &self,
        jobs: &[(StatementId, Job)],
        tried: &HashSet<StatementId>,
    ) -> Option<(StatementId, Job)> {
        jobs.iter()
            .filter(|(id, job)| {
                job.state == State::Queued && self.host.leads(job.agent) && !tried.contains(id)
            })
            .min_by_key(|(_, job)| {
                let deadline = job
                    .statement()
                    .and_then(|statement| deadline(&statement, &self.host.clock()));
                (deadline.unwrap_or(u64::MAX), job.agent, job.attested)
            })
            .cloned()
    }

    /// Prove `job`: taken as proved when its agent records it proved by
    /// another replica; dead when its anchor would age past `MaxRootAge`
    /// before its proof ends; refused once [`MAX_ATTEMPTS`] proofs of it
    /// began, or when its record kept no witness (recorded proved, its proof
    /// never fetched); else proved, its proof kept, held and recorded, or
    /// refused. False when its kernel's blob is not here, or the prover
    /// failed: it waits, queued.
    fn prove(&mut self, id: StatementId, job: Job) -> Result<bool, String> {
        let agent = job.agent.0;
        let lost = matches!(self.fetches.get(&id), Some(Fetch::Lost));
        if let Some(proof) = self.host.proven(job.agent, job.window, &id)
            && !lost
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
        if attest.witness_input.is_empty() {
            tracing::error!(
                agent,
                "a statement recorded proved whose proof never arrived, its record without its witness: refused"
            );
            self.jobs
                .put(&id, &job.to(State::Refused(REFUSED_UNWITNESSED)))?;
            return Ok(true);
        }
        let Some(kernel) = self.host.program(job.agent, &attest.program) else {
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
                self.fetches.remove(&id);
                let proof = self.host.keep(&proof)?;
                let (recorder, window, attested) = (job.agent, job.window, job.attested);
                // Proved before held: a crash between the two leaves a job
                // whose opening holds its proof.
                self.jobs.put(&id, &job.to(State::Proved { proof }))?;
                self.host.hold(&proof, true);
                tracing::info!(agent, seconds = took.as_secs_f64(), "a statement proved");
                self.host.record(recorder, window, id, proof, attested);
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
        let mut by_window: BTreeMap<(u64, AgentId, [u8; 32]), (StatementId, Job)> = BTreeMap::new();
        for (id, job) in jobs {
            if job.state.proof().is_some() && self.host.leads(job.agent) {
                let window = job.earliest_window().unwrap_or(0);
                by_window.insert((window, job.agent, job.attested), (*id, job.clone()));
            }
        }
        by_window.into_values().collect()
    }

    /// Submit the led agents' proved statements that are recorded in their
    /// agents and whose roots the venue holds anchored: each handed over
    /// once its job says so, a repeat counted as accepted, a refusal that
    /// may not hold later ([`SubmitOutcome::Retry`]) submitted again after
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
                self.host
                    .record(job.agent, job.window, id, proof, job.attested);
                continue;
            }
            if self
                .retries
                .get(&id)
                .is_some_and(|(at, _)| Instant::now() < *at)
            {
                continue;
            }
            if !statement.roots.iter().all(|root| self.venue.anchored(root)) {
                continue;
            }
            let Some(bytes) = self.host.proof(job.agent, &proof) else {
                let fetch = *self
                    .fetches
                    .entry(id)
                    .or_insert_with(|| Fetch::Asked(Instant::now()));
                if let Fetch::Asked(asked) = fetch
                    && asked.elapsed() >= self.options.patience
                {
                    tracing::warn!(agent = job.agent.0, "a proof never arrived: proved here");
                    self.fetches.insert(id, Fetch::Lost);
                    let state = if job.attest.is_some() {
                        State::Queued
                    } else {
                        State::Refused(REFUSED_KERNEL)
                    };
                    self.release(&id, job, proof, state)?;
                }
                continue;
            };
            self.fetches.remove(&id);
            self.host.hold(&proof, true);
            let mut job = job.to(State::Submitted { proof });
            self.jobs.put(&id, &job)?;
            handed += 1;
            let Some(state) = self.judged(id, &mut job, &statement, &bytes) else {
                self.jobs.put(&id, &job)?;
                continue;
            };
            self.retries.remove(&id);
            self.release(&id, job, proof, state)?;
        }
        Ok(handed)
    }

    /// The venue's outcome of `statement` with its proof's `bytes`, as
    /// `job`'s next state: none while it goes again later. A venue's
    /// failure to judge it counts towards [`MAX_RESUBMITS`], in the job;
    /// the rest that go again (its anchor yet to land, the paying space's
    /// configuration or funds, an answer lost) go until its anchor ages.
    fn judged(
        &mut self,
        id: StatementId,
        job: &mut Job,
        statement: &Statement,
        bytes: &[u8],
    ) -> Option<State> {
        let code = match self.venue.submit(statement, bytes) {
            SubmitOutcome::Accepted => return Some(State::Accepted),
            SubmitOutcome::Refused(code) => {
                tracing::error!(
                    agent = job.agent.0,
                    code,
                    "a statement refused by the venue"
                );
                return Some(State::Refused(code));
            }
            SubmitOutcome::Retry(code) => code,
        };
        if (vos_venue::UNJUDGED_FROM..vos_venue::UNJUDGED).contains(&code) {
            job.resubmits += 1;
            if job.resubmits > MAX_RESUBMITS {
                tracing::error!(
                    agent = job.agent.0,
                    code,
                    "a statement the venue failed to judge, every time: refused"
                );
                return Some(State::Refused(code));
            }
        }
        let wait = self.retry_later(id);
        tracing::warn!(
            agent = job.agent.0,
            code,
            seconds = wait.as_secs(),
            "a statement not accepted for now: submitted again later"
        );
        None
    }
}
