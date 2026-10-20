//! The worker: from the logs of the agents this node leads, each attest at
//! a window's cut becomes a job; one job at a time is proved; each proof is
//! kept, recorded in its agent, and submitted once its roots are anchored.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_venue::vos_statement::{ProgramId, Statement, StatementId};
use vos_venue::{NotAccepted, VenueClient};
use vos_wire::ids::{AgentId, ProgramHash};
use vos_wire::result::Attest;
use vos_wire::{SpaceId, WindowClock};

use crate::job::{Job, REFUSED_KERNEL, REFUSED_RERUN, State, deadline};

/// The final proofs' format: the masked wrap's.
pub const FORMAT: u32 = vos_venue::vos_statement::vos_pvm_final_verifier::masked::FORMAT;

/// A venue's code for a statement it holds accepted already: counted as
/// accepted.
const REPEATED: u32 = 6;

/// What the worker reads of and does to the node it runs on.
pub trait Host {
    /// Whether this node leads `agent` now: only its leader proves its
    /// records and submits their statements.
    fn leads(&self, agent: AgentId) -> bool;
    /// The agents this node leads.
    fn led(&self) -> Vec<AgentId>;
    /// The last index of `agent`'s log this replica applied.
    fn applied(&self, agent: AgentId) -> u64;
    /// The attests the work result at `index` of `agent`'s log recorded:
    /// none for another kind of entry; `None` when the log no longer holds
    /// the entry.
    fn attests(&self, agent: AgentId, index: u64) -> Result<Option<Vec<Attest>>, String>;
    /// A program's blob, by its hash: a kernel an attest names.
    fn program(&self, hash: &ProgramHash) -> Option<Vec<u8>>;
    /// The proof `agent` holds recorded for statement `id`
    /// (`vos_wire::keys::proven`), as this replica applied it.
    fn proven(&self, agent: AgentId, id: &StatementId) -> Option<[u8; 32]>;
    /// Keep a final proof: its BLAKE2b-256.
    fn keep(&self, proof: &[u8]) -> Result<[u8; 32], String>;
    /// The proof `hash`, if this node holds it; when not, `agent`'s other
    /// replicas are asked for it.
    fn proof(&self, agent: AgentId, hash: &[u8; 32]) -> Option<Vec<u8>>;
    /// Have `agent`'s leader record statement `id` proved by `proof`
    /// (`vos_wire::batch::Input::Proven`).
    fn record(&self, agent: AgentId, id: StatementId, proof: [u8; 32]);
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
    /// The prover failed: tried again.
    Failed(String),
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
    /// How many records of an agent's log one step reads.
    pub scan: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            expected: Duration::from_secs(600),
            patience: Duration::from_secs(60),
            scan: 256,
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
                    if host.proven(job.agent, &id).is_none() {
                        host.record(job.agent, id, proof);
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

    /// One step: the led agents' new records read into jobs, the proved
    /// statements whose roots are anchored submitted, then one statement
    /// proved, the one whose anchor ages first.
    pub fn step(&mut self) -> Result<Stepped, String> {
        let mut stepped = Stepped::default();
        let led = self.host.led();
        for agent in &led {
            stepped.read += self.scan(*agent)?;
        }
        let jobs = self.jobs.all()?;
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
                    let window = job
                        .statement()
                        .and_then(|statement| statement.roots.iter().map(|root| root.window).min());
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
    /// nowhere. A rootless statement's job is kept.
    pub fn prune(&mut self) -> Result<usize, String> {
        let Some(now) = self.venue.time() else {
            return Ok(0);
        };
        let clock = self.host.clock();
        let mut removed = 0;
        for (id, job) in self.jobs.all()? {
            let aged = job
                .statement()
                .and_then(|statement| deadline(&statement, &clock))
                .is_some_and(|deadline| now > deadline);
            if job.state.finished() && aged {
                self.jobs.remove(job.agent, &id)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Read `agent`'s records past its watermark, at most
    /// [`Options::scan`], into jobs: the new jobs.
    fn scan(&mut self, agent: AgentId) -> Result<usize, String> {
        let applied = self.host.applied(agent);
        let from = self.jobs.watermark(agent)?;
        let mut made = 0;
        let mut through = from;
        for index in from + 1..=applied.min(from + self.options.scan) {
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
                let state = match self.host.proven(agent, &id) {
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
    /// here; a kernel the prover cannot read makes a statement of no
    /// program, which the prover then refuses.
    fn statement(&mut self, attest: &Attest) -> Result<Option<Statement>, String> {
        let program = match self.programs.get(&attest.program) {
            Some(program) => *program,
            None => {
                let Some(blob) = self.host.program(&attest.program) else {
                    return Ok(None);
                };
                let program = self
                    .prover
                    .program(&blob)
                    .unwrap_or(ProgramId([u32::MAX; 8]));
                self.programs.insert(attest.program, program);
                program
            }
        };
        Ok(Some(Statement {
            format: FORMAT,
            program,
            space: attest
                .roots
                .first()
                .map_or(SpaceId::NONE, |root| root.space),
            public_args: attest.public_args.clone(),
            output: attest.output.clone(),
            roots: attest.roots.clone(),
        }))
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

    /// Prove `job`: dead when its anchor would age past `MaxRootAge` before
    /// its proof ends; else proved, its proof kept and recorded, or refused.
    /// False when its kernel's blob is not here, or the prover failed: it
    /// waits, queued.
    fn prove(&mut self, id: StatementId, job: Job) -> Result<bool, String> {
        let (Some(statement), Some(attest)) = (job.statement(), job.attest.clone()) else {
            self.jobs
                .put(&id, &job.to(State::Refused(REFUSED_KERNEL)))?;
            return Ok(true);
        };
        if self.dead(&statement, self.options.expected.max(self.longest)) {
            tracing::warn!(
                agent = job.agent.0,
                "a statement's anchor ages before its proof would end: dead"
            );
            self.jobs.put(&id, &job.to(State::Dead))?;
            return Ok(true);
        }
        let Some(kernel) = self.host.program(&attest.program) else {
            return Ok(false);
        };
        let agent = job.agent.0;
        let job = job.to(State::Proving);
        self.jobs.put(&id, &job)?;
        let started = Instant::now();
        let proved = self.prover.prove(&kernel, &attest);
        let took = started.elapsed();
        match proved {
            Ok(proof) => {
                self.longest = self.longest.max(took);
                let proof = self.host.keep(&proof)?;
                let recorder = job.agent;
                self.jobs.put(&id, &job.to(State::Proved { proof }))?;
                tracing::info!(agent, seconds = took.as_secs_f64(), "a statement proved");
                self.host.record(recorder, id, proof);
            }
            Err(ProveError::Rerun(why)) => {
                tracing::error!(agent, %why, "a record's re-run is not its statement: refused");
                self.jobs.put(&id, &job.to(State::Refused(REFUSED_RERUN)))?;
            }
            Err(ProveError::Kernel(why)) => {
                tracing::error!(agent, %why, "a record's kernel is not provable: refused");
                self.jobs
                    .put(&id, &job.to(State::Refused(REFUSED_KERNEL)))?;
            }
            Err(ProveError::Failed(why)) => {
                tracing::warn!(agent, %why, "a proof failed: queued again");
                self.jobs.put(&id, &job.to(State::Queued))?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Submit the led agents' proved statements that are recorded in their
    /// agents and whose roots the venue holds anchored: each handed over
    /// once its job says so, a repeat counted as accepted. The number
    /// handed over.
    fn submit(&mut self, jobs: &[(StatementId, Job)]) -> Result<usize, String> {
        let mut handed = 0;
        let mut by_window: BTreeMap<(u64, AgentId, u64), (StatementId, Job)> = BTreeMap::new();
        for (id, job) in jobs {
            if job.state.proof().is_some() && self.host.leads(job.agent) {
                let window = job
                    .statement()
                    .and_then(|statement| statement.roots.iter().map(|root| root.window).min())
                    .unwrap_or(0);
                by_window.insert((window, job.agent, job.index), (*id, job.clone()));
            }
        }
        for (id, job) in by_window.into_values() {
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
                self.jobs.put(&id, &job.to(State::Dead))?;
                continue;
            }
            // Recorded in its agent first, so every replica knows it proved.
            if self.host.proven(job.agent, &id).is_none() {
                self.host.record(job.agent, id, proof);
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
                    let state = if job.attest.is_some() {
                        State::Queued
                    } else {
                        State::Refused(REFUSED_KERNEL)
                    };
                    self.jobs.put(&id, &job.to(state))?;
                }
                continue;
            };
            self.asked.remove(&id);
            let job = job.to(State::Submitted { proof });
            self.jobs.put(&id, &job)?;
            handed += 1;
            let state = match self.venue.submit(&statement, &bytes) {
                Ok(_) | Err(NotAccepted::Refused(REPEATED)) => State::Accepted,
                Err(NotAccepted::Refused(code)) => {
                    tracing::error!(
                        agent = job.agent.0,
                        code,
                        "a statement refused by the venue"
                    );
                    State::Refused(code)
                }
                Err(NotAccepted::Unjudged(why)) => {
                    tracing::warn!(
                        agent = job.agent.0,
                        ?why,
                        "a statement not judged: submitted again later"
                    );
                    continue;
                }
            };
            self.jobs.put(&id, &job.to(state))?;
        }
        Ok(handed)
    }
}
