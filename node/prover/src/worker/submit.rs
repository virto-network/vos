//! The proved jobs submitted to the venue, and its judgments taken.

use super::*;

impl<H: Host, J: Jobs> Worker<H, J> {
    /// The proved jobs of the agents this node leads, in the order of
    /// their statements' earliest windows.
    pub(super) fn submittable(&self, jobs: &[(StatementId, Job)]) -> Vec<(StatementId, Job)> {
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
    pub(super) fn submit(&mut self, jobs: &[(StatementId, Job)]) -> Result<usize, String> {
        let mut handed = 0;
        for (id, job) in self.submittable(jobs) {
            let Some(proof) = job.state.proof() else {
                continue;
            };
            let Some(statement) = job.statement() else {
                self.jobs
                    .put(&id, &job.to(State::Refused(Refusal::Kernel)))?;
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
                        State::Refused(Refusal::Kernel)
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
    pub(super) fn judged(
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
                return Some(State::Refused(Refusal::Venue(code)));
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
                return Some(State::Refused(Refusal::Venue(code)));
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
