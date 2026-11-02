//! A batch's run: refined and dry-run on executors, its result proposed,
//! and, in flight with those after it, waited for until this replica
//! applied it.

use std::sync::Arc;
use std::time::Instant;

use smol::future::FutureExt;
use vos_wire::Encode;
use vos_wire::batch::{Batch, Work};
use vos_wire::keys;
use vos_wire::keys::Due;
use vos_wire::records::unstored;
use vos_wire::result::{Step, WorkResult, Write as StateWrite};

use super::{Ended, Leader, is_due, leads};
use crate::blobs::{Held, Keep, blob_ref};
use crate::fault::Fault;
use crate::group::{DryRun, Local};
use crate::node::Inner;
use crate::node::Pending;
use crate::pvm::{self, AgentState};
use crate::stats::Histogram;
use crate::store::{BlobRef, EntryKind, LARGE_RESULT, LogEntry, Snapshot};

/// A batch proposed whose result has yet to apply here.
pub(super) struct Flight {
    pub(super) pending: Vec<Pending>,
    pub(super) result: WorkResult,
    /// The state it refined on.
    pub(super) before: Arc<Snapshot>,
    /// Its entry's index.
    pub(super) index: u64,
    /// Its dry run's writes, which the batches after it refine over.
    pub(super) writes: Vec<StateWrite>,
    /// The first due row its sweep found, if it swept.
    pub(super) sweeping: Option<(u64, Due)>,
    /// When it started, and when its proposal was answered.
    pub(super) started: Instant,
    pub(super) proposed: Instant,
}

/// A batch's run up to its proposal.
pub(super) enum Launched {
    /// Proposed at its index: its result, its dry run's writes and when the
    /// proposal was answered.
    Proposed {
        index: u64,
        result: WorkResult,
        writes: Vec<StateWrite>,
        proposed: Instant,
    },
    /// Leadership ended before it was proposed.
    Lost,
}

impl Leader {
    /// Refine `batch`, or take `marker`, a `Cut` marker, as its result
    /// unrefined; dry-run accumulate on the same state, propose the result,
    /// and wait until this replica applied it.
    pub(super) async fn execute(
        &mut self,
        snapshot: Arc<Snapshot>,
        batch: Batch,
        blobs: Vec<BlobRef>,
        marker: Option<WorkResult>,
    ) -> Result<Ended, Fault> {
        let started = Instant::now();
        let launched = self
            .launch(Arc::clone(&snapshot), batch, blobs, marker)
            .await?;
        let Launched::Proposed {
            index,
            result,
            writes,
            proposed,
        } = launched
        else {
            return Ok(Ended::Lost);
        };
        self.sweeps.writes(&writes);
        let flight = Flight {
            pending: Vec::new(),
            result,
            before: snapshot,
            index,
            writes,
            sweeping: None,
            started,
            proposed,
        };
        self.land(&flight).await
    }

    /// Refine `batch`, or take `marker` as its result; dry-run accumulate
    /// on the same state, which the batches in flight's writes are over,
    /// and propose the result.
    pub(super) async fn launch(
        &mut self,
        snapshot: Arc<Snapshot>,
        batch: Batch,
        blobs: Vec<BlobRef>,
        marker: Option<WorkResult>,
    ) -> Result<Launched, Fault> {
        let id = self.id;
        let (version, inputs) = (batch.version, batch.inputs.len() as u64);
        let stats = &self.inner.stats;
        stats.batch_inputs.record(inputs);
        let work = Arc::new(Work::Batch(batch));
        let (output, refine_gas) = match marker {
            Some(marker) => (marker.encode(), 0),
            None => {
                self.refine(Arc::clone(&snapshot), Arc::clone(&work))
                    .await?
            }
        };
        let result: WorkResult = pvm::decode(&output)?;
        // The inputs' steps' gas: a workflow's due step is no input's.
        let step_gas: u64 = result
            .steps
            .iter()
            .map(|step| match step {
                Step::Ran(run) if !is_due(step) => run.gas_used,
                _ => 0,
            })
            .sum();
        stats.refine_gas.record(refine_gas / inputs.max(1));
        stats.step_gas.record(step_gas / inputs.max(1));
        // The dry run: a failure here isolates its input off the log. A
        // large result is stored meanwhile, as the blob its entry names.
        let (payload, writes, held) = if output.len() >= LARGE_RESULT {
            let output = Arc::new(output);
            let stored = store_result(&self.inner, Arc::clone(&output));
            let dried = self.dry_run(snapshot, work, output);
            let (stored, writes) = smol::future::zip(stored, dried).await;
            let (blob, held) = stored?;
            let entry = LogEntry {
                term: 0,
                kind: EntryKind::LargeResult,
                blobs: [vec![blob], blobs].concat(),
                body: Vec::new(),
            };
            (entry.payload(), writes?, Some(held))
        } else {
            let entry = LogEntry {
                term: 0,
                kind: EntryKind::Result,
                blobs,
                body: output,
            };
            let payload = entry.payload();
            let writes = self.dry_run(snapshot, work, Arc::new(entry.body)).await?;
            (payload, writes, None)
        };
        let written = writes
            .iter()
            .find(|write| write.key == keys::version())
            .and_then(|write| write.value.as_deref())
            .and_then(unstored)
            .and_then(|bytes| vos_wire::Decode::decode(bytes).ok())
            .map(|(version, _): (u64, usize)| version);
        if written != Some(version + 1) {
            return Err(Fault::Invariant(format!(
                "accumulate skipped the work result: the agent's state is not at version {version}"
            )));
        }
        self.inner.keep_dry_run(
            id,
            DryRun {
                applied: self.applied,
                term: self.term,
                seed: result.seed,
                version,
                writes: writes.clone(),
            },
        );
        let (answer, answered) = smol::channel::bounded(1);
        let term = self.term;
        let proposing = Instant::now();
        let proposed = self.inner.to_group(
            id,
            Local::Propose {
                term,
                payload,
                answer,
                held,
            },
        );
        if !proposed {
            return Ok(Launched::Lost);
        }
        let answer = async { Some(answered.recv().await) };
        let stopped = async {
            self.shared.wait(|state| state.stopped).await;
            None
        };
        let (index, proposed) = match answer.or(stopped).await {
            Some(Ok((Ok(index), taken))) => (index, taken),
            _ => return Ok(Launched::Lost),
        };
        stats.ran(&stats.propose, proposing, proposed);
        // The next batch's state follows this one's.
        self.applied = index;
        Ok(Launched::Proposed {
            index,
            result,
            writes,
            proposed,
        })
    }

    /// Wait until this replica applied `flight`'s result: how it ended.
    pub(super) async fn land(&mut self, flight: &Flight) -> Result<Ended, Fault> {
        let (term, index) = (self.term, flight.index);
        let stats = &self.inner.stats;
        let state = self
            .shared
            .wait(|state| state.stopped || !leads(state, term) || state.commit >= index)
            .await;
        if state.commit < index {
            return Ok(Ended::Lost);
        }
        // The commit's and the apply's ends as the driver and the applier
        // saw them: the time this task took to be polled again is the
        // runtime's, apart.
        let committed = state.commit_at.unwrap_or_else(Instant::now);
        stats.ran(&stats.commit, flight.proposed, committed);
        let state = self
            .shared
            .wait(|state| state.stopped || !leads(state, term) || state.applied >= index)
            .await;
        if state.applied < index {
            return Ok(Ended::Lost);
        }
        let applied = state.applied_at.unwrap_or_else(Instant::now);
        stats.ran(&stats.apply, committed, applied);
        stats.batch.took(flight.started.elapsed());
        // The entry at its index is this leader's, of its term.
        let ours = self
            .inner
            .store
            .log_entry(self.id, index)?
            .is_some_and(|entry| entry.term == term);
        if !ours {
            return Ok(Ended::Lost);
        }
        Ok(match self.shared.outcome(index) {
            Some(true) => Ended::Done(flight.result.clone()),
            _ => Ended::Skipped,
        })
    }

    /// Refine `work`, a batch's, on an executor, unless the refine hook
    /// fails the batch: its output and gas.
    async fn refine(
        &self,
        snapshot: Arc<Snapshot>,
        work: Arc<Work>,
    ) -> Result<(Vec<u8>, u64), Fault> {
        let id = self.id;
        let hooks = Arc::clone(&self.inner.hooks);
        let machines = self.inner.machines.clone();
        let gas = self.inner.settings.refine_gas;
        let stats = &self.inner.stats;
        self.timed(&stats.refine_queue, &stats.refine, move || {
            if hooks.fail_refine(id, batch(&work)) {
                return Err(Fault::Agent("a hook failed the refine".into()));
            }
            machines.refine(AgentState::shared(snapshot, id), id, &work, gas)
        })
        .await
    }

    /// Accumulate `result` on `snapshot` on an executor, unless the dry
    /// run's hook fails `work`'s batch: the writes applying it would make.
    async fn dry_run(
        &self,
        snapshot: Arc<Snapshot>,
        work: Arc<Work>,
        result: Arc<Vec<u8>>,
    ) -> Result<Vec<StateWrite>, Fault> {
        let id = self.id;
        let hooks = Arc::clone(&self.inner.hooks);
        let machines = self.inner.machines.clone();
        let gas = self.shared.record.accumulate_gas;
        let stats = &self.inner.stats;
        self.timed(&stats.dry_run_queue, &stats.dry_run, move || {
            if hooks.fail_dry_run(id, batch(&work)) {
                return Err(Fault::Agent("a hook failed accumulate".into()));
            }
            let state = AgentState::of(snapshot, id);
            machines.accumulate(&state, id, Arc::unwrap_or_clone(result), gas)
        })
        .await
    }

    /// Run `work` on an executor: its wait for one recorded in `queue`, and
    /// its run in `stage`.
    async fn timed<T: Send + 'static>(
        &self,
        queue: &Histogram,
        stage: &Histogram,
        work: impl FnOnce() -> Result<T, Fault> + Send + 'static,
    ) -> Result<T, Fault> {
        let queued = Instant::now();
        let (output, running, finished) = self
            .inner
            .executors
            .run(move || {
                let running = Instant::now();
                let output = work();
                (output, running, Instant::now())
            })
            .await?;
        queue.took(running - queued);
        self.inner.stats.ran(stage, running, finished);
        output
    }
}

/// The batch `work` carries.
fn batch(work: &Work) -> &Batch {
    work.batch().expect("a batch's work")
}

/// Store a large work result as a blob, hashed on an executor, held until
/// the entry naming it is written. That entry's log row keeps it from then
/// on, and once the log is compacted past it, it goes within its brief
/// horizon.
async fn store_result(inner: &Inner, result: Arc<Vec<u8>>) -> Result<(BlobRef, Held), Fault> {
    let hashed = Arc::clone(&result);
    let blob = inner.executors.run(move || blob_ref(&hashed)).await?;
    let held = inner.blobs.hold(blob.hash);
    inner
        .blobs
        .put(blob, result, Keep::Named)
        .await
        .map_err(|error| Fault::Storage(format!("the blob store failed: {error}")))?;
    Ok((blob, held))
}
