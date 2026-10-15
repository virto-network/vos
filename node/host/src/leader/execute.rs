//! A batch's run: refined and dry-run on executors, its result proposed,
//! and waited for until this replica applied it.

use std::sync::Arc;
use std::time::Instant;

use smol::future::FutureExt;
use vos_wire::batch::{Batch, Work};
use vos_wire::keys;
use vos_wire::records::unstored;
use vos_wire::result::{InputRef, Run, Step, WorkResult, Write as StateWrite};

use super::{Leader, Ran, leads};
use crate::blobs::{Held, Keep, blob_ref};
use crate::fault::{Fault, ran};
use crate::group::{DryRun, Local, Shared};
use crate::node::Inner;
use crate::pvm;
use crate::store::{BlobRef, EntryKind, LARGE_RESULT, LogEntry, Snapshot};

impl Leader {
    /// Refine `batch`, dry-run accumulate on the same state, propose the
    /// result, and wait until this replica applied it.
    pub(super) async fn execute(
        &mut self,
        inner: &Inner,
        shared: &Shared,
        snapshot: Arc<Snapshot>,
        batch: Batch,
        blobs: Vec<BlobRef>,
    ) -> Result<Ran, Fault> {
        let id = self.id;
        let started = Instant::now();
        let inputs = batch.inputs.len() as u64;
        inner.stats.batch_inputs.record(inputs);
        let (output, refine_gas, batch) = self.refine(inner, Arc::clone(&snapshot), batch).await?;
        let result: WorkResult = pvm::decode(&output)?;
        // The inputs' steps' gas: a workflow's due step is no input's.
        let step_gas: u64 = result
            .steps
            .iter()
            .map(|step| match step {
                Step::Ran(Run {
                    input: InputRef::Due { .. },
                    ..
                }) => 0,
                Step::Ran(run) => run.gas_used,
                Step::Refused { .. } | Step::Swept { .. } => 0,
            })
            .sum();
        inner.stats.refine_gas.record(refine_gas / inputs.max(1));
        inner.stats.step_gas.record(step_gas / inputs.max(1));
        // The dry run: a failure here isolates its input off the log. A
        // large result is stored meanwhile, as the blob its entry names.
        let (payload, writes, held) = if output.len() >= LARGE_RESULT {
            let stored = store_result(inner, Arc::new(output.clone()));
            let dried = self.dry_run(inner, shared, snapshot, batch, output);
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
            let writes = self
                .dry_run(inner, shared, snapshot, batch, entry.body)
                .await?;
            (payload, writes, None)
        };
        let version = writes
            .iter()
            .find(|write| write.key == keys::version())
            .and_then(|write| write.value.as_deref())
            .and_then(unstored)
            .and_then(|bytes| vos_wire::Decode::decode(bytes).ok())
            .map(|(version, _): (u64, usize)| version);
        if version != Some(self.version + 1) {
            return Err(Fault::Invariant(format!(
                "accumulate skipped the work result: the agent's state is not at version {}",
                self.version
            )));
        }
        inner.keep_dry_run(
            id,
            DryRun {
                applied: self.applied,
                term: self.term,
                seed: result.seed,
                writes,
            },
        );
        let (answer, answered) = smol::channel::bounded(1);
        let term = self.term;
        let proposing = Instant::now();
        let proposed = inner.propose(
            id,
            Local::Propose {
                term,
                payload,
                answer,
                held,
            },
        );
        if !proposed {
            return Ok(Ran::Lost);
        }
        let answer = async { Some(answered.recv().await) };
        let stopped = async {
            shared.wait(|state| state.stopped).await;
            None
        };
        let (index, taken) = match answer.or(stopped).await {
            Some(Ok((Ok(index), taken))) => (index, taken),
            _ => return Ok(Ran::Lost),
        };
        inner
            .stats
            .propose
            .took(taken.saturating_duration_since(proposing));
        inner.stats.resume.took(taken.elapsed());
        let state = shared
            .wait(|state| state.stopped || !leads(state, term) || state.commit >= index)
            .await;
        if state.commit < index {
            return Ok(Ran::Lost);
        }
        // The commit's and the apply's ends as the driver and the applier
        // saw them: the time this task took to be polled again is the
        // runtime's, apart.
        let committed = state.commit_at.unwrap_or_else(Instant::now);
        inner
            .stats
            .commit
            .took(committed.saturating_duration_since(taken));
        inner.stats.resume.took(committed.elapsed());
        let state = shared
            .wait(|state| state.stopped || !leads(state, term) || state.applied >= index)
            .await;
        if state.applied < index {
            return Ok(Ran::Lost);
        }
        let applied = state.applied_at.unwrap_or_else(Instant::now);
        inner
            .stats
            .apply
            .took(applied.saturating_duration_since(committed));
        inner.stats.resume.took(applied.elapsed());
        inner.stats.batch.took(started.elapsed());
        // The entry at its index is this leader's, of its term.
        let ours = inner
            .store
            .log_entry(id, index)
            .map_err(|error| Fault::Infrastructure(error.to_string()))?
            .is_some_and(|entry| entry.term == term);
        if !ours {
            return Ok(Ran::Lost);
        }
        self.applied = index;
        match shared.outcome(index) {
            Some(true) => Ok(Ran::Done(result)),
            _ => Ok(Ran::Skipped),
        }
    }

    /// Refine `batch` on an executor, unless the refine hook fails it: its
    /// output and gas, with the batch back for the dry run's hook.
    async fn refine(
        &self,
        inner: &Inner,
        snapshot: Arc<Snapshot>,
        batch: Batch,
    ) -> Result<(Vec<u8>, u64, Batch), Fault> {
        let id = self.id;
        let program = Arc::clone(&inner.program);
        let pool = Arc::clone(&inner.pool);
        let blobs = inner.blobs.clone();
        let hooks = Arc::clone(&inner.hooks);
        let gas = inner.settings.refine_gas;
        let queued = Instant::now();
        let refined = inner
            .executors
            .run(move || {
                let running = Instant::now();
                if hooks.fail_refine(id, &batch) {
                    let failed = Err(Fault::Agent("a hook failed the refine".into()));
                    return (failed, [queued, running, Instant::now()]);
                }
                let work = Work::Batch(batch);
                let output = pvm::refine(&program, &pool, &blobs, snapshot, id, &work, gas);
                let Work::Batch(batch) = work else {
                    unreachable!("a batch's work")
                };
                let output = output.map(|(output, gas)| (output, gas, batch));
                (output, [queued, running, Instant::now()])
            })
            .await;
        ran(refined.map(|(output, [queued, running, finished])| {
            inner.stats.refine_queue.took(running - queued);
            inner.stats.refine.took(finished - running);
            inner.stats.resume.took(finished.elapsed());
            output
        }))
    }

    /// Accumulate `result` on `snapshot` on an executor, unless the dry
    /// run's hook fails `batch`: the writes applying it would make.
    async fn dry_run(
        &self,
        inner: &Inner,
        shared: &Shared,
        snapshot: Arc<Snapshot>,
        batch: Batch,
        result: Vec<u8>,
    ) -> Result<Vec<StateWrite>, Fault> {
        let id = self.id;
        let program = Arc::clone(&inner.program);
        let hooks = Arc::clone(&inner.hooks);
        let gas = shared.record.accumulate_gas;
        let queued = Instant::now();
        let dried = inner
            .executors
            .run(move || {
                let running = Instant::now();
                if hooks.fail_dry_run(id, &batch) {
                    let failed = Err(Fault::Agent("a hook failed accumulate".into()));
                    return (failed, [queued, running, Instant::now()]);
                }
                let writes = pvm::accumulate(&program, snapshot, id, result, gas);
                (writes, [queued, running, Instant::now()])
            })
            .await;
        ran(dried.map(|(writes, [queued, running, finished])| {
            inner.stats.dry_run_queue.took(running - queued);
            inner.stats.dry_run.took(finished - running);
            inner.stats.resume.took(finished.elapsed());
            writes
        }))
    }
}

/// Store a large work result as a blob, hashed on an executor, held until
/// the entry naming it is written. That entry's log row keeps it from then
/// on, and once the log is compacted past it, it goes within its brief
/// horizon.
async fn store_result(inner: &Inner, result: Arc<Vec<u8>>) -> Result<(BlobRef, Held), Fault> {
    let hashed = Arc::clone(&result);
    let blob = ran(inner.executors.run(move || Ok(blob_ref(&hashed))).await)?;
    let held = inner.blobs.hold(blob.hash);
    inner
        .blobs
        .put_kept(blob, result, Keep::Named)
        .await
        .map_err(|error| Fault::Storage(format!("the blob store failed: {error}")))?;
    Ok((blob, held))
}
