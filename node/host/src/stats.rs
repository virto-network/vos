//! How long the node's stages take, as histograms an operator reads
//! (`GET /stats`): each a count per bucket of `vos_wire::ingress::bucket`,
//! in microseconds, or in units for a count. Recording is a relaxed atomic
//! add, so any thread records without a lock.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use vos_wire::ingress::{BUCKETS, Stage, Stats as Wire, bucket};

/// One stage's counts, and their values' sum.
pub(crate) struct Histogram {
    counts: Vec<AtomicU64>,
    total: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            counts: (0..BUCKETS).map(|_| AtomicU64::new(0)).collect(),
            total: AtomicU64::new(0),
        }
    }
}

impl Histogram {
    pub(crate) fn record(&self, value: u64) {
        self.counts[bucket(value)].fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(value, Ordering::Relaxed);
    }

    pub(crate) fn took(&self, duration: Duration) {
        self.record(duration.as_micros().min(u128::from(u64::MAX)) as u64);
    }

    fn counts(&self) -> Vec<u64> {
        self.counts
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect()
    }
}

/// The stages a leader's batch goes through, and the writer's flushes.
#[derive(Default)]
pub(crate) struct Stats {
    /// An input's wait in its agent's queue, until its batch takes it.
    pub(crate) queued: Histogram,
    /// Inputs in a batch.
    pub(crate) batch_inputs: Histogram,
    /// A batch's refine's gas, per input.
    pub(crate) refine_gas: Histogram,
    /// The gas its steps used, per input: what is left of `refine_gas` is
    /// the agent program's own, around the steps.
    pub(crate) step_gas: Histogram,
    /// A batch's refine waiting for an executor.
    pub(crate) refine_queue: Histogram,
    pub(crate) refine: Histogram,
    /// Its dry run waiting for an executor.
    pub(crate) dry_run_queue: Histogram,
    pub(crate) dry_run: Histogram,
    /// From proposing its result to the core's taking it.
    pub(crate) propose: Histogram,
    /// From the core's taking it to its commit.
    pub(crate) commit: Histogram,
    /// From its commit to its apply here.
    pub(crate) apply: Histogram,
    /// The whole batch, from its refine's start to its apply.
    pub(crate) batch: Histogram,
    /// Before it: from its inputs taken to its refine's start (the state
    /// read, the inputs filtered).
    pub(crate) prepare: Histogram,
    /// After its apply: the replies, deliveries and acknowledgements.
    pub(crate) dispatch: Histogram,
    /// From a batch's end to the next one's taking its inputs: the queue
    /// read, the linger after an idle wait, the windows' rounds.
    pub(crate) between: Histogram,
    /// The leader loop's wait to be polled again after each stage ended:
    /// the runtime's queue.
    pub(crate) resume: Histogram,
    /// A signature check of a call or a query, on an executor.
    pub(crate) verify: Histogram,
    /// A credential proof's verification waiting for an executor, from
    /// its verification slot taken, and its run there.
    pub(crate) credential_queue: Histogram,
    pub(crate) credential: Histogram,
    /// A batch of an agent's root build waiting for an executor, and its
    /// run there: the builds share the executors with the batches.
    pub(crate) root_build_queue: Histogram,
    pub(crate) root_build: Histogram,
    /// How late a probe on the runtime wakes once due: a proxy for every
    /// task's wait to be polled there, the driver's and the applier's too
    /// (to the timers' millisecond or so).
    pub(crate) late: Histogram,
}

/// How often [`probe`] wakes.
const PROBE: Duration = Duration::from_millis(10);

/// Sleep [`PROBE`] at a time on the node's runtime, and record how late
/// each wake comes.
pub(crate) async fn probe(inner: Arc<crate::node::Inner>) {
    loop {
        let due = Instant::now() + PROBE;
        smol::Timer::at(due).await;
        inner
            .stats
            .late
            .took(Instant::now().saturating_duration_since(due));
    }
}

/// `histogram` on the wire, as `name`.
pub(crate) fn stage(name: &str, histogram: &Histogram) -> Stage {
    Stage {
        name: name.to_string(),
        counts: histogram.counts(),
        total: histogram.total.load(Ordering::Relaxed),
    }
}

impl Stats {
    /// A stage of a leader's batch, from `from` to `to`, and the leader
    /// loop's wait since `to` to be polled again.
    pub(crate) fn ran(&self, stage: &Histogram, from: Instant, to: Instant) {
        stage.took(to.saturating_duration_since(from));
        self.resume.took(to.elapsed());
    }

    /// Its stages, and `more` after them.
    pub(crate) fn wire(&self, more: Vec<Stage>) -> Wire {
        let mut stages = vec![
            stage("queued", &self.queued),
            stage("batch_inputs", &self.batch_inputs),
            stage("refine_gas", &self.refine_gas),
            stage("step_gas", &self.step_gas),
            stage("refine_queue", &self.refine_queue),
            stage("refine", &self.refine),
            stage("dry_run_queue", &self.dry_run_queue),
            stage("dry_run", &self.dry_run),
            stage("propose", &self.propose),
            stage("commit", &self.commit),
            stage("apply", &self.apply),
            stage("batch", &self.batch),
            stage("prepare", &self.prepare),
            stage("dispatch", &self.dispatch),
            stage("between", &self.between),
            stage("resume", &self.resume),
            stage("verify", &self.verify),
            stage("credential_queue", &self.credential_queue),
            stage("credential", &self.credential),
            stage("root_build_queue", &self.root_build_queue),
            stage("root_build", &self.root_build),
            stage("late", &self.late),
        ];
        stages.extend(more);
        Wire {
            stages,
            groups: Default::default(),
            memory: Default::default(),
        }
    }
}
