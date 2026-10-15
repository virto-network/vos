//! Clients' queries, on any replica's applied state once it has applied as
//! far as the query asks: through an index the client was answered, or
//! through a read index from the agent's leader, which then holds every
//! call answered before the query. A method its schema marks linearizable
//! always reads after a read index.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_net::Class;
use vos_wire::Decode;
use vos_wire::batch::{Query, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::ingress::{Consistency, Rejection, Response};
use vos_wire::keys;
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::records::{Installed, unstored};
use vos_wire::result::Outcome;

use crate::asking::pause;
use crate::calls::answer_of;
use crate::fault::{Fault, ran};
use crate::group::Local;
use crate::node::{CATCH_UP, CallError, Inner, Run};
use crate::peer::{self, Refusal};
use crate::pvm;
use crate::store::Snapshot;
use crate::timeout;

/// How long a query waits for its replica to apply through the index it
/// asks for.
const FLOOR: Duration = Duration::from_secs(5);
/// How long a replica tries to learn a read index from its leader.
const READING: Duration = Duration::from_secs(10);
/// How long it waits for the leader's answer before it asks again.
const REASK: Duration = Duration::from_secs(2);
/// How long it waits, for a change of leader, before it asks again a leader
/// that could not answer.
const PAUSE: Duration = Duration::from_millis(100);

impl Inner {
    /// A client's query, its signature checked: run on this replica's
    /// applied state once that is as far as `consistency` asks, and for a
    /// linearizable method as far as a read index.
    pub(crate) async fn client_query(
        self: &Arc<Self>,
        agent: AgentId,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
        consistency: Consistency,
    ) -> Response {
        let Some(run) = self.run(agent) else {
            return answer_of(Err(self.absent(agent)));
        };
        let linearized = consistency == Consistency::Linearizable;
        let read = match consistency {
            Consistency::Applied { at } => self.snapshot_through(&run, at).await,
            Consistency::Linearizable => self.after_read_index(&run, agent).await,
        };
        let snapshot = match read {
            Ok(snapshot) => snapshot,
            Err(answer) => return answer,
        };
        let ran = self
            .query_on(
                snapshot, agent, caller, instance, method, arguments, linearized,
            )
            .await;
        // The program at the state it read says its method reads after a
        // read index: it runs again past one.
        let arguments = match ran {
            Ok(Queried::Linearizable(arguments)) => arguments,
            ran => return answered(ran),
        };
        let snapshot = match self.after_read_index(&run, agent).await {
            Ok(snapshot) => snapshot,
            Err(answer) => return answer,
        };
        answered(
            self.query_on(snapshot, agent, caller, instance, method, arguments, true)
                .await,
        )
    }

    /// A snapshot of the store once this replica applied `agent` through
    /// `through`, and through what it recovered, which a query also waits
    /// for.
    pub(crate) async fn snapshot_through(
        &self,
        run: &Run,
        through: u64,
    ) -> Result<Snapshot, Response> {
        let applied = run
            .shared
            .wait(|state| state.stopped || state.applied >= through.max(state.recovered));
        match timeout(FLOOR, applied).await {
            Some(state) if state.stopped => Err(Response::Stopped),
            Some(_) => Ok(self.store.snapshot()),
            None => Err(Response::Rejected(Rejection::Behind)),
        }
    }

    /// A snapshot of the store once this replica applied `agent` through a
    /// read index.
    pub(crate) async fn after_read_index(
        self: &Arc<Self>,
        run: &Arc<Run>,
        agent: AgentId,
    ) -> Result<Snapshot, Response> {
        let index = self.read_index_of(run, agent).await?;
        self.snapshot_through(run, index).await
    }

    /// A read index for `agent`: this replica's core's when it leads, else
    /// its leader's, asked again through leader changes and silences.
    async fn read_index_of(
        self: &Arc<Self>,
        run: &Arc<Run>,
        agent: AgentId,
    ) -> Result<u64, Response> {
        let until = Instant::now() + READING;
        let wait = self.reads.register(agent);
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Response::TimedOut);
            }
            let state = run.shared.state();
            if state.stopped {
                return Err(Response::Stopped);
            }
            let (leader, term) = (state.leader, state.term);
            let changed = |state: &crate::group::State| {
                state.stopped || state.leader != leader || state.term != term
            };
            // Leading, its own core confirms it; a handover under way fails
            // that, and the read asks the next leader.
            if leader == Some(self.number) {
                match self.confirm(agent).await {
                    Ok(index) => return Ok(index),
                    Err(CallError::Stopped) => return Err(Response::Stopped),
                    Err(_) => {
                        pause(run, PAUSE, until, changed).await;
                        continue;
                    }
                }
            }
            let Some(to) = leader else {
                timeout(left, run.shared.wait(changed)).await;
                continue;
            };
            self.send(
                to,
                Class::Requests,
                &PeerMessage::ReadIndex {
                    agent,
                    token: wait.token,
                },
            );
            match wait.within(REASK.min(left), run.shared.wait(changed)).await {
                Some(Some(index)) => return Ok(index),
                // It could not confirm it leads, now: again once this
                // replica follows another leader, or at the pace of a quiet
                // one, as it may only be busy.
                Some(None) => pause(run, REASK, until, changed).await,
                None => {}
            }
        }
    }

    /// A replica of `agent` asks for a read index: answered, in a task of
    /// its own, once this replica's core has confirmed it leads.
    pub(crate) fn on_read_index(self: &Arc<Self>, from: NodeNumber, agent: AgentId, token: u64) {
        if let Err(refusal) = self.check_replica(agent, from) {
            self.drops.count(refusal);
            return;
        }
        let inner = Arc::clone(self);
        self.spawn(async move {
            let index = inner.confirm(agent).await.ok();
            inner.send(
                from,
                Class::Requests,
                &PeerMessage::ReadIndexAnswer {
                    agent,
                    token,
                    index,
                },
            );
        });
    }

    /// That `from` replicates `agent`.
    pub(crate) fn check_replica(&self, agent: AgentId, from: NodeNumber) -> Result<(), Refusal> {
        peer::check_replica(self.placement(agent).as_ref(), from)
    }

    /// Confirm that this replica leads agent `id`'s group, by a read
    /// index, and wait until it has applied through that index: its
    /// applied state then holds everything committed before the call.
    pub(crate) async fn read_index(&self, id: AgentId) -> Result<u64, CallError> {
        let run = self.run(id).ok_or_else(|| self.absent(id))?;
        let index = self.confirm(id).await?;
        self.applied_through(&run, index).await?;
        Ok(index)
    }

    /// A read index from this replica's core: it leads, as a quorum has
    /// confirmed, and its applied state, through the index, holds every
    /// call answered before.
    pub(crate) async fn confirm(&self, id: AgentId) -> Result<u64, CallError> {
        let run = self.run(id).ok_or_else(|| self.absent(id))?;
        let (answer, answered) = smol::channel::bounded(1);
        if !self.propose(id, Local::ReadIndex { answer }) {
            return Err(CallError::Stopped);
        }
        let index = match answered.recv().await {
            Ok(Ok(index)) => index,
            Ok(Err(
                vos_raft::core::ReadIndexError::Backpressure
                | vos_raft::core::ReadIndexError::TimedOut,
            )) => {
                return Err(CallError::Failed(
                    "leadership was not confirmed in time".into(),
                ));
            }
            Ok(Err(_)) | Err(_) => return Err(self.not_leader(&run.shared)),
        };
        Ok(index)
    }

    /// Wait until `run`'s replica has applied through `index`, for
    /// [`CATCH_UP`] at most.
    pub(crate) async fn applied_through(&self, run: &Run, index: u64) -> Result<(), CallError> {
        let applied = run
            .shared
            .wait(|state| state.stopped || state.applied >= index);
        match timeout(CATCH_UP, applied).await {
            Some(state) if !state.stopped => Ok(()),
            Some(_) => Err(CallError::Stopped),
            None => Err(CallError::Failed(
                "the replica has not applied through its read index".into(),
            )),
        }
    }

    /// Run a query on this replica's applied state, once it has applied
    /// what it recovered.
    pub(crate) async fn query(
        self: &Arc<Self>,
        agent: AgentId,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<(Outcome, u64), CallError> {
        let run = self.run(agent).ok_or_else(|| self.absent(agent))?;
        let state = run
            .shared
            .wait(|state| state.stopped || state.applied >= state.recovered)
            .await;
        if state.stopped {
            return Err(CallError::Stopped);
        }
        let snapshot = self.store.snapshot();
        match self
            .query_on(snapshot, agent, caller, instance, method, arguments, true)
            .await?
        {
            Queried::Ran(outcome, at) => Ok((outcome, at)),
            Queried::Linearizable(_) => unreachable!("a query read as it stands runs"),
        }
    }

    /// Run a query on `snapshot` of `agent`'s applied state, on an
    /// executor. Unless `linearized`, a method its schema marks
    /// linearizable does not run there: the snapshot was not read after a
    /// read index.
    #[expect(clippy::too_many_arguments)]
    pub(crate) async fn query_on(
        &self,
        snapshot: Snapshot,
        agent: AgentId,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
        linearized: bool,
    ) -> Result<Queried, CallError> {
        let program = Arc::clone(&self.program);
        let pool = Arc::clone(&self.pool);
        let blobs = self.blobs.clone();
        let gas = self.settings.refine_gas;
        let run = move || {
            let read = |error: fjall::Error| Fault::Infrastructure(error.to_string());
            if !linearized
                && crate::queries::linearizable(&snapshot, agent, instance, method).map_err(read)?
            {
                return Ok(Queried::Linearizable(arguments));
            }
            let at = snapshot.applied(agent).map_err(read)?.unwrap_or(0);
            let (time, seed) = snapshot
                .last_result(agent)
                .map_err(read)?
                .unwrap_or((0, [0; 32]));
            let work = Work::Query(Query {
                time,
                seed,
                caller,
                instance,
                method,
                arguments,
            });
            let snapshot = Arc::new(snapshot);
            let (output, _) = pvm::refine(&program, &pool, &blobs, snapshot, agent, &work, gas)?;
            Ok(Queried::Ran(pvm::decode::<Outcome>(&output)?, at))
        };
        ran(self.executors.run(run).await)
            .map_err(|fault| CallError::Failed(fault.message().to_string()))
    }
}

/// A query's run on a snapshot.
pub(crate) enum Queried {
    /// Its outcome, and the index applied where it ran.
    Ran(Outcome, u64),
    /// Its method is linearizable, and the snapshot was not read after a
    /// read index: it did not run. Its arguments, back.
    Linearizable(Vec<u8>),
}

/// A query's answer to its client.
fn answered(ran: Result<Queried, CallError>) -> Response {
    match ran {
        Ok(Queried::Ran(outcome, at)) => Response::Ran { outcome, at },
        Ok(Queried::Linearizable(_)) => unreachable!("a query past a read index runs"),
        Err(error) => answer_of(Err(error)),
    }
}

/// Whether `instance`'s `method`, as installed at `snapshot`, always reads
/// after a read index. An instance or a method not installed is answered
/// by the query itself. The marking governs the query a client names: a
/// method it calls reads the caller's snapshot, marked or not.
pub(crate) fn linearizable(
    snapshot: &Snapshot,
    agent: AgentId,
    instance: InstanceId,
    method: MethodId,
) -> Result<bool, fjall::Error> {
    let Some(bytes) = snapshot.get(agent, &keys::installed(instance))? else {
        return Ok(false);
    };
    Ok(unstored(&bytes)
        .and_then(|bytes| Installed::decode(bytes).ok())
        .and_then(|(installed, _)| Some(installed.schema.method(method)?.linearizable))
        .unwrap_or(false))
}
