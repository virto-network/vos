//! Clients' queries, on any replica's applied state once it has applied as
//! far as the query asks: through an index the client was answered, or
//! through a read index from the agent's leader, which then holds every
//! call answered before the query.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::Class;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::ingress::{Answer, Consistency, Rejection};
use vos_wire::peer::{NodeNumber, PeerMessage};

use crate::calls::{answer_of, within};
use crate::node::{CallError, Inner, Run};
use crate::peer::{self, Refusal};

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

#[derive(Default)]
pub(crate) struct Reads {
    /// The read indexes this replica asked its leaders for, by token.
    asked: Mutex<HashMap<u64, Asked>>,
}

/// A read index asked for `agent`'s group, and where its answer goes.
type Asked = (AgentId, smol::channel::Sender<Option<u64>>);

impl Inner {
    /// A client's query, its signature checked: run on this replica's
    /// applied state once that is as far as `consistency` asks.
    pub(crate) async fn client_query(
        self: &Arc<Self>,
        agent: AgentId,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
        consistency: Consistency,
    ) -> Answer {
        let Some(run) = self.run(agent) else {
            return answer_of(Err(self.absent(agent)));
        };
        let through = match consistency {
            Consistency::Applied { at } => at,
            Consistency::Linearizable => match self.read_index_of(&run, agent).await {
                Ok(index) => index,
                Err(answer) => return answer,
            },
        };
        // Through what it recovered too, which the query would wait for.
        let applied = async {
            Some(
                run.shared
                    .wait(|state| state.stopped || state.applied >= through.max(state.recovered))
                    .await,
            )
        };
        let late = async {
            smol::Timer::after(FLOOR).await;
            None
        };
        match applied.or(late).await {
            Some(state) if state.stopped => return Answer::Stopped,
            Some(_) => {}
            None => return Answer::Rejected(Rejection::Behind),
        }
        match self.query(agent, caller, instance, method, arguments).await {
            Ok((outcome, at)) => Answer::Ran { outcome, at },
            Err(error) => answer_of(Err(error)),
        }
    }

    /// A read index for `agent`: this replica's core's when it leads, else
    /// its leader's, asked again through leader changes and silences.
    async fn read_index_of(
        self: &Arc<Self>,
        run: &Arc<Run>,
        agent: AgentId,
    ) -> Result<u64, Answer> {
        let until = Instant::now() + READING;
        let token = u64::from_le_bytes(crate::node::seed()[..8].try_into().expect("8 bytes"));
        let (answer, answered) = smol::channel::unbounded();
        self.reads
            .asked
            .lock()
            .expect("the reads")
            .insert(token, (agent, answer));
        let index = self.asking(run, agent, token, &answered, until).await;
        self.reads.asked.lock().expect("the reads").remove(&token);
        index
    }

    async fn asking(
        self: &Arc<Self>,
        run: &Arc<Run>,
        agent: AgentId,
        token: u64,
        answered: &smol::channel::Receiver<Option<u64>>,
        until: Instant,
    ) -> Result<u64, Answer> {
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Answer::TimedOut);
            }
            let state = run.shared.state();
            if state.stopped {
                return Err(Answer::Stopped);
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
                    Err(CallError::Stopped) => return Err(Answer::Stopped),
                    Err(_) => {
                        let left = until.saturating_duration_since(Instant::now());
                        within(PAUSE.min(left), run.shared.wait(changed)).await;
                        continue;
                    }
                }
            }
            let Some(to) = leader else {
                within(left, run.shared.wait(changed)).await;
                continue;
            };
            self.send(
                to,
                Class::Requests,
                &PeerMessage::ReadIndex { agent, token },
            );
            let answer = async { answered.recv().await.ok() };
            let moved = async {
                run.shared.wait(changed).await;
                None
            };
            let quiet = async {
                smol::Timer::after(REASK.min(left)).await;
                None
            };
            match answer.or(moved).or(quiet).await {
                Some(Some(index)) => return Ok(index),
                // It could not confirm it leads, now: again once this
                // replica follows another leader, or at the pace of a quiet
                // one, as it may only be busy.
                Some(None) => {
                    let left = until.saturating_duration_since(Instant::now());
                    within(REASK.min(left), run.shared.wait(changed)).await;
                }
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

    /// The leader's answer to a read index this replica asked for.
    pub(crate) fn on_read_index_answer(
        &self,
        from: NodeNumber,
        agent: AgentId,
        token: u64,
        index: Option<u64>,
    ) {
        if let Err(refusal) = self.check_replica(agent, from) {
            self.drops.count(refusal);
            return;
        }
        let waiting = self
            .reads
            .asked
            .lock()
            .expect("the reads")
            .get(&token)
            .filter(|(asked, _)| *asked == agent)
            .map(|(_, waiting)| waiting.clone());
        match waiting {
            Some(waiting) => {
                let _ = waiting.try_send(index);
            }
            None => self.drops.count(Refusal::Unmatched),
        }
    }

    /// That `from` replicates `agent`.
    pub(crate) fn check_replica(&self, agent: AgentId, from: NodeNumber) -> Result<(), Refusal> {
        let replicas = self
            .directory
            .lock()
            .expect("the directory")
            .get(&agent)
            .map(|record| record.replicas.clone());
        peer::check_replica(replicas.as_deref(), from)
    }
}
