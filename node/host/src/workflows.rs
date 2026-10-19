//! Workflows' statuses and results, read by their owners on any replica's
//! applied state, once it has applied as far as the read asks, as queries
//! are; a read of a workflow not ended waits a while for it to end.
//!
//! The read is of the workflow's record, the agent's own row under
//! `keys::workflow`, in the format the agent writes, its head alone
//! decoded: no actor runs, so a read costs a row, and a wait reads the row
//! again at each apply, off the node's runtime thread. Only the workflow's
//! owner learns anything of it, as only its owner may wait for it in the
//! agent: any other key is answered `Unknown`, as for a workflow never
//! started or collected.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_wire::Decode;
use vos_wire::ids::{AgentId, Principal, WorkflowId};
use vos_wire::ingress::{Consistency, Response, WorkflowStatus};
use vos_wire::keys;
use vos_wire::records::{Workflow, WorkflowHead, WorkflowState, unstored};

use crate::node::Inner;
use crate::store::Snapshot;
use crate::timeout;

impl Inner {
    /// Client `key`'s read of `agent`'s workflow `workflow`, its signature
    /// checked: its status on this replica's applied state once that is
    /// as far as `consistency` asks, read again at each apply until it
    /// ends or `wait` passes.
    pub(crate) async fn client_workflow(
        self: &Arc<Self>,
        agent: AgentId,
        key: [u8; 32],
        workflow: WorkflowId,
        consistency: Consistency,
        wait: Duration,
    ) -> Response {
        let run = match self.present(agent) {
            Ok(run) => run,
            Err(error) => return error.into(),
        };
        let mut snapshot = match self.snapshot_at(&run, agent, consistency).await {
            Ok(snapshot) => Some(snapshot),
            Err(answer) => return answer,
        };
        let until = Instant::now() + wait;
        let owner = Principal::Client(key);
        loop {
            // No snapshot is held while the read waits.
            let read = {
                let (inner, snapshot) = (Arc::clone(self), snapshot.take());
                self.offload(move || {
                    let snapshot = snapshot.unwrap_or_else(|| inner.store.snapshot());
                    status_at(&snapshot, agent, owner, workflow)
                })
                .await
            };
            let (status, at) = match read {
                Some(Ok(read)) => read,
                Some(Err(answer)) => return answer,
                None => return Response::Stopped,
            };
            let left = until.saturating_duration_since(Instant::now());
            if matches!(status, WorkflowStatus::Ended(_) | WorkflowStatus::Unknown)
                || left.is_zero()
            {
                return Response::Workflow { status, at };
            }
            let applied = run.shared.wait(|state| state.stopped || state.applied > at);
            if timeout(left, applied)
                .await
                .is_none_or(|state| state.stopped)
            {
                return Response::Workflow { status, at };
            }
        }
    }
}

/// Workflow `workflow`'s status for `owner` on `snapshot` of `agent`'s
/// applied state, and the index applied there.
fn status_at(
    snapshot: &Snapshot,
    agent: AgentId,
    owner: Principal,
    workflow: WorkflowId,
) -> Result<(WorkflowStatus, u64), Response> {
    let at = snapshot
        .applied(agent)
        .map_err(|_| Response::Unavailable)?
        .unwrap_or(0);
    let Some(bytes) = snapshot
        .get(agent, &keys::workflow(workflow))
        .map_err(|_| Response::Unavailable)?
    else {
        return Ok((WorkflowStatus::Unknown, at));
    };
    // A record that does not read as the agent writes it: a row this
    // replica lost, or a format this node does not know, which its agent
    // halts on and every replica shares. The node's to mend, never an
    // answer of the workflow's.
    match unstored(&bytes).map(WorkflowHead::decode) {
        Some(Ok((head, _))) if head.format == Workflow::FORMAT => Ok((status(&head, owner), at)),
        _ => {
            tracing::error!(
                agent = agent.0,
                workflow = workflow.0,
                "a workflow's record does not read"
            );
            Err(Response::Unavailable)
        }
    }
}

/// What `record` says of its workflow to `reader`: nothing unless it is
/// the owner.
fn status(record: &WorkflowHead, reader: Principal) -> WorkflowStatus {
    if record.owner != reader {
        return WorkflowStatus::Unknown;
    }
    match &record.state {
        WorkflowState::Ready(_) | WorkflowState::Preempted(_) => WorkflowStatus::Running,
        WorkflowState::Awaiting {
            agent, deadline, ..
        } => WorkflowStatus::Awaiting {
            agent: *agent,
            deadline: *deadline,
        },
        WorkflowState::Sleeping { until } => WorkflowStatus::Sleeping { until: *until },
        WorkflowState::Attesting {
            window, deadline, ..
        } => WorkflowStatus::Attesting {
            window: *window,
            deadline: *deadline,
        },
        WorkflowState::Ended(outcome) => WorkflowStatus::Ended(outcome.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_wire::Encode;
    use vos_wire::ids::{InstanceId, MethodId, ProgramHash};
    use vos_wire::result::Outcome;

    /// The head of a record of `owner`'s workflow in `state`.
    fn record(owner: Principal, state: WorkflowState) -> WorkflowHead {
        let record = Workflow {
            format: Workflow::FORMAT,
            program: ProgramHash([1; 32]),
            instance: InstanceId(1),
            method: MethodId(1),
            owner,
            gas: 1,
            writable: 1,
            awaits: 0,
            due: 0,
            waiter: None,
            state,
            snapshot: None,
            target: vos_wire::abi::cap::Target::Vos,
            stored: 0,
        };
        WorkflowHead::decode(&record.encode()).unwrap().0
    }

    #[test]
    fn only_the_owner_reads_a_status() {
        let owner = Principal::Client([1; 32]);
        let ended = record(owner, WorkflowState::Ended(Outcome::Done(vec![7])));
        assert_eq!(
            status(&ended, owner),
            WorkflowStatus::Ended(Outcome::Done(vec![7]))
        );
        for other in [
            Principal::Client([2; 32]),
            Principal::Agent(AgentId(1)),
            Principal::Instance(InstanceId(1)),
        ] {
            assert_eq!(status(&ended, other), WorkflowStatus::Unknown);
        }
        let awaiting = WorkflowState::Awaiting {
            agent: AgentId(3),
            counter: 2,
            deadline: 9,
        };
        assert_eq!(
            status(&record(owner, awaiting), owner),
            WorkflowStatus::Awaiting {
                agent: AgentId(3),
                deadline: 9
            }
        );
        for running in [
            WorkflowState::Ready(vec![]),
            WorkflowState::Preempted(vec![]),
        ] {
            assert_eq!(
                status(&record(owner, running), owner),
                WorkflowStatus::Running
            );
        }
    }
}
