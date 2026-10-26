//! A client's reads: signed queries, its workflows' results, and the
//! schemas installed.

use std::collections::HashMap;
use std::time::Duration;

use vos_wire::ids::{AgentId, InstanceId, MethodId, WorkflowId};
use vos_wire::ingress::{Consistency, Rejection, Response};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

use super::{
    Client, ClientError, Target, Transport, decode_answer, signed_query, signed_workflow_read,
    workflow_read_not_after,
};

impl Client {
    /// Run query `method` on `agent`'s `instance`, good until `not_after`,
    /// on state that holds every answer this client was given for the
    /// agent: it reads its own writes, and never reads back.
    pub fn query(
        &self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
        not_after: u64,
    ) -> Result<Response, ClientError> {
        let consistency = Consistency::Applied {
            at: self.floor(agent),
        };
        self.query_with(agent, instance, method, arguments, not_after, consistency)
    }

    /// Run a query on the state `consistency` asks for. `not_after` is by
    /// this client's clock: it goes moved to the agents' time, as a node
    /// last reported it, and once more after a node says it is stale.
    pub fn query_with(
        &self,
        agent: AgentId,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
        not_after: u64,
        consistency: Consistency,
    ) -> Result<Response, ClientError> {
        let identity = self.identity(agent)?;
        let path = format!("/agents/{}/queries", agent.0);
        self.with_learned_time(|offset| {
            let query = signed_query(
                &identity,
                &self.key,
                not_after.saturating_add_signed(offset),
                consistency,
                instance,
                method,
                arguments.to_vec(),
            );
            self.read(agent, &path, &query.encode())
        })
    }

    /// Read workflow `workflow` of `agent`, which this client's key
    /// started, on state that holds every answer this client was given for
    /// the agent, waiting up to `wait` for it to end, as long as the node
    /// allows: its status, as [`Response::Workflow`]. Only the workflow's
    /// owner learns of it: to any other key it is unknown, as it is to its
    /// owner once collected, [`vos_wire::defaults::WORKFLOW_KEPT_MS`] after
    /// it ended.
    pub fn workflow(
        &self,
        agent: AgentId,
        workflow: WorkflowId,
        wait: Duration,
    ) -> Result<Response, ClientError> {
        let consistency = Consistency::Applied {
            at: self.floor(agent),
        };
        self.workflow_with(agent, workflow, wait, consistency)
    }

    /// [`Client::workflow`] on the state `consistency` asks for.
    pub fn workflow_with(
        &self,
        agent: AgentId,
        workflow: WorkflowId,
        wait: Duration,
        consistency: Consistency,
    ) -> Result<Response, ClientError> {
        let identity = self.identity(agent)?;
        let wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        let path = format!("/agents/{}/workflows", agent.0);
        self.with_learned_time(|offset| {
            let now = crate::wall_clock().saturating_add_signed(offset);
            let read = signed_workflow_read(
                &identity,
                &self.key,
                workflow_read_not_after(now, wait_ms),
                consistency,
                workflow,
                wait_ms,
            );
            self.read(agent, &path, &read.encode())
        })
    }

    /// `read` at the agents' time as this client knows it, given as its
    /// offset from this client's clock; once more after a node says it is
    /// stale, at the time that node reported.
    fn with_learned_time(
        &self,
        read: impl Fn(i64) -> Result<Response, ClientError>,
    ) -> Result<Response, ClientError> {
        let offset = self.state().offset;
        let answer = read(offset)?;
        let Response::Rejected(Rejection::StaleQuery { now }) = answer else {
            return Ok(answer);
        };
        self.learn_time(now);
        let offset = self.state().offset;
        read(offset)
    }

    /// A signed read, `body` posted to `path`: it changes nothing, so one
    /// this replica cannot answer now goes to the others in turn, the
    /// client still calling this one. An answer raises the agent's floor.
    fn read(&self, agent: AgentId, path: &str, body: &[u8]) -> Result<Response, ClientError> {
        let ask = |transport: &Transport| -> Result<Response, ClientError> {
            let (status, answered) = transport.post_repeatable(path, body)?;
            decode_answer(status, &answered)
        };
        let unanswered = |answer: &Result<Response, ClientError>| {
            matches!(
                answer,
                Err(_)
                    | Ok(Response::Rejected(Rejection::Behind)
                        | Response::TimedOut
                        | Response::Unavailable
                        | Response::Stopped
                        | Response::NotLeader { .. }
                        | Response::Elsewhere { .. })
            )
        };
        let mut answer = ask(&self.transport);
        if unanswered(&answer) {
            for replica in self.other_replicas(agent) {
                let Ok(target) = self.target_for(&replica) else {
                    continue;
                };
                answer = ask(&Transport::new(&target));
                if !unanswered(&answer) {
                    break;
                }
            }
        }
        let answer = answer?;
        if let Response::Ran { at, .. } | Response::Workflow { at, .. } = answer {
            self.raise_floor(agent, at);
        }
        Ok(answer)
    }

    /// The highest applied index an answer for `agent` reflected: the
    /// floor its queries ask a replica to have reached.
    pub fn floor(&self, agent: AgentId) -> u64 {
        self.state().floors.get(&agent).copied().unwrap_or(0)
    }

    /// Each agent's floor, to keep.
    pub fn floors(&self) -> HashMap<AgentId, u64> {
        self.state().floors.clone()
    }

    /// Raise `agent`'s floor to `at`, as an answer, or one kept from
    /// before, reflected.
    pub fn raise_floor(&self, agent: AgentId, at: u64) {
        crate::raise(&mut self.state().floors, agent, at);
    }

    /// The schema installed as `agent`'s `instance`.
    pub fn schema(
        &self,
        agent: AgentId,
        instance: InstanceId,
    ) -> Result<Option<Schema>, ClientError> {
        self.transport.schema(agent, instance)
    }
}

/// The schema installed as `agent`'s `instance`, if any.
pub fn schema(
    target: &Target,
    agent: AgentId,
    instance: InstanceId,
) -> Result<Option<Schema>, ClientError> {
    Transport::new(target).schema(agent, instance)
}

impl Transport {
    fn schema(&self, agent: AgentId, instance: InstanceId) -> Result<Option<Schema>, ClientError> {
        let path = format!("/agents/{}/instances/{}/schema", agent.0, instance.0);
        let (status, body) = self.get(&path, None)?;
        if status == 404 {
            return Ok(None);
        }
        Schema::decode(&body)
            .map(|(schema, _)| Some(schema))
            .map_err(|_| ClientError::Undecodable(status))
    }
}
