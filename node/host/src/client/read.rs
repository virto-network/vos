//! A client's reads: signed queries, its workflows' results, and the
//! schemas installed.

use std::collections::HashMap;
use std::time::Duration;

use ed25519_dalek::Signer;
use vos_wire::ids::{AgentId, InstanceId, MethodId, WorkflowId};
use vos_wire::ingress::{
    Consistency, QueryCall, Rejection, Response, WORKFLOW_READ_HORIZON_MS, WorkflowRead,
    query_message, workflow_message, workflow_read_horizon,
};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

use super::{Client, ClientError, Http, Target, answer};
use crate::lock;

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
        let offset = || *lock(&self.offset);
        let used = offset();
        let answer = self.query_until(
            agent,
            &identity,
            (instance, method, arguments),
            not_after.saturating_add_signed(used),
            consistency,
        )?;
        let Response::Rejected(Rejection::StaleQuery { now }) = answer else {
            return Ok(answer);
        };
        self.learn_time(now);
        self.query_until(
            agent,
            &identity,
            (instance, method, arguments),
            not_after.saturating_add_signed(offset()),
            consistency,
        )
    }

    /// A query good until `not_after`, by the agents' time.
    fn query_until(
        &self,
        agent: AgentId,
        identity: &[u8; 32],
        (instance, method, arguments): (InstanceId, MethodId, &[u8]),
        not_after: u64,
        consistency: Consistency,
    ) -> Result<Response, ClientError> {
        let key = self.key.verifying_key().to_bytes();
        let message = query_message(
            identity,
            &key,
            not_after,
            consistency,
            instance,
            method,
            arguments,
        );
        let query = QueryCall {
            key,
            not_after,
            consistency,
            instance,
            method,
            arguments: arguments.to_vec(),
            signature: self.key.sign(&message).to_bytes(),
        };
        self.read(
            agent,
            &format!("/agents/{}/queries", agent.0),
            &query.encode(),
        )
    }

    /// Read workflow `workflow` of `agent`, which this client's key
    /// started, on state that holds every answer this client was given for
    /// the agent, waiting up to `wait` for it to end, as long as the node
    /// allows: its status, as [`Response::Workflow`]. Only the workflow's
    /// owner learns of it: to any other key it is unknown, as it is to its
    /// owner once collected, about an hour after it ended
    /// ([`defaults::WORKFLOW_KEPT_MS`]).
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
        let key = self.key.verifying_key().to_bytes();
        let path = format!("/agents/{}/workflows", agent.0);
        let read_until = |not_after: u64| {
            let message =
                workflow_message(&identity, &key, not_after, consistency, workflow, wait_ms);
            let read = WorkflowRead {
                key,
                not_after,
                consistency,
                workflow,
                wait_ms,
                signature: self.key.sign(&message).to_bytes(),
            };
            self.read(agent, &path, &read.encode())
        };
        // Good past the wait, by the agents' time, within half the horizon
        // a node allows: room for clocks off by as much either way.
        let not_after = || {
            crate::wall_clock()
                .saturating_add(workflow_read_horizon(wait_ms) - WORKFLOW_READ_HORIZON_MS / 2)
                .saturating_add_signed(*lock(&self.offset))
        };
        let answer = read_until(not_after())?;
        let Response::Rejected(Rejection::StaleQuery { now }) = answer else {
            return Ok(answer);
        };
        self.learn_time(now);
        read_until(not_after())
    }

    /// A signed read, `body` posted to `path`: it changes nothing, so one
    /// this replica cannot answer now goes to the others in turn, the
    /// client still calling this one. An answer raises the agent's floor.
    fn read(&self, agent: AgentId, path: &str, body: &[u8]) -> Result<Response, ClientError> {
        let ask = |http: &Http| -> Result<Response, ClientError> {
            let (status, answered) = http.post(path, None, body, true)?;
            answer(status, &answered)
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
        let mut answer = ask(&self.http);
        if unanswered(&answer) {
            for replica in self.other_replicas(agent) {
                let Ok(target) = self.target_for(&replica) else {
                    continue;
                };
                answer = ask(&Http::new(&target));
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
        lock(&self.floors).get(&agent).copied().unwrap_or(0)
    }

    /// Each agent's floor, to keep.
    pub fn floors(&self) -> HashMap<AgentId, u64> {
        lock(&self.floors).clone()
    }

    /// Raise `agent`'s floor to `at`, as an answer, or one kept from
    /// before, reflected.
    pub fn raise_floor(&self, agent: AgentId, at: u64) {
        let mut floors = lock(&self.floors);
        let floor = floors.entry(agent).or_insert(0);
        *floor = (*floor).max(at);
    }

    /// The schema installed as `agent`'s `instance`.
    pub fn schema(
        &self,
        agent: AgentId,
        instance: InstanceId,
    ) -> Result<Option<Schema>, ClientError> {
        schema_from(&self.http, agent, instance)
    }
}

/// The schema installed as `agent`'s `instance`, if any.
pub fn schema(
    target: &Target,
    agent: AgentId,
    instance: InstanceId,
) -> Result<Option<Schema>, ClientError> {
    schema_from(&Http::new(target), agent, instance)
}

fn schema_from(
    http: &Http,
    agent: AgentId,
    instance: InstanceId,
) -> Result<Option<Schema>, ClientError> {
    let path = format!("/agents/{}/instances/{}/schema", agent.0, instance.0);
    let (status, body) = http.get(&path)?;
    if status == 404 {
        return Ok(None);
    }
    Schema::decode(&body)
        .map(|(schema, _)| Some(schema))
        .map_err(|_| ClientError::Undecodable(status))
}
