//! The agents of the space the processes make: operators' commands, agents
//! created and installed, their identities and methods, and their replicas
//! converged.

use vos_node::client::Operator;
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::ingress::{Install, ReplicaStatus, Response};
use vos_wire::peer::NodeNumber;

use super::{PROCESS_WAIT, Processes};
use crate::programs::package;
use crate::{Methods, wait_until};

impl Processes {
    /// An operator's command, at whichever running node takes it: its
    /// answer, once one is `accepted`.
    pub fn operate(
        &self,
        command: impl Fn(&Operator) -> Response,
        accepted: impl Fn(&Response) -> bool,
    ) -> Response {
        let mut answer = None;
        wait_until("an operator's command is taken", PROCESS_WAIT, || {
            answer = (1..=self.count)
                .filter(|number| self.is_running(*number))
                .map(|number| command(&self.operator(number)))
                .find(&accepted);
            answer.is_some()
        });
        answer.unwrap()
    }

    /// An agent created on `replicas`, with package `elf` installed as each
    /// of `instances`, in order.
    pub fn agent_with(
        &self,
        replicas: Vec<NodeNumber>,
        elf: &[u8],
        instances: &[InstanceId],
    ) -> AgentId {
        let installs: Vec<Install> = instances
            .iter()
            .map(|instance| Install {
                instance: *instance,
                elf: elf.to_vec(),
                roles: Vec::new(),
            })
            .collect();
        self.agent_installing(replicas, &installs)
    }

    /// An agent created on `replicas`, with each of `installs` made, in
    /// order.
    pub fn agent_installing(&self, replicas: Vec<NodeNumber>, installs: &[Install]) -> AgentId {
        let Response::Created(agent) = self.operate(
            |operator| {
                operator
                    .create_agent(replicas.clone())
                    .unwrap_or(Response::Unavailable)
            },
            |answer| matches!(answer, Response::Created(_)),
        ) else {
            unreachable!()
        };
        for install in installs {
            self.operate(
                |operator| {
                    operator
                        .install(agent, install)
                        .unwrap_or(Response::Unavailable)
                },
                |answer| matches!(answer, Response::Ran { .. }),
            );
        }
        agent
    }

    /// Agent `agent`'s identity, the hash of its creation record.
    pub fn identity(&self, agent: AgentId) -> [u8; 32] {
        let mut identity = None;
        wait_until("the agent's record is served", PROCESS_WAIT, || {
            identity = (1..=self.count)
                .filter(|number| self.is_running(*number))
                .find_map(|number| {
                    vos_node::client::agent_info(self.target(number), agent)
                        .ok()
                        .flatten()
                })
                .map(|info| vos_node::identity(&info.record));
            identity.is_some()
        });
        identity.unwrap()
    }
}

/// The counter's methods, by its schema at `agent`'s `instance`.
pub fn methods(processes: &Processes, agent: AgentId, instance: InstanceId) -> Methods {
    let mut schema = None;
    wait_until("the schema is served", PROCESS_WAIT, || {
        schema = (1..=processes.count)
            .filter(|number| processes.is_running(*number))
            .find_map(|number| {
                vos_node::client::schema(processes.target(number), agent, instance)
                    .ok()
                    .flatten()
            });
        schema.is_some()
    });
    let schema = schema.unwrap();
    let method = |name: &str| {
        schema
            .method_id(name)
            .unwrap_or_else(|| panic!("no method {name}"))
    };
    Methods {
        increment: method("increment"),
        value: method("value"),
        forward: method("forward"),
    }
}

/// An agent created on nodes 1 to 3, with the test counter installed as
/// `instance`, through whichever node takes the operator's commands.
pub fn counter_agent(processes: &Processes, instance: InstanceId) -> AgentId {
    processes.agent_with(vec![1, 2, 3], &package("counter"), &[instance])
}

/// Wait until the three replicas of `agent` applied through the commit
/// of its leader at the highest term: their statuses, read at each node.
pub fn converged(processes: &Processes, agent: AgentId) {
    wait_until(
        "every replica applies through the commit",
        PROCESS_WAIT,
        || {
            let statuses: Vec<ReplicaStatus> = (1..=processes.count)
                .filter_map(|number| processes.status(number, agent))
                .collect();
            let Some(commit) = statuses
                .iter()
                .filter(|status| status.leads)
                .max_by_key(|status| status.term)
                .map(|status| status.commit)
            else {
                return false;
            };
            statuses.len() == 3 && statuses.iter().all(|status| status.applied >= commit)
        },
    );
}
