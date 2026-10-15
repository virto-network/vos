//! The model's terms: the counter instances, its timing, how clients
//! send, the suite's nodes as its clients see them, the run's log, and the
//! counter's methods.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use vos_node::client::Target;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session};
use vos_wire::peer::NodeNumber;
use vos_wire::schema::Schema;

/// The counter instance a client forwarding to the next agent increments.
pub const COUNTER: InstanceId = InstanceId(1);
/// The counter instance an agent's messages increment.
pub const INBOX: InstanceId = InstanceId(2);
/// The counter instance a second client at each agent increments.
pub const SECOND: InstanceId = InstanceId(3);
/// How long one attempt waits for its answer before trying another node.
pub const ATTEMPT: Duration = Duration::from_secs(2);
/// How long a request may take to be answered, through every failure.
pub const ANSWERED: Duration = Duration::from_secs(60);

/// How a client sends its requests.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// One request in flight at a time.
    OneAtATime,
    /// Several in flight, each on its connection: lanes, in-flight
    /// duplicates and gaps meet the failures.
    Pipelined,
}

/// The suite's nodes, as its clients see them.
pub trait Nodes: Sync {
    /// How many nodes the space has, numbered from 1.
    fn count(&self) -> NodeNumber;

    /// Where node `number`'s ingress is reached.
    fn target(&self, number: NodeNumber) -> &Target;

    /// The node whose ingress an answer names by `address`.
    fn number_at(&self, address: &str) -> Option<NodeNumber>;

    /// How far every node's clock runs ahead of the wall clock: the
    /// agents' time, as clients take it, moves with it.
    fn offset(&self) -> i64;

    /// How often node `number` has started.
    fn starts(&self, number: NodeNumber) -> u64;

    /// The node leading `agent`, where the suite knows it cheaply.
    fn leader(&self, agent: AgentId) -> Option<NodeNumber>;

    /// Whether the clients pause, with every request answered.
    fn paused(&self) -> bool;

    /// Whether every node's clock is moving to a new offset, some there
    /// and some not: a node may refuse a session timed by the other.
    fn clocks_moving(&self) -> bool {
        false
    }

    /// The suite's record of what happened.
    fn log(&self) -> &Log;

    /// What the suite can say of `agent`, when a check fails.
    fn report(&self, agent: AgentId) -> String;

    /// Node `at`, in its run `starts`, answered `sequence` of `session` at
    /// `agent`: check what the suite can see of its state, if anything.
    fn answered(
        &self,
        at: NodeNumber,
        starts: u64,
        agent: AgentId,
        session: &Session,
        sequence: u64,
    ) {
        let _ = (at, starts, agent, session, sequence);
    }

    /// The agents' time, as clients take it.
    fn time(&self) -> u64 {
        vos_node::wall_clock().saturating_add_signed(self.offset())
    }
}

/// What a run saw, by kind, and its last events, for a failure's report.
#[derive(Default)]
pub struct Log {
    seen: Mutex<BTreeMap<&'static str, u64>>,
    events: Mutex<VecDeque<String>>,
}

impl Log {
    /// The most events kept.
    const EVENTS: usize = 40;

    pub fn saw(&self, what: &'static str) {
        *self.seen.lock().unwrap().entry(what).or_default() += 1;
    }

    pub fn event(&self, what: String) {
        let mut events = self.events.lock().unwrap();
        if events.len() == Self::EVENTS {
            events.pop_front();
        }
        events.push_back(what);
    }

    pub fn seen(&self) -> BTreeMap<&'static str, u64> {
        self.seen.lock().unwrap().clone()
    }

    pub fn events(&self) -> String {
        let events = self.events.lock().unwrap();
        events.iter().cloned().collect::<Vec<_>>().join("\n")
    }
}

/// The methods of the counter program a client calls.
#[derive(Clone, Copy, Debug)]
pub struct Methods {
    pub increment: MethodId,
    pub value: MethodId,
    /// Sends its amount to another agent's counter, as a message.
    pub forward: MethodId,
}

impl Methods {
    /// The counter's methods, by their names in its `schema`.
    pub fn of(schema: &Schema) -> Self {
        let method = |name: &str| {
            schema
                .method_id(name)
                .unwrap_or_else(|| panic!("no method {name}"))
        };
        Self {
            increment: method("increment"),
            value: method("value"),
            forward: method("forward"),
        }
    }
}
