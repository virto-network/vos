//! A world of agents for an actor's tests: each the default agent on a
//! VOS node's refine and accumulate hosts ([`Node`]), its actors installed
//! from their derivations, calls made by name in one session per caller,
//! every batch at the world's clock, and the messages between its agents
//! delivered in order as the nodes deliver them.
//!
//! ```text
//! let mut world = World::new();
//! world
//!     .agent(HOME)
//!     .install_in(SPACE, CREDENTIALS, &credentials, &[("registrar", 1)])
//!     .install_in(SPACE, HOMES, &homes, &[("operator", 1)])
//!     .grant(ALICE, 1);
//! // A call by name, in ALICE's session: its run.
//! let run = world.agent(HOME).call(ALICE, HOMES, "configure", terms);
//! let done: Result<(), HomesError> = answer(&run.outcome);
//! // A member's proven call, as ingress hands it on (`CredentialedInput`).
//! let run = world
//!     .agent(HOME)
//!     .proven(CREDENTIALS, (b"home", nullifier), HOMES, "claim", claim);
//! // What its steps sent, delivered between the world's agents.
//! world.deliver_all();
//! world.pass(3_600_000);
//! let tally: Counts = world.read(HOME, HOMES, "tally", ());
//! ```

use std::collections::{BTreeMap, VecDeque};

use vos_abi::abi::Failure;
use vos_abi::abi::cap::Target;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_abi::records::Derivation;
use vos_abi::result::{Outcome, Outgoing, Run, Step};
use vos_abi::{Decode, Encode, SpaceId, WindowClock};
use vos_pvm_compiler::Derived;
use vos_wire::batch::{Admin, CredentialedInput, Input, Message, Query, Request, Work};
use vos_wire::credentials::{self, AuthClaim, OwnerClaim, RootEntry};
use vos_wire::defaults::{DEVICE_FORMATS, SESSION_EXPIRY_MS};
use vos_wire::ingress::Grant;

use crate::node::Node;
use crate::programs::method;

/// The batch time a world starts at.
pub const T0: u64 = 1_800_000_000_000;

/// How long a credentialed call's binding holds, past its batch time.
const BINDING_MS: u64 = 60_000;

/// The agents of a test, their clock and the messages they sent.
pub struct World {
    agents: BTreeMap<AgentId, Agent>,
    /// The next batch's time; each batch moves it a millisecond on.
    pub now: u64,
    /// The next message's number, by sender and receiver.
    sequences: BTreeMap<(AgentId, AgentId), u64>,
    /// The messages sent and not yet delivered, by their sender, in order.
    sent: VecDeque<(AgentId, Outgoing)>,
    /// Credentialed calls made, which each binding is drawn from.
    bindings: u64,
}

/// One agent: its node, and what a caller names its instances by.
struct Agent {
    node: Node,
    /// Each installed instance's actor program, linked, and its space.
    installed: BTreeMap<InstanceId, (Vec<u8>, SpaceId)>,
    /// Each caller's session, its last sequence and its last call's time.
    sessions: BTreeMap<Principal, (Session, u64, u64)>,
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    /// No agent yet, its clock at [`T0`].
    pub fn new() -> Self {
        Self::at(T0)
    }

    /// No agent yet, its clock at `now`.
    pub fn at(now: u64) -> Self {
        Self {
            agents: BTreeMap::new(),
            now,
            sequences: BTreeMap::new(),
            sent: VecDeque::new(),
            bindings: 0,
        }
    }

    /// Agent `agent`, on a node of its own from its first use.
    pub fn agent(&mut self, agent: AgentId) -> On<'_> {
        self.agents.entry(agent).or_insert_with(|| Agent {
            node: Node::of(agent),
            installed: BTreeMap::new(),
            sessions: BTreeMap::new(),
        });
        On { world: self, agent }
    }

    /// Agent `agent`'s node: its state, its programs.
    pub fn node(&self, agent: AgentId) -> &Node {
        &self.agents[&agent].node
    }

    /// Agent `agent`'s node, to change apart from a batch: a program
    /// added, one forgotten.
    pub fn node_mut(&mut self, agent: AgentId) -> &mut Node {
        &mut self.agents.get_mut(&agent).expect("an agent").node
    }

    /// The id of method `name` of the actor at `agent`'s `instance`.
    pub fn method(&self, agent: AgentId, instance: InstanceId, name: &str) -> MethodId {
        let (program, _) = self.agents[&agent]
            .installed
            .get(&instance)
            .expect("an installed instance");
        method(program, name)
    }

    /// `caller`'s query of `instance`'s `name` at `agent`, at the clock:
    /// its outcome.
    pub fn query(
        &self,
        agent: AgentId,
        caller: Principal,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> Outcome {
        let work = Work::Query(Query {
            time: self.now,
            seed: [0; 32],
            caller,
            instance,
            method: self.method(agent, instance, name),
            arguments: arguments.encode(),
        });
        Outcome::decode(&self.node(agent).refine(&work))
            .expect("an outcome")
            .0
    }

    /// An anonymous query of `instance`'s `name` at `agent` that runs to
    /// `Done`: its reply.
    pub fn read<T: Decode>(
        &self,
        agent: AgentId,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> T {
        match self.query(agent, Principal::Client([0; 32]), instance, name, arguments) {
            Outcome::Done(bytes) => T::decode_exact(&bytes).expect("the reply decodes"),
            other => panic!("{name}: {other:?}"),
        }
    }

    /// Move the clock on by `ms`.
    pub fn pass(&mut self, ms: u64) {
        self.now += ms;
    }

    /// The messages sent and not yet delivered, in order.
    pub fn sent(&self) -> impl Iterator<Item = &(AgentId, Outgoing)> {
        self.sent.iter()
    }

    /// Queue `message` as sent by `from`: a message a test makes itself.
    pub fn send(&mut self, from: AgentId, message: Outgoing) {
        self.sent.push_back((from, message));
    }

    /// Deliver every message sent, and every message their steps send, in
    /// order, until none is left: each delivery's receiver and run.
    pub fn deliver_all(&mut self) -> Vec<(AgentId, Run)> {
        self.deliver(|_| true)
    }

    /// Deliver the messages `from` sent, and every message their steps
    /// set off, in order; the other agents' earlier messages stay queued,
    /// as on nodes that have not delivered them yet.
    pub fn deliver_from(&mut self, from: AgentId) -> Vec<(AgentId, Run)> {
        self.deliver(|sender| sender == from)
    }

    fn deliver(&mut self, picked: impl Fn(AgentId) -> bool) -> Vec<(AgentId, Run)> {
        let (mut queue, kept): (VecDeque<_>, VecDeque<_>) =
            self.sent.drain(..).partition(|(from, _)| picked(*from));
        self.sent = kept;
        let mut delivered = Vec::new();
        while let Some((from, Outgoing { to, body })) = queue.pop_front() {
            let sequence = self.sequences.entry((from, to)).or_insert(0);
            *sequence += 1;
            let input = Input::Message(Message {
                from,
                sequence: *sequence,
                body,
            });
            assert!(
                self.agents.contains_key(&to),
                "a message to {to:?}, no agent of this world"
            );
            let waiting = self.sent.len();
            let run = self.agent(to).step(input);
            queue.extend(self.sent.drain(waiting..));
            delivered.push((to, run));
        }
        delivered
    }
}

/// An agent of a [`World`], at the world's clock.
pub struct On<'w> {
    world: &'w mut World,
    agent: AgentId,
}

impl On<'_> {
    fn this(&self) -> &Agent {
        &self.world.agents[&self.agent]
    }

    fn this_mut(&mut self) -> &mut Agent {
        self.world.agents.get_mut(&self.agent).expect("an agent")
    }

    /// The agent's node.
    pub fn node(&mut self) -> &mut Node {
        self.world.node_mut(self.agent)
    }

    /// `derived` installed at `instance`, outside any space, its roles
    /// `roles` by name and byte.
    pub fn install(
        &mut self,
        instance: InstanceId,
        derived: &Derived,
        roles: &[(&str, u8)],
    ) -> &mut Self {
        self.install_in(SpaceId::NONE, instance, derived, roles)
    }

    /// [`On::install`] in `space`.
    pub fn install_in(
        &mut self,
        space: SpaceId,
        instance: InstanceId,
        derived: &Derived,
        roles: &[(&str, u8)],
    ) -> &mut Self {
        let programs: Vec<&[u8]> = std::iter::once(derived.actor.as_slice())
            .chain(derived.kernels.iter().map(|(_, kernel)| kernel.as_slice()))
            .collect();
        self.install_derivation(space, instance, derived.derivation(), &programs, roles)
    }

    /// The install of `derivation` at `instance` in `space`, the node
    /// holding `programs`, the actor's program first: a release's package
    /// installs so.
    pub fn install_derivation(
        &mut self,
        space: SpaceId,
        instance: InstanceId,
        derivation: Derivation,
        programs: &[&[u8]],
        roles: &[(&str, u8)],
    ) -> &mut Self {
        for program in programs {
            self.node().add(program);
        }
        let actor = programs.first().expect("the actor's program").to_vec();
        self.this_mut().installed.insert(instance, (actor, space));
        let install = Input::Admin(Admin::Install {
            instance,
            derivation,
            roles: roles
                .iter()
                .map(|(name, role)| (name.as_bytes().to_vec(), *role))
                .collect(),
            target: Target::Vos,
            space,
            clock: WindowClock::DEFAULT,
        });
        let run = self.step(install);
        assert!(
            matches!(run.outcome, Outcome::Done(_)),
            "install: {:?}",
            run.outcome
        );
        self
    }

    /// `role` granted to `principal`.
    pub fn grant(&mut self, principal: Principal, role: u8) -> &mut Self {
        let run = self.step(Input::Admin(Admin::SetRole(Grant {
            principal,
            role: Some(role),
        })));
        assert!(
            matches!(run.outcome, Outcome::Done(_)),
            "grant: {:?}",
            run.outcome
        );
        self
    }

    /// The id of method `name` of the actor at `instance`.
    pub fn method(&self, instance: InstanceId, name: &str) -> MethodId {
        self.world.method(self.agent, instance, name)
    }

    /// `inputs` in one batch at the world's clock, which moves a
    /// millisecond on: its steps. The messages they send wait for
    /// [`World::deliver_all`].
    pub fn batch(&mut self, inputs: Vec<Input>) -> Vec<Step> {
        let now = self.world.now;
        let result = self.node().batch(now, inputs);
        self.world.now += 1;
        let agent = self.agent;
        for step in &result.steps {
            if let Step::Ran(run) = step {
                self.world
                    .sent
                    .extend(run.messages.iter().map(|message| (agent, message.clone())));
            }
        }
        result.steps
    }

    /// `input` alone in a batch: its run.
    pub fn step(&mut self, input: Input) -> Run {
        match self.batch(vec![input]).into_iter().next() {
            Some(Step::Ran(run)) => run,
            other => panic!("did not run: {other:?}"),
        }
    }

    /// `caller`'s session for a call now and the call's sequence, moved
    /// on: a new session when its last call is older than a session's
    /// expiry allows.
    pub fn session(&mut self, caller: Principal) -> (Session, u64) {
        let now = self.world.now;
        let fresh = || {
            let key = match caller {
                Principal::Client(key) => key,
                _ => [0; 32],
            };
            let mut name = [0; 16];
            name[..8].copy_from_slice(&now.to_le_bytes());
            (Session { key, name, t0: now }, 0, now)
        };
        let entry = self.this_mut().sessions.entry(caller).or_insert_with(fresh);
        if entry.2 + SESSION_EXPIRY_MS / 2 < now {
            *entry = fresh();
        }
        entry.1 += 1;
        entry.2 = now;
        (entry.0, entry.1)
    }

    /// `caller`'s request of `instance`'s `name`, not yet sent.
    pub fn request(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> Request {
        let method = self.method(instance, name);
        let (session, sequence) = self.session(caller);
        Request {
            session,
            sequence,
            caller,
            instance,
            method,
            arguments: arguments.encode(),
        }
    }

    /// `caller`'s call of `instance`'s `name`, alone in a batch: its run.
    pub fn call(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> Run {
        let request = self.request(caller, instance, name, arguments);
        self.step(Input::Request(request))
    }

    /// [`World::query`] at this agent.
    pub fn query(
        &self,
        caller: Principal,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> Outcome {
        self.world
            .query(self.agent, caller, instance, name, arguments)
    }

    /// [`World::read`] at this agent.
    pub fn read<T: Decode>(&self, instance: InstanceId, name: &str, arguments: impl Encode) -> T {
        self.world.read(self.agent, instance, name, arguments)
    }

    /// The input a member's proven call of `instance`'s `name` is past
    /// ingress: its proof of the credential actor at `credentials`' stock
    /// `auth` kernel verified, its claim at the actor's root now, in scope
    /// `scope` of `instance`, under the member's `nullifier` there, bound
    /// to a binding of its own.
    pub fn credentialed(
        &mut self,
        credentials: InstanceId,
        (scope, nullifier): (&[u8], [u8; 32]),
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> CredentialedInput {
        self.world.bindings += 1;
        let mut binding = [0x3b; 32];
        binding[..8].copy_from_slice(&self.world.bindings.to_le_bytes());
        let root: RootEntry = self.read(credentials, "root", ());
        let (_, space) = self.this().installed[&instance];
        let scope = credentials::scope(&space, self.agent, instance, scope);
        let claim = AuthClaim {
            map_root: root.root,
            scope,
            nullifier,
            binding,
        };
        CredentialedInput {
            origin: Principal::Anonymous { scope, nullifier },
            instance,
            method: self.method(instance, name),
            arguments: arguments.encode(),
            binding,
            expires_ms: self.world.now + BINDING_MS,
            claim: claim.encode(),
            kernel: self.method(credentials, "auth"),
            format: DEVICE_FORMATS[0].0,
            release: self
                .this()
                .node
                .release(credentials, self.method(credentials, "auth")),
        }
    }

    /// The input an owner's proven call of `instance`'s `name` is past
    /// ingress: its proof of the credential actor at `credentials`' stock
    /// `owner` kernel verified, its claim the owner digest `owner`, bound
    /// to a binding of its own.
    pub fn owned(
        &mut self,
        credentials: InstanceId,
        owner: [u8; 32],
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> CredentialedInput {
        self.world.bindings += 1;
        let mut binding = [0x3c; 32];
        binding[..8].copy_from_slice(&self.world.bindings.to_le_bytes());
        CredentialedInput {
            origin: Principal::Owner(owner),
            instance,
            method: self.method(instance, name),
            arguments: arguments.encode(),
            binding,
            expires_ms: self.world.now + BINDING_MS,
            claim: OwnerClaim { owner, binding }.encode(),
            kernel: self.method(credentials, "owner"),
            format: DEVICE_FORMATS[0].0,
            release: self
                .this()
                .node
                .release(credentials, self.method(credentials, "owner")),
        }
    }

    /// [`On::credentialed`]'s input alone in a batch: its run.
    pub fn proven(
        &mut self,
        credentials: InstanceId,
        member: (&[u8], [u8; 32]),
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> Run {
        let input = self.credentialed(credentials, member, instance, name, arguments);
        self.step(Input::Credentialed(Box::new(input)))
    }
}

/// A run's answer: its handler's reply, or its handler's error. Any other
/// outcome panics.
pub fn answer<T: Decode, E: Decode>(outcome: &Outcome) -> Result<T, E> {
    match outcome {
        Outcome::Done(bytes) => Ok(T::decode_exact(bytes).expect("the reply decodes")),
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } => Err(E::decode_exact(detail).expect("the error decodes")),
        other => panic!("{other:?}"),
    }
}
