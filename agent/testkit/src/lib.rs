//! A native host for actor programs: it runs them on the PVM interpreter and
//! serves the actor ABI against in-memory state, with the default agent's
//! semantics.
//!
//! It is the reference model for the agent's differential test, so it
//! shares no overlay, dispatch or enforcement code with the agent: only
//! the wire definitions in `vos_wire`.
//!
//! Beside it, for tests and benches: [`programs`], the guest programs,
//! linked; and [`node`], what a VOS node serves the agent beyond the
//! runtime's host.

mod invocation;
mod memory;
pub mod node;
pub mod programs;
mod workflows;

use std::collections::BTreeMap;

use vos_wire::abi::cap::{Limits, Refused, Target};
use vos_wire::abi::{Failure, Kind};
use vos_wire::batch::{Await, Body};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, WorkflowId};
use vos_wire::keys;
use vos_wire::records::versioned;
use vos_wire::result::{Attest, CommittedWrite, InstanceGas, Outcome, Outgoing, Page, Write};
use vos_wire::schema::{Schema, SchemaError};
use vos_wire::{Decode, SpaceId, WindowClock};

use invocation::{Call, Invocation};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallError {
    NotAProgram,
    Schema(SchemaError),
    /// An attestable method has no kernel bound.
    Unbound(MethodId),
    /// A kernel is bound to no attestable method.
    Unmatched(MethodId),
    /// A method has two kernels bound.
    Duplicate(MethodId),
    /// A role name the schema uses has no role byte.
    UnmappedRole(Vec<u8>),
    /// The install's space or clock is not its agent's, its target is not
    /// its agent's, or its program's statics pass its target's limits: its
    /// kernels, its bytes, the pages it may write, or the gas an attestable
    /// method declares for its kernel.
    Refused(Refused),
}

struct Installed {
    program: Vec<u8>,
    schema: Schema,
    roles: BTreeMap<Vec<u8>, u8>,
    /// Each attestable method's kernel.
    kernels: Vec<(MethodId, Vec<u8>)>,
    target: Target,
    /// The pages of its heap past its program's read-write data, which a
    /// workflow's machine maps there.
    heap: u32,
}

impl Installed {
    fn kernel(&self, method: MethodId) -> Option<&[u8]> {
        self.kernels
            .iter()
            .find(|(bound, _)| *bound == method)
            .map(|(_, kernel)| kernel.as_slice())
    }
}

/// What one step produced: as a work result's step, applied to the
/// testkit's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub outcome: Outcome,
    pub instances: Vec<InstanceGas>,
    pub writes: Vec<Write>,
    pub committed: Vec<CommittedWrite>,
    pub messages: Vec<Outgoing>,
    pub attests: Vec<Attest>,
    /// The pages of a workflow's snapshot it stores or drops.
    pub pages: Vec<Page>,
    pub gas_used: u64,
}

impl Step {
    /// A step that ran nothing: `outcome`, and no effects.
    fn consumed(outcome: Outcome) -> Self {
        Self {
            outcome,
            instances: Vec::new(),
            writes: Vec::new(),
            committed: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            pages: Vec::new(),
            gas_used: 0,
        }
    }
}

pub struct Testkit {
    pub agent: AgentId,
    /// The batch time and seed operations see.
    pub time: u64,
    pub seed: [u8; 32],
    /// The agent's state version once the batch applies: its committed
    /// writes are made at it, as accumulate makes them.
    pub version: u64,
    /// The batch's budget: a workflow's step that could never run in a
    /// batch of it fails.
    pub budget: u64,
    /// Whether the batch's refine, by the agent's meter, which the model
    /// does not keep, lacks the step's limit for a workflow's effectful unit
    /// beyond what the step used before its first effect: every first
    /// effect after gas used, in every workflow step of every batch while
    /// it is set, then ends its step, unserved. A test sets it for the
    /// batch it builds so, and clears it after.
    pub uncovered: bool,
    /// The target its first install named, which every later one must.
    target: Option<Target>,
    /// The space and clock its first install named, which every later one
    /// must.
    space: Option<(SpaceId, WindowClock)>,
    instances: BTreeMap<InstanceId, Installed>,
    members: BTreeMap<Principal, u8>,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Every program installed, by hash, which a workflow keeps running
    /// whatever an upgrade does.
    programs: BTreeMap<ProgramHash, Vec<u8>>,
    /// The bytes of each page a workflow's snapshot stores.
    pages: BTreeMap<(WorkflowId, u32), Vec<u8>>,
    steps: u32,
}

/// The space and clock of an agent whose node has no genesis, which the
/// installs name unless a test names another ([`Testkit::install_in`]).
pub const SPACELESS: (SpaceId, WindowClock) = (SpaceId::NONE, WindowClock::DEFAULT);

impl Testkit {
    pub fn new(agent: AgentId) -> Self {
        Self {
            agent,
            time: 0,
            seed: [0; 32],
            version: 0,
            budget: u64::MAX,
            uncovered: false,
            target: None,
            space: None,
            instances: BTreeMap::new(),
            members: BTreeMap::new(),
            state: BTreeMap::new(),
            programs: BTreeMap::new(),
            pages: BTreeMap::new(),
            steps: 0,
        }
    }

    /// Install an actor program for a VOS node ([`Testkit::install_for`]).
    pub fn install(
        &mut self,
        instance: InstanceId,
        program: &[u8],
        kernels: &[(MethodId, &[u8])],
        roles: &[(&str, u8)],
    ) -> Result<(), InstallError> {
        self.install_for(Target::Vos, instance, program, kernels, roles)
    }

    /// Install an actor program, which holds its handlers and workflows,
    /// for `target`, binding its attestable methods to their kernels and
    /// its role names to role bytes. Refused for another target than the
    /// agent's, which its first install names, and past the target's limits
    /// on its statics.
    pub fn install_for(
        &mut self,
        target: Target,
        instance: InstanceId,
        program: &[u8],
        kernels: &[(MethodId, &[u8])],
        roles: &[(&str, u8)],
    ) -> Result<(), InstallError> {
        self.install_with_heap(SPACELESS, target, instance, program, 0, kernels, roles)
    }

    /// [`Testkit::install_for`] into an agent of `space`, whose windows
    /// `clock` numbers: refused for another space or clock than the
    /// agent's, which its first install names, before anything else.
    #[allow(clippy::too_many_arguments)]
    pub fn install_in(
        &mut self,
        space: SpaceId,
        clock: WindowClock,
        target: Target,
        instance: InstanceId,
        program: &[u8],
        kernels: &[(MethodId, &[u8])],
        roles: &[(&str, u8)],
    ) -> Result<(), InstallError> {
        self.install_with_heap((space, clock), target, instance, program, 0, kernels, roles)
    }

    /// Install what an ELF derived ([`programs::derived`]) for `target`:
    /// its actor's program, its kernels, and the pages of its heap its
    /// program leaves out, which its workflows map.
    pub fn install_derived(
        &mut self,
        target: Target,
        instance: InstanceId,
        derived: &vos_pvm_compiler::Derived,
        roles: &[(&str, u8)],
    ) -> Result<(), InstallError> {
        self.install_derived_in(SPACELESS, target, instance, derived, roles)
    }

    /// [`Testkit::install_derived`] into an agent of `space`, whose
    /// windows `clock` numbers, as [`Testkit::install_in`].
    pub fn install_derived_in(
        &mut self,
        (space, clock): (SpaceId, WindowClock),
        target: Target,
        instance: InstanceId,
        derived: &vos_pvm_compiler::Derived,
        roles: &[(&str, u8)],
    ) -> Result<(), InstallError> {
        let kernels: Vec<(MethodId, &[u8])> = derived
            .kernels
            .iter()
            .map(|(method, kernel)| (MethodId(*method), kernel.as_slice()))
            .collect();
        self.install_with_heap(
            (space, clock),
            target,
            instance,
            &derived.actor,
            derived.heap,
            &kernels,
            roles,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn install_with_heap(
        &mut self,
        space: (SpaceId, WindowClock),
        target: Target,
        instance: InstanceId,
        program: &[u8],
        heap: u32,
        kernels: &[(MethodId, &[u8])],
        roles: &[(&str, u8)],
    ) -> Result<(), InstallError> {
        if let Some((space, clock)) = self.space.filter(|&agent| agent != space) {
            return Err(InstallError::Refused(Refused::Space { space, clock }));
        }
        if let Some(agent) = self.target.filter(|&agent| agent != target) {
            return Err(InstallError::Refused(Refused::Target { agent }));
        }
        let parsed =
            vos_pvm::spi::parse_standard_program(program).ok_or(InstallError::NotAProgram)?;
        let schema = Schema::read(&parsed.ro_data).map_err(InstallError::Schema)?;
        let roles: BTreeMap<Vec<u8>, u8> = roles
            .iter()
            .map(|(name, role)| (name.as_bytes().to_vec(), *role))
            .collect();
        for (index, (method, _)) in kernels.iter().enumerate() {
            if !schema
                .method(*method)
                .is_some_and(|bound| bound.kind.is_attestable())
            {
                return Err(InstallError::Unmatched(*method));
            }
            if kernels[..index].iter().any(|(bound, _)| bound == method) {
                return Err(InstallError::Duplicate(*method));
            }
        }
        for method in &schema.methods {
            if method.kind.is_attestable() && !kernels.iter().any(|(bound, _)| *bound == method.id)
            {
                return Err(InstallError::Unbound(method.id));
            }
            if let Some(role) = &method.role
                && !roles.contains_key(role)
            {
                return Err(InstallError::UnmappedRole(role.clone()));
            }
        }
        let layout = parsed.layout(&[]).ok_or(InstallError::NotAProgram)?;
        let pages =
            (layout.rw.size + layout.stack.size) / vos_wire::result::PAGE as u64 + u64::from(heap);
        statics_within(program, pages, &schema, kernels.len(), target.limits())
            .map_err(InstallError::Refused)?;
        self.target = Some(target);
        self.space = Some(space);
        let installed = Installed {
            program: program.to_vec(),
            schema,
            roles,
            kernels: kernels
                .iter()
                .map(|(method, kernel)| (*method, kernel.to_vec()))
                .collect(),
            target,
            heap,
        };
        for program in core::iter::once(&installed.program)
            .chain(installed.kernels.iter().map(|(_, kernel)| kernel))
        {
            self.programs
                .insert(ProgramHash::of(program), program.clone());
        }
        self.instances.insert(instance, installed);
        Ok(())
    }

    /// Start a batch: its time and seed, step indices from 0, and the next
    /// state version.
    pub fn batch(&mut self, time: u64, seed: [u8; 32]) {
        self.time = time;
        self.seed = seed;
        self.steps = 0;
        self.version += 1;
    }

    /// A step the model does not run, a sweep's or a refusal: it takes its
    /// index in the batch all the same.
    pub fn pass(&mut self) {
        self.steps += 1;
    }

    /// Set a row of the agent's state, as a test plants it in a node's.
    pub fn set_row(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.state.insert(key, value);
    }

    /// The bytes of a page workflow `id`'s snapshot stores.
    pub fn page(&self, id: WorkflowId, index: u32) -> Option<&[u8]> {
        self.pages.get(&(id, index)).map(Vec::as_slice)
    }

    pub fn set_role(&mut self, principal: Principal, role: Option<u8>) {
        match role {
            Some(role) => self.members.insert(principal, role),
            None => self.members.remove(&principal),
        };
    }

    /// The id of an installed instance's method, by name.
    pub fn method(&self, instance: InstanceId, name: &str) -> Option<MethodId> {
        let installed = self.instances.get(&instance)?;
        installed
            .schema
            .methods
            .iter()
            .find(|method| method.name == name.as_bytes())
            .map(|method| method.id)
    }

    /// Every row of the agent's applied state the model keeps (instances'
    /// rows, and committed maps' dirty and seed rows), in key order.
    pub fn rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    /// A value of the agent's applied state, by agent-relative key.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.state.get(key).map(Vec::as_slice)
    }

    /// Run a step: a handler through the log, its writes applied when it
    /// succeeds, or a workflow's start.
    pub fn command(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Step {
        let call = Call {
            caller,
            instance,
            method,
            arguments,
        };
        if self.is_workflow(instance, method) {
            return self.start(call);
        }
        let step = self.steps;
        self.steps += 1;
        let mut invocation = Invocation::new(self, step, Kind::Command);
        let result = invocation.top(call);
        let gas_used = invocation.gas_used;
        let instances = invocation.instances.clone();
        let outcome = result.unwrap_or_else(Outcome::failed);
        let mut step = Step::consumed(outcome);
        step.instances = instances;
        step.gas_used = gas_used;
        if let Outcome::Done(_) = step.outcome {
            step.messages = std::mem::take(&mut invocation.messages);
            step.attests = std::mem::take(&mut invocation.attests);
            (step.writes, step.committed) =
                split_writes(invocation.frames.pop().expect("the step overlay"));
            self.apply(&step, Vec::new());
        }
        step
    }

    /// Apply a step's effects to the state: its writes, its committed
    /// writes at the batch's version, and the pages it stores, `stored`'s
    /// bytes in order, or drops.
    fn apply(&mut self, step: &Step, stored: Vec<Vec<u8>>) {
        for write in &step.writes {
            match &write.value {
                Some(value) => self.state.insert(write.key.clone(), value.clone()),
                None => self.state.remove(&write.key),
            };
        }
        for write in &step.committed {
            let row = keys::committed(&write.map, &write.key);
            let dirty = keys::dirty(self.version, &row);
            match &write.value {
                Some(value) => self.state.insert(row, versioned(self.version, value)),
                None => self.state.remove(&row),
            };
            self.state.insert(dirty, Vec::new());
        }
        if !step.committed.is_empty() {
            self.state
                .insert(keys::seed(self.version), self.seed.to_vec());
        }
        let mut stored = stored.into_iter();
        for page in &step.pages {
            let key = (page.workflow, page.index);
            match page.hash {
                Some(_) => {
                    let bytes = stored.next().expect("a stored page's bytes");
                    self.pages.insert(key, bytes);
                }
                None => {
                    self.pages.remove(&key);
                }
            }
        }
    }

    /// Run a message from agent `from` as a step: a call runs as a command
    /// of that agent's, or starts a workflow, and one that awaits adds its
    /// reply to the step's messages, whatever its outcome; a reply resumes
    /// the workflow awaiting it, or is consumed and dropped; a wait for a
    /// workflow's result is answered, or held until it ends.
    pub fn message(&mut self, from: AgentId, body: &Body) -> Step {
        match body {
            Body::Call {
                instance,
                method,
                arguments,
                awaiting,
            } => {
                let mut step = self.command(Principal::Agent(from), *instance, *method, arguments);
                answer(&mut step, from, *awaiting);
                step
            }
            Body::Reply { awaiting, answer } => match self.resume(from, awaiting, answer) {
                Some(step) => step,
                None => self.consumed(Outcome::Done(Vec::new())),
            },
            Body::Wait { workflow, awaiting } => self.wait(from, *workflow, *awaiting),
        }
    }

    /// A message from agent `from` that the leader asserts failed in
    /// refine: consumed as failed without running, and answered when it
    /// awaits.
    pub fn failed(&mut self, from: AgentId, awaiting: Option<Await>) -> Step {
        let mut step = self.consumed(Outcome::failed(Failure::InRefine));
        answer(&mut step, from, awaiting);
        step
    }

    /// A step that runs nothing: `outcome`.
    fn consumed(&mut self, outcome: Outcome) -> Step {
        self.steps += 1;
        Step::consumed(outcome)
    }

    /// Run a query: a `&self` handler on applied state, outside the log.
    pub fn query(
        &self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Outcome {
        let mut invocation = Invocation::new(self, self.steps, Kind::Query);
        invocation
            .top(Call {
                caller,
                instance,
                method,
                arguments,
            })
            .unwrap_or_else(Outcome::failed)
    }
}

/// Whether a program's statics are within `limits`: the kernels bound to
/// it, its bytes, the `pages` it may write, its whole heap's included, and
/// the gas each attestable method declares for its kernel.
fn statics_within(
    program: &[u8],
    pages: u64,
    schema: &Schema,
    kernels: usize,
    limits: &Limits,
) -> Result<(), Refused> {
    if kernels > limits.kernels {
        return Err(Refused::Kernels {
            kernels: kernels as u64,
            most: limits.kernels as u64,
        });
    }
    if program.len() > limits.program {
        return Err(Refused::Program {
            bytes: program.len() as u64,
            most: limits.program as u64,
        });
    }
    if let Some(most) = limits.program_pages
        && pages > most as u64
    {
        return Err(Refused::Pages {
            pages,
            most: most as u64,
        });
    }
    let Some(most) = limits.kernel_gas() else {
        return Ok(());
    };
    for method in &schema.methods {
        if method.kind.is_attestable()
            && let Some(gas) = method.gas.filter(|&gas| gas > most)
        {
            return Err(Refused::KernelGas {
                method: method.id,
                gas,
                most,
            });
        }
    }
    Ok(())
}

/// Add the reply to agent `to`'s request awaiting at `awaiting`, if any,
/// after `step`'s own messages: the step's outcome.
fn answer(step: &mut Step, to: AgentId, awaiting: Option<Await>) {
    if let Some(awaiting) = awaiting {
        let answer = step.outcome.clone().into();
        step.messages.push(Outgoing::reply(to, awaiting, answer));
    }
}

/// A step's writes, those to committed maps apart, by map and transformed
/// key.
fn split_writes(overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>>) -> (Vec<Write>, Vec<CommittedWrite>) {
    let mut writes = Vec::new();
    let mut committed = Vec::new();
    for (key, value) in overlay {
        match keys::committed_entry(&key) {
            Some((map, transformed)) => committed.push(CommittedWrite {
                map,
                key: transformed.to_vec(),
                value,
            }),
            None => writes.push(Write { key, value }),
        }
    }
    (writes, committed)
}

/// A kernel's run as an attest runs it ([`run_kernel`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelRan {
    pub output: Vec<u8>,
    /// What it left in φ9..φ12.
    pub io_hash: [u8; 32],
    pub gas_used: u64,
    /// Its precompile calls.
    pub compressions: u64,
}

/// Run kernel `program` on `input`, its witness input, with `gas`, as an
/// attest runs it, or why it failed.
pub fn run_kernel(program: &[u8], input: &[u8], gas: u64) -> Result<KernelRan, Failure> {
    let run =
        memory::kernel(program, input, gas, vos_wire::abi::cap::REPLY).map_err(|(code, _)| code)?;
    Ok(KernelRan {
        output: run.output,
        io_hash: run.io_hash,
        gas_used: run.gas_used,
        compressions: run.compressions,
    })
}

/// Decode a reply as `T`.
pub fn decode<T: Decode>(bytes: &[u8]) -> Option<T> {
    T::decode(bytes).ok().map(|(value, _)| value)
}
