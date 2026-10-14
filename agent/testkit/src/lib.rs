//! A native host for actor programs: it runs them on the PVM interpreter and
//! serves the actor ABI against in-memory state, with the default agent's
//! semantics.
//!
//! It is the reference model for the agent's differential test, so it
//! shares no overlay, dispatch or enforcement code with the agent: only
//! the wire definitions in `vos_wire`.
//!
//! Beside it, [`programs`]: the guest programs, linked, for tests and
//! benches.

pub mod programs;

use std::collections::BTreeMap;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use vos_pvm::ExitReason;
use vos_pvm::refine::Machine;
use vos_wire::abi::{self, Failure, Kind, cap, code, op, price};
use vos_wire::batch::{Await, Body};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash};
use vos_wire::keys;
use vos_wire::result::{Attest, InstanceGas, Outcome, Outgoing, Write};
use vos_wire::schema::{Schema, SchemaError};
use vos_wire::{Decode, Encode};

/// Nested invocations a step may hold at once: the agent's inner machines.
const MAX_DEPTH: usize = 63;

pub fn program_hash(blob: &[u8]) -> ProgramHash {
    ProgramHash(Blake2b::<U32>::digest(blob).into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallError {
    NotAProgram,
    Schema(SchemaError),
    /// An attestable method has no program bound.
    Unbound(MethodId),
    /// A role name the schema uses has no role byte.
    UnmappedRole(Vec<u8>),
}

struct Installed {
    program: Vec<u8>,
    schema: Schema,
    roles: BTreeMap<Vec<u8>, u8>,
    attestables: BTreeMap<MethodId, Vec<u8>>,
}

/// What one step produced: as a work result's step, applied to the
/// testkit's state when it succeeded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub outcome: Outcome,
    pub instances: Vec<InstanceGas>,
    pub writes: Vec<Write>,
    pub messages: Vec<Outgoing>,
    pub attests: Vec<Attest>,
    pub gas_used: u64,
}

pub struct Testkit {
    pub agent: AgentId,
    /// The batch time and seed operations see.
    pub time: u64,
    pub seed: [u8; 32],
    /// The gas limit of a handler whose schema requests none, and the most
    /// any handler may request.
    pub default_gas: u64,
    pub max_gas: u64,
    instances: BTreeMap<InstanceId, Installed>,
    members: BTreeMap<Principal, u8>,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    steps: u32,
}

impl Testkit {
    pub fn new(agent: AgentId) -> Self {
        Self {
            agent,
            time: 0,
            seed: [0; 32],
            default_gas: vos_wire::defaults::HANDLER_GAS,
            max_gas: vos_wire::defaults::MAX_HANDLER_GAS,
            instances: BTreeMap::new(),
            members: BTreeMap::new(),
            state: BTreeMap::new(),
            steps: 0,
        }
    }

    /// Install an actor program, binding its attestable methods to their
    /// programs and its role names to role bytes.
    pub fn install(
        &mut self,
        instance: InstanceId,
        program: &[u8],
        attestables: &[(MethodId, &[u8])],
        roles: &[(&str, u8)],
    ) -> Result<(), InstallError> {
        let parsed =
            vos_pvm::spi::parse_standard_program(program).ok_or(InstallError::NotAProgram)?;
        let schema = Schema::read(&parsed.ro_data).map_err(InstallError::Schema)?;
        let roles: BTreeMap<Vec<u8>, u8> = roles
            .iter()
            .map(|(name, role)| (name.as_bytes().to_vec(), *role))
            .collect();
        let attestables: BTreeMap<MethodId, Vec<u8>> = attestables
            .iter()
            .map(|(method, blob)| (*method, blob.to_vec()))
            .collect();
        for method in &schema.methods {
            if method.kind == Kind::Attestable && !attestables.contains_key(&method.id) {
                return Err(InstallError::Unbound(method.id));
            }
            if let Some(role) = &method.role
                && !roles.contains_key(role)
            {
                return Err(InstallError::UnmappedRole(role.clone()));
            }
        }
        self.instances.insert(
            instance,
            Installed {
                program: program.to_vec(),
                schema,
                roles,
                attestables,
            },
        );
        Ok(())
    }

    /// Start a batch: its time and seed, and step indices from 0.
    pub fn batch(&mut self, time: u64, seed: [u8; 32]) {
        self.time = time;
        self.seed = seed;
        self.steps = 0;
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

    /// Every row of the agent's applied state, in key order.
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

    /// Run a step: a handler through the log. Its writes apply when it
    /// succeeds.
    pub fn command(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Step {
        let step = self.steps;
        self.steps += 1;
        let mut run = Run::new(self, step, Kind::Command);
        let result = run.top(caller, instance, method, arguments);
        let gas_used = run.gas_used;
        let instances = run.instances.clone();
        let outcome = match result {
            Ok(reply) => reply,
            Err(code) => Outcome::Failed {
                code,
                detail: Vec::new(),
            },
        };
        if let Outcome::Done(_) = outcome {
            let overlay = run.frames.pop().expect("the step overlay");
            let messages = std::mem::take(&mut run.messages);
            let attests = std::mem::take(&mut run.attests);
            let writes: Vec<Write> = overlay
                .into_iter()
                .map(|(key, value)| Write { key, value })
                .collect();
            for write in &writes {
                match &write.value {
                    Some(value) => self.state.insert(write.key.clone(), value.clone()),
                    None => self.state.remove(&write.key),
                };
            }
            Step {
                outcome,
                instances,
                writes,
                messages,
                attests,
                gas_used,
            }
        } else {
            Step {
                outcome,
                instances,
                writes: Vec::new(),
                messages: Vec::new(),
                attests: Vec::new(),
                gas_used,
            }
        }
    }

    /// Run a message from agent `from` as a step: a call runs as a command
    /// of that agent's, and one that awaits adds its reply to the step's
    /// messages, whatever its outcome; a reply is consumed, with no await
    /// to resume.
    pub fn message(&mut self, from: AgentId, body: &Body) -> Step {
        match body {
            Body::Call {
                instance,
                method,
                arguments,
                awaiting,
            } => {
                let mut step = self.command(Principal::Agent(from), *instance, *method, arguments);
                if let Some(awaiting) = awaiting {
                    step.messages.push(reply(from, *awaiting, &step.outcome));
                }
                step
            }
            Body::Reply { .. } => self.consumed(Outcome::Done(Vec::new()), None),
        }
    }

    /// A message from agent `from` that the leader asserts failed in
    /// refine: consumed as failed without running, and answered when it
    /// awaits.
    pub fn failed(&mut self, from: AgentId, awaiting: Option<Await>) -> Step {
        let outcome = Outcome::Failed {
            code: Failure::InRefine,
            detail: Vec::new(),
        };
        self.consumed(outcome, awaiting.map(|awaiting| (from, awaiting)))
    }

    /// A step that runs nothing: `outcome`, and the reply to the request
    /// awaiting, if any.
    fn consumed(&mut self, outcome: Outcome, awaiting: Option<(AgentId, Await)>) -> Step {
        self.steps += 1;
        let messages = awaiting
            .map(|(from, awaiting)| reply(from, awaiting, &outcome))
            .into_iter()
            .collect();
        Step {
            outcome,
            instances: Vec::new(),
            writes: Vec::new(),
            messages,
            attests: Vec::new(),
            gas_used: 0,
        }
    }

    /// Run a query: a `&self` handler on applied state, outside the log.
    pub fn query(
        &self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Outcome {
        let mut run = Run::new(self, self.steps, Kind::Query);
        match run.top(caller, instance, method, arguments) {
            Ok(outcome) => outcome,
            Err(code) => Outcome::Failed {
                code,
                detail: Vec::new(),
            },
        }
    }
}

/// The reply to agent `to`'s request awaiting at `awaiting`: the step's
/// outcome.
fn reply(to: AgentId, awaiting: Await, outcome: &Outcome) -> Outgoing {
    Outgoing {
        to,
        body: Body::Reply {
            awaiting,
            answer: outcome.clone().into(),
        },
    }
}

/// How an invocation ended, short of failing the whole step.
enum Ended {
    Replied(Vec<u8>),
    /// The handler's own error.
    Failed(Vec<u8>),
    /// The caller lacks the handler's role; it did not run.
    Forbidden,
}

/// One step's execution: the overlays, the call stack and the effects.
struct Run<'a> {
    kit: &'a Testkit,
    step: u32,
    /// The entry's kind: queries never write.
    kind: Kind,
    /// The step overlay, then one per nested call.
    frames: Vec<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
    stack: Vec<InstanceId>,
    /// Gas the callees of each invocation on the stack used.
    nested: Vec<u64>,
    /// Instances in the order they first ran, each with the gas its own
    /// code used, callees excluded.
    instances: Vec<InstanceGas>,
    messages: Vec<Outgoing>,
    attests: Vec<Attest>,
    written: usize,
    draws: u64,
    gas_used: u64,
}

impl<'a> Run<'a> {
    fn new(kit: &'a Testkit, step: u32, kind: Kind) -> Self {
        Self {
            kit,
            step,
            kind,
            frames: vec![BTreeMap::new()],
            stack: Vec::new(),
            nested: Vec::new(),
            instances: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            written: 0,
            draws: 0,
            gas_used: 0,
        }
    }

    /// The entry invocation. `Err` is a failure code that fails the step.
    fn top(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Outcome, Failure> {
        if arguments.len() > cap::REQUEST {
            return Err(Failure::Cap);
        }
        let installed = self.kit.instances.get(&instance).ok_or(Failure::Unknown)?;
        let schema = installed.schema.method(method).ok_or(Failure::Unknown)?;
        if schema.kind == Kind::Attestable
            || (self.kind == Kind::Query && schema.kind != Kind::Query)
        {
            return Err(Failure::Unknown);
        }
        let gas = schema
            .gas
            .unwrap_or(self.kit.default_gas)
            .min(self.kit.max_gas);
        let (ended, used) = self
            .invoke(caller, instance, method, arguments, gas)
            .map_err(|(code, used)| {
                // A failed step still used its gas.
                self.gas_used = used;
                code
            })?;
        self.gas_used = used;
        Ok(match ended {
            Ended::Replied(reply) => Outcome::Done(reply),
            Ended::Failed(detail) => Outcome::Failed {
                code: Failure::Handler,
                detail,
            },
            Ended::Forbidden => Outcome::Failed {
                code: Failure::Forbidden,
                detail: Vec::new(),
            },
        })
    }

    /// Run one invocation with `gas`: how it ended and the gas it used, or
    /// a code that fails the step with the gas used.
    fn invoke(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
        gas: u64,
    ) -> Result<(Ended, u64), (Failure, u64)> {
        let installed = self
            .kit
            .instances
            .get(&instance)
            .ok_or((Failure::Unknown, 0))?;
        let schema = installed
            .schema
            .method(method)
            .ok_or((Failure::Unknown, 0))?;
        if let Some(role) = &schema.role {
            let required = installed.roles[role];
            if self.kit.members.get(&caller) != Some(&required) {
                return Ok((Ended::Forbidden, 0));
            }
        }
        if self.stack.contains(&instance) {
            return Err((Failure::Cycle, 0));
        }
        if self.stack.len() >= MAX_DEPTH {
            return Err((Failure::Depth, 0));
        }
        let kind = schema.kind;
        let mut machine =
            Machine::load(&installed.program, &[], gas).map_err(|_| (Failure::Trapped, 0))?;
        let registers = machine.registers_mut();
        registers[7] = u64::from(method.0);
        registers[8] = kind.encode()[0].into();
        registers[9] = arguments.len() as u64;
        if !self
            .instances
            .iter()
            .any(|entry| entry.instance == instance)
        {
            self.instances.push(InstanceGas { instance, gas: 0 });
        }
        self.stack.push(instance);
        self.nested.push(0);
        let ended = self.serve(&mut machine, caller, instance, kind, arguments);
        self.stack.pop();
        let nested = self.nested.pop().expect("this invocation's entry");
        let used = gas - machine.gas_remaining();
        let entry = self
            .instances
            .iter_mut()
            .find(|entry| entry.instance == instance)
            .expect("recorded when it started");
        entry.gas += used - nested;
        match ended {
            Ok(ended) => Ok((ended, used)),
            Err(code) => Err((code, used)),
        }
    }

    fn serve(
        &mut self,
        machine: &mut Machine,
        caller: Principal,
        instance: InstanceId,
        kind: Kind,
        arguments: &[u8],
    ) -> Result<Ended, Failure> {
        let mut outcome: Option<Ended> = None;
        loop {
            match machine.try_resume().map_err(|_| Failure::Trapped)? {
                ExitReason::Halt => {
                    return Ok(outcome.unwrap_or(Ended::Replied(Vec::new())));
                }
                ExitReason::OutOfGas => return Err(Failure::OutOfGas),
                ExitReason::HostCall(id) => {
                    if vos_pvm::precompile::is_precompile(id) {
                        precompile(machine, id)?;
                        continue;
                    }
                    if !known(id) {
                        // Not an actor operation: the agent answers WHAT.
                        if !machine.charge(price::OPERATION) {
                            return Err(Failure::OutOfGas);
                        }
                        machine.registers_mut()[7] = code::WHAT;
                        continue;
                    }
                    if !abi::allowed(kind, id) {
                        return Err(Failure::Trapped);
                    }
                    if !machine.charge(price::of(id)) {
                        return Err(Failure::OutOfGas);
                    }
                    self.operation(machine, id, caller, instance, kind, arguments, &mut outcome)?;
                }
                _ => return Err(Failure::Trapped),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn operation(
        &mut self,
        machine: &mut Machine,
        id: u64,
        caller: Principal,
        instance: InstanceId,
        kind: Kind,
        arguments: &[u8],
        outcome: &mut Option<Ended>,
    ) -> Result<(), Failure> {
        let r = *machine.registers();
        match id {
            op::INPUT => {
                copy_out(machine, arguments, r[7], r[8], r[9])?;
                machine.registers_mut()[7] = arguments.len() as u64;
            }
            op::REPLY | op::FAIL => {
                if outcome.is_some() {
                    return Err(Failure::Trapped);
                }
                let bytes = read(machine, r[7], r[8], cap::REPLY)?;
                *outcome = Some(if id == op::REPLY {
                    Ended::Replied(bytes)
                } else {
                    Ended::Failed(bytes)
                });
                machine.registers_mut()[7] = code::OK;
            }
            op::LOG => {
                read(machine, r[8], r[9], 4096)?;
                machine.registers_mut()[7] = code::OK;
            }
            op::CALLER => {
                copy_out(machine, &caller.encode(), r[7], 0, r[8])?;
                machine.registers_mut()[7] = caller.encode().len() as u64;
            }
            op::NOW => machine.registers_mut()[7] = self.kit.time,
            op::RANDOM => {
                let bytes = random(&self.kit.seed, self.step, self.draws);
                self.draws += 1;
                write(machine, r[7], &bytes)?;
                machine.registers_mut()[7] = code::OK;
            }
            op::SELF_ID => {
                machine.registers_mut()[7] = u64::from(instance.0);
                machine.registers_mut()[8] = u64::from(self.kit.agent.0);
            }
            op::GET => {
                let key = self.key(machine, instance, r[7], r[8])?;
                match self.read_state(&key) {
                    Some(value) => {
                        copy_out(machine, &value, r[9], r[10], r[11])?;
                        machine.registers_mut()[7] = value.len() as u64;
                    }
                    None => machine.registers_mut()[7] = code::NONE,
                }
            }
            op::PUT | op::DELETE => {
                let key = self.key(machine, instance, r[7], r[8])?;
                let value = if id == op::PUT {
                    Some(read(machine, r[9], r[10], cap::VALUE)?)
                } else {
                    None
                };
                self.written += key.len() + value.as_ref().map_or(0, Vec::len);
                if self.written > cap::STEP_WRITES {
                    return Err(Failure::Cap);
                }
                self.frames.last_mut().expect("a frame").insert(key, value);
                machine.registers_mut()[7] = code::OK;
            }
            op::SCAN => {
                let prefix = self.key(machine, instance, r[7], r[8])?;
                let cursor = read(machine, r[9], r[10], cap::KEY)?;
                let base = keys::instance_prefix(instance);
                let after = (!cursor.is_empty()).then(|| [base.clone(), cursor].concat());
                let capacity = (r[12] as usize).min(cap::SCAN);
                let mut out = Vec::new();
                let mut full = false;
                for (key, value) in self.rows(&prefix, after.as_deref()) {
                    let row = (key[base.len()..].to_vec(), value).encode();
                    if out.len() + row.len() > capacity {
                        full = out.is_empty();
                        break;
                    }
                    out.extend_from_slice(&row);
                }
                write(machine, r[11], &out)?;
                machine.registers_mut()[7] = if full { code::FULL } else { out.len() as u64 };
            }
            op::CALL => {
                let callee = InstanceId(r[7] as u32);
                let method = MethodId(r[8] as u32);
                let call_arguments = read(machine, r[9], r[10], cap::REQUEST)?;
                let callee_kind = self
                    .kit
                    .instances
                    .get(&callee)
                    .and_then(|installed| installed.schema.method(method))
                    .map(|schema| schema.kind)
                    .ok_or(Failure::Unknown)?;
                if callee_kind == Kind::Attestable
                    || (kind == Kind::Query && callee_kind != Kind::Query)
                {
                    return Err(Failure::Trapped);
                }
                self.frames.push(BTreeMap::new());
                // A failed callee's effects are discarded: its writes with
                // its frame, and its messages, attests and share of the
                // step's write cap here. Random draws are not effects: they
                // keep counting.
                let effects = (self.messages.len(), self.attests.len(), self.written);
                let gas = machine.gas_remaining();
                let (ended, used) = self
                    .invoke(
                        Principal::Instance(instance),
                        callee,
                        method,
                        &call_arguments,
                        gas,
                    )
                    .map_err(|(code, _)| code)?;
                let frame = self.frames.pop().expect("the call's frame");
                *self.nested.last_mut().expect("the caller's entry") += used;
                if !machine.charge(used) {
                    return Err(Failure::OutOfGas);
                }
                let (bytes, failed) = match ended {
                    Ended::Replied(reply) => {
                        let parent = self.frames.last_mut().expect("a frame");
                        parent.extend(frame);
                        (reply, None)
                    }
                    Ended::Failed(detail) => (detail, Some(Failure::Handler)),
                    Ended::Forbidden => (Vec::new(), Some(Failure::Forbidden)),
                };
                if failed.is_some() {
                    let (messages, attests, written) = effects;
                    self.messages.truncate(messages);
                    self.attests.truncate(attests);
                    self.written = written;
                }
                copy_out(machine, &bytes, r[11], 0, r[12])?;
                machine.registers_mut()[7] = bytes.len() as u64;
                machine.registers_mut()[8] = failed.map_or(0, |code| code.code().into());
            }
            op::SEND => {
                let call_arguments = read(machine, r[10], r[11], cap::MESSAGE)?;
                if self.messages.len() == cap::MESSAGES {
                    return Err(Failure::Cap);
                }
                self.messages.push(Outgoing {
                    to: AgentId(r[7] as u32),
                    body: Body::Call {
                        instance: InstanceId(r[8] as u32),
                        method: MethodId(r[9] as u32),
                        arguments: call_arguments,
                        awaiting: None,
                    },
                });
                machine.registers_mut()[7] = code::OK;
            }
            op::ATTEST => {
                let method = MethodId(r[7] as u32);
                let call_arguments = read(machine, r[8], r[9], cap::REQUEST)?;
                if self.attests.len() == cap::ATTESTS {
                    return Err(Failure::Cap);
                }
                let program = self
                    .kit
                    .instances
                    .get(&instance)
                    .and_then(|installed| installed.attestables.get(&method))
                    .ok_or(Failure::Unknown)?;
                let gas = machine.gas_remaining();
                let (output, used) = attestable(program, &call_arguments, gas)?;
                if !machine.charge(used) {
                    return Err(Failure::OutOfGas);
                }
                self.attests.push(Attest {
                    program: program_hash(program),
                    arguments: call_arguments,
                    output: output.clone(),
                });
                copy_out(machine, &output, r[10], 0, r[11])?;
                machine.registers_mut()[7] = output.len() as u64;
                machine.registers_mut()[8] = 0;
            }
            _ => unreachable!("served operations are known"),
        }
        Ok(())
    }

    /// The agent-relative key for the instance-relative key at
    /// `address`/`len`.
    fn key(
        &self,
        machine: &mut Machine,
        instance: InstanceId,
        address: u64,
        len: u64,
    ) -> Result<Vec<u8>, Failure> {
        let relative = read(machine, address, len, cap::KEY)?;
        if relative.is_empty() {
            return Err(Failure::Trapped);
        }
        Ok([keys::instance_prefix(instance), relative].concat())
    }

    fn read_state(&self, key: &[u8]) -> Option<Vec<u8>> {
        for frame in self.frames.iter().rev() {
            if let Some(value) = frame.get(key) {
                return value.clone();
            }
        }
        self.kit.state.get(key).cloned()
    }

    /// Rows under `prefix`, after `after` when given, through the overlays.
    fn rows(&self, prefix: &[u8], after: Option<&[u8]>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> = self
            .kit
            .state
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), Some(value.clone())))
            .collect();
        for frame in &self.frames {
            for (key, value) in frame.range(prefix.to_vec()..) {
                if !key.starts_with(prefix) {
                    break;
                }
                merged.insert(key.clone(), value.clone());
            }
        }
        merged
            .into_iter()
            .filter(|(key, _)| after.is_none_or(|after| key.as_slice() > after))
            .filter_map(|(key, value)| Some((key, value?)))
            .collect()
    }
}

/// Serve a precompile as the node's machines do: its price, then its work
/// on the actor's memory.
fn precompile(machine: &mut Machine, id: u64) -> Result<(), Failure> {
    if !machine.charge(vos_pvm::precompile::price(id).unwrap_or(0)) {
        return Err(Failure::OutOfGas);
    }
    let registers = *machine.registers();
    vos_pvm::precompile::execute(id, &registers, machine.memory_mut())
        .map(|_| ())
        .ok_or(Failure::Trapped)
}

/// Run an attestable program: arguments in the standard window, output by
/// the halt convention, and no host calls but precompiles. Its output and
/// gas used.
fn attestable(program: &[u8], arguments: &[u8], gas: u64) -> Result<(Vec<u8>, u64), Failure> {
    let mut machine = Machine::load(program, arguments, gas).map_err(|_| Failure::Trapped)?;
    loop {
        match machine.try_resume().map_err(|_| Failure::Trapped)? {
            ExitReason::HostCall(id) if vos_pvm::precompile::is_precompile(id) => {
                precompile(&mut machine, id)?;
            }
            ExitReason::Halt => {
                let invocation = machine.finish(ExitReason::Halt);
                let output = invocation.output_bounded(cap::REPLY).ok_or(Failure::Cap)?;
                return Ok((output, invocation.gas_used));
            }
            ExitReason::OutOfGas => return Err(Failure::OutOfGas),
            _ => return Err(Failure::Trapped),
        }
    }
}

fn known(id: u64) -> bool {
    matches!(
        id,
        op::INPUT
            | op::REPLY
            | op::FAIL
            | op::LOG
            | op::CALLER
            | op::NOW
            | op::RANDOM
            | op::GET
            | op::PUT
            | op::DELETE
            | op::SCAN
            | op::CALL
            | op::SEND
            | op::ATTEST
            | op::SELF_ID
    )
}

/// The 32 bytes of `RANDOM`: BLAKE2b-256 of the batch seed, the step's
/// index and how many the step drew before.
fn random(seed: &[u8; 32], step: u32, draw: u64) -> [u8; 32] {
    Blake2b::<U32>::new()
        .chain_update(b"vos/random")
        .chain_update(seed)
        .chain_update(step.to_le_bytes())
        .chain_update(draw.to_le_bytes())
        .finalize()
        .into()
}

/// The actor's bytes at `address`, at most `limit` of them; an unreadable
/// buffer traps and a longer one exceeds a cap.
fn read(machine: &mut Machine, address: u64, len: u64, limit: usize) -> Result<Vec<u8>, Failure> {
    let len = usize::try_from(len).map_err(|_| Failure::Cap)?;
    if len > limit {
        return Err(Failure::Cap);
    }
    price_bytes(machine, len)?;
    let mut bytes = vec![0; len];
    if len > 0 {
        let address = u32::try_from(address).map_err(|_| Failure::Trapped)?;
        if !machine.memory().is_readable(address, len)
            || !machine.memory().read_bytes_checked(address, &mut bytes)
        {
            return Err(Failure::Trapped);
        }
    }
    Ok(bytes)
}

fn write(machine: &mut Machine, address: u64, bytes: &[u8]) -> Result<(), Failure> {
    price_bytes(machine, bytes.len())?;
    if bytes.is_empty() {
        return Ok(());
    }
    let address = u32::try_from(address).map_err(|_| Failure::Trapped)?;
    if machine.memory_mut().write_bytes_checked(address, bytes) {
        Ok(())
    } else {
        Err(Failure::Trapped)
    }
}

/// Copy `bytes[offset..]`, at most `capacity` of them, to `address`.
fn copy_out(
    machine: &mut Machine,
    bytes: &[u8],
    address: u64,
    offset: u64,
    capacity: u64,
) -> Result<(), Failure> {
    let offset = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let len = usize::try_from(capacity)
        .unwrap_or(usize::MAX)
        .min(bytes.len() - offset);
    write(machine, address, &bytes[offset..offset + len])
}

fn price_bytes(machine: &mut Machine, len: usize) -> Result<(), Failure> {
    if machine.charge(len as u64 * price::PER_BYTE) {
        Ok(())
    } else {
        Err(Failure::OutOfGas)
    }
}

/// Decode a reply as `T`.
pub fn decode<T: Decode>(bytes: &[u8]) -> Option<T> {
    T::decode(bytes).ok().map(|(value, _)| value)
}
