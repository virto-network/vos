//! One step's execution: an actor's handlers, nested calls and every
//! operation of the actor ABI, served against the step's overlays.

mod at_cut;

use std::collections::BTreeMap;

use vos_pvm::ExitReason;
use vos_pvm::refine::Machine;
use vos_wire::abi::cap::{self, Limits};
use vos_wire::abi::{self, Failure, Kind, Op, Rows, code, price};
use vos_wire::batch::{Await, Body};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, WorkflowId};
use vos_wire::records::WorkflowState;
use vos_wire::result::{Attest, InstanceGas, KernelReturn, Outcome, Outgoing};
use vos_wire::{Encode, keys};

use crate::Testkit;
use crate::memory::{
    copy_out, held, kernel, parts, precompile, random, read, read_key, row, write,
};

/// Nested invocations a step may hold at once: the agent's inner machines.
const MAX_DEPTH: usize = 63;

/// Rows of state, each a key and its value, in key order.
type StateRows = Vec<(Vec<u8>, Vec<u8>)>;

/// A call of an instance's method: a request's, a message's, a query's, a
/// nested call's, or a workflow's, of its method by its owner. Its
/// arguments are what [`Op::Input`] copies out: for a workflow's step, the
/// step's input.
#[derive(Clone, Copy)]
pub(crate) struct Call<'a> {
    pub(crate) caller: Principal,
    pub(crate) instance: InstanceId,
    pub(crate) method: MethodId,
    pub(crate) arguments: &'a [u8],
}

/// How an invocation ended, short of failing the whole step.
pub(crate) enum Ended {
    Replied(Vec<u8>),
    /// The handler's own error.
    Failed(Vec<u8>),
    /// The caller lacks the handler's role; it did not run.
    Forbidden,
    /// A workflow paused, in this state.
    Paused(WorkflowState),
    /// A workflow's step was preempted, before the host call it names when
    /// it did not serve it; idle when out of gas with no call served since
    /// it resumed.
    Preempted {
        pending: Option<u64>,
        idle: bool,
    },
}

/// One step's execution: the overlays, the call stack and the effects,
/// within the limits of its agent's target, which its entry instance's
/// install names.
pub(crate) struct Invocation<'a> {
    pub(crate) kit: &'a Testkit,
    step: u32,
    /// The entry's kind: queries never write.
    entry: Kind,
    pub(crate) limits: &'static Limits,
    /// A workflow's step: the workflow and its next await's counter.
    pub(crate) awaits: Option<Await>,
    /// A workflow's section on its instance's state is open.
    pub(crate) section: bool,
    /// The step overlay, then one per nested call.
    pub(crate) frames: Vec<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
    stack: Vec<InstanceId>,
    /// Gas the callees of each invocation on the stack used.
    pub(crate) nested: Vec<u64>,
    /// Instances in the order they first ran, each with the gas its own
    /// code used, callees excluded.
    pub(crate) instances: Vec<InstanceGas>,
    pub(crate) messages: Vec<Outgoing>,
    pub(crate) attests: Vec<Attest>,
    /// The bytes and the rows of state the step has written, against its
    /// limits.
    write_bytes: usize,
    rows_written: usize,
    draws: u64,
    pub(crate) gas_used: u64,
}

impl<'a> Invocation<'a> {
    pub(crate) fn new(kit: &'a Testkit, step: u32, entry: Kind) -> Self {
        Self {
            kit,
            step,
            entry,
            limits: &cap::VOS,
            awaits: None,
            section: false,
            frames: vec![BTreeMap::new()],
            stack: Vec::new(),
            nested: Vec::new(),
            instances: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            write_bytes: 0,
            rows_written: 0,
            draws: 0,
            gas_used: 0,
        }
    }

    /// The entry invocation. `Err` is a failure code that fails the step.
    pub(crate) fn top(&mut self, call: Call) -> Result<Outcome, Failure> {
        let Call {
            instance,
            method,
            arguments,
            ..
        } = call;
        if arguments.len() > cap::REQUEST {
            return Err(Failure::Cap);
        }
        let installed = self.kit.instances.get(&instance).ok_or(Failure::Unknown)?;
        self.limits = installed.target.limits();
        let schema = installed.schema.method(method).ok_or(Failure::Unknown)?;
        if !schema.kind.is_handler() || (self.entry == Kind::Query && schema.kind != Kind::Query) {
            return Err(Failure::Unknown);
        }
        let gas = schema.gas_limit();
        let (ended, used) = self.invoke(call, gas).map_err(|(code, used)| {
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
            Ended::Forbidden => Outcome::failed(Failure::Forbidden),
            Ended::Paused(_) | Ended::Preempted { .. } => unreachable!("only a workflow pauses"),
        })
    }

    /// Run one invocation with `gas`: how it ended and the gas it used, or
    /// a code that fails the step with the gas used.
    fn invoke(&mut self, call: Call, gas: u64) -> Result<(Ended, u64), (Failure, u64)> {
        let Call {
            caller,
            instance,
            method,
            arguments,
        } = call;
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
        // A workflow's own machine is on no stack, but counts as one.
        let depth = self.stack.len() + usize::from(self.entry == Kind::Workflow);
        if depth >= MAX_DEPTH {
            return Err((Failure::Depth, 0));
        }
        let kind = schema.kind;
        let mut machine =
            Machine::load(&installed.program, &[], gas).map_err(|_| (Failure::Trapped, 0))?;
        let registers = machine.registers_mut();
        registers[7] = u64::from(method.0);
        registers[8] = kind.index().into();
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
        let ended = self.serve(&mut machine, call, kind);
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

    fn serve(&mut self, machine: &mut Machine, call: Call, kind: Kind) -> Result<Ended, Failure> {
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
                    let Some(op) = Op::from_id(id) else {
                        // Not an actor operation: the agent answers WHAT.
                        if !machine.charge(price::OPERATION) {
                            return Err(Failure::OutOfGas);
                        }
                        machine.registers_mut()[7] = code::WHAT;
                        continue;
                    };
                    if !abi::allowed(kind, op) {
                        return Err(Failure::Trapped);
                    }
                    if !machine.charge(price::of(op)) {
                        return Err(Failure::OutOfGas);
                    }
                    self.operation(machine, op, call, kind, &mut outcome)?;
                }
                _ => return Err(Failure::Trapped),
            }
        }
    }

    pub(crate) fn operation(
        &mut self,
        machine: &mut Machine,
        op: Op,
        call: Call,
        kind: Kind,
        outcome: &mut Option<Ended>,
    ) -> Result<(), Failure> {
        let Call {
            caller,
            instance,
            arguments,
            ..
        } = call;
        let r = *machine.registers();
        match op {
            Op::Input => {
                copy_out(machine, arguments, r[7], r[8], r[9])?;
                machine.registers_mut()[7] = arguments.len() as u64;
            }
            Op::Reply | Op::Fail => {
                if outcome.is_some() {
                    return Err(Failure::Trapped);
                }
                let bytes = read(machine, r[7], r[8], cap::REPLY)?;
                *outcome = Some(if op == Op::Reply {
                    Ended::Replied(bytes)
                } else {
                    Ended::Failed(bytes)
                });
                machine.registers_mut()[7] = code::OK;
            }
            Op::Log => {
                read(machine, r[8], r[9], 4096)?;
                machine.registers_mut()[7] = code::OK;
            }
            Op::Caller => {
                let encoded = caller.encode();
                copy_out(machine, &encoded, r[7], 0, r[8])?;
                machine.registers_mut()[7] = encoded.len() as u64;
            }
            Op::Now => machine.registers_mut()[7] = self.kit.time,
            Op::Random => {
                let bytes = random(&self.kit.seed, self.step, self.draws);
                self.draws += 1;
                write(machine, r[7], &bytes)?;
                machine.registers_mut()[7] = code::OK;
            }
            Op::SelfId => {
                machine.registers_mut()[7] = u64::from(instance.0);
                machine.registers_mut()[8] = u64::from(self.kit.agent.0);
            }
            Op::Get => {
                let key = row(machine, instance, r[7], r[8], r[9])?;
                match self.read_state(&key)? {
                    Some(value) => {
                        copy_out(machine, &value, r[10], r[11], r[12])?;
                        machine.registers_mut()[7] = value.len() as u64;
                    }
                    None => machine.registers_mut()[7] = code::NONE,
                }
            }
            Op::Put | Op::Delete => {
                let key = row(machine, instance, r[7], r[8], r[9])?;
                let value = if op == Op::Put {
                    Some(read(machine, r[10], r[11], cap::VALUE)?)
                } else {
                    None
                };
                self.write_bytes += key.len() + value.as_ref().map_or(0, Vec::len);
                self.rows_written += 1;
                if self.write_bytes > self.limits.step_writes
                    || self.rows_written > self.limits.step_rows
                {
                    return Err(Failure::Cap);
                }
                self.frames.last_mut().expect("a frame").insert(key, value);
                machine.registers_mut()[7] = code::OK;
            }
            Op::Scan => self.scan(machine, instance, &r)?,
            Op::Call => self.call(machine, instance, kind, &r)?,
            Op::Send => {
                let call_arguments = read(machine, r[10], r[11], self.limits.message)?;
                if self.messages.len() == self.limits.messages {
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
            Op::Attest => self.attest(machine, instance, &r)?,
            Op::AttestAt => {
                if outcome.is_some() {
                    return Err(Failure::Trapped);
                }
                match self.ask_at_cut(machine, instance, &r)? {
                    Ok(state) => *outcome = Some(Ended::Paused(state)),
                    Err(refused) => {
                        machine.registers_mut()[7] = 0;
                        machine.registers_mut()[8] = refused.code().into();
                    }
                }
            }
            Op::Request | Op::Result | Op::Sleep => {
                if outcome.is_some() {
                    return Err(Failure::Trapped);
                }
                let state = match op {
                    Op::Sleep => WorkflowState::Sleeping {
                        until: r[7].max(self.kit.time + 1),
                    },
                    _ => self.request(machine, op, &r)?,
                };
                *outcome = Some(Ended::Paused(state));
            }
            Op::Open => {
                if self.section || r[7] != u64::from(instance.0) {
                    return Err(Failure::Trapped);
                }
                self.section = true;
                machine.registers_mut()[7] = code::OK;
            }
            Op::Close => {
                if !self.section {
                    return Err(Failure::Trapped);
                }
                self.section = false;
                machine.registers_mut()[7] = code::OK;
            }
        }
        Ok(())
    }

    /// [`Op::Scan`]: a page of the instance's rows of one kind, after a
    /// cursor when given, each key's bytes charged.
    fn scan(
        &self,
        machine: &mut Machine,
        instance: InstanceId,
        r: &[u64; 13],
    ) -> Result<(), Failure> {
        let cursor = match r[12] {
            0 => None,
            1 => Some(read_key(machine, r[8], r[9])?),
            _ => return Err(Failure::Trapped),
        };
        let rows = Rows::from_register(r[7]).ok_or(Failure::Trapped)?;
        let (prefix, transform) = keys::rows_prefix(instance, rows).ok_or(Failure::Trapped)?;
        let after = match cursor {
            Some(cursor) => Some(keys::row(instance, rows, &cursor)?),
            None => None,
        };
        let capacity = (r[11] as usize).min(cap::SCAN);
        let mut out = Vec::new();
        let mut full = false;
        let mut returned = 0;
        for (key, value) in self.rows(&prefix, after.as_deref())? {
            let raw = transform
                .raw(&key[prefix.len()..])
                .ok_or(Failure::Trapped)?;
            let length = raw.len();
            let row = (raw, value).encode();
            if out.len() + row.len() > capacity {
                full = out.is_empty();
                break;
            }
            returned += length;
            out.extend_from_slice(&row);
        }
        if !machine.charge(returned as u64 * price::KEY_BYTE) {
            return Err(Failure::OutOfGas);
        }
        write(machine, r[10], &out)?;
        machine.registers_mut()[7] = if full { code::FULL } else { out.len() as u64 };
        Ok(())
    }

    /// [`Op::Call`]: a nested call of another instance's handler, its
    /// effects discarded when it fails.
    fn call(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        kind: Kind,
        r: &[u64; 13],
    ) -> Result<(), Failure> {
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
        if !callee_kind.is_handler() || (kind == Kind::Query && callee_kind != Kind::Query) {
            return Err(Failure::Trapped);
        }
        self.frames.push(BTreeMap::new());
        // A failed callee's effects are discarded: its writes with
        // its frame, and its messages, attests and share of the
        // step's write cap here. Random draws are not effects: they
        // keep counting.
        let effects = (
            self.messages.len(),
            self.attests.len(),
            self.write_bytes,
            self.rows_written,
        );
        let gas = machine.gas_remaining();
        let call = Call {
            caller: Principal::Instance(instance),
            instance: callee,
            method,
            arguments: &call_arguments,
        };
        let (ended, used) = self.invoke(call, gas).map_err(|(code, _)| code)?;
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
            Ended::Paused(_) | Ended::Preempted { .. } => {
                unreachable!("only a workflow pauses")
            }
        };
        if failed.is_some() {
            let (messages, attests, written, rows) = effects;
            self.messages.truncate(messages);
            self.attests.truncate(attests);
            self.write_bytes = written;
            self.rows_written = rows;
        }
        copy_out(machine, &bytes, r[11], 0, r[12])?;
        machine.registers_mut()[7] = bytes.len() as u64;
        machine.registers_mut()[8] = failed.map_or(0, |code| code.code().into());
        Ok(())
    }

    /// [`Op::Attest`]: a method's kernel run on its arguments, its output
    /// returned and recorded as the step's attest.
    fn attest(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        r: &[u64; 13],
    ) -> Result<(), Failure> {
        let method = MethodId(r[7] as u32);
        let call_arguments = read(machine, r[8], r[9], self.limits.attest)?;
        if Attest::weighed(&self.attests) + 1 > self.limits.attests {
            return Err(Failure::Cap);
        }
        let installed = self.kit.instances.get(&instance);
        let program = installed
            .and_then(|installed| installed.kernel(method))
            .ok_or(Failure::Unknown)?;
        // A kernel of statement parts, or of its output alone; one
        // that reads at a window's cut runs there alone.
        let stating = match installed
            .and_then(|installed| installed.schema.method(method))
            .map(|schema| schema.kind)
        {
            Some(Kind::Attestable) => false,
            Some(Kind::Stating) => true,
            _ => return Err(Failure::Unknown),
        };
        // Bounded compressions: the kernel runs within its method's
        // gas and the bound's, for both the step's target and the
        // attesting instance's.
        let mut gas = machine.gas_remaining();
        if let Some(installed) = installed {
            let declared = installed
                .schema
                .method(method)
                .and_then(|schema| schema.gas);
            for limits in [self.limits, installed.target.limits()] {
                if let Some(limit) = limits.kernel_limit(declared) {
                    gas = gas.min(limit);
                }
            }
        }
        let run =
            kernel(program, &call_arguments, gas, self.limits.attest).map_err(|(code, _)| code)?;
        if !machine.charge(run.gas_used) {
            return Err(Failure::OutOfGas);
        }
        // Its statement's parts, their io-hash the one it left: a
        // kernel's bug fails the step.
        let parts = if stating {
            if !machine.charge(price::io_hash(run.output.len())) {
                return Err(Failure::OutOfGas);
            }
            parts(&run.output, &run.io_hash).ok_or(Failure::Trapped)?
        } else {
            KernelReturn {
                public_args: Vec::new(),
                output: run.output,
                roots: Vec::new(),
            }
        };
        copy_out(machine, &parts.output, r[10], 0, r[11])?;
        machine.registers_mut()[7] = parts.output.len() as u64;
        machine.registers_mut()[8] = 0;
        self.attests.push(Attest {
            program: ProgramHash::of(program),
            window: None,
            witness_input: run.witness_input,
            output: parts.output,
            public_args: parts.public_args,
            roots: parts.roots,
        });
        Ok(())
    }

    /// A workflow's request of another agent, or its wait for a result
    /// there: the message it sends, and the await, until its deadline.
    fn request(
        &mut self,
        machine: &mut Machine,
        op: Op,
        r: &[u64; 13],
    ) -> Result<WorkflowState, Failure> {
        let awaiting = self.awaits.expect("only a workflow awaits");
        let agent = AgentId(r[7] as u32);
        if agent == self.kit.agent {
            return Err(Failure::Trapped);
        }
        let (body, within) = if op == Op::Request {
            let arguments = read(machine, r[10], r[11], self.limits.message)?;
            let body = Body::Call {
                instance: InstanceId(r[8] as u32),
                method: MethodId(r[9] as u32),
                arguments,
                awaiting: Some(awaiting),
            };
            (body, r[12])
        } else {
            let workflow = WorkflowId(r[8]);
            (Body::Wait { workflow, awaiting }, r[9])
        };
        if self.messages.len() == self.limits.messages {
            return Err(Failure::Cap);
        }
        self.messages.push(Outgoing { to: agent, body });
        let within = if within == 0 {
            vos_wire::defaults::AWAIT_MS
        } else {
            within
        };
        Ok(WorkflowState::Awaiting {
            agent,
            counter: awaiting.counter,
            deadline: self.kit.time.saturating_add(within),
        })
    }

    /// A value through the overlays and applied state.
    fn read_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Failure> {
        for frame in self.frames.iter().rev() {
            if let Some(value) = frame.get(key) {
                return Ok(value.clone());
            }
        }
        self.kit
            .state
            .get(key)
            .map(|value| held(key, value))
            .transpose()
    }

    /// Rows under `prefix`, after `after` when given, through the overlays.
    fn rows(&self, prefix: &[u8], after: Option<&[u8]>) -> Result<StateRows, Failure> {
        let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        for (key, value) in self
            .kit
            .state
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
        {
            merged.insert(key.clone(), Some(held(key, value)?));
        }
        for frame in &self.frames {
            for (key, value) in frame.range(prefix.to_vec()..) {
                if !key.starts_with(prefix) {
                    break;
                }
                merged.insert(key.clone(), value.clone());
            }
        }
        Ok(merged
            .into_iter()
            .filter(|(key, _)| after.is_none_or(|after| key.as_slice() > after))
            .filter_map(|(key, value)| Some((key, value?)))
            .collect())
    }
}
