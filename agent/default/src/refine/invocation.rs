//! One step's invocation: an actor's handler or a workflow's machine, run
//! against the step's overlays, with its nested calls, and every operation
//! of the actor ABI served.

mod ended;
mod kernel;
mod memory;
mod scan;
mod units;

pub(super) use ended::{Ended, Pause};
pub(super) use units::Share;

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;

use vos_wire::abi::{self, Failure, Kind, Op, Rows, cap, code, precompile, price};
use vos_wire::batch::{Await, Body};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, WorkflowId};
use vos_wire::records::Installed;
use vos_wire::result::{Attest, InstanceGas, Outcome, Outgoing};
use vos_wire::{Encode, defaults, keys};

use super::Overlay;
use super::base::{Base, Corrupt, Meter};
use crate::machines::{self, Exit, Machine};
use kernel::{kernel, random, serve_precompile};
use memory::{copy_out, read, read_key, row, window, write};

/// Machines a step may hold at once: a handler and its nested callees, or
/// a workflow's and its callees. A host's own limit is the same on VOS, so
/// either refuses the 64th; an attest at the deepest level needs a 64th,
/// which the host refuses, as `Depth`.
const MAX_DEPTH: usize = 63;

/// One step: its overlays, call stack and effects.
pub(super) struct Invocation<'a> {
    base: &'a Base,
    step: u32,
    entry: Kind,
    /// A workflow's step: the workflow, and the counter its next await
    /// takes.
    pub(super) awaits: Option<Await>,
    /// The pages of the workflow's machine the meter has taken.
    pages_paid: usize,
    /// A workflow's section on its instance's state is open.
    section: bool,
    /// The step overlay, then one per nested call.
    pub(super) frames: Vec<Overlay>,
    stack: Vec<InstanceId>,
    /// Gas the callees of each invocation on the stack used.
    nested: Vec<u64>,
    pub(super) instances: Vec<InstanceGas>,
    pub(super) messages: Vec<Outgoing>,
    pub(super) attests: Vec<Attest>,
    /// The bytes of state the step has written, against its cap.
    write_bytes: usize,
    draws: u64,
    pub(super) gas_used: u64,
}

impl<'a> Invocation<'a> {
    pub(super) fn new(base: &'a Base, step: u32, entry: Kind) -> Self {
        Self {
            base,
            step,
            entry,
            awaits: None,
            pages_paid: 0,
            section: false,
            frames: alloc::vec![BTreeMap::new()],
            stack: Vec::new(),
            nested: Vec::new(),
            instances: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            write_bytes: 0,
            draws: 0,
            gas_used: 0,
        }
    }

    pub(super) fn top(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
    ) -> Outcome {
        if arguments.len() > cap::REQUEST {
            return Outcome::failed(Failure::Cap);
        }
        let installed = match self.installed(instance) {
            Ok(installed) => installed,
            Err(code) => return Outcome::failed(code),
        };
        let Some(schema) = installed.schema.method(method) else {
            return Outcome::failed(Failure::Unknown);
        };
        if !schema.kind.is_handler() || (self.entry == Kind::Query && schema.kind != Kind::Query)
        {
            return Outcome::failed(Failure::Unknown);
        }
        let gas = schema.gas_limit();
        match self.invoke(caller, instance, method, arguments, gas) {
            Ok((ended, used)) => {
                self.gas_used = used;
                match ended {
                    Ended::Replied(reply) => Outcome::Done(reply),
                    Ended::Failed(detail) => Outcome::Failed {
                        code: Failure::Handler,
                        detail,
                    },
                    Ended::Forbidden => Outcome::failed(Failure::Forbidden),
                    Ended::Paused(_) => unreachable!("only a workflow pauses"),
                }
            }
            Err((code, used)) => {
                self.gas_used = used;
                Outcome::failed(code)
            }
        }
    }

    /// Run one invocation with `gas`: how it ended and the gas it used,
    /// or a failure of the whole step with the gas used.
    fn invoke(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: &[u8],
        gas: u64,
    ) -> Result<(Ended, u64), (Failure, u64)> {
        let installed = self.installed(instance).map_err(|code| (code, 0))?;
        let schema = installed
            .schema
            .method(method)
            .ok_or((Failure::Unknown, 0))?;
        if let Some(role) = &schema.role {
            let required = installed.role(role).expect("checked at install");
            if self.role(&caller).map_err(|_| (Failure::Trapped, 0))? != Some(required) {
                return Ok((Ended::Forbidden, 0));
            }
        }
        if self.stack.contains(&instance) {
            return Err((Failure::Cycle, 0));
        }
        // A workflow's own machine is on no stack, but takes a machine too.
        let depth = self.stack.len() + usize::from(self.entry == Kind::Workflow);
        if depth >= MAX_DEPTH {
            return Err((Failure::Depth, 0));
        }
        let kind = schema.kind;
        let mut machine = machines::pinned(&installed.program().0, 0)
            .map_err(|unavailable| (unavailable.into(), 0))?;
        machine.set_gas(gas);
        machine.set_register(7, u64::from(method.0));
        machine.set_register(8, u64::from(kind.index()));
        machine.set_register(9, arguments.len() as u64);
        if !self
            .instances
            .iter()
            .any(|entry| entry.instance == instance)
        {
            self.instances.push(InstanceGas { instance, gas: 0 });
        }
        self.stack.push(instance);
        self.nested.push(0);
        let ended = self.serve(
            &mut machine,
            Some(&installed),
            caller,
            instance,
            kind,
            arguments,
        );
        self.stack.pop();
        let nested = self.nested.pop().expect("this invocation's entry");
        let used = gas - machine.gas();
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

    /// An instance's installed record: actors cannot write system keys,
    /// so the refine's committed writes and applied state hold it.
    fn installed(&self, instance: InstanceId) -> Result<Rc<Installed>, Failure> {
        self.base.installed(instance)?.ok_or(Failure::Unknown)
    }

    fn role(&self, principal: &Principal) -> Result<Option<u8>, Corrupt> {
        Ok(self
            .read_state(&keys::member(principal))?
            .and_then(|bytes| bytes.first().copied()))
    }

    /// Serve a handler's machine's exits until it halts or fails. Inlined,
    /// as a call is into it: a nested call holds one frame of the agent's
    /// stack a level, sixty-three levels deep.
    #[inline(always)]
    fn serve(
        &mut self,
        machine: &mut Machine,
        installed: Option<&Installed>,
        caller: Principal,
        instance: InstanceId,
        kind: Kind,
        arguments: &[u8],
    ) -> Result<Ended, Failure> {
        let mut outcome: Option<Ended> = None;
        loop {
            match machine.invoke() {
                Exit::Halt => return Ok(outcome.unwrap_or(Ended::Replied(Vec::new()))),
                Exit::OutOfGas => return Err(Failure::OutOfGas),
                Exit::Panic | Exit::Fault(_) => return Err(Failure::Trapped),
                Exit::Host(id) => {
                    let Some(op) = self.plain(machine, id, instance)? else {
                        continue;
                    };
                    if !abi::allowed(kind, op) {
                        return Err(Failure::Trapped);
                    }
                    if !machine.charge(price::of(op)) {
                        return Err(Failure::OutOfGas);
                    }
                    if op == Op::Call {
                        self.call(machine, instance, kind)?;
                        continue;
                    }
                    self.operation(
                        machine,
                        installed,
                        op,
                        caller,
                        instance,
                        arguments,
                        &mut outcome,
                    )?;
                }
            }
        }
    }

    /// Serve host call `id` when it is a precompile, an id the agent does
    /// not serve, answered `WHAT`, or an operation every kind may use that
    /// only sets registers: `None` once served, else the operation to
    /// serve. They cost the agent least, so come first.
    #[inline(always)]
    fn plain(
        &self,
        machine: &mut Machine,
        id: u64,
        instance: InstanceId,
    ) -> Result<Option<Op>, Failure> {
        if precompile::price(id).is_some() {
            return serve_precompile(&self.base.meter, machine, id).map(|()| None);
        }
        let op = Op::from_id(id);
        if let Some(op) = op
            && !matches!(op, Op::Now | Op::SelfId)
        {
            return Ok(Some(op));
        }
        if !machine.charge(price::OPERATION) {
            return Err(Failure::OutOfGas);
        }
        match op {
            Some(Op::Now) => machine.set_register(7, self.base.time),
            Some(Op::SelfId) => {
                machine.set_register(7, u64::from(instance.0));
                machine.set_register(8, u64::from(self.base.agent.0));
            }
            _ => machine.set_register(7, code::WHAT),
        }
        Ok(None)
    }

    /// A nested call of a handler of this agent's: the callee runs, and
    /// its reply or error lands in the caller's output.
    #[inline(always)]
    fn call(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        kind: Kind,
    ) -> Result<(), Failure> {
        let r: [u64; 13] = core::array::from_fn(|index| machine.register(index));
        let callee = InstanceId(r[7] as u32);
        let method = MethodId(r[8] as u32);
        let call_arguments = read(machine, r[9], r[10], cap::REQUEST)?;
        let callee_kind = self
            .installed(callee)?
            .schema
            .method(method)
            .map(|schema| schema.kind)
            .ok_or(Failure::Unknown)?;
        if !callee_kind.is_handler() || (kind == Kind::Query && callee_kind != Kind::Query) {
            return Err(Failure::Trapped);
        }
        self.frames.push(BTreeMap::new());
        let effects = (self.messages.len(), self.attests.len(), self.write_bytes);
        let gas = machine.gas();
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
                self.frames.last_mut().expect("a frame").extend(frame);
                (reply, None)
            }
            Ended::Failed(detail) => (detail, Some(Failure::Handler)),
            Ended::Forbidden => (Vec::new(), Some(Failure::Forbidden)),
            Ended::Paused(_) => unreachable!("only a workflow pauses"),
        };
        if failed.is_some() {
            let (messages, attests, written) = effects;
            self.messages.truncate(messages);
            self.attests.truncate(attests);
            self.write_bytes = written;
        }
        copy_out(machine, &bytes, r[11], 0, r[12])?;
        machine.set_register(7, bytes.len() as u64);
        machine.set_register(8, failed.map_or(0, |code| code.code().into()));
        Ok(())
    }

    /// Every other served operation.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn operation(
        &mut self,
        machine: &mut Machine,
        installed: Option<&Installed>,
        op: Op,
        caller: Principal,
        instance: InstanceId,
        arguments: &[u8],
        outcome: &mut Option<Ended>,
    ) -> Result<(), Failure> {
        let r: [u64; 13] = core::array::from_fn(|index| machine.register(index));
        match op {
            Op::Input => {
                copy_out(machine, arguments, r[7], r[8], r[9])?;
                machine.set_register(7, arguments.len() as u64);
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
                machine.set_register(7, code::OK);
            }
            Op::Log => {
                read(machine, r[8], r[9], 4096)?;
                machine.set_register(7, code::OK);
            }
            Op::Caller => {
                let encoded = caller.encode();
                copy_out(machine, &encoded, r[7], 0, r[8])?;
                machine.set_register(7, encoded.len() as u64);
            }
            Op::Random => {
                let bytes = random(&self.base.seed, self.step, self.draws);
                self.draws += 1;
                write(machine, r[7], &bytes)?;
                machine.set_register(7, code::OK);
            }
            Op::Get => {
                let key = row(machine, instance, r[7], r[8], r[9])?;
                match self.read_state(&key)? {
                    Some(value) => {
                        copy_out(machine, &value, r[10], r[11], r[12])?;
                        machine.set_register(7, value.len() as u64);
                    }
                    None => machine.set_register(7, code::NONE),
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
                if self.write_bytes > cap::STEP_WRITES {
                    return Err(Failure::Cap);
                }
                self.frames.last_mut().expect("a frame").insert(key, value);
                machine.set_register(7, code::OK);
            }
            Op::Scan => {
                let cursor = match r[12] {
                    0 => None,
                    1 => Some(read_key(machine, r[8], r[9])?),
                    _ => return Err(Failure::Trapped),
                };
                let rows = Rows::from_register(r[7]).ok_or(Failure::Trapped)?;
                let (prefix, transform) =
                    keys::rows_prefix(instance, rows).ok_or(Failure::Trapped)?;
                let after = cursor
                    .map(|cursor| keys::row(instance, rows, &cursor))
                    .transpose()?;
                let capacity = (r[11] as usize).min(cap::SCAN);
                let (out, full, returned) = self.scan(&prefix, after, capacity, transform)?;
                if !machine.charge(returned as u64 * price::KEY_BYTE) {
                    return Err(Failure::OutOfGas);
                }
                write(machine, r[10], &out)?;
                machine.set_register(7, if full { code::FULL } else { out.len() as u64 });
            }
            Op::Send => {
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
                machine.set_register(7, code::OK);
            }
            Op::Attest => {
                let method = MethodId(r[7] as u32);
                let call_arguments = read(machine, r[8], r[9], cap::REQUEST)?;
                if self.attests.len() == cap::ATTESTS {
                    return Err(Failure::Cap);
                }
                let program = installed
                    .and_then(|installed| installed.kernel(method))
                    .ok_or(Failure::Unknown)?;
                let gas = machine.gas();
                let (output, used) = kernel(&self.base.meter, &program, &call_arguments, gas)?;
                if !machine.charge(used) {
                    return Err(Failure::OutOfGas);
                }
                self.attests.push(Attest {
                    program,
                    arguments: call_arguments,
                    output: output.clone(),
                });
                copy_out(machine, &output, r[10], 0, r[11])?;
                machine.set_register(7, output.len() as u64);
                machine.set_register(8, 0);
            }
            Op::Request | Op::Result | Op::Sleep => {
                if outcome.is_some() {
                    return Err(Failure::Trapped);
                }
                *outcome = Some(Ended::Paused(self.pause(machine, op)?));
            }
            // A workflow's section: on its own instance, never two at once.
            Op::Open => {
                if self.section || r[7] != u64::from(instance.0) {
                    return Err(Failure::Trapped);
                }
                self.section = true;
                machine.set_register(7, code::OK);
            }
            Op::Close => {
                if !self.section {
                    return Err(Failure::Trapped);
                }
                self.section = false;
                machine.set_register(7, code::OK);
            }
            Op::Now | Op::SelfId | Op::Call => unreachable!("served apart"),
        }
        Ok(())
    }

    /// A workflow's pause: a sleep until a time, or a request of another
    /// agent or a wait for a workflow's result there, whose message the
    /// step sends, awaited until its deadline. Apart, reading its own
    /// registers, so the operations above keep theirs as they need them.
    #[cold]
    #[inline(never)]
    fn pause(&mut self, machine: &mut Machine, op: Op) -> Result<Pause, Failure> {
        let r: [u64; 13] = core::array::from_fn(|index| machine.register(index));
        if op == Op::Sleep {
            let until = r[7].max(self.base.time.saturating_add(1));
            return Ok(Pause::Sleep { until });
        }
        let awaiting = self.awaits.expect("only a workflow awaits");
        let agent = AgentId(r[7] as u32);
        if agent == self.base.agent {
            return Err(Failure::Trapped);
        }
        let (body, within) = match op {
            Op::Request => {
                let arguments = read(machine, r[10], r[11], cap::MESSAGE)?;
                let body = Body::Call {
                    instance: InstanceId(r[8] as u32),
                    method: MethodId(r[9] as u32),
                    arguments,
                    awaiting: Some(awaiting),
                };
                (body, r[12])
            }
            _ => {
                let workflow = WorkflowId(r[8]);
                (Body::Wait { workflow, awaiting }, r[9])
            }
        };
        if self.messages.len() == cap::MESSAGES {
            return Err(Failure::Cap);
        }
        self.messages.push(Outgoing { to: agent, body });
        let within = match within {
            0 => defaults::AWAIT_MS,
            within => within,
        };
        Ok(Pause::Await {
            agent,
            counter: awaiting.counter,
            deadline: self.base.time.saturating_add(within),
        })
    }
}
