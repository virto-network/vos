//! One step's invocation: an actor's handler or a workflow's machine, run
//! against the step's overlays, with its nested calls, and every operation
//! of the actor ABI served.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;

use vos_wire::abi::{self, Failure, Kind, Rows, cap, code, op, precompile, price};
use vos_wire::batch::{Await, Body};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, WorkflowId};
use vos_wire::keys::Transform;
use vos_wire::records::{Installed, WorkflowState};
use vos_wire::result::{Attest, InstanceGas, Outcome, Outgoing};
use vos_wire::{Encode, defaults, keys};

use super::{Base, Corrupt, Meter, Overlay, applied_rows, has_own_program};
use crate::machines::{ARGUMENTS, Exit, Machine};

/// Machines a step may hold at once: a handler and its nested callees, or
/// a workflow's and its callees.
const MAX_DEPTH: usize = 63;

/// How an invocation ended, short of failing the whole step.
pub(super) enum Ended {
    Replied(Vec<u8>),
    Failed(Vec<u8>),
    Forbidden,
    /// A workflow paused.
    Paused(Pause),
}

/// Where a workflow's step paused: awaiting another agent's answer to
/// await `counter` until a deadline, or asleep until a time.
pub(super) enum Pause {
    Await {
        agent: AgentId,
        counter: u64,
        deadline: u64,
    },
    Sleep {
        until: u64,
    },
}

impl Pause {
    /// The batch time its row in the due index lies at.
    pub(super) fn due(&self) -> u64 {
        match self {
            Pause::Await { deadline, .. } => *deadline,
            Pause::Sleep { until } => *until,
        }
    }

    /// The workflow's state while it pauses.
    pub(super) fn state(self) -> WorkflowState {
        match self {
            Pause::Await {
                agent,
                counter,
                deadline,
            } => WorkflowState::Awaiting {
                agent,
                counter,
                deadline,
            },
            Pause::Sleep { until } => WorkflowState::Sleeping { until },
        }
    }
}

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
        let failed = |code| Outcome::Failed {
            code,
            detail: Vec::new(),
        };
        if arguments.len() > cap::REQUEST {
            return failed(Failure::Cap);
        }
        let installed = match self.installed(instance) {
            Ok(installed) => installed,
            Err(code) => return failed(code),
        };
        let Some(schema) = installed.schema.method(method) else {
            return failed(Failure::Unknown);
        };
        if has_own_program(schema.kind) || (self.entry == Kind::Query && schema.kind != Kind::Query)
        {
            return failed(Failure::Unknown);
        }
        let gas = schema
            .gas
            .unwrap_or(defaults::HANDLER_GAS)
            .min(defaults::MAX_HANDLER_GAS);
        match self.invoke(caller, instance, method, arguments, gas) {
            Ok((ended, used)) => {
                self.gas_used = used;
                match ended {
                    Ended::Replied(reply) => Outcome::Done(reply),
                    Ended::Failed(detail) => Outcome::Failed {
                        code: Failure::Handler,
                        detail,
                    },
                    Ended::Forbidden => failed(Failure::Forbidden),
                    Ended::Paused(_) => unreachable!("only a workflow pauses"),
                }
            }
            Err((code, used)) => {
                self.gas_used = used;
                failed(code)
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
        let mut machine = Machine::acquire(&installed.program.0)
            .map_err(|unavailable| (unavailable.into(), 0))?;
        machine.set_gas(gas);
        machine.set_register(7, u64::from(method.0));
        machine.set_register(8, u64::from(kind.encode()[0]));
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
        let ended = self.serve::<false>(
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

    /// Run a workflow's machine, of `instance`'s workflow method, through
    /// its step: until it pauses, ends or fails. Its own gas goes to its
    /// instance, as a handler's.
    pub(super) fn workflow(
        &mut self,
        machine: &mut Machine,
        owner: Principal,
        instance: InstanceId,
        input: &[u8],
    ) -> Result<Ended, Failure> {
        let gas = machine.gas();
        self.instances.push(InstanceGas { instance, gas: 0 });
        self.nested.push(0);
        let ended = self.serve::<true>(machine, None, owner, instance, Kind::Workflow, input);
        let nested = self.nested.pop().expect("the workflow's entry");
        self.gas_used = gas - machine.gas();
        self.instances[0].gas += self.gas_used - nested;
        ended
    }

    /// Serve a machine's exits until it halts, fails or pauses: a
    /// workflow's (`TRACKED`) pays each page it writes as it writes it.
    /// Inlined, as a call is into it: a nested call holds one frame of the
    /// agent's stack a level, sixty-three levels deep.
    #[inline(always)]
    fn serve<const TRACKED: bool>(
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
            // Only a workflow writes pages it pays for, and pauses.
            if TRACKED {
                self.pay_pages(machine)?;
                if let Some(Ended::Paused(_)) = outcome {
                    return Ok(outcome.take().expect("paused"));
                }
            }
            let exit = machine.invoke();
            if TRACKED {
                self.pay_pages(machine)?;
            }
            match exit {
                Exit::Halt => return Ok(outcome.unwrap_or(Ended::Replied(Vec::new()))),
                Exit::OutOfGas => return Err(Failure::OutOfGas),
                Exit::Panic | Exit::Fault(_) => return Err(Failure::Trapped),
                // The operations that only set registers, which every kind
                // served here may use, first: they cost the agent least.
                Exit::Host(id @ (op::NOW | op::SELF_ID)) => {
                    if !machine.charge(price::OPERATION) {
                        return Err(Failure::OutOfGas);
                    }
                    if id == op::NOW {
                        machine.set_register(7, self.base.time);
                    } else {
                        machine.set_register(7, u64::from(instance.0));
                        machine.set_register(8, u64::from(self.base.agent.0));
                    }
                }
                Exit::Host(id) if precompile::price(id).is_some() => {
                    serve_precompile(&self.base.meter, machine, id)?;
                }
                Exit::Host(id) => {
                    if !known(id) {
                        if !machine.charge(price::OPERATION) {
                            return Err(Failure::OutOfGas);
                        }
                        machine.set_register(7, code::WHAT);
                        continue;
                    }
                    if !abi::allowed(kind, id) {
                        return Err(Failure::Trapped);
                    }
                    if !machine.charge(price::of(id)) {
                        return Err(Failure::OutOfGas);
                    }
                    if id == op::CALL {
                        self.call(machine, instance, kind)?;
                        continue;
                    }
                    self.operation(
                        machine,
                        installed,
                        id,
                        caller,
                        instance,
                        arguments,
                        &mut outcome,
                    )?;
                }
            }
        }
    }

    /// Take the pages a workflow's machine has written since the last take
    /// from the meter, before they are captured: out of gas, the budget
    /// overrun, when it cannot pay them.
    fn pay_pages(&mut self, machine: &Machine) -> Result<(), Failure> {
        let written = machine.written().map_or(0, |pages| pages.len());
        let new = (written - self.pages_paid) as u64;
        self.pages_paid = written;
        if new > 0 && !self.base.meter.take(new * defaults::WRITTEN_PAGE) {
            return Err(Failure::OutOfGas);
        }
        Ok(())
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
        if has_own_program(callee_kind) || (kind == Kind::Query && callee_kind != Kind::Query) {
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
        id: u64,
        caller: Principal,
        instance: InstanceId,
        arguments: &[u8],
        outcome: &mut Option<Ended>,
    ) -> Result<(), Failure> {
        let r: [u64; 13] = core::array::from_fn(|index| machine.register(index));
        match id {
            op::INPUT => {
                copy_out(machine, arguments, r[7], r[8], r[9])?;
                machine.set_register(7, arguments.len() as u64);
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
                machine.set_register(7, code::OK);
            }
            op::LOG => {
                read(machine, r[8], r[9], 4096)?;
                machine.set_register(7, code::OK);
            }
            op::CALLER => {
                let encoded = caller.encode();
                copy_out(machine, &encoded, r[7], 0, r[8])?;
                machine.set_register(7, encoded.len() as u64);
            }
            op::RANDOM => {
                let bytes = random(&self.base.seed, self.step, self.draws);
                self.draws += 1;
                write(machine, r[7], &bytes)?;
                machine.set_register(7, code::OK);
            }
            op::GET => {
                let key = row(machine, instance, r[7], r[8], r[9])?;
                match self.read_state(&key)? {
                    Some(value) => {
                        copy_out(machine, &value, r[10], r[11], r[12])?;
                        machine.set_register(7, value.len() as u64);
                    }
                    None => machine.set_register(7, code::NONE),
                }
            }
            op::PUT | op::DELETE => {
                let key = row(machine, instance, r[7], r[8], r[9])?;
                let value = if id == op::PUT {
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
            op::SCAN => {
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
                machine.set_register(7, code::OK);
            }
            op::ATTEST => {
                let method = MethodId(r[7] as u32);
                let call_arguments = read(machine, r[8], r[9], cap::REQUEST)?;
                if self.attests.len() == cap::ATTESTS {
                    return Err(Failure::Cap);
                }
                let program = installed
                    .and_then(|installed| installed.attestable(method))
                    .ok_or(Failure::Unknown)?;
                let gas = machine.gas();
                let (output, used) = attestable(&self.base.meter, &program, &call_arguments, gas)?;
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
            op::REQUEST | op::RESULT | op::SLEEP => {
                if outcome.is_some() {
                    return Err(Failure::Trapped);
                }
                *outcome = Some(Ended::Paused(self.pause(machine, id)?));
            }
            _ => unreachable!("served operations are known, and the others served apart"),
        }
        Ok(())
    }

    /// A workflow's pause: a sleep until a time, or a request of another
    /// agent or a wait for a workflow's result there, whose message the
    /// step sends, awaited until its deadline. Apart, reading its own
    /// registers, so the operations above keep theirs as they need them.
    #[cold]
    #[inline(never)]
    fn pause(&mut self, machine: &mut Machine, id: u64) -> Result<Pause, Failure> {
        let r: [u64; 13] = core::array::from_fn(|index| machine.register(index));
        if id == op::SLEEP {
            let until = r[7].max(self.base.time.saturating_add(1));
            return Ok(Pause::Sleep { until });
        }
        let awaiting = self.awaits.expect("only a workflow awaits");
        let agent = AgentId(r[7] as u32);
        if agent == self.base.agent {
            return Err(Failure::Trapped);
        }
        let (body, within) = match id {
            op::REQUEST => {
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

    /// A value through the call frames, the refine's earlier steps and
    /// applied state.
    fn read_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        for frame in self.frames.iter().rev() {
            if let Some(value) = frame.get(key) {
                return Ok(value.clone());
            }
        }
        self.base.read(key)
    }

    /// The rows of the table at `prefix`, after `after` when given, merged
    /// through every overlay and packed until `capacity`, each with the
    /// key its `transform` was given; whether the first row alone did not
    /// fit; and the bytes of the keys returned. The sources are walked in
    /// key order and the walk stops
    /// when the buffer is full, so a scan costs the rows it returns, not
    /// the overlays' size.
    fn scan(
        &self,
        prefix: &[u8],
        mut after: Option<Vec<u8>>,
        capacity: usize,
        transform: Transform,
    ) -> Result<(Vec<u8>, bool, usize), Corrupt> {
        use core::ops::Bound;
        let mut out = Vec::new();
        let mut returned = 0;
        loop {
            // A page of applied rows bounds which overlay rows join it; an
            // empty page means no applied rows remain, so all of them do.
            let page = applied_rows(prefix, after.as_deref().unwrap_or(&[]))?;
            let bound = page.last().map(|(key, _)| key.as_slice());
            // A cursor below the prefix starts the scan at the prefix, as
            // the node's applied rows do; one above it leaves no row.
            let lower = match &after {
                Some(after) if after.as_slice() >= prefix => Bound::Excluded(after.as_slice()),
                _ => Bound::Included(prefix),
            };
            let joins =
                |key: &[u8]| key.starts_with(prefix) && bound.is_none_or(|bound| key <= bound);
            // Lowest precedence first: the refine's earlier steps' writes,
            // then each frame up the stack.
            let mut overlays: Vec<_> = core::iter::once(&self.base.earlier)
                .chain(self.frames.iter())
                .map(|overlay| {
                    overlay
                        .range::<[u8], _>((lower, Bound::Unbounded))
                        .take_while(|(key, _)| joins(key))
                        .peekable()
                })
                .collect();
            let mut applied = page.iter().peekable();
            loop {
                let mut next = applied.peek().copied().map(|(key, _)| key.as_slice());
                for overlay in &mut overlays {
                    if let Some(&(key, _)) = overlay.peek()
                        && next.is_none_or(|next| key.as_slice() < next)
                    {
                        next = Some(key.as_slice());
                    }
                }
                let Some(key) = next else {
                    break;
                };
                // The source the key came from holds it without a compare:
                // keys here run to kilobytes.
                let holds = |head: &[u8]| core::ptr::eq(head, key) || head == key;
                // The highest source holding the key decides its value.
                let mut value: Option<Option<&[u8]>> = None;
                for overlay in overlays.iter_mut().rev() {
                    if overlay.peek().is_some_and(|&(head, _)| holds(head)) {
                        let (_, held) = overlay.next().expect("peeked");
                        value.get_or_insert(held.as_deref());
                    }
                }
                if applied.peek().is_some_and(|(head, _)| holds(head)) {
                    let (_, held) = applied.next().expect("peeked");
                    value.get_or_insert(Some(held));
                }
                let Some(Some(value)) = value else { continue };
                let raw = transform.raw(&key[prefix.len()..]).ok_or(Corrupt)?;
                if out.len() + 8 + raw.len() + value.len() > capacity {
                    let full = out.is_empty();
                    return Ok((out, full, returned));
                }
                returned += raw.len();
                (raw.len() as u32).encode_to(&mut out);
                out.extend_from_slice(&raw);
                (value.len() as u32).encode_to(&mut out);
                out.extend_from_slice(value);
            }
            match bound {
                Some(bound) => after = Some(bound.to_vec()),
                None => return Ok((out, false, returned)),
            }
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
            | op::REQUEST
            | op::RESULT
            | op::SLEEP
    )
}

/// `RANDOM`'s bytes: BLAKE2b-256 of `vos/random`, the seed, the step's
/// index and the draws before.
fn random(seed: &[u8; 32], step: u32, draw: u64) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(
        b"vos/random",
        &[seed, &step.to_le_bytes(), &draw.to_le_bytes()],
    )
}

/// Serve a machine's precompile call, accounting for the agent's serving
/// on the meter first.
pub(super) fn serve_precompile(
    meter: &Meter,
    machine: &mut Machine,
    id: u64,
) -> Result<(), Failure> {
    if !meter.take(defaults::PRECOMPILE_SERVING) {
        return Err(Failure::OutOfGas);
    }
    machine.precompile(id)
}

/// Run an attestable program in its own machine: arguments in the standard
/// window, output by the halt convention, and no host calls but
/// precompiles, which the agent serves.
fn attestable(
    meter: &Meter,
    program: &ProgramHash,
    arguments: &[u8],
    gas: u64,
) -> Result<(Vec<u8>, u64), Failure> {
    let mut machine = Machine::acquire(&program.0)?;
    if !machine.map_read_only(ARGUMENTS, arguments.len() as u64, arguments) {
        return Err(Failure::Trapped);
    }
    machine.set_gas(gas);
    machine.set_register(7, ARGUMENTS);
    machine.set_register(8, arguments.len() as u64);
    loop {
        match machine.invoke() {
            Exit::Host(id) if precompile::price(id).is_some() => {
                serve_precompile(meter, &mut machine, id)?;
            }
            Exit::Halt => {
                let used = gas - machine.gas();
                let len = machine.register(8) as usize;
                if len > cap::REPLY {
                    return Err(Failure::Cap);
                }
                let output = machine.peek(machine.register(7), len).ok_or(Failure::Cap)?;
                return Ok((output, used));
            }
            Exit::OutOfGas => return Err(Failure::OutOfGas),
            _ => return Err(Failure::Trapped),
        }
    }
}

/// The agent-relative key of the row an operation names: its rows, by the
/// register `rows`, and the actor's key at `address`.
fn row(
    machine: &mut Machine,
    instance: InstanceId,
    rows: u64,
    address: u64,
    len: u64,
) -> Result<Vec<u8>, Failure> {
    let key = read_key(machine, address, len)?;
    let rows = Rows::from_register(rows).ok_or(Failure::Trapped)?;
    keys::row(instance, rows, &key)
}

/// A row operation's key: its bytes, and the price of transforming them.
fn read_key(machine: &mut Machine, address: u64, len: u64) -> Result<Vec<u8>, Failure> {
    let key = read(machine, address, len, cap::KEY)?;
    if !machine.charge(key.len() as u64 * price::KEY_BYTE) {
        return Err(Failure::OutOfGas);
    }
    Ok(key)
}

/// The actor's bytes, at most `limit`: a longer buffer exceeds a cap and
/// an unreadable one traps.
fn read(machine: &mut Machine, address: u64, len: u64, limit: usize) -> Result<Vec<u8>, Failure> {
    let len = usize::try_from(len).map_err(|_| Failure::Cap)?;
    if len > limit {
        return Err(Failure::Cap);
    }
    if !machine.charge(len as u64 * price::PER_BYTE) {
        return Err(Failure::OutOfGas);
    }
    machine.peek(address, len).ok_or(Failure::Trapped)
}

/// Write `bytes` into the actor's memory through the machine's tracked
/// write, at their price.
fn write(machine: &mut Machine, address: u64, bytes: &[u8]) -> Result<(), Failure> {
    if !machine.charge(bytes.len() as u64 * price::PER_BYTE) {
        return Err(Failure::OutOfGas);
    }
    machine.write(address, bytes)
}

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
