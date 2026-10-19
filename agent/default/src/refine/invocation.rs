//! One step's invocation: an actor's handler or a workflow's machine, run
//! against the step's overlays, with its nested calls, and every operation
//! of the actor ABI served.

mod ended;
mod kernel;
mod memory;
mod scan;
mod units;

pub(crate) use ended::{Attesting, Ended, Pause};
pub(crate) use units::Share;

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;

use vos_wire::abi::cap::{self, Limits};
use vos_wire::abi::{self, AttestError, Failure, Kind, Op, Rows, code, precompile, price};
use vos_wire::batch::{Await, Body};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, RequestId, WorkflowId};
use vos_wire::records::{Installed, PendingRead};
use vos_wire::result::{Attest, Attested, InstanceGas, KernelReturn, Outcome, Outgoing};
use vos_wire::served::{ClosedRow, Served};
use vos_wire::{Decode, Encode, SpaceId, WindowClock, defaults, keys};

use super::base::{Base, Corrupt, Meter, role_byte};
use super::{Call, Overlay};
use crate::machines::{self, Exit, Machine};
use kernel::{kernel, parts, random, serve_precompile};
use memory::{copy_out, read, read_key, row, window, write};

/// The most bytes of the rows a read at a cut names, as an
/// [`Op::AttestAt`] passes them: past it, its reads are refused.
const READS: usize = cap::REQUEST;

/// Whether `rows` are a read at a cut of `instance`'s rows: at least one,
/// at most [`defaults::MAX_READS`], strictly increasing, each a committed
/// row of `instance`'s ([`keys::committed_entry`]) no longer than a tree's
/// key.
fn valid_reads(instance: InstanceId, rows: &[Vec<u8>]) -> bool {
    let prefix = keys::instance_committed(instance);
    !rows.is_empty()
        && rows.len() <= defaults::MAX_READS
        && rows.windows(2).all(|pair| pair[0] < pair[1])
        && rows.iter().all(|row| {
            row.starts_with(&prefix)
                && keys::committed_entry(row).is_some()
                && row.len() <= vos_tree::MAX_KEY
        })
}

/// Machines a step may hold at once: a handler and its nested callees, or
/// a workflow's and its callees. A host's own limit is the same on VOS, so
/// either refuses the 64th; an attest at the deepest level needs a 64th,
/// which the host refuses, as `Depth`.
const MAX_DEPTH: usize = 63;

/// One step: its overlays, call stack and effects, within the limits of
/// its agent's target, which the install of the instance it enters names,
/// its nested calls' too.
pub(crate) struct Invocation<'a> {
    base: &'a Base,
    step: u32,
    entry: Kind,
    pub(crate) limits: &'static Limits,
    /// A workflow's step: the workflow, and the counter its next await
    /// takes.
    pub(crate) awaits: Option<Await>,
    /// The pages of the workflow's machine the meter has taken.
    pages_paid: usize,
    /// A workflow's section on its instance's state is open.
    section: bool,
    /// The step overlay, then one per nested call.
    pub(crate) frames: Vec<Overlay>,
    stack: Vec<InstanceId>,
    /// Gas the callees of each invocation on the stack used.
    nested: Vec<u64>,
    pub(crate) instances: Vec<InstanceGas>,
    pub(crate) messages: Vec<Outgoing>,
    pub(crate) attests: Vec<Attest>,
    /// What the step's attests count against its limit: one each, an
    /// attest at a window's cut [`cap::AT_CUT`].
    attests_counted: usize,
    /// The bytes of state the step has written, and the rows, against
    /// its limits.
    write_bytes: usize,
    rows_written: usize,
    draws: u64,
    pub(crate) gas_used: u64,
}

impl<'a> Invocation<'a> {
    pub(crate) fn new(base: &'a Base, step: u32, entry: Kind) -> Self {
        Self {
            base,
            step,
            entry,
            limits: &cap::VOS,
            awaits: None,
            pages_paid: 0,
            section: false,
            frames: alloc::vec![BTreeMap::new()],
            stack: Vec::new(),
            nested: Vec::new(),
            instances: Vec::new(),
            messages: Vec::new(),
            attests: Vec::new(),
            attests_counted: 0,
            write_bytes: 0,
            rows_written: 0,
            draws: 0,
            gas_used: 0,
        }
    }

    pub(crate) fn top(&mut self, call: Call) -> Outcome {
        let Call {
            instance,
            method,
            arguments,
            ..
        } = call;
        if arguments.len() > cap::REQUEST {
            return Outcome::failed(Failure::Cap);
        }
        let installed = match self.installed(instance) {
            Ok(installed) => installed,
            Err(code) => return Outcome::failed(code),
        };
        self.limits = installed.target.limits();
        let Some(schema) = installed.schema.method(method) else {
            return Outcome::failed(Failure::Unknown);
        };
        if !schema.kind.is_handler() || (self.entry == Kind::Query && schema.kind != Kind::Query) {
            return Outcome::failed(Failure::Unknown);
        }
        let gas = schema.gas_limit();
        match self.invoke(call, gas) {
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
    fn invoke(&mut self, call: Call, gas: u64) -> Result<(Ended, u64), (Failure, u64)> {
        let Call {
            caller,
            instance,
            method,
            arguments,
        } = call;
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
        let ended = self.serve(&mut machine, Some(&installed), call, kind);
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
        Ok(role_byte(self.read_state(&keys::member(principal))?))
    }

    /// Serve a handler's machine's exits until it halts or fails. Inlined,
    /// as a call is into it: a nested call holds one frame of the agent's
    /// stack a level, sixty-three levels deep.
    #[inline(always)]
    fn serve(
        &mut self,
        machine: &mut Machine,
        installed: Option<&Installed>,
        call: Call,
        kind: Kind,
    ) -> Result<Ended, Failure> {
        let mut outcome: Option<Ended> = None;
        loop {
            match machine.invoke() {
                Exit::Halt => return Ok(outcome.unwrap_or(Ended::Replied(Vec::new()))),
                Exit::OutOfGas => return Err(Failure::OutOfGas),
                Exit::Panic | Exit::Fault(_) => return Err(Failure::Trapped),
                Exit::Host(id) => {
                    let Some(op) = self.plain(machine, id, call.instance)? else {
                        continue;
                    };
                    if !abi::allowed(kind, op) {
                        return Err(Failure::Trapped);
                    }
                    if !machine.charge(price::of(op)) {
                        return Err(Failure::OutOfGas);
                    }
                    if op == Op::Call {
                        self.call(machine, call.instance, kind)?;
                        continue;
                    }
                    self.operation(machine, installed, op, call, &mut outcome)?;
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
        let r = machine.registers();
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
        let effects = (
            self.messages.len(),
            (self.attests.len(), self.attests_counted),
            self.write_bytes,
            self.rows_written,
        );
        let gas = machine.gas();
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
                self.frames.last_mut().expect("a frame").extend(frame);
                (reply, None)
            }
            Ended::Failed(detail) => (detail, Some(Failure::Handler)),
            Ended::Forbidden => (Vec::new(), Some(Failure::Forbidden)),
            Ended::Paused(_) => unreachable!("only a workflow pauses"),
        };
        if failed.is_some() {
            let (messages, (attests, counted), written, rows) = effects;
            self.messages.truncate(messages);
            self.attests.truncate(attests);
            self.attests_counted = counted;
            self.write_bytes = written;
            self.rows_written = rows;
        }
        copy_out(machine, &bytes, r[11], 0, r[12])?;
        machine.set_register(7, bytes.len() as u64);
        machine.set_register(8, failed.map_or(0, |code| code.code().into()));
        Ok(())
    }

    /// Every other served operation.
    #[inline(always)]
    fn operation(
        &mut self,
        machine: &mut Machine,
        installed: Option<&Installed>,
        op: Op,
        call: Call,
        outcome: &mut Option<Ended>,
    ) -> Result<(), Failure> {
        let Call {
            caller,
            instance,
            arguments,
            ..
        } = call;
        let r = machine.registers();
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
                self.rows_written += 1;
                if self.write_bytes > self.limits.step_writes
                    || self.rows_written > self.limits.step_rows
                {
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
                machine.set_register(7, code::OK);
            }
            Op::Attest => self.attest(machine, installed)?,
            Op::Request | Op::Result | Op::Sleep => {
                if outcome.is_some() {
                    return Err(Failure::Trapped);
                }
                *outcome = Some(Ended::Paused(self.pause(machine, op)?));
            }
            Op::AttestAt => self.ask_at_cut(machine, instance, outcome)?,
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

    /// [`Op::Attest`]: the method's kernel run on the arguments, within the
    /// attest limits of the step's target. Where kernels' compressions are
    /// bounded, a kernel runs within its method's gas and the bound's, on
    /// the attesting instance's target and on the step's. Apart, so a nested
    /// call's frame holds none of it.
    #[inline(never)]
    fn attest(
        &mut self,
        machine: &mut Machine,
        installed: Option<&Installed>,
    ) -> Result<(), Failure> {
        let r = machine.registers();
        let method = MethodId(r[7] as u32);
        let call_arguments = read(machine, r[8], r[9], self.limits.attest)?;
        if self.attests_counted + 1 > self.limits.attests {
            return Err(Failure::Cap);
        }
        let installed = installed.ok_or(Failure::Unknown)?;
        let program = installed.kernel(method).ok_or(Failure::Unknown)?;
        let schema = installed.schema.method(method).ok_or(Failure::Unknown)?;
        // A method that reads at a window's cut runs there alone.
        let stating = match schema.kind {
            Kind::Attestable => false,
            Kind::Stating => true,
            _ => return Err(Failure::Unknown),
        };
        let declared = schema.gas;
        let gas = [self.limits, installed.target.limits()]
            .iter()
            .filter_map(|limits| limits.kernel_limit(declared))
            .fold(machine.gas(), u64::min);
        let run = kernel(
            &self.base.meter,
            &program,
            &call_arguments,
            gas,
            self.limits.attest,
        )
        .map_err(|(code, _)| code)?;
        if !machine.charge(run.gas_used) {
            return Err(Failure::OutOfGas);
        }
        // Its output alone, or its statement's parts, their io-hash the
        // one it left: a kernel's bug fails the step.
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
        machine.set_register(7, parts.output.len() as u64);
        machine.set_register(8, 0);
        self.attests_counted += 1;
        self.attests.push(Attest {
            program,
            window: None,
            witness_input: run.witness_input,
            output: parts.output,
            public_args: parts.public_args,
            roots: parts.roots,
        });
        Ok(())
    }

    /// [`Op::AttestAt`]: a workflow's read of its instance's committed rows
    /// at the cut of the batch time's window, through attestable `&self`
    /// method φ7 on the arguments at φ8/φ9, of the rows at φ10/φ11. Its
    /// request recorded, the workflow pauses; refused at once, φ7 0 and φ8
    /// the [`AttestError`]. Apart, reading its own registers.
    #[cold]
    #[inline(never)]
    fn ask_at_cut(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        outcome: &mut Option<Ended>,
    ) -> Result<(), Failure> {
        if outcome.is_some() {
            return Err(Failure::Trapped);
        }
        match self.asked(machine, instance)? {
            Ok(pause) => *outcome = Some(Ended::Paused(pause)),
            Err(refused) => {
                machine.set_register(7, 0);
                machine.set_register(8, refused.code().into());
            }
        }
        Ok(())
    }

    /// The pause of [`Op::AttestAt`]'s read, its request recorded, or why
    /// it is refused.
    fn asked(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
    ) -> Result<Result<Pause, AttestError>, Failure> {
        let r = machine.registers();
        let method = MethodId(r[7] as u32);
        let awaiting = self.awaits.expect("only a workflow reads at a cut");
        let Some((_, clock)) = self.space()? else {
            return Ok(Err(AttestError::NoSpace));
        };
        let Some(window) = clock.window(self.base.time) else {
            return Ok(Err(AttestError::NoSpace));
        };
        let installed = self.installed(instance)?;
        let reading = installed
            .schema
            .method(method)
            .is_some_and(|schema| schema.kind == Kind::Reading);
        if !reading || installed.kernel(method).is_none() {
            return Ok(Err(AttestError::Unknown));
        }
        if r[9] > self.limits.attest as u64 {
            return Ok(Err(AttestError::Cap));
        }
        let arguments = read(machine, r[8], r[9], self.limits.attest)?;
        if r[11] > READS as u64 {
            return Ok(Err(AttestError::Reads));
        }
        let reads = read(machine, r[10], r[11], READS)?;
        let rows = match <Vec<Vec<u8>>>::decode(&reads) {
            Ok((rows, used)) if used == reads.len() && valid_reads(instance, &rows) => rows,
            _ => return Ok(Err(AttestError::Reads)),
        };
        let request = RequestId {
            workflow: awaiting.workflow,
            awaits: awaiting.counter,
        };
        let key = keys::request(window, request);
        let value = PendingRead { instance, rows }.encode();
        self.write_bytes += key.len() + value.len();
        self.rows_written += 1;
        if self.write_bytes > self.limits.step_writes || self.rows_written > self.limits.step_rows {
            return Err(Failure::Cap);
        }
        self.frames
            .last_mut()
            .expect("a frame")
            .insert(key, Some(value));
        let deadline = clock
            .boundary(window.saturating_add(defaults::READ_WINDOWS))
            .unwrap_or(u64::MAX);
        Ok(Ok(Pause::Attesting(alloc::boxed::Box::new(Attesting {
            counter: awaiting.counter,
            window,
            method,
            arguments,
            deadline,
        }))))
    }

    /// The agent's space and clock, through the refine's earlier steps:
    /// `None` for an agent of no space.
    fn space(&self) -> Result<Option<(SpaceId, WindowClock)>, Failure> {
        let space = self.read_state(&keys::space())?;
        let clock = self.read_state(&keys::clock())?;
        let (Some(space), Some(clock)) = (space, clock) else {
            return Ok(None);
        };
        let space = SpaceId::decode(&space).map_err(|_| Failure::Trapped)?.0;
        let clock = WindowClock::decode(&clock).map_err(|_| Failure::Trapped)?.0;
        Ok((space != SpaceId::NONE).then_some((space, clock)))
    }

    /// A workflow's read at window `window`'s cut, awaited at `counter` by
    /// `id`, its rows `served` (`None`: unserved): attestable `method`'s
    /// kernel run on `arguments` then the served rows, within the step's
    /// `limit`, its statement recorded as the step's attest. The answer the
    /// workflow resumes with, and the gas its machine pays for it: the
    /// attest's price, the kernel's gas and the check of its parts.
    #[inline(never)]
    pub(crate) fn at_cut(
        &mut self,
        instance: InstanceId,
        request: RequestId,
        call: (u64, MethodId, &[u8]),
        served: Option<Vec<u8>>,
        limit: u64,
    ) -> (Attested, u64) {
        let (window, method, arguments) = call;
        let Some(served) = served else {
            return (Attested::Failed(AttestError::Unserved), 0);
        };
        if served.len() > self.limits.served {
            return (Attested::Failed(AttestError::Unserved), 0);
        }
        // The agent's work on the rows, the batch's: out of it, as a
        // kernel out of its precompiles' serving.
        if !self
            .base
            .meter
            .take(defaults::SERVED_BYTE * served.len() as u64)
        {
            return (Attested::Failed(AttestError::Failed), 0);
        }
        let Some(at) = self.serves(instance, window, request, &served) else {
            return (Attested::Failed(AttestError::Unserved), 0);
        };
        let Ok(installed) = self.installed(instance) else {
            return (Attested::Failed(AttestError::Unknown), 0);
        };
        let Some(program) = installed.kernel(method) else {
            return (Attested::Failed(AttestError::Unknown), 0);
        };
        if self.attests_counted + cap::AT_CUT > self.limits.attests {
            return (Attested::Failed(AttestError::Failed), 0);
        }
        let declared = installed
            .schema
            .method(method)
            .and_then(|schema| schema.gas);
        let gas = [self.limits, installed.target.limits()]
            .iter()
            .filter_map(|limits| limits.kernel_limit(declared))
            .fold(limit.saturating_sub(price::ATTEST), u64::min);
        let mut input = Vec::with_capacity(arguments.len() + served.len());
        input.extend_from_slice(arguments);
        input.extend_from_slice(&served);
        let run = match kernel(&self.base.meter, &program, &input, gas, self.limits.attest) {
            Ok(run) => run,
            Err((_, used)) => return (Attested::Failed(AttestError::Failed), price::ATTEST + used),
        };
        let spent = price::ATTEST + run.gas_used + price::io_hash(run.output.len());
        let Some(parts) = parts(&run.output, &run.io_hash) else {
            return (Attested::Failed(AttestError::Failed), spent);
        };
        self.attests_counted += cap::AT_CUT;
        self.attests.push(Attest {
            program,
            window: Some(at),
            witness_input: run.witness_input,
            output: parts.output.clone(),
            public_args: parts.public_args,
            roots: parts.roots,
        });
        (Attested::Done(parts.output), spent)
    }

    /// The window whose cut serves the request asked in window `window` by
    /// `request` when `served` is what it asked for: within the target's
    /// cap, of this agent and its space, of the window it was asked in or
    /// one its re-cuts moved it to ([`keys::moved`]), of the request's
    /// instance and its rows, in order, and with the representative's
    /// root, salt and path the agent holds of that window's close
    /// ([`keys::closed`]).
    fn serves(
        &self,
        instance: InstanceId,
        window: u64,
        request: RequestId,
        bytes: &[u8],
    ) -> Option<u64> {
        if bytes.len() > self.limits.served {
            return None;
        }
        let asked = self.read_state(&keys::request(window, request)).ok()??;
        let (asked, _) = PendingRead::decode(&asked).ok()?;
        let (served, used) = Served::decode(bytes).ok()?;
        let at = served.window;
        let windows = vos_wire::served::serving_windows(window, |window| {
            let moved = self.read_state(&keys::moved(window)).ok()??;
            u64::decode_exact(&moved)
        });
        if !windows.contains(&at) {
            return None;
        }
        let closed = self.read_state(&keys::closed(at)).ok()??;
        let closed = ClosedRow::decode_exact(&closed)?;
        let space = matches!(self.space(), Ok(Some((space, _))) if space == served.space);
        let holds = used == bytes.len()
            && space
            && served.agent == self.base.agent
            && served.instance == instance
            && asked.instance == instance
            && served.rep_root == closed.rep_root
            && served.rep_salt == closed.rep_salt
            && served.space_path == closed.space_path
            && served.rows.len() == asked.rows.len()
            && served
                .rows
                .iter()
                .zip(&asked.rows)
                .all(|((row, _), asked)| row == asked);
        holds.then_some(at)
    }

    /// A workflow's pause: a sleep until a time, or a request of another
    /// agent or a wait for a workflow's result there, whose message the
    /// step sends, awaited until its deadline. Apart, reading its own
    /// registers, so the operations above keep theirs as they need them.
    #[cold]
    #[inline(never)]
    fn pause(&mut self, machine: &mut Machine, op: Op) -> Result<Pause, Failure> {
        let r = machine.registers();
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
                let arguments = read(machine, r[10], r[11], self.limits.message)?;
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
        if self.messages.len() == self.limits.messages {
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
