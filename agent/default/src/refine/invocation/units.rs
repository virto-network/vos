//! A workflow's step, a unit at a time: a unit is the code between two
//! awaits, and runs atomically.
//!
//! **Effect-free code runs on the step's share,** its limit, which the
//! agent sets as the machine's gas at the step's start, and again at each
//! first effect and each await. Out of gas there, at the start of a block,
//! having done nothing of it, the step ends: the earlier units' effects
//! commit with the snapshot, as an await separates them from this unit,
//! which has done nothing, and the workflow is due again at once. So does a
//! first write to a page, or an operation, whose serving the meter cannot
//! pay: an operation charges before it writes anything, so one left unserved
//! has changed nothing.
//!
//! **A unit's first effect** ([`abi::is_effect`]) exits to the agent, which
//! gives the unit the step's whole limit when the refine has it beyond what
//! the step has used. When it has not, the step ends there, the call
//! unserved and kept in the snapshot, and the next step serves it first.
//! From its first effect a unit runs to its next await within that limit,
//! never preempted; past it the step fails.
//!
//! **A call of this agent's is an await:** the unit ends with it, and so
//! does the step once its share is spent.
//!
//! **A section** on the workflow's instance's state is an effect: opened, it
//! runs within the unit's whole limit, never preempted, so it never spans
//! a pause. Inside it only the instance's row operations, the time, logs
//! and its close are served, besides precompiles; anything else fails the
//! step, and so does a machine that halts with a section open.
//!
//! **The floor:** a step ends early only once its machine has moved since
//! it resumed; one that has not fails, out of gas, as no step of its limit
//! could move it, or, stopped by the meter, waits for a batch with room, as
//! an overrun does. Whether it moved is judged from what every host gives
//! alike:
//! - at a call left unserved, by the gas used before it;
//! - at a page left unpaid, by a call served or a page paid since the
//!   resume: a machine resumed at a fault re-enters its block, charged
//!   again, so gas used says nothing there;
//! - out of gas, by a call served or a page paid, or else by its registers
//!   and its counter: the gas after an out-of-gas exit is the host's own,
//!   so the share counts as spent and is never read. A page paid is any
//!   the step's meter took, the machine's first store to it or the agent's
//!   write serving a call: a loop that writes only memory may start each
//!   block with the very registers it resumed with, and it moves all the
//!   same.

use super::*;

/// What a workflow's step may spend, which the agent sets in its machine.
pub(in crate::refine) struct Share {
    /// What the meter keeps below the step: its reserve, the finish, and
    /// what a sweep's due step leaves the batch's inputs.
    floor: u64,
    /// The step's limit: its effect-free code's share in all, and each
    /// effectful unit's own.
    limit: u64,
    /// The gas the machine has been given in the step.
    allotted: u64,
    /// The running unit has made an effect.
    effectful: bool,
    /// The machine has served a call since it resumed.
    served: bool,
}

impl Share {
    pub(in crate::refine) fn new(floor: u64, limit: u64) -> Self {
        Self {
            floor: floor + defaults::FINISH_RESERVE,
            limit,
            allotted: limit,
            effectful: false,
            served: false,
        }
    }

    /// The gas the machine has used in the step.
    fn used(&self, machine: &Machine) -> u64 {
        self.allotted - machine.gas()
    }
}

impl Invocation<'_> {
    /// Run a workflow's machine, of `instance`'s workflow method, through
    /// its step from where its snapshot left it, the call `pending` first:
    /// until it pauses, is preempted, ends or fails. Its own gas goes to its
    /// instance, as a handler's.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::refine) fn workflow(
        &mut self,
        machine: &mut Machine,
        owner: Principal,
        instance: InstanceId,
        input: &[u8],
        share: &mut Share,
        pending: Option<u64>,
    ) -> Result<Ended, Failure> {
        machine.set_gas(share.limit);
        self.instances.push(InstanceGas { instance, gas: 0 });
        self.nested.push(0);
        let ended = self.units(machine, owner, instance, input, share, pending);
        let nested = self.nested.pop().expect("the workflow's entry");
        self.gas_used = share.used(machine);
        self.instances[0].gas += self.gas_used - nested;
        ended
    }

    fn units(
        &mut self,
        machine: &mut Machine,
        owner: Principal,
        instance: InstanceId,
        input: &[u8],
        share: &mut Share,
        pending: Option<u64>,
    ) -> Result<Ended, Failure> {
        let mut outcome: Option<Ended> = None;
        let mut next = pending.map(Exit::Host);
        loop {
            // The pages the agent wrote serving the last call, taken before
            // they are captured.
            self.pay_pages(machine)?;
            if let Some(Ended::Paused(_)) = outcome {
                return Ok(outcome.take().expect("paused"));
            }
            let exit = match next.take() {
                Some(exit) => exit,
                None => {
                    let (meter, paid) = (&self.base.meter, &mut self.pages_paid);
                    machine.invoke_paying(&mut || pay_page(meter, paid))
                }
            };
            match exit {
                Exit::Halt if self.section => return Err(Failure::Trapped),
                Exit::Halt => return Ok(outcome.unwrap_or(Ended::Replied(Vec::new()))),
                Exit::Panic => return Err(Failure::Trapped),
                Exit::OutOfGas => {
                    machine.set_gas(0);
                    let idle = !self.moved(share);
                    return self.preempt_or_fail(share, true, None, idle);
                }
                // A first store the meter could not pay.
                Exit::Fault(address) if machine.unwritten(address) => {
                    return self.preempt_or_fail(share, self.moved(share), None, false);
                }
                Exit::Fault(_) => return Err(Failure::Trapped),
                Exit::Host(id) => {
                    self.unit_call(machine, owner, instance, input, share, id, &mut outcome)?;
                }
            }
        }
    }

    /// Serve the machine's host call `id` in its unit, or end the step at
    /// it unserved, or at the await it is, setting `outcome`.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn unit_call(
        &mut self,
        machine: &mut Machine,
        owner: Principal,
        instance: InstanceId,
        input: &[u8],
        share: &mut Share,
        id: u64,
        outcome: &mut Option<Ended>,
    ) -> Result<(), Failure> {
        if !serves(self.section, id) {
            return Err(Failure::Trapped);
        }
        let used = share.used(machine);
        // Before a unit's first effect, what serving the call takes of the
        // meter is kept first, so a call it cannot pay waits unserved.
        let pages = match share.effectful {
            true => 0,
            false => {
                let first = abi::is_effect(id);
                let (pages, serving) = self.serving(machine, id, input);
                // A first effect: the step's whole limit, beyond what it
                // used.
                let keep = match first {
                    true => share.floor + used + share.limit,
                    false => self.base.meter.kept.get(),
                };
                if self.base.meter.left.get() < keep + pages + serving {
                    self.base.meter.overrun.set(true);
                    *outcome = Some(self.preempt_or_fail(share, used > 0, Some(id), false)?);
                    return Ok(());
                }
                if first {
                    share.allotted = used + share.limit;
                    machine.set_gas(share.limit);
                    share.effectful = true;
                }
                self.base.meter.kept.set(keep + pages);
                pages
            }
        };
        let served = match self.plain(machine, id, instance) {
            Some(served) => served,
            None if !machine.charge(price::of(id)) => Err(Failure::OutOfGas),
            None if id == op::CALL => self.call(machine, instance, Kind::Workflow),
            None => self.operation(machine, None, id, owner, instance, input, outcome),
        };
        // What the call's output was kept for, its pages take next.
        self.base.meter.kept.set(self.base.meter.kept.get() - pages);
        match served {
            Ok(()) => share.served = true,
            // Effect-free, a call the machine's share cannot pay waits
            // unserved, having changed nothing.
            Err(Failure::OutOfGas) if !share.effectful => {
                *outcome = Some(self.preempt_or_fail(share, used > 0, Some(id), false)?);
                return Ok(());
            }
            Err(code) => return Err(code),
        }
        // An await: the unit ends, and the step with it once its share is
        // spent. A workflow that has replied runs on to its end.
        if id == op::CALL && outcome.is_none() {
            share.effectful = false;
            let used = share.used(machine);
            if used >= share.limit {
                *outcome = Some(Ended::Paused(Pause::Preempted {
                    pending: None,
                    idle: false,
                }));
                return Ok(());
            }
            machine.set_gas(share.limit - used);
            share.allotted = share.limit;
            self.base.meter.kept.set(share.floor + share.limit);
        }
        Ok(())
    }

    /// Whether the machine has moved since it resumed, by what it did
    /// rather than where it stands: a call served, or a page paid.
    fn moved(&self, share: &Share) -> bool {
        share.served || self.pages_paid > 0
    }

    /// The step's end between two awaits, before the call `pending` when
    /// given, effect-free and once the machine has `moved` since it
    /// resumed; else it fails, out of gas.
    fn preempt_or_fail(
        &self,
        share: &Share,
        moved: bool,
        pending: Option<u64>,
        idle: bool,
    ) -> Result<Ended, Failure> {
        if share.effectful || !moved {
            return Err(Failure::OutOfGas);
        }
        self.base.meter.overrun.set(false);
        Ok(Ended::Paused(Pause::Preempted { pending, idle }))
    }

    /// What serving the call `id` takes of the meter beside the machine's
    /// price: the pages its output marks written, and a precompile's
    /// serving.
    fn serving(&self, machine: &Machine, id: u64, input: &[u8]) -> (u64, u64) {
        let r = |index| machine.register(index);
        let (address, len, serving) = match id {
            op::INPUT => (r(7), window(input.len(), r(8), r(9)).len(), 0),
            op::RANDOM => (r(7), 32, 0),
            // The callee's reply, at most the cap.
            op::CALL => (r(11), (r(12) as usize).min(cap::REPLY), 0),
            id if precompile::price(id).is_some() => (r(7), 64, defaults::PRECOMPILE_SERVING),
            _ => return (0, 0),
        };
        let pages = machine.unwritten_in(address, len as u64);
        (pages * defaults::WRITTEN_PAGE, serving)
    }

    /// Take the pages the agent has written in the workflow's machine since
    /// the last take from the meter, before they are captured: out of gas,
    /// the budget overrun, when it cannot pay them.
    fn pay_pages(&mut self, machine: &Machine) -> Result<(), Failure> {
        let written = machine.written().map_or(0, |pages| pages.len());
        let new = (written - self.pages_paid) as u64;
        self.pages_paid = written;
        if new > 0 && !self.base.meter.take(new * defaults::WRITTEN_PAGE) {
            return Err(Failure::OutOfGas);
        }
        Ok(())
    }
}

/// Whether a workflow's machine may make host call `id`, with a section
/// open or not ([`abi::workflow_may_use`]). A precompile or an id the agent
/// does not serve is served alike either way.
fn serves(section: bool, id: u64) -> bool {
    !known(id) || abi::workflow_may_use(section, id)
}

/// Pay a page the machine first stores to, before it is opened.
fn pay_page(meter: &Meter, paid: &mut usize) -> bool {
    let taken = meter.take(defaults::WRITTEN_PAGE);
    if taken {
        *paid += 1;
    }
    taken
}
