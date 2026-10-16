//! Operator commands: installs and roles.

use alloc::vec::Vec;

use vos_wire::abi::cap::{Limits, Refused, Target};
use vos_wire::abi::{Failure, Kind, cap};
use vos_wire::batch::Admin;
use vos_wire::records::{Derivation, Installed};
use vos_wire::result::{InputRef, Outcome, Step, Write};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, keys};

use super::base::Base;
use super::inputs::consumed;
use crate::machines::{self, Machine};

/// Where a program's schema starts: the read-only zone.
const SCHEMA_AT: u64 = 1 << 16;

/// An operator command: install a package or set a role. Its writes are
/// under the step write cap like any step's.
pub(crate) fn admin(base: &Base, admin: Admin) -> Step {
    let failed =
        |code, detail| Step::Ran(consumed(InputRef::Admin, Outcome::Failed { code, detail }));
    let (writes, reply) = match admin {
        Admin::Install {
            instance,
            derivation,
            roles,
            target,
        } => {
            let reply = derivation.encode();
            let agent = match base.read(&keys::target()).map(|row| {
                row.map(|bytes| Target::decode(&bytes).map(|(target, _)| target))
                    .transpose()
            }) {
                Ok(Ok(agent)) => agent,
                _ => return failed(Failure::Trapped, Vec::new()),
            };
            let installed = match install(agent, derivation, roles, target) {
                Ok(installed) => installed,
                Err(Err(code)) => return failed(code, Vec::new()),
                Err(Ok(refused)) => return failed(refused.failure(), refused.encode()),
            };
            let mut writes = alloc::vec![Write {
                key: keys::installed(instance),
                value: Some(installed.encode()),
            }];
            if agent.is_none() {
                writes.push(Write {
                    key: keys::target(),
                    value: Some(target.encode()),
                });
            }
            (writes, reply)
        }
        Admin::SetRole(grant) => {
            let write = Write {
                key: keys::member(&grant.principal),
                value: grant.role.map(|role| alloc::vec![role]),
            };
            (alloc::vec![write], Vec::new())
        }
    };
    let written: usize = writes
        .iter()
        .map(|write| write.key.len() + write.value.as_ref().map_or(0, Vec::len))
        .sum();
    if written > cap::STEP_WRITES {
        return failed(Failure::Cap, Vec::new());
    }
    let mut run = consumed(InputRef::Admin, Outcome::Done(reply));
    run.writes.extend(writes);
    Step::Ran(run)
}

/// Check an install for an agent of target `agent`, none before its first
/// install: its target is the agent's, or it fails `Target`; each kernel is
/// bound to an attestable method, every attestable method has exactly one,
/// and every role name is mapped, read from the actor program's schema, or
/// it fails `Unknown`; its statics are within its target's limits
/// ([`within`]), or it fails `Cap`. A refusal against the target is
/// `Ok`, its detail.
fn install(
    agent: Option<Target>,
    derivation: Derivation,
    roles: Vec<(Vec<u8>, u8)>,
    target: Target,
) -> Result<Installed, Result<Refused, Failure>> {
    if let Some(agent) = agent.filter(|&agent| agent != target) {
        return Err(Ok(Refused::Target { agent }));
    }
    let installed = package(derivation, roles, target).ok_or(Err(Failure::Unknown))?;
    match within(&installed, target.limits()) {
        Some(Ok(())) => Ok(installed),
        Some(Err(refused)) => Err(Ok(refused)),
        None => Err(Err(Failure::Cap)),
    }
}
/// The package an install names, read and checked.
fn package(derivation: Derivation, roles: Vec<(Vec<u8>, u8)>, target: Target) -> Option<Installed> {
    // The program an install names, which its operator may never have
    // given the node, is not yet pinned: its absence fails the install.
    let machine = Machine::acquire(&derivation.program.0).ok()?;
    let header = machine.peek(SCHEMA_AT, 8)?;
    let len = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    if len > vos_wire::schema::MAX_LEN {
        return None;
    }
    let section = machine.peek(SCHEMA_AT, 8 + len)?;
    let schema = Schema::read(&section).ok()?;
    let installed = Installed {
        derivation,
        roles,
        schema,
        target,
    };
    for &(method, _) in &installed.derivation.kernels {
        let schema = installed.schema.method(method)?;
        if schema.kind != Kind::Attestable {
            return None;
        }
    }
    let mut attestables = 0;
    for method in &installed.schema.methods {
        if method.kind == Kind::Attestable {
            attestables += 1;
            installed.kernel(method.id)?;
        }
        if let Some(role) = &method.role
            && installed.role(role).is_none()
        {
            return None;
        }
    }
    // Each kernel is bound to such a method, and each such method has one:
    // as many as there are of them, no method has two.
    (installed.derivation.kernels.len() == attestables).then_some(installed)
}

/// Whether an installed package's statics are within `limits`: the
/// kernels it binds, its program's bytes and the pages it may write, its
/// whole heap included, and the gas each attestable method declares for
/// its kernel. `None` when its program has no header to read them from.
fn within(installed: &Installed, limits: &Limits) -> Option<Result<(), Refused>> {
    let kernels = installed.derivation.kernels.len();
    if kernels > limits.kernels {
        return Some(Err(Refused::Kernels {
            kernels: kernels as u64,
            most: limits.kernels as u64,
        }));
    }
    let (header, len) = machines::header_and_len(&installed.program().0)?;
    if len > limits.program {
        return Some(Err(Refused::Program {
            bytes: len as u64,
            most: limits.program as u64,
        }));
    }
    let pages = machines::writable_pages(&header)? + u64::from(installed.derivation.heap);
    if let Some(most) = limits.program_pages
        && pages > most as u64
    {
        return Some(Err(Refused::Pages {
            pages,
            most: most as u64,
        }));
    }
    let Some(most) = limits.kernel_gas() else {
        return Some(Ok(()));
    };
    let declared = installed
        .schema
        .methods
        .iter()
        .filter(|method| method.kind == Kind::Attestable)
        .find_map(|method| Some((method.id, method.gas.filter(|&gas| gas > most)?)));
    Some(match declared {
        Some((method, gas)) => Err(Refused::KernelGas { method, gas, most }),
        None => Ok(()),
    })
}
