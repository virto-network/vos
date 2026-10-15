//! Operator commands: installs and roles.

use alloc::vec::Vec;

use vos_wire::abi::{Failure, Kind, cap};
use vos_wire::batch::Admin;
use vos_wire::records::{Derivation, Installed};
use vos_wire::result::{InputRef, Outcome, Step, Write};
use vos_wire::schema::Schema;
use vos_wire::{Encode, keys};

use super::inputs::consumed;
use crate::machines::Machine;

/// Where a program's schema starts: the read-only zone.
const SCHEMA_AT: u64 = 1 << 16;

/// An operator command: install a package or set a role. Its writes are
/// under the step write cap like any step's.
pub(crate) fn admin(admin: Admin) -> Step {
    let failed = |code| Step::Ran(consumed(InputRef::Admin, Outcome::failed(code)));
    let (write, reply) = match admin {
        Admin::Install {
            instance,
            derivation,
            roles,
        } => {
            let reply = derivation.encode();
            let Some(installed) = install(derivation, roles) else {
                return failed(Failure::Unknown);
            };
            let write = Write {
                key: keys::installed(instance),
                value: Some(installed.encode()),
            };
            (write, reply)
        }
        Admin::SetRole(grant) => {
            let write = Write {
                key: keys::member(&grant.principal),
                value: grant.role.map(|role| alloc::vec![role]),
            };
            (write, Vec::new())
        }
    };
    if write.key.len() + write.value.as_ref().map_or(0, Vec::len) > cap::STEP_WRITES {
        return failed(Failure::Cap);
    }
    let mut run = consumed(InputRef::Admin, Outcome::Done(reply));
    run.writes.push(write);
    Step::Ran(run)
}

/// Read the actor program's schema from its machine and check the package:
/// each kernel is bound to an attestable method, every attestable method
/// has exactly one, and every role name is mapped.
fn install(derivation: Derivation, roles: Vec<(Vec<u8>, u8)>) -> Option<Installed> {
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
