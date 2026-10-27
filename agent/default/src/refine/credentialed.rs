//! A credentialed call's step (`identity-and-authority.md` §5's apply
//! rule, at the batch's time): refused, writing nothing, when it expired,
//! when its binding digest is recorded, when an auth root is not fresh, or
//! when a `once` guard admitted its nullifier; else its binding digest is
//! recorded, whatever the method then does, and the method runs as the
//! call's origin, a `once` guard's nullifier recorded only when the method
//! returned `Ok`. A ring the meter cannot pay, or that does not read,
//! fails the call before anything is recorded: nothing of it ran, and it
//! may come again.

use alloc::vec::Vec;

use vos_wire::abi::{Failure, Refusal};
use vos_wire::batch::CredentialedInput;
use vos_wire::credentials::{self, Ring, tables};
use vos_wire::ids::{InstanceId, Principal, derive_id};
use vos_wire::keys::{self, Due, Transform};
use vos_wire::result::{InputRef, Outcome, Step, Write};
use vos_wire::schema::CredentialGuard;
use vos_wire::{Decode, Encode, SpaceId, defaults};

use super::Call;
use super::base::{Base, Corrupt};
use super::batch::Stepped;
use super::inputs::{command, consumed};

pub(crate) fn credentialed(base: &Base, index: u32, call: CredentialedInput) -> Stepped {
    let input = InputRef::Credentialed {
        binding: call.binding,
    };
    let refused = |code| {
        Stepped::new(
            Step::Refused {
                input: input.clone(),
                code,
            },
            None,
        )
    };
    if call.expires_ms < base.time {
        return refused(Refusal::CredentialExpired);
    }
    if base.holds(&keys::binding(&call.binding)) {
        return refused(Refusal::Replayed);
    }
    if let Some(root) = &call.root {
        match ring(base) {
            Ok(Some(ring)) if ring.accepts(root, base.time).is_ok() => {}
            Ok(_) => return refused(Refusal::StaleRoot),
            // A ring the meter cannot pay, or that does not read: the call
            // fails, nothing recorded.
            Err(code) => return Stepped::ran(consumed(input, Outcome::failed(code))),
        }
    }
    let guard = guard(base, call.instance, call.method);
    let once = match (&guard, call.origin) {
        (
            Some(CredentialGuard::Auth { once: true, .. }),
            Principal::Anonymous { scope, nullifier },
        ) => Some(keys::once(&scope, &nullifier)),
        _ => None,
    };
    if once.as_ref().is_some_and(|key| base.holds(key)) {
        return refused(Refusal::Once);
    }
    let recorded = [
        Write {
            key: keys::binding(&call.binding),
            value: Some(call.expires_ms.encode()),
        },
        Write {
            key: keys::due(
                call.expires_ms.saturating_add(defaults::BINDING_KEPT_MS),
                Due::Binding(call.binding),
            ),
            value: Some(Vec::new()),
        },
    ];
    // An auth origin's scope is its guard's: ingress checked it, and the
    // guard holds to it.
    let scoped = match (&guard, call.origin) {
        (Some(CredentialGuard::Auth { name, .. }), Principal::Anonymous { scope, .. }) => {
            space(base).is_some_and(|space| {
                credentials::scope(&space, base.agent, call.instance, name) == scope
            })
        }
        _ => true,
    };
    let mut run = if scoped {
        let invoked = Call {
            caller: &call.origin,
            instance: call.instance,
            method: call.method,
            arguments: &call.arguments,
        };
        command(base, index, input, invoked)
    } else {
        consumed(input, Outcome::failed(Failure::Forbidden))
    };
    run.writes.extend(recorded);
    if let (Some(key), Outcome::Done(_)) = (once, &run.outcome) {
        run.writes.push(Write {
            key,
            value: Some(base.time.encode()),
        });
    }
    Stepped::ran(run)
}

/// The guard of `instance`'s `method`, if both exist and it has one.
fn guard(
    base: &Base,
    instance: InstanceId,
    method: vos_wire::ids::MethodId,
) -> Option<CredentialGuard> {
    let installed = base.installed(instance).ok().flatten()?;
    installed
        .schema
        .method(method)?
        .credential
        .as_deref()
        .cloned()
}

/// The agent's space, when it has one.
fn space(base: &Base) -> Option<SpaceId> {
    let bytes = base.read(&keys::space()).ok().flatten()?;
    SpaceId::decode_exact(&bytes).filter(|space| *space != SpaceId::NONE)
}

/// The credential actor's ring, `None` in an agent with none; its row
/// paid for by its length. A row that does not read fails the step
/// ([`Failure::Trapped`]), as one the meter cannot pay does
/// ([`Failure::OutOfGas`]).
fn ring(base: &Base) -> Result<Option<Ring>, Failure> {
    let corrupt = |_: Corrupt| Failure::Trapped;
    let Some(actor) = base.read(&keys::credentials()).map_err(corrupt)? else {
        return Ok(None);
    };
    let actor = InstanceId::decode_exact(&actor).ok_or(Failure::Trapped)?;
    let rows = vos_wire::abi::Rows::Table {
        tag: derive_id("vos/table/", tables::RING),
        transform: Transform::Hashed,
    };
    let key = keys::row(actor, rows, &tables::RING_KEY.encode())?;
    let Some(bytes) = base.read(&key).map_err(corrupt)? else {
        return Ok(None);
    };
    if !base.meter.take(defaults::RECORD_BYTE * bytes.len() as u64) {
        return Err(Failure::OutOfGas);
    }
    Ring::decode_exact(&bytes).ok_or(Failure::Trapped).map(Some)
}
