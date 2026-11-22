//! A proven call's step (`identity-and-authority.md` §5's apply rule, at
//! the batch's time): refused, writing nothing, when it expired, when its
//! binding digest is recorded, when its proof's device format is retired,
//! by the release or the agent's log, whatever the node that verified it
//! admits, when the kernel's release it was verified against has left the
//! kernel's window by the batch's time, when a stock auth claim's root is
//! not fresh at [`credentials::judged_at`] (the earlier of the batch's time and the
//! expiry less the horizon, no later than any admitting ingress's clock,
//! so apply refuses no root ingress admitted), or when a `once` guard
//! admitted its nullifier; else its binding digest is recorded, whatever
//! the method then does, and the method runs
//! as the call's origin, a `once` guard's nullifier recorded only when the
//! method returned `Ok`. A kernel guard's handler takes the claim before
//! the call's arguments, and its checks are its own. A ring the meter
//! cannot pay, or that does not read, fails the call before anything is
//! recorded: nothing of it ran, and it may come again.

use alloc::rc::Rc;
use alloc::vec::Vec;

use vos_abi::abi::{Failure, Refusal};
use vos_abi::ids::{InstanceId, MethodId, Principal};
use vos_abi::keys::{self, Due};
use vos_abi::result::{InputRef, Outcome, Step, Write};
use vos_abi::schema::CredentialGuard;
use vos_abi::{Decode, Encode, SpaceId};
use vos_wire::batch::CredentialedInput;
use vos_wire::credentials::{self, AuthClaim, Ring};
use vos_wire::defaults;

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
    // After the binding: a resend of a call that ran before its format
    // was retired is `Replayed`, and its forwarder answers the run.
    if base.holds(&keys::binding(&call.binding)) {
        return refused(Refusal::Replayed);
    }
    match admitted(base, call.format) {
        Ok(true) => {}
        Ok(false) => return refused(Refusal::Format),
        Err(Corrupt) => return Stepped::ran(consumed(input, Outcome::failed(Failure::Trapped))),
    }
    let (guard, kernel) = guard(base, call.instance, call.method);
    match released(base, guard.as_ref(), &call) {
        Ok(true) => {}
        Ok(false) => return refused(Refusal::Release),
        Err(code) => return Stepped::ran(consumed(input, Outcome::failed(code))),
    }
    // A stock auth claim's root, its first digest: ingress checked the
    // claim's shape, and one that is not an auth claim runs nothing.
    if let Some(CredentialGuard::Auth { .. }) = &guard {
        let Some(claim) = AuthClaim::decode_exact(&call.claim) else {
            return Stepped::ran(consumed(input, Outcome::failed(Failure::Forbidden)));
        };
        let at = credentials::judged_at(base.time, call.expires_ms);
        match ring(base) {
            Ok(Some(ring)) if ring.accepts(&claim.map_root, at).is_ok() => {}
            Ok(_) => return refused(Refusal::StaleRoot),
            // A ring the meter cannot pay, or that does not read: the call
            // fails, nothing recorded.
            Err(code) => return Stepped::ran(consumed(input, Outcome::failed(code))),
        }
    }
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
    // An auth origin's scope is its guard's, and a kernel origin's kernel
    // the one its guard names: ingress checked both, and the guard holds
    // to them.
    let scoped = match (&guard, call.origin) {
        (Some(CredentialGuard::Auth { name, .. }), Principal::Anonymous { scope, .. }) => {
            space(base).is_some_and(|space| {
                credentials::scope(&space, base.agent, call.instance, name) == scope
            })
        }
        (Some(CredentialGuard::Kernel { .. }), Principal::Kernel { .. }) => {
            kernel == Some(call.kernel)
        }
        _ => true,
    };
    // A kernel guard's handler takes the claim first, as one
    // length-prefixed part its first argument decodes whole, then the
    // call's arguments; a stock guard's handler, the call's alone.
    let arguments = match &guard {
        Some(CredentialGuard::Kernel { .. }) => {
            let mut arguments = call.claim.encode();
            arguments.extend_from_slice(&call.arguments);
            arguments
        }
        _ => call.arguments,
    };
    let mut run = if scoped {
        let invoked = Call {
            caller: &call.origin,
            instance: call.instance,
            method: call.method,
            arguments: &arguments,
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

/// The guard of `instance`'s `method`, if both exist and it has one, and
/// a kernel guard's kernel, a method of the same instance.
fn guard(
    base: &Base,
    instance: InstanceId,
    method: MethodId,
) -> (Option<CredentialGuard>, Option<MethodId>) {
    let Some(installed) = base.installed(instance).ok().flatten() else {
        return (None, None);
    };
    let guard = installed
        .schema
        .method(method)
        .and_then(|method| method.credential.as_deref().cloned());
    let kernel = match &guard {
        Some(CredentialGuard::Kernel { name }) => core::str::from_utf8(name)
            .ok()
            .and_then(|name| installed.schema.method_id(name)),
        _ => None,
    };
    (guard, kernel)
}

/// Whether the release `call`'s proof was verified against is in its
/// kernel's window at the batch's time: the kernel's actor's
/// ([`CredentialGuard::kernel`]), the credential actor's for a stock
/// guard. A method with no guard names no kernel, and nothing is refused
/// here; one whose kernel's actor is gone admits no release.
fn released(
    base: &Base,
    guard: Option<&CredentialGuard>,
    call: &CredentialedInput,
) -> Result<bool, Failure> {
    let Some(guard) = guard else {
        return Ok(true);
    };
    let actor = match guard.kernel().1 {
        false => call.instance,
        true => {
            let Some(bytes) = base
                .read(&keys::credentials())
                .map_err(|_: Corrupt| Failure::Trapped)?
            else {
                return Ok(false);
            };
            InstanceId::decode_exact(&bytes).ok_or(Failure::Trapped)?
        }
    };
    Ok(base.installed(actor)?.is_some_and(|installed| {
        installed
            .window(call.kernel, base.time)
            .contains(&call.release)
    }))
}

/// Whether device format `format` is admitted at the batch's time: one the
/// release admits, before its release's date and its log's.
fn admitted(base: &Base, format: u32) -> Result<bool, Corrupt> {
    let Some((_, released)) = defaults::DEVICE_FORMATS
        .iter()
        .find(|(number, _)| *number == format)
    else {
        return Ok(false);
    };
    let logged = base.decoded::<u64>(&keys::format_retired(format))?;
    Ok([*released, logged]
        .into_iter()
        .flatten()
        .all(|date| date > base.time))
}

/// The agent's space, when it has one.
fn space(base: &Base) -> Option<SpaceId> {
    let bytes = base.read(&keys::space()).ok().flatten()?;
    SpaceId::decode_exact(&bytes).filter(|space| *space != SpaceId::NONE)
}

/// The credential actor's ring, `None` in an agent with none; its row
/// paid for by its length the first time a refine reads it
/// ([`Base::ring`]). A row that does not read fails the step
/// ([`Failure::Trapped`]), as one the meter cannot pay does
/// ([`Failure::OutOfGas`]).
fn ring(base: &Base) -> Result<Option<Rc<Ring>>, Failure> {
    let corrupt = |_: Corrupt| Failure::Trapped;
    let Some(actor) = base.read(&keys::credentials()).map_err(corrupt)? else {
        return Ok(None);
    };
    let actor = InstanceId::decode_exact(&actor).ok_or(Failure::Trapped)?;
    let key = credentials::ring_key(actor);
    if let Some((cached, ring)) = base.ring.borrow().as_ref()
        && *cached == key
    {
        return Ok(Some(Rc::clone(ring)));
    }
    let Some(bytes) = base.read(&key).map_err(corrupt)? else {
        return Ok(None);
    };
    if !base.meter.take(defaults::RECORD_BYTE * bytes.len() as u64) {
        return Err(Failure::OutOfGas);
    }
    let ring = Rc::new(Ring::decode_exact(&bytes).ok_or(Failure::Trapped)?);
    *base.ring.borrow_mut() = Some((key, Rc::clone(&ring)));
    Ok(Some(ring))
}
