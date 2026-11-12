//! A device's memberships in the spaces other than the home
//! (`light-node.md` §3.8): each device of the user holds a secret of its
//! own in each space, so a new device is enrolled by another of the
//! person's devices, and a retired one revoked.
//!
//! - **Enrolled at the pairing** ([`plan`], [`Enrollment`]): the opener
//!   offers its memberships over the pairing channel, the joiner answers
//!   its handle in each (its member and owner digests there), and the
//!   opener calls each registrar's `enroll_device(member, owner)` under its
//!   own owner proof, one prompt a space. The enrollments are held in the
//!   store ([`hold`]) once the agent took the commit adding the joiner,
//!   never for a pairing cut short, each until it is made or dropped, so
//!   the chrome may defer any space to a later prompt.
//! - **Confirmed by the joiner** ([`expect`]): once its
//!   leaf is in a space's tree, the joiner calls `confirm_device(member)`
//!   under its own owner proof there, naming its own member digest, so its
//!   owner digest acts for the person.
//! - **The credential book:** each device's handle in each space, as the
//!   registrar's person record holds it ([`handles_of`] reads what the
//!   opener offers and what a retired device's revocations name,
//!   [`record`] writes the new device's once its add is confirmed; a
//!   device that finds a device of the set with no handle in a space it
//!   enrolled records it again).
//! - **Revoked at retirement** ([`revoke_call`]): `revoke_device(member)`
//!   under another device's owner proof, each space at once.
//!
//! The registrar records a person's first device itself (`register`), as
//! it enrolls the member; from then on the person's devices enroll and
//! revoke one another.

use vos_wire::books::{DeviceHandle, Enrolled, Space};
use vos_wire::ids::{InstanceId, MethodId, Principal};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::pairing::{Hello, Membership};
use crate::store::{Store, StoreError};
use crate::{Call, DeviceError, Error, Light, call};

/// The rows of the enrollments held and the confirmations owed, by space.
const ENROLL: &[u8] = b"m/enroll/";
const CONFIRM: &[u8] = b"m/confirm/";

/// A membership's row: by its space and its handle, since one space may
/// hold several credential actors.
fn key(prefix: &[u8], space: &Space, handle: &[u8; 32]) -> Vec<u8> {
    [prefix, &space[..], &handle[..]].concat()
}

impl Membership {
    fn call(&self, method: &str, arguments: Vec<u8>, expires_ms: u64) -> Result<Call, DeviceError> {
        Call::new(
            self.space,
            self.agent,
            self.credentials.0,
            call::method_id(method),
            arguments,
            expires_ms,
        )
    }
}

/// An enrollment of another device of the person in a space: the space,
/// and the device's handle there.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Enrollment {
    pub membership: Membership,
    pub device: DeviceHandle,
}

impl Enrollment {
    /// The registrar's `enroll_device(member, owner)`, to prove under this
    /// device's owner secret in the space ([`crate::Prover::prove_owner`]).
    pub fn call(&self, expires_ms: u64) -> Result<Call, DeviceError> {
        let arguments = (self.device.member, self.device.owner).encode();
        self.membership.call("enroll_device", arguments, expires_ms)
    }
}

/// The enrollments of the joiner whose hello is `hello`, in each of the
/// `offered` memberships it answered a handle for; held only once the
/// agent took the commit adding it ([`hold`]).
pub fn plan(offered: &[Membership], hello: &Hello) -> Vec<Enrollment> {
    offered
        .iter()
        .filter_map(|membership| {
            let (_, device) = hello.handles.iter().find(|(space, handle)| {
                *space == membership.space && handle.handle == membership.handle
            })?;
            Some(Enrollment {
                membership: membership.clone(),
                device: *device,
            })
        })
        .collect()
}

/// Hold `enrollments` in `store` once the agent took the commit adding
/// their device, each until [`done`] drops it.
pub fn hold(store: &Store, enrollments: &[Enrollment]) -> Result<(), StoreError> {
    store.write_group_rows(
        enrollments
            .iter()
            .map(|enrollment| {
                let membership = &enrollment.membership;
                let key = key(ENROLL, &membership.space, &membership.handle);
                (key, Some(enrollment.encode()))
            })
            .collect(),
    )
}

/// The enrollments held: made later on their prompts, or dropped.
pub fn enrollments(store: &Store) -> Result<Vec<Enrollment>, StoreError> {
    rows(store, ENROLL)
}

/// The enrollment in `membership` made (its slot answered, or the
/// registrar refused it for good): no longer held.
pub fn done(store: &Store, membership: &Membership) -> Result<(), StoreError> {
    let key = key(ENROLL, &membership.space, &membership.handle);
    store.write_group_rows(vec![(key, None)])
}

/// The confirmations of the joiner offered `memberships`, held in `store`
/// until [`confirmed`].
pub fn expect(store: &Store, memberships: &[Membership]) -> Result<(), StoreError> {
    store.write_group_rows(
        memberships
            .iter()
            .map(|membership| {
                let key = key(CONFIRM, &membership.space, &membership.handle);
                (key, Some(membership.encode()))
            })
            .collect(),
    )
}

/// The confirmations owed.
pub fn confirmations(store: &Store) -> Result<Vec<Membership>, StoreError> {
    rows(store, CONFIRM)
}

/// The registrar's `confirm_device(member)` in `membership`'s space,
/// `member` this device's member digest there, to prove under its owner
/// secret there once its leaf is in the tree (its `path` answered).
pub fn confirm_call(
    membership: &Membership,
    member: &[u8; 32],
    expires_ms: u64,
) -> Result<Call, DeviceError> {
    membership.call("confirm_device", member.encode(), expires_ms)
}

/// The confirmation in `membership` made: no longer owed.
pub fn confirmed(store: &Store, membership: &Membership) -> Result<(), StoreError> {
    let key = key(CONFIRM, &membership.space, &membership.handle);
    store.write_group_rows(vec![(key, None)])
}

/// The registrar's `revoke_device(member)` in `membership`'s space, a
/// retired or lost device's leaf, to prove under this device's owner
/// secret there.
pub fn revoke_call(
    membership: &Membership,
    member: &[u8; 32],
    expires_ms: u64,
) -> Result<Call, DeviceError> {
    membership.call("revoke_device", member.encode(), expires_ms)
}

fn rows<T: Decode>(store: &Store, prefix: &[u8]) -> Result<Vec<T>, StoreError> {
    store
        .group_rows(prefix, None)?
        .into_iter()
        .map(|(_, value)| T::decode_exact(&value).ok_or(StoreError::Layout(None)))
        .collect()
}

/// Why the credential book did not answer.
#[derive(Debug)]
pub enum ReadError {
    Light(Error),
    /// Its query's outcome, not done (the book not installed), or a reply
    /// that does not decode.
    Answer(Outcome),
}

impl From<Error> for ReadError {
    fn from(error: Error) -> Self {
        ReadError::Light(error)
    }
}

/// `method` of the credential book at `book` as `light` answers it.
fn read<T: Decode>(
    light: &Light,
    book: InstanceId,
    method: &str,
    arguments: Vec<u8>,
) -> Result<T, ReadError> {
    let outcome = light.query(
        Principal::Client(light.sync_key().verifying_key().to_bytes()),
        book,
        MethodId(call::method_id(method)),
        arguments,
    )?;
    match &outcome {
        Outcome::Done(bytes) => T::decode_exact(bytes).ok_or(ReadError::Answer(outcome)),
        _ => Err(ReadError::Answer(outcome)),
    }
}

/// The membership of `space` as the credential book holds it, for the
/// device whose handle there is `handle`: its credential actor's agent
/// must be among its agents, whose identity it is signed for.
fn membership_of(space: Space, enrolled: &Enrolled, handle: [u8; 32]) -> Option<Membership> {
    let agent = enrolled
        .agents
        .iter()
        .find(|agent| agent.agent == enrolled.credentials.agent)?;
    Some(Membership {
        space,
        handle,
        agent: agent.agent,
        identity: agent.identity,
        credentials: InstanceId(enrolled.credentials.instance),
    })
}

/// The memberships the device `device` holds handles in, as the
/// credential book at `book` records them, with its handle in each: what
/// an opener offers (its own), and what a retired device's revocations
/// name.
pub fn handles_of(
    light: &Light,
    book: InstanceId,
    device: u32,
) -> Result<Vec<(Membership, DeviceHandle)>, ReadError> {
    let spaces: Vec<(Space, Enrolled)> = read(light, book, "spaces", Vec::new())?;
    let mut held = Vec::new();
    for (space, enrolled) in spaces {
        let handles: Vec<(u32, DeviceHandle)> = read(light, book, "handles", space.encode())?;
        if let Some((_, handle)) = handles.into_iter().find(|(id, _)| *id == device)
            && let Some(membership) = membership_of(space, &enrolled, handle.handle)
        {
            held.push((membership, handle));
        }
    }
    Ok(held)
}

/// Record in the credential book at `book` the handle of the device
/// `device` in `space`, as its enrollment made it: synced to every device,
/// which names it to revoke it.
pub fn record(
    light: &Light,
    book: InstanceId,
    space: Space,
    device: u32,
    handle: DeviceHandle,
) -> Result<Outcome, Error> {
    light.call(
        book,
        MethodId(call::method_id("handle")),
        (space, device, handle).encode(),
    )
}
