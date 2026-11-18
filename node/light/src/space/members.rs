//! The memberships a pairing leaves (another device to enroll, this
//! device's own confirmation), a retired device's revocations, and the
//! credential book's records of this device's enrollments.

use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_wire::books::{DeviceHandle, Enrolled as BookEntry, credential_book};
use vos_wire::credentials::CredentialError;

use super::{CREDENTIAL_BOOK, EXPIRY_MS, Enrolled, Error, Host, Personal, Prompts, Proof};
use super::{To, failed, secret, store_failed};
use crate::pairing::Membership as Offered;
use crate::route::Purpose;
use crate::{Call, Light, memberships};

/// What a membership waits for on this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Owed {
    /// Another device of the person to enroll there, by this device's
    /// owner proof: deferrable.
    Enroll,
    /// This device's own confirmation there, once its leaf is in.
    Confirm,
}

/// A membership in a space other than the home: the space, its handle, its
/// credential actor's agent and instance, and what is owed there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Membership {
    pub space: [u8; 32],
    pub handle: [u8; 32],
    pub agent: u32,
    pub instance: u32,
    pub owed: Owed,
}

/// A registrar's outcome, done or its refusal.
fn registrar_done(outcome: &Outcome) -> Result<(), Error> {
    match outcome {
        Outcome::Done(_) => Ok(()),
        Outcome::Failed { detail, .. } => Err(match CredentialError::decode_exact(detail) {
            Some(CredentialError::Enrollments) => Error::Spent,
            error => Error::RegistrarRefused(error),
        }),
        other => Err(failed(format!("the registrar answered {other:?}"))),
    }
}

impl<H: Host> Personal<H> {
    /// Record in the credential book each enrollment's space and this
    /// device's handle there, unless it is: what a pairing offers, and a
    /// retirement revokes. Again at each pass, so a space enrolled in
    /// later, or a record a process did not live to make, is recorded.
    pub(super) fn book(&self, light: &Light, device: u32) {
        let Ok(all) = self.host.enrollments() else {
            return;
        };
        let recorded = memberships::handles_of(light, CREDENTIAL_BOOK, device).unwrap_or_default();
        for enrollment in all {
            if recorded.iter().any(|(membership, handle)| {
                membership.space == enrollment.space
                    && handle.handle == enrollment.handle
                    && handle.member == enrollment.member
            }) {
                continue;
            }
            let entry = BookEntry {
                name: hex_prefix(&enrollment.handle),
                credentials: vos_wire::books::Location {
                    agent: enrollment.credentials.0,
                    instance: enrollment.credentials.1,
                },
                agents: enrollment
                    .agents
                    .iter()
                    .map(|(agent, identity)| vos_wire::books::Agent {
                        agent: *agent,
                        identity: *identity,
                    })
                    .collect(),
            };
            let join = light.call(
                CREDENTIAL_BOOK,
                credential_book::JOIN,
                (enrollment.space, entry).encode(),
            );
            if join.is_ok() {
                let _ = memberships::record(
                    light,
                    CREDENTIAL_BOOK,
                    enrollment.space,
                    device,
                    DeviceHandle {
                        handle: enrollment.handle,
                        member: enrollment.member,
                        owner: enrollment.owner,
                    },
                );
            }
        }
    }

    /// The memberships owed on this device: enrollments of a device it
    /// paired, and its own confirmations.
    pub fn memberships(&self) -> Result<Vec<Membership>, Error> {
        let held = self.held();
        let store = held.light.store();
        let of = |membership: &Offered, owed| Membership {
            space: membership.space,
            handle: membership.handle,
            agent: membership.agent,
            instance: membership.credentials.0,
            owed,
        };
        let mut all: Vec<Membership> = memberships::enrollments(store)
            .map_err(store_failed)?
            .iter()
            .map(|enrollment| of(&enrollment.membership, Owed::Enroll))
            .collect();
        all.extend(
            memberships::confirmations(store)
                .map_err(store_failed)?
                .iter()
                .map(|membership| of(membership, Owed::Confirm)),
        );
        Ok(all)
    }

    /// This device's enrollment at `handle`, which an owner proof there
    /// takes: its secret's source and its routes.
    fn enrolled_at(&self, handle: &[u8; 32]) -> Result<Enrolled, Error> {
        self.host
            .enrollments()
            .map_err(store_failed)?
            .into_iter()
            .find(|enrollment| enrollment.handle == *handle)
            .ok_or(Error::NotEnrolled)
    }

    /// `call` proved under this device's owner secret in the space of
    /// `enrollment`, at its source's prompt, sent as a proven call: the
    /// registrar's outcome.
    fn prove_owner(
        &self,
        prompts: &dyn Prompts,
        enrollment: &Enrolled,
        call: impl FnOnce(u64) -> Result<Call, crate::DeviceError>,
    ) -> Result<Outcome, Error> {
        let now = self.time(To::Space(enrollment.handle), Purpose::Fetch)?;
        let call = call(now + EXPIRY_MS).map_err(failed)?;
        let secret = secret(prompts, &enrollment.source, &enrollment.handle)?;
        let request = self.host.prove(Proof::Owner { secret, call })?;
        self.proven(To::Space(enrollment.handle), &request)
    }

    /// The device a pairing added enrolled in `membership`'s space, by
    /// this device's owner proof there.
    pub fn enroll_device(
        &self,
        prompts: &dyn Prompts,
        membership: Membership,
    ) -> Result<(), Error> {
        let held = self.held();
        let owed = memberships::enrollments(held.light.store()).map_err(store_failed)?;
        let enrollment = owed
            .into_iter()
            .find(|owed| {
                owed.membership.space == membership.space
                    && owed.membership.handle == membership.handle
            })
            .ok_or(Error::NothingOwed)?;
        let mine = self.enrolled_at(&membership.handle)?;
        let outcome = self.prove_owner(prompts, &mine, |expires| enrollment.call(expires))?;
        registrar_done(&outcome)?;
        memberships::done(held.light.store(), &enrollment.membership).map_err(store_failed)
    }

    /// This device's own confirmation in `membership`'s space, once its
    /// leaf is there.
    pub fn confirm_device(
        &self,
        prompts: &dyn Prompts,
        membership: Membership,
    ) -> Result<(), Error> {
        let held = self.held();
        let owed = memberships::confirmations(held.light.store()).map_err(store_failed)?;
        let confirmation = owed
            .into_iter()
            .find(|owed| owed.space == membership.space && owed.handle == membership.handle)
            .ok_or(Error::NothingOwed)?;
        let mine = self.enrolled_at(&membership.handle)?;
        let outcome = self.prove_owner(prompts, &mine, |expires| {
            memberships::confirm_call(&confirmation, &mine.member, expires)
        })?;
        registrar_done(&outcome)?;
        memberships::confirmed(held.light.store(), &confirmation).map_err(store_failed)
    }

    /// An enrollment owed, given up.
    pub fn drop_enrollment(&self, membership: Membership) -> Result<(), Error> {
        let held = self.held();
        let owed = memberships::enrollments(held.light.store()).map_err(store_failed)?;
        let Some(enrollment) = owed.into_iter().find(|owed| {
            owed.membership.space == membership.space && owed.membership.handle == membership.handle
        }) else {
            return Ok(());
        };
        memberships::done(held.light.store(), &enrollment.membership).map_err(store_failed)
    }

    /// A removed device's leaf revoked in each space its handles name, by
    /// this device's owner proof there (a phone retired): how many.
    pub fn revoke(&self, prompts: &dyn Prompts, device: u32) -> Result<u32, Error> {
        let held = self.held();
        let handles = memberships::handles_of(&held.light, CREDENTIAL_BOOK, device)
            .map_err(|error| failed(format!("{error:?}")))?;
        drop(held);
        let mut revoked = 0;
        for (membership, handle) in handles {
            let mine = self.enrolled_at(&membership.handle)?;
            let outcome = self.prove_owner(prompts, &mine, |expires| {
                memberships::revoke_call(&membership, &handle.member, expires)
            })?;
            registrar_done(&outcome)?;
            revoked += 1;
        }
        Ok(revoked)
    }
}

/// A space's name in the credential book: its handle's first 8 bytes in
/// hex.
fn hex_prefix(handle: &[u8; 32]) -> String {
    handle[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
