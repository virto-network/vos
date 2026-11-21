//! The device set: its operations under the admin key (remove, veto,
//! cosign, resolve, a kit's rotation, a regroup), an admin key replaced by
//! the kit or by another device, and a commit now.

use ed25519_dalek::Signer as _;
use vos_abi::Encode;
use vos_abi::ids::MethodId;
use vos_wire::personal::{
    AdminClass, Attached, Attestation, Candidacy, DeviceView, NewAdmin, Overview, PersonalError,
    Place, Recorded, Standing, Status, method,
};

use super::link::{AgentLink, Called, Hold, Key, Signer, answer};
use super::{
    AdminKey, Approval, Error, Held, Host, Personal, Posted, Prompts, admin_sign, answered,
    entered_kit, failed, logged, new_kit, unreached,
};
use crate::group::{Event, Prepared};
use crate::route::Purpose;

/// The most signatures one admin call takes, each signed at the log's head
/// read anew after the one before was refused for a head the log moved
/// past or for `Settling`: for the admin key, a prompt each.
pub(super) const PLACINGS: usize = 3;

/// The follows a leave makes after the one its call makes, until one
/// reads it through.
const LEAVE_FOLLOWS: usize = 2;

/// A device's new admin key, offered to another device of the set to sign
/// its replacement: `device` (u32 big-endian) ‖ `key` ‖ a flags byte (1
/// hardware, 2 verified boot) ‖ the offering device's sync key's signature
/// over them ([`AdminOffer::message`]), as a screen shows it. The device
/// that takes it checks the signature against the sync key the set knows
/// for `device` before it asks its user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminOffer {
    pub device: u32,
    pub key: [u8; 32],
    pub hardware: bool,
    pub verified_boot: bool,
    pub signature: [u8; 64],
}

impl AdminOffer {
    pub const LEN: usize = 4 + 32 + 1 + 64;
    /// The signed message's domain.
    const DOMAIN: &[u8] = b"vos/personal/admin-offer";

    fn flags(&self) -> u8 {
        u8::from(self.hardware) | u8::from(self.verified_boot) << 1
    }

    /// What the offering device's sync key signs: the domain, the personal
    /// agent's identity, the device's admin key it replaces, then the
    /// device, its new key and the flags.
    pub fn message(&self, identity: &[u8; 32], admin: &[u8; 32]) -> Vec<u8> {
        [
            Self::DOMAIN,
            identity,
            admin,
            &self.device.to_be_bytes(),
            &self.key,
            &[self.flags()],
        ]
        .concat()
    }

    /// Whether `sync`, the set's sync key of the offering device, signed
    /// it for the agent `identity` while the device's admin key was
    /// `admin`.
    pub fn verifies(&self, identity: &[u8; 32], admin: &[u8; 32], sync: &[u8; 32]) -> bool {
        ed25519_dalek::VerifyingKey::from_bytes(sync).is_ok_and(|key| {
            key.verify_strict(
                &self.message(identity, admin),
                &ed25519_dalek::Signature::from_bytes(&self.signature),
            )
            .is_ok()
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.device.to_be_bytes().to_vec();
        bytes.extend_from_slice(&self.key);
        bytes.push(self.flags());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; Self::LEN] = bytes.try_into().ok()?;
        let flags = bytes[36];
        (flags < 4).then(|| Self {
            device: u32::from_be_bytes(bytes[..4].try_into().unwrap_or_default()),
            key: bytes[4..36].try_into().unwrap_or_default(),
            hardware: flags & 1 != 0,
            verified_boot: flags & 2 != 0,
            signature: bytes[37..].try_into().unwrap_or([0; 64]),
        })
    }

    /// The key check both devices show: its key's first 8 bytes in hex.
    pub fn check(&self) -> String {
        self.key[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// A device of the set, as a screen lists it: its id and label, whether its
/// admin is strong, its standing, its last call the agent took (0 before
/// any), whether a removal of it matured, and whether it is this device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub id: u32,
    pub label: String,
    pub strong: bool,
    pub standing: Standing,
    pub seen: u64,
    pub removed: bool,
    pub me: bool,
}

impl<H: Host> Personal<H> {
    /// The device set as the agent holds it, at its batch time now: a home
    /// whose batch time is older than [`crate::job::STALE_MS`] is woken
    /// first, as a pass wakes it, since its reads are at its last batch's
    /// time.
    pub fn devices(&self) -> Result<Vec<Device>, Error> {
        let mut held = self.held();
        let me = held.group.as_ref().and_then(crate::group::DeviceGroup::id);
        // This device's removal is its own log's word, not the answer's.
        let out = held
            .group
            .as_ref()
            .is_some_and(|group| group.course() == crate::group::Course::Out);
        let now = self.host.now();
        let overview: Overview = self.with_link(&mut held, Purpose::Personal, |link, _| {
            answered(link.query(method::OVERVIEW, ()))
        })?;
        if overview.at.saturating_add(crate::job::STALE_MS) < now {
            self.wake(&mut held)?;
        }
        let views = self.views(&mut held)?;
        self.adopt_admin(&mut held, &views)?;
        Ok(views
            .into_iter()
            .map(|view| Device {
                id: view.id,
                label: String::from_utf8_lossy(&view.device.keys.label).into_owned(),
                strong: view.device.keys.class == AdminClass::Strong,
                standing: view.standing,
                seen: view.seen,
                removed: if Some(view.id) == me {
                    out
                } else {
                    view.removal.is_some() || view.standing == Standing::Removed
                },
                me: Some(view.id) == me,
            })
            .collect())
    }

    /// The device set as the agent shows it.
    fn views(&self, held: &mut Held) -> Result<Vec<DeviceView>, Error> {
        self.with_link(held, Purpose::Personal, |link, _| {
            answered(link.query(method::DEVICES, ()))
        })
    }

    /// A replaced admin key is this device's once the set `views` shows
    /// it.
    fn adopt_admin(&self, held: &mut Held, views: &[DeviceView]) -> Result<(), Error> {
        let me = held.group.as_ref().and_then(crate::group::DeviceGroup::id);
        if let Some(view) = views.iter().find(|view| Some(view.id) == me)
            && held
                .state
                .admin
                .is_some_and(|admin| admin.key != view.device.keys.admin)
            && let Some(next) = held.state.next_admin(&view.device.keys.admin)
        {
            held.state.admin = Some(next);
            held.state.next_admin.clear();
            held.admin = Signer::new(next.key);
            self.keep(&held.light, &held.state)?;
        }
        Ok(())
    }

    /// What fell due settled at the agent, under the sync key.
    fn wake(&self, held: &mut Held) -> Result<(), Error> {
        self.with_link(held, Purpose::Personal, |link, _| {
            answered(link.settle())?;
            Ok(())
        })
    }

    /// While a new admin key is offered, what fell due settled and the key
    /// taken if the set shows it: the step before an admin call is
    /// prepared, since the call itself settles a replacement that matured
    /// and would then refuse the key it was signed by.
    pub(super) fn settle(&self, held: &mut Held) -> Result<(), Error> {
        if held.state.next_admin.is_empty() {
            return Ok(());
        }
        self.wake(held)?;
        let views = self.views(held)?;
        self.adopt_admin(held, &views)
    }

    /// The device set's operations open, as a pass raises them.
    pub fn operations(&self) -> Result<Vec<crate::job::Notice>, Error> {
        let held = self.held();
        let group = held.group.as_ref().ok_or(Error::NoSpace)?;
        let pass = crate::job::Pass {
            operations: group.operations(),
            ..Default::default()
        };
        Ok(pass.notices())
    }

    /// A device of the set removed, by the admin key (a phone retired, or
    /// lost): it matures after the policy's delay unless vetoed, and the
    /// next commit carries it.
    pub fn remove(&self, prompts: &dyn Prompts, device: u32) -> Result<Posted, Error> {
        self.operate(
            &mut self.held(),
            prompts,
            method::REMOVE,
            device.encode(),
            None,
        )
    }

    /// This device leaves the personal space: its own removal, signed by
    /// its admin key (on its probation too), which the agent matures once
    /// its evidence is posted; the log then read through to `Out`, as a
    /// removed device reads its removal, and the space forgotten at once
    /// by the follow that read it (`Personal::forget`): the group's MLS
    /// state, the key archive and `R`'s share, the kit's state, the home,
    /// the agent, the admin key's public half, every flow's state and the
    /// local actors' rows go with the store; the secret source's key and
    /// the label stay, as at a fresh install. The other devices commit the
    /// removal, as any matured one. The leave posted but not read through,
    /// the space stays held and the flow answers `Unreachable`: the next
    /// pass posts what is held, reads the leave through and forgets. Out
    /// already, by a leave read through with the forgetting cut short, it
    /// forgets at once.
    pub fn leave(&self, prompts: &dyn Prompts) -> Result<(), Error> {
        let mut held = self.held();
        let out = |held: &Held| {
            held.group
                .as_ref()
                .is_some_and(|group| group.course() == crate::group::Course::Out)
        };
        if out(&held) {
            return self.forget(&mut held);
        }
        let me = held
            .group
            .as_ref()
            .and_then(crate::group::DeviceGroup::id)
            .ok_or(Error::NoSpace)?;
        self.operate(&mut held, prompts, method::REMOVE, me.encode(), None)?;
        prompts.stage(super::Stage::Leaving);
        for _ in 0..LEAVE_FOLLOWS {
            if held.group.is_none() {
                return Ok(());
            }
            self.follow(&mut held)?;
        }
        if held.group.is_some() {
            return Err(Error::Unreachable(
                "the leave is posted, not yet read through: it finishes once this phone \
                 reaches your agent again"
                    .into(),
            ));
        }
        Ok(())
    }

    /// An operation open vetoed, by the admin key.
    pub fn veto(&self, prompts: &dyn Prompts, index: u64) -> Result<Posted, Error> {
        self.operate(
            &mut self.held(),
            prompts,
            method::VETO,
            index.encode(),
            None,
        )
    }

    /// An operation open cosigned, which makes it immediate.
    pub fn cosign(&self, prompts: &dyn Prompts, index: u64) -> Result<Posted, Error> {
        self.operate(
            &mut self.held(),
            prompts,
            method::COSIGN,
            index.encode(),
            None,
        )
    }

    /// A contested operation upheld or dropped.
    pub fn resolve(
        &self,
        prompts: &dyn Prompts,
        index: u64,
        upheld: bool,
    ) -> Result<Posted, Error> {
        self.operate(
            &mut self.held(),
            prompts,
            method::RESOLVE,
            (index, upheld).encode(),
            None,
        )
    }

    /// A new kit of `kind`, `R` split anew for it, the old kit admitted no
    /// more once it matures.
    pub fn rotate_kit(
        &self,
        prompts: &dyn Prompts,
        kind: vos_wire::personal::KitKind,
    ) -> Result<Posted, Error> {
        let mut held = self.held();
        let kept = held.state.home.clone().ok_or(Error::NoSpace)?;
        let kit = new_kit(prompts, kind, &kept, None)?;
        let group = held.group.as_mut().ok_or(Error::NoSpace)?;
        let split = group.rotate(&[kit.key()]).map_err(failed)?;
        self.operate(
            &mut held,
            prompts,
            method::ROTATE,
            split.kit.encode(),
            Some(*split.r2()),
        )
    }

    /// A new admin key for this device, made in the UI's keystore, its
    /// replacement signed by the kit entered (a device signs no replacement
    /// of its own key): it matures after the kit's delay; the set showing
    /// it, the key is this device's ([`Personal::devices`]).
    pub fn replace_admin(
        &self,
        prompts: &dyn Prompts,
        kind: vos_wire::personal::KitKind,
    ) -> Result<Posted, Error> {
        let mut held = self.held();
        let me = held
            .group
            .as_ref()
            .and_then(crate::group::DeviceGroup::id)
            .ok_or(Error::NoSpace)?;
        let kit = entered_kit(prompts, kind)?;
        let next = prompts.create_admin()?;
        let admin = new_admin(next);
        held.state.set_next_admin(next);
        self.keep(&held.light, &held.state)?;
        let kept = held.state.home.clone().ok_or(Error::NoSpace)?;
        let agent = held.state.agent.ok_or(Error::NoSpace)?;
        drop(held);
        // The kit's call, kept as signed until its evidence is posted.
        let posted = self.kit_call(
            &kit,
            kept,
            Some(agent),
            method::REPLACE,
            (me, admin).encode(),
        )?;
        self.posted(
            &mut self.held(),
            Recorded {
                at: posted.at,
                index: posted.index,
            },
        )
    }

    /// A new admin key for this device, made in the UI's keystore, offered
    /// to another seasoned device of the set to sign its replacement: the
    /// code that device takes ([`Personal::replace_admin_of`]). The set
    /// showing it, the key is this device's ([`Personal::devices`]).
    pub fn admin_offer(&self, prompts: &dyn Prompts) -> Result<Vec<u8>, Error> {
        let mut held = self.held();
        // Signed over the admin key the set shows for this device.
        self.settle(&mut held)?;
        let me = held
            .group
            .as_ref()
            .and_then(crate::group::DeviceGroup::id)
            .ok_or(Error::NoSpace)?;
        let next = prompts.create_admin()?;
        let (_, identity) = held.state.agent.ok_or(Error::NoSpace)?;
        let admin = held.state.admin.ok_or(Error::NoSpace)?.key;
        held.state.set_next_admin(next);
        self.keep(&held.light, &held.state)?;
        let mut offer = AdminOffer {
            device: me,
            key: next.key,
            hardware: next.hardware,
            verified_boot: next.verified_boot,
            signature: [0; 64],
        };
        offer.signature = held
            .light
            .sync_key()
            .sign(&offer.message(&identity, &admin))
            .to_bytes();
        Ok(offer.to_bytes())
    }

    /// Another device's admin key replaced by the one its code offers,
    /// signed by this device's admin key once the user approves it (the
    /// code's key check beside the other device's): the agent takes it from
    /// a seasoned device other than the one replaced, the new key on its
    /// probation.
    pub fn replace_admin_of(&self, prompts: &dyn Prompts, code: &[u8]) -> Result<Posted, Error> {
        let offer = AdminOffer::from_bytes(code).ok_or(Error::NotAnOffer)?;
        let label = {
            let mut held = self.held();
            let group = held.group.as_ref().ok_or(Error::NoSpace)?;
            if group.id() == Some(offer.device) {
                return Err(Error::OwnKey);
            }
            let (_, identity) = held.state.agent.ok_or(Error::NoSpace)?;
            let (_, sync) = group
                .sync_keys()
                .into_iter()
                .find(|(id, _)| *id == offer.device)
                .ok_or(Error::NotInSet)?;
            let view = self
                .views(&mut held)?
                .into_iter()
                .find(|view| {
                    view.id == offer.device
                        && view.removal.is_none()
                        && view.standing != Standing::Removed
                })
                .ok_or(Error::NotInSet)?;
            // Signed by the offering device's sync key as this device's log
            // knows it, over its admin key as the set shows it: a code made
            // anywhere else, or before that key changed, is refused before
            // the user is asked.
            if !offer.verifies(&identity, &view.device.keys.admin, &sync) {
                return Err(Error::StaleOffer);
            }
            String::from_utf8_lossy(&view.device.keys.label).into_owned()
        };
        let approval = Approval {
            device: offer.device,
            label,
            check: offer.check(),
            hardware: offer.hardware,
        };
        if !prompts.approve_admin(&approval) {
            return Err(Error::Declined);
        }
        let admin = new_admin(AdminKey {
            key: offer.key,
            hardware: offer.hardware,
            verified_boot: offer.verified_boot,
        });
        self.operate(
            &mut self.held(),
            prompts,
            method::REPLACE,
            (offer.device, admin).encode(),
            None,
        )
    }

    /// Every other live device of the set removed and a new group started
    /// by this device alone; the others pair again from it.
    pub fn regroup(&self, prompts: &dyn Prompts) -> Result<Posted, Error> {
        let mut held = self.held();
        let me = held
            .group
            .as_ref()
            .and_then(crate::group::DeviceGroup::id)
            .ok_or(Error::NoSpace)?;
        let remove: Vec<u32> = self
            .views(&mut held)?
            .into_iter()
            .filter(|view| view.id != me && view.device.status == Status::Live)
            .map(|view| view.id)
            .collect();
        self.operate(&mut held, prompts, method::REGROUP, remove.encode(), None)
    }

    /// A commit now, carrying every matured removal and this device's leaf
    /// update: the devices it carried out. After a matured regroup it is
    /// the regrouper's new group, of it alone.
    pub fn update(&self, prompts: &dyn Prompts) -> Result<Vec<u32>, Error> {
        let mut held = self.held();
        let mut carried = Vec::new();
        // A removal that matured between the reading and the call is
        // refused as the commit's to carry: read again, commit once more.
        for again in [true, false] {
            // What fell due settled first, so the log shows every matured
            // removal the commit must carry.
            self.wake(&mut held)?;
            self.settle(&mut held)?;
            self.follow(&mut held)?;
            self.drop_unsent(&mut held)?;
            let now = self.host.now();
            let group = held.group.as_mut().ok_or(Error::NoSpace)?;
            carried = group.owed();
            let prepared = match group.regrouper() {
                Some(regrouper) if Some(regrouper) == group.id() => group.regroup(now),
                Some(regrouper) => return Err(Error::Regrouped { by: regrouper }),
                None => group.commit(None, now),
            }
            .map_err(failed)?;
            match self.commit(&mut held, prompts, &prepared) {
                Err(Error::AgentRefused(
                    PersonalError::MissingRemoval(_) | PersonalError::NotMatured(_),
                )) if again => {}
                done => {
                    done?;
                    break;
                }
            }
        }
        // Done once a follow leaves the device complete (its vote on the
        // commit posted, the epoch decided, the archive and recovery
        // kept); the rest of the three after the flow returns.
        let made = self.follow_until_complete(&mut held, 3)?;
        self.leave_behind(&held, 3 - made);
        Ok(carried)
    }

    /// The admin call of `method` with `arguments`, placed at the log's
    /// head this device read just before (the call names it first, and the
    /// agent takes it there alone), signed by the admin key at its prompt
    /// and held in the group before it leaves, its evidence posted under
    /// the sync key with `r2` beside it: an evidence post that fails on the
    /// way is posted again by the next pass, from the held call
    /// ([`crate::group::DeviceGroup::sending`]). Refused because the log
    /// moved past the head (another device's entry meanwhile) or `Settling`
    /// (a wake first), the log is read again and the call signed there, a
    /// prompt each time, at most [`PLACINGS`] signatures in all.
    fn operate(
        &self,
        held: &mut Held,
        prompts: &dyn Prompts,
        method: MethodId,
        arguments: Vec<u8>,
        r2: Option<[u8; 32]>,
    ) -> Result<Posted, Error> {
        self.settle(held)?;
        let admin = held.state.admin.ok_or(Error::NoSpace)?.key;
        let mut signer = held.admin;
        let sign = admin_sign(prompts, admin);
        let recorded = self.with_link(held, Purpose::Personal, |link, held| {
            let group = held.group.as_mut().ok_or(Error::NoSpace)?;
            let read = read_to_head(link, group)?;
            // The same call made before and taken, its answer lost: its
            // evidence posted, never signed again at another place.
            if let Some((index, at, message, signature)) = group.taken(method, &arguments) {
                post_evidence(link, group, index, (&message, &signature), r2)?;
                return Ok(Recorded { at, index });
            }
            let group = std::cell::RefCell::new(group);
            let mut read = Some(read);
            // The log read to its head before each signature again.
            let mut head = |link: &mut AgentLink<'_, H>| match read.take() {
                Some(place) => Ok(place),
                None => read_to_head(link, &mut group.borrow_mut()),
            };
            // A call signed again replaces the one before, which the agent
            // did not take.
            let mut previous: Option<Vec<u8>> = None;
            let mut hold = |message: &[u8], signature: &[u8; 64]| {
                let mut group = group.borrow_mut();
                if let Some(previous) = previous.replace(message.to_vec()) {
                    group.unsent(&previous).map_err(|error| error.to_string())?;
                }
                group
                    .sending(message.to_vec(), *signature, r2)
                    .map_err(|error| error.to_string())
            };
            let called = call_placed(
                link,
                &mut Key::Lent(&mut signer, &sign),
                method,
                &arguments,
                &mut head,
                &mut hold,
            )?;
            let group = group.into_inner();
            let recorded = match answer::<Recorded>(&called.outcome).map_err(failed)? {
                Ok(recorded) => recorded,
                Err(error) => {
                    group.unsent(&called.message).map_err(failed)?;
                    return Err(Error::AgentRefused(error));
                }
            };
            group
                .made(recorded.index, &called.message)
                .map_err(failed)?;
            post_evidence(
                link,
                group,
                recorded.index,
                (&called.message, &called.signature),
                r2,
            )?;
            Ok(recorded)
        });
        held.admin = signer;
        self.posted(held, recorded?)
    }

    /// An operation recorded: the group told its batch time, the log
    /// followed.
    pub(super) fn posted(&self, held: &mut Held, recorded: Recorded) -> Result<Posted, Error> {
        if let Some(group) = held.group.as_mut() {
            group.called(recorded.at);
        }
        self.follow(held)?;
        Ok(Posted {
            index: recorded.index,
            at: recorded.at,
        })
    }

    /// `prepared`'s commit under the admin key, its message held before
    /// the call; its evidence posted; a refused one abandoned.
    pub(super) fn commit(
        &self,
        held: &mut Held,
        prompts: &dyn Prompts,
        prepared: &Prepared,
    ) -> Result<Candidacy, Error> {
        let admin = held.state.admin.ok_or(Error::NoSpace)?.key;
        let mut signer = held.admin;
        let prompted = admin_sign(prompts, admin);
        let group_sign = |message: &[u8]| prompted(message);
        let result = self.with_link(held, Purpose::Personal, |link, held| {
            let group = held.group.as_mut().ok_or(Error::NoSpace)?;
            // The message is held in the group before the call leaves, so a
            // restart posts the evidence of the commit it made.
            let mut hold = |message: &[u8], signature: &[u8; 64]| {
                group
                    .signed_commit(message.to_vec(), *signature)
                    .map_err(|error| error.to_string())
            };
            let called = link
                .settled(
                    &mut Key::Lent(&mut signer, &group_sign),
                    method::COMMIT,
                    prepared.arguments(),
                    &mut hold,
                )
                .map_err(unreached)?;
            match answer::<Candidacy>(&called.outcome).map_err(failed)? {
                Ok(candidacy) => {
                    group.called(candidacy.at);
                    group
                        .made(candidacy.index, &called.message)
                        .map_err(failed)?;
                    let Event::Evidence {
                        index,
                        message,
                        signature,
                        attached,
                    } = group.called_commit(candidacy.index).map_err(failed)?
                    else {
                        return Err(failed("a commit's evidence"));
                    };
                    let arguments = ((index, message), (signature, attached)).encode();
                    answered(link.call::<Recorded>(method::EVIDENCE, arguments))?;
                    Ok(candidacy)
                }
                Err(error) => {
                    group.abandon().map_err(failed)?;
                    Err(Error::AgentRefused(error))
                }
            }
        });
        held.admin = signer;
        result
    }
}

/// The admin call of `method` with `arguments`, signed by `key` at the
/// place `head` reads, the log's head, before each signature, each message
/// given to `hold` before its call leaves ([`AgentLink::signed`]): signed
/// again at the head read anew while the agent refuses it for a head the
/// log moved past (an entry logged between the reading and the call) or,
/// after a wake, `Settling`, at most [`PLACINGS`] signatures in all. The
/// last call's answer.
pub(super) fn call_placed<H: Host>(
    link: &mut AgentLink<'_, H>,
    key: &mut Key<'_>,
    method: MethodId,
    arguments: &[u8],
    head: &mut dyn FnMut(&mut AgentLink<'_, H>) -> Result<Place, Error>,
    hold: Hold<'_>,
) -> Result<Called, Error> {
    let mut signed = 1;
    loop {
        let place = head(link)?;
        let called = link
            .signed(key, method, place.arguments(arguments), &mut *hold)
            .map_err(unreached)?;
        let again = match answer::<()>(&called.outcome) {
            Ok(Err(PersonalError::Settling)) => {
                answered(link.settle())?;
                true
            }
            Ok(Err(PersonalError::StaleHead)) => true,
            _ => false,
        };
        if !again || signed == PLACINGS {
            return Ok(called);
        }
        signed += 1;
    }
}

/// The log read to its head and followed: the place a call made now names.
/// A device whose log stops at an entry it refuses, or that is out of the
/// set, signs nothing: no place it names is the agent's.
fn read_to_head<H: Host>(
    link: &mut AgentLink<'_, H>,
    group: &mut crate::group::DeviceGroup,
) -> Result<Place, Error> {
    let entries = logged(link, group.cursor())?;
    let end = entries.last().map(|(index, _)| index + 1);
    group.follow(entries).map_err(failed)?;
    if group.course() == crate::group::Course::Out {
        return Err(Error::AgentRefused(PersonalError::Removed));
    }
    if end.is_some_and(|end| group.cursor() < end) {
        return Err(Error::Unreachable(
            "the log stops at an entry this device refuses".into(),
        ));
    }
    let (next, chain) = group.view();
    Ok(Place { next, chain })
}

/// The evidence of this device's admin call at `index`, signed as
/// `signed`, posted with `r2` beside it: held for the next pass when it
/// does not get through, given up when the agent refuses it.
fn post_evidence<H: Host>(
    link: &mut AgentLink<'_, H>,
    group: &mut crate::group::DeviceGroup,
    index: u64,
    signed: (&[u8], &[u8; 64]),
    r2: Option<[u8; 32]>,
) -> Result<(), Error> {
    match evidence(link, index, signed, Attached { welcome: None, r2 }) {
        // Held: the next pass posts it.
        Ok(())
        | Err(Error::Unreachable(_))
        | Err(Error::AgentRefused(PersonalError::Settling | PersonalError::Evidenced)) => Ok(()),
        Err(error) => {
            group.evidence_refused(index).map_err(failed)?;
            Err(error)
        }
    }
}

/// An admin key as an admin call names it: its class and attestation.
fn new_admin(key: AdminKey) -> NewAdmin {
    NewAdmin {
        key: key.key,
        class: key.class(),
        attestation: Attestation {
            hardware: key.hardware,
            verified_boot: key.verified_boot,
        },
    }
}

/// The evidence of the admin call at `index`, as signed (`message`,
/// `signature`), posted under the link's key.
pub(super) fn evidence<H: Host>(
    link: &mut AgentLink<'_, H>,
    index: u64,
    (message, signature): (&[u8], &[u8; 64]),
    attached: Attached,
) -> Result<(), Error> {
    let arguments = ((index, message.to_vec()), (*signature, attached)).encode();
    answered(link.call::<Recorded>(method::EVIDENCE, arguments)).map(drop)
}
