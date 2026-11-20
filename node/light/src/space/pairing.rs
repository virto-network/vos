//! Pairing, as the device that shows the code (the opener) and as the one
//! that scans it (the joiner), and the joiner's acknowledgement a pass puts
//! in the slot when the process that made it died first.

use vos_abi::Encode;
use vos_wire::books::DeviceHandle;
use vos_wire::personal::{AdminClass, InboxItem, Overview, PersonalError, method};
use zeroize::Zeroizing;

use super::link::Signer;
use super::{
    Acked, CREDENTIAL_BOOK, Error, Held, Host, Kept, POLL, Paired, Personal, Prompts, answered,
    failed, link, secret, store_failed, unreached,
};
use crate::group::{Course, DeviceGroup, Prepared};
use crate::memberships;
use crate::pairing::{Code, Hello, Joined, Joiner, Offer, Opened, Opener};
use crate::route::Purpose;

/// A pairing under way, in memory alone: a pairing cut short starts again
/// from a new slot.
pub(super) enum Pairing {
    Opener {
        opener: Box<Opener>,
        offer: Offer,
        expires: u64,
    },
    /// Declined: its slot left open for the joiner to read the decline,
    /// closed when the next offer opens one.
    Declined { slot: vos_wire::personal::Scope },
}

/// The code a pairing offer shows: the QR code's bytes, which hold the
/// pairing's one-time code, and when the slot expires (the agent's time).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairCode {
    pub code: Zeroizing<Vec<u8>>,
    pub expires_ms: u64,
}

/// `handle`'s device handle from its secret: the member and owner digests.
fn device_handle(secret: &crate::DeviceSecret, handle: [u8; 32]) -> DeviceHandle {
    DeviceHandle {
        handle,
        member: crate::member(secret).to_bytes(),
        owner: crate::owner(secret).to_bytes(),
    }
}

impl<H: Host> Personal<H> {
    /// A pairing slot at the agent, and the QR code to show: the home, the
    /// agent, the slot and its one-time code. The offer names this
    /// device's memberships, which the new device is enrolled in.
    pub fn pair_offer(&self) -> Result<PairCode, Error> {
        let mut held = self.held();
        let group = held.group.as_ref().ok_or(Error::NoSpace)?;
        let (kept, agent) = (
            held.state.home.clone().ok_or(Error::NoSpace)?,
            held.state.agent.ok_or(Error::NoSpace)?,
        );
        let me = group.id().ok_or(Error::NoSpace)?;
        // A delayed admin's add waits as an operation first, past any
        // pairing's slot: it opens none.
        if held
            .state
            .admin
            .is_some_and(|admin| admin.class() != AdminClass::Strong)
        {
            return Err(Error::DelayedAdmin);
        }
        let item_bytes = group.policy().inbox_item_bytes;
        let ttl = group.policy().slot_ttl_ms;
        if let Some(Pairing::Declined { slot }) = held.pairing.take() {
            // Gone already if it expired: the agent answers `NoSlot`.
            self.with_link(&mut held, Purpose::Personal, |link, _| {
                Ok(link.call::<u64>(method::CLOSE_SLOT, slot.encode()))
            })?
            .ok();
        }
        self.book(&held.light, me);
        let offered = memberships::handles_of(&held.light, CREDENTIAL_BOOK, me)
            .map(|held| held.into_iter().map(|(membership, _)| membership).collect())
            .unwrap_or_default();
        let offer = Offer {
            home: kept.home.clone(),
            memberships: offered,
        };
        let (mut opener, drawn) =
            Opener::open(agent.1, offer.clone(), item_bytes).map_err(failed)?;
        let at = self.with_link(&mut held, Purpose::Personal, |link, _| {
            answered(link.call::<u64>(method::OPEN_SLOT, drawn.slot.arguments()))
        })?;
        let expires = at + ttl;
        let code = opener.code(
            &drawn,
            expires,
            agent.0,
            super::PERSONAL,
            kept.onions.clone(),
        );
        held.pairing = Some(Pairing::Opener {
            opener: Box::new(opener),
            offer,
            expires,
        });
        self.waiting.start();
        Ok(PairCode {
            code: code.to_bytes(),
            expires_ms: expires,
        })
    }

    /// The pairing the code shown opened, driven to its end: the
    /// handshake's messages, the user's confirmation that the new device
    /// shows the handshake's check, the joiner's hello, the handover (the
    /// archive and `R`), then, once the joiner acknowledged it, the commit
    /// adding it; the enrollments it is owed held, each deferrable.
    pub fn pair_await(&self, prompts: &dyn Prompts) -> Result<Paired, Error> {
        let done = self.opened(prompts);
        self.waiting.end();
        done
    }

    /// The pairing under way stops at its next read of the slot, as the
    /// user asked; nothing when none is.
    pub fn pair_cancel(&self) {
        self.waiting.cancel();
    }

    fn opened(&self, prompts: &dyn Prompts) -> Result<Paired, Error> {
        let mut held = self.held();
        let (mut opener, offer, expires) = match held.pairing.take() {
            Some(Pairing::Opener {
                opener,
                offer,
                expires,
            }) => (opener, offer, expires),
            declined => {
                held.pairing = declined;
                return Err(Error::NoPairing);
            }
        };
        let mut prepared = None;
        let shaken = self.handshake(
            &mut held,
            prompts,
            &mut opener,
            &offer,
            expires,
            &mut prepared,
        );
        if prepared.is_some()
            && let Some(group) = held.group.as_mut()
        {
            // The commit made for the joiner is never sent.
            let _ = group.abandon();
        }
        let heard = shaken?;
        let until = self.host.now().saturating_add(self.wait_ms());
        if !self.caught_up(&mut held, until)? {
            return Err(Error::AwaitsVotes);
        }
        let group = held.group.as_ref().ok_or(Error::NoSpace)?;
        let device = group
            .author(&heard.device.sync)
            .map(|(id, _)| id)
            .ok_or(Error::CommitVoid)?;
        let owed = memberships::enrollments(held.light.store()).map_err(store_failed)?;
        for (space, handle) in &heard.handles {
            let _ = memberships::record(&held.light, CREDENTIAL_BOOK, *space, device, *handle);
        }
        Ok(Paired {
            device,
            memberships: owed.len() as u32,
        })
    }

    /// The pairing's exchange over the slot, to the commit adding the
    /// joiner once it acknowledged the handover: the joiner's hello. The
    /// commit made at the hello is in `prepared` until its call.
    fn handshake(
        &self,
        held: &mut Held,
        prompts: &dyn Prompts,
        opener: &mut Opener,
        offer: &Offer,
        expires: u64,
        prepared: &mut Option<Prepared>,
    ) -> Result<Hello, Error> {
        let mut hello: Option<Hello> = None;
        loop {
            if self.host.now() > expires {
                return Err(Error::SlotExpired);
            }
            // Cut short only before the handover: once the joiner holds it,
            // the pairing runs to its end or the slot's.
            if hello.is_none() && self.waiting.cancelled() {
                self.close_slot(held, opener)?;
                return Err(Error::Cancelled);
            }
            let items: Vec<InboxItem> = self.with_link(held, Purpose::Personal, |link, _| {
                answered(link.query(method::INBOX, Option::<(u64, [u8; 16])>::None))
            })?;
            match opener.read(&items).map_err(failed)? {
                Opened::Waiting => self.host.sleep(POLL),
                Opened::Check { check, put } => {
                    self.put(held, &put.arguments())?;
                    // Nothing more, the offer included, leaves until the
                    // user confirms the new device shows this check.
                    // Declined, the joiner reads it in the slot, which
                    // stays open for it.
                    if !prompts.confirm_pairing(&check) {
                        let put = opener.decline().map_err(failed)?;
                        held.pairing = Some(Pairing::Declined {
                            slot: opener.slot(),
                        });
                        self.put(held, &put.arguments())?;
                        return Err(Error::Declined);
                    }
                    let put = opener.offer().map_err(failed)?;
                    self.put(held, &put.arguments())?;
                }
                Opened::Hello(heard) => {
                    // The commit is made on what the log decided, its admin
                    // key the one the set shows.
                    self.settle(held)?;
                    let until = expires.min(self.host.now().saturating_add(self.wait_ms()));
                    if !self.caught_up(held, until)? {
                        return Err(Error::Undecided);
                    }
                    let now = self.host.now();
                    let group = held.group.as_mut().ok_or(Error::NoSpace)?;
                    let (made, pairing) = group
                        .pair(heard.device.clone(), heard.key_package.clone(), now)
                        .map_err(failed)?;
                    *prepared = Some(made);
                    for put in opener.hand_over(&pairing).map_err(failed)? {
                        self.put(held, &put.arguments())?;
                    }
                    hello = Some(heard);
                }
                Opened::Received => {
                    let made = prepared.take().ok_or_else(|| failed("no commit made"))?;
                    // Refused, the commit is abandoned; one taken past
                    // another device's commit since the hello is pairing's
                    // to make again.
                    self.commit(held, prompts, &made)
                        .map_err(|error| match error {
                            Error::AgentRefused(PersonalError::EpochTaken) => {
                                Error::CommittedMeanwhile
                            }
                            error => error,
                        })?;
                    let heard = hello.take().ok_or_else(|| failed("no hello"))?;
                    memberships::hold(
                        held.light.store(),
                        &memberships::plan(&offer.memberships, &heard),
                    )
                    .map_err(store_failed)?;
                    return Ok(heard);
                }
            }
        }
    }

    /// The slot `opener` opened, closed: the next offer starts anew.
    fn close_slot(&self, held: &mut Held, opener: &Opener) -> Result<(), Error> {
        let slot = opener.slot();
        self.with_link(held, Purpose::Personal, |link, _| {
            answered(link.call::<u64>(method::CLOSE_SLOT, slot.encode())).map(drop)
        })
    }

    /// The log followed until no candidate is pending, by `until` (ms),
    /// whether it got there: a commit is made for the epoch after the last
    /// one decided, so one made past another device's commit this device
    /// has not read yet would be refused as `EpochTaken`, its Welcome never
    /// sent; and a pairing's own commit is decided before the device it
    /// adds is named.
    pub(super) fn caught_up(&self, held: &mut Held, until: u64) -> Result<bool, Error> {
        loop {
            self.follow(held)?;
            self.drop_unsent(held)?;
            if !held.group.as_ref().ok_or(Error::NoSpace)?.pending() {
                return Ok(true);
            }
            if self.host.now() > until {
                return Ok(false);
            }
            self.host.sleep(POLL);
        }
    }

    /// A commit of this device's the agent never took, its process killed
    /// before the call left, dropped: with the log followed to its head
    /// and no candidate at the agent, a commit still held was not taken,
    /// and nothing else commits while it is held. One the log holds is
    /// kept (`DeviceGroup::abandon` refuses it).
    pub(super) fn drop_unsent(&self, held: &mut Held) -> Result<(), Error> {
        if !held.group.as_ref().is_some_and(DeviceGroup::pending) {
            return Ok(());
        }
        let overview: Overview = self.with_link(held, Purpose::Personal, |link, _| {
            answered(link.query(method::OVERVIEW, ()))
        })?;
        if overview.candidate.is_none()
            && let Some(group) = held.group.as_mut()
            && group.cursor() >= overview.next
        {
            let _ = group.abandon();
        }
        Ok(())
    }

    /// An item put in the pairing slot under the sync key.
    fn put(&self, held: &mut Held, arguments: &[u8]) -> Result<(), Error> {
        self.with_link(held, Purpose::Personal, |link, _| {
            answered(link.call::<u64>(method::PUT, arguments.to_vec())).map(drop)
        })
    }

    /// The code scanned, the device joined through the slot: its hello (its
    /// keys, its "home" nullifier, its key package, its handle in each
    /// offered space, each from its source at its prompt), the handover,
    /// its group joined; the acknowledgement left. A device that holds
    /// another personal space, or this one's once out of it (its removal
    /// matured), leaves it once the opener's offer is read
    /// (`Personal::leave`); one the set still holds live is refused. The
    /// label is the caller's to check.
    pub fn pair_join(
        &self,
        prompts: &dyn Prompts,
        code: &[u8],
        label: &str,
    ) -> Result<Paired, Error> {
        self.waiting.start();
        let done = self.joining(prompts, code, label);
        self.waiting.end();
        done
    }

    fn joining(&self, prompts: &dyn Prompts, code: &[u8], label: &str) -> Result<Paired, Error> {
        let code = Code::from_bytes(code).ok_or(Error::NotAPairingCode)?;
        let mut held = self.held();
        // A device of that personal space pairs again only once out of it
        // on the log it verifies (its removal read through: the agent
        // serves a removed device's key that far), or if never added (its
        // add's candidate void), or named by a removal it verified the
        // signature of (one whose maturity its log never shows it, its
        // supporting evidence never posted): while in the set it is
        // refused, whatever a refusal says. Out, it leaves at the offer.
        let in_set = |held: &Held| {
            held.group.as_ref().is_some_and(|group| {
                group.agent().identity == code.identity
                    && group.id().is_some_and(|me| {
                        group.course() != Course::Out && !group.removal_signed(me)
                    })
            })
        };
        if in_set(&held) {
            // Unreached, it stays as it was: in the set.
            let _ = self.follow(&mut held);
            if in_set(&held) {
                return Err(Error::InSetAlready);
            }
        }
        // The rest of the home comes in the offer.
        let kept = Kept::reached(code.handle, code.onions.clone());
        self.pin(&kept);
        let slot = code.slot_key();
        let mut slot_signer = Signer::new(slot.verifying_key().to_bytes());
        let agent = (code.agent, code.identity);
        let (mut joiner, put) = Joiner::scan(&code).map_err(failed)?;
        let slot_put = |signer: &mut Signer, arguments: Vec<u8>| -> Result<(), Error> {
            let mut link = link(&self.host, &kept, Purpose::Personal, agent, &slot, signer);
            answered(link.call::<u64>(method::PUT, arguments)).map(drop)
        };
        slot_put(&mut slot_signer, put.arguments())?;
        let mut home = None;
        let until = code.expires;
        let (pairing, ack, offer, device) = loop {
            if self.host.now() > until {
                return Err(Error::SlotExpired);
            }
            // Cut short only before its hello: once the opener has it, the
            // pairing runs to its end or the slot's.
            if home.is_none() && self.waiting.cancelled() {
                return Err(Error::Cancelled);
            }
            let items: Vec<InboxItem> = {
                let mut link = link(
                    &self.host,
                    &kept,
                    Purpose::Personal,
                    agent,
                    &slot,
                    &mut slot_signer,
                );
                match link
                    .query(method::INBOX, Option::<(u64, [u8; 16])>::None)
                    .map_err(unreached)?
                {
                    Ok(items) => items,
                    // The slot's key admitted no more: closed, or a word
                    // nobody signed. Only the opener's decline over the
                    // channel ends the pairing; until the slot expires, it
                    // is read again.
                    Err(PersonalError::NotAdmitted) => {
                        self.host.sleep(POLL);
                        continue;
                    }
                    Err(error) => return Err(Error::AgentRefused(error)),
                }
            };
            match joiner.read(&items).map_err(failed)? {
                Joined::Waiting => self.host.sleep(POLL),
                // Shown while the opener's user confirms it; until then the
                // opener sends nothing more.
                Joined::Check(check) => {
                    if !prompts.show_pairing(&check) {
                        return Err(Error::Declined);
                    }
                }
                Joined::Declined => return Err(Error::PairingDeclined),
                Joined::Offer(offer) => {
                    // The code is the opener's: the space this device holds
                    // is left, and it pairs as a fresh install.
                    if held.group.is_some()
                        || crate::home::holds_archive(held.light.store()).map_err(failed)?
                        || held.state.restoring.is_some()
                        || crate::home::Claim::pending(held.light.store())
                            .map_err(failed)?
                            .is_some()
                    {
                        self.leave(&mut held)?;
                    }
                    let source = self.source(prompts, &mut held)?;
                    let secret = secret(prompts, &source, &offer.home.handle)?;
                    let device = self.device(&mut held, prompts, &offer.home, &secret, label)?;
                    let mut handles = Vec::new();
                    for membership in &offer.memberships {
                        let there = super::secret(prompts, &source, &membership.handle)?;
                        handles.push((membership.space, device_handle(&there, membership.handle)));
                    }
                    let key_package =
                        DeviceGroup::key_package(held.light.store(), &device, self.host.now())
                            .map_err(failed)?;
                    let put = joiner
                        .hello(&Hello {
                            device: device.clone(),
                            key_package,
                            handles,
                        })
                        .map_err(failed)?;
                    slot_put(&mut slot_signer, put.arguments())?;
                    home = Some((offer, device));
                }
                Joined::Handover(pairing, ack) => {
                    let (offer, device) = home
                        .take()
                        .ok_or_else(|| failed("a handover before the offer"))?;
                    break (pairing, ack, offer, device);
                }
            }
        };
        // What the pairing makes this device's is in its group's batch: the
        // home and agent, the confirmations it owes, the acknowledgement
        // itself, which a pass puts in the slot if this process dies before
        // it leaves; after it, the opener commits the add.
        let kept = Kept {
            home: offer.home.clone(),
            onions: code.onions.clone(),
        };
        self.pin(&kept);
        let mut next = held.state.clone();
        next.home = Some(kept);
        next.agent = Some(agent);
        next.label = label.to_owned();
        next.acked = Some(Acked {
            handle: code.handle,
            onions: code.onions.clone(),
            agent,
            slot: code.slot_key().to_bytes(),
            expires: code.expires,
            ack: ack.arguments(),
        });
        let mut rows = next.rows();
        rows.extend(memberships::expected(&offer.memberships));
        let group =
            DeviceGroup::join(held.light.store(), device, *pairing, rows).map_err(failed)?;
        held.group = Some(group);
        self.adopt(&mut held, next);
        held.sync = Signer::new(held.light.sync_key().verifying_key().to_bytes());
        slot_put(&mut slot_signer, ack.arguments())?;
        held.state.acked = None;
        self.keep(&held.light, &held.state)?;
        self.joined(&mut held)?;
        let device = held.group.as_ref().and_then(DeviceGroup::id).unwrap_or(0);
        self.book(&held.light, device);
        Ok(Paired {
            device,
            memberships: offer.memberships.len() as u32,
        })
    }

    /// The log followed until the opener's commit adding this device is
    /// confirmed (until then its sync key is not admitted, the group names
    /// no device and a pass stops at its keys), then twice more.
    fn joined(&self, held: &mut Held) -> Result<(), Error> {
        let until = std::time::Instant::now() + self.wait();
        loop {
            let followed = self.follow(held);
            if followed.is_ok() && held.group.as_ref().and_then(DeviceGroup::id).is_some() {
                break;
            }
            if std::time::Instant::now() > until {
                return Err(Error::NotJoinedYet);
            }
            self.host.sleep(POLL);
        }
        for _ in 0..2 {
            self.follow(held)?;
        }
        Ok(())
    }

    /// A joiner's acknowledgement kept by a process that died before it
    /// was put in its slot, put there now while the slot lives and the
    /// device holds the group it joined; one the agent refuses is the
    /// pairing's end, as is a slot past its expiry.
    pub(super) fn acknowledge(&self, held: &mut Held) -> Result<(), Error> {
        let Some(acked) = held.state.acked.clone() else {
            return Ok(());
        };
        let joined = held
            .group
            .as_ref()
            .is_some_and(|group| group.agent().identity == acked.agent.1);
        let put = if !joined || self.host.now() > acked.expires {
            Ok(())
        } else {
            let kept = Kept::reached(acked.handle, acked.onions.clone());
            let slot = ed25519_dalek::SigningKey::from_bytes(&acked.slot);
            let mut signer = Signer::new(slot.verifying_key().to_bytes());
            let mut link = link(
                &self.host,
                &kept,
                Purpose::Personal,
                acked.agent,
                &slot,
                &mut signer,
            );
            match link
                .call::<u64>(method::PUT, acked.ack.clone())
                .map_err(unreached)?
            {
                Ok(_) => Ok(()),
                Err(error) => Err(Error::AgentRefused(error)),
            }
        };
        held.state.acked = None;
        self.keep(&held.light, &held.state)?;
        put
    }
}
