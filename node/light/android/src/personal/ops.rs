// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The personal space's flows, each as the light node exposes it
//! (`vos_light::home`, `pairing`, `memberships`, `kit`, `moving`), over the
//! facility's client: `Personal` for the agent and `Homes`, `Member` for an
//! open claim, `Feed` for a home's tree, `Proven` for a proof. Every flow
//! runs on the calling thread, each request blocking on the facility's
//! runtime.

use std::time::Duration;

use ed25519_dalek::Signer as _;
use vos_light::group::{Agent as GroupAgent, DeviceGroup, Event, Prepared, Restored};
use vos_light::home::{self, Claim as Claiming, Home as HomeSpace};
use vos_light::kit::{KitSecret, SecurityKey};
use vos_light::memberships;
use vos_light::moving::{self, Move};
use vos_light::pairing::{
    Code, Hello, Joined, Joiner, Membership as Offered, Offer, Opened, Opener,
};
use vos_light::personal::{Link as _, SealedSync, recover};
use vos_light::route::Purpose;
use vos_light::tor::Registrar;
use vos_light::{AuthWitness, Call, Digest, Light, TreeKeeper, wire};
use vos_wire::books::{DeviceHandle, Enrolled as BookEntry};
use vos_wire::credentials::{CredentialError, Open};
use vos_wire::homes::HomesError;
use vos_wire::personal::{
    AdminClass, Attached, Attestation, Body, Candidacy, DeviceView, Entry, InboxItem, NewAdmin,
    NewDevice, OpState, Overview, PersonalError, RECOVERY, Recorded, RecoveryView, Standing,
};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};
use zeroize::Zeroizing;

pub(super) mod regroup;

use super::link::{AgentLink, Signer, answer};
use super::{
    Acked, Bound, CREDENTIAL_BOOK, ClaimDue, Held, Kept, Lent, PERSONAL, Restoring, Space, State,
    failed, link, reference, unreached,
};
use crate::enrollment::Enrollment;
use crate::job::now_ms;
use crate::personal::{
    Claim, Claimed, Device, Home, KitKind, Membership, Moved, Owed, PairCode, Paired, Posted,
};
use crate::session::{Inner, store_error};
use crate::source::{Kind, Reference};
use crate::{Answer, Code as Refused, Form, Refusal, refused};
use s4_credential_contract::KeyAnswer;

/// How long a flow waits for the agent to take a claim (ms), and between
/// reads of a slot or a log.
pub(super) const WAIT_MS: u64 = 120_000;
const POLL: Duration = Duration::from_millis(500);
/// The wakes a flow sends until what fell due is settled.
const WAKES: usize = 8;
/// A proven call's expiry past the node's time.
const EXPIRY_MS: u64 = 60_000;
/// The open claim's work, on this many threads.
const WORK_THREADS: usize = 2;

/// A pairing under way, in memory alone: a pairing cut short starts again
/// from a new slot.
pub(super) enum Pairing {
    Opener {
        opener: Opener,
        offer: Offer,
        expires: u64,
    },
}

/// A device's new admin key, offered to another device of the set to sign
/// its replacement: `device` (u32 big-endian) ‖ `key` ‖ a flags byte (1
/// hardware, 2 verified boot) ‖ the offering device's sync key's signature
/// over them ([`AdminOffer::message`]), as the screens show it. The device
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
        hex::encode(&self.key[..8])
    }
}

/// A device whose removal a retirement revokes in each space.
pub type Removal = u32;

fn declined() -> Refusal {
    refused(Refused::Declined, "the user declined")
}

fn agent_refused(error: PersonalError) -> Refusal {
    refused(
        Refused::Refused,
        format!("the personal agent refused: {error:?}"),
    )
}

fn cancelled() -> Refusal {
    refused(Refused::Declined, "the pairing was cancelled")
}

fn no_space() -> Refusal {
    refused(Refused::NotEnrolled, "this device holds no personal space")
}

/// A key's answer, its bytes or why there are none.
fn key_answer(answer: KeyAnswer) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    match answer {
        KeyAnswer::Done(bytes) => Ok(bytes),
        KeyAnswer::Declined => Err(declined()),
        KeyAnswer::Failed(message) => Err(refused(Refused::Source, message)),
    }
}

/// A security key's `hmac-secret` through the UI's prompt: its credential
/// `id` (empty: the key's discoverable credential), the salt its input.
struct Touched<'a> {
    prompts: Lent<'a>,
    id: Vec<u8>,
}

impl SecurityKey for Touched<'_> {
    type Error = Refusal;

    fn hmac_secret(&mut self, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Refusal> {
        let bytes = key_answer(self.prompts.evaluate_key(Kind::Kit, &self.id, salt))?;
        let mut out = Zeroizing::new([0; 32]);
        if bytes.len() != 32 {
            return Err(refused(
                Refused::Source,
                "the security key's output is not 32 bytes",
            ));
        }
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// The kit's card, shown with it: the home's handle (its stable 32 bytes,
/// so a re-founded home still matches) and each onion with its SSH host
/// key, the home a restore goes to.
fn card(kept: &Kept) -> Vec<(String, String)> {
    let mut rows = vec![("Home".to_owned(), hex::encode(kept.home.handle))];
    for (at, onion) in kept.onions.iter().enumerate() {
        rows.push((
            format!("Onion {}", at + 1),
            vos_light::tor::onion_address(&onion.key),
        ));
        rows.push((
            format!("Onion {} host key", at + 1),
            hex::encode(onion.ssh_host_key),
        ));
    }
    rows
}

/// A new kit of `kind` for the home `kept`: a phrase shown once in the
/// chrome beside its card, or a security key's, its discoverable
/// credential made at its prompt, then its card.
fn new_kit(prompts: Lent<'_>, kind: KitKind, kept: &Kept) -> Result<KitSecret, Refusal> {
    let shown = |form: Form| match prompts.confirm(form) {
        Answer::Confirmed { .. } => Ok(()),
        Answer::Declined => Err(declined()),
    };
    match kind {
        KitKind::Phrase => {
            let secret = KitSecret::phrase().ok_or_else(|| failed("no randomness"))?;
            let words = secret.words().ok_or_else(|| failed("a phrase has words"))?;
            let rows = words
                .split(' ')
                .enumerate()
                .map(|(at, word)| (format!("{}", at + 1), word.to_owned()))
                .chain(card(kept))
                .collect();
            shown(Form {
                title: "Your recovery phrase".into(),
                detail: "Write these 24 words down, in order, with the card below them, and \
                         keep them apart from this phone. They restore your personal space at \
                         this home if every device is lost; this is the only time they are \
                         shown."
                    .into(),
                rows,
                fields: Vec::new(),
                notice: None,
                choices: vec!["I wrote them down".into()],
            })?;
            Ok(secret)
        }
        KitKind::SecurityKey => {
            let id = key_answer(prompts.create_key(Kind::Kit))?;
            let secret = KitSecret::security_key(&mut Touched {
                prompts,
                id: id.to_vec(),
            })?;
            shown(Form {
                title: "Your recovery key's card".into(),
                detail: "Write this card down and keep it with the security key: it names the \
                         home a restore with the key goes to."
                    .into(),
                rows: card(kept),
                fields: Vec::new(),
                notice: None,
                choices: vec!["I wrote it down".into()],
            })?;
            Ok(secret)
        }
    }
}

/// The kit the user has: its words entered in the chrome, or its security
/// key touched (its discoverable credential).
fn entered_kit(prompts: Lent<'_>, kind: KitKind) -> Result<KitSecret, Refusal> {
    match kind {
        KitKind::Phrase => {
            let answer = prompts.confirm(Form {
                title: "Enter your recovery phrase".into(),
                detail: "The 24 words you wrote down, in order, separated by spaces.".into(),
                rows: Vec::new(),
                fields: vec![crate::Field {
                    label: "Words".into(),
                    value: String::new(),
                }],
                notice: None,
                choices: vec!["Restore".into()],
            });
            let Answer::Confirmed { values, .. } = answer else {
                return Err(declined());
            };
            let words = Zeroizing::new(values.join(" "));
            KitSecret::from_words(words.trim())
                .ok_or_else(|| refused(Refused::Arguments, "those are not the kit's 24 words"))
        }
        KitKind::SecurityKey => KitSecret::security_key(&mut Touched {
            prompts,
            id: Vec::new(),
        }),
    }
}

/// A new admin key, made in the UI's keystore behind a strong biometric:
/// its public half and what its attestation showed.
fn new_admin(prompts: Lent<'_>) -> Result<([u8; 32], bool, bool), Refusal> {
    let bytes = key_answer(prompts.create_key(Kind::Admin))?;
    let (key, flags) = bytes
        .split_first_chunk::<32>()
        .ok_or_else(|| refused(Refused::Source, "the admin key's answer is short"))?;
    let flags = flags.first().copied().unwrap_or(0);
    Ok((*key, flags & 1 != 0, flags & 2 != 0))
}

/// A signer of messages by the admin key `key`, at its prompt.
fn admin_sign<'a>(
    prompts: Lent<'a>,
    key: [u8; 32],
) -> impl Fn(&[u8]) -> Result<[u8; 64], String> + 'a {
    move |message: &[u8]| {
        let bytes = match prompts.sign_key(Kind::Admin, &key, message) {
            KeyAnswer::Done(bytes) => bytes,
            KeyAnswer::Declined => return Err("the user declined".into()),
            KeyAnswer::Failed(message) => return Err(message),
        };
        <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| "a signature is 64 bytes".into())
    }
}

/// The secret for the space whose handle is `handle`, from the source at
/// its prompt.
fn secret(
    prompts: Lent<'_>,
    reference: &Reference,
    handle: &[u8; 32],
) -> Result<Box<vos_light::DeviceSecret>, Refusal> {
    let kind = reference.kind();
    let bytes = reference.to_bytes();
    let output =
        key_answer(prompts.evaluate_key(kind, &bytes[1..], &vos_light::source_input(handle)))?;
    let output: Zeroizing<[u8; 32]> = Zeroizing::new(
        output
            .as_slice()
            .try_into()
            .map_err(|_| refused(Refused::Source, "the source's output is not 32 bytes"))?,
    );
    Ok(Box::new(vos_light::derive_secret(&output, handle)))
}

/// `handle`'s device handle from its secret: the member and owner digests.
fn device_handle(secret: &vos_light::DeviceSecret, handle: [u8; 32]) -> DeviceHandle {
    DeviceHandle {
        handle,
        member: vos_light::member(secret).to_bytes(),
        owner: vos_light::owner(secret).to_bytes(),
    }
}

/// A home as the chrome names it, as the light node keeps it.
fn kept_of(home: &Home) -> Kept {
    Kept {
        home: HomeSpace {
            space: home.space,
            handle: home.handle,
            agent: home.agent,
            identity: home.identity,
            homes: vos_wire::ids::InstanceId(home.homes),
            credentials: vos_wire::ids::InstanceId(home.credentials),
        },
        onions: crate::net::onions(&home.onions),
    }
}

/// The home's credential actor, whose feed holds its tree.
fn home_registrar(home: &HomeSpace) -> Registrar {
    Registrar {
        agent: home.agent,
        instance: home.credentials.0,
        identity: home.identity,
    }
}

impl Space {
    fn wait_ms(&self) -> u64 {
        self.wait().as_millis() as u64
    }

    /// The device's secret source's key: the one kept, or one made now and
    /// kept at once, so a flow cut short proves with it again.
    fn source(&self, prompts: Lent<'_>, held: &mut Held) -> Result<Reference, Refusal> {
        if let Some(reference) = reference(&held.state) {
            return Ok(reference);
        }
        let key = key_answer(prompts.create_key(Kind::Keystore))?;
        let reference = Reference::from_bytes(&[&[Kind::Keystore as u8], &key[..]].concat())
            .ok_or_else(|| refused(Refused::Source, "the source's key handle"))?;
        held.state.source = Some(reference.to_bytes());
        self.keep(&held.state)?;
        Ok(reference)
    }

    fn block<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        self.runtime.block_on(future)
    }

    /// `request` to the space whose handle is `space`, under `purpose`.
    fn ask(&self, space: [u8; 32], purpose: Purpose, request: &[u8]) -> Result<Vec<u8>, Refusal> {
        self.block(self.net().request(space, purpose, request))
            .map_err(unreached)
    }

    /// The node's time at `space`, under `purpose`.
    fn time(&self, space: [u8; 32], purpose: Purpose) -> Result<u64, Refusal> {
        wire::time_answer(&self.ask(space, purpose, &wire::time_request())?).map_err(failed)
    }

    /// A query by a key drawn for it alone, of `name` at `instance` of the
    /// home's agent: `Homes`' and the registrar's terms.
    fn home_query<T: Decode>(
        &self,
        home: &HomeSpace,
        purpose: Purpose,
        instance: u32,
        name: &str,
        arguments: Vec<u8>,
    ) -> Result<T, Refusal> {
        let now = self.time(home.handle, purpose)?;
        let request = wire::query_request(
            home.agent,
            &home.identity,
            instance,
            name,
            arguments,
            now + EXPIRY_MS,
        )
        .map_err(failed)?;
        wire::query_answer(&self.ask(home.handle, purpose, &request)?).map_err(failed)
    }

    /// The identity of `agent`, from its record, as the home's node says.
    fn identity(&self, home: &HomeSpace, agent: u32) -> Result<[u8; 32], Refusal> {
        let answer = self.ask(home.handle, Purpose::Personal, &wire::agent_request(agent))?;
        wire::agent_answer(&answer)
            .map_err(failed)?
            .ok_or_else(|| refused(Refused::Failed, "the home's node knows no such agent"))
    }

    /// The open claim of `member` at `home`: its work for the terms the
    /// registrar serves, a call in a session of its own. A member already
    /// there is done.
    fn open_claim(&self, home: &HomeSpace, member: &[u8; 32]) -> Result<(), Refusal> {
        let terms: Option<Open> = self.home_query(
            home,
            Purpose::Member,
            home.credentials.0,
            "opening",
            Vec::new(),
        )?;
        let terms =
            terms.ok_or_else(|| refused(Refused::Refused, "the home admits no open claim"))?;
        let nonce = home::work(
            &home.handle,
            member,
            &terms.salt,
            terms.difficulty,
            WORK_THREADS,
        );
        let now = self.time(home.handle, Purpose::Member)?;
        let request = home::open_claim(home, member, nonce, now).map_err(failed)?;
        let outcome =
            wire::outcome(&self.ask(home.handle, Purpose::Member, &request)?).map_err(failed)?;
        match &outcome {
            Outcome::Done(_) => Ok(()),
            Outcome::Failed { detail, .. }
                if CredentialError::decode_exact(detail) == Some(CredentialError::Enrolled) =>
            {
                Ok(())
            }
            other => Err(refused(
                Refused::Refused,
                format!("the open claim: {other:?}"),
            )),
        }
    }

    /// The joiner's open claim, made once its time is `now` or past, then
    /// owed no more; refused, tried again after a wait doubled at each of
    /// the home's refusals ([`super::CLAIM_RETRY`]), kept with its time.
    pub(super) fn claim_if_due(&self, state: &mut State, now: u64) -> Result<(), Refusal> {
        let Some(due) = state.claim_due.as_mut().filter(|due| due.due <= now) else {
            return Ok(());
        };
        if let Err(refusal) = self.open_claim(&due.home, &due.member) {
            // The home's refusal doubles the wait; a home not reached is
            // tried again after the first wait.
            let refusals = if refusal.code == Refused::Api {
                1
            } else {
                due.refused = due.refused.saturating_add(1);
                due.refused
            };
            due.due = now.saturating_add(self.claim_retry(refusals)?);
            self.keep(state)?;
            return Err(refusal);
        }
        state.claim_due = None;
        self.keep(state)
    }

    /// `member`'s path at the newest root of `home`'s tree, read from its
    /// feed until it holds the member's leaf.
    fn home_witness(&self, home: &HomeSpace, member: &[u8; 32]) -> Result<AuthWitness, Refusal> {
        let member = Digest::from_bytes(member).ok_or_else(|| failed("the member is no digest"))?;
        let mut keeper = TreeKeeper::new(member);
        let registrar = home_registrar(home);
        let until = std::time::Instant::now() + self.wait();
        loop {
            self.block(
                self.net()
                    .client()
                    .read_tree(home.handle, &registrar, &mut keeper, now_ms),
            )
            .map_err(unreached)?;
            if let Some(witness) = keeper.witness() {
                return Ok(witness);
            }
            if std::time::Instant::now() > until {
                return Err(refused(
                    Refused::NoPath,
                    "the home's tree holds no leaf of this device",
                ));
            }
            std::thread::sleep(POLL);
        }
    }

    /// `call` of `Homes` proved in the scope "home" with `secret`, sent as
    /// a proven call: `Homes`' answer.
    fn prove_home<T: Decode + Send + 'static>(
        &self,
        home: &HomeSpace,
        secret: Box<vos_light::DeviceSecret>,
        witness: AuthWitness,
        call: Call,
    ) -> Result<Result<T, HomesError>, Refusal> {
        let inner = std::sync::Arc::clone(self.facility.inner());
        let request = self.block(Inner::prove(
            &inner,
            |stock| &stock.auth,
            move |prover, program| {
                let proof = prover.prove_home(&secret, &witness, &call, program);
                drop(secret);
                proof.map(|proof| wire::credentialed(&call, &proof))
            },
        ))?;
        let answer = self.ask(home.handle, Purpose::Proven, &request)?;
        crate::session::update_refused(&answer)?;
        match wire::credentialed_answer(&answer).map_err(failed)? {
            wire::Answer::Ran { outcome, .. } => match outcome {
                Outcome::Done(bytes) => T::decode_exact(&bytes)
                    .map(Ok)
                    .ok_or_else(|| failed("`Homes`' reply does not decode")),
                Outcome::Failed { detail, .. } => HomesError::decode_exact(&detail)
                    .map(Err)
                    .ok_or_else(|| failed("`Homes`' error does not decode")),
                other => Err(failed(format!("`Homes` answered {other:?}"))),
            },
            other => Err(refused(
                Refused::Refused,
                format!("the home's ingress: {other:?}"),
            )),
        }
    }

    /// The agent's log once it holds the assignment, read by the sync key.
    fn assigned(
        &self,
        held: &mut Held,
        kept: &Kept,
        agent: (u32, [u8; 32]),
    ) -> Result<Vec<(u64, Entry)>, Refusal> {
        let key = held.light.sync_key().clone();
        let mut sync = Signer::new(key.verifying_key().to_bytes());
        let until = std::time::Instant::now() + self.wait();
        loop {
            let mut link = link(
                self.net(),
                &self.runtime,
                kept,
                Purpose::Personal,
                agent,
                &key,
                &mut sync,
            );
            if let Ok(Ok(entries)) = link.log_all(0)
                && entries
                    .iter()
                    .any(|(_, entry)| matches!(entry.body, Body::Assigned { .. }))
            {
                held.sync = sync;
                return Ok(entries);
            }
            if std::time::Instant::now() > until {
                return Err(refused(
                    Refused::Api,
                    "the agent has not taken the claim yet",
                ));
            }
            std::thread::sleep(POLL);
        }
    }

    /// The log followed until the opener's commit adding this device is
    /// confirmed (until then its sync key is not admitted, the group names
    /// no device and a pass stops at its keys), then twice more.
    fn joined(&self, held: &mut Held) -> Result<(), Refusal> {
        let until = std::time::Instant::now() + self.wait();
        loop {
            let followed = self.follow(held);
            if followed.is_ok() && held.group.as_ref().and_then(DeviceGroup::id).is_some() {
                break;
            }
            if std::time::Instant::now() > until {
                return Err(refused(
                    Refused::Api,
                    "the commit adding this device is not confirmed yet: it joins once the \
                     other devices confirm it, unless the device it paired from shows it void",
                ));
            }
            std::thread::sleep(POLL);
        }
        for _ in 0..2 {
            self.follow(held)?;
        }
        Ok(())
    }

    /// The device's keys at `home`: its sync key, its admin key (made now
    /// unless kept), its "home" nullifier from `secret`, its label.
    fn device(
        &self,
        held: &mut Held,
        prompts: Lent<'_>,
        home: &HomeSpace,
        secret: &vos_light::DeviceSecret,
        label: &str,
    ) -> Result<NewDevice, Refusal> {
        let (admin, hardware, verified_boot) = match held.state.admin {
            Some(admin) => admin,
            None => {
                let admin = new_admin(prompts)?;
                held.state.admin = Some(admin);
                held.admin = Signer::new(admin.0);
                self.keep(&held.state)?;
                admin
            }
        };
        Ok(NewDevice {
            sync: held.light.sync_key().verifying_key().to_bytes(),
            admin,
            class: AdminClass::Strong,
            attestation: Attestation {
                hardware,
                verified_boot,
            },
            nullifier: home.nullifier(secret),
            label: label.as_bytes().to_vec(),
            carried: Vec::new(),
        })
    }

    /// The pooled agent `Homes` at `home` names, and its identity.
    fn pooled(&self, home: &HomeSpace) -> Result<(u32, [u8; 32]), Refusal> {
        let pooled: Option<u32> =
            self.home_query(home, Purpose::Personal, home.homes.0, "pooled", Vec::new())?;
        let agent =
            pooled.ok_or_else(|| refused(Refused::Refused, "the home has no agent to give"))?;
        Ok((agent, self.identity(home, agent)?))
    }

    /// `claim`: a personal agent at a home-only space, with a kit of the
    /// kind asked. The device's open claim first (its own work, a session
    /// of its own), then the claim of the agent `Homes` names, sealed to
    /// its identity, proved in the scope "home"; held until the agent's log
    /// shows it, so a retry sends the same claim.
    pub fn claim(&self, prompts: Lent<'_>, request: Claim) -> Result<Claimed, Refusal> {
        let request = request.check()?;
        let mut held = self.held();
        if held.group.is_some() {
            return Err(refused(
                Refused::Refused,
                "this device holds a personal space already",
            ));
        }
        let kept = kept_of(&request.home);
        let pending = Claiming::pending(held.light.store()).map_err(failed)?;
        if pending.is_none()
            && vos_light::home::holds_archive(held.light.store()).map_err(failed)?
        {
            return Err(refused(
                Refused::Refused,
                "this device holds a personal space's keys already: restore or pair it",
            ));
        }
        if pending.is_some()
            && let Some(bound) = &held.state.bound
            && bound.home.home.handle != kept.home.handle
        {
            return Err(refused(
                Refused::Refused,
                "a claim at another home is under way: claim there again to finish it",
            ));
        }
        self.pin(&kept);
        let home = kept.home.clone();
        let reference = self.source(prompts, &mut held)?;
        let secret = secret(prompts, &reference, &home.handle)?;
        let member = vos_light::member(&secret).to_bytes();
        self.open_claim(&home, &member)?;
        let claim = match pending {
            Some(claim) => claim,
            None => {
                let agent = self.pooled(&home)?;
                let device = self.device(&mut held, prompts, &home, &secret, &request.label)?;
                let kit = new_kit(prompts, request.kit, &kept)?;
                Claiming::prepare(
                    held.light.store(),
                    device,
                    vec![kit.key()],
                    agent.0,
                    agent.1,
                )
                .map_err(|error| refused(Refused::Refused, error.to_string()))?
            }
        };
        let agent = claim.agent();
        held.state.bound = Some(Bound { home: kept, agent });
        held.state.label = request.label;
        self.keep(&held.state)?;
        let witness = self.home_witness(&home, &member)?;
        let now = self.time(home.handle, Purpose::Fetch)?;
        let call = claim.call(&home, now + EXPIRY_MS).map_err(failed)?;
        match self.prove_home::<u32>(&home, secret, witness, call)? {
            Ok(_) | Err(HomesError::Claimed) => {}
            Err(error) => {
                claim.abandon(held.light.store()).map_err(failed)?;
                held.state.bound = None;
                self.keep(&held.state)?;
                return Err(refused(
                    Refused::Refused,
                    format!("`Homes` refused the claim: {error:?}"),
                ));
            }
        }
        let kept = held.state.bound.as_ref().ok_or_else(no_space)?.home.clone();
        let entries = self.assigned(&mut held, &kept, agent)?;
        let group = claim
            .claimed(held.light.store(), PERSONAL, &entries, now_ms())
            .map_err(failed)?;
        let device = group.id().unwrap_or(0);
        held.group = Some(group);
        held.arrived();
        self.keep(&held.state)?;
        self.book(&held.light, device);
        self.follow(&mut held)?;
        Ok(Claimed {
            agent: agent.0,
            device,
        })
    }

    /// Record in the credential book each enrollment's space and this
    /// device's handle there, unless it is: what a pairing offers, and a
    /// retirement revokes. Again at each pass, so a space enrolled in
    /// later, or a record a process did not live to make, is recorded.
    pub(super) fn book(&self, light: &Light, device: u32) {
        let Ok(all) = self.facility.inner().store.all() else {
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
                name: hex::encode(&enrollment.handle[..8]),
                credentials: vos_wire::books::Location {
                    agent: enrollment.credentials.agent,
                    instance: enrollment.credentials.instance,
                },
                agents: enrollment
                    .agents
                    .iter()
                    .map(|agent| vos_wire::books::Agent {
                        agent: agent.agent,
                        identity: agent.identity,
                    })
                    .collect(),
            };
            let join = light.call(
                CREDENTIAL_BOOK,
                vos_wire::ids::MethodId(vos_light::method_id("join")),
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

    /// A joiner's acknowledgement kept by a process that died before it
    /// was put in its slot, put there now while the slot lives and the
    /// device holds the group it joined; one the agent refuses is the
    /// pairing's end, as is a slot past its expiry.
    pub(super) fn acknowledge(&self, held: &mut Held) -> Result<(), Refusal> {
        let Some(acked) = held.state.acked.clone() else {
            return Ok(());
        };
        let joined = held
            .group
            .as_ref()
            .is_some_and(|group| group.agent().identity == acked.agent.1);
        let put = if !joined || now_ms() > acked.expires {
            Ok(())
        } else {
            let kept = Kept {
                home: HomeSpace {
                    space: [0; 32],
                    handle: acked.handle,
                    agent: 0,
                    identity: [0; 32],
                    homes: vos_wire::ids::InstanceId(0),
                    credentials: vos_wire::ids::InstanceId(0),
                },
                onions: acked.onions.clone(),
            };
            let slot = ed25519_dalek::SigningKey::from_bytes(&acked.slot);
            let mut signer = Signer::new(slot.verifying_key().to_bytes());
            let mut link = link(
                self.net(),
                &self.runtime,
                &kept,
                Purpose::Personal,
                acked.agent,
                &slot,
                &mut signer,
            );
            match link
                .call::<u64>("put", acked.ack.clone())
                .map_err(unreached)?
            {
                Ok(_) => Ok(()),
                Err(error) => Err(agent_refused(error)),
            }
        };
        held.state.acked = None;
        self.keep(&held.state)?;
        put
    }

    /// A link of `purpose` to the agent the device's group is at.
    fn with_link<T>(
        &self,
        held: &mut Held,
        purpose: Purpose,
        f: impl FnOnce(&mut AgentLink<'_>, &mut Held) -> Result<T, Refusal>,
    ) -> Result<T, Refusal> {
        let (Some(kept), Some(agent)) = (held.state.home.clone(), held.state.agent) else {
            return Err(no_space());
        };
        let key = held.light.sync_key().clone();
        let mut sync = held.sync;
        let mut link = link(
            self.net(),
            &self.runtime,
            &kept,
            purpose,
            agent,
            &key,
            &mut sync,
        );
        let done = f(&mut link, held);
        held.sync = sync;
        done
    }

    /// One pass of the light node's job in the foreground: the log
    /// followed and every vote, evidence and `alive` posted, the scopes
    /// pushed and read.
    fn follow(&self, held: &mut Held) -> Result<(), Refusal> {
        self.with_link(held, Purpose::Personal, |link, held| {
            let Held { light, group, .. } = held;
            let group = group.as_mut().ok_or_else(no_space)?;
            let instances = light.instances().map_err(failed)?;
            vos_light::job::run(light, group, link, &instances, now_ms())
                .map(drop)
                .map_err(|stopped| unreached(stopped.error))
        })
    }

    /// The admin call of `name` with `arguments`, signed by the admin key
    /// at its prompt, its evidence posted under the sync key with `r2`
    /// beside it.
    fn operate(
        &self,
        held: &mut Held,
        prompts: Lent<'_>,
        name: &str,
        arguments: Vec<u8>,
        r2: Option<[u8; 32]>,
    ) -> Result<Posted, Refusal> {
        self.settle(held)?;
        let admin = held.state.admin.ok_or_else(no_space)?.0;
        let mut signer = held.admin;
        let sign = admin_sign(prompts, admin);
        let recorded = self.with_link(held, Purpose::Personal, |link, _| {
            let called = link
                .settled(&mut signer, &sign, name, arguments)
                .map_err(unreached)?;
            let recorded = answer::<Recorded>(&called.outcome)
                .map_err(failed)?
                .map_err(agent_refused)?;
            evidence(
                link,
                recorded.index,
                (&called.message, &called.signature),
                Attached { welcome: None, r2 },
            )?;
            Ok(recorded)
        });
        held.admin = signer;
        self.posted(held, recorded?)
    }

    /// An operation recorded: the group told its batch time, the log
    /// followed.
    fn posted(&self, held: &mut Held, recorded: Recorded) -> Result<Posted, Refusal> {
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
    fn commit(
        &self,
        held: &mut Held,
        prompts: Lent<'_>,
        prepared: &Prepared,
    ) -> Result<Candidacy, Refusal> {
        let admin = held.state.admin.ok_or_else(no_space)?.0;
        let mut signer = held.admin;
        let prompted = admin_sign(prompts, admin);
        let group_sign = |message: &[u8]| prompted(message);
        let result = self.with_link(held, Purpose::Personal, |link, held| {
            let group = held.group.as_mut().ok_or_else(no_space)?;
            // The message is held in the group before the call leaves, so a
            // restart posts the evidence of the commit it made.
            let mut hold = |message: &[u8], signature: &[u8; 64]| {
                group
                    .signed_commit(message.to_vec(), *signature)
                    .map_err(|error| error.to_string())
            };
            let called = link
                .settled_held(
                    &mut signer,
                    &group_sign,
                    "commit",
                    prepared.arguments(),
                    &mut hold,
                )
                .map_err(unreached)?;
            match answer::<Candidacy>(&called.outcome).map_err(failed)? {
                Ok(candidacy) => {
                    group.called(candidacy.at);
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
                    link.call::<Recorded>("evidence", arguments)
                        .map_err(unreached)?
                        .map_err(agent_refused)?;
                    Ok(candidacy)
                }
                Err(error) => {
                    group.abandon().map_err(failed)?;
                    Err(agent_refused(error))
                }
            }
        });
        held.admin = signer;
        result
    }

    // ----- pairing -----

    /// `pair_offer`: a pairing slot at the agent, and the QR code to show:
    /// the home, the agent, the slot and its one-time code. The offer names
    /// this device's memberships, which the new device is enrolled in.
    pub fn pair_offer(&self, _prompts: Lent<'_>) -> Result<PairCode, Refusal> {
        let mut held = self.held();
        let group = held.group.as_ref().ok_or_else(no_space)?;
        let (kept, agent) = (
            held.state.home.clone().ok_or_else(no_space)?,
            held.state.agent.ok_or_else(no_space)?,
        );
        let me = group.id().ok_or_else(no_space)?;
        let item_bytes = group.policy().inbox_item_bytes;
        let ttl = group.policy().slot_ttl_ms;
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
            link.call::<u64>("open_slot", drawn.slot.arguments())
                .map_err(unreached)?
                .map_err(agent_refused)
        })?;
        let expires = at + ttl;
        let code = opener.code(&drawn, expires, agent.0, PERSONAL, kept.onions.clone());
        held.pairing = Some(Pairing::Opener {
            opener,
            offer,
            expires,
        });
        self.waiting.start();
        Ok(PairCode {
            code: code.to_bytes(),
            expires_ms: expires,
        })
    }

    /// `pair_await`: the pairing the code shown opened, driven to its end:
    /// the handshake's messages, the joiner's hello, the handover (the
    /// archive, `R`, each scope's checkpoint), then, once the joiner
    /// acknowledged it, the commit adding it; the enrollments it is owed
    /// held, each deferrable.
    pub fn pair_await(&self, prompts: Lent<'_>) -> Result<Paired, Refusal> {
        let done = self.opened(prompts);
        self.waiting.end();
        done
    }

    /// `pair_cancel`: the pairing under way stops at its next read of the
    /// slot, as the chrome asked; nothing when none is.
    pub fn pair_cancel(&self) {
        self.waiting.cancel();
    }

    fn opened(&self, prompts: Lent<'_>) -> Result<Paired, Refusal> {
        let mut held = self.held();
        let Some(Pairing::Opener {
            mut opener,
            offer,
            expires,
        }) = held.pairing.take()
        else {
            return Err(refused(Refused::Refused, "no pairing was offered"));
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
        match self.caught_up(&mut held, now_ms().saturating_add(self.wait_ms()))? {
            true => {}
            false => {
                return Err(refused(
                    Refused::Refused,
                    "the commit adding the device awaits the other devices' votes: it is the \
                     set's once they confirm it",
                ));
            }
        }
        let group = held.group.as_ref().ok_or_else(no_space)?;
        let device = group
            .author(&heard.device.sync)
            .map(|(id, _)| id)
            .ok_or_else(|| {
                refused(
                    Refused::Refused,
                    "the commit adding the device was void: pair again",
                )
            })?;
        let owed = memberships::enrollments(held.light.store()).map_err(failed)?;
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
        prompts: Lent<'_>,
        opener: &mut Opener,
        offer: &Offer,
        expires: u64,
        prepared: &mut Option<Prepared>,
    ) -> Result<Hello, Refusal> {
        let mut hello: Option<Hello> = None;
        loop {
            if now_ms() > expires {
                return Err(refused(Refused::Refused, "the pairing's slot expired"));
            }
            // Cut short only before the handover: once the joiner holds it,
            // the pairing runs to its end or the slot's.
            if hello.is_none() && self.waiting.cancelled() {
                // The slot closed, so the next offer starts anew.
                let slot = opener.slot();
                self.with_link(held, Purpose::Personal, |link, _| {
                    link.call::<u64>("close_slot", slot.encode())
                        .map_err(unreached)?
                        .map_err(agent_refused)
                        .map(drop)
                })?;
                return Err(cancelled());
            }
            let items: Vec<InboxItem> = self.with_link(held, Purpose::Personal, |link, _| {
                link.query("inbox", Option::<(u64, [u8; 16])>::None)
                    .map_err(unreached)?
                    .map_err(agent_refused)
            })?;
            match opener.read(&items).map_err(failed)? {
                Opened::Waiting => std::thread::sleep(POLL),
                Opened::Put(put) => self.put(held, &put.arguments())?,
                Opened::Hello(heard) => {
                    // The commit is made on what the log decided, its admin
                    // key the one the set shows.
                    self.settle(held)?;
                    let until = expires.min(now_ms().saturating_add(self.wait_ms()));
                    if !self.caught_up(held, until)? {
                        return Err(refused(
                            Refused::Refused,
                            "another device's commit is undecided: pair once the other devices \
                             have synced",
                        ));
                    }
                    let instances = held.light.instances().map_err(failed)?;
                    let checkpoints = self.checkpoints(held, &instances);
                    let group = held.group.as_mut().ok_or_else(no_space)?;
                    let (made, mut pairing) = group
                        .pair(heard.device.clone(), heard.key_package.clone(), now_ms())
                        .map_err(failed)?;
                    *prepared = Some(made);
                    for checkpoint in checkpoints {
                        pairing.trust(checkpoint);
                    }
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
                    self.commit(held, prompts, &made).map_err(|refusal| {
                        if refusal.message.contains("EpochTaken") {
                            refused(
                                Refused::Refused,
                                "another device committed during the pairing: pair again",
                            )
                        } else {
                            refusal
                        }
                    })?;
                    let heard = hello.take().ok_or_else(|| failed("no hello"))?;
                    memberships::hold(
                        held.light.store(),
                        &memberships::plan(&offer.memberships, &heard),
                    )
                    .map_err(failed)?;
                    return Ok(heard);
                }
            }
        }
    }

    /// The log followed until no candidate is pending, by `until` (ms),
    /// whether it got there: a commit is made for the epoch after the last
    /// one decided, so one made past another device's commit this device
    /// has not read yet would be refused as `EpochTaken`, its Welcome never
    /// sent; and a pairing's own commit is decided before the device it
    /// adds is named.
    fn caught_up(&self, held: &mut Held, until: u64) -> Result<bool, Refusal> {
        loop {
            self.follow(held)?;
            self.drop_unsent(held)?;
            if !held.group.as_ref().ok_or_else(no_space)?.pending() {
                return Ok(true);
            }
            if now_ms() > until {
                return Ok(false);
            }
            std::thread::sleep(POLL);
        }
    }

    /// A commit of this device's the agent never took, its process killed
    /// before the call left, dropped: with the log followed to its head
    /// and no candidate at the agent, a commit still held was not taken,
    /// and nothing else commits while it is held. One the log holds is
    /// kept (`DeviceGroup::abandon` refuses it).
    fn drop_unsent(&self, held: &mut Held) -> Result<(), Refusal> {
        if !held.group.as_ref().is_some_and(DeviceGroup::pending) {
            return Ok(());
        }
        let overview: Overview = self.with_link(held, Purpose::Personal, |link, _| {
            link.query("overview", ())
                .map_err(unreached)?
                .map_err(agent_refused)
        })?;
        if overview.candidate.is_none()
            && let Some(group) = held.group.as_mut()
            && group.cursor() >= overview.next
        {
            let _ = group.abandon();
        }
        Ok(())
    }

    /// Each installed scope's checkpoint, for a pairing's handover.
    fn checkpoints(
        &self,
        held: &mut Held,
        instances: &[vos_wire::ids::InstanceId],
    ) -> Vec<vos_light::group::Checkpoint> {
        self.with_link(held, Purpose::Personal, |link, held| {
            let Held { light, group, .. } = held;
            let group = group.as_mut().ok_or_else(no_space)?;
            let mut sync =
                SealedSync::new(light, group, link, instances.to_vec()).map_err(failed)?;
            Ok(instances
                .iter()
                .filter_map(|instance| sync.checkpoint(*instance).ok())
                .collect())
        })
        .unwrap_or_default()
    }

    /// An item put in the pairing slot under the sync key.
    fn put(&self, held: &mut Held, arguments: &[u8]) -> Result<(), Refusal> {
        self.with_link(held, Purpose::Personal, |link, _| {
            link.call::<u64>("put", arguments.to_vec())
                .map_err(unreached)?
                .map_err(agent_refused)
                .map(drop)
        })
    }

    /// `pair_join`: the code scanned, the device joined through the slot:
    /// its hello (its keys, its "home" nullifier, its key package, its
    /// handle in each offered space, each from its source at its prompt),
    /// the handover, its group joined, or rejoined after a move; the
    /// acknowledgement left; then its open claim at the home (`Member`, a
    /// session of its own), so its re-proof proves under the nullifier its
    /// add recorded. The home sees the claim follow the join.
    pub fn pair_join(
        &self,
        prompts: Lent<'_>,
        code: &[u8],
        label: &str,
    ) -> Result<Paired, Refusal> {
        self.waiting.start();
        let done = self.joining(prompts, code, label);
        self.waiting.end();
        done
    }

    fn joining(&self, prompts: Lent<'_>, code: &[u8], label: &str) -> Result<Paired, Refusal> {
        let delay = self.draw_claim_delay()?;
        crate::personal::label(label)?;
        let code = Code::from_bytes(code)
            .ok_or_else(|| refused(Refused::Arguments, "not a pairing code"))?;
        let mut held = self.held();
        let kept = Kept {
            home: HomeSpace {
                // The rest of the home comes in the offer.
                space: [0; 32],
                handle: code.handle,
                agent: 0,
                identity: [0; 32],
                homes: vos_wire::ids::InstanceId(0),
                credentials: vos_wire::ids::InstanceId(0),
            },
            onions: code.onions.clone(),
        };
        self.pin(&kept);
        let slot = code.slot_key();
        let mut slot_signer = Signer::new(slot.verifying_key().to_bytes());
        let agent = (code.agent, code.identity);
        let (mut joiner, put) = Joiner::scan(&code).map_err(failed)?;
        let slot_put =
            |space: &Space, signer: &mut Signer, arguments: Vec<u8>| -> Result<(), Refusal> {
                let mut link = link(
                    space.net(),
                    &space.runtime,
                    &kept,
                    Purpose::Personal,
                    agent,
                    &slot,
                    signer,
                );
                link.call::<u64>("put", arguments)
                    .map_err(unreached)?
                    .map_err(agent_refused)
                    .map(drop)
            };
        slot_put(self, &mut slot_signer, put.arguments())?;
        let mut home = None;
        let until = code.expires;
        let (pairing, ack, offered, device) = loop {
            if now_ms() > until {
                return Err(refused(Refused::Refused, "the pairing's slot expired"));
            }
            // Cut short only before its hello: once the opener has it, the
            // pairing runs to its end or the slot's.
            if home.is_none() && self.waiting.cancelled() {
                return Err(cancelled());
            }
            let items: Vec<InboxItem> = {
                let mut link = link(
                    self.net(),
                    &self.runtime,
                    &kept,
                    Purpose::Personal,
                    agent,
                    &slot,
                    &mut slot_signer,
                );
                link.query("inbox", Option::<(u64, [u8; 16])>::None)
                    .map_err(unreached)?
                    .map_err(agent_refused)?
            };
            match joiner.read(&items).map_err(failed)? {
                Joined::Waiting => std::thread::sleep(POLL),
                Joined::Offer(offer) => {
                    let reference = self.source(prompts, &mut held)?;
                    let secret = secret(prompts, &reference, &offer.home.handle)?;
                    let mut device =
                        self.device(&mut held, prompts, &offer.home, &secret, label)?;
                    // A device of a group a move left says what it carries
                    // in its hello: the keys it rejoins with name it.
                    if let Some(old) = held.group.as_ref() {
                        device = moving::naming(&held.light, old, device).map_err(moved)?;
                    }
                    let member = vos_light::member(&secret).to_bytes();
                    let mut handles = Vec::new();
                    for membership in &offer.memberships {
                        let there = self::secret(prompts, &reference, &membership.handle)?;
                        handles.push((membership.space, device_handle(&there, membership.handle)));
                    }
                    let key_package =
                        DeviceGroup::key_package(held.light.store(), &device, now_ms())
                            .map_err(failed)?;
                    let put = joiner
                        .hello(&Hello {
                            device: device.clone(),
                            key_package,
                            handles,
                        })
                        .map_err(failed)?;
                    slot_put(self, &mut slot_signer, put.arguments())?;
                    home = Some((offer, device, member));
                }
                Joined::Handover(pairing, ack) => {
                    let (offer, device, member) = home
                        .take()
                        .ok_or_else(|| failed("a handover before the offer"))?;
                    break (pairing, ack, (offer, member), device);
                }
            }
        };
        let (offer, member) = offered;
        // What the pairing makes this device's is kept before the
        // acknowledgement leaves, after which the opener commits the add:
        // the home and agent, the open claim owed there, the
        // acknowledgement itself, which a pass puts in the slot if this
        // process dies first.
        let kept = Kept {
            home: offer.home.clone(),
            onions: code.onions.clone(),
        };
        self.pin(&kept);
        held.state.bound = Some(Bound { home: kept, agent });
        held.state.label = label.to_owned();
        // The joiner's open claim at the home, so its re-proof proves under
        // the nullifier its add recorded: made by the background job after a
        // drawn delay, so the home's operators do not link the new member to
        // the agent by its time.
        held.state.claim_due = Some(ClaimDue {
            home: offer.home.clone(),
            member,
            due: now_ms().saturating_add(delay),
            refused: 0,
        });
        self.keep(&held.state)?;
        let old = held.group.take();
        let joined = match old {
            None if !vos_light::home::holds_archive(held.light.store()).map_err(failed)? => {
                DeviceGroup::join(held.light.store(), device, *pairing).map_err(failed)
            }
            old => moving::rejoin(&held.light, old, device, *pairing).map_err(moved),
        };
        let group = match joined {
            Ok(group) => group,
            Err(refusal) => {
                // Not joined: what the pairing was to make dropped, the
                // store's group (none, or the one a rejoin left) held.
                let store = held.light.store().clone();
                let group = DeviceGroup::open(&store).ok().flatten();
                held.state.unjoined(&store, group.as_ref())?;
                held.group = group;
                self.keep(&held.state)?;
                return Err(refusal);
            }
        };
        held.group = Some(group);
        memberships::expect(held.light.store(), &offer.memberships).map_err(failed)?;
        held.arrived();
        held.state.acked = Some(Acked {
            handle: code.handle,
            onions: code.onions.clone(),
            agent,
            slot: code.slot_key().to_bytes(),
            expires: code.expires,
            ack: ack.arguments(),
        });
        held.sync = Signer::new(held.light.sync_key().verifying_key().to_bytes());
        self.keep(&held.state)?;
        slot_put(self, &mut slot_signer, ack.arguments())?;
        held.state.acked = None;
        self.keep(&held.state)?;
        self.joined(&mut held)?;
        if moving::carrying(held.light.store()).map_err(failed)? {
            self.finish_move(&mut held)?;
        }
        let device = held.group.as_ref().and_then(DeviceGroup::id).unwrap_or(0);
        self.book(&held.light, device);
        Ok(Paired {
            device,
            memberships: offer.memberships.len() as u32,
        })
    }

    // ----- memberships -----

    /// The memberships owed on this device: enrollments of a device it
    /// paired, and its own confirmations.
    pub fn memberships(&self) -> Result<Vec<Membership>, Refusal> {
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
            .map_err(failed)?
            .iter()
            .map(|enrollment| of(&enrollment.membership, Owed::Enroll))
            .collect();
        all.extend(
            memberships::confirmations(store)
                .map_err(failed)?
                .iter()
                .map(|membership| of(membership, Owed::Confirm)),
        );
        Ok(all)
    }

    /// This device's enrollment at `handle`, which an owner proof there
    /// takes: its secret's source and its routes.
    fn enrolled_at(&self, handle: &[u8; 32]) -> Result<Enrollment, Refusal> {
        self.facility
            .inner()
            .store
            .all()
            .map_err(store_error)?
            .into_iter()
            .find(|enrollment| enrollment.handle == *handle)
            .ok_or_else(|| {
                refused(
                    Refused::NotEnrolled,
                    "this device is not enrolled in that space here yet",
                )
            })
    }

    /// `call` proved under this device's owner secret in the space of
    /// `enrollment`, at its source's prompt, sent as a proven call: the
    /// registrar's outcome.
    fn prove_owner(
        &self,
        prompts: Lent<'_>,
        enrollment: &Enrollment,
        call: impl FnOnce(u64) -> Result<Call, vos_light::DeviceError>,
    ) -> Result<Outcome, Refusal> {
        let now = self.time(enrollment.handle, Purpose::Fetch)?;
        let call = call(now + EXPIRY_MS).map_err(failed)?;
        let secret = secret(prompts, &enrollment.source, &enrollment.handle)?;
        let inner = std::sync::Arc::clone(self.facility.inner());
        let request = self.block(Inner::prove(
            &inner,
            |stock| &stock.owner,
            move |prover, program| {
                let proof = prover.prove_owner(&secret, &call, program);
                drop(secret);
                proof.map(|proof| wire::credentialed(&call, &proof))
            },
        ))?;
        let answer = self.ask(enrollment.handle, Purpose::Proven, &request)?;
        crate::session::update_refused(&answer)?;
        match wire::credentialed_answer(&answer).map_err(failed)? {
            wire::Answer::Ran { outcome, .. } => Ok(outcome),
            other => Err(refused(
                Refused::Refused,
                format!("the space's ingress: {other:?}"),
            )),
        }
    }

    /// `enroll_device`: the device a pairing added enrolled in
    /// `membership`'s space, by this device's owner proof there.
    pub fn enroll_device(&self, prompts: Lent<'_>, membership: Membership) -> Result<(), Refusal> {
        let held = self.held();
        let owed = memberships::enrollments(held.light.store()).map_err(failed)?;
        let enrollment = owed
            .into_iter()
            .find(|owed| {
                owed.membership.space == membership.space
                    && owed.membership.handle == membership.handle
            })
            .ok_or_else(|| refused(Refused::Arguments, "no enrollment is owed there"))?;
        let mine = self.enrolled_at(&membership.handle)?;
        let outcome = self.prove_owner(prompts, &mine, |expires| enrollment.call(expires))?;
        registrar_done(&outcome)?;
        memberships::done(held.light.store(), &enrollment.membership).map_err(failed)
    }

    /// `confirm_device`: this device's own confirmation in `membership`'s
    /// space, once its leaf is there.
    pub fn confirm_device(&self, prompts: Lent<'_>, membership: Membership) -> Result<(), Refusal> {
        let held = self.held();
        let owed = memberships::confirmations(held.light.store()).map_err(failed)?;
        let confirmation = owed
            .into_iter()
            .find(|owed| owed.space == membership.space && owed.handle == membership.handle)
            .ok_or_else(|| refused(Refused::Arguments, "no confirmation is owed there"))?;
        let mine = self.enrolled_at(&membership.handle)?;
        let outcome = self.prove_owner(prompts, &mine, |expires| {
            memberships::confirm_call(&confirmation, &mine.member, expires)
        })?;
        registrar_done(&outcome)?;
        memberships::confirmed(held.light.store(), &confirmation).map_err(failed)
    }

    /// `drop_enrollment`: an enrollment owed, given up.
    pub fn drop_enrollment(&self, membership: Membership) -> Result<(), Refusal> {
        let held = self.held();
        let owed = memberships::enrollments(held.light.store()).map_err(failed)?;
        let Some(enrollment) = owed.into_iter().find(|owed| {
            owed.membership.space == membership.space && owed.membership.handle == membership.handle
        }) else {
            return Ok(());
        };
        memberships::done(held.light.store(), &enrollment.membership).map_err(failed)
    }

    /// `revoke`: a removed device's leaf revoked in each space its handles
    /// name, by this device's owner proof there (a phone retired).
    pub fn revoke(&self, prompts: Lent<'_>, device: u32) -> Result<u32, Refusal> {
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

    // ----- the device set -----

    /// `devices`: the device set as the agent holds it.
    pub fn devices(&self) -> Result<Vec<Device>, Refusal> {
        let mut held = self.held();
        let me = held.group.as_ref().and_then(DeviceGroup::id);
        let views = self.views(&mut held)?;
        self.adopt_admin(&mut held, &views)?;
        Ok(views
            .into_iter()
            .map(|view| Device {
                id: view.id,
                label: String::from_utf8_lossy(&view.device.keys.label).into_owned(),
                strong: view.device.keys.class == AdminClass::Strong,
                standing: view.standing as u8,
                seen: view.seen,
                removed: view.removal.is_some() || view.standing == Standing::Removed,
                me: Some(view.id) == me,
            })
            .collect())
    }

    /// The device set as the agent shows it.
    fn views(&self, held: &mut Held) -> Result<Vec<DeviceView>, Refusal> {
        self.with_link(held, Purpose::Personal, |link, _| {
            link.query("devices", ())
                .map_err(unreached)?
                .map_err(agent_refused)
        })
    }

    /// A replaced admin key is this device's once the set `views` shows
    /// it.
    fn adopt_admin(&self, held: &mut Held, views: &[DeviceView]) -> Result<(), Refusal> {
        let me = held.group.as_ref().and_then(DeviceGroup::id);
        if let Some(view) = views.iter().find(|view| Some(view.id) == me)
            && held
                .state
                .admin
                .is_some_and(|(key, ..)| key != view.device.keys.admin)
            && let Some(next) = held.state.next_admin(&view.device.keys.admin)
        {
            held.state.admin = Some(next);
            held.state.next_admin.clear();
            held.admin = Signer::new(next.0);
            self.keep(&held.state)?;
        }
        Ok(())
    }

    /// What fell due settled at the agent, under the sync key.
    fn wake(&self, held: &mut Held) -> Result<(), Refusal> {
        self.with_link(held, Purpose::Personal, |link, _| {
            for _ in 0..WAKES {
                let woken = link.wake().map_err(unreached)?.map_err(agent_refused)?;
                if woken.settled {
                    break;
                }
            }
            Ok(())
        })
    }

    /// While a new admin key is offered, what fell due settled and the key
    /// taken if the set shows it: the step before an admin call is
    /// prepared, since the call itself settles a replacement that matured
    /// and would then refuse the key it was signed by.
    fn settle(&self, held: &mut Held) -> Result<(), Refusal> {
        if held.state.next_admin.is_empty() {
            return Ok(());
        }
        self.wake(held)?;
        let views = self.views(held)?;
        self.adopt_admin(held, &views)
    }

    /// `operations`: the device set's operations open, as the chrome
    /// raises them.
    pub fn operations(&self) -> Result<Vec<crate::Notice>, Refusal> {
        let held = self.held();
        let group = held.group.as_ref().ok_or_else(no_space)?;
        let pass = vos_light::job::Pass {
            operations: group.operations(),
            ..Default::default()
        };
        Ok(pass.notices().into_iter().map(crate::job::notice).collect())
    }

    /// `remove`: a device of the set removed, by the admin key (a phone
    /// retired, or lost): it matures after the policy's delay unless
    /// vetoed, and the next commit carries it.
    pub fn remove(&self, prompts: Lent<'_>, device: u32) -> Result<Posted, Refusal> {
        self.operate(&mut self.held(), prompts, "remove", device.encode(), None)
    }

    pub fn veto(&self, prompts: Lent<'_>, index: u64) -> Result<Posted, Refusal> {
        self.operate(&mut self.held(), prompts, "veto", index.encode(), None)
    }

    pub fn cosign(&self, prompts: Lent<'_>, index: u64) -> Result<Posted, Refusal> {
        self.operate(&mut self.held(), prompts, "cosign", index.encode(), None)
    }

    /// `resolve`: a contested operation upheld or dropped.
    pub fn resolve(&self, prompts: Lent<'_>, index: u64, upheld: bool) -> Result<Posted, Refusal> {
        self.operate(
            &mut self.held(),
            prompts,
            "resolve",
            (index, upheld).encode(),
            None,
        )
    }

    /// `rotate_kit`: a new kit of `kind`, `R` split anew for it, the old
    /// kit admitted no more once it matures.
    pub fn rotate_kit(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Posted, Refusal> {
        let mut held = self.held();
        let kept = held.state.home.clone().ok_or_else(no_space)?;
        let kit = new_kit(prompts, kind, &kept)?;
        let group = held.group.as_mut().ok_or_else(no_space)?;
        let split = group.rotate(&[kit.key()]).map_err(failed)?;
        self.operate(
            &mut held,
            prompts,
            "rotate",
            split.kit.encode(),
            Some(*split.r2()),
        )
    }

    /// `replace_admin`: a new admin key for this device, made in the UI's
    /// keystore, its replacement signed by the kit entered (a device signs
    /// no replacement of its own key): it matures after the kit's delay;
    /// the set showing it, the key is this device's ([`Space::devices`]).
    pub fn replace_admin(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Posted, Refusal> {
        let mut held = self.held();
        let me = held
            .group
            .as_ref()
            .and_then(DeviceGroup::id)
            .ok_or_else(no_space)?;
        let kit = entered_kit(prompts, kind)?;
        let next = new_admin(prompts)?;
        let admin = NewAdmin {
            key: next.0,
            class: AdminClass::Strong,
            attestation: Attestation {
                hardware: next.1,
                verified_boot: next.2,
            },
        };
        held.state.set_next_admin(next);
        self.keep(&held.state)?;
        let (kept, agent) = (
            held.state.home.clone().ok_or_else(no_space)?,
            held.state.agent.ok_or_else(no_space)?,
        );
        // The kit's call and its evidence, each under the kit's key.
        let signing = kit.signing();
        let mut signer = Signer::new(signing.verifying_key().to_bytes());
        let mut session = signer;
        let recorded = {
            let mut link = link(
                self.net(),
                &self.runtime,
                &kept,
                Purpose::Personal,
                agent,
                &signing,
                &mut session,
            );
            let sign = |message: &[u8]| Ok(signing.sign(message).to_bytes());
            let called = link
                .settled(&mut signer, &sign, "replace", (me, admin).encode())
                .map_err(unreached)?;
            let recorded = answer::<Recorded>(&called.outcome)
                .map_err(failed)?
                .map_err(agent_refused)?;
            evidence(
                &mut link,
                recorded.index,
                (&called.message, &called.signature),
                Attached {
                    welcome: None,
                    r2: None,
                },
            )?;
            recorded
        };
        self.posted(&mut held, recorded)
    }

    /// `admin_offer`: a new admin key for this device, made in the UI's
    /// keystore, offered to another seasoned device of the set to sign its
    /// replacement: the code that device takes ([`Space::replace_admin_of`]).
    /// The set showing it, the key is this device's ([`Space::devices`]).
    pub fn admin_offer(&self, prompts: Lent<'_>) -> Result<Vec<u8>, Refusal> {
        let mut held = self.held();
        // Signed over the admin key the set shows for this device.
        self.settle(&mut held)?;
        let me = held
            .group
            .as_ref()
            .and_then(DeviceGroup::id)
            .ok_or_else(no_space)?;
        let next = new_admin(prompts)?;
        let (_, identity) = held.state.agent.ok_or_else(no_space)?;
        let (admin, ..) = held.state.admin.ok_or_else(no_space)?;
        held.state.set_next_admin(next);
        self.keep(&held.state)?;
        let mut offer = AdminOffer {
            device: me,
            key: next.0,
            hardware: next.1,
            verified_boot: next.2,
            signature: [0; 64],
        };
        offer.signature = held
            .light
            .sync_key()
            .sign(&offer.message(&identity, &admin))
            .to_bytes();
        Ok(offer.to_bytes())
    }

    /// `replace_admin_of`: another device's admin key replaced by the one
    /// its code offers, signed by this device's admin key once the user
    /// approves it (the code's key check beside the other device's): the
    /// agent takes it from a seasoned device other than the one replaced,
    /// the new key on its probation.
    pub fn replace_admin_of(&self, prompts: Lent<'_>, code: &[u8]) -> Result<Posted, Refusal> {
        let offer = AdminOffer::from_bytes(code)
            .ok_or_else(|| refused(Refused::Arguments, "that is no device's admin-key code"))?;
        let label = {
            let mut held = self.held();
            let group = held.group.as_ref().ok_or_else(no_space)?;
            if group.id() == Some(offer.device) {
                return Err(refused(
                    Refused::Refused,
                    "the personal agent refused: Targeted (a device signs no replacement of its \
                     own key)",
                ));
            }
            let (_, identity) = held.state.agent.ok_or_else(no_space)?;
            let (_, sync) = group
                .sync_keys()
                .into_iter()
                .find(|(id, _)| *id == offer.device)
                .ok_or_else(|| {
                    refused(
                        Refused::Arguments,
                        "that device is not in the set as this device has read it: sync and \
                         try again",
                    )
                })?;
            let view = self
                .views(&mut held)?
                .into_iter()
                .find(|view| {
                    view.id == offer.device
                        && view.removal.is_none()
                        && view.standing != Standing::Removed
                })
                .ok_or_else(|| refused(Refused::Arguments, "no such device in the set"))?;
            // Signed by the offering device's sync key as this device's log
            // knows it, over its admin key as the set shows it: a code made
            // anywhere else, or before that key changed, is refused before
            // the user is asked.
            if !offer.verifies(&identity, &view.device.keys.admin, &sync) {
                return Err(refused(
                    Refused::Arguments,
                    "that admin-key code is not signed by the device it names, or is stale",
                ));
            }
            String::from_utf8_lossy(&view.device.keys.label).into_owned()
        };
        match prompts.confirm(Form {
            title: "Approve a new admin key".into(),
            detail: format!(
                "\"{label}\" asks to replace its admin key. Approve only if that device shows \
                 the same key check: the new key signs nothing until its probation ends."
            ),
            rows: vec![
                ("Device".into(), format!("{} ({label})", offer.device)),
                ("Key check".into(), offer.check()),
                (
                    "Key kept in".into(),
                    if offer.hardware {
                        "hardware"
                    } else {
                        "software"
                    }
                    .into(),
                ),
            ],
            fields: Vec::new(),
            notice: None,
            choices: vec!["Approve".into()],
        }) {
            Answer::Confirmed { .. } => {}
            Answer::Declined => return Err(declined()),
        }
        let admin = NewAdmin {
            key: offer.key,
            class: AdminClass::Strong,
            attestation: Attestation {
                hardware: offer.hardware,
                verified_boot: offer.verified_boot,
            },
        };
        self.operate(
            &mut self.held(),
            prompts,
            "replace",
            (offer.device, admin).encode(),
            None,
        )
    }

    /// `regroup`: the devices named removed and a new group started.
    pub fn regroup(&self, prompts: Lent<'_>, remove: Vec<u32>) -> Result<Posted, Refusal> {
        if remove.len() > super::MAX_REGROUP {
            return Err(crate::refused(
                crate::Code::Arguments,
                format!("a regroup names at most {} devices", super::MAX_REGROUP),
            ));
        }
        self.operate(&mut self.held(), prompts, "regroup", remove.encode(), None)
    }

    /// `update`: a commit now, carrying every matured removal and this
    /// device's leaf update; the yearly prompt's. After a matured regroup
    /// it is the regrouper's new group, with the key packages every device
    /// it keeps handed over ([`regroup`]); a kept device hands its own over
    /// and makes no commit.
    pub fn update(&self, prompts: Lent<'_>) -> Result<(), Refusal> {
        let mut held = self.held();
        // What fell due settled first, so the log shows every matured
        // removal the commit must carry.
        self.wake(&mut held)?;
        self.settle(&mut held)?;
        self.follow(&mut held)?;
        self.drop_unsent(&mut held)?;
        let group = held.group.as_ref().ok_or_else(no_space)?;
        let prepared = match group.regrouper() {
            Some(regrouper) if Some(regrouper) == group.id() => {
                let packages = self.handed_over(&mut held)?;
                let group = held.group.as_mut().ok_or_else(no_space)?;
                group.regroup(packages, now_ms())
            }
            Some(regrouper) => {
                if !self.hand_over_now(&mut held)? {
                    return Err(refused(
                        Refused::Refused,
                        format!(
                            "this device is out of device {regrouper}'s regroup, or cannot follow \
                             the group: it re-pairs once the new group is made"
                        ),
                    ));
                }
                return Err(refused(
                    Refused::Refused,
                    format!(
                        "device {regrouper}'s regroup starts the new group: this device \
                         handed it its key package, and joins the new group once that device \
                         commits it"
                    ),
                ));
            }
            None => held
                .group
                .as_mut()
                .ok_or_else(no_space)?
                .commit(None, now_ms()),
        }
        .map_err(failed)?;
        self.commit(&mut held, prompts, &prepared)?;
        for _ in 0..3 {
            self.follow(&mut held)?;
        }
        Ok(())
    }

    /// `renew`: the yearly re-proof at the home under this device's
    /// nullifier, then the leaf's update on the same prompt.
    pub fn renew(&self, prompts: Lent<'_>) -> Result<(), Refusal> {
        let held = self.held();
        let (kept, agent) = (
            held.state.home.clone().ok_or_else(no_space)?,
            held.state.agent.ok_or_else(no_space)?,
        );
        let reference = reference(&held.state).ok_or_else(no_space)?;
        if held.state.claim_due.is_some() {
            return Err(refused(
                Refused::Refused,
                "this device's membership at the home is not made yet: the background job makes \
                 it within hours of the pairing",
            ));
        }
        drop(held);
        let home = &kept.home;
        let secret = secret(prompts, &reference, &home.handle)?;
        let member = vos_light::member(&secret).to_bytes();
        let witness = self.home_witness(home, &member)?;
        let now = self.time(home.handle, Purpose::Fetch)?;
        let call = home::renew_call(home, agent.0, now + EXPIRY_MS).map_err(failed)?;
        self.prove_home::<()>(home, secret, witness, call)?
            .map_err(|error| {
                refused(
                    Refused::Refused,
                    format!("`Homes` refused the re-proof: {error:?}"),
                )
            })?;
        self.update(prompts)
    }

    // ----- the kit -----

    /// `restore`: a fresh device's restore from the kit at `home`: the
    /// agent the kit's index names, a new kit split for it, the restore
    /// signed by the kit. It matures after the kit's delay unless a device
    /// of the set answers `alive`; then [`Space::restored`]. What the
    /// restore makes is kept before its call: called again with the kit, a
    /// restore cut short is resumed, its call sent if the agent never took
    /// it and its evidence posted, no new kit shown.
    pub fn restore(
        &self,
        prompts: Lent<'_>,
        request: Claim,
        old: KitKind,
    ) -> Result<Posted, Refusal> {
        let request = request.check()?;
        let mut held = self.held();
        if held.group.is_some() {
            return Err(refused(
                Refused::Refused,
                "this device holds a personal space already",
            ));
        }
        let kept = kept_of(&request.home);
        self.pin(&kept);
        let home = kept.home.clone();
        let kit = entered_kit(prompts, old)?;
        let signing = kit.signing();
        let mut session = Signer::new(signing.verifying_key().to_bytes());
        let mut resumed = match (&held.state.restoring, &held.state.home, held.state.agent) {
            (Some(_), Some(at), Some(agent)) if at.home.handle == home.handle => Some(agent),
            _ => None,
        };
        // A restore kept from before is resumed while the agent holds it
        // open; one cancelled since (an `alive`, a veto, no evidence) is
        // dropped, and a new one opened.
        let mut entries = Vec::new();
        if let Some(agent) = resumed
            && let Some(restoring) = held.state.restoring.clone()
            && restoring.signed.is_some()
        {
            let mut link = link(
                self.net(),
                &self.runtime,
                &kept,
                Purpose::Personal,
                agent,
                &signing,
                &mut session,
            );
            entries = link.log_all(0).map_err(unreached)?.map_err(agent_refused)?;
            if restore_cancelled(&entries, &restoring.arguments) {
                held.state.restoring = None;
                held.state.home = None;
                held.state.agent = None;
                self.keep(&held.state)?;
                resumed = None;
                entries.clear();
            }
        }
        let agent = match resumed {
            Some(agent) => agent,
            None => {
                let found: Option<u32> = self.home_query(
                    &home,
                    Purpose::Personal,
                    home.homes.0,
                    "find",
                    kit.index().encode(),
                )?;
                let agent = found.ok_or_else(|| {
                    refused(Refused::Refused, "the home holds no agent for this kit")
                })?;
                let agent = (agent, self.identity(&home, agent)?);
                // Every prompt that can refuse before the new kit is shown.
                let reference = self.source(prompts, &mut held)?;
                let secret = secret(prompts, &reference, &home.handle)?;
                let device = self.device(&mut held, prompts, &home, &secret, &request.label)?;
                let next = new_kit(prompts, request.kit, &kept)?;
                let split = vos_light::group::restoring(
                    held.light.store(),
                    &[next.key()],
                    &GroupAgent {
                        identity: agent.1,
                        instance: PERSONAL,
                    },
                )
                .map_err(failed)?;
                held.state.home = Some(kept.clone());
                held.state.agent = Some(agent);
                held.state.label = request.label;
                held.state.restoring =
                    Some(Restoring::new(&device, &split.kit, next.key(), *split.r2()));
                self.keep(&held.state)?;
                agent
            }
        };
        let mut link = link(
            self.net(),
            &self.runtime,
            &kept,
            Purpose::Personal,
            agent,
            &signing,
            &mut session,
        );
        let restoring = held.state.restoring.clone().ok_or_else(no_space)?;
        if entries.is_empty() && restoring.signed.is_some() {
            entries = link.log_all(0).map_err(unreached)?.map_err(agent_refused)?;
        }
        let taken = entries.iter().find_map(|(index, entry)| match &entry.body {
            Body::Operation { call, .. }
                if call.method == vos_light::method_id("restore")
                    && call.arguments == restoring.arguments =>
            {
                Some(Posted {
                    index: *index,
                    at: entry.at,
                })
            }
            _ => None,
        });
        let (posted, message, signature) = match (taken, &restoring.signed) {
            (Some(posted), Some((message, signature))) => (posted, message.clone(), *signature),
            _ => {
                let sign = |message: &[u8]| Ok(signing.sign(message).to_bytes());
                let mut kit_signer = Signer::new(signing.verifying_key().to_bytes());
                // The call as signed is kept before it leaves, so a
                // restart finds it in the log and posts its evidence.
                let mut hold = |message: &[u8], signature: &[u8; 64]| {
                    if let Some(restoring) = held.state.restoring.as_mut() {
                        restoring.signed = Some((message.to_vec(), *signature));
                    }
                    self.keep(&held.state).map_err(|refusal| refusal.message)
                };
                let called = link
                    .settled_held(
                        &mut kit_signer,
                        &sign,
                        "restore",
                        restoring.arguments.clone(),
                        &mut hold,
                    )
                    .map_err(unreached)?;
                let recorded = answer::<Recorded>(&called.outcome)
                    .map_err(failed)?
                    .map_err(agent_refused)?;
                let posted = Posted {
                    index: recorded.index,
                    at: recorded.at,
                };
                (posted, called.message, called.signature)
            }
        };
        let evidenced = entries.iter().any(|(_, entry)| {
            matches!(&entry.body, Body::Evidence { index, .. } if *index == posted.index)
        });
        if let (false, Some(r2)) = (evidenced, restoring.r2) {
            evidence(
                &mut link,
                posted.index,
                (&message, &signature),
                Attached {
                    welcome: None,
                    r2: Some(r2),
                },
            )?;
        }
        if let Some(restoring) = held.state.restoring.as_mut() {
            restoring.r2 = None;
        }
        self.keep(&held.state)?;
        Ok(posted)
    }

    /// `restored`: the restore matured: the kit entered again opens `R1`,
    /// the archive recovered from the recovery scope, the device's group
    /// started from what the agent holds, the personal space read back.
    pub fn restored(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Claimed, Refusal> {
        let mut held = self.held();
        let (kept, agent) = (
            held.state.home.clone().ok_or_else(no_space)?,
            held.state.agent.ok_or_else(no_space)?,
        );
        let (next, r_hash) = held
            .state
            .restoring
            .as_ref()
            .map(|restoring| (restoring.next, restoring.r_hash))
            .ok_or_else(|| refused(Refused::Refused, "no restore is pending"))?;
        let kit = entered_kit(prompts, kind)?;
        let signing = kit.signing();
        let mut kit_signer = Signer::new(signing.verifying_key().to_bytes());
        {
            let mut link = link(
                self.net(),
                &self.runtime,
                &kept,
                Purpose::Personal,
                agent,
                &signing,
                &mut kit_signer,
            );
            link.wake().map_err(unreached)?.map_err(agent_refused)?;
        }
        let key = held.light.sync_key().clone();
        let mut sync = held.sync;
        let (view, envelopes, overview, devices) = {
            let mut link = link(
                self.net(),
                &self.runtime,
                &kept,
                Purpose::Personal,
                agent,
                &key,
                &mut sync,
            );
            for _ in 0..WAKES {
                let woken = link.wake().map_err(unreached)?.map_err(agent_refused)?;
                if woken.settled {
                    break;
                }
            }
            let view: RecoveryView = link
                .query("recovery", ())
                .map_err(unreached)?
                .map_err(agent_refused)?;
            let mut envelopes = Vec::new();
            loop {
                let after = envelopes
                    .last()
                    .map_or(0, |envelope: &vos_wire::personal::Envelope| {
                        envelope.position
                    });
                let page: Vec<vos_wire::personal::Envelope> = link
                    .query("since", (RECOVERY, after))
                    .map_err(unreached)?
                    .map_err(agent_refused)?;
                if page.is_empty() {
                    break;
                }
                envelopes.extend(page);
            }
            let overview: Overview = link
                .query("overview", ())
                .map_err(unreached)?
                .map_err(agent_refused)?;
            let devices: Vec<DeviceView> = link
                .query("devices", ())
                .map_err(unreached)?
                .map_err(agent_refused)?;
            (view, envelopes, overview, devices)
        };
        held.sync = sync;
        let archive = recover(&kit, &view, &agent.1, &envelopes)
            .ok_or_else(|| refused(Refused::Refused, "the kit opens no archive the agent holds"))?;
        let device = self.device_of(&held, &devices)?;
        let policy = vos_wire::personal::Policy::DEFAULT;
        let read = Restored {
            next: overview.next,
            chain: overview.chain,
            time: now_ms(),
            confirmed: overview.confirmed,
            policy,
            kit: vec![next],
            r_hash,
            devices,
        };
        let mut group = DeviceGroup::restore(
            held.light.store(),
            GroupAgent {
                identity: agent.1,
                instance: PERSONAL,
            },
            device,
            read,
        )
        .map_err(failed)?;
        group.inherit(&archive).map_err(failed)?;
        let id = group.id().unwrap_or(0);
        held.group = Some(group);
        held.state.restoring = None;
        self.keep(&held.state)?;
        self.follow(&mut held)?;
        drop(held);
        // Its first commit re-seals the kit under a new `R`.
        self.update(prompts)?;
        Ok(Claimed {
            agent: agent.0,
            device: id,
        })
    }

    /// This device's keys as the agent's set holds them.
    fn device_of(&self, held: &Held, devices: &[DeviceView]) -> Result<NewDevice, Refusal> {
        let sync = held.light.sync_key().verifying_key().to_bytes();
        devices
            .iter()
            .find(|view| view.device.keys.sync == sync)
            .map(|view| view.device.keys.clone())
            .ok_or_else(|| {
                refused(
                    Refused::Refused,
                    "the agent's set holds no device of this sync key",
                )
            })
    }

    // ----- moving home -----

    /// `move_home`: the personal space moved to another home: this
    /// device's open claim there, the agent its `Homes` names claimed with
    /// a new kit, a signed notice left at the old home for the other
    /// devices, the old group left and the new one started, then everything
    /// carried; the other devices pair again from this one.
    pub fn move_home(&self, prompts: Lent<'_>, request: Claim) -> Result<Moved, Refusal> {
        let request = request.check()?;
        let mut held = self.held();
        let kept = kept_of(&request.home);
        // A move whose carry was cut short is finished: no new kit, no
        // other agent.
        if moving::carrying(held.light.store()).map_err(failed)? {
            let agent = held.state.agent.ok_or_else(no_space)?;
            let carried = self.finish_move(&mut held)?;
            return Ok(Moved {
                agent: agent.0,
                carried,
            });
        }
        let pending = Move::pending(held.light.store()).map_err(failed)?;
        match (&pending, &held.state.bound) {
            (None, _) => {
                let group = held.group.as_ref().ok_or_else(no_space)?;
                if group.course() != vos_light::group::Course::Following {
                    return Err(refused(
                        Refused::Refused,
                        "this device does not follow its group: it moves nothing",
                    ));
                }
                if held
                    .state
                    .home
                    .as_ref()
                    .is_some_and(|at| at.home.handle == kept.home.handle)
                {
                    return Err(refused(
                        Refused::Refused,
                        "the personal space is at that home already",
                    ));
                }
                if moving::moving(held.light.store()).map_err(failed)?
                    || Claiming::pending(held.light.store())
                        .map_err(failed)?
                        .is_some()
                {
                    return Err(refused(Refused::Refused, "a move or a claim waits already"));
                }
            }
            (Some(_), Some(bound)) if bound.home.home.handle != kept.home.handle => {
                return Err(refused(
                    Refused::Refused,
                    "a move to another home is under way: move there again to finish it",
                ));
            }
            (Some(_), _) => {}
        }
        held.state.home.as_ref().ok_or_else(no_space)?;
        self.pin(&kept);
        let home = kept.home.clone();
        let reference = reference(&held.state).ok_or_else(no_space)?;
        let secret = secret(prompts, &reference, &home.handle)?;
        let member = vos_light::member(&secret).to_bytes();
        self.open_claim(&home, &member)?;
        let held_move = match pending {
            Some(held_move) => held_move,
            None => {
                let agent = self.pooled(&home)?;
                let label = held.state.label.clone();
                let mut device = self.device(&mut held, prompts, &home, &secret, &label)?;
                device.nullifier = home.nullifier(&secret);
                let kit = new_kit(prompts, request.kit, &kept)?;
                let group = held.group.as_ref().ok_or_else(no_space)?;
                Move::prepare(
                    &held.light,
                    group,
                    device,
                    vec![kit.key()],
                    agent.0,
                    agent.1,
                )
                .map_err(|error| refused(Refused::Refused, error.to_string()))?
            }
        };
        let agent = held_move.agent();
        held.state.bound = Some(Bound {
            home: kept.clone(),
            agent,
        });
        // This device's open claim at the new home is made: none owed at
        // the old one, which the space leaves.
        held.state.claim_due = None;
        self.keep(&held.state)?;
        let witness = self.home_witness(&home, &member)?;
        let now = self.time(home.handle, Purpose::Fetch)?;
        let call = held_move.call(&home, now + EXPIRY_MS).map_err(failed)?;
        match self.prove_home::<u32>(&home, secret, witness, call)? {
            Ok(_) | Err(HomesError::Claimed) => {}
            Err(error) => {
                held_move.abandon(held.light.store()).map_err(failed)?;
                held.state.bound = None;
                self.keep(&held.state)?;
                return Err(refused(
                    Refused::Refused,
                    format!("`Homes` refused the move: {error:?}"),
                ));
            }
        }
        // The notice at the old home, sealed under the old group's epoch,
        // unless a process cut short left that group already.
        if held.group.is_some() {
            let notice = held_move.notice(&home);
            self.with_link(&mut held, Purpose::Personal, |link, held| {
                let Held { light, group, .. } = held;
                let group = group.as_mut().ok_or_else(no_space)?;
                let mut sync = SealedSync::new(light, group, link, Vec::new()).map_err(failed)?;
                sync.announce(&notice).map(drop).map_err(failed)
            })?;
        }
        let entries = self.assigned(&mut held, &kept, agent)?;
        let old_group = held.group.take();
        let group = match held_move.claimed(&held.light, old_group, PERSONAL, &entries, now_ms()) {
            Ok(group) => group,
            Err(error) => {
                // The store's group, whichever the move left, held again.
                held.group = DeviceGroup::open(held.light.store()).ok().flatten();
                return Err(failed(error));
            }
        };
        held.group = Some(group);
        held.arrived();
        held.sync = Signer::new(held.light.sync_key().verifying_key().to_bytes());
        self.keep(&held.state)?;
        self.follow(&mut held)?;
        let carried = self.finish_move(&mut held)?;
        Ok(Moved {
            agent: agent.0,
            carried,
        })
    }

    /// Everything carried to the new home (`moving::finish`): what the
    /// archive and each scope hold that the new agent lacks.
    fn finish_move(&self, held: &mut Held) -> Result<u64, Refusal> {
        self.with_link(held, Purpose::Personal, |link, held| {
            let Held { light, group, .. } = held;
            let group = group.as_mut().ok_or_else(no_space)?;
            carry(light, group, link)?.ok_or_else(|| {
                refused(
                    Refused::Api,
                    "the move is not carried whole yet: sync again",
                )
            })
        })
    }
}

/// The carry of a move held in `light`'s store to the agent of `group`
/// (`moving::finish`), if one waits: the nodes pushed once all of it went
/// (none pushed when no move waits), or `None` while some waits.
pub(super) fn carry(
    light: &mut Light,
    group: &mut DeviceGroup,
    link: &mut AgentLink<'_>,
) -> Result<Option<u64>, Refusal> {
    if !moving::carrying(light.store()).map_err(failed)? {
        return Ok(Some(0));
    }
    let instances = light.instances().map_err(failed)?;
    let mut sync = SealedSync::new(light, group, link, instances).map_err(failed)?;
    let finished = moving::finish(&mut sync).map_err(failed)?;
    Ok(finished.done.then(|| {
        finished
            .scopes
            .iter()
            .map(|(_, _, carried)| carried.pushed.len() as u64)
            .sum()
    }))
}

/// Whether the restore whose arguments are `arguments` was cancelled, as
/// the log `entries` show it.
fn restore_cancelled(entries: &[(u64, Entry)], arguments: &[u8]) -> bool {
    let restore = vos_light::method_id("restore");
    let Some(at) = entries.iter().find_map(|(index, entry)| match &entry.body {
        Body::Operation { call, .. } if call.method == restore && call.arguments == arguments => {
            Some(*index)
        }
        _ => None,
    }) else {
        return false;
    };
    entries.iter().any(|(_, entry)| {
        matches!(
            &entry.body,
            Body::Settled { op, state: OpState::Cancelled { .. } } if *op == at
        )
    })
}

/// The evidence of the admin call at `index`, as signed (`message`,
/// `signature`), posted under the link's key.
fn evidence(
    link: &mut AgentLink<'_>,
    index: u64,
    (message, signature): (&[u8], &[u8; 64]),
    attached: Attached,
) -> Result<(), Refusal> {
    let arguments = ((index, message.to_vec()), (*signature, attached)).encode();
    link.call::<Recorded>("evidence", arguments)
        .map_err(unreached)?
        .map_err(agent_refused)
        .map(drop)
}

/// A registrar's outcome, done or its refusal.
fn registrar_done(outcome: &Outcome) -> Result<(), Refusal> {
    match outcome {
        Outcome::Done(_) => Ok(()),
        Outcome::Failed { detail, .. } => Err(refused(
            Refused::Refused,
            match CredentialError::decode_exact(detail) {
                Some(CredentialError::Enrollments) => {
                    "replacements spent; next year, or ask the registrar".into()
                }
                error => format!("the registrar refused: {error:?}"),
            },
        )),
        other => Err(failed(format!("the registrar answered {other:?}"))),
    }
}

impl State {
    /// The offered admin key `key`, if it is one.
    fn next_admin(&self, key: &[u8; 32]) -> Option<([u8; 32], bool, bool)> {
        self.next_admin.iter().find(|next| next.0 == *key).copied()
    }

    /// `next` offered too: any key offered may be the one signed in, so
    /// the last few are kept.
    fn set_next_admin(&mut self, next: ([u8; 32], bool, bool)) {
        const KEPT: usize = 4;
        self.next_admin.push(next);
        if self.next_admin.len() > KEPT {
            self.next_admin.remove(0);
        }
    }
}

/// A move's or a rejoin's refusal: a device that carries more authors than
/// its keys can name is refused, as nothing this device can retry fixes.
fn moved(error: moving::MoveError) -> Refusal {
    match error {
        moving::MoveError::Carried => refused(Refused::Refused, error.to_string()),
        error => failed(error),
    }
}
