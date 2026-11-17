// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The device's personal space (VOS's `light-node.md` §3), as the
//! facility serves it: `vos_light::space`'s flows over the facility's
//! client, prover and enrollments ([`Reach`]), the chrome's prompts in
//! their forms ([`Asked`]), the interface's types converted at the
//! boundary and each flow's error a [`Refusal`]. The orchestration is
//! `vos-light`'s; nothing of it is here.

pub mod contract;

use std::path::Path;
use std::sync::Arc;

use vos_abi::ids::InstanceId;
use vos_light::group::Alarm;
use vos_light::route::{Purpose, Route};
use vos_light::space::{self, AdminKey, Approval, Card, Enrolled, Error, Host, Proof};
use vos_light::wire;
use vos_wire::credentials::Onion;
use zeroize::Zeroizing;

use crate::job::{Passed, Personal};
use crate::net::Pinned;
use crate::node::Prompts;
use crate::session::Inner;
use crate::source::{Kind, Reference};
use crate::{Answer, Code, Facility, Field, Form, Refusal, refused};
use s4_credential_contract::KeyAnswer;

pub use contract::{
    Claim, Claimed, Device, Home, KitKind, MAX_LABEL, Membership, Notice, Owed, PairCode, Paired,
    Pending, Posted, Seen, Synced, label,
};
pub use vos_light::space::{AdminOffer, Artifacts, CREDENTIAL_BOOK, DEVICE_BOOK, LIGHT, PERSONAL};

/// The light node's artifacts this crate embeds (`just facility-release`):
/// the default agent's program, and the local actors' packages.
pub fn embedded() -> Artifacts {
    Artifacts {
        agent: include_bytes!("../../release/agent.program").to_vec(),
        books: vec![
            (
                CREDENTIAL_BOOK,
                include_bytes!("../../release/credential-book.package").to_vec(),
            ),
            (
                DEVICE_BOOK,
                include_bytes!("../../release/device-book.package").to_vec(),
            ),
        ],
    }
}

/// A removed device whose leaf a retirement revokes in each space.
pub type Removal = u32;

/// The facility as the personal space's host: requests over its client on
/// its runtime, proofs on its prover one at a time, its enrollments.
pub struct Reach {
    facility: Facility,
    runtime: tokio::runtime::Handle,
}

impl Host for Reach {
    fn request(
        &self,
        space: &[u8; 32],
        purpose: Purpose,
        request: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.runtime
            .block_on(self.facility.net().request(*space, purpose, request))
    }

    fn pin(&self, home: &[u8; 32], onions: &[Onion]) {
        self.facility.net().pin(
            *home,
            Pinned {
                onions: onions.to_vec(),
                clearnet: None,
                onion_only: true,
            },
        );
    }

    fn route(&self, space: &[u8; 32], purpose: Purpose) -> Route {
        match self.facility.net().client().routes(space) {
            Some(routes) => routes.route(purpose).unwrap_or(Route::Clearnet),
            None => Route::Clearnet,
        }
    }

    fn prove(&self, proof: Proof) -> Result<Vec<u8>, Error> {
        let inner = Arc::clone(self.facility.inner());
        let proved = match proof {
            Proof::Home {
                secret,
                witness,
                call,
            } => self.runtime.block_on(Inner::prove(
                &inner,
                |stock| &stock.auth,
                move |prover, program| {
                    let proof = prover.prove_home(&secret, &witness, &call, program);
                    drop(secret);
                    proof.map(|proof| wire::credentialed(&call, &proof))
                },
            )),
            Proof::Owner { secret, call } => self.runtime.block_on(Inner::prove(
                &inner,
                |stock| &stock.owner,
                move |prover, program| {
                    let proof = prover.prove_owner(&secret, &call, program);
                    drop(secret);
                    proof.map(|proof| wire::credentialed(&call, &proof))
                },
            )),
        };
        proved.map_err(|refusal| match refusal.code {
            Code::Refused => Error::Update,
            _ => Error::Prove(refusal.message),
        })
    }

    fn enrollments(&self) -> Result<Vec<Enrolled>, String> {
        Ok(self
            .facility
            .inner()
            .store
            .all()?
            .into_iter()
            .map(|enrollment| Enrolled {
                space: enrollment.space,
                handle: enrollment.handle,
                member: enrollment.member,
                owner: enrollment.owner,
                source: enrollment.source.to_bytes(),
                credentials: (
                    enrollment.credentials.agent,
                    enrollment.credentials.instance,
                ),
                agents: enrollment
                    .agents
                    .iter()
                    .map(|agent| (agent.agent, agent.identity))
                    .collect(),
            })
            .collect())
    }

    fn now(&self) -> u64 {
        crate::job::now_ms()
    }
}

/// The chrome's prompts, lent to one flow, as the personal space asks
/// them: each kit shown and entered in a form, each key's use the UI's.
pub struct Asked<'a>(pub &'a dyn Prompts);

/// The kit's card's rows: the home's handle and each onion with its SSH
/// host key.
fn card_rows(card: &Card) -> Vec<(String, String)> {
    let mut rows = vec![("Home".to_owned(), hex::encode(card.handle))];
    for (at, onion) in card.onions.iter().enumerate() {
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

/// A key's answer, its bytes or why there are none.
fn key_answer(answer: KeyAnswer) -> Result<Zeroizing<Vec<u8>>, Error> {
    match answer {
        KeyAnswer::Done(bytes) => Ok(bytes),
        KeyAnswer::Declined => Err(Error::Declined),
        KeyAnswer::Failed(message) => Err(Error::Source(message)),
    }
}

/// 32 bytes of a key's answer.
fn thirty_two(answer: KeyAnswer, what: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    let bytes = key_answer(answer)?;
    let mut out = Zeroizing::new([0; 32]);
    if bytes.len() != 32 {
        return Err(Error::Source(format!("{what} is not 32 bytes")));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

impl Asked<'_> {
    fn shown(&self, form: Form) -> bool {
        matches!(self.0.confirm(form), Answer::Confirmed { .. })
    }
}

impl space::Prompts for Asked<'_> {
    fn show_phrase(&self, words: &str, card: &Card) -> bool {
        let rows = words
            .split(' ')
            .enumerate()
            .map(|(at, word)| (format!("{}", at + 1), word.to_owned()))
            .chain(card_rows(card))
            .collect();
        self.shown(Form {
            title: "Your recovery phrase".into(),
            detail: "Write these 24 words down, in order, with the card below them, and keep \
                     them apart from this phone. They restore your personal space at this home \
                     if every device is lost; this is the only time they are shown."
                .into(),
            rows,
            fields: Vec::new(),
            notice: None,
            choices: vec!["I wrote them down".into()],
        })
    }

    fn show_card(&self, card: &Card) -> bool {
        self.shown(Form {
            title: "Your recovery key's card".into(),
            detail: "Write this card down and keep it with the security key: it names the home \
                     a restore with the key goes to."
                .into(),
            rows: card_rows(card),
            fields: Vec::new(),
            notice: None,
            choices: vec!["I wrote it down".into()],
        })
    }

    fn enter_phrase(&self) -> Option<Zeroizing<String>> {
        let answer = self.0.confirm(Form {
            title: "Enter your recovery phrase".into(),
            detail: "The 24 words you wrote down, in order, separated by spaces.".into(),
            rows: Vec::new(),
            fields: vec![Field {
                label: "Words".into(),
                value: String::new(),
            }],
            notice: None,
            choices: vec!["Restore".into()],
        });
        match answer {
            Answer::Confirmed { values, .. } => Some(Zeroizing::new(values.join(" "))),
            Answer::Declined => None,
        }
    }

    fn approve_admin(&self, approval: &Approval) -> bool {
        let label = &approval.label;
        self.shown(Form {
            title: "Approve a new admin key".into(),
            detail: format!(
                "\"{label}\" asks to replace its admin key. Approve only if that device shows \
                 the same key check: the new key signs nothing until its probation ends."
            ),
            rows: vec![
                ("Device".into(), format!("{} ({label})", approval.device)),
                ("Key check".into(), approval.check.clone()),
                (
                    "Key kept in".into(),
                    if approval.hardware {
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
        })
    }

    fn create_source(&self) -> Result<Vec<u8>, Error> {
        let key = key_answer(self.0.create_key(Kind::Keystore))?;
        Reference::from_bytes(&[&[Kind::Keystore as u8], &key[..]].concat())
            .map(|reference| reference.to_bytes())
            .ok_or_else(|| Error::Source("the source's key handle".into()))
    }

    fn evaluate_source(
        &self,
        source: &[u8],
        input: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, Error> {
        let reference = Reference::from_bytes(source)
            .ok_or_else(|| Error::Source("the source's key handle".into()))?;
        let bytes = reference.to_bytes();
        thirty_two(
            self.0.evaluate_key(reference.kind(), &bytes[1..], input),
            "the source's output",
        )
    }

    fn create_kit_key(&self) -> Result<Vec<u8>, Error> {
        key_answer(self.0.create_key(Kind::Kit)).map(|id| id.to_vec())
    }

    fn kit_secret(&self, id: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        thirty_two(
            self.0.evaluate_key(Kind::Kit, id, salt),
            "the security key's output",
        )
    }

    fn create_admin(&self) -> Result<AdminKey, Error> {
        let bytes = key_answer(self.0.create_key(Kind::Admin))?;
        let (key, flags) = bytes
            .split_first_chunk::<32>()
            .ok_or_else(|| Error::Source("the admin key's answer is short".into()))?;
        let flags = flags.first().copied().unwrap_or(0);
        Ok(AdminKey {
            key: *key,
            hardware: flags & 1 != 0,
            verified_boot: flags & 2 != 0,
        })
    }

    fn sign_admin(&self, key: &[u8; 32], message: &[u8]) -> Result<[u8; 64], Error> {
        let bytes = key_answer(self.0.sign_key(Kind::Admin, key, message))?;
        <[u8; 64]>::try_from(bytes.as_slice())
            .map_err(|_| Error::Source("a signature is 64 bytes".into()))
    }
}

/// A flow's error as the interface refuses it.
pub fn refusal(error: Error) -> Refusal {
    let code = match &error {
        Error::NoSpace | Error::NotEnrolled => Code::NotEnrolled,
        Error::Declined | Error::Cancelled => Code::Declined,
        Error::NotAKit
        | Error::NotAPairingCode
        | Error::NotAnOffer
        | Error::StaleOffer
        | Error::NotInSet
        | Error::NothingOwed => Code::Arguments,
        Error::Source(_) => Code::Source,
        Error::NoLeaf => Code::NoPath,
        Error::Unreachable(_) | Error::NotTakenYet | Error::NotJoinedYet => Code::Api,
        Error::Prove(_) => Code::Prove,
        Error::Store(_) | Error::NeedsRepair(_) => Code::Store,
        Error::Failed(_) | Error::UnknownAgent => Code::Failed,
        _ => Code::Refused,
    };
    refused(code, error.to_string())
}

fn kit(kind: KitKind) -> vos_wire::personal::KitKind {
    match kind {
        KitKind::Phrase => vos_wire::personal::KitKind::Phrase,
        KitKind::SecurityKey => vos_wire::personal::KitKind::SecurityKey,
    }
}

/// A claim as the chrome makes it, checked, as the personal space takes it.
fn claim(request: Claim) -> Result<space::Claim, Refusal> {
    let request = request.check()?;
    let home = request.home;
    Ok(space::Claim {
        home: space::Kept {
            home: vos_light::home::Home {
                space: home.space,
                handle: home.handle,
                agent: home.agent,
                identity: home.identity,
                homes: InstanceId(home.homes),
                credentials: InstanceId(home.credentials),
            },
            onions: crate::net::onions(&home.onions),
        },
        kit: kit(request.kit),
        label: request.label,
    })
}

fn claimed(claimed: space::Claimed) -> Claimed {
    Claimed {
        agent: claimed.agent,
        device: claimed.device,
    }
}

fn paired(paired: space::Paired) -> Paired {
    Paired {
        device: paired.device,
        memberships: paired.memberships,
    }
}

fn posted(posted: space::Posted) -> Posted {
    Posted {
        index: posted.index,
        at: posted.at,
    }
}

fn membership(membership: space::Membership) -> Membership {
    Membership {
        space: membership.space,
        handle: membership.handle,
        agent: membership.agent,
        instance: membership.instance,
        owed: match membership.owed {
            space::Owed::Enroll => Owed::Enroll,
            space::Owed::Confirm => Owed::Confirm,
        },
    }
}

fn of_membership(membership: Membership) -> space::Membership {
    space::Membership {
        space: membership.space,
        handle: membership.handle,
        agent: membership.agent,
        instance: membership.instance,
        owed: match membership.owed {
            Owed::Enroll => space::Owed::Enroll,
            Owed::Confirm => space::Owed::Confirm,
        },
    }
}

/// The device's personal space, as the facility serves it.
pub struct Space(space::Personal<Reach>);

/// The prompts a flow is lent.
pub type Lent<'a> = &'a dyn Prompts;

/// A shared space, as the node holds it.
pub type Shared = Arc<Space>;

impl Space {
    /// The personal space under `directory` (the facility's), its light
    /// node opened from `artifacts`, its homes' routes told to the
    /// facility's client. One this build does not read is refused as in
    /// need of repair, and left as it is.
    pub fn open(
        directory: &Path,
        artifacts: &Artifacts,
        facility: Facility,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, Refusal> {
        space::Personal::open(directory, artifacts, Reach { facility, runtime })
            .map(Space)
            .map_err(refusal)
    }

    pub fn grouped(&self) -> bool {
        self.0.grouped()
    }

    #[doc(hidden)]
    pub fn set_wait(&self, ms: u64) {
        self.0.set_wait(ms);
    }

    pub fn scope_key(&self, name: &[u8]) -> Result<[u8; 32], Refusal> {
        self.0.scope_key(name).map_err(refusal)
    }

    #[doc(hidden)]
    pub fn recorded(&self, device: u32) -> usize {
        self.0.recorded(device)
    }

    pub fn sync_key(&self) -> [u8; 32] {
        self.0.sync_key()
    }

    pub fn claim(&self, prompts: Lent<'_>, request: Claim) -> Result<Claimed, Refusal> {
        let request = claim(request)?;
        self.0
            .claim(&Asked(prompts), request)
            .map(claimed)
            .map_err(refusal)
    }

    pub fn pair_offer(&self, _prompts: Lent<'_>) -> Result<PairCode, Refusal> {
        let code = self.0.pair_offer().map_err(refusal)?;
        Ok(PairCode {
            code: code.code,
            expires_ms: code.expires_ms,
        })
    }

    pub fn pair_await(&self, prompts: Lent<'_>) -> Result<Paired, Refusal> {
        self.0
            .pair_await(&Asked(prompts))
            .map(paired)
            .map_err(refusal)
    }

    pub fn pair_cancel(&self) {
        self.0.pair_cancel();
    }

    pub fn pair_join(
        &self,
        prompts: Lent<'_>,
        code: &[u8],
        label: &str,
    ) -> Result<Paired, Refusal> {
        contract::label(label)?;
        self.0
            .pair_join(&Asked(prompts), code, label)
            .map(paired)
            .map_err(refusal)
    }

    pub fn memberships(&self) -> Result<Vec<Membership>, Refusal> {
        let all = self.0.memberships().map_err(refusal)?;
        Ok(all.into_iter().map(membership).collect())
    }

    pub fn enroll_device(&self, prompts: Lent<'_>, owed: Membership) -> Result<(), Refusal> {
        self.0
            .enroll_device(&Asked(prompts), of_membership(owed))
            .map_err(refusal)
    }

    pub fn confirm_device(&self, prompts: Lent<'_>, owed: Membership) -> Result<(), Refusal> {
        self.0
            .confirm_device(&Asked(prompts), of_membership(owed))
            .map_err(refusal)
    }

    pub fn drop_enrollment(&self, owed: Membership) -> Result<(), Refusal> {
        self.0.drop_enrollment(of_membership(owed)).map_err(refusal)
    }

    pub fn revoke(&self, prompts: Lent<'_>, device: Removal) -> Result<u32, Refusal> {
        self.0.revoke(&Asked(prompts), device).map_err(refusal)
    }

    pub fn devices(&self) -> Result<Vec<Device>, Refusal> {
        let all = self.0.devices().map_err(refusal)?;
        Ok(all
            .into_iter()
            .map(|device| Device {
                id: device.id,
                label: device.label,
                strong: device.strong,
                standing: device.standing as u8,
                seen: device.seen,
                removed: device.removed,
                me: device.me,
            })
            .collect())
    }

    pub fn operations(&self) -> Result<Vec<Notice>, Refusal> {
        let open = self.0.operations().map_err(refusal)?;
        Ok(open.into_iter().map(crate::job::notice).collect())
    }

    pub fn remove(&self, prompts: Lent<'_>, device: u32) -> Result<Posted, Refusal> {
        self.0
            .remove(&Asked(prompts), device)
            .map(posted)
            .map_err(refusal)
    }

    pub fn veto(&self, prompts: Lent<'_>, index: u64) -> Result<Posted, Refusal> {
        self.0
            .veto(&Asked(prompts), index)
            .map(posted)
            .map_err(refusal)
    }

    pub fn cosign(&self, prompts: Lent<'_>, index: u64) -> Result<Posted, Refusal> {
        self.0
            .cosign(&Asked(prompts), index)
            .map(posted)
            .map_err(refusal)
    }

    pub fn resolve(&self, prompts: Lent<'_>, index: u64, upheld: bool) -> Result<Posted, Refusal> {
        self.0
            .resolve(&Asked(prompts), index, upheld)
            .map(posted)
            .map_err(refusal)
    }

    pub fn rotate_kit(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Posted, Refusal> {
        self.0
            .rotate_kit(&Asked(prompts), kit(kind))
            .map(posted)
            .map_err(refusal)
    }

    pub fn replace_admin(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Posted, Refusal> {
        self.0
            .replace_admin(&Asked(prompts), kit(kind))
            .map(posted)
            .map_err(refusal)
    }

    pub fn admin_offer(&self, prompts: Lent<'_>) -> Result<Vec<u8>, Refusal> {
        self.0.admin_offer(&Asked(prompts)).map_err(refusal)
    }

    pub fn replace_admin_of(&self, prompts: Lent<'_>, code: &[u8]) -> Result<Posted, Refusal> {
        self.0
            .replace_admin_of(&Asked(prompts), code)
            .map(posted)
            .map_err(refusal)
    }

    pub fn regroup(&self, prompts: Lent<'_>) -> Result<Posted, Refusal> {
        self.0.regroup(&Asked(prompts)).map(posted).map_err(refusal)
    }

    pub fn update(&self, prompts: Lent<'_>) -> Result<(), Refusal> {
        self.0.update(&Asked(prompts)).map_err(refusal)
    }

    pub fn restore(
        &self,
        prompts: Lent<'_>,
        request: Claim,
        old: KitKind,
    ) -> Result<Posted, Refusal> {
        let request = claim(request)?;
        self.0
            .restore(&Asked(prompts), request, kit(old))
            .map(posted)
            .map_err(refusal)
    }

    pub fn restored(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Claimed, Refusal> {
        self.0
            .restored(&Asked(prompts), kit(kind))
            .map(claimed)
            .map_err(refusal)
    }

    pub fn move_home(&self, prompts: Lent<'_>, request: Claim) -> Result<Claimed, Refusal> {
        let request = claim(request)?;
        self.0
            .move_home(&Asked(prompts), request)
            .map(claimed)
            .map_err(refusal)
    }
}

impl Personal for Space {
    fn pass(&self, now: u64, _runtime: &tokio::runtime::Handle) -> Result<Passed, String> {
        let passed = self.0.pass(now).map_err(|error| error.to_string())?;
        Ok(Passed {
            notices: passed.notices.into_iter().map(crate::job::notice).collect(),
            alarms: passed.alarms,
            seen: passed
                .seen
                .into_iter()
                .map(|(device, at)| Seen { device, at })
                .collect(),
            stopped: passed.stopped,
        })
    }

    fn acknowledge(&self, alarms: &[Alarm]) -> Result<(), String> {
        self.0
            .acknowledge_alarms(alarms)
            .map_err(|error| error.to_string())
    }
}

impl crate::session::Paired for Space {
    fn owed_source(&self, handle: &[u8; 32]) -> Result<Option<Reference>, String> {
        match self
            .0
            .owed_source(handle)
            .map_err(|error| error.to_string())?
        {
            None => Ok(None),
            Some(bytes) => Reference::from_bytes(&bytes)
                .map(Some)
                .ok_or_else(|| "a confirmation is owed with no source kept".into()),
        }
    }

    fn enrolled(&self) {
        self.0.enrolled();
    }
}
