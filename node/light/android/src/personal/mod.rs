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

use vos_wire::credentials::Onion;
use zeroize::Zeroizing;

use crate::job::{Passed, Personal};
use crate::net::Pinned;
use crate::node::Prompts;
use crate::session::{Inner, Kernel};
use crate::source::{Kind, Reference};
use crate::{Answer, Code, Facility, Field, Form};
use s4_credential_contract::KeyAnswer;

pub use contract::{
    Claim, Claimed, Device, Home, KitKind, KitView, MAX_LABEL, Membership, Notice, Owed, PairCode,
    Paired, Pending, PersonalStatus, Phase, Posted, Refused, Seen, Synced, Tor, Why, label,
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

    fn requests(
        &self,
        space: &[u8; 32],
        purpose: Purpose,
        requests: &[Vec<u8>],
    ) -> Vec<Result<Vec<u8>, String>> {
        self.runtime
            .block_on(self.facility.net().requests(*space, purpose, requests))
    }

    fn fetch_timed(
        &self,
        space: &[u8; 32],
        query: &mut dyn FnMut(u64) -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, String> {
        self.runtime
            .block_on(self.facility.net().client().fetch_timed(*space, |now| {
                query(now).map_err(vos_light::tor::Error::Query)
            }))
            .map(|(_, body)| body)
            .map_err(|error| error.to_string())
    }

    fn prepare(&self, space: &[u8; 32], purpose: Purpose) {
        let (client, space) = (self.facility.net().client().clone(), *space);
        self.runtime.spawn(async move {
            let _ = client.prepare(space, purpose).await;
        });
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
                Kernel::Auth,
                call,
                move |prover, program, call| {
                    let proof = prover.prove_home(&secret, &witness, call, program);
                    drop(secret);
                    proof
                },
            )),
            Proof::Owner { secret, call } => self.runtime.block_on(Inner::prove(
                &inner,
                Kernel::Owner,
                call,
                move |prover, program, call| {
                    let proof = prover.prove_owner(&secret, call, program);
                    drop(secret);
                    proof
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
    fn show_phrase(&self, words: &str, card: &Card, void: Option<&str>) -> bool {
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
            notice: void.map(str::to_owned),
            choices: vec!["I wrote them down".into()],
        })
    }

    fn show_card(&self, card: &Card, void: Option<&str>) -> bool {
        self.shown(Form {
            title: "Your recovery key's card".into(),
            detail: "Write this card down and keep it with the security key: it names the home \
                     a restore with the key goes to."
                .into(),
            rows: card_rows(card),
            fields: Vec::new(),
            notice: void.map(str::to_owned),
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

    fn confirm_pairing(&self, check: &str) -> bool {
        self.shown(Form {
            title: "Pair a new device".into(),
            detail: "Confirm only if the new device shows this same check. Someone else who saw \
                     the code would show another, and would be given your keys."
                .into(),
            rows: vec![("Check".into(), check.to_owned())],
            fields: Vec::new(),
            notice: None,
            choices: vec!["It shows the same".into()],
        })
    }

    fn show_pairing(&self, check: &str) -> bool {
        self.shown(Form {
            title: "Pairing".into(),
            detail: "Your other device asks you to confirm this check. Go on once it is confirmed \
                     there."
                .into(),
            rows: vec![("Check".into(), check.to_owned())],
            fields: Vec::new(),
            notice: None,
            choices: vec!["Go on".into()],
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

/// Why `error`, as the screens branch on it: its kind, a time or a
/// device it names, and the inner error's name or the failure's detail.
impl From<Error> for Refused {
    fn from(error: Error) -> Self {
        let why = |why| Refused {
            why,
            ..Refused::default()
        };
        let detailed = |kind, detail: String| Refused {
            why: kind,
            detail,
            ..Refused::default()
        };
        match error {
            Error::NoSpace => why(Why::NoSpace),
            Error::AlreadyHeld => why(Why::AlreadyHeld),
            Error::HoldsKeys => why(Why::HoldsKeys),
            Error::ClaimElsewhere { home } => detailed(Why::ClaimElsewhere, hex::encode(home)),
            Error::AtThatHome => why(Why::AtThatHome),
            Error::NoRestore => why(Why::NoRestore),
            Error::NoPairing => why(Why::NoPairing),
            Error::NeedsRepair(detail) => detailed(Why::NeedsRepair, detail),
            Error::Declined => why(Why::Declined),
            Error::Cancelled => why(Why::Cancelled),
            Error::NotAKit => why(Why::NotAKit),
            Error::WrongKit => why(Why::WrongKit),
            Error::NotAPairingCode => why(Why::NotAPairingCode),
            Error::NotAnOffer => why(Why::NotAnOffer),
            Error::StaleOffer => why(Why::StaleOffer),
            Error::OwnKey => why(Why::OwnKey),
            Error::NotInSet => why(Why::NotInSet),
            Error::Source(detail) => detailed(Why::Source, detail),
            Error::NoOpenClaim => why(Why::NoOpenClaim),
            Error::OpenClaimRefused(detail) => detailed(Why::OpenClaimRefused, detail),
            Error::NoAgentToGive => why(Why::NoAgentToGive),
            Error::NoAgentForKit => why(Why::NoAgentForKit),
            Error::HoldsAgentThere => why(Why::HoldsAgentThere),
            Error::UnknownAgent => why(Why::UnknownAgent),
            Error::NoLeaf => why(Why::NoLeaf),
            Error::HomeRefused(error) => detailed(Why::HomeRefused, format!("{error:?}")),
            Error::Update => why(Why::Update),
            Error::Rejected(detail) => detailed(Why::Rejected, detail),
            Error::AgentRefused(error) => detailed(Why::AgentRefused, format!("{error:?}")),
            Error::NotTakenYet => why(Why::NotTakenYet),
            Error::NotJoinedYet => why(Why::NotJoinedYet),
            Error::AwaitsVotes => why(Why::AwaitsVotes),
            Error::Undecided => why(Why::Undecided),
            Error::CommitVoid => why(Why::CommitVoid),
            Error::CommittedMeanwhile => why(Why::CommittedMeanwhile),
            Error::SlotExpired => why(Why::SlotExpired),
            Error::PairingDeclined => why(Why::PairingDeclined),
            Error::InSetAlready => why(Why::InSetAlready),
            Error::NotInAgentSet => why(Why::NotInAgentSet),
            Error::Regrouped { by } => Refused {
                why: Why::Regrouped,
                device: by,
                ..Refused::default()
            },
            Error::DelayedAdmin => why(Why::DelayedAdmin),
            Error::NotEnrolled => why(Why::NotEnrolled),
            Error::NothingOwed => why(Why::NothingOwed),
            Error::Spent => why(Why::Spent),
            Error::RegistrarRefused(error) => detailed(
                Why::RegistrarRefused,
                error.map(|error| format!("{error:?}")).unwrap_or_default(),
            ),
            Error::Unreachable(detail) => detailed(Why::Unreachable, detail),
            Error::Prove(detail) => detailed(Why::Prove, detail),
            Error::Store(detail) => detailed(Why::Store, detail),
            Error::Failed(detail) => detailed(Why::Failed, detail),
        }
    }
}

impl From<KitKind> for vos_wire::personal::KitKind {
    fn from(kind: KitKind) -> Self {
        match kind {
            KitKind::Phrase => Self::Phrase,
            KitKind::SecurityKey => Self::SecurityKey,
        }
    }
}

/// A claim as the chrome makes it, checked, as the personal space takes it.
fn claim(request: Claim) -> Result<space::Claim, Refused> {
    let request = request.check()?;
    Ok(space::Claim {
        home: request.home.into(),
        kit: request.kit.into(),
        label: request.label,
    })
}

/// A home as the chrome names it, checked ([`Home::check`]): as the
/// personal space reaches it.
impl From<Home> for space::Kept {
    fn from(home: Home) -> Self {
        Self {
            home: vos_light::home::Home {
                space: home.space,
                handle: home.handle,
                agent: home.agent,
                identity: home.identity,
                homes: InstanceId(home.homes),
                credentials: InstanceId(home.credentials),
            },
            onions: crate::net::onions(&home.onions),
        }
    }
}

/// A kept home as the chrome names it.
impl From<space::Kept> for Home {
    fn from(kept: space::Kept) -> Self {
        Self {
            space: kept.home.space,
            handle: kept.home.handle,
            agent: kept.home.agent,
            identity: kept.home.identity,
            homes: kept.home.homes.0,
            credentials: kept.home.credentials.0,
            onions: kept
                .onions
                .iter()
                .map(|onion| s4_credential_contract::Onion {
                    key: onion.key,
                    ssh_host_key: onion.ssh_host_key,
                })
                .collect(),
        }
    }
}

impl From<space::Device> for Device {
    fn from(device: space::Device) -> Self {
        Self {
            id: device.id,
            label: device.label,
            strong: device.strong,
            standing: device.standing as u8,
            seen: device.seen,
            removed: device.removed,
            me: device.me,
        }
    }
}

impl From<space::Claimed> for Claimed {
    fn from(claimed: space::Claimed) -> Self {
        Self {
            agent: claimed.agent,
            device: claimed.device,
        }
    }
}

impl From<space::Paired> for Paired {
    fn from(paired: space::Paired) -> Self {
        Self {
            device: paired.device,
            memberships: paired.memberships,
        }
    }
}

impl From<space::Posted> for Posted {
    fn from(posted: space::Posted) -> Self {
        Self {
            index: posted.index,
            at: posted.at,
        }
    }
}

impl From<space::Membership> for Membership {
    fn from(membership: space::Membership) -> Self {
        Self {
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
}

impl From<Membership> for space::Membership {
    fn from(membership: Membership) -> Self {
        Self {
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
}

/// The device's personal space, as the facility serves it.
pub struct Space(space::Personal<Reach>);

/// The prompts a flow is lent.
pub type Lent<'a> = &'a dyn Prompts;

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
    ) -> Result<Self, Refused> {
        space::Personal::open(directory, artifacts, Reach { facility, runtime })
            .map(Space)
            .map_err(Refused::from)
    }

    pub fn grouped(&self) -> bool {
        self.0.grouped()
    }

    /// Whether a flow returned with follows left for after it.
    pub fn behind(&self) -> bool {
        self.0.behind()
    }

    /// The follows a flow left for after it returned.
    pub fn follow_behind(&self) -> Result<(), Refused> {
        Ok(self.0.follow_behind()?)
    }

    /// The personal space's state as the device holds it, the facility's
    /// parts (Tor, the notices standing) left for the node to fill.
    pub fn status(&self) -> Result<PersonalStatus, Refused> {
        let status = self.0.status()?;
        let (phase, matures) = match status.phase {
            space::Phase::None => (Phase::None, 0),
            space::Phase::Claiming => (Phase::Claiming, 0),
            space::Phase::Joining => (Phase::Joining, 0),
            space::Phase::Held => (Phase::Held, 0),
            space::Phase::Restoring { matures } => (Phase::Restoring, matures),
            space::Phase::Removed => (Phase::Removed, 0),
            space::Phase::Stuck => (Phase::Stuck, 0),
        };
        let home = status.home.map_or_else(Home::default, Home::from);
        Ok(PersonalStatus {
            phase,
            matures,
            home,
            agent: status.agent.map_or(0, |(agent, _)| agent),
            device: status.device.unwrap_or(0),
            owed: status.owed,
            ..PersonalStatus::default()
        })
    }

    #[doc(hidden)]
    pub fn set_wait(&self, ms: u64) {
        self.0.set_wait(ms);
    }

    /// The route a request of `purpose` to the device's home takes now.
    #[doc(hidden)]
    pub fn home_route(
        &self,
        purpose: vos_light::route::Purpose,
    ) -> Option<vos_light::route::Route> {
        let kept = self.0.home()?;
        let routes = self
            .0
            .host()
            .facility
            .net()
            .client()
            .routes(&vos_light::route::home(&kept.home.handle))?;
        routes.route(purpose).ok()
    }

    pub fn scope_key(&self, name: &[u8]) -> Result<[u8; 32], Refused> {
        Ok(self.0.scope_key(name)?)
    }

    #[doc(hidden)]
    pub fn recorded(&self, device: u32) -> usize {
        self.0.recorded(device)
    }

    pub fn sync_key(&self) -> [u8; 32] {
        self.0.sync_key()
    }

    pub fn claim(&self, prompts: Lent<'_>, request: Claim) -> Result<Claimed, Refused> {
        let request = claim(request)?;
        Ok(self.0.claim(&Asked(prompts), request)?.into())
    }

    pub fn pair_offer(&self, _prompts: Lent<'_>) -> Result<PairCode, Refused> {
        let code = self.0.pair_offer()?;
        Ok(PairCode {
            code: code.code,
            expires_ms: code.expires_ms,
        })
    }

    pub fn pair_await(&self, prompts: Lent<'_>) -> Result<Paired, Refused> {
        Ok(self.0.pair_await(&Asked(prompts))?.into())
    }

    pub fn pair_cancel(&self) {
        self.0.pair_cancel();
    }

    pub fn pair_join(
        &self,
        prompts: Lent<'_>,
        code: &[u8],
        label: &str,
    ) -> Result<Paired, Refused> {
        contract::label(label)?;
        Ok(self.0.pair_join(&Asked(prompts), code, label)?.into())
    }

    pub fn memberships(&self) -> Result<Vec<Membership>, Refused> {
        let all = self.0.memberships()?;
        Ok(all.into_iter().map(Into::into).collect())
    }

    pub fn enroll_device(&self, prompts: Lent<'_>, owed: Membership) -> Result<(), Refused> {
        Ok(self.0.enroll_device(&Asked(prompts), owed.into())?)
    }

    pub fn confirm_device(&self, prompts: Lent<'_>, owed: Membership) -> Result<(), Refused> {
        Ok(self.0.confirm_device(&Asked(prompts), owed.into())?)
    }

    pub fn drop_enrollment(&self, owed: Membership) -> Result<(), Refused> {
        Ok(self.0.drop_enrollment(owed.into())?)
    }

    /// Each space's leaf of the removed `device` revoked.
    pub fn revoke(&self, prompts: Lent<'_>, device: u32) -> Result<u32, Refused> {
        Ok(self.0.revoke(&Asked(prompts), device)?)
    }

    pub fn devices(&self) -> Result<Vec<Device>, Refused> {
        let all = self.0.devices()?;
        Ok(all.into_iter().map(Into::into).collect())
    }

    pub fn kit_view(
        &self,
        prompts: Lent<'_>,
        home: Home,
        kind: KitKind,
    ) -> Result<KitView, Refused> {
        let view = self
            .0
            .kit_view(&Asked(prompts), home.check()?.into(), kind.into())?;
        Ok(KitView {
            devices: view.devices.into_iter().map(Into::into).collect(),
            operations: view
                .operations
                .into_iter()
                .map(crate::job::notice)
                .collect(),
        })
    }

    pub fn remove_by_kit(
        &self,
        prompts: Lent<'_>,
        home: Home,
        kind: KitKind,
        device: u32,
    ) -> Result<Posted, Refused> {
        Ok(self
            .0
            .remove_by_kit(&Asked(prompts), home.check()?.into(), kind.into(), device)?
            .into())
    }

    pub fn resolve_by_kit(
        &self,
        prompts: Lent<'_>,
        home: Home,
        kind: KitKind,
        index: u64,
        upheld: bool,
    ) -> Result<Posted, Refused> {
        Ok(self
            .0
            .resolve_by_kit(
                &Asked(prompts),
                home.check()?.into(),
                kind.into(),
                index,
                upheld,
            )?
            .into())
    }

    pub fn operations(&self) -> Result<Vec<Notice>, Refused> {
        let open = self.0.operations()?;
        Ok(open.into_iter().map(crate::job::notice).collect())
    }

    pub fn remove(&self, prompts: Lent<'_>, device: u32) -> Result<Posted, Refused> {
        Ok(self.0.remove(&Asked(prompts), device)?.into())
    }

    pub fn veto(&self, prompts: Lent<'_>, index: u64) -> Result<Posted, Refused> {
        Ok(self.0.veto(&Asked(prompts), index)?.into())
    }

    pub fn cosign(&self, prompts: Lent<'_>, index: u64) -> Result<Posted, Refused> {
        Ok(self.0.cosign(&Asked(prompts), index)?.into())
    }

    pub fn resolve(&self, prompts: Lent<'_>, index: u64, upheld: bool) -> Result<Posted, Refused> {
        Ok(self.0.resolve(&Asked(prompts), index, upheld)?.into())
    }

    pub fn rotate_kit(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Posted, Refused> {
        Ok(self.0.rotate_kit(&Asked(prompts), kind.into())?.into())
    }

    pub fn replace_admin(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Posted, Refused> {
        Ok(self.0.replace_admin(&Asked(prompts), kind.into())?.into())
    }

    pub fn admin_offer(&self, prompts: Lent<'_>) -> Result<Vec<u8>, Refused> {
        Ok(self.0.admin_offer(&Asked(prompts))?)
    }

    pub fn replace_admin_of(&self, prompts: Lent<'_>, code: &[u8]) -> Result<Posted, Refused> {
        Ok(self.0.replace_admin_of(&Asked(prompts), code)?.into())
    }

    pub fn regroup(&self, prompts: Lent<'_>) -> Result<Posted, Refused> {
        Ok(self.0.regroup(&Asked(prompts))?.into())
    }

    pub fn update(&self, prompts: Lent<'_>) -> Result<(), Refused> {
        Ok(self.0.update(&Asked(prompts))?)
    }

    pub fn restore(
        &self,
        prompts: Lent<'_>,
        request: Claim,
        old: KitKind,
    ) -> Result<Posted, Refused> {
        let request = claim(request)?;
        Ok(self.0.restore(&Asked(prompts), request, old.into())?.into())
    }

    pub fn restored(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Claimed, Refused> {
        Ok(self.0.restored(&Asked(prompts), kind.into())?.into())
    }

    pub fn move_home(&self, prompts: Lent<'_>, request: Claim) -> Result<Claimed, Refused> {
        let request = claim(request)?;
        Ok(self.0.move_home(&Asked(prompts), request)?.into())
    }
}

impl Personal for Space {
    fn pass(&self, now: u64) -> Result<Passed, String> {
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

impl crate::session::PersonalLink for Space {
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

    fn home(&self) -> Option<([u8; 32], [u8; 32], Vec<vos_wire::credentials::Onion>)> {
        self.0
            .home()
            .map(|kept| (kept.home.handle, kept.home.space, kept.onions))
    }
}
