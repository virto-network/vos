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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_abi::ids::InstanceId;
use vos_light::group::Alarm;
use vos_light::route::{Purpose, Route};
use vos_light::space::{self, AdminKey, Approval, Card, Enrolled, Error, Host, Proof};

use vos_wire::credentials::Onion;
use zeroize::Zeroizing;

use crate::job::{Passed, Personal};
use crate::kept::Kept;
use crate::net::Pinned;
use crate::node::Prompts;
use crate::session::{Inner, Kernel};
use crate::source::{Kind, Reference};
use crate::{Answer, Code, Facility, Field, Form};
use s4_credential_contract::KeyAnswer;

pub use contract::{
    Claim, Claimed, Device, Home, KitKind, KitView, MAX_LABEL, Membership, Notice, Owed, PairCode,
    Paired, Pending, PersonalStatus, Phase, Posted, Refused, Seen, Stage, Synced, Tor, Why, label,
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

/// The form a kit's words are entered in, and the one asking two of a new
/// phrase's words back: the screens give their fields the kit's word list
/// by these titles (`KitWords.java`).
pub const ENTER_PHRASE: &str = "Enter your recovery phrase";
pub const CHECK_PHRASE: &str = "Check your recovery phrase";

/// How long a restore's sitting holds the kit entered, at most, from its
/// entry (`light-node.md` §3.5).
pub const KIT_LIFE_MS: u64 = 10 * 60_000;

/// The facility's database row naming the kind of kit a restore under way
/// was opened with, which its finish enters again: not a secret.
const RESTORE_KIT: &[u8] = b"personal/restore-kit";

/// A kit entered: a phrase's words, or a security key's `hmac-secret` of
/// the kit's salt. Zeroized on drop; no `Clone`, no `Debug`.
enum Entered {
    Words(Zeroizing<String>),
    Touched {
        salt: [u8; 32],
        secret: Zeroizing<[u8; 32]>,
    },
}

/// The restore screen's sitting (`IVosPersonal.kitHold`): the kit entered
/// in one of its flows held in this process for the next, until the
/// sitting closes, the app goes to the background, or [`KIT_LIFE_MS`] (or
/// the life a test sets) after its entry, whichever is first, then
/// zeroized. Never written, logged or handed back to the UI.
#[derive(Default)]
pub struct Sitting(Mutex<Holding>);

#[derive(Default)]
struct Holding {
    open: bool,
    /// Counted at each open and close: a flow that began in one sitting
    /// keeps nothing in the next.
    opened: u64,
    /// Counted at each change, so a wipe timed for one kit wipes no later.
    generation: u64,
    kit: Option<Entered>,
    /// A test's life for the kit, in ms; none: [`KIT_LIFE_MS`].
    life_ms: Option<u64>,
}

impl Sitting {
    fn lock(&self) -> std::sync::MutexGuard<'_, Holding> {
        crate::lock(&self.0)
    }

    fn open(&self) {
        let mut holding = self.lock();
        holding.generation += 1;
        holding.opened += 1;
        holding.open = true;
        holding.kit = None;
    }

    /// The sitting closed, its kit zeroized.
    fn close(&self) {
        let mut holding = self.lock();
        holding.generation += 1;
        holding.opened += 1;
        holding.open = false;
        holding.kit = None;
    }

    /// The kit zeroized, the sitting left open: a kit that is not the
    /// space's is entered anew.
    fn wipe(&self) {
        let mut holding = self.lock();
        holding.generation += 1;
        holding.kit = None;
    }

    /// `kit`, entered in the sitting `opened`, held while that sitting is
    /// still open: the generation and life to time its wipe at.
    fn keep(&self, kit: Entered, opened: u64) -> Option<(u64, u64)> {
        let mut holding = self.lock();
        if !holding.open || holding.opened != opened {
            return None;
        }
        holding.generation += 1;
        holding.kit = Some(kit);
        Some((holding.generation, holding.life_ms.unwrap_or(KIT_LIFE_MS)))
    }

    fn expire(&self, generation: u64) {
        let mut holding = self.lock();
        if holding.generation == generation {
            holding.kit = None;
        }
    }

    fn words(&self) -> Option<Zeroizing<String>> {
        match &self.lock().kit {
            Some(Entered::Words(words)) => Some(words.clone()),
            _ => None,
        }
    }

    fn touched(&self, salt: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
        match &self.lock().kit {
            Some(Entered::Touched { salt: held, secret }) if held == salt => Some(secret.clone()),
            _ => None,
        }
    }
}

/// The chrome's prompts, lent to one flow, as the personal space asks
/// them: each kit shown and entered in a form, each key's use the UI's;
/// within a restore's sitting, the kit it holds given for the kit entered.
pub struct Asked<'a> {
    prompts: &'a dyn Prompts,
    sitting: Option<&'a Sitting>,
    /// The kit this flow entered, for the sitting to hold once it is done.
    entered: Mutex<Option<Entered>>,
}

impl<'a> Asked<'a> {
    fn new(prompts: &'a dyn Prompts) -> Self {
        Self {
            prompts,
            sitting: None,
            entered: Mutex::new(None),
        }
    }

    fn within(prompts: &'a dyn Prompts, sitting: &'a Sitting) -> Self {
        Self {
            sitting: Some(sitting),
            ..Self::new(prompts)
        }
    }
}

/// A phrase as entered, as the kit's words are: lower case, one space
/// between words.
fn normalized(words: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(words.len()));
    for word in words.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.extend(word.chars().flat_map(char::to_lowercase));
    }
    out
}

/// Two distinct positions among `count` words, drawn, in order.
fn two_of(count: usize) -> (usize, usize) {
    let mut bytes = [0; 4];
    getrandom::getrandom(&mut bytes).expect("the system's randomness");
    let count = count.max(2);
    let first = u16::from_le_bytes([bytes[0], bytes[1]]) as usize % count;
    let second =
        (first + 1 + u16::from_le_bytes([bytes[2], bytes[3]]) as usize % (count - 1)) % count;
    (first.min(second), first.max(second))
}

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
        matches!(self.prompts.confirm(form), Answer::Confirmed { .. })
    }

    /// Two of the phrase's words asked back, from what the user wrote:
    /// whether both are right; `None` when the user declined.
    fn checked(&self, words: &[&str]) -> Option<bool> {
        let (first, second) = two_of(words.len());
        let answer = self.prompts.confirm(Form {
            title: CHECK_PHRASE.into(),
            detail: format!(
                "From what you wrote down, words {} and {}: so a word written wrong is found \
                 now, while the phrase can still be read.",
                first + 1,
                second + 1
            ),
            rows: Vec::new(),
            fields: [first, second]
                .iter()
                .map(|at| Field {
                    label: format!("Word {}", at + 1),
                    value: String::new(),
                })
                .collect(),
            notice: None,
            choices: vec!["Check".into()],
            code: None,
        });
        let Answer::Confirmed { values, .. } = answer else {
            return None;
        };
        let given: Vec<Zeroizing<String>> = values.iter().map(|value| normalized(value)).collect();
        Some(
            given.len() == 2
                && given[0].as_str() == words[first]
                && given[1].as_str() == words[second],
        )
    }
}

impl From<space::Stage> for Stage {
    fn from(stage: space::Stage) -> Self {
        match stage {
            space::Stage::Reaching => Self::Reaching,
            space::Stage::Proving => Self::Proving,
            space::Stage::WritingKit => Self::WritingKit,
            space::Stage::Joining => Self::Joining,
            space::Stage::Scanned => Self::Scanned,
            space::Stage::Checked => Self::Checked,
            space::Stage::HandingOver => Self::HandingOver,
            space::Stage::Approving => Self::Approving,
            space::Stage::Leaving => Self::Leaving,
        }
    }
}

impl space::Prompts for Asked<'_> {
    fn stage(&self, stage: space::Stage) {
        self.prompts.step(stage.into());
    }

    /// The phrase shown (with why the one before is void, if one is),
    /// then two of its words asked back before the flow goes on; a wrong
    /// word shows the phrase again, saying so, and so does a check
    /// declined.
    fn show_phrase(&self, words: &str, card: &Card, void: Option<&str>) -> bool {
        let each: Vec<&str> = words.split(' ').collect();
        let mut notice = void.map(str::to_owned);
        loop {
            let rows = each
                .iter()
                .enumerate()
                .map(|(at, word)| (format!("{}", at + 1), (*word).to_owned()))
                .chain(card_rows(card))
                .collect();
            let shown = self.shown(Form {
                title: "Your recovery phrase".into(),
                detail: "Write these 24 words down, in order, with the card below them, and keep \
                         them apart from this phone. They restore your personal space at this \
                         home if every device is lost; this is the only time they are shown."
                    .into(),
                rows,
                fields: Vec::new(),
                notice: notice.take(),
                choices: vec!["I wrote them down".into()],
                code: None,
            });
            if !shown {
                return false;
            }
            match self.checked(&each) {
                Some(true) => return true,
                Some(false) => {
                    notice = Some(
                        "Those were not the words asked: compare what you wrote with the phrase \
                         above, word by word, and correct it."
                            .into(),
                    );
                }
                None => {}
            }
        }
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
            code: None,
        })
    }

    fn enter_phrase(&self) -> Option<Zeroizing<String>> {
        if let Some(words) = self.sitting.and_then(Sitting::words) {
            return Some(words);
        }
        let answer = self.prompts.confirm(Form {
            title: ENTER_PHRASE.into(),
            detail: "The 24 words you wrote down, in order, separated by spaces.".into(),
            rows: Vec::new(),
            fields: vec![Field {
                label: "Words".into(),
                value: String::new(),
            }],
            notice: None,
            choices: vec!["Go on".into()],
            code: None,
        });
        let Answer::Confirmed { values, .. } = answer else {
            return None;
        };
        let words = normalized(&Zeroizing::new(values.join(" ")));
        if self.sitting.is_some() {
            *crate::lock(&self.entered) = Some(Entered::Words(words.clone()));
        }
        Some(words)
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
            code: None,
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
            code: None,
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
            code: None,
        })
    }

    fn create_source(&self) -> Result<Vec<u8>, Error> {
        let key = key_answer(self.prompts.create_key(Kind::Keystore))?;
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
            self.prompts
                .evaluate_key(reference.kind(), &bytes[1..], input),
            "the source's output",
        )
    }

    fn create_kit_key(&self) -> Result<Vec<u8>, Error> {
        key_answer(self.prompts.create_key(Kind::Kit)).map(|id| id.to_vec())
    }

    /// The kit's security key's output; for its discoverable credential
    /// (the kit entered, `id` empty), the one the sitting holds if any.
    fn kit_secret(&self, id: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let entered = id.is_empty() && self.sitting.is_some();
        if entered && let Some(secret) = self.sitting.and_then(|sitting| sitting.touched(salt)) {
            return Ok(secret);
        }
        let secret = thirty_two(
            self.prompts.evaluate_key(Kind::Kit, id, salt),
            "the security key's output",
        )?;
        if entered {
            *crate::lock(&self.entered) = Some(Entered::Touched {
                salt: *salt,
                secret: secret.clone(),
            });
        }
        Ok(secret)
    }

    fn create_admin(&self) -> Result<AdminKey, Error> {
        let bytes = key_answer(self.prompts.create_key(Kind::Admin))?;
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
        let bytes = key_answer(self.prompts.sign_key(Kind::Admin, key, message))?;
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

impl From<vos_wire::personal::KitKind> for KitKind {
    fn from(kind: vos_wire::personal::KitKind) -> Self {
        match kind {
            vos_wire::personal::KitKind::Phrase => Self::Phrase,
            vos_wire::personal::KitKind::SecurityKey => Self::SecurityKey,
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

/// The device's personal space, as the facility serves it: its flows, the
/// restore screen's sitting, and the facility's database for the kind of
/// kit a restore under way was opened with.
pub struct Space {
    personal: space::Personal<Reach>,
    sitting: Arc<Sitting>,
    /// The facility's directory, whose database is opened at each use:
    /// held open, it would outlive the facility that opened it.
    directory: std::path::PathBuf,
}

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
        let personal = space::Personal::open(directory, artifacts, Reach { facility, runtime })?;
        Ok(Space {
            personal,
            sitting: Arc::default(),
            directory: directory.to_path_buf(),
        })
    }

    /// The restore screen's sitting opened: the kit entered in its flows
    /// held until [`Space::forget_kit`], the app in the background, or its
    /// life's end.
    pub fn hold_kit(&self) {
        self.sitting.open();
    }

    /// The sitting closed, the kit it held zeroized.
    pub fn forget_kit(&self) {
        self.sitting.close();
    }

    /// Whether the sitting holds a kit now.
    #[doc(hidden)]
    pub fn kit_held(&self) -> bool {
        self.sitting.lock().kit.is_some()
    }

    /// The life of a kit the sitting holds from now on, in ms.
    #[doc(hidden)]
    pub fn set_kit_life(&self, ms: u64) {
        self.sitting.lock().life_ms = Some(ms);
    }

    /// `flow` within the sitting: the kit it entered held after, unless it
    /// is not a kit or not this space's, which is wiped; its wipe timed.
    fn with_kit<T>(
        &self,
        prompts: Lent<'_>,
        flow: impl FnOnce(&Asked<'_>) -> Result<T, Error>,
    ) -> Result<T, Refused> {
        let opened = self.sitting.lock().opened;
        let asked = Asked::within(prompts, &self.sitting);
        let done = flow(&asked);
        let entered = crate::lock(&asked.entered).take();
        match &done {
            Err(Error::NotAKit | Error::WrongKit | Error::NoAgentForKit) => self.sitting.wipe(),
            _ => {
                if let Some((generation, life)) =
                    entered.and_then(|kit| self.sitting.keep(kit, opened))
                {
                    let sitting = Arc::clone(&self.sitting);
                    self.personal.host().runtime.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(life)).await;
                        sitting.expire(generation);
                    });
                }
            }
        }
        Ok(done?)
    }

    pub fn grouped(&self) -> bool {
        self.personal.grouped()
    }

    /// Whether a flow returned with follows left for after it.
    pub fn behind(&self) -> bool {
        self.personal.behind()
    }

    /// The follows a flow left for after it returned.
    pub fn follow_behind(&self) -> Result<(), Refused> {
        Ok(self.personal.follow_behind()?)
    }

    /// The follows left for after a flow dropped: the next pass makes
    /// them.
    pub fn drop_behind(&self) {
        self.personal.drop_behind();
    }

    /// The personal space's state as the device holds it, the facility's
    /// parts (Tor, the notices standing) left for the node to fill.
    pub fn status(&self) -> Result<PersonalStatus, Refused> {
        let status = self.personal.status()?;
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
        let restoring = matches!(phase, Phase::Restoring).then(|| self.restore_kit());
        let known = restoring.unwrap_or_else(|| status.kit.map(KitKind::from));
        let (kit, kit_known) = (known.unwrap_or_default(), known.is_some());
        Ok(PersonalStatus {
            phase,
            matures,
            home,
            agent: status.agent.map_or(0, |(agent, _)| agent),
            device: status.device.unwrap_or(0),
            owed: status.owed,
            kit,
            kit_known,
            ..PersonalStatus::default()
        })
    }

    #[doc(hidden)]
    pub fn set_wait(&self, ms: u64) {
        self.personal.set_wait(ms);
    }

    /// The route a request of `purpose` to the device's home takes now.
    #[doc(hidden)]
    pub fn home_route(
        &self,
        purpose: vos_light::route::Purpose,
    ) -> Option<vos_light::route::Route> {
        let kept = self.personal.home()?;
        let routes = self
            .personal
            .host()
            .facility
            .net()
            .client()
            .routes(&vos_light::route::home(&kept.home.handle))?;
        routes.route(purpose).ok()
    }

    pub fn scope_key(&self, name: &[u8]) -> Result<[u8; 32], Refused> {
        Ok(self.personal.scope_key(name)?)
    }

    #[doc(hidden)]
    pub fn recorded(&self, device: u32) -> usize {
        self.personal.recorded(device)
    }

    pub fn sync_key(&self) -> [u8; 32] {
        self.personal.sync_key()
    }

    pub fn claim(&self, prompts: Lent<'_>, request: Claim) -> Result<Claimed, Refused> {
        let request = claim(request)?;
        Ok(self.personal.claim(&Asked::new(prompts), request)?.into())
    }

    pub fn pair_offer(&self, _prompts: Lent<'_>) -> Result<PairCode, Refused> {
        let code = self.personal.pair_offer()?;
        Ok(PairCode {
            code: code.code,
            expires_ms: code.expires_ms,
        })
    }

    pub fn pair_await(&self, prompts: Lent<'_>) -> Result<Paired, Refused> {
        Ok(self.personal.pair_await(&Asked::new(prompts))?.into())
    }

    pub fn pair_cancel(&self) {
        self.personal.pair_cancel();
    }

    pub fn pair_join(
        &self,
        prompts: Lent<'_>,
        code: &[u8],
        label: &str,
    ) -> Result<Paired, Refused> {
        contract::label(label)?;
        Ok(self
            .personal
            .pair_join(&Asked::new(prompts), code, label)?
            .into())
    }

    pub fn memberships(&self) -> Result<Vec<Membership>, Refused> {
        let all = self.personal.memberships()?;
        Ok(all.into_iter().map(Into::into).collect())
    }

    pub fn enroll_device(&self, prompts: Lent<'_>, owed: Membership) -> Result<(), Refused> {
        Ok(self
            .personal
            .enroll_device(&Asked::new(prompts), owed.into())?)
    }

    pub fn confirm_device(&self, prompts: Lent<'_>, owed: Membership) -> Result<(), Refused> {
        Ok(self
            .personal
            .confirm_device(&Asked::new(prompts), owed.into())?)
    }

    pub fn drop_enrollment(&self, owed: Membership) -> Result<(), Refused> {
        Ok(self.personal.drop_enrollment(owed.into())?)
    }

    /// Each space's leaf of the removed `device` revoked.
    pub fn revoke(&self, prompts: Lent<'_>, device: u32) -> Result<u32, Refused> {
        Ok(self.personal.revoke(&Asked::new(prompts), device)?)
    }

    pub fn devices(&self) -> Result<Vec<Device>, Refused> {
        let all = self.personal.devices()?;
        Ok(all.into_iter().map(Into::into).collect())
    }

    pub fn kit_view(
        &self,
        prompts: Lent<'_>,
        home: Home,
        kind: KitKind,
    ) -> Result<KitView, Refused> {
        let home = home.check()?;
        let view = self.with_kit(prompts, |asked| {
            self.personal.kit_view(asked, home.into(), kind.into())
        })?;
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
        let home = home.check()?;
        self.with_kit(prompts, |asked| {
            self.personal
                .remove_by_kit(asked, home.into(), kind.into(), device)
        })
        .map(Into::into)
    }

    pub fn resolve_by_kit(
        &self,
        prompts: Lent<'_>,
        home: Home,
        kind: KitKind,
        index: u64,
        upheld: bool,
    ) -> Result<Posted, Refused> {
        let home = home.check()?;
        self.with_kit(prompts, |asked| {
            self.personal
                .resolve_by_kit(asked, home.into(), kind.into(), index, upheld)
        })
        .map(Into::into)
    }

    pub fn operations(&self) -> Result<Vec<Notice>, Refused> {
        let open = self.personal.operations()?;
        Ok(open.into_iter().map(crate::job::notice).collect())
    }

    pub fn remove(&self, prompts: Lent<'_>, device: u32) -> Result<Posted, Refused> {
        Ok(self.personal.remove(&Asked::new(prompts), device)?.into())
    }

    pub fn veto(&self, prompts: Lent<'_>, index: u64) -> Result<Posted, Refused> {
        Ok(self.personal.veto(&Asked::new(prompts), index)?.into())
    }

    pub fn cosign(&self, prompts: Lent<'_>, index: u64) -> Result<Posted, Refused> {
        Ok(self.personal.cosign(&Asked::new(prompts), index)?.into())
    }

    pub fn resolve(&self, prompts: Lent<'_>, index: u64, upheld: bool) -> Result<Posted, Refused> {
        Ok(self
            .personal
            .resolve(&Asked::new(prompts), index, upheld)?
            .into())
    }

    pub fn rotate_kit(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Posted, Refused> {
        Ok(self
            .personal
            .rotate_kit(&Asked::new(prompts), kind.into())?
            .into())
    }

    pub fn replace_admin(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Posted, Refused> {
        Ok(self
            .personal
            .replace_admin(&Asked::new(prompts), kind.into())?
            .into())
    }

    pub fn admin_offer(&self, prompts: Lent<'_>) -> Result<Vec<u8>, Refused> {
        Ok(self.personal.admin_offer(&Asked::new(prompts))?)
    }

    pub fn replace_admin_of(&self, prompts: Lent<'_>, code: &[u8]) -> Result<Posted, Refused> {
        Ok(self
            .personal
            .replace_admin_of(&Asked::new(prompts), code)?
            .into())
    }

    pub fn regroup(&self, prompts: Lent<'_>) -> Result<Posted, Refused> {
        Ok(self.personal.regroup(&Asked::new(prompts))?.into())
    }

    pub fn update(&self, prompts: Lent<'_>) -> Result<(), Refused> {
        self.personal.update(&Asked::new(prompts))?;
        Ok(())
    }

    pub fn leave(&self, prompts: Lent<'_>) -> Result<(), Refused> {
        self.personal.leave(&Asked::new(prompts))?;
        Ok(())
    }

    /// The commit a matured removal's notice asks for, then each device it
    /// carried out revoked in every space its handles name: how many
    /// revokes. A revoke refused leaves the commit made, and the device
    /// listed removed, its revoke the Devices screen's.
    pub fn commit_removals(&self, prompts: Lent<'_>) -> Result<u32, Refused> {
        let carried = self.personal.update(&Asked::new(prompts))?;
        let mut revoked = 0;
        for device in carried {
            revoked += self.personal.revoke(&Asked::new(prompts), device)?;
        }
        Ok(revoked)
    }

    pub fn restore(
        &self,
        prompts: Lent<'_>,
        request: Claim,
        old: KitKind,
    ) -> Result<Posted, Refused> {
        let request = claim(request)?;
        let posted = self.with_kit(prompts, |asked| {
            self.personal.restore(asked, request, old.into())
        })?;
        // The finish enters the same kit: its kind is named to the screen,
        // which the device holds nowhere else while it restores.
        // Not kept, the finish shows the kit's choice again: the restore
        // stands at the home whatever this row is.
        if let Ok(kept) = Kept::open(&self.directory) {
            let _ = kept.put(RESTORE_KIT, &(old as u8));
        }
        Ok(posted.into())
    }

    pub fn restored(&self, prompts: Lent<'_>, kind: KitKind) -> Result<Claimed, Refused> {
        let claimed = self.with_kit(prompts, |asked| self.personal.restored(asked, kind.into()))?;
        if let Ok(kept) = Kept::open(&self.directory) {
            let _ = kept.remove(RESTORE_KIT);
        }
        Ok(claimed.into())
    }

    /// The kind of kit the restore under way was opened with.
    fn restore_kit(&self) -> Option<KitKind> {
        let byte: u8 = Kept::open(&self.directory).ok()?.get(RESTORE_KIT).ok()??;
        KitKind::from_byte(byte)
    }

    pub fn move_home(&self, prompts: Lent<'_>, request: Claim) -> Result<Claimed, Refused> {
        let request = claim(request)?;
        Ok(self
            .personal
            .move_home(&Asked::new(prompts), request)?
            .into())
    }
}

impl Personal for Space {
    fn pass(&self, now: u64) -> Result<Passed, String> {
        let passed = self.personal.pass(now).map_err(|error| error.to_string())?;
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
        self.personal
            .acknowledge_alarms(alarms)
            .map_err(|error| error.to_string())
    }
}

impl crate::session::PersonalLink for Space {
    fn owed_source(&self, handle: &[u8; 32]) -> Result<Option<Reference>, String> {
        match self
            .personal
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
        self.personal.enrolled();
    }

    fn home(&self) -> Option<([u8; 32], [u8; 32], Vec<vos_wire::credentials::Onion>)> {
        self.personal
            .home()
            .map(|kept| (kept.home.handle, kept.home.space, kept.onions))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use space::Prompts as _;

    /// A user who answers the phrase's check from a script: each check's
    /// answer wrong or right, every form seen.
    struct Scripted {
        right: Mutex<VecDeque<bool>>,
        seen: Mutex<Vec<Form>>,
    }

    impl Prompts for Scripted {
        fn confirm(&self, form: Form) -> Answer {
            self.seen.lock().unwrap().push(form.clone());
            if form.title != CHECK_PHRASE {
                return Answer::Confirmed {
                    choice: 0,
                    values: Vec::new(),
                };
            }
            let right = self.right.lock().unwrap().pop_front().expect("scripted");
            let values = form
                .fields
                .iter()
                .map(|field| {
                    let at: usize = field.label["Word ".len()..].parse().unwrap();
                    if right {
                        // As written, the case and spaces aside.
                        format!("  {} ", WORDS[at - 1].to_uppercase())
                    } else {
                        "abandon".into()
                    }
                })
                .collect();
            Answer::Confirmed { choice: 0, values }
        }

        fn create_key(&self, _: Kind) -> KeyAnswer {
            KeyAnswer::Declined
        }

        fn evaluate_key(&self, _: Kind, _: &[u8], _: &[u8; 32]) -> KeyAnswer {
            KeyAnswer::Declined
        }

        fn sign_key(&self, _: Kind, _: &[u8], _: &[u8]) -> KeyAnswer {
            KeyAnswer::Declined
        }
    }

    const WORDS: [&str; 24] = [
        "zoo", "wrist", "vote", "unit", "toast", "swamp", "sun", "spy", "salon", "rich", "pupil",
        "price", "oyster", "nurse", "mule", "milk", "lunar", "loud", "liar", "keep", "invite",
        "hybrid", "habit", "gather",
    ];

    /// A new phrase is asked back, two of its words, before the flow goes
    /// on: a wrong answer shows the phrase again, saying so.
    #[test]
    fn two_words_of_a_new_phrase_are_asked_back() {
        let user = Scripted {
            right: Mutex::new([false, true].into()),
            seen: Mutex::new(Vec::new()),
        };
        let card = Card {
            handle: [1; 32],
            onions: Vec::new(),
        };
        assert!(Asked::new(&user).show_phrase(&WORDS.join(" "), &card, None));
        let seen = user.seen.lock().unwrap();
        let titles: Vec<&str> = seen.iter().map(|form| form.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Your recovery phrase",
                CHECK_PHRASE,
                "Your recovery phrase",
                CHECK_PHRASE
            ]
        );
        assert!(seen[0].notice.is_none());
        assert!(seen[2].notice.is_some(), "the wrong word said");
        let asked: Vec<&str> = seen[1].fields.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(asked.len(), 2);
        assert_ne!(asked[0], asked[1]);
    }

    /// A kit entered in a sitting the app's going to the background closed
    /// is not held by the sitting opened on its return.
    #[test]
    fn a_kit_entered_before_the_background_is_not_held_after() {
        let sitting = Sitting::default();
        sitting.open();
        let opened = sitting.lock().opened;
        sitting.close();
        sitting.open();
        let words = Entered::Words(Zeroizing::new("zoo".into()));
        assert!(sitting.keep(words, opened).is_none());
        assert!(sitting.lock().kit.is_none());
        let now = sitting.lock().opened;
        let words = Entered::Words(Zeroizing::new("zoo".into()));
        assert!(sitting.keep(words, now).is_some());
    }

    #[test]
    fn a_phrase_entered_is_read_as_the_kit_reads_it() {
        assert_eq!(
            normalized("  Zoo\tWRIST \n vote ").as_str(),
            "zoo wrist vote"
        );
        for _ in 0..64 {
            let (first, second) = two_of(24);
            assert!(first < second && second < 24);
        }
    }
}
