// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility as its own process serves it (`:vos` on Android): one
//! [`Node`] holding the facility, the runtime it runs on and the sessions
//! the client opened, each operation of the Binder interface one method
//! here, blocking its caller's thread until it is answered.
//!
//! - **Prompts stay with the client.** An operation is lent the client's
//!   [`Prompts`] for its length: the trusted chrome's forms, and each use of
//!   a secret source's key, whose prompt and keystore operation the client
//!   runs and whose result it hands back. The facility's [`Source`] asks the
//!   prompts lent to the operation it serves; outside an operation it asks
//!   nothing.
//! - **Requests are checked again** as they come off the interface,
//!   whoever made them.
//! - **What a death costs:** the client's death leaves an operation running
//!   to its end, its answer dropped; this process's death loses only what
//!   it held in memory (its sessions, the paths, a proof under way): every
//!   enrollment is written whole or not at all, so the store it leaves is
//!   one the next process opens.
//! - **The background jobs** run [`Node::sync`] and
//!   [`Node::sync_personal`] here, with no client at all ([`crate::job`]):
//!   their runs kept beside the enrollments.
//! - **One client over Tor** ([`crate::net`]): every request to a space,
//!   arti's state in the app's private files; dormant while the app is in
//!   the background and no job runs ([`Node::foreground`]).
//! - **The personal space** ([`crate::personal`]): its flows, called on
//!   it through [`Node::personal`], lent the client's prompts as the
//!   others are.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::chrome::Chrome;
use crate::enrollment::Store;
use crate::job::{Job, Part};
use crate::net::{Arti, Net};
use crate::personal::{Artifacts, PersonalStatus, Phase, Refused, Space, Stage, Why};
use crate::source::{BoxFuture, Kind, Output, Reference, Source, SourceError};
use crate::{
    Answer, Carriage, Code, Enroll, Enrolled, EnrolledSpace, Facility, Form, Gateway, JobRun, Paid,
    Pay, Refusal, Session, SignIn, SignedIn, StreamTarget, Synced, Warming, refused,
};
use s4_credential_contract::KeyAnswer;

/// The client's prompts, lent to one operation. Each call blocks until the
/// user answers, or the client is gone.
pub trait Prompts: Send + Sync + 'static {
    /// The form's answer, from the client's trusted chrome.
    fn confirm(&self, form: Form) -> Answer;
    /// A new key of `kind`: its handle (an alias, a credential id).
    fn create_key(&self, kind: Kind) -> KeyAnswer;
    /// The key's HMAC-SHA-256 of `input`, after the user's consent at its
    /// prompt: 32 bytes. A security key's is its `hmac-secret`, `key` its
    /// credential id (empty: its discoverable credential, a kit's).
    fn evaluate_key(&self, kind: Kind, key: &[u8], input: &[u8; 32]) -> KeyAnswer;
    /// The admin key's Ed25519 signature over `message`, which this process
    /// prepared, after a strong biometric at its prompt: 64 bytes.
    fn sign_key(&self, kind: Kind, key: &[u8], message: &[u8]) -> KeyAnswer;
    /// The personal flow reached `stage`, which the app's screens say while
    /// it runs: nothing answered, nothing of a secret in it.
    fn step(&self, _stage: Stage) {}
    /// Where the operation is, in words, for the client's chrome to show.
    fn stage(&self, _stage: &str) {}
}

/// What the device offers, which this process reads itself.
pub trait Device: Send + Sync + 'static {
    /// The secret sources' kinds, the default first.
    fn kinds(&self) -> Vec<Kind>;
}

tokio::task_local! {
    /// The prompts lent to the operation this task serves.
    static LENT: Arc<dyn Prompts>;
}

fn lent() -> Result<Arc<dyn Prompts>, SourceError> {
    LENT.try_with(Arc::clone)
        .map_err(|_| SourceError::Failed("no operation lent its prompts".into()))
}

/// The facility's secret sources: the device's kinds, each key's use the
/// lent prompts'.
struct Lent {
    device: Arc<dyn Device>,
}

fn source_error(answer: KeyAnswer) -> SourceError {
    match answer {
        KeyAnswer::Declined => SourceError::Declined,
        KeyAnswer::Failed(message) => SourceError::Failed(message),
        KeyAnswer::Done(_) => SourceError::Failed("the source answered out of turn".into()),
    }
}

impl Source for Lent {
    fn kinds(&self) -> Vec<Kind> {
        self.device.kinds()
    }

    fn create(&self, kind: Kind) -> BoxFuture<'_, Result<Reference, SourceError>> {
        Box::pin(async move {
            let prompts = lent()?;
            let answer = tokio::task::spawn_blocking(move || prompts.create_key(kind))
                .await
                .map_err(|_| SourceError::Failed("the source stopped".into()))?;
            match answer {
                KeyAnswer::Done(key) => Reference::from_bytes(&[&[kind as u8], &key[..]].concat())
                    .ok_or_else(|| SourceError::Failed("the source's key handle".into())),
                other => Err(source_error(other)),
            }
        })
    }

    fn evaluate<'a>(
        &'a self,
        reference: &'a Reference,
        input: [u8; 32],
    ) -> BoxFuture<'a, Result<Output, SourceError>> {
        let (kind, bytes) = (reference.kind(), reference.to_bytes());
        Box::pin(async move {
            let prompts = lent()?;
            let answer = tokio::task::spawn_blocking(move || {
                prompts.evaluate_key(kind, &bytes[1..], &input)
            })
            .await
            .map_err(|_| SourceError::Failed("the source stopped".into()))?;
            match answer {
                KeyAnswer::Done(bytes) => {
                    let mut output: Output = Box::new(Zeroizing::new([0; 32]));
                    if bytes.len() != output.len() {
                        return Err(SourceError::Failed(
                            "the source's output is not 32 bytes".into(),
                        ));
                    }
                    output.copy_from_slice(&bytes);
                    Ok(output)
                }
                other => Err(source_error(other)),
            }
        })
    }
}

/// The lent prompts as the facility's chrome.
struct Shown(Arc<dyn Prompts>);

impl Chrome for Shown {
    fn confirm(&self, form: Form) -> BoxFuture<'_, Answer> {
        let prompts = Arc::clone(&self.0);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || prompts.confirm(form))
                .await
                .unwrap_or(Answer::Declined)
        })
    }

    fn stage(&self, stage: &str) {
        self.0.stage(stage);
    }
}

/// The most sessions kept at once: a client that dies leaves its sessions
/// open, and the oldest go first.
const SESSIONS: usize = 64;

/// The facility, its runtime, its sessions and its warm-ups, its personal
/// space.
pub struct Node {
    runtime: tokio::runtime::Runtime,
    facility: Facility,
    job: Arc<Job>,
    /// The personal space, or why it does not open: sign-in and payments
    /// run whatever it is.
    personal: Option<Result<Arc<Space>, Refused>>,
    sessions: Mutex<Sessions>,
    warming: Mutex<Vec<Warming>>,
    /// Whether the app is in the foreground, and the operations and jobs
    /// running: the client is dormant only when neither.
    waking: Arc<Mutex<(bool, usize)>>,
    /// The thread making the follows a flow left for after it, one at a
    /// time: joined before the node goes.
    behind: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[derive(Default)]
struct Sessions {
    open: HashMap<u64, Arc<Session>>,
    order: VecDeque<u64>,
}

fn no_session() -> Refusal {
    refused(
        Code::NoSession,
        "the facility's process started anew since this session opened",
    )
}

fn no_personal() -> Refused {
    Refused {
        why: Why::Failed,
        detail: "this facility runs no personal space".into(),
        ..Refused::default()
    }
}

/// Whether `host` names an onion service, in any case and with its root's
/// dot.
fn onion(host: &str) -> bool {
    host.trim_end_matches('.')
        .to_ascii_lowercase()
        .ends_with(".onion")
}

/// The runtime the facility runs on.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("vos-node")
        .enable_all()
        .build()
}

impl Node {
    /// The facility whose enrollments are kept under `directory`, over
    /// arti with its state under `tor` (the app's private files, excluded
    /// from backups), bootstrapped in the background.
    pub fn open(
        directory: PathBuf,
        tor: PathBuf,
        device: Arc<dyn Device>,
    ) -> std::io::Result<Self> {
        let runtime = runtime()?;
        // Bridges that do not read are not none: Tor is held back rather
        // than tried directly where they were needed.
        let bridges = Net::bridges_kept(&directory);
        let (net, arti) = {
            let _entered = runtime.enter();
            let arti = Arti::new(tor, bridges.as_deref().unwrap_or_default())
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            (Arc::new(Net::over(Arc::clone(&arti), &directory)), arti)
        };
        // Held before anything can dial.
        if let Err(why) = &bridges {
            arti.hold(format!("the bridges kept do not read: {why}"));
        }
        let node = Self::over(runtime, directory, device, net, crate::personal::embedded())?;
        if bridges.is_ok() {
            let net = Arc::clone(node.facility.net());
            node.runtime.spawn(async move {
                // A failure is named when the chrome asks (`bootstrap`).
                let _ = net.bootstrap().await;
            });
        }
        Ok(node)
    }

    /// The same over `net` (tests: an in-process gateway's dial).
    pub fn over(
        runtime: tokio::runtime::Runtime,
        directory: PathBuf,
        device: Arc<dyn Device>,
        net: Arc<Net>,
        artifacts: Artifacts,
    ) -> std::io::Result<Self> {
        let facility = Facility::new(Store::new(&directory), Arc::new(Lent { device }), net);
        Self::with(
            runtime,
            facility,
            Job::new(&directory),
            Some((directory, artifacts)),
        )
    }

    /// The same over `facility` and `job`, with a personal space from
    /// `light` if given (tests).
    pub fn with(
        runtime: tokio::runtime::Runtime,
        facility: Facility,
        job: Job,
        light: Option<(PathBuf, Artifacts)>,
    ) -> std::io::Result<Self> {
        let personal = light.map(|(directory, artifacts)| {
            let _entered = runtime.enter();
            Space::open(
                &directory,
                &artifacts,
                facility.clone(),
                runtime.handle().clone(),
            )
            .map(Arc::new)
        });
        if let Some(Ok(space)) = &personal {
            let paired: Arc<dyn crate::session::PersonalLink> = Arc::clone(space) as _;
            facility.lend_personal(Arc::downgrade(&paired));
            if space.grouped() {
                job.attach(Arc::clone(space) as Arc<dyn crate::job::Personal>);
            }
        }
        {
            let _entered = runtime.enter();
            facility.pin_all();
        }
        Ok(Self {
            runtime,
            facility,
            job: Arc::new(job),
            personal,
            sessions: Mutex::new(Sessions::default()),
            warming: Mutex::new(Vec::new()),
            waking: Arc::new(Mutex::new((false, 0))),
            behind: Mutex::new(None),
        })
    }

    /// Whether the device has a secret source, or an enrollment already.
    pub fn supported(&self) -> bool {
        self.facility.supported()
    }

    /// Compute the enrolled kernels' programs in the background, unless the
    /// device is `thrifty` (in power-save mode or low on battery).
    pub fn warm(&self, thrifty: bool) {
        if !thrifty {
            self.keep_warming(self.facility.warm());
        }
    }

    fn keep_warming(&self, warming: Option<Warming>) {
        let mut all = crate::lock(&self.warming);
        all.retain(|warming| !warming.is_finished());
        all.extend(warming);
    }

    /// The facility on one connection: its session's handle, drawn at
    /// random so no handle of an earlier process names a session of this
    /// one.
    pub fn open_session(&self, gateway: Gateway) -> u64 {
        let session = Arc::new(self.facility.session(gateway));
        let mut sessions = crate::lock(&self.sessions);
        let handle = loop {
            let mut bytes = [0; 8];
            getrandom::getrandom(&mut bytes).expect("the system's randomness");
            let handle = u64::from_le_bytes(bytes);
            if handle != 0 && !sessions.open.contains_key(&handle) {
                break handle;
            }
        };
        sessions.open.insert(handle, session);
        sessions.order.push_back(handle);
        let mut dropped = Vec::new();
        while sessions.order.len() > SESSIONS {
            if let Some(oldest) = sessions.order.pop_front() {
                dropped.extend(sessions.open.remove(&oldest));
            }
        }
        drop(sessions);
        let _entered = self.runtime.enter();
        drop(dropped);
        handle
    }

    fn session(&self, handle: u64) -> Result<Arc<Session>, Refusal> {
        crate::lock(&self.sessions)
            .open
            .get(&handle)
            .cloned()
            .ok_or_else(no_session)
    }

    /// The user granted the facility for the session.
    pub fn granted(&self, handle: u64) -> Result<(), Refusal> {
        let session = self.session(handle)?;
        let _entered = self.runtime.enter();
        session.granted();
        self.keep_warming(session.warm());
        Ok(())
    }

    /// Close the session: the last holding a space's tree stops its
    /// refresher.
    pub fn close(&self, handle: u64) {
        let mut sessions = crate::lock(&self.sessions);
        if let Some(session) = sessions.open.remove(&handle) {
            sessions.order.retain(|open| *open != handle);
            drop(sessions);
            let _entered = self.runtime.enter();
            drop(session);
        }
    }

    /// Close every session in `handles`: a UI process that died.
    pub fn close_all(&self, handles: &[u64]) {
        for handle in handles {
            self.close(*handle);
        }
    }

    /// `operation` on the session `handle`, `prompts` lent to it.
    fn lend<T>(
        &self,
        handle: u64,
        prompts: Arc<dyn Prompts>,
        operation: impl AsyncFnOnce(&Session, &dyn Chrome) -> Result<T, Refusal>,
    ) -> Result<T, Refusal> {
        let session = self.session(handle)?;
        let chrome = Shown(Arc::clone(&prompts));
        self.awake(|| {
            self.runtime
                .block_on(LENT.scope(prompts, operation(&session, &chrome)))
        })
    }

    pub fn enroll(
        &self,
        handle: u64,
        request: Enroll,
        prompts: Arc<dyn Prompts>,
    ) -> Result<Enrolled, Refusal> {
        let request = request.check()?;
        let enrolled = self.lend(handle, prompts, async |session, chrome| {
            session.enroll(request, chrome).await
        })?;
        Ok(enrolled)
    }

    pub fn sign_in(
        &self,
        handle: u64,
        request: SignIn,
        prompts: Arc<dyn Prompts>,
    ) -> Result<SignedIn, Refusal> {
        let request = request.check()?;
        self.lend(handle, prompts, async |session, chrome| {
            session.sign_in(request, chrome).await
        })
    }

    pub fn pay(
        &self,
        handle: u64,
        request: Pay,
        prompts: Arc<dyn Prompts>,
    ) -> Result<Paid, Refusal> {
        let request = request.check()?;
        self.lend(handle, prompts, async |session, chrome| {
            session.pay(request, chrome).await
        })
    }

    /// The server says the node did not hold the proof's root.
    pub fn refresh(&self, handle: u64) -> Result<(), Refusal> {
        self.session(handle)?.refreshed();
        Ok(())
    }

    /// `personal` the job's personal space, in place of the device's.
    pub fn attach(&self, personal: Arc<dyn crate::job::Personal>) {
        self.job.attach(personal);
    }

    /// One run of the spaces' job: every enrollment's tree read if due.
    pub fn sync(&self) -> Result<Synced, Refusal> {
        let synced = self.awake(|| self.job.run(&self.runtime, &self.facility, Part::Spaces));
        self.facility.net().keep_rendezvous();
        synced
    }

    /// One run of the personal space's job, on its own schedule and its
    /// own isolation group.
    pub fn sync_personal(&self) -> Result<Synced, Refusal> {
        let synced = self.awake(|| self.job.run(&self.runtime, &self.facility, Part::Personal));
        self.facility.net().keep_rendezvous();
        synced
    }

    /// `run` with the client awake, dormant again after once nothing else
    /// runs and the app is in the background.
    fn awake<T>(&self, run: impl FnOnce() -> T) -> T {
        let _awake = self.wake();
        run()
    }

    /// The client awake, within the runtime, until the guard drops.
    fn wake(&self) -> Awake<'_> {
        let entered = self.runtime.enter();
        let mut waking = crate::lock(&self.waking);
        waking.1 += 1;
        self.facility.net().set_dormant(false);
        drop(waking);
        Awake {
            node: self,
            _entered: entered,
        }
    }

    /// The app came to the foreground, or left it (its binding's grace
    /// over): the client awake, or dormant (no circuit kept, no timer
    /// firing) once no operation or job runs.
    pub fn foreground(&self, foreground: bool) {
        let _entered = self.runtime.enter();
        let mut waking = crate::lock(&self.waking);
        waking.0 = foreground;
        // The app in the background: a restore's sitting holds no kit.
        if !foreground && let Some(Ok(space)) = &self.personal {
            space.forget_kit();
        }
        self.facility.net().set_foreground(foreground);
        self.facility.net().keep_rendezvous();
        if foreground {
            self.facility.net().set_dormant(false);
        } else if waking.1 == 0 {
            self.facility.net().set_dormant(true);
        }
    }

    /// The bridges pasted in the chrome (none: the public relays): arti
    /// built anew through them and bootstrapped, its failure named as
    /// `BootstrapError`'s `Display` names it.
    pub fn bridges(&self, lines: Vec<String>) -> Result<(), Refusal> {
        self.awake(|| self.runtime.block_on(self.facility.net().bridges(lines)))
            .map_err(|error| refused(Code::Api, error))
    }

    /// Bootstrap arti now: its failure named.
    pub fn bootstrap(&self) -> Result<(), Refusal> {
        self.awake(|| self.runtime.block_on(self.facility.net().bootstrap()))
            .map_err(|error| refused(Code::Api, error))
    }

    /// Opt the space whose handle is `handle` out of Tor for its key-signed
    /// calls, after the chrome showed `net::OPT_OUT_WARNING`; or back.
    pub fn opt_out(&self, handle: [u8; 32], out: bool) -> Result<(), Refusal> {
        let _entered = self.runtime.enter();
        self.facility
            .net()
            .opt_out(vos_light::route::space(&handle), out)
            .map_err(|refusal| refused(Code::Refused, refusal))
    }

    /// The background job's runs kept, the latest last.
    pub fn runs(&self) -> Result<Vec<JobRun>, Refusal> {
        self.job.runs()
    }

    /// The enrollments kept.
    pub fn enrollments(&self) -> Result<Vec<EnrolledSpace>, Refusal> {
        self.facility.enrollments()
    }

    /// s4's screen session with the gateway `gateway` names, carried
    /// between `end` (the UI's end of a socket pair) and that gateway's SSH
    /// port over its space's routes, on a circuit of its own, for as long
    /// as both sides keep it open: the carriage names the SSH host key the
    /// space pinned for that port, the one the UI accepts, and the onion it
    /// took; a space's own onion is that space's, however it was enrolled.
    /// An onion service no space pins is carried over Tor all the same, on
    /// a circuit of its own, with no key pinned: the client's known hosts
    /// decide it, as for any first contact. `NotEnrolled` for any other
    /// gateway no space was enrolled through: the UI connects itself.
    pub fn screens(
        &self,
        gateway: StreamTarget,
        end: std::os::fd::OwnedFd,
    ) -> Result<Carriage, Refusal> {
        let _entered = self.runtime.enter();
        let space = match self.facility.screens_space(&gateway) {
            Ok(space) => space,
            Err(refusal) if refusal.code == Code::NotEnrolled && onion(&gateway.host) => {
                if let Some(space) = self.facility.onion_space(&gateway.host)? {
                    return self.carried(space, end);
                }
                let host = gateway.host.trim_end_matches('.');
                let stream = self
                    .awake(|| {
                        self.runtime
                            .block_on(self.facility.net().onion_stream(host, gateway.port))
                    })
                    .map_err(|error| refused(Code::Api, error.to_string()))?;
                crate::stream::carry(end, Box::new(stream))
                    .map_err(|error| refused(Code::Failed, error.to_string()))?;
                return Ok(Carriage {
                    ssh_host_key: None,
                    onion: host.to_ascii_lowercase(),
                });
            }
            Err(refusal) => return Err(refusal),
        };
        self.carried(space, end)
    }

    /// s4's screens carried over `space`'s routes: the key it pinned, and
    /// the onion it took.
    fn carried(
        &self,
        space: crate::net::SpaceId,
        end: std::os::fd::OwnedFd,
    ) -> Result<Carriage, Refusal> {
        let screens = self.awake(|| {
            self.runtime
                .block_on(self.facility.net().client().screens_fd(space, end))
        });
        screens
            .map(|screens| Carriage {
                ssh_host_key: Some(screens.ssh_host_key),
                onion: screens.onion.unwrap_or_default(),
            })
            .map_err(|error| refused(Code::Api, error.to_string()))
    }

    /// Refused when `host_key`, presented to s4's own connection to a
    /// gateway, is one a space pinned to its onion while its routes take
    /// it: s4 then reaches that gateway only through [`Node::screens`],
    /// however its name or port is spelled.
    pub fn clearnet(&self, host_key: [u8; 32]) -> Result<(), Refusal> {
        let _entered = self.runtime.enter();
        self.facility.clearnet_refused(&host_key)
    }

    // ----- the personal space -----

    /// The personal space, or why it does not open: its reads, and the
    /// test seams that need no client awake.
    pub fn space(&self) -> Result<&Arc<Space>, Refused> {
        match &self.personal {
            Some(Ok(space)) => Ok(space),
            Some(Err(refusal)) => Err(refusal.clone()),
            None => Err(no_personal()),
        }
    }

    /// The personal space's state, read without a request: its phase
    /// (in need of repair when it does not open as this build reads it),
    /// Tor's state and the notices standing after the last pass.
    pub fn status(&self) -> Result<PersonalStatus, Refused> {
        let (tor, tor_why) = self.facility.net().tor();
        // The facility's database not read is the facility in need of
        // repair, whatever the personal space is.
        let (standing, mut repair) = match self.job.standing() {
            Ok(standing) => (standing, None),
            Err(refusal) => (Vec::new(), Some(refusal.message)),
        };
        if let Some(why) = self.facility.net().repair() {
            repair.get_or_insert(why);
        }
        let mut status = match &self.personal {
            Some(Ok(space)) => space.status()?,
            Some(Err(refused)) if refused.why == Why::NeedsRepair => PersonalStatus {
                phase: Phase::NeedsRepair,
                repair: refused.detail.clone(),
                ..PersonalStatus::default()
            },
            Some(Err(refused)) => return Err(refused.clone()),
            None => return Err(no_personal()),
        };
        (status.tor, status.tor_why, status.standing) = (tor, tor_why, standing);
        status.failed = self.job.failed().unwrap_or_default();
        if let Some(repair) = repair {
            (status.phase, status.repair) = (Phase::NeedsRepair, repair);
        }
        Ok(status)
    }

    /// The personal space for one flow, called on it directly
    /// (`node.personal()?.claim(..)`): its client awake while the flow
    /// runs, the job attached once the device holds a group.
    pub fn personal(&self) -> Result<Personal<'_>, Refused> {
        let space = self.space()?;
        Ok(Personal {
            space,
            job: &self.job,
            phase: phase(space),
            _awake: self.wake(),
        })
    }

    /// The follows a flow left for after it returned
    /// ([`vos_light::space::Personal::follow_behind`]), on a thread of
    /// their own with the client awake: the flow's answer does not wait
    /// for them, and one that fails stands as a notice until a pass
    /// finishes what it left.
    fn follow_behind(&self, space: &Arc<Space>) {
        let mut running = crate::lock(&self.behind);
        // One thread at a time: one running makes these follows too.
        if !space.behind() || running.as_ref().is_some_and(|thread| !thread.is_finished()) {
            return;
        }
        let (space, job, waking) = (
            Arc::clone(space),
            Arc::clone(&self.job),
            Arc::clone(&self.waking),
        );
        let (facility, runtime) = (self.facility.clone(), self.runtime.handle().clone());
        crate::lock(&waking).1 += 1;
        facility.net().set_dormant(false);
        *running = Some(std::thread::spawn(move || {
            {
                let _entered = runtime.enter();
                match space.follow_behind() {
                    Ok(()) => job.finished(),
                    Err(_) => job.unfinished(crate::job::now_ms()),
                }
            }
            let _entered = runtime.enter();
            let mut waking = crate::lock(&waking);
            waking.1 -= 1;
            if *waking == (false, 0) {
                facility.net().set_dormant(true);
            }
        }));
    }
}

/// The device's phase, if it reads.
fn phase(space: &Space) -> Option<Phase> {
    space.status().ok().map(|status| status.phase)
}

/// The personal space lent to one flow ([`Node::personal`]).
pub struct Personal<'a> {
    space: &'a Arc<Space>,
    job: &'a Arc<Job>,
    /// The device's phase before the flow.
    phase: Option<Phase>,
    _awake: Awake<'a>,
}

impl std::ops::Deref for Personal<'_> {
    type Target = Space;

    fn deref(&self) -> &Space {
        self.space
    }
}

impl Drop for Personal<'_> {
    fn drop(&mut self) {
        // Its notices of being out of the group go once it follows it; of
        // the kit's operations before, once its own restore finished.
        if phase(self.space) == Some(Phase::Held) {
            self.job.following(self.phase == Some(Phase::Restoring));
        }
        if self.space.grouped() {
            self.job
                .attach(Arc::clone(self.space) as Arc<dyn crate::job::Personal>);
        }
        self._awake.node.follow_behind(self.space);
    }
}

/// The client awake while this lives ([`Node::wake`]).
struct Awake<'a> {
    node: &'a Node,
    _entered: tokio::runtime::EnterGuard<'a>,
}

impl Drop for Awake<'_> {
    fn drop(&mut self) {
        let mut waking = crate::lock(&self.node.waking);
        waking.1 -= 1;
        if *waking == (false, 0) {
            self.node.facility.net().set_dormant(true);
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // The follows left stop after the one running, before the runtime
        // goes: the next pass makes the rest.
        if let Some(Ok(space)) = &self.personal {
            space.drop_behind();
        }
        if let Some(thread) = crate::lock(&self.behind).take() {
            let _ = thread.join();
        }
        for warming in crate::lock(&self.warming).iter() {
            warming.cancel();
        }
        let _entered = self.runtime.enter();
        crate::lock(&self.sessions).open.clear();
    }
}
