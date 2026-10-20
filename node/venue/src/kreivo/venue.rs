//! [`KreivoVenue`]: Kreivo as a [`VenueClient`].
//!
//! The representative's leader hands an anchor over inside its batch, so
//! [`VenueClient::anchor`] never waits on the chain: it answers from what
//! the client last read (the space's status, range, anchor keys and last
//! anchored window, and the venue's time) and queues what it takes. One
//! worker thread sends the queue in window order, submits in turn, all
//! signed by the node's one account ([`Sender`]), and reads the watched
//! spaces again every [`Options::refresh`].
//!
//! The worker never sends an anchor for a window the venue's clock has not
//! closed (`w < now_w` by `Timestamp.Now`), nor while the space is not
//! active or anchors are paused: each failed `anchor` is a fee the space's
//! sovereign account pays. The pallet's errors (`spaces-pallet.md` §9):
//! 14 `AlreadyAnchored` and 15 `WindowNotAfterLast` done; 16
//! `WindowInFuture` sent again once the venue's time passes `B_w` plus a
//! block, never skipped; 17 `WindowTooOld` and 18 `OutOfRange` dead, with
//! an alert; the configuration's errors and `InvalidTransaction::Payment`
//! an alert.

use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use vos_anchor::{Anchor, MAX_ROOT_AGE_MS, RootRead, SpaceId, VenueId};
use vos_statement::{Statement, StatementId};

use super::calls::{
    self, AccountInfo, Active, AnchorRecord, Balance, Call, Error, Event, MAX_PROOF_LEN,
    MAX_STATEMENT_LEN, PAUSED_ANCHOR, PAUSED_SUBMIT, ProgramInfo, SpaceInfo, SpaceStatus, Spend,
    keys,
};
use super::transport::{Invalid, Lost, Sender, Sent, Transport, Unsent};
use crate::{AnchorRefusal, Anchored, NotAccepted, Status, Unjudged, VenueClient};

/// How the client paces itself, and what it takes a submit to cost.
#[derive(Clone, Debug)]
pub struct Options {
    /// How often the worker reads the watched spaces and the venue's time.
    pub refresh: Duration,
    /// The first wait after a lost connection, doubled up to 32 times it.
    pub backoff: Duration,
    /// A block's time: after `WindowInFuture`, an anchor waits until the
    /// venue's time passes the window's boundary by this much.
    pub block_ms: u64,
    /// The most one submit takes of the paying space's sovereign account:
    /// `SubmitDeposit` and a fee's bound.
    pub per_submit: Balance,
    /// The funding alert: the sovereign account's free balance below this
    /// many submits.
    pub funding_submits: u32,
}

impl Default for Options {
    fn default() -> Self {
        const UNITS: Balance = 1_000_000_000_000;
        Self {
            refresh: Duration::from_secs(2),
            backoff: Duration::from_secs(1),
            block_ms: 12_000,
            per_submit: UNITS,
            funding_submits: 8,
        }
    }
}

/// What the client tells an operator: each is logged as an error, once
/// while it repeats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alert {
    /// An anchor the venue refuses for good: its window too old, or past
    /// the space's migration away. The window stays unanchored.
    Dead {
        space: SpaceId,
        window: u64,
        error: Error,
    },
    /// An anchor recorded an equivocation: the space is suspended until
    /// its controller removes both keys and resumes it.
    Equivocation { space: SpaceId, window: u64 },
    /// The node's configuration at the venue: the space unknown or not
    /// active, this node not its authority, the pallet paused, a key or a
    /// signature refused, or a call past the venue's bounds.
    Configuration { space: SpaceId, what: String },
    /// The paying space's funds: the venue refused the fee
    /// (`InvalidTransaction::Payment`: its sovereign's balance or its
    /// budget), or its sovereign account holds less than
    /// [`Options::funding_submits`] submits.
    Funding { space: SpaceId, what: String },
    /// An answer the client cannot place.
    Unexpected(String),
}

/// What the client last read of a space.
#[derive(Clone, Debug, Default)]
struct Known {
    /// Whether it has been read since it was watched.
    read: bool,
    info: Option<SpaceInfo>,
    /// Its anchor keys (`AnchorKeys[space]`).
    keys: Vec<[u8; 32]>,
    /// Its last anchored window (`Last[space][0]`).
    last: Option<u64>,
    /// The roots the client saw anchored, by window.
    held: BTreeMap<u64, [u8; 32]>,
}

/// An anchor queued, and the venue time it waits for.
struct Waiting {
    anchor: Anchor,
    not_before: u64,
}

/// A submit for the worker to send, and where its verdict goes.
struct Job {
    call: Vec<u8>,
    id: StatementId,
    answer: mpsc::Sender<Result<StatementId, NotAccepted>>,
}

#[derive(Default)]
struct State {
    /// The venue's time when last read.
    now: Option<u64>,
    /// `Paused`'s flags.
    paused: u8,
    spaces: BTreeMap<SpaceId, Known>,
    queue: BTreeMap<(SpaceId, u64), Waiting>,
    submits: VecDeque<Job>,
    alerts: Vec<Alert>,
    /// When the worker last read the spaces: none to read them now.
    refreshed: Option<Instant>,
    /// How many times it has read them.
    reads: u64,
}

/// The most anchored roots kept of a space, its newest: a leader asks
/// again only of its last few windows.
const HELD: usize = 64;

/// The most alerts kept for [`KreivoVenue::alerts`].
const ALERTS: usize = 256;

impl State {
    fn alert(&mut self, alert: Alert) {
        if self.alerts.last() != Some(&alert) {
            tracing::error!(?alert, "Kreivo");
            if self.alerts.len() == ALERTS {
                self.alerts.remove(0);
            }
            self.alerts.push(alert);
        }
    }

    /// `space`, watched from now on: read at the worker's next turn.
    fn watch(&mut self, space: SpaceId) -> &Known {
        if !self.spaces.contains_key(&space) {
            self.refreshed = None;
        }
        self.spaces.entry(space).or_default()
    }
}

struct Shared {
    id: VenueId,
    /// The space whose sovereign account pays this node's submits.
    payer: SpaceId,
    sender: Sender,
    options: Options,
    state: Mutex<State>,
    wake: Condvar,
}

/// Kreivo, through the spaces pallet's client.
pub struct KreivoVenue {
    shared: Arc<Shared>,
}

impl KreivoVenue {
    /// The venue `transport` reaches, signing with its account: the spaces
    /// in `spaces` read once now, before a batch asks, and `payer` the
    /// space whose sovereign account pays this node's submits. Its worker
    /// runs until it is dropped.
    pub fn connect(
        transport: Arc<dyn Transport>,
        spaces: &[SpaceId],
        payer: SpaceId,
        options: Options,
    ) -> Result<Self, Lost> {
        let id = VenueId(transport.genesis()?);
        let mut state = State::default();
        for space in spaces.iter().chain([&payer]) {
            state.watch(*space);
        }
        let shared = Arc::new(Shared {
            id,
            payer,
            sender: Sender::new(transport, options.backoff),
            options,
            state: Mutex::new(state),
            wake: Condvar::new(),
        });
        shared.refresh()?;
        let worker = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("kreivo".into())
            .spawn(move || worker.run())
            .map_err(|error| Lost(error.to_string()))?;
        Ok(Self { shared })
    }

    /// The alerts raised, oldest first.
    pub fn alerts(&self) -> Vec<Alert> {
        self.shared.state().alerts.clone()
    }

    /// How many times the client has read the venue's state.
    pub fn reads(&self) -> u64 {
        self.shared.state().reads
    }

    /// The anchors queued, not yet settled at the venue.
    pub fn queued(&self) -> usize {
        self.shared.state().queue.len()
    }
}

impl Drop for KreivoVenue {
    fn drop(&mut self) {
        self.shared.sender.stop();
        self.shared.wake.notify_all();
    }
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn transport(&self) -> &Arc<dyn Transport> {
        self.sender.transport()
    }

    fn read<T: parity_scale_codec::Decode>(&self, key: &[u8]) -> Result<Option<T>, Lost> {
        Ok(self
            .transport()
            .storage(key)?
            .and_then(|bytes| calls::read(&bytes)))
    }

    fn venue_now(&self) -> Result<u64, Lost> {
        let now = self
            .read::<u64>(&keys::now())?
            .ok_or_else(|| Lost("no `Timestamp.Now`".into()))?;
        self.state().now = Some(now);
        Ok(now)
    }

    /// Read the venue's time, the pause, and every watched space; alert
    /// when the paying space's sovereign account runs short.
    fn refresh(&self) -> Result<(), Lost> {
        let now = self.venue_now()?;
        let paused = self.read::<u8>(&keys::paused())?.unwrap_or(0);
        let watched: Vec<SpaceId> = self.state().spaces.keys().copied().collect();
        let mut read = Vec::new();
        for space in watched {
            let info = self.read::<SpaceInfo>(&keys::spaces(&space.0))?;
            let prefix = keys::anchor_keys_of(&space.0);
            let keys = self
                .transport()
                .keys(&prefix)?
                .iter()
                .filter_map(|key| key.get(prefix.len()..)?.try_into().ok())
                .collect();
            let last = self.read::<u64>(&keys::last(&space.0, 0))?;
            read.push((space, info, keys, last));
        }
        let payer = read
            .iter()
            .find(|(space, ..)| *space == self.payer)
            .and_then(|(_, info, ..)| info.clone());
        let free = match &payer {
            Some(info) => self
                .read::<AccountInfo>(&keys::account(&info.sovereign))?
                .unwrap_or_default()
                .free
                .into(),
            None => None,
        };
        let mut state = self.state();
        state.now = Some(now);
        state.paused = paused;
        for (space, info, keys, last) in read {
            let known = state.spaces.entry(space).or_default();
            known.read = true;
            known.info = info;
            known.keys = keys;
            known.last = last;
        }
        let floor = self
            .options
            .per_submit
            .saturating_mul(self.options.funding_submits.into());
        if let Some(free) = free.filter(|free: &Balance| *free < floor) {
            let what = format!("the sovereign account holds {free}, under {floor}");
            state.alert(Alert::Funding {
                space: self.payer,
                what,
            });
        }
        state.refreshed = Some(Instant::now());
        state.reads += 1;
        Ok(())
    }

    fn run(self: Arc<Self>) {
        loop {
            if self.sender.stopped() {
                return;
            }
            let due = self
                .state()
                .refreshed
                .is_none_or(|at| at.elapsed() >= self.options.refresh);
            if due && let Err(Lost(why)) = self.refresh() {
                tracing::warn!(%why, "Kreivo is not reachable to read");
            }
            let job = self.state().submits.pop_front();
            if let Some(job) = job {
                let verdict = self.send_submit(&job);
                let _ = job.answer.send(verdict);
                continue;
            }
            if self.send_anchor() {
                continue;
            }
            let state = self.state();
            if state.submits.is_empty() {
                let _ = self.wake.wait_timeout(state, self.options.refresh);
            }
        }
    }

    /// Send the first anchor queued, when the venue would take it: whether
    /// it sent one.
    fn send_anchor(&self) -> bool {
        let Some((key, anchor, not_before)) = self
            .state()
            .queue
            .first_key_value()
            .map(|(key, waiting)| (*key, waiting.anchor, waiting.not_before))
        else {
            return false;
        };
        let (space, window) = key;
        let Ok(now) = self.venue_now() else {
            return false;
        };
        let mut state = self.state();
        let paused = state.paused & PAUSED_ANCHOR != 0;
        let Some(info) = state
            .spaces
            .get(&space)
            .and_then(|known| known.info.clone())
        else {
            state.queue.remove(&key);
            let what = "the space is not registered".to_string();
            state.alert(Alert::Configuration { space, what });
            return true;
        };
        let clock = info.clock();
        let boundary = clock.boundary(window).unwrap_or(u64::MAX);
        if now.saturating_sub(boundary) > MAX_ROOT_AGE_MS {
            state.queue.remove(&key);
            let error = Error::WindowTooOld;
            state.alert(Alert::Dead {
                space,
                window,
                error,
            });
            return true;
        }
        let closed = clock.window(now).is_some_and(|open| window < open);
        if paused || info.status != SpaceStatus::Active || !closed || now < not_before {
            return false;
        }
        drop(state);
        let sent = self.sender.call(&Call::anchor(&anchor).bytes());
        let mut state = self.state();
        let settled = match sent {
            Ok(Sent::Included(outcome)) => {
                let anchored = outcome.events.iter().any(|event| {
                    matches!(event, Event::Anchored { space: of, window: w, root, .. }
                        if *of == space.0 && *w == window && *root == anchor.root)
                });
                let equivocated = outcome
                    .events
                    .iter()
                    .any(|event| matches!(event, Event::Equivocated { .. }));
                if anchored {
                    held(&mut state, &anchor);
                    true
                } else if equivocated {
                    state.alert(Alert::Equivocation { space, window });
                    true
                } else {
                    let error = outcome.failure.and_then(|failure| failure.pallet());
                    self.anchor_failed(&mut state, &key, error, boundary)
                }
            }
            Ok(Sent::Landed) => {
                drop(state);
                let record = self.read::<AnchorRecord>(&keys::anchors(&space.0, 0, window));
                state = self.state();
                if let Ok(Some(record)) = &record
                    && record.root == anchor.root
                {
                    held(&mut state, &anchor);
                }
                true
            }
            Err(Unsent::Invalid(Invalid::Payment)) => {
                let what = "the venue refused an anchor's fee".to_string();
                state.alert(Alert::Funding { space, what });
                false
            }
            Err(Unsent::Invalid(invalid)) => {
                state.alert(Alert::Unexpected(format!("an anchor refused: {invalid:?}")));
                true
            }
            Err(Unsent::Stopped) => return false,
        };
        if settled {
            state.queue.remove(&key);
        }
        settled
    }

    /// What an anchor's dispatch error makes of it: whether it is settled.
    fn anchor_failed(
        &self,
        state: &mut State,
        key: &(SpaceId, u64),
        error: Option<Error>,
        boundary: u64,
    ) -> bool {
        let (space, window) = *key;
        match anchor_fate(error) {
            Fate::Done => true,
            Fate::Later => {
                if let Some(waiting) = state.queue.get_mut(key) {
                    waiting.not_before = boundary.saturating_add(self.options.block_ms);
                }
                false
            }
            Fate::Dead(error) => {
                state.alert(Alert::Dead {
                    space,
                    window,
                    error,
                });
                true
            }
            Fate::Inactive => {
                state.refreshed = None;
                false
            }
            Fate::Paused => {
                state.paused |= PAUSED_ANCHOR;
                false
            }
            Fate::Configuration(error) => {
                let what = format!("an anchor refused: {error:?}");
                state.alert(Alert::Configuration { space, what });
                true
            }
            Fate::Unexpected => {
                let what = "an anchor failed for a reason not the pallet's".to_string();
                state.alert(Alert::Unexpected(what));
                true
            }
        }
    }

    /// Send a submit: its verdict.
    fn send_submit(&self, job: &Job) -> Result<StatementId, NotAccepted> {
        let space = self.payer;
        let unjudged = |state: &mut State, alert: Alert, why: Unjudged| {
            state.alert(alert);
            Err(NotAccepted::Unjudged(why))
        };
        match self.sender.call(&job.call) {
            Ok(Sent::Included(outcome)) => {
                if let Some(verdict) = judged(&outcome.events, job.id) {
                    return verdict;
                }
                let mut state = self.state();
                let error = outcome.failure.and_then(|failure| failure.pallet());
                match error {
                    Some(Error::InsufficientSovereignBalance | Error::OverBudget) => {
                        let what = format!("a submit refused: {error:?}");
                        unjudged(
                            &mut state,
                            Alert::Funding { space, what },
                            Unjudged::Funding,
                        )
                    }
                    Some(error) => {
                        let what = format!("a submit refused: {error:?}");
                        let alert = Alert::Configuration { space, what };
                        unjudged(&mut state, alert, Unjudged::Configuration)
                    }
                    None => {
                        let what = format!("a submit's outcome unread: {outcome:?}");
                        unjudged(&mut state, Alert::Unexpected(what), Unjudged::Unknown)
                    }
                }
            }
            Ok(Sent::Landed) => match self.read::<u64>(&keys::seen(&job.id.0)) {
                Ok(Some(_)) => Ok(job.id),
                _ => Err(NotAccepted::Unjudged(Unjudged::Unknown)),
            },
            Err(Unsent::Invalid(Invalid::Payment)) => {
                let what = "the venue refused a submit's fee".to_string();
                let alert = Alert::Funding { space, what };
                unjudged(&mut self.state(), alert, Unjudged::Funding)
            }
            Err(Unsent::Invalid(invalid)) => {
                let what = format!("a submit refused: {invalid:?}");
                let alert = Alert::Configuration { space, what };
                unjudged(&mut self.state(), alert, Unjudged::Configuration)
            }
            Err(Unsent::Stopped) => Err(NotAccepted::Unjudged(Unjudged::Unknown)),
        }
    }

    /// What the venue's state says of `statement` before paying for it,
    /// in pin F's order as far as its storage tells (the pause, the
    /// format, the program, a repeat), then the paying space and its
    /// budget: a verdict, or none to send it. A read that fails says
    /// nothing.
    fn before_paying(
        &self,
        statement: &Statement,
        id: &StatementId,
    ) -> Option<Result<StatementId, NotAccepted>> {
        let space = self.payer;
        let configuration = |what: &str| {
            let what = what.to_string();
            self.state().alert(Alert::Configuration { space, what });
            Some(Err(NotAccepted::Unjudged(Unjudged::Configuration)))
        };
        if self.read::<u8>(&keys::paused()).ok()?.unwrap_or(0) & PAUSED_SUBMIT != 0 {
            return configuration("submits are paused");
        }
        let now = self.venue_now().ok()?;
        let format = self.read::<Active>(&keys::formats(statement.format)).ok()?;
        if !format.is_some_and(|active| active.at(now)) {
            return Some(Err(NotAccepted::Refused(2)));
        }
        let program = self
            .read::<ProgramInfo>(&keys::programs(&statement.program.0))
            .ok()?;
        if !program.is_some_and(|info| info.active.at(now)) {
            return Some(Err(NotAccepted::Refused(3)));
        }
        if self.read::<u64>(&keys::seen(&id.0)).ok()?.is_some() {
            return Some(Ok(*id));
        }
        let Some(info) = self.read::<SpaceInfo>(&keys::spaces(&space.0)).ok()? else {
            return configuration("the paying space is not registered");
        };
        if info.status != SpaceStatus::Active {
            return configuration("the paying space is not active");
        }
        let spend = self.read::<Spend>(&keys::budget(&space.0)).ok()?;
        let window = info.clock().window(now);
        let spent = spend
            .filter(|spend| Some(spend.window) == window)
            .map_or(0, |spend| spend.spent);
        if spent.saturating_add(self.options.per_submit) > info.max_spend_per_window {
            let what = format!(
                "the window's budget is spent: {spent} of {}",
                info.max_spend_per_window
            );
            self.state().alert(Alert::Funding { space, what });
            return Some(Err(NotAccepted::Unjudged(Unjudged::Funding)));
        }
        None
    }
}

/// What becomes of an anchor the chain refused (`spaces-pallet.md` §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fate {
    /// 14 `AlreadyAnchored`, 15 `WindowNotAfterLast`: the venue holds it,
    /// or a later window.
    Done,
    /// 16 `WindowInFuture`: sent again once the venue's time passes the
    /// window's boundary by a block; never skipped.
    Later,
    /// 17 `WindowTooOld`, 18 `OutOfRange`: never taken; an alert.
    Dead(Error),
    /// 19 `SpaceNotActive`: kept until the space is active again.
    Inactive,
    /// 20 `Paused`: kept until anchors are not paused.
    Paused,
    /// Any other of the pallet's: the node's configuration, or a bug; an
    /// alert.
    Configuration(Error),
    /// Not the pallet's error: an alert.
    Unexpected,
}

pub(super) fn anchor_fate(error: Option<Error>) -> Fate {
    match error {
        Some(Error::AlreadyAnchored | Error::WindowNotAfterLast) => Fate::Done,
        Some(Error::WindowInFuture) => Fate::Later,
        Some(error @ (Error::WindowTooOld | Error::OutOfRange)) => Fate::Dead(error),
        Some(Error::SpaceNotActive) => Fate::Inactive,
        Some(Error::Paused) => Fate::Paused,
        Some(error) => Fate::Configuration(error),
        None => Fate::Unexpected,
    }
}

/// A submit's verdict from its events: `Accepted { id }` accepted,
/// `Refused { 6 }` accepted (a repeat, two nodes racing), `Refused { c }`
/// refused; none when it was not judged.
pub(super) fn judged(
    events: &[Event],
    id: StatementId,
) -> Option<Result<StatementId, NotAccepted>> {
    events.iter().find_map(|event| match event {
        Event::Accepted { id: accepted, .. } if *accepted == id.0 => Some(Ok(id)),
        Event::Refused { code: 6, .. } => Some(Ok(id)),
        Event::Refused { code, .. } => Some(Err(NotAccepted::Refused(*code))),
        _ => None,
    })
}

/// `anchor` seen anchored.
fn held(state: &mut State, anchor: &Anchor) {
    let known = state.spaces.entry(anchor.space).or_default();
    known.held.insert(anchor.window, anchor.root);
    while known.held.len() > HELD {
        known.held.pop_first();
    }
    known.last = known.last.max(Some(anchor.window));
}

impl VenueClient for KreivoVenue {
    fn id(&self) -> VenueId {
        self.shared.id
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        let mut state = self.shared.state();
        let known = state.watch(anchor.space).clone();
        if !known.read {
            self.shared.wake.notify_all();
            return Err(AnchorRefusal::Open);
        }
        let Some(info) = known.info else {
            return Err(AnchorRefusal::Unregistered);
        };
        if info.status != SpaceStatus::Active {
            return Err(AnchorRefusal::Suspended);
        }
        if !known.keys.contains(&anchor.signer) {
            return Err(AnchorRefusal::Key);
        }
        let window = anchor.window;
        if known.last.is_some_and(|last| window <= last) {
            return match known.held.get(&window) {
                Some(root) if *root == anchor.root => Ok(Anchored::Again),
                _ => Err(AnchorRefusal::Window),
            };
        }
        if !info.holds(window) {
            return Err(AnchorRefusal::Window);
        }
        let key = (anchor.space, window);
        if state.queue.contains_key(&key) {
            return Ok(Anchored::Queued);
        }
        let clock = info.clock();
        let now = state.now.unwrap_or(0);
        if clock.window(now).is_none_or(|open| window >= open) {
            return Err(AnchorRefusal::Open);
        }
        let boundary = clock.boundary(window).unwrap_or(u64::MAX);
        if now.saturating_sub(boundary) > MAX_ROOT_AGE_MS {
            return Err(AnchorRefusal::Age);
        }
        let waiting = Waiting {
            anchor: *anchor,
            not_before: 0,
        };
        state.queue.insert(key, waiting);
        self.shared.wake.notify_all();
        Ok(Anchored::Queued)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        let id = statement.id();
        let bytes = statement.encode();
        if bytes.len() > MAX_STATEMENT_LEN || proof.len() > MAX_PROOF_LEN {
            let what = "a statement or proof past the venue's bounds".to_string();
            let space = self.shared.payer;
            self.shared
                .state()
                .alert(Alert::Configuration { space, what });
            return Err(NotAccepted::Unjudged(Unjudged::Configuration));
        }
        if let Some(verdict) = self.shared.before_paying(statement, &id) {
            return verdict;
        }
        let call = Call::Submit {
            payer: self.shared.payer.0,
            statement: bytes,
            proof: proof.to_vec(),
        }
        .bytes();
        let (answer, verdict) = mpsc::channel();
        self.shared
            .state()
            .submits
            .push_back(Job { call, id, answer });
        self.shared.wake.notify_all();
        verdict
            .recv()
            .unwrap_or(Err(NotAccepted::Unjudged(Unjudged::Unknown)))
    }

    fn anchored(&self, root: &RootRead) -> bool {
        let (known, now) = {
            let mut state = self.shared.state();
            (state.watch(root.space).clone(), state.now)
        };
        let Some(info) = known.info else {
            return false;
        };
        let fresh = info
            .clock()
            .boundary(root.window)
            .zip(now)
            .is_some_and(|(boundary, now)| now.saturating_sub(boundary) <= MAX_ROOT_AGE_MS);
        if info.status != SpaceStatus::Active || !info.holds(root.window) || !fresh {
            return false;
        }
        if known.held.get(&root.window) == Some(&root.root) {
            return true;
        }
        let key = keys::anchors(&root.space.0, root.kind as u8, root.window);
        self.shared
            .read::<AnchorRecord>(&key)
            .is_ok_and(|record| record.is_some_and(|record| record.root == root.root))
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.shared.state().watch(*space).keys.clone()
    }

    fn status(&self, space: &SpaceId) -> Status {
        let mut state = self.shared.state();
        match state.watch(*space).info.as_ref().map(|info| info.status) {
            None => Status::Unregistered,
            Some(SpaceStatus::Active) => Status::Active,
            Some(SpaceStatus::Suspended) => Status::Suspended,
            Some(SpaceStatus::Blocked) => Status::Blocked,
        }
    }
}
