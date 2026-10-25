//! [`KreivoVenue`]: Kreivo as a [`VenueClient`].
//!
//! The representative's leader hands an anchor over inside its batch, so
//! [`VenueClient::anchor`] never waits on the chain: it answers from what
//! the client last read (the space's status and anchor keys) and queues
//! what it takes in an [`AnchorQueue`], whose worker sends each space's
//! anchors in window order. A reader thread connects (a node starts while
//! Kreivo is down: until it is reached, every anchor is `Open`), then reads
//! the watched spaces every [`Options::refresh`]. Submits go on the
//! caller's thread. Every call is signed by the node's one account, one at
//! a time ([`Sender`]).
//!
//! The client does not judge an anchor: the pallet does, by the venue
//! rules (`vos_anchor::venue`), and the client maps its answer onto the
//! leader's [`AnchorOutcome`] by one table (`send::outcome`,
//! `spaces-pallet.md` §9). It answers an anchor from its last read: not
//! yet while it has not read the space, the space is not registered or
//! anchors are paused; stopped while the space is not active; unlisted
//! while the space does not list the signer; never for a window the venue
//! refused for good, or one at or behind the space's last anchored at
//! which it holds no root; else taken, and queued. The queue's worker
//! sends it unless the venue already holds a root there: the same root
//! settles it; another is sent only when the leader offered the anchor
//! after reading that root ([`VenueClient::held`]), its divergence guard
//! passed, as the equivocation's evidence, which ends the space. The
//! pallet's answers are kept: 16 `WindowInFuture` waits a block of the
//! venue's time; 20 `Paused`, 21 and 27, and `InvalidTransaction::Payment`
//! (a funding alert) wait for the next read; 11 `UnknownAnchorKey` and 7
//! `NotAuthority` drop the signer from the listing read, until the next
//! read; the pool's other refusals an alert, and again after a backoff.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use vos_anchor::venue::{self as rules, Held, Roots};
use vos_anchor::{Anchor, RootKind, RootRead, SpaceId, VenueId};
use vos_statement::Statement;

use super::calls::{
    self, AccountInfo, AnchorRecord, Balance, Call, Error, MAX_PROOF_LEN, MAX_STATEMENT_LEN,
    PAUSED_ANCHOR, SpaceInfo, SpaceStatus, keys,
};
use super::send::KreivoSend;
use super::transport::{Backoff, Lost, Sender, Transport};
use crate::queue::AnchorQueue;
use crate::{AnchorOutcome, Held as Holding, Status, SubmitOutcome, UNJUDGED, VenueClient};

/// How the client paces itself, and what it takes a submit to cost.
#[derive(Clone, Debug)]
pub struct Options {
    /// How often the reader reads the watched spaces and the venue's time.
    pub refresh: Duration,
    /// The first wait after a lost connection, doubled up to 32 times it.
    pub backoff: Duration,
    /// A block's time: after `WindowInFuture`, or an anchor landed whose
    /// answer was lost, an anchor waits this much of the venue's time.
    pub block_ms: u64,
    /// The most one submit takes of the paying space's sovereign account:
    /// `SubmitDeposit` and a fee's bound, 1.5 UNIT at the design's
    /// suggested values (`spaces-pallet.md` §4).
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
            per_submit: UNITS + UNITS / 2,
            funding_submits: 8,
        }
    }
}

/// What the client tells an operator: each is logged as an error, once
/// while it repeats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alert {
    /// An anchor the venue refuses for good: its window too old. The window
    /// stays unanchored.
    Dead {
        space: SpaceId,
        window: u64,
        error: Error,
    },
    /// The venue held another root of the space at a window than this
    /// node's anchor: a listed anchor key signed it. This node's anchor
    /// went as the equivocation's evidence, which ends the space for good;
    /// it re-founds under a new genesis.
    Equivocation { space: SpaceId, window: u64 },
    /// The node's configuration at the venue: the space unknown or not
    /// active, this node not its authority, the pallet paused, a key or a
    /// signature refused, or a call past the venue's bounds.
    Configuration { space: SpaceId, what: String },
    /// The paying space's funds: the venue refused the fee
    /// (`InvalidTransaction::Payment`: its sovereign's balance or its
    /// budget), its sovereign could not pay (21, 27), or it holds less than
    /// [`Options::funding_submits`] submits.
    Funding { space: SpaceId, what: String },
    /// An answer the client cannot place.
    Unexpected(String),
}

/// What the client last read of a space.
#[derive(Clone, Debug, Default)]
pub(super) struct Known {
    /// Whether it has been read since it was watched.
    read: bool,
    pub(super) info: Option<SpaceInfo>,
    /// Its anchor keys (`AnchorKeys[space]`).
    pub(super) keys: Vec<[u8; 32]>,
    /// Its last anchored window (`Last[space][0]`).
    pub(super) last: Option<u64>,
    /// What the venue holds at the windows the client read (`Anchors[w]`):
    /// a root, or none. Forgotten when the space is read not active, or
    /// ends, and each window once it ages.
    pub(super) held: BTreeMap<u64, Option<[u8; 32]>>,
    /// The windows at or behind its last the leader asked of, to read.
    wanted: BTreeSet<u64>,
    /// The windows the venue refused for good, each with its code.
    pub(super) never: BTreeMap<u64, u32>,
    /// The windows at which the leader offered an anchor while the client
    /// held another root read there: sent as the equivocation's evidence.
    pub(super) evidence: BTreeSet<u64>,
}

#[derive(Default)]
pub(super) struct State {
    /// The venue's time when last read.
    pub(super) now: Option<u64>,
    /// `Paused`'s flags.
    pub(super) paused: u8,
    pub(super) spaces: BTreeMap<SpaceId, Known>,
    /// The venue time an anchor waits for before it goes again: after
    /// `WindowInFuture`, or after it landed with its answer lost.
    pub(super) later: BTreeMap<(SpaceId, u64), u64>,
    alerts: Vec<Alert>,
    /// When the reader last read the spaces: none to read them now.
    pub(super) refreshed: Option<Instant>,
    /// How many times it has read them.
    reads: u64,
}

/// The most alerts kept for [`KreivoVenue::alerts`].
const ALERTS: usize = 256;

impl State {
    pub(super) fn alert(&mut self, alert: Alert) {
        if self.alerts.last() != Some(&alert) {
            tracing::error!(?alert, "Kreivo");
            if self.alerts.len() == ALERTS {
                self.alerts.remove(0);
            }
            self.alerts.push(alert);
        }
    }

    /// `space`, watched from now on: read at the reader's next turn.
    pub(super) fn watch(&mut self, space: SpaceId) -> &Known {
        if !self.spaces.contains_key(&space) {
            self.refreshed = None;
        }
        self.spaces.entry(space).or_default()
    }

    /// The anchor of `key`'s space and window no longer waits on the venue.
    pub(super) fn forget(&mut self, key: (SpaceId, u64)) {
        self.later.remove(&key);
    }

    /// `space` ended by an equivocation: none of its roots taken as
    /// anchored, and the space read again.
    pub(super) fn ended(&mut self, space: SpaceId) {
        if let Some(known) = self.spaces.get_mut(&space) {
            known.held.clear();
        }
        self.refreshed = None;
    }

    /// `anchor` seen anchored.
    pub(super) fn held(&mut self, anchor: &Anchor) {
        self.forget((anchor.space, anchor.window));
        let known = self.spaces.entry(anchor.space).or_default();
        known.held.insert(anchor.window, Some(anchor.root));
        known.last = known.last.max(Some(anchor.window));
    }
}

/// How the client reaches Kreivo, made on the reader's thread and made
/// again until it is reached.
pub type Connect = Box<dyn FnMut() -> Result<Arc<dyn Transport>, Lost> + Send>;

pub(super) struct Shared {
    /// The space whose sovereign account pays this node's submits.
    pub(super) payer: SpaceId,
    pub(super) options: Options,
    /// Set once Kreivo is reached.
    pub(super) sender: OnceLock<Sender>,
    /// Kreivo's genesis hash, once read.
    id: OnceLock<VenueId>,
    state: Mutex<State>,
    wake: Condvar,
    stopping: AtomicBool,
}

/// Kreivo, through the spaces pallet's client.
pub struct KreivoVenue {
    shared: Arc<Shared>,
    queue: AnchorQueue,
}

impl KreivoVenue {
    /// The venue `connect` reaches, signing with its account, on a thread
    /// of its own: the spaces in `spaces` watched, and `payer` the space
    /// whose sovereign account pays this node's submits. It runs until it
    /// is dropped.
    pub fn connect(connect: Connect, spaces: &[SpaceId], payer: SpaceId, options: Options) -> Self {
        Self::start(Some(connect), None, spaces, payer, options)
    }

    /// The venue `transport` reaches, read once now when it can be, before
    /// a batch asks.
    pub fn over(
        transport: Arc<dyn Transport>,
        spaces: &[SpaceId],
        payer: SpaceId,
        options: Options,
    ) -> Self {
        Self::start(None, Some(transport), spaces, payer, options)
    }

    fn start(
        connect: Option<Connect>,
        transport: Option<Arc<dyn Transport>>,
        spaces: &[SpaceId],
        payer: SpaceId,
        options: Options,
    ) -> Self {
        let mut state = State::default();
        for space in spaces.iter().chain([&payer]) {
            state.watch(*space);
        }
        let shared = Arc::new(Shared {
            payer,
            sender: OnceLock::new(),
            id: OnceLock::new(),
            state: Mutex::new(state),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
            options,
        });
        if let Some(transport) = transport {
            shared.reached(transport);
            if let Err(Lost(why)) = shared.refresh() {
                tracing::warn!(%why, "Kreivo is not reachable to read");
            }
        }
        let reader = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("kreivo".into())
            .spawn(move || reader.read_on(connect))
            .expect("Kreivo's reader starts");
        let queue = AnchorQueue::spawn("kreivo-anchors", KreivoSend(Arc::clone(&shared)));
        Self { shared, queue }
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
        self.queue.len()
    }
}

impl Drop for KreivoVenue {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        if let Some(sender) = self.shared.sender.get() {
            sender.stop();
        }
        self.shared.wake.notify_all();
    }
}

impl Shared {
    pub(super) fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn stopped(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Wait `wait`, or until woken.
    fn pause(&self, wait: Duration) {
        let state = self.state();
        let _ = self.wake.wait_timeout(state, wait);
    }

    /// Kreivo's genesis read through `transport`: the venue's id.
    fn read_id(&self, transport: &dyn Transport) -> Result<(), Lost> {
        let genesis = transport.genesis()?;
        let _ = self.id.set(VenueId(genesis));
        Ok(())
    }

    /// Kreivo reached through `transport`: its genesis read, if it can be.
    fn reached(&self, transport: Arc<dyn Transport>) {
        let _ = self.read_id(&*transport);
        let _ = self
            .sender
            .set(Sender::new(transport, self.options.backoff));
    }

    fn transport(&self) -> Result<&Arc<dyn Transport>, Lost> {
        self.sender
            .get()
            .map(Sender::transport)
            .ok_or_else(|| Lost("Kreivo is not reached yet".into()))
    }

    pub(super) fn read<T: parity_scale_codec::Decode>(
        &self,
        key: &[u8],
    ) -> Result<Option<T>, Lost> {
        Ok(self
            .transport()?
            .storage(key)?
            .and_then(|bytes| calls::read(&bytes)))
    }

    pub(super) fn venue_now(&self) -> Result<u64, Lost> {
        let now = self
            .read::<u64>(&keys::now())?
            .ok_or_else(|| Lost("no `Timestamp.Now`".into()))?;
        self.state().now = Some(now);
        Ok(now)
    }

    /// Connect, read Kreivo's genesis, then read the watched spaces every
    /// refresh, until stopped.
    fn read_on(&self, mut connect: Option<Connect>) {
        let mut backoff = Backoff::new(self.options.backoff);
        loop {
            if self.stopped() {
                return;
            }
            let reached = match (self.sender.get(), connect.as_mut()) {
                (Some(_), _) => Ok(()),
                (None, Some(connect)) => connect().map(|transport| self.reached(transport)),
                (None, None) => Err(Lost("no way to reach Kreivo".into())),
            };
            let genesis = reached.and_then(|()| match self.id.get() {
                Some(_) => Ok(()),
                None => self.read_id(&**self.transport()?),
            });
            if let Err(Lost(why)) = genesis {
                tracing::warn!(%why, "Kreivo is not reachable; trying again");
                self.pause(backoff.next());
                continue;
            }
            backoff.reset();
            let due = self
                .state()
                .refreshed
                .is_none_or(|at| at.elapsed() >= self.options.refresh);
            if due && let Err(Lost(why)) = self.refresh() {
                tracing::warn!(%why, "Kreivo is not reachable to read");
            }
            self.pause(self.options.refresh);
        }
    }

    /// Read the venue's time, the pause, and every watched space; alert
    /// when the paying space's sovereign account runs short.
    fn refresh(&self) -> Result<(), Lost> {
        self.venue_now()?;
        let paused = self.read::<u8>(&keys::paused())?.unwrap_or(0);
        let watched: Vec<SpaceId> = self.state().spaces.keys().copied().collect();
        let mut read = Vec::new();
        for space in watched {
            let info = self.read::<SpaceInfo>(&keys::spaces(&space.0))?;
            let prefix = keys::anchor_keys_of(&space.0);
            let keys = self
                .transport()?
                .keys(&prefix)?
                .iter()
                .filter_map(|key| key.get(prefix.len()..)?.try_into().ok())
                .collect();
            let last = self.read::<u64>(&keys::last(&space.0, 0))?;
            let wanted: Vec<u64> = self
                .state()
                .spaces
                .get(&space)
                .map(|known| known.wanted.iter().copied().collect())
                .unwrap_or_default();
            let mut held = Vec::new();
            for window in wanted {
                let record = keys::anchors(&space.0, RootKind::Space as u8, window);
                let root = self
                    .read::<AnchorRecord>(&record)?
                    .map(|record| record.root);
                held.push((window, root));
            }
            read.push((space, info, keys, last, held));
        }
        let payer = read
            .iter()
            .find(|(space, ..)| *space == self.payer)
            .and_then(|(_, info, ..)| *info);
        let now = self.state().now;
        let free = match &payer {
            Some(info) => self
                .read::<AccountInfo>(&keys::account(&info.sovereign))?
                .unwrap_or_default()
                .free
                .into(),
            None => None,
        };
        let mut state = self.state();
        state.paused = paused;
        for (space, info, keys, last, held) in read {
            let known = state.spaces.entry(space).or_default();
            known.read = true;
            known.info = info;
            known.keys = keys;
            for (window, root) in held {
                known.wanted.remove(&window);
                known.held.entry(window).or_insert(root);
            }
            // A blocked or ended space's roots are not anchored: what was
            // seen held is read from the venue anew.
            if info.is_none_or(|info| info.status != SpaceStatus::Active) {
                known.held.clear();
            }
            // A venue's last window never goes back: a read begun before
            // an anchor landed does not undo the anchor seen held.
            known.last = known.last.max(last);
            if let (Some(info), Some(now)) = (info, now) {
                let fresh = |window: &u64| !rules::aged(&info.clock(), *window, now);
                known.held.retain(|window, _| fresh(window));
                known.never.retain(|window, _| fresh(window));
                known.evidence.retain(fresh);
                known.wanted.retain(fresh);
            }
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
}

impl VenueClient for KreivoVenue {
    fn id(&self) -> VenueId {
        self.shared.id.get().copied().unwrap_or(VenueId([0; 32]))
    }

    fn anchor(&self, anchor: &Anchor) -> AnchorOutcome {
        // Signed over the venue's id: one signed before Kreivo was reached
        // goes again, signed anew.
        let Some(id) = self.shared.id.get() else {
            return AnchorOutcome::NotYet;
        };
        if !crate::signed(anchor, id) {
            return AnchorOutcome::NotYet;
        }
        let mut state = self.shared.state();
        let paused = state.paused & PAUSED_ANCHOR != 0;
        state.watch(anchor.space);
        let Some(known) = state.spaces.get_mut(&anchor.space) else {
            return AnchorOutcome::NotYet;
        };
        if !known.read {
            self.shared.wake.notify_all();
            return AnchorOutcome::NotYet;
        }
        let Some(info) = known.info else {
            return AnchorOutcome::NotYet;
        };
        if info.status != SpaceStatus::Active {
            return AnchorOutcome::Stopped(Error::SpaceNotActive as u32);
        }
        if paused {
            return AnchorOutcome::NotYet;
        }
        if !known.keys.contains(&anchor.signer) {
            return AnchorOutcome::Unlisted(Error::UnknownAnchorKey as u32);
        }
        let window = anchor.window;
        if let Some(code) = known.never.get(&window) {
            return AnchorOutcome::Never(*code);
        }
        match known.held.get(&window) {
            Some(Some(root)) if *root == anchor.root => return AnchorOutcome::Taken,
            Some(Some(_)) => {
                known.evidence.insert(window);
            }
            Some(None) if rules::passed(known.last, window) => {
                return AnchorOutcome::Never(Error::WindowNotAfterLast as u32);
            }
            _ => {}
        }
        drop(state);
        self.queue.push(anchor);
        AnchorOutcome::Taken
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> SubmitOutcome {
        let id = statement.id();
        let bytes = statement.encode();
        let space = self.shared.payer;
        if bytes.len() > MAX_STATEMENT_LEN || proof.len() > MAX_PROOF_LEN {
            let what = "a statement or proof past the venue's bounds".to_string();
            self.shared
                .state()
                .alert(Alert::Configuration { space, what });
            return SubmitOutcome::Retry(UNJUDGED);
        }
        let Some(sender) = self.shared.sender.get() else {
            return SubmitOutcome::Retry(UNJUDGED);
        };
        if let Some(verdict) = self.shared.before_paying(statement, &id) {
            return verdict;
        }
        let call = Call::Submit {
            payer: space.0,
            statement: bytes,
            proof: proof.to_vec(),
        }
        .bytes();
        self.shared.send_submit(sender, &call, id)
    }

    /// The venue rules' `anchored` over the client's last read of the
    /// space and the venue's time, and the root held at the window: the
    /// one it saw anchored, or else the venue's record, read now.
    fn anchored(&self, root: &RootRead) -> bool {
        let (info, now, seen) = {
            let mut state = self.shared.state();
            let now = state.now;
            let known = state.watch(root.space);
            (
                known.info,
                now,
                known.held.get(&root.window).copied().flatten(),
            )
        };
        let (Some(info), Some(now)) = (info, now) else {
            return false;
        };
        let held = match seen {
            Some(seen) if seen == root.root => Some(seen),
            _ => {
                let key = keys::anchors(&root.space.0, root.kind as u8, root.window);
                self.shared
                    .read::<AnchorRecord>(&key)
                    .ok()
                    .flatten()
                    .map(|record| record.root)
            }
        };
        rules::anchored(&Read { info, now, held }, root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.shared.state().watch(*space).keys.clone()
    }

    fn status(&self, space: &SpaceId) -> Status {
        let mut state = self.shared.state();
        state
            .watch(*space)
            .info
            .as_ref()
            .map_or(Status::Unregistered, |info| info.status.into())
    }

    /// `Timestamp.Now` as the reader thread last read it.
    fn time(&self) -> Option<u64> {
        self.shared.state().now
    }

    /// The root read at `window`: none past the space's last anchored;
    /// unread at or behind it until the reader reads it.
    fn held(&self, space: &SpaceId, window: u64) -> Holding {
        let mut state = self.shared.state();
        state.watch(*space);
        let Some(known) = state.spaces.get_mut(space) else {
            return Holding::Unread;
        };
        if !known.read {
            return Holding::Unread;
        }
        match known.held.get(&window) {
            Some(Some(root)) => Holding::Root(*root),
            Some(None) => Holding::Nothing,
            None if !rules::passed(known.last, window) => Holding::Nothing,
            None => {
                if known.wanted.insert(window) {
                    state.refreshed = None;
                    self.shared.wake.notify_all();
                }
                Holding::Unread
            }
        }
    }
}

/// One window of a space as the client read it, for the venue rules.
struct Read {
    info: SpaceInfo,
    now: u64,
    /// The root the venue holds at the window asked about.
    held: Option<[u8; 32]>,
}

impl Roots for Read {
    fn now(&self) -> u64 {
        self.now
    }

    fn space(&self, _: &SpaceId) -> Option<rules::Space> {
        Some(rules::Space {
            clock: self.info.clock(),
            start: self.info.start_window,
            status: self.info.status.into(),
        })
    }

    fn held(&self, _: &SpaceId, _: RootKind, _: u64) -> Option<Held> {
        self.held.map(|root| Held {
            root,
            signer: [0; 32],
        })
    }
}
