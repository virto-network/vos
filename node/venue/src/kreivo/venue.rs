//! [`KreivoVenue`]: Kreivo as a [`VenueClient`].
//!
//! The representative's leader hands an anchor over inside its batch, so
//! [`VenueClient::anchor`] never waits on the chain: it answers from what
//! the client last read (the space's status, range, anchor keys and last
//! anchored window, and the venue's time) and queues what it takes in an
//! [`AnchorQueue`], whose worker sends each space's anchors in window
//! order. A reader thread connects (a node starts while Kreivo is down:
//! until it is reached, every anchor is `Open`), then reads the watched
//! spaces every [`Options::refresh`]. Submits go on the caller's thread.
//! Every call is signed by the node's one account, one at a time
//! ([`Sender`]).
//!
//! An anchor is never sent for a window the venue's clock has not closed
//! (`w < now_w` by `Timestamp.Now`), nor while the space is not active or
//! anchors are paused: each failed `anchor` is a fee the space's sovereign
//! account pays. It is settled only by the venue holding it or a later
//! window (14 `AlreadyAnchored`, 15 `WindowNotAfterLast`), by an
//! equivocation, or for good (17 `WindowTooOld`, 18 `OutOfRange`, or past
//! `MaxRootAge` by the venue's clock); otherwise it is kept: 16
//! `WindowInFuture` until `Timestamp.Now` passes `B_w` plus a block; 19 and
//! 20 until the space is active and anchors are not paused; 21 and 27, and
//! `InvalidTransaction::Payment`, a funding alert, until the next read; 11
//! `UnknownAnchorKey`, or a signer the space no longer lists by the
//! client's last read (then unsent), an alert, and the anchor handed back
//! to the representative's leader to sign again with a key it lists
//! ([`VenueClient::unsettled`]); the others (7 `NotAuthority`, 12 the
//! signature, 13 the kind) an alert, and again a window later; the pool's
//! other refusals an alert, and again after a backoff.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use vos_anchor::{Anchor, RootRead, SpaceId, VenueId};
use vos_statement::{Statement, StatementId};

use super::calls::{
    self, AccountInfo, AnchorRecord, Balance, Call, Error, MAX_PROOF_LEN, MAX_STATEMENT_LEN,
    SpaceInfo, SpaceStatus, keys,
};
use super::send::KreivoSend;
use super::transport::{Backoff, Lost, Sender, Transport};
use crate::queue::AnchorQueue;
use crate::{AnchorRefusal, Anchored, NotAccepted, Status, Unjudged, VenueClient};

/// How the client paces itself, and what it takes a submit to cost.
#[derive(Clone, Debug)]
pub struct Options {
    /// How often the reader reads the watched spaces and the venue's time.
    pub refresh: Duration,
    /// The first wait after a lost connection, doubled up to 32 times it.
    pub backoff: Duration,
    /// A block's time: after `WindowInFuture`, or an anchor landed whose
    /// record is not read yet, an anchor waits this much of the venue's
    /// time.
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
    /// The roots the client saw anchored, by window: the newest [`HELD`].
    held: BTreeMap<u64, [u8; 32]>,
}

#[derive(Default)]
pub(super) struct State {
    /// The venue's time when last read.
    pub(super) now: Option<u64>,
    /// `Paused`'s flags.
    pub(super) paused: u8,
    pub(super) spaces: BTreeMap<SpaceId, Known>,
    /// The venue time an anchor waits for before it goes again: after
    /// `WindowInFuture`, or after it landed with its record not yet read.
    pub(super) later: BTreeMap<(SpaceId, u64), u64>,
    /// Anchors that landed with their answers lost: their records are read
    /// before they go again.
    pub(super) landed: BTreeSet<(SpaceId, u64)>,
    alerts: Vec<Alert>,
    /// When the reader last read the spaces: none to read them now.
    pub(super) refreshed: Option<Instant>,
    /// How many times it has read them.
    reads: u64,
}

/// The most anchored roots kept of a space, its newest: a leader asks
/// again only of its last few windows.
const HELD: usize = 64;

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
        self.landed.remove(&key);
    }

    /// `anchor` seen anchored.
    pub(super) fn held(&mut self, anchor: &Anchor) {
        self.forget((anchor.space, anchor.window));
        let known = self.spaces.entry(anchor.space).or_default();
        known.held.insert(anchor.window, anchor.root);
        while known.held.len() > HELD {
            known.held.pop_first();
        }
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
            read.push((space, info, keys, last));
        }
        let payer = read
            .iter()
            .find(|(space, ..)| *space == self.payer)
            .and_then(|(_, info, ..)| *info);
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
        for (space, info, keys, last) in read {
            let known = state.spaces.entry(space).or_default();
            known.read = true;
            known.info = info;
            known.keys = keys;
            // A venue's last window never goes back: a read begun before
            // an anchor landed does not undo the anchor seen held.
            known.last = known.last.max(last);
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

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        // Signed over the venue's id: one signed before Kreivo was reached
        // goes again, signed anew.
        let Some(id) = self.shared.id.get() else {
            return Err(AnchorRefusal::Open);
        };
        if !crate::signed(anchor, id) {
            return Err(AnchorRefusal::Open);
        }
        let mut state = self.shared.state();
        let now = state.now.unwrap_or(0);
        let known = state.watch(anchor.space);
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
        // Settled, taken or refused for good: no longer handed back.
        let settled = |answer| {
            self.queue.settle(&anchor.space, window);
            answer
        };
        if known.last.is_some_and(|last| window <= last) {
            return settled(match known.held.get(&window) {
                Some(root) if *root == anchor.root => Ok(Anchored::Again),
                _ => Err(AnchorRefusal::Window),
            });
        }
        if !info.holds(window) || self.queue.dead(&anchor.space, window) {
            return settled(Err(AnchorRefusal::Window));
        }
        // Queued already: this one replaces it if signed by another key.
        if self.queue.holds(&anchor.space, window) {
            self.queue.push_listed(anchor);
            return Ok(Anchored::Queued);
        }
        let clock = info.clock();
        if clock.window(now).is_none_or(|open| window >= open) {
            return Err(AnchorRefusal::Open);
        }
        if crate::aged(&clock, window, now) {
            return Err(AnchorRefusal::Age);
        }
        drop(state);
        // Its key listed by the last read: queued, even if an anchor of it
        // by the same key was handed back before the listing changed.
        self.queue.push_listed(anchor);
        Ok(Anchored::Queued)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        let id = statement.id();
        let bytes = statement.encode();
        let space = self.shared.payer;
        if bytes.len() > MAX_STATEMENT_LEN || proof.len() > MAX_PROOF_LEN {
            let what = "a statement or proof past the venue's bounds".to_string();
            self.shared
                .state()
                .alert(Alert::Configuration { space, what });
            return Err(NotAccepted::Unjudged(Unjudged::Configuration));
        }
        let Some(sender) = self.shared.sender.get() else {
            return Err(NotAccepted::Unjudged(Unjudged::Unknown));
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

    fn anchored(&self, root: &RootRead) -> bool {
        {
            let mut state = self.shared.state();
            let now = state.now;
            let known = state.watch(root.space);
            let Some(info) = known.info else {
                return false;
            };
            let fresh = now.is_some_and(|now| crate::fresh(&info.clock(), root.window, now));
            if info.status != SpaceStatus::Active || !info.holds(root.window) || !fresh {
                return false;
            }
            if known.held.get(&root.window) == Some(&root.root) {
                return true;
            }
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

    fn unsettled(&self, space: &SpaceId) -> Vec<Anchor> {
        self.queue.unsettled(space)
    }
}
