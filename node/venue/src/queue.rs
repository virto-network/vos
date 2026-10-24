//! A venue client's anchors in flight ([`AnchorQueue`]): the
//! representative's leader hands an anchor over inside its batch, so a
//! client that reaches a chain queues it and answers at once; one worker
//! thread sends each space's anchors in window order through the client's
//! [`AnchorSend`], until the venue holds one, refuses it for good, or it
//! is too old. Each space waits apart: one space's wait holds back only
//! its own later windows.
//!
//! An anchor whose key the venue does not list is dropped and handed back
//! ([`AnchorQueue::unsettled`]): the representative's leader signs its
//! root again with a key the venue lists. Until it is queued again, or the
//! venue no longer needs it ([`AnchorSend::settled`]: it holds the window
//! or a later one, or the window is past `MaxRootAge`), its window holds
//! back its space's later ones, since a venue takes a space's windows in
//! rising order only; and the same anchor, by the same signer, is refused
//! ([`AnchorQueue::push`]). An anchor queued again with another signer
//! replaces the one queued, the newest signature winning.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use vos_anchor::{Anchor, SpaceId};

/// How many windows the venue will never take a queue remembers, the
/// latest refused, so an anchor of one handed over again is refused at
/// once, unsent.
const DEAD_KEPT: usize = 256;

/// How often the worker asks whether a window handed back is still
/// needed.
const UNSETTLED_RECHECK: Duration = Duration::from_secs(60);

/// What became of an anchor sent, or offered to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    /// The venue holds it, or a later window of its space: settled.
    Done,
    /// The venue will never take it (too old, past the space's range):
    /// settled, its client having alerted.
    Dead,
    /// Not taken now: kept, and offered again no sooner than this.
    Again(Duration),
    /// Not taken as signed, the venue not listing its key: dropped and
    /// handed back to be signed again, its client having alerted.
    Resign,
}

/// How a client sends one anchor: it checks the venue would take it,
/// sends it, and follows it until the venue answers.
pub trait AnchorSend: Send + Sync + 'static {
    fn send(&self, anchor: &Anchor) -> Fate;
    /// Whether the venue no longer needs `anchor`, handed back to be
    /// signed again: it holds its window or a later one of its space, or
    /// the window is past `MaxRootAge` by the venue's time. False while the
    /// client cannot say.
    fn settled(&self, anchor: &Anchor) -> bool;
}

struct Entry {
    anchor: Anchor,
    not_before: Instant,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<(SpaceId, u64), Entry>,
    /// The anchors handed back to be signed again, by space and window.
    unsettled: BTreeMap<(SpaceId, u64), Anchor>,
    /// The windows the venue will never take, at most [`DEAD_KEPT`], and
    /// the order they were refused in.
    dead: BTreeSet<(SpaceId, u64)>,
    refused: VecDeque<(SpaceId, u64)>,
    stopping: bool,
}

impl State {
    /// Whether `space` has a window handed back before `window`, which
    /// holds `window` back.
    fn held_back(&self, space: SpaceId, window: u64) -> bool {
        self.unsettled
            .range((space, 0)..(space, window))
            .next()
            .is_some()
    }

    fn died(&mut self, key: (SpaceId, u64)) {
        if self.dead.insert(key) {
            self.refused.push_back(key);
        }
        while self.refused.len() > DEAD_KEPT {
            if let Some(oldest) = self.refused.pop_front() {
                self.dead.remove(&oldest);
            }
        }
    }
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Anchors queued, by space and window, and the worker sending them.
pub struct AnchorQueue {
    shared: Arc<Shared>,
}

impl AnchorQueue {
    /// A queue whose worker, a thread named `name`, sends through
    /// `sender` until the queue is dropped.
    pub fn spawn(name: &str, sender: impl AnchorSend) -> Self {
        Self::spawn_rechecking(name, sender, UNSETTLED_RECHECK)
    }

    /// [`AnchorQueue::spawn`], asking whether each window handed back is
    /// still needed every `recheck`.
    pub fn spawn_rechecking(name: &str, sender: impl AnchorSend, recheck: Duration) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::default(),
            wake: Condvar::new(),
        });
        let worker = Arc::clone(&shared);
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || run(&worker, &sender, recheck))
            .expect("the anchor queue's thread starts");
        Self { shared }
    }

    /// Queue `anchor`, unless one of its space and window by the same
    /// signer is queued: one by another signer is replaced, and sent
    /// next. False, queuing nothing, for the anchor handed back itself, by
    /// the signer the venue does not list: a client answers it refused for
    /// its key. Another signer's settles the window handed back.
    pub fn push(&self, anchor: &Anchor) -> bool {
        self.queue(anchor, false)
    }

    /// [`AnchorQueue::push`] by a client that read the venue listing
    /// `anchor`'s key since it was handed back: queued whatever its signer.
    pub fn push_listed(&self, anchor: &Anchor) {
        self.queue(anchor, true);
    }

    fn queue(&self, anchor: &Anchor, listed: bool) -> bool {
        let mut state = self.shared.state();
        let key = (anchor.space, anchor.window);
        if let Some(back) = state.unsettled.get(&key) {
            if back.signer == anchor.signer && !listed {
                return false;
            }
            state.unsettled.remove(&key);
        }
        let entry = Entry {
            anchor: *anchor,
            not_before: Instant::now(),
        };
        match state.entries.get_mut(&key) {
            Some(queued) if queued.anchor.signer == anchor.signer => {}
            Some(queued) => *queued = entry,
            None => {
                state.entries.insert(key, entry);
            }
        }
        self.shared.wake.notify_all();
        true
    }

    /// The anchors of `space` handed back to be signed again ([`Fate::Resign`]),
    /// not queued again since and still needed, in window order.
    pub fn unsettled(&self, space: &SpaceId) -> Vec<Anchor> {
        self.shared
            .state()
            .unsettled
            .range((*space, 0)..=(*space, u64::MAX))
            .map(|(_, anchor)| *anchor)
            .collect()
    }

    /// No longer hand back `space`'s anchor of `window`: its client found
    /// it settled, taken or refused for good.
    pub fn settle(&self, space: &SpaceId, window: u64) {
        self.shared.state().unsettled.remove(&(*space, window));
        self.shared.wake.notify_all();
    }

    /// Whether an anchor of `space` at `window` is queued.
    pub fn holds(&self, space: &SpaceId, window: u64) -> bool {
        self.shared.state().entries.contains_key(&(*space, window))
    }

    /// Whether the venue refused an anchor of `space` at `window` for
    /// good ([`Fate::Dead`]): a client answers one handed over again
    /// refused, unsent.
    pub fn dead(&self, space: &SpaceId, window: u64) -> bool {
        self.shared.state().dead.contains(&(*space, window))
    }

    /// How many anchors are queued.
    pub fn len(&self) -> usize {
        self.shared.state().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for AnchorQueue {
    fn drop(&mut self) {
        self.shared.state().stopping = true;
        self.shared.wake.notify_all();
    }
}

/// The first anchor of each space, in space order, unless a window handed
/// back holds it back: the one due soonest among them, or when the
/// earliest is due.
fn next(state: &State, now: Instant) -> Result<((SpaceId, u64), Anchor), Option<Instant>> {
    let mut earliest: Option<Instant> = None;
    let mut space = None;
    for (key, entry) in &state.entries {
        if space == Some(key.0) {
            continue;
        }
        space = Some(key.0);
        if state.held_back(key.0, key.1) {
            continue;
        }
        if entry.not_before <= now {
            return Ok((*key, entry.anchor));
        }
        earliest = Some(earliest.map_or(entry.not_before, |at| at.min(entry.not_before)));
    }
    Err(earliest)
}

/// Drop the anchors handed back that the venue no longer needs, asked
/// with the state's lock released.
fn recheck(shared: &Shared, sender: &impl AnchorSend) {
    let back: Vec<Anchor> = shared.state().unsettled.values().copied().collect();
    let settled: Vec<Anchor> = back
        .into_iter()
        .filter(|anchor| sender.settled(anchor))
        .collect();
    let mut state = shared.state();
    for anchor in settled {
        let key = (anchor.space, anchor.window);
        if state.unsettled.get(&key) == Some(&anchor) {
            state.unsettled.remove(&key);
        }
    }
}

fn run(shared: &Shared, sender: &impl AnchorSend, every: Duration) {
    let mut rechecked = Instant::now();
    let mut state = shared.state();
    loop {
        if state.stopping {
            return;
        }
        if !state.unsettled.is_empty() && rechecked.elapsed() >= every {
            drop(state);
            recheck(shared, sender);
            rechecked = Instant::now();
            state = shared.state();
            continue;
        }
        let now = Instant::now();
        let (key, anchor) = match next(&state, now) {
            Ok(due) => due,
            Err(earliest) => {
                let due = earliest.map_or(Duration::from_secs(3_600), |at| at - now);
                let wait = match state.unsettled.is_empty() {
                    true => due,
                    false => due.min(every.saturating_sub(rechecked.elapsed())),
                };
                state = shared
                    .wake
                    .wait_timeout(state, wait)
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .0;
                continue;
            }
        };
        drop(state);
        let fate = sender.send(&anchor);
        state = shared.state();
        // Replaced while it was sent: the new one goes next, whatever
        // became of this one, unless the venue now holds the window.
        let replaced = state
            .entries
            .get(&key)
            .is_none_or(|entry| entry.anchor != anchor);
        match fate {
            Fate::Done => {
                state.entries.remove(&key);
            }
            _ if replaced => {}
            Fate::Dead => {
                state.entries.remove(&key);
                state.died(key);
            }
            Fate::Resign => {
                state.entries.remove(&key);
                state.unsettled.insert(key, anchor);
                if state
                    .entries
                    .range(key..=(key.0, u64::MAX))
                    .next()
                    .is_some()
                {
                    tracing::warn!(
                        window = key.1,
                        "an anchor handed back to be signed again: its space's later windows wait \
                         behind it"
                    );
                }
            }
            Fate::Again(after) => {
                if let Some(entry) = state.entries.get_mut(&key) {
                    entry.not_before = Instant::now() + after;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use vos_anchor::RootKind;

    use super::*;

    fn anchor(space: u8, window: u64) -> Anchor {
        Anchor {
            space: SpaceId([space; 32]),
            window,
            kind: RootKind::Space,
            root: [0; 32],
            signer: [0; 32],
            signature: [0; 64],
        }
    }

    /// Space 1 waits; space 2's anchors are sent all the same, in window
    /// order; a repeat is queued once. Space 1's send is held until
    /// `held` is cleared, so the test queues space 2's anchors while the
    /// worker is busy, and the worker finds them all at once.
    struct Sends {
        sent: Mutex<Vec<(u8, u64)>>,
        tries: AtomicUsize,
        held: AtomicBool,
    }

    impl AnchorSend for Arc<Sends> {
        fn send(&self, anchor: &Anchor) -> Fate {
            self.tries.fetch_add(1, Ordering::SeqCst);
            if anchor.space.0[0] == 1 {
                while self.held.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                return Fate::Again(Duration::from_secs(60));
            }
            self.sent
                .lock()
                .unwrap()
                .push((anchor.space.0[0], anchor.window));
            Fate::Done
        }

        fn settled(&self, _: &Anchor) -> bool {
            false
        }
    }

    #[test]
    fn each_space_waits_apart_and_sends_in_window_order() {
        let sends = Arc::new(Sends {
            sent: Mutex::default(),
            tries: AtomicUsize::new(0),
            held: AtomicBool::new(true),
        });
        let queue = AnchorQueue::spawn("test-anchors", Arc::clone(&sends));
        queue.push(&anchor(1, 3));
        queue.push(&anchor(1, 3));
        queue.push(&anchor(1, 4));
        let start = Instant::now();
        while sends.tries.load(Ordering::SeqCst) == 0 {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(1));
        }
        for window in [6, 5, 7] {
            queue.push(&anchor(2, window));
        }
        sends.held.store(false, Ordering::SeqCst);
        while sends.sent.lock().unwrap().len() < 3 {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(*sends.sent.lock().unwrap(), [(2, 5), (2, 6), (2, 7)]);
        assert_eq!(queue.len(), 2, "space 1's two kept");
        assert!(queue.holds(&SpaceId([1; 32]), 4));
        assert_eq!(
            sends.tries.load(Ordering::SeqCst),
            4,
            "space 1's first once"
        );
    }

    /// Hands back every anchor signed by `refused`, and takes the rest,
    /// recording each window and signer it took; a handed-back anchor is
    /// settled once `settled` is set.
    struct Rotated {
        refused: [u8; 32],
        taken: Mutex<Vec<(u64, [u8; 32])>>,
        settled: AtomicBool,
    }

    impl AnchorSend for Arc<Rotated> {
        fn send(&self, anchor: &Anchor) -> Fate {
            if anchor.signer == self.refused {
                return Fate::Resign;
            }
            self.taken
                .lock()
                .unwrap()
                .push((anchor.window, anchor.signer));
            Fate::Done
        }

        fn settled(&self, _: &Anchor) -> bool {
            self.settled.load(Ordering::SeqCst)
        }
    }

    fn rotated(recheck: Duration) -> (Arc<Rotated>, AnchorQueue) {
        let sends = Arc::new(Rotated {
            refused: [1; 32],
            taken: Mutex::default(),
            settled: AtomicBool::new(false),
        });
        let queue = AnchorQueue::spawn_rechecking("test-resign", Arc::clone(&sends), recheck);
        (sends, queue)
    }

    fn signed(window: u64, signer: u8) -> Anchor {
        Anchor {
            signer: [signer; 32],
            ..anchor(3, window)
        }
    }

    fn until(what: &str, done: impl Fn() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(start.elapsed() < Duration::from_secs(10), "{what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Window 7, signed by a key the venue does not list, is handed back;
    /// window 8, signed by a listed key, waits behind it, since a venue
    /// takes a space's windows in rising order. The same anchor queued
    /// again is refused; signed by the listed key, window 7 lands, then 8.
    #[test]
    fn a_window_handed_back_holds_back_its_spaces_later_ones() {
        let (sends, queue) = rotated(Duration::from_secs(3_600));
        let space = SpaceId([3; 32]);
        queue.push(&signed(7, 1));
        queue.push(&signed(8, 2));
        until("window 7 handed back", || {
            queue.unsettled(&space) == [signed(7, 1)]
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(sends.taken.lock().unwrap().is_empty(), "window 8 waits");
        assert!(queue.holds(&space, 8));
        assert!(!queue.push(&signed(7, 1)), "the same signer refused");
        assert!(queue.push(&signed(7, 2)));
        assert!(queue.unsettled(&space).is_empty(), "queued again");
        until("both land", || queue.is_empty());
        assert_eq!(*sends.taken.lock().unwrap(), [(7, [2; 32]), (8, [2; 32])]);
    }

    /// A window handed back that the venue no longer needs (it holds a
    /// later window, or the window aged) is dropped at a recheck, and
    /// holds back no later window.
    #[test]
    fn a_window_handed_back_is_dropped_once_settled() {
        let (sends, queue) = rotated(Duration::from_millis(20));
        let space = SpaceId([3; 32]);
        queue.push(&signed(7, 1));
        queue.push(&signed(8, 2));
        until("window 7 handed back", || {
            queue.unsettled(&space).len() == 1
        });
        std::thread::sleep(Duration::from_millis(60));
        assert!(!queue.unsettled(&space).is_empty(), "needed still");
        sends.settled.store(true, Ordering::SeqCst);
        until("window 7 dropped", || queue.unsettled(&space).is_empty());
        until("window 8 lands", || queue.is_empty());
        assert_eq!(*sends.taken.lock().unwrap(), [(8, [2; 32])]);
    }

    /// A window handed back that its client finds settled (the venue
    /// answers it `Again` or `Window`) is handed back no more, and holds
    /// back no later window.
    #[test]
    fn a_window_its_client_settles_is_handed_back_no_more() {
        let (sends, queue) = rotated(Duration::from_secs(3_600));
        let space = SpaceId([3; 32]);
        queue.push(&signed(7, 1));
        queue.push(&signed(8, 2));
        until("window 7 handed back", || {
            queue.unsettled(&space).len() == 1
        });
        queue.settle(&space, 7);
        assert!(queue.unsettled(&space).is_empty());
        until("window 8 lands", || queue.is_empty());
        assert_eq!(*sends.taken.lock().unwrap(), [(8, [2; 32])]);
    }

    /// An anchor queued again by another signer replaces the one queued.
    #[test]
    fn a_new_signer_replaces_the_anchor_queued() {
        let held = Arc::new(Sends {
            sent: Mutex::default(),
            tries: AtomicUsize::new(0),
            held: AtomicBool::new(true),
        });
        let queue = AnchorQueue::spawn("test-replace", Arc::clone(&held));
        let first = anchor(1, 3);
        queue.push(&first);
        queue.push(&Anchor {
            signer: [9; 32],
            ..first
        });
        assert_eq!(queue.len(), 1);
        let entry = queue.shared.state().entries[&(first.space, 3)].anchor;
        assert_eq!(entry.signer, [9; 32], "the newest signature wins");
        held.held.store(false, Ordering::SeqCst);
    }

    /// The windows refused for good are forgotten oldest first, whatever
    /// their order.
    #[test]
    fn the_oldest_dead_window_is_forgotten_first() {
        let mut state = State::default();
        let space = SpaceId([4; 32]);
        for window in (0..=DEAD_KEPT as u64).rev() {
            state.died((space, window));
        }
        assert_eq!(state.dead.len(), DEAD_KEPT);
        assert!(
            !state.dead.contains(&(space, DEAD_KEPT as u64)),
            "the first refused"
        );
        assert!(state.dead.contains(&(space, 0)), "the last refused");
    }
}
