//! A venue client's anchors in flight ([`AnchorQueue`]): the
//! representative's leader hands an anchor over inside its batch, so a
//! client that reaches a chain queues it and answers at once; one worker
//! thread sends each space's anchors in window order through the client's
//! [`AnchorSend`], until the venue holds one, refuses it for good, or it
//! is too old. Each space waits apart: one space's wait holds back only
//! its own later windows.
//!
//! An anchor the venue will not take as signed (its key no longer listed,
//! its signature refused) is dropped and its window kept as unsettled
//! ([`AnchorQueue::unsettled`]), which the representative's leader reads
//! to sign it again; and an anchor queued again with another signer
//! replaces the one queued, the newest signature winning.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use vos_anchor::{Anchor, SpaceId};

/// How many windows the venue will never take a queue remembers, so an
/// anchor of one handed over again is refused at once, unsent.
const DEAD_KEPT: usize = 256;

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
    /// Not taken as signed (a key the venue does not list, a signature it
    /// refuses): dropped, its window unsettled until an anchor of it is
    /// queued again, signed anew, its client having alerted.
    Resign,
}

/// How a client sends one anchor: it checks the venue would take it,
/// sends it, and follows it until the venue answers.
pub trait AnchorSend: Send + Sync + 'static {
    fn send(&self, anchor: &Anchor) -> Fate;
}

struct Entry {
    anchor: Anchor,
    not_before: Instant,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<(SpaceId, u64), Entry>,
    /// The windows whose anchors were dropped to be signed again.
    unsettled: BTreeSet<(SpaceId, u64)>,
    /// The latest windows the venue will never take, at most [`DEAD_KEPT`].
    dead: BTreeSet<(SpaceId, u64)>,
    stopping: bool,
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
        let shared = Arc::new(Shared {
            state: Mutex::default(),
            wake: Condvar::new(),
        });
        let worker = Arc::clone(&shared);
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || run(&worker, &sender))
            .expect("the anchor queue's thread starts");
        Self { shared }
    }

    /// Queue `anchor`, unless one of its space and window by the same
    /// signer is queued: one by another signer is replaced, and sent
    /// next. Its window is no longer unsettled.
    pub fn push(&self, anchor: &Anchor) {
        let mut state = self.shared.state();
        let key = (anchor.space, anchor.window);
        state.unsettled.remove(&key);
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
    }

    /// The windows of `space` whose anchors were dropped, not taken as
    /// signed ([`Fate::Resign`]), and not queued again since, in order.
    pub fn unsettled(&self, space: &SpaceId) -> Vec<u64> {
        self.shared
            .state()
            .unsettled
            .range((*space, 0)..=(*space, u64::MAX))
            .map(|(_, window)| *window)
            .collect()
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

/// The first anchor of each space, in space order: the one due soonest
/// among them, or when the earliest is due.
fn next(state: &State, now: Instant) -> Result<((SpaceId, u64), Anchor), Option<Instant>> {
    let mut earliest: Option<Instant> = None;
    let mut space = None;
    for (key, entry) in &state.entries {
        if space == Some(key.0) {
            continue;
        }
        space = Some(key.0);
        if entry.not_before <= now {
            return Ok((*key, entry.anchor));
        }
        earliest = Some(earliest.map_or(entry.not_before, |at| at.min(entry.not_before)));
    }
    Err(earliest)
}

fn run(shared: &Shared, sender: &impl AnchorSend) {
    let mut state = shared.state();
    loop {
        if state.stopping {
            return;
        }
        let now = Instant::now();
        let (key, anchor) = match next(&state, now) {
            Ok(due) => due,
            Err(earliest) => {
                let wait = earliest.map_or(Duration::from_secs(3_600), |at| at - now);
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
                state.dead.insert(key);
                if state.dead.len() > DEAD_KEPT {
                    state.dead.pop_first();
                }
            }
            Fate::Resign => {
                state.entries.remove(&key);
                state.unsettled.insert(key);
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

    /// Refuses every anchor signed by `refused` as signed, and takes the
    /// rest, recording each signer it took.
    struct Rotated {
        refused: [u8; 32],
        taken: Mutex<Vec<[u8; 32]>>,
    }

    impl AnchorSend for Arc<Rotated> {
        fn send(&self, anchor: &Anchor) -> Fate {
            if anchor.signer == self.refused {
                return Fate::Resign;
            }
            self.taken.lock().unwrap().push(anchor.signer);
            Fate::Done
        }
    }

    /// An anchor queued again by another signer replaces the one queued;
    /// one the venue refuses as signed is dropped and its window
    /// unsettled, until it is queued again, signed anew, and taken.
    #[test]
    fn a_window_refused_as_signed_is_unsettled_until_signed_again() {
        let sends = Arc::new(Rotated {
            refused: [1; 32],
            taken: Mutex::default(),
        });
        let queue = AnchorQueue::spawn("test-resign", Arc::clone(&sends));
        let space = SpaceId([3; 32]);
        let signed = |signer: u8| Anchor {
            signer: [signer; 32],
            ..anchor(3, 7)
        };
        queue.push(&signed(1));
        let start = Instant::now();
        while queue.unsettled(&space) != [7] {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(queue.is_empty(), "dropped");
        queue.push(&signed(2));
        assert!(queue.unsettled(&space).is_empty(), "queued again");
        assert!(!queue.dead(&space, 7));
        while !queue.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(*sends.taken.lock().unwrap(), [[2; 32]]);

        // Replaced in place: one entry, the newest signer's.
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
}
