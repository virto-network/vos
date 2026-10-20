//! A venue client's anchors in flight ([`AnchorQueue`]): the
//! representative's leader hands an anchor over inside its batch, so a
//! client that reaches a chain queues it and answers at once; one worker
//! thread sends each space's anchors in window order through the client's
//! [`AnchorSend`], until the venue holds one, refuses it for good, or it
//! is too old. Each space waits apart: one space's wait holds back only
//! its own later windows.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use vos_anchor::{Anchor, SpaceId};

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

    /// Queue `anchor`, unless one of its space and window is queued.
    pub fn push(&self, anchor: &Anchor) {
        let mut state = self.shared.state();
        state
            .entries
            .entry((anchor.space, anchor.window))
            .or_insert(Entry {
                anchor: *anchor,
                not_before: Instant::now(),
            });
        self.shared.wake.notify_all();
    }

    /// Whether an anchor of `space` at `window` is queued.
    pub fn holds(&self, space: &SpaceId, window: u64) -> bool {
        self.shared.state().entries.contains_key(&(*space, window))
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
        match fate {
            Fate::Done | Fate::Dead => {
                state.entries.remove(&key);
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    /// order; a repeat is queued once.
    struct Sends {
        sent: Mutex<Vec<(u8, u64)>>,
        tries: AtomicUsize,
    }

    impl AnchorSend for Arc<Sends> {
        fn send(&self, anchor: &Anchor) -> Fate {
            self.tries.fetch_add(1, Ordering::SeqCst);
            if anchor.space.0[0] == 1 {
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
        });
        let queue = AnchorQueue::spawn("test-anchors", Arc::clone(&sends));
        queue.push(&anchor(1, 3));
        queue.push(&anchor(1, 3));
        queue.push(&anchor(1, 4));
        for window in [6, 5, 7] {
            queue.push(&anchor(2, window));
        }
        let start = Instant::now();
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
}
