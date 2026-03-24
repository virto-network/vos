/// The result of a single `poll` round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// At least one actor processed a message.
    Progressed,
    /// No actors had pending messages (all idle).
    Idle,
    /// All actors have stopped.
    Done,
}

/// A cooperative, single-threaded executor for actors.
///
/// The host calls `poll` on the executor's async methods. Each round
/// processes at most one message per actor (round-robin fairness),
/// then yields so the host can drive other work.
///
/// ```text
/// Host loop:
///     let exec = Executor::new();
///     // ... spawn actors ...
///     loop {
///         match poll(exec.tick(...)).await {
///             Progress::Progressed => continue,
///             Progress::Idle => wait_for_input(),
///             Progress::Done => break,
///         }
///     }
/// ```
///
/// The executor is `no_alloc` — actors stored inline via const generics.
pub struct Executor<S, const N: usize> {
    actors: [Option<Slot<S>>; N],
    count: usize,
}

/// Internal slot holding an actor and its running state.
pub(crate) struct Slot<S> {
    pub(crate) state: S,
    pub(crate) alive: bool,
}

impl<S, const N: usize> Executor<S, N> {
    const NONE: Option<Slot<S>> = None;

    /// Create an empty executor.
    pub const fn new() -> Self {
        Self {
            actors: [Self::NONE; N],
            count: 0,
        }
    }

    /// Spawn an actor, returning its index. Returns `None` if full.
    pub fn spawn(&mut self, state: S) -> Option<usize> {
        if self.count >= N {
            return None;
        }
        let id = self.count;
        self.actors[id] = Some(Slot {
            state,
            alive: true,
        });
        self.count += 1;
        Some(id)
    }

    /// Get a reference to an actor's state by index.
    pub fn get(&self, id: usize) -> Option<&S> {
        self.actors.get(id)?.as_ref().map(|s| &s.state)
    }

    /// Get a mutable reference to an actor's state by index.
    pub fn get_mut(&mut self, id: usize) -> Option<&mut S> {
        self.actors.get_mut(id)?.as_mut().map(|s| &mut s.state)
    }

    /// Number of alive actors.
    pub fn alive_count(&self) -> usize {
        self.actors
            .iter()
            .filter(|s| s.as_ref().is_some_and(|s| s.alive))
            .count()
    }

    /// Stop an actor by index.
    pub fn stop(&mut self, id: usize) {
        if let Some(Some(slot)) = self.actors.get_mut(id) {
            slot.alive = false;
        }
    }

    /// Run one round: call `f` for each alive actor. The callback is
    /// async — `.await` points inside it yield to the PVM host.
    ///
    /// Returns whether any progress was made.
    pub async fn tick(&mut self, mut f: impl AsyncFnMut(usize, &mut S) -> bool) -> Progress {
        let mut progress = false;
        let mut any_alive = false;
        for (i, slot) in self.actors.iter_mut().enumerate() {
            if let Some(slot) = slot {
                if !slot.alive {
                    continue;
                }
                any_alive = true;
                if f(i, &mut slot.state).await {
                    progress = true;
                }
            }
        }
        if !any_alive {
            Progress::Done
        } else if progress {
            Progress::Progressed
        } else {
            Progress::Idle
        }
    }
}
