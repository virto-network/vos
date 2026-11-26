//! Bytes held under a budget per class: frames being assembled, waiting
//! for the consumer, or queued for a peer.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{Class, Classes};

/// What a frame costs beyond its bytes, so empty frames are bounded too.
pub(crate) const FRAME_COST: usize = 64;

/// Bytes held per class under a budget each, and a wakeup whenever some
/// are let go.
pub(crate) struct Budgets {
    held: Box<[AtomicUsize]>,
    budgets: Box<[usize]>,
    /// Per class, so a frame let go wakes only its own class's waiters.
    released: Box<[event_listener::Event]>,
}

/// The least a budget holds, so classes of small frames still take many.
const BUDGET_FLOOR: usize = 1 << 20;

impl Budgets {
    /// A budget of `frames` of each class's largest frames.
    pub(crate) fn new(classes: &Classes, frames: usize) -> Arc<Self> {
        let budgets = classes.frames(frames);
        Self::with(
            budgets
                .into_iter()
                .map(|budget| budget.max(BUDGET_FLOOR))
                .collect(),
        )
    }

    /// A budget of `budgets[class]` bytes for each class.
    pub(crate) fn with(budgets: Vec<usize>) -> Arc<Self> {
        Arc::new(Self {
            held: budgets.iter().map(|_| AtomicUsize::new(0)).collect(),
            released: budgets
                .iter()
                .map(|_| event_listener::Event::new())
                .collect(),
            budgets: budgets.into(),
        })
    }

    /// Hold a frame of `bytes` while the class is under its budget: a
    /// budget under its bound takes one frame more, so it holds less than
    /// its bound and one frame. `class` is one of the table's.
    pub(crate) fn try_hold(self: &Arc<Self>, class: Class, bytes: usize) -> Option<Hold> {
        let cost = bytes.saturating_add(FRAME_COST);
        let budget = self.budgets[usize::from(class)];
        self.held[usize::from(class)]
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < budget).then(|| held.saturating_add(cost))
            })
            .ok()?;
        Some(Hold {
            budgets: Arc::clone(self),
            class,
            cost,
        })
    }

    /// Hold a frame of `bytes`, waiting until it fits.
    pub(crate) async fn hold(self: &Arc<Self>, class: Class, bytes: usize) -> Hold {
        loop {
            let released = self.released[usize::from(class)].listen();
            if let Some(hold) = self.try_hold(class, bytes) {
                return hold;
            }
            released.await;
        }
    }

    pub(crate) fn has_room(&self, class: Class) -> bool {
        self.held[usize::from(class)].load(Ordering::Acquire) < self.budgets[usize::from(class)]
    }

    /// Resolves once the class is under its budget.
    pub(crate) async fn room(&self, class: Class) {
        loop {
            let released = self.released[usize::from(class)].listen();
            if self.has_room(class) {
                return;
            }
            released.await;
        }
    }
}

/// A frame's bytes held under a budget, let go when dropped.
pub(crate) struct Hold {
    budgets: Arc<Budgets>,
    class: Class,
    cost: usize,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let class = usize::from(self.class);
        self.budgets.held[class].fetch_sub(self.cost, Ordering::AcqRel);
        self.budgets.released[class].notify(usize::MAX);
    }
}
