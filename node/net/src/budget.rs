//! Bytes held under a budget per class: frames being assembled, waiting
//! for the consumer, or queued for a peer.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{Class, Limits};

/// What a frame costs beyond its bytes, so empty frames are bounded too.
pub(crate) const FRAME_COST: usize = 64;

/// Bytes held per class under a budget each, and a wakeup whenever some
/// are let go.
pub(crate) struct Budgets {
    held: [AtomicUsize; 4],
    budgets: [usize; 4],
    /// Per class, so a frame let go wakes only its own class's waiters.
    released: [event_listener::Event; 4],
}

/// The least a budget holds, so classes of small frames still take many.
const BUDGET_FLOOR: usize = 1 << 20;

impl Budgets {
    /// A budget of `frames` of each class's largest frames.
    pub(crate) fn new(limits: &Limits, frames: usize) -> Arc<Self> {
        Self::with(Class::ALL.map(|class| limits.frames(class, frames).max(BUDGET_FLOOR)))
    }

    /// A budget of `budgets[class]` bytes for each class.
    pub(crate) fn with(budgets: [usize; 4]) -> Arc<Self> {
        Arc::new(Self {
            held: Default::default(),
            budgets,
            released: Default::default(),
        })
    }

    /// Hold a frame of `bytes` while the class is under its budget: a
    /// budget under its bound takes one frame more, so it holds less than
    /// its bound and one frame.
    pub(crate) fn try_hold(self: &Arc<Self>, class: Class, bytes: usize) -> Option<Hold> {
        let cost = bytes.saturating_add(FRAME_COST);
        let budget = self.budgets[class as usize];
        self.held[class as usize]
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
            let released = self.released[class as usize].listen();
            if let Some(hold) = self.try_hold(class, bytes) {
                return hold;
            }
            released.await;
        }
    }

    pub(crate) fn has_room(&self, class: Class) -> bool {
        self.held[class as usize].load(Ordering::Acquire) < self.budgets[class as usize]
    }

    /// Resolves once the class is under its budget.
    pub(crate) async fn room(&self, class: Class) {
        loop {
            let released = self.released[class as usize].listen();
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
        let class = self.class as usize;
        self.budgets.held[class].fetch_sub(self.cost, Ordering::AcqRel);
        self.budgets.released[class].notify(usize::MAX);
    }
}
