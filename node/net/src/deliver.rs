//! The sending half of the arrival queues, each bounded in frames and in
//! bytes.

use std::sync::Arc;

use smol::future::FutureExt;

use crate::{Arrivals, Budgets, Class, Classes, Incoming};

/// The sending half of [`Arrivals`].
#[derive(Clone)]
pub(crate) struct Deliver {
    queues: Box<[smol::channel::Sender<Incoming>]>,
    waiting: Arc<Budgets>,
}

/// The bytes each class's arrival queue holds, from every peer: this many
/// of its largest frames.
const WAITING: usize = 4;

/// Arrival queues of each class's bound in frames, and bounded in bytes by
/// [`WAITING`] of its largest frames.
pub(crate) fn arrivals(classes: &Classes) -> (Deliver, Arrivals) {
    let (queues, receivers) = classes
        .iter()
        .map(|(_, spec)| smol::channel::bounded(spec.arrivals))
        .unzip::<_, _, Vec<_>, Vec<_>>();
    (
        Deliver {
            queues: queues.into(),
            waiting: Budgets::new(classes, WAITING),
        },
        Arrivals {
            queues: receivers.into(),
        },
    )
}

impl Deliver {
    /// Hand an arrival over, waiting while its class's queue is full.
    /// `class` is one of the table's.
    pub(crate) async fn deliver(&self, class: Class, mut incoming: Incoming) -> bool {
        let queue = &self.queues[usize::from(class)];
        let bytes = incoming.frame.len();
        let held = async { Some(self.waiting.hold(class, bytes).await) }.or(async {
            // The consumer is gone: nothing it would read is held.
            queue.closed().await;
            None
        });
        incoming.held = held.await;
        queue.send(incoming).await.is_ok()
    }

    /// Hand an arrival over now, or give it back while its class's queue
    /// is full. One for a consumer that is gone, or of a class these
    /// queues do not hold, is lost.
    pub(crate) fn try_deliver(&self, class: Class, mut incoming: Incoming) -> Result<(), Incoming> {
        let Some(queue) = self.queues.get(usize::from(class)) else {
            return Ok(());
        };
        if queue.is_closed() {
            return Ok(());
        }
        let Some(held) = self.waiting.try_hold(class, incoming.frame.len()) else {
            return Err(incoming);
        };
        incoming.held = Some(held);
        queue.try_send(incoming).or_else(|error| {
            if queue.is_closed() {
                return Ok(());
            }
            let mut incoming = error.into_inner();
            // Let go, so a retry does not hold its bytes twice.
            incoming.held = None;
            Err(incoming)
        })
    }

    /// Whether a frame of `class` would be taken now, or dropped because
    /// the consumer is gone or the class is not one of these queues':
    /// either way, not a wait.
    pub(crate) fn has_room(&self, class: Class) -> bool {
        let Some(queue) = self.queues.get(usize::from(class)) else {
            return true;
        };
        queue.is_closed() || (!queue.is_full() && self.waiting.has_room(class))
    }
}
