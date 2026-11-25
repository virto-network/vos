//! The sending half of the arrival queues, each bounded in frames and in
//! bytes.

use std::sync::Arc;

use smol::future::FutureExt;

use crate::{Arrivals, Budgets, Class, Incoming, Limits};

/// The sending half of [`Arrivals`].
#[derive(Clone)]
pub(crate) struct Deliver {
    queues: [smol::channel::Sender<Incoming>; 4],
    waiting: Arc<Budgets>,
}

/// How many frames each class's arrival queue holds before a stream's
/// reader waits for the consumer (and the sender, for flow control).
const ARRIVALS: usize = 1024;
/// Bulk frames are large: few wait.
const BULK_ARRIVALS: usize = 16;
/// The bytes each class's arrival queue holds, from every peer: this many
/// of its largest frames.
const WAITING: usize = 4;

/// Arrival queues bounded in bytes by [`WAITING`] of each class's largest
/// frames under `limits`.
pub(crate) fn arrivals(limits: &Limits) -> (Deliver, Arrivals) {
    let (liveness, liveness_rx) = smol::channel::bounded(ARRIVALS);
    let (consensus, consensus_rx) = smol::channel::bounded(ARRIVALS);
    let (requests, requests_rx) = smol::channel::bounded(ARRIVALS);
    let (bulk, bulk_rx) = smol::channel::bounded(BULK_ARRIVALS);
    (
        Deliver {
            queues: [liveness, consensus, requests, bulk],
            waiting: Budgets::new(limits, WAITING),
        },
        Arrivals {
            liveness: liveness_rx,
            consensus: consensus_rx,
            requests: requests_rx,
            bulk: bulk_rx,
        },
    )
}

impl Deliver {
    /// Hand an arrival over, waiting while its class's queue is full.
    pub(crate) async fn deliver(&self, class: Class, mut incoming: Incoming) -> bool {
        let queue = &self.queues[class as usize];
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
    /// is full. One for a consumer that is gone is lost.
    pub(crate) fn try_deliver(&self, class: Class, mut incoming: Incoming) -> Result<(), Incoming> {
        let queue = &self.queues[class as usize];
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
    /// the consumer is gone: either way, not a wait.
    pub(crate) fn has_room(&self, class: Class) -> bool {
        let queue = &self.queues[class as usize];
        queue.is_closed() || (!queue.is_full() && self.waiting.has_room(class))
    }
}
