//! Endpoints in one process, joined through a hub, for tests: frames go
//! through channels, and the hub can cut links, lose frames and delay
//! them. Order holds per pair of endpoints, as it does per stream over
//! QUIC (and here across streams too, which QUIC does not promise). As
//! over QUIC, a node takes frames only from the peers it lists.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{
    Arrivals, Class, Deliver, Incoming, Limits, Network, NodeNumber, Peer, Refused, arrivals,
};

/// How often a frame waiting for room looks again.
const POLL: Duration = Duration::from_millis(1);

/// Endpoints joined in one process.
#[derive(Clone)]
pub struct Hub {
    state: Arc<Mutex<State>>,
}

struct State {
    endpoints: HashMap<NodeNumber, Joined>,
    generation: u64,
    /// Directed links that lose everything.
    cut: HashSet<(NodeNumber, NodeNumber)>,
    /// Frames lost out of every million sent.
    loss: u32,
    /// Directed links that lose frames of their own, out of a million.
    link_loss: HashMap<(NodeNumber, NodeNumber), u32>,
    /// Directed links that lose every frame of one class.
    class_cut: HashSet<(NodeNumber, NodeNumber, Class)>,
    /// Frames sent through the hub, by class, lost or not.
    sent: HashMap<Class, u64>,
    random: u64,
    delay: Duration,
    limits: Limits,
}

/// A joined endpoint: the generation it joined in, its arrivals and the
/// peers it takes frames from.
struct Joined {
    generation: u64,
    deliver: Deliver,
    peers: Arc<Mutex<Vec<NodeNumber>>>,
}

impl State {
    /// Where a frame from `from` to `to` goes, if `to` is up and lists
    /// `from`.
    fn deliver(&self, from: NodeNumber, to: NodeNumber) -> Option<Deliver> {
        let joined = self.endpoints.get(&to)?;
        let listed = joined.peers.lock().expect("the peers").contains(&from);
        listed.then(|| joined.deliver.clone())
    }
}

impl Hub {
    /// A hub whose losses follow `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                endpoints: HashMap::new(),
                generation: 0,
                cut: HashSet::new(),
                loss: 0,
                link_loss: HashMap::new(),
                class_cut: HashSet::new(),
                sent: HashMap::new(),
                random: seed | 1,
                delay: Duration::ZERO,
                limits: Limits::default(),
            })),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("the hub")
    }

    /// Join as node `number`, replacing an endpoint joined before under
    /// it, as a restarted node does.
    pub fn join(&self, number: NodeNumber) -> (Endpoint, Arrivals) {
        let (deliver, arrivals) = arrivals();
        let peers = Arc::new(Mutex::new(Vec::new()));
        let mut state = self.state();
        state.generation += 1;
        let generation = state.generation;
        state.endpoints.insert(
            number,
            Joined {
                generation,
                deliver,
                peers: Arc::clone(&peers),
            },
        );
        let endpoint = Endpoint {
            number,
            generation,
            hub: self.clone(),
            peers,
            delayed: Mutex::new(HashMap::new()),
        };
        (endpoint, arrivals)
    }

    /// Lose every frame between `a` and `b`, both ways.
    pub fn partition(&self, a: NodeNumber, b: NodeNumber) {
        let mut state = self.state();
        state.cut.insert((a, b));
        state.cut.insert((b, a));
    }

    /// Lose every frame to and from `node`.
    pub fn isolate(&self, node: NodeNumber) {
        let mut state = self.state();
        let others: Vec<_> = state.endpoints.keys().copied().collect();
        for other in others.into_iter().filter(|other| *other != node) {
            state.cut.insert((node, other));
            state.cut.insert((other, node));
        }
    }

    /// Restore every link: no cuts, and no link's own losses.
    pub fn heal(&self) {
        let mut state = self.state();
        state.cut.clear();
        state.link_loss.clear();
        state.class_cut.clear();
    }

    /// Lose every frame of `class` from `from` to `to`, the others going
    /// through: a gray failure.
    pub fn cut_class(&self, from: NodeNumber, to: NodeNumber, class: Class) {
        self.state().class_cut.insert((from, to, class));
    }

    /// Lose `per_million` of every million frames between `a` and `b`,
    /// both ways, at random.
    pub fn set_link_loss(&self, a: NodeNumber, b: NodeNumber, per_million: u32) {
        let mut state = self.state();
        let per_million = per_million.min(1_000_000);
        state.link_loss.insert((a, b), per_million);
        state.link_loss.insert((b, a), per_million);
    }

    /// The frames of `class` sent through the hub so far, lost or not.
    pub fn sent(&self, class: Class) -> u64 {
        self.state().sent.get(&class).copied().unwrap_or(0)
    }

    /// Lose `per_million` of every million frames, at random.
    pub fn set_loss(&self, per_million: u32) {
        self.state().loss = per_million.min(1_000_000);
    }

    /// Deliver every frame `delay` after it was sent.
    pub fn set_delay(&self, delay: Duration) {
        self.state().delay = delay;
    }

    /// The largest frames of each class.
    pub fn set_limits(&self, limits: Limits) {
        self.state().limits = limits;
    }
}

/// A node's endpoint on a [`Hub`].
pub struct Endpoint {
    number: NodeNumber,
    generation: u64,
    hub: Hub,
    peers: Arc<Mutex<Vec<NodeNumber>>>,
    /// A delivery task per peer while frames are delayed, so they keep
    /// their order.
    delayed: Mutex<HashMap<NodeNumber, Delayed>>,
}

struct Delayed {
    frames: smol::channel::Sender<(Instant, Class, Incoming)>,
    _task: smol::Task<()>,
}

impl Endpoint {
    /// Replace the peers this endpoint sends to and takes frames from.
    pub fn set_peers(&self, peers: Vec<Peer>) {
        *self.peers.lock().expect("the peers") = peers
            .into_iter()
            .map(|peer| peer.number)
            .filter(|number| *number != self.number)
            .collect();
    }

    /// The delivery task to `to`, among `delayed`. Each frame goes, when
    /// due, to whichever run of `to` is up then, if it lists this node.
    fn delayed<'a>(
        &self,
        delayed: &'a mut HashMap<NodeNumber, Delayed>,
        to: NodeNumber,
    ) -> &'a smol::channel::Sender<(Instant, Class, Incoming)> {
        let link = delayed.entry(to).or_insert_with(|| {
            let (frames, pending) = smol::channel::unbounded::<(Instant, Class, Incoming)>();
            let hub = self.hub.clone();
            let from = self.number;
            let task = smol::spawn(async move {
                while let Ok((at, class, mut incoming)) = pending.recv().await {
                    smol::Timer::at(at).await;
                    // Wait while the run up then is full, looking again
                    // each time, so a run replaced meanwhile holds
                    // nothing up.
                    loop {
                        let deliver = hub.state().deliver(from, to);
                        let Some(deliver) = deliver else {
                            break;
                        };
                        match deliver.try_deliver(class, incoming) {
                            Err(smol::channel::TrySendError::Full(back)) => {
                                incoming = back;
                                smol::Timer::after(POLL).await;
                            }
                            _ => break,
                        }
                    }
                }
            });
            Delayed {
                frames,
                _task: task,
            }
        });
        &link.frames
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let mut state = self.hub.state();
        if state
            .endpoints
            .get(&self.number)
            .is_some_and(|joined| joined.generation == self.generation)
        {
            state.endpoints.remove(&self.number);
        }
    }
}

impl Network for Endpoint {
    fn send(
        &self,
        to: NodeNumber,
        class: Class,
        stream: u64,
        frame: Vec<u8>,
    ) -> Result<(), Refused> {
        if !self.peers.lock().expect("the peers").contains(&to) {
            return Err(Refused::UnknownPeer);
        }
        let mut state = self.hub.state();
        if frame.len() > state.limits.of(class) {
            return Err(Refused::TooLarge);
        }
        let incoming = Incoming {
            from: self.number,
            stream,
            frame,
        };
        *state.sent.entry(class).or_insert(0) += 1;
        // A peer that is down, or cut off, loses what is sent to it.
        if !state.endpoints.contains_key(&to)
            || state.cut.contains(&(self.number, to))
            || state.class_cut.contains(&(self.number, to, class))
        {
            return Ok(());
        }
        let loss = state
            .link_loss
            .get(&(self.number, to))
            .copied()
            .unwrap_or(0)
            .max(state.loss);
        if loss > 0 {
            state.random ^= state.random << 13;
            state.random ^= state.random >> 7;
            state.random ^= state.random << 17;
            if (state.random % 1_000_000) < u64::from(loss) {
                return Ok(());
            }
        }
        let delay = state.delay;
        let deliver = state.deliver(self.number, to);
        drop(state);
        let mut delayed = self.delayed.lock().expect("the delayed links");
        if delay.is_zero() && !delayed.contains_key(&to) {
            drop(delayed);
            let Some(deliver) = deliver else {
                return Ok(());
            };
            return match deliver.try_deliver(class, incoming) {
                Err(smol::channel::TrySendError::Full(_)) => Err(Refused::Full),
                // Delivered, or lost with a consumer that is gone.
                _ => Ok(()),
            };
        }
        // Once delayed, a link stays on its delivery task, so a later
        // frame never passes an earlier one.
        let _ = self
            .delayed(&mut delayed, to)
            .try_send((Instant::now() + delay, class, incoming));
        Ok(())
    }

    fn ready(&self, to: NodeNumber, class: Class) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let hub = self.hub.clone();
        Box::pin(async move {
            loop {
                let room = hub
                    .state()
                    .endpoints
                    .get(&to)
                    .is_none_or(|joined| joined.deliver.has_room(class));
                if room {
                    return;
                }
                smol::Timer::after(POLL).await;
            }
        })
    }
}
