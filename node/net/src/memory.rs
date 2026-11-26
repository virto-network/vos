//! Endpoints in one process, joined through a hub, for tests: frames go
//! through channels, and the hub can cut links, lose frames and delay
//! them. It keeps what QUIC does of the model: a node takes frames only
//! from the peers it lists, arrival queues are bounded in frames and
//! bytes, and a delayed frame holds its bytes in its link's queue until it
//! is delivered, a queue past its class's budget refusing. Order holds
//! per pair of endpoints, across ids too, which QUIC does not promise; and
//! no frame is dropped for its age.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{
    Arrivals, Class, Classes, Deliver, Incoming, Network, NodeKey, Peer, Refused, arrivals,
};

/// How often a frame waiting for room looks again.
const POLL: Duration = Duration::from_millis(1);

/// Endpoints joined in one process.
#[derive(Clone)]
pub struct Hub {
    state: Arc<Mutex<State>>,
}

struct State {
    endpoints: HashMap<NodeKey, Joined>,
    generation: u64,
    /// Directed links that lose everything.
    cut: HashSet<(NodeKey, NodeKey)>,
    /// Frames lost out of every million sent.
    loss: u32,
    /// Directed links that lose frames of their own, out of a million.
    link_loss: HashMap<(NodeKey, NodeKey), u32>,
    /// Directed links that lose every frame of one class.
    class_cut: HashSet<(NodeKey, NodeKey, Class)>,
    /// Frames sent through the hub, by class, lost or not.
    sent: Vec<u64>,
    random: u64,
    delay: Duration,
    classes: Classes,
    /// Sees every frame sent, lost or not.
    tap: Option<Tap>,
}

/// What sees every frame a hub is sent: from, to, its class and its bytes.
pub type Tap = Arc<dyn Fn(NodeKey, NodeKey, Class, &[u8]) + Send + Sync>;

/// A joined endpoint: the generation it joined in, its arrivals and the
/// peers it takes frames from.
struct Joined {
    generation: u64,
    deliver: Deliver,
    peers: Arc<Mutex<Vec<NodeKey>>>,
}

impl State {
    /// Where a frame from `from` to `to` goes, if `to` is up and lists
    /// `from`.
    fn deliver(&self, from: NodeKey, to: NodeKey) -> Option<Deliver> {
        let joined = self.endpoints.get(&to)?;
        let listed = joined.peers.lock().expect("the peers").contains(&from);
        listed.then(|| joined.deliver.clone())
    }
}

impl Hub {
    /// A hub of `classes` whose losses follow `seed`.
    pub fn new(seed: u64, classes: Classes) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                endpoints: HashMap::new(),
                generation: 0,
                cut: HashSet::new(),
                loss: 0,
                link_loss: HashMap::new(),
                class_cut: HashSet::new(),
                sent: vec![0; classes.len()],
                random: seed | 1,
                delay: Duration::ZERO,
                classes,
                tap: None,
            })),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("the hub")
    }

    /// Join as the node whose key is `key`, replacing an endpoint joined
    /// before under it, as a restarted node does.
    pub fn join(&self, key: NodeKey) -> (Endpoint, Arrivals) {
        let peers = Arc::new(Mutex::new(Vec::new()));
        let mut state = self.state();
        let (deliver, arrivals) = arrivals(&state.classes);
        state.generation += 1;
        let generation = state.generation;
        state.endpoints.insert(
            key,
            Joined {
                generation,
                deliver,
                peers: Arc::clone(&peers),
            },
        );
        let endpoint = Endpoint {
            key,
            generation,
            hub: self.clone(),
            peers,
            delayed: Mutex::new(HashMap::new()),
            held: Held::default(),
        };
        (endpoint, arrivals)
    }

    /// Lose every frame between `a` and `b`, both ways.
    pub fn partition(&self, a: NodeKey, b: NodeKey) {
        let mut state = self.state();
        state.cut.insert((a, b));
        state.cut.insert((b, a));
    }

    /// Lose every frame to and from `node`.
    pub fn isolate(&self, node: NodeKey) {
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
    pub fn cut_class(&self, from: NodeKey, to: NodeKey, class: Class) {
        self.state().class_cut.insert((from, to, class));
    }

    /// Lose `per_million` of every million frames between `a` and `b`,
    /// both ways, at random.
    pub fn set_link_loss(&self, a: NodeKey, b: NodeKey, per_million: u32) {
        let mut state = self.state();
        let per_million = per_million.min(1_000_000);
        state.link_loss.insert((a, b), per_million);
        state.link_loss.insert((b, a), per_million);
    }

    /// The frames of `class` sent through the hub so far, lost or not.
    pub fn sent(&self, class: Class) -> u64 {
        self.state()
            .sent
            .get(usize::from(class))
            .copied()
            .unwrap_or(0)
    }

    /// Lose `per_million` of every million frames, at random.
    pub fn set_loss(&self, per_million: u32) {
        self.state().loss = per_million.min(1_000_000);
    }

    /// Show every frame sent from now on to `tap`, lost or not.
    pub fn tap(&self, tap: Tap) {
        self.state().tap = Some(tap);
    }

    /// Deliver every frame `delay` after it was sent.
    pub fn set_delay(&self, delay: Duration) {
        self.state().delay = delay;
    }

    /// Replace the classes' definitions. An endpoint joined before keeps
    /// the arrival queues the table at its join gave.
    ///
    /// # Panics
    ///
    /// If `classes` holds another count of classes than the hub's.
    pub fn set_classes(&self, classes: Classes) {
        let mut state = self.state();
        assert_eq!(
            classes.len(),
            state.classes.len(),
            "a hub's classes keep their count"
        );
        state.classes = classes;
    }
}

/// Bytes each delayed link holds, by peer and class.
type Held = Arc<Mutex<HashMap<(NodeKey, Class), usize>>>;

/// A node's endpoint on a [`Hub`].
pub struct Endpoint {
    key: NodeKey,
    generation: u64,
    hub: Hub,
    peers: Arc<Mutex<Vec<NodeKey>>>,
    /// A delivery task per peer while frames are delayed, so they keep
    /// their order.
    delayed: Mutex<HashMap<NodeKey, Delayed>>,
    /// What the delayed frames hold of each link's queue.
    held: Held,
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
            .map(|peer| peer.key)
            .filter(|key| *key != self.key)
            .collect();
    }

    /// The delivery task to `to`, among `delayed`. Each frame goes, when
    /// due, to whichever run of `to` is up then, if it lists this node.
    fn delayed<'a>(
        &self,
        delayed: &'a mut HashMap<NodeKey, Delayed>,
        to: NodeKey,
    ) -> &'a smol::channel::Sender<(Instant, Class, Incoming)> {
        let link = delayed.entry(to).or_insert_with(|| {
            let (frames, pending) = smol::channel::unbounded::<(Instant, Class, Incoming)>();
            let hub = self.hub.clone();
            let from = self.key;
            let held = Arc::clone(&self.held);
            let task = smol::spawn(async move {
                while let Ok((at, class, mut incoming)) = pending.recv().await {
                    smol::Timer::at(at).await;
                    let bytes = incoming.frame.len();
                    // Wait while the run up then is full, looking again
                    // each time, so a run replaced meanwhile holds
                    // nothing up.
                    loop {
                        let deliver = hub.state().deliver(from, to);
                        let Some(deliver) = deliver else {
                            break;
                        };
                        match deliver.try_deliver(class, incoming) {
                            Ok(()) => break,
                            Err(back) => {
                                incoming = back;
                                smol::Timer::after(POLL).await;
                            }
                        }
                    }
                    if let Some(held) = held.lock().expect("the held bytes").get_mut(&(to, class)) {
                        *held = held.saturating_sub(bytes);
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
            .get(&self.key)
            .is_some_and(|joined| joined.generation == self.generation)
        {
            state.endpoints.remove(&self.key);
        }
    }
}

impl Network for Endpoint {
    fn send(&self, to: NodeKey, class: Class, stream: u64, frame: Vec<u8>) -> Result<(), Refused> {
        if !self.peers.lock().expect("the peers").contains(&to) {
            return Err(Refused::UnknownPeer);
        }
        let mut state = self.hub.state();
        if state.classes.get(class).is_none() {
            return Err(Refused::UnknownClass);
        }
        if frame.len() > state.classes.max_frame(class) {
            return Err(Refused::TooLarge);
        }
        let incoming = Incoming::new(self.key, stream, frame);
        state.sent[usize::from(class)] += 1;
        if let Some(tap) = &state.tap {
            tap(self.key, to, class, &incoming.frame);
        }
        // A peer that is down, or cut off, loses what is sent to it.
        if !state.endpoints.contains_key(&to)
            || state.cut.contains(&(self.key, to))
            || state.class_cut.contains(&(self.key, to, class))
        {
            return Ok(());
        }
        let loss = state
            .link_loss
            .get(&(self.key, to))
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
        let budget = state.classes.queue(class);
        let deliver = state.deliver(self.key, to);
        drop(state);
        let mut delayed = self.delayed.lock().expect("the delayed links");
        if delay.is_zero() && !delayed.contains_key(&to) {
            drop(delayed);
            let Some(deliver) = deliver else {
                return Ok(());
            };
            // Delivered, or lost with a consumer that is gone.
            return deliver
                .try_deliver(class, incoming)
                .map_err(|_| Refused::Full);
        }
        // A delayed link's queue holds what it has yet to deliver, under its
        // class's budget.
        {
            let mut held = self.held.lock().expect("the held bytes");
            let held = held.entry((to, class)).or_insert(0);
            if *held >= budget {
                return Err(Refused::Full);
            }
            *held += incoming.frame.len();
        }
        // Once delayed, a link stays on its delivery task, so a later
        // frame never passes an earlier one.
        let _ = self
            .delayed(&mut delayed, to)
            .try_send((Instant::now() + delay, class, incoming));
        Ok(())
    }

    fn ready(&self, to: NodeKey, class: Class) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let hub = self.hub.clone();
        let held = Arc::clone(&self.held);
        Box::pin(async move {
            loop {
                let (arrivals, budget) = {
                    let state = hub.state();
                    let arrivals = state
                        .endpoints
                        .get(&to)
                        .is_none_or(|joined| joined.deliver.has_room(class));
                    let budget = match state.classes.get(class) {
                        Some(_) => state.classes.queue(class),
                        None => usize::MAX,
                    };
                    (arrivals, budget)
                };
                let queued = held
                    .lock()
                    .expect("the held bytes")
                    .get(&(to, class))
                    .copied()
                    .unwrap_or(0);
                if arrivals && queued < budget {
                    return;
                }
                smol::Timer::after(POLL).await;
            }
        })
    }

    fn classes(&self) -> Classes {
        self.hub.state().classes.clone()
    }
}
