//! The pair heartbeat. Once per heartbeat interval each node tells every
//! other node of its space that it is alive, and which of the groups that
//! node replicates it leads, at what term: what changed since the last
//! round that node took whole, so an idle node's rounds name no group
//! ([`vos_raft::pair`]). What a node hears goes into its peer table, which
//! its groups' drivers read to vouch for their leaders and members before
//! their own timers lapse ([`vos_raft::core::Core::vouch`]): an idle group
//! then sends nothing. A group whose core needs no tick but those this
//! stands in for waits on no timer at all ([`crate::group::Quiet`]): a
//! change to its leader's listing wakes it as it arrives, and a round
//! wakes those whose leader's listing went unrenewed, or with a member
//! whose node fell silent. Whatever goes wrong here leaves Raft's own
//! timing in charge.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use smol::future::FutureExt;
use vos_net::{Class, Incoming};
use vos_raft::Role;
use vos_raft::pair::{Frame, PeerTable, Round, Telling};
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{Leading, NodeNumber, PeerMessage};

use crate::group::{Local, Quiet};
use crate::node::{Inner, Known, Run};
use crate::peer;
use crate::{lock, timeout};

/// The most groups one frame names, well within the network's default cap
/// on a liveness frame.
const LISTED: usize = 4_096;

/// The most groups one frame of at most `limit` bytes names: a group
/// listed takes 12 bytes, one unlisted 4, and the frame's other fields
/// under 64.
fn per_frame(limit: usize) -> usize {
    (limit.saturating_sub(64) / 12).clamp(1, LISTED)
}
/// How long the pair heartbeat waits to start again after it failed,
/// first: short, as every group it leads is unvouched while it waits. It
/// doubles while it keeps failing, to `RESTART_MOST`.
const RESTART: Duration = Duration::from_millis(100);
const RESTART_MOST: Duration = Duration::from_secs(1);
/// A run of the heartbeat this long counts as recovered: the next
/// failure waits `RESTART` again.
const RECOVERED: Duration = Duration::from_secs(10);

/// What this node heard of its peers: when, and which groups each leads.
pub(crate) type Table = PeerTable<NodeNumber, AgentId, Instant>;

pub(crate) struct Liveness {
    /// This run of the node: its start time in microseconds, past every
    /// earlier run's.
    pub(crate) incarnation: u64,
    table: RwLock<Table>,
    /// What this node tells each peer of the groups it leads.
    telling: Mutex<HashMap<NodeNumber, Telling<AgentId>>>,
    started: Instant,
    /// The last round sent, kept across the heartbeat's restarts: peers
    /// ignore a round below the last they took from this run.
    round: AtomicU64,
    /// When the heartbeat last went round, in milliseconds since the node
    /// started: a group goes quiet only while it goes round on time.
    beaten: AtomicU64,
    /// The peers whose last heartbeat named other lanes than this node's,
    /// with the lanes it named: each is refused whole until it names this
    /// node's.
    other_lanes: Mutex<HashMap<NodeNumber, u32>>,
    /// Whether `other_lanes` holds any: every frame from a peer asks.
    refusing: AtomicBool,
}

impl Liveness {
    pub(crate) fn new(incarnation: u64) -> Self {
        Self {
            incarnation,
            table: RwLock::new(PeerTable::new()),
            telling: Mutex::new(HashMap::new()),
            started: Instant::now(),
            round: AtomicU64::new(0),
            beaten: AtomicU64::new(0),
            other_lanes: Mutex::new(HashMap::new()),
            refusing: AtomicBool::new(false),
        }
    }

    /// Whether `from`, its heartbeat naming `theirs` lanes, agrees with
    /// this node's `ours`. A peer that does not is refused whole, and
    /// logged as a warning when it first names those lanes; one that
    /// agrees again is taken again.
    pub(crate) fn lanes_agree(&self, from: NodeNumber, theirs: u32, ours: u32) -> bool {
        let mut other = lock(&self.other_lanes);
        if theirs == ours {
            if other.remove(&from).is_some() {
                tracing::info!(peer = from, lanes = ours, "a peer's lanes agree again");
            }
            self.refusing.store(!other.is_empty(), Ordering::Relaxed);
            return true;
        }
        if other.insert(from, theirs) != Some(theirs) {
            tracing::warn!(
                peer = from,
                theirs,
                ours,
                "a peer's peer_lanes differ from this node's: it is refused until they agree, \
                 as each would refuse the other's groups' frames"
            );
        }
        self.refusing.store(true, Ordering::Relaxed);
        false
    }

    /// Whether `from`'s last heartbeat named other lanes than this node's.
    pub(crate) fn refuses(&self, from: NodeNumber) -> bool {
        self.refusing.load(Ordering::Relaxed) && lock(&self.other_lanes).contains_key(&from)
    }

    /// The next round to send.
    fn next_round(&self) -> u64 {
        self.round.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Whether the heartbeat went round within two of its intervals, `every`
    /// milliseconds: only then does it stand in for a quiet group's timers.
    pub(crate) fn on_time(&self, every: u64) -> bool {
        let beaten = self.beaten.load(Ordering::Relaxed);
        self.elapsed().saturating_sub(beaten) < 2 * every
    }

    /// Milliseconds since the node started.
    pub(crate) fn elapsed(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// The peer table, as the last write left it, whole: a panic in one
    /// leaves what it wrote.
    pub(crate) fn table(&self) -> RwLockReadGuard<'_, Table> {
        self.table.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn table_mut(&self) -> RwLockWriteGuard<'_, Table> {
        self.table.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The run after `last`: the clock's microseconds, or one past `last`
/// when the clock stands behind it.
pub(crate) fn next_incarnation(last: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_micros() as u64);
    now.max(last.saturating_add(1))
}

/// The pair heartbeat's thread, until `stopped`: it sends and hears on a
/// thread of its own, so a busy node thread delays neither, and starts
/// again after a failure, which it logs.
pub(crate) fn supervise(
    inner: Arc<Inner>,
    arrivals: smol::channel::Receiver<Incoming>,
    stopped: smol::channel::Receiver<()>,
) {
    let mut pause = RESTART;
    loop {
        let started = Instant::now();
        let ran = catch_unwind(AssertUnwindSafe(|| {
            smol::block_on(run(Arc::clone(&inner), arrivals.clone(), stopped.clone()))
        }));
        if started.elapsed() >= RECOVERED {
            pause = RESTART;
        }
        match ran {
            Ok(Ended::Stopped) => return,
            Ok(Ended::Closed) => {
                tracing::warn!("the pair heartbeat stopped: the network closed");
                return;
            }
            Err(panic) => {
                let message = crate::panic_message(&*panic);
                tracing::error!("the pair heartbeat failed, and starts again: {message}");
                // Stopped meanwhile, it does not start again.
                if smol::block_on(timeout(pause, stopped.recv())).is_some() {
                    return;
                }
                pause = (pause * 2).min(RESTART_MOST);
            }
        }
    }
}

/// Why the pair heartbeat ended.
enum Ended {
    Stopped,
    Closed,
}

async fn run(
    inner: Arc<Inner>,
    arrivals: smol::channel::Receiver<Incoming>,
    stopped: smol::channel::Receiver<()>,
) -> Ended {
    let listen = async {
        while let Ok(incoming) = arrivals.recv().await {
            inner.take_liveness(incoming);
        }
        Ended::Closed
    };
    beat(Arc::clone(&inner))
        .or(listen)
        .or(async {
            let _ = stopped.recv().await;
            Ended::Stopped
        })
        .await
}

/// Send the pair heartbeat every interval, and wake the groups this node
/// leads when its writer stalls or recovers, so they hand over or go on
/// at once rather than at their next deadline.
async fn beat(inner: Arc<Inner>) -> Ended {
    let interval = Duration::from_millis(inner.settings.heartbeat_ms);
    let mut stalled = false;
    // The first heartbeat goes at once, then one each interval.
    let mut first = true;
    loop {
        if !first {
            smol::Timer::after(interval).await;
        }
        first = false;
        inner.halt_if_store_failed();
        // A halted node falls silent: its groups' followers elect others.
        if inner.halted.load(Ordering::SeqCst) {
            continue;
        }
        if inner.storage.stalled() != stalled {
            stalled = !stalled;
            inner.to_led(None, || Local::Wake);
        }
        inner.wake_quiet();
        inner
            .liveness
            .beaten
            .store(inner.liveness.elapsed(), Ordering::Relaxed);
        let round = inner.liveness.next_round();
        let size = inner
            .network
            .as_ref()
            .map_or(LISTED, |network| per_frame(network.limits().liveness));
        // None listed while the writer is stalled, so their followers elect
        // leaders that can write, and none that is not live.
        let led = if inner.storage.stalled() {
            Vec::new()
        } else {
            inner.led()
        };
        // The round's frames wait for room until half an interval from
        // now, all peers together: slow ones do not hold the next round.
        let room = Instant::now() + interval / 2;
        for &peer in inner.numbers.iter().filter(|&&peer| peer != inner.number) {
            // A group whose placement this node does not hold goes to
            // every node.
            let listed: Vec<(AgentId, u64)> = led
                .iter()
                .filter(|led| led.live && led.admits(peer))
                .map(|led| (led.leading.agent, led.leading.term))
                .collect();
            let told = lock(&inner.liveness.telling)
                .entry(peer)
                .or_default()
                .round(round, listed);
            let took = inner.liveness.table().taken(peer).unwrap_or((0, 0));
            let frames = frames(
                (inner.liveness.incarnation, inner.settings.lanes),
                round,
                told,
                took,
                size,
            );
            // A frame the peer's queue has no room for ends the round
            // there: the next names its changes again.
            for frame in frames {
                if !inner.send_heartbeat(peer, &frame, room).await {
                    break;
                }
            }
        }
    }
}

/// One round's heartbeat to one peer, from this node's run `incarnation`
/// on its `lanes`: `told` in frames of at most `size` groups, and one
/// frame when it names none.
fn frames(
    (incarnation, lanes): (u64, u32),
    round: u64,
    told: Round<AgentId>,
    took: (u64, u64),
    size: usize,
) -> Vec<PeerMessage> {
    let Round {
        since,
        leading,
        unlisted,
    } = told;
    let mut leading = leading
        .into_iter()
        .map(|(agent, term)| Leading { agent, term });
    let mut unlisted = unlisted.into_iter();
    let mut parts = Vec::new();
    loop {
        let listed: Vec<Leading> = leading.by_ref().take(size).collect();
        let gone: Vec<AgentId> = unlisted.by_ref().take(size - listed.len()).collect();
        if listed.is_empty() && gone.is_empty() && !parts.is_empty() {
            break;
        }
        parts.push((listed, gone));
    }
    let count = parts.len() as u32;
    parts
        .into_iter()
        .zip(0..)
        .map(|((leading, unlisted), part)| PeerMessage::Liveness {
            incarnation,
            round,
            since,
            part,
            parts: count,
            leading,
            unlisted,
            took,
            lanes,
        })
        .collect()
}

/// A group this node leads, at its term, as a round lists it.
pub(crate) struct Led {
    pub(crate) leading: Leading,
    /// Not stopped, and its driver gone round in two election timeouts.
    pub(crate) live: bool,
    /// Its record and placement, when known.
    known: Option<Arc<Known>>,
}

impl Led {
    /// Whether its placement names `member`, or this node holds none.
    pub(crate) fn admits(&self, member: NodeNumber) -> bool {
        self.known
            .as_ref()
            .is_none_or(|known| known.placement.admits(member))
    }
}

impl Inner {
    /// The groups this node leads, at their terms, in group order, each
    /// with its placement when known, and whether it is live: not stopped,
    /// and its driver gone round in two election timeouts. A quiet driver
    /// with nothing waiting for it, its leader loop's queue included,
    /// counts as gone round now: the two timeouts run from the first work
    /// that waits for it.
    fn led(&self) -> Vec<Led> {
        let now = self.liveness.elapsed();
        let stuck = 2 * self.settings.election_timeout_ms.1;
        let leaders: Vec<AgentId> = lock(&self.leaders).iter().copied().collect();
        let runs: Vec<(AgentId, Arc<Run>)> = {
            let runs = lock(&self.runs);
            leaders
                .into_iter()
                .filter_map(|agent| Some((agent, Arc::clone(runs.get(&agent)?))))
                .collect()
        };
        let mut led: Vec<Led> = runs
            .iter()
            .filter_map(|(agent, run)| {
                let state = run.shared.state();
                if state.role != Role::Leader {
                    return None;
                }
                let idle = lock(&run.shared.quiet).is_some()
                    && run.inbox.is_empty()
                    && run.local.is_empty()
                    && lock(&run.agent.queue).is_empty();
                if idle {
                    run.shared.woke.fetch_max(now, Ordering::Relaxed);
                }
                let woke = run.shared.woke.load(Ordering::Relaxed);
                Some(Led {
                    leading: Leading {
                        agent: *agent,
                        term: state.term,
                    },
                    live: !state.stopped && now.saturating_sub(woke) < stuck,
                    known: None,
                })
            })
            .collect();
        led.sort_unstable_by_key(|led| led.leading.agent);
        let directory = lock(&self.directory.known);
        for led in &mut led {
            led.known = directory.get(&led.leading.agent).cloned();
        }
        led
    }

    /// Send one frame of the pair heartbeat to `to`, waiting until `room`
    /// at most for room in its queue: false when it was refused.
    async fn send_heartbeat(&self, to: NodeNumber, message: &PeerMessage, room: Instant) -> bool {
        let Some(network) = &self.network else {
            return false;
        };
        let wait = room.saturating_duration_since(Instant::now());
        timeout(wait, network.ready(to, Class::Liveness)).await;
        network
            .send(to, Class::Liveness, 0, message.encode())
            .is_ok()
    }

    /// Wake each quiet group whose quiet the pair heartbeat no longer
    /// vouches for, or will not by the next round: a follower whose leader
    /// has not listed the group at its term within the election timeout's
    /// lower end, a leader with a member whose node has not been heard
    /// within its upper end, as [`vos_raft::core::Core::vouch`] judges
    /// them.
    fn wake_quiet(&self) {
        let (low, high) = self.settings.election_timeout_ms;
        let ahead = Instant::now() + Duration::from_millis(self.settings.heartbeat_ms);
        let lapsed = |at: Option<Instant>, within: u64| {
            at.is_none_or(|at| at + Duration::from_millis(within) <= ahead)
        };
        // A group goes quiet only while its leader's listing names it, and
        // a change to that listing wakes it as it arrives: only a peer
        // whose listing went unrenewed, or who fell silent, leaves groups
        // to wake here.
        let lapsing = {
            let table = self.liveness.table();
            self.numbers
                .iter()
                .filter(|&&peer| peer != self.number)
                .any(|&peer| lapsed(table.renewed(peer), low) || lapsed(table.heard_at(peer), high))
        };
        if !lapsing {
            return;
        }
        // Taken apart from the runs' lock, which no group's quiet then waits
        // behind.
        let runs: Vec<(AgentId, Arc<Run>)> = lock(&self.runs)
            .iter()
            .map(|(agent, run)| (*agent, Arc::clone(run)))
            .collect();
        let due: Vec<AgentId> = {
            let table = self.liveness.table();
            runs.iter()
                .filter(|(agent, run)| match &*lock(&run.shared.quiet) {
                    None => false,
                    Some(Quiet::Following { leader, term }) => {
                        lapsed(table.listed(*leader, agent, *term), low)
                    }
                    Some(Quiet::Leading { members }) => members
                        .iter()
                        .any(|&member| lapsed(table.heard_at(member), high)),
                })
                .map(|(agent, _)| *agent)
                .collect()
        };
        for agent in due {
            self.to_group(agent, Local::Wake);
        }
    }

    /// Note whether `agent`'s replica here leads.
    pub(crate) fn led_here(&self, agent: AgentId, leads: bool) {
        let mut leaders = lock(&self.leaders);
        if leads {
            leaders.insert(agent);
        } else {
            leaders.remove(&agent);
        }
    }

    /// Give each group this node leads `local`: every one, or those whose
    /// placement admits `member`.
    fn to_led(&self, member: Option<NodeNumber>, local: impl Fn() -> Local) {
        for led in self.led() {
            if member.is_none_or(|member| led.admits(member)) {
                self.to_group(led.leading.agent, local());
            }
        }
    }

    /// Wake each quiet group among `changed`, whose listing by `from` just
    /// changed, that the pair heartbeat no longer stands in for: one that
    /// follows `from` at a term it no longer lists the group at, or follows
    /// another node while `from` claims or gives up the group.
    fn wake_changed(&self, from: NodeNumber, changed: &[AgentId]) {
        let table = self.liveness.table();
        for &agent in changed {
            let Some(run) = self.run(agent) else {
                continue;
            };
            let due = match &*lock(&run.shared.quiet) {
                Some(Quiet::Following { leader, term }) => {
                    *leader != from || table.listed(from, &agent, *term).is_none()
                }
                _ => false,
            };
            if due {
                self.to_group(agent, Local::Wake);
            }
        }
    }

    /// A liveness frame from a peer: checked, and taken into the table. A
    /// peer that came back (a new run of it, or heard again after a
    /// silence) is probed by every group this node leads with it.
    fn take_liveness(&self, incoming: Incoming) {
        let Incoming {
            from,
            stream,
            frame,
        } = incoming;
        let message = match peer::decode(&frame) {
            Ok(message) => message,
            Err(refusal) => {
                self.drops.count(refusal);
                return;
            }
        };
        if let Err(refusal) = peer::check(
            &self.numbers,
            &self.space_and_clock().0,
            from,
            (Class::Liveness, stream),
            self.settings.lanes,
            &message,
            |_| None,
        ) {
            self.drops.count(refusal);
            return;
        }
        let PeerMessage::Liveness {
            incarnation,
            round,
            since,
            part,
            parts,
            leading,
            unlisted,
            took,
            lanes,
        } = message
        else {
            return;
        };
        if !self.liveness.lanes_agree(from, lanes, self.settings.lanes) {
            self.drops.count(peer::Refusal::OtherLanes);
            return;
        }
        let frame = Frame {
            incarnation,
            round,
            part,
            parts,
            listing: Round {
                since,
                leading: leading
                    .into_iter()
                    .map(|led| (led.agent, led.term))
                    .collect(),
                unlisted,
            },
        };
        let now = Instant::now();
        let Some(heard) = self.liveness.table_mut().heard(from, now, frame) else {
            return;
        };
        {
            let mut telling = lock(&self.liveness.telling);
            let teller = telling.entry(from).or_default();
            // A new run of the peer holds nothing this node told the last.
            if heard.new_run {
                teller.reset();
            }
            if took.0 == self.liveness.incarnation {
                teller.acked(took.1);
            }
        }
        if !heard.changed.is_empty() {
            self.wake_changed(from, &heard.changed);
        }
        let silence = Duration::from_millis(self.settings.election_timeout_ms.1);
        let returned = heard.new_run
            || heard
                .before
                .is_none_or(|before| now.duration_since(before) >= silence);
        if returned {
            self.to_led(Some(from), || Local::Probe(from));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_outranks_the_last_even_when_the_clock_stands_behind() {
        let now = next_incarnation(0);
        assert!(now > 0);
        let ahead = now + 10_000_000;
        assert_eq!(next_incarnation(ahead), ahead + 1);
        assert!(next_incarnation(now) > now);
        assert_eq!(next_incarnation(u64::MAX), u64::MAX);
    }

    #[test]
    fn a_peer_on_other_lanes_is_refused_until_it_agrees() {
        let liveness = Liveness::new(1);
        assert!(!liveness.refuses(2));
        assert!(liveness.lanes_agree(2, 8, 8));
        assert!(!liveness.lanes_agree(2, 4, 8));
        assert!(liveness.refuses(2));
        assert!(!liveness.refuses(3));
        assert!(!liveness.lanes_agree(2, 4, 8), "still refused");
        assert!(liveness.lanes_agree(2, 8, 8));
        assert!(!liveness.refuses(2));
    }

    #[test]
    fn rounds_go_on_across_the_heartbeats_restarts() {
        let liveness = Liveness::new(1);
        assert_eq!(liveness.next_round(), 1);
        assert_eq!(liveness.next_round(), 2);
        // A restarted heartbeat takes the same counter.
        assert_eq!(liveness.next_round(), 3);
    }

    #[test]
    fn a_frame_of_as_many_groups_as_its_limit_allows_fits_it() {
        for limit in [128, 1 << 10, vos_net::Limits::DEFAULT.liveness] {
            let size = per_frame(limit);
            let leading: Vec<(AgentId, u64)> = (0..size as u32)
                .map(|agent| (AgentId(u32::MAX - agent), u64::MAX))
                .collect();
            let told = Round {
                since: u64::MAX,
                leading,
                unlisted: Vec::new(),
            };
            let frames = frames(
                (u64::MAX, u32::MAX),
                u64::MAX,
                told,
                (u64::MAX, u64::MAX),
                size,
            );
            assert_eq!(frames.len(), 1);
            assert!(frames[0].encode().len() <= limit, "{limit}");
        }
        assert_eq!(per_frame(vos_net::Limits::DEFAULT.liveness), LISTED);
    }

    #[test]
    fn a_long_round_goes_in_frames_of_one_round() {
        let leading: Vec<(AgentId, u64)> = (0..5).map(|agent| (AgentId(agent), 2)).collect();
        let told = Round {
            since: 4,
            leading: leading.clone(),
            unlisted: vec![AgentId(9)],
        };
        let frames = frames((7, 5), 3, told, (8, 6), 2);
        assert_eq!(frames.len(), 3);
        let (mut listed, mut gone) = (Vec::new(), Vec::new());
        for (frame, at) in frames.into_iter().zip(0..) {
            let PeerMessage::Liveness {
                incarnation,
                round,
                since,
                part,
                parts,
                leading,
                unlisted,
                took,
                lanes,
            } = frame
            else {
                panic!("a liveness frame");
            };
            assert_eq!(
                (incarnation, round, since, part, parts, took, lanes),
                (7, 3, 4, at, 3, (8, 6), 5)
            );
            assert!(leading.len() + unlisted.len() <= 2);
            listed.extend(leading.into_iter().map(|led| (led.agent, led.term)));
            gone.extend(unlisted);
        }
        assert_eq!(listed, leading);
        assert_eq!(gone, [AgentId(9)]);
        let empty = Round {
            since: 4,
            leading: Vec::new(),
            unlisted: Vec::new(),
        };
        let one = super::frames((7, 5), 4, empty, (0, 0), 2);
        assert_eq!(one.len(), 1, "one frame for none");
    }
}
