//! The pair heartbeat. Once per heartbeat interval each node tells every
//! other node of its space that it is alive, and which of the groups that
//! node replicates it leads, at what term. What a node hears goes into its
//! peer table, which its groups' drivers read to vouch for their leaders
//! and members before their own timers lapse
//! ([`vos_raft::core::Core::vouch`]): an idle group then sends nothing.
//! A group whose core needs no tick but those this stands in for waits on
//! no timer at all ([`crate::group::Quiet`]): each round wakes those whose
//! leader stopped listing them, or with a member whose node fell silent.
//! Whatever goes wrong here leaves Raft's own timing in charge.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use smol::future::FutureExt;
use vos_net::{Class, Incoming};
use vos_raft::Role;
use vos_raft::pair::PeerTable;
use vos_wire::ids::AgentId;
use vos_wire::peer::{Leading, NodeNumber, PeerMessage, Placement};

use crate::group::{Local, Quiet};
use crate::node::{Inner, Run};
use crate::peer;
use crate::{lock, timeout};

/// The most groups one frame lists, well within the network's cap on a
/// liveness frame.
const LISTED: usize = 4_096;
/// How long a listing not renewed is kept: far past any election timeout,
/// so the table stays bounded as groups come and go.
const FORGET: Duration = Duration::from_secs(60);
/// How long the pair heartbeat waits to start again after it failed,
/// first: short, as every group it leads is unvouched while it waits. It
/// doubles while it keeps failing, to `RESTART_MOST`.
const RESTART: Duration = Duration::from_millis(100);
const RESTART_MOST: Duration = Duration::from_secs(1);
/// A run of the heartbeat this long counts as recovered: the next
/// failure waits `RESTART` again.
const RECOVERED: Duration = Duration::from_secs(10);

/// What this node heard of its peers: when, and which groups each leads.
type Table = PeerTable<NodeNumber, AgentId, Instant>;

pub(crate) struct Liveness {
    /// This run of the node: its start time in microseconds, past every
    /// earlier run's.
    pub(crate) incarnation: u64,
    table: RwLock<Table>,
    started: Instant,
    /// The last round sent, kept across the heartbeat's restarts: peers
    /// ignore a round below the last they took from this run.
    round: AtomicU64,
    /// When the heartbeat last went round, in milliseconds since the node
    /// started: a group goes quiet only while it goes round on time.
    beaten: AtomicU64,
}

impl Liveness {
    pub(crate) fn new(incarnation: u64) -> Self {
        Self {
            incarnation,
            table: RwLock::new(PeerTable::new()),
            started: Instant::now(),
            round: AtomicU64::new(0),
            beaten: AtomicU64::new(0),
        }
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
        // None listed while the writer is stalled, so their followers elect
        // leaders that can write, and none that is not live.
        let leading = if inner.storage.stalled() {
            Vec::new()
        } else {
            inner.led()
        };
        for &peer in inner.numbers.iter().filter(|&&peer| peer != inner.number) {
            // A group whose placement this node does not hold goes to
            // every node.
            let listed: Vec<Leading> = leading
                .iter()
                .filter(|(_, placement, live)| {
                    *live
                        && placement
                            .as_ref()
                            .is_none_or(|placement| placement.admits(peer))
                })
                .map(|(leading, ..)| *leading)
                .collect();
            for frame in frames(inner.liveness.incarnation, round, &listed, LISTED) {
                inner.send(peer, &frame);
            }
        }
        if round.is_multiple_of(100)
            && let Some(before) = Instant::now().checked_sub(FORGET)
        {
            inner.liveness.table_mut().forget_before(before);
        }
    }
}

/// One round's heartbeat: `listed` in frames of at most `size` groups,
/// and one frame when it lists none.
fn frames(incarnation: u64, round: u64, listed: &[Leading], size: usize) -> Vec<PeerMessage> {
    let frame = |leading: &[Leading]| PeerMessage::Liveness {
        incarnation,
        round,
        leading: leading.to_vec(),
    };
    if listed.is_empty() {
        return vec![frame(&[])];
    }
    listed.chunks(size).map(frame).collect()
}

impl Inner {
    /// The groups this node leads, at their terms, each with its placement
    /// when known, and whether it is live: not stopped, and its driver gone
    /// round in two election timeouts. A quiet driver with nothing waiting
    /// for it, its leader loop's queue included, counts as gone round now:
    /// the two timeouts run from the first work that waits for it.
    fn led(&self) -> Vec<(Leading, Option<Placement>, bool)> {
        let now = self.liveness.elapsed();
        let stuck = 2 * self.settings.election_timeout_ms.1;
        let led: Vec<(Leading, bool)> = lock(&self.runs)
            .iter()
            .filter_map(|(agent, run)| {
                let state = run.shared.state();
                let idle = lock(&run.shared.quiet).is_some()
                    && run.inbox.is_empty()
                    && run.local.is_empty()
                    && lock(&run.agent.queue).is_empty();
                if idle {
                    run.shared.woke.fetch_max(now, Ordering::Relaxed);
                }
                let woke = run.shared.woke.load(Ordering::Relaxed);
                let live = !state.stopped && now.saturating_sub(woke) < stuck;
                let leading = Leading {
                    agent: *agent,
                    term: state.term,
                };
                (state.role == Role::Leader).then_some((leading, live))
            })
            .collect();
        let directory = lock(&self.directory.known);
        led.into_iter()
            .map(|(leading, live)| {
                let placement = directory
                    .get(&leading.agent)
                    .map(|known| known.placement.clone());
                (leading, placement, live)
            })
            .collect()
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

    /// Give each group this node leads `local`: every one, or those whose
    /// placement admits `member`.
    fn to_led(&self, member: Option<NodeNumber>, local: impl Fn() -> Local) {
        for (leading, placement, _) in self.led() {
            let admitted = member
                .is_none_or(|member| placement.is_none_or(|placement| placement.admits(member)));
            if admitted {
                self.to_group(leading.agent, local());
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
            &message,
            |_| None,
        ) {
            self.drops.count(refusal);
            return;
        }
        let PeerMessage::Liveness {
            incarnation,
            round,
            leading,
        } = message
        else {
            return;
        };
        let now = Instant::now();
        let heard = self.liveness.table_mut().heard(
            from,
            now,
            incarnation,
            round,
            leading.into_iter().map(|led| (led.agent, led.term)),
        );
        let silence = Duration::from_millis(self.settings.election_timeout_ms.1);
        let returned = heard.is_some_and(|heard| {
            heard.new_run
                || heard
                    .before
                    .is_none_or(|before| now.duration_since(before) >= silence)
        });
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
    fn rounds_go_on_across_the_heartbeats_restarts() {
        let liveness = Liveness::new(1);
        assert_eq!(liveness.next_round(), 1);
        assert_eq!(liveness.next_round(), 2);
        // A restarted heartbeat takes the same counter.
        assert_eq!(liveness.next_round(), 3);
    }

    #[test]
    fn a_long_list_goes_in_frames_of_one_round() {
        let listed: Vec<Leading> = (0..5)
            .map(|agent| Leading {
                agent: AgentId(agent),
                term: 2,
            })
            .collect();
        let frames = frames(7, 3, &listed, 2);
        assert_eq!(frames.len(), 3);
        let mut all = Vec::new();
        for frame in frames {
            let PeerMessage::Liveness {
                incarnation,
                round,
                leading,
            } = frame
            else {
                panic!("a liveness frame");
            };
            assert_eq!((incarnation, round), (7, 3));
            all.extend(leading);
        }
        assert_eq!(all, listed);
        assert_eq!(super::frames(7, 4, &[], 2).len(), 1, "one frame for none");
    }
}
