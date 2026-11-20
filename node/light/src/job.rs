//! The background job's pass (`light-node.md` §3.6, "Background sync"):
//! what a device does each time the operating system runs its job, over
//! one connection to its personal agent ([`Control`]), and what it leaves
//! for the chrome ([`Pass`]).
//!
//! In order: the control log read from the device group's cursor and
//! followed, every vote, evidence and `alive` it asks for posted until it
//! asks for none (`alive` while a restore is pending, §3.5); a quiet home
//! woken ([`STALE_MS`]) and the log followed again; the agent's head and
//! batch time checked; each scope's queued operations pushed and
//! its envelopes read by its cursor, the log followed again where a push or
//! a page waits for an epoch, the archive read where a page waits for a
//! key; the archive and the recovery envelopes kept; a sample of each
//! scope's own pushes audited; the device set read for each device's last
//! call.
//!
//! **A pass killed at any point leaves the store consistent:** every
//! change it makes is one of the device group's or sealed sync's batches,
//! each synced, and every request it sends is safe to send again: a push
//! the agent answers by its envelope's id, `alive` it logs at most once an
//! hour, and a vote or evidence it already holds (or whose candidate it
//! decided meanwhile) is refused with an answer the pass takes as done,
//! reading the log on. The next pass starts from what the store holds and
//! finishes the work.
//!
//! **A device that cannot follow** (stuck, or out of the group) reads the
//! log, the overview and the device set, and leaves its scopes alone: it
//! is removed and pairs again, or regroups, first. One the agent turns
//! away, once added, is out ([`DeviceGroup::turned_away`]). A pass that stops on an error hands back
//! what it had found ([`Stopped`]), its alarms with it.
//!
//! **What the chrome raises** ([`Pass::notices`]): the device set's open
//! operations, each a local notification while it can be vetoed; a
//! pending restore; this device's removal, and that it cannot follow, for
//! as long as either holds; a commit owed, for the matured removals it
//! carries or the kit it re-seals, until one is taken; and every alarm kept,
//! from the batch that consumed its evidence until the chrome, its user
//! having seen it, acknowledges it ([`DeviceGroup::acknowledge`]): a pass
//! killed or stopped after an alarm loses none.
//! No push-notification token is given to any space (§8, L3).

use ed25519_dalek::Signer as _;
use vos_abi::ids::{InstanceId, MethodId};
use vos_abi::{Decode, Encode};
use vos_wire::personal::{
    Attached, Body, DeviceId, DeviceView, Entry, Op, Overview, PersonalError, Recorded, Signer,
    Vote, Voted, method,
};

use crate::group::{self, Alarm, DeviceGroup, Event, Open};
use crate::light::Light;
use crate::personal::{Answer, Link, SealedSync, SyncError, Waiting};
use crate::route::Route;

/// The rounds of posting a pass makes while the log keeps asking for
/// more: a vote, then the next candidate's, and so on.
const ROUNDS: usize = 8;

/// The `wake`s a post makes before it gives up on `Settling`.
const WAKES: usize = 8;

/// The readings of one scope a pass makes while a page waits for an epoch
/// or a key.
const READINGS: usize = 4;

/// The own envelopes a pass audits in each scope.
pub const AUDIT_SAMPLE: usize = 1;

/// How old, by the device's clock, the agent's batch time may be before a
/// pass that posts nothing wakes the agent ([`due`]).
pub const STALE_MS: u64 = 10 * 60 * 1000;

/// What a device posts to its agent under its sync key while following
/// the log, each a named call of `Personal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Post {
    /// `confirm(epoch, h, signature)`.
    Confirm {
        epoch: u64,
        h: [u8; 32],
        signature: [u8; 64],
    },
    /// `nack(epoch, signature)`.
    Nack { epoch: u64, signature: [u8; 64] },
    /// `evidence((index, message), (signature, attached))`.
    Evidence {
        index: u64,
        message: Vec<u8>,
        signature: [u8; 64],
        attached: Attached,
    },
    /// `alive()`.
    Alive,
}

impl Post {
    /// The method.
    pub fn method(&self) -> MethodId {
        match self {
            Post::Confirm { .. } => method::CONFIRM,
            Post::Nack { .. } => method::NACK,
            Post::Evidence { .. } => method::EVIDENCE,
            Post::Alive => method::ALIVE,
        }
    }

    /// Its arguments, encoded.
    pub fn arguments(&self) -> Vec<u8> {
        match self {
            Post::Confirm {
                epoch,
                h,
                signature,
            } => (*epoch, *h, *signature).encode(),
            Post::Nack { epoch, signature } => (*epoch, *signature).encode(),
            Post::Evidence {
                index,
                message,
                signature,
                attached,
            } => ((*index, message.clone()), (*signature, attached.clone())).encode(),
            Post::Alive => ().encode(),
        }
    }

    /// The batch time its reply names, from the reply's bytes.
    pub fn at(&self, reply: &[u8]) -> Option<u64> {
        match self {
            Post::Confirm { .. } | Post::Nack { .. } => {
                Voted::decode_exact(reply).map(|voted| voted.at)
            }
            Post::Evidence { .. } | Post::Alive => {
                Recorded::decode_exact(reply).map(|recorded| recorded.at)
            }
        }
    }
}

/// A connection to the personal agent with what a pass reads and posts
/// beyond sealed sync's: the control log, the overview, the device set,
/// and the posts. Each method one round trip.
pub trait Control: Link {
    /// `log(from)`: the log's entries from `from`, as much as one answer
    /// holds.
    fn log(&mut self, from: u64) -> Answer<Vec<(u64, Entry)>, Self::Error>;

    /// `overview()`: the epochs, the log's head, the lease.
    fn overview(&mut self) -> Answer<Overview, Self::Error>;

    /// `devices()`: the device set, each device's standing and last call.
    fn devices(&mut self) -> Answer<Vec<DeviceView>, Self::Error>;

    /// `post` under the sync key in the link's session: the batch time it
    /// was taken at.
    fn post(&mut self, post: &Post) -> Answer<u64, Self::Error>;
}

/// What the chrome raises as a local notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// A device-set operation open at `index`, maturing at `matures`
    /// unless vetoed: `at` is when the log took it, if this pass read it.
    /// Contested, it waits for a resolution: none of this device's when it
    /// is `targeted`, the kit's alone when it is `kit_only`
    /// ([`group::Open`]).
    Operation {
        index: u64,
        by: Signer,
        kind: Kind,
        matures: u64,
        contested: bool,
        at: Option<u64>,
        targeted: bool,
        kit_only: bool,
    },
    /// The kit opened a restore, at `index`, which asserts every device
    /// lost: this device's `alive` stopped it, and its user rotates the
    /// kit unless they made it.
    Restore {
        index: u64,
    },
    /// This device is out of the group.
    Removed,
    /// This device cannot follow the confirmed epoch: removed from another
    /// device, it pairs again; or it regroups.
    Stuck,
    /// A commit is owed, which the user makes ("commit now", behind the
    /// biometric): what it carries.
    Commit(Commit),
    Alarm(Alarm),
}

/// What an owed commit carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// The removals that matured: until a commit carries them, the removed
    /// devices hold the epoch's keys, every device seals under it, and no
    /// recovery envelope is pushed.
    Removals,
    /// The kit re-sealed under a new `R`: the agent's verdict on the epoch
    /// that re-sealed it did not confirm it (or this device did not), so
    /// the `R` before, a removed device's, stands, and nothing is pushed to
    /// the recovery scope.
    Reseal,
}

/// A device-set operation's kind, as a notification names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Add,
    Remove,
    Replace,
    Rotate,
    Regroup,
    Restore,
}

impl Kind {
    pub fn of(op: &Op) -> Self {
        match op {
            Op::Add(_) => Kind::Add,
            Op::Remove(_) => Kind::Remove,
            Op::Replace { .. } => Kind::Replace,
            Op::Rotate(_) => Kind::Rotate,
            Op::Regroup(_) => Kind::Regroup,
            Op::Restore { .. } => Kind::Restore,
        }
    }
}

/// What one pass did and found.
#[derive(Debug, Default)]
pub struct Pass {
    /// The log entries read, and the posts made.
    pub entries: usize,
    pub posts: usize,
    /// Whether it posted `alive`: a restore is pending.
    pub alive: bool,
    /// The restore it answered with `alive`, by its log index.
    pub restore: Option<u64>,
    /// The epochs confirmed or voided, and this device's removal, as read.
    pub events: Vec<Event>,
    /// Every alarm kept and not yet acknowledged
    /// ([`DeviceGroup::acknowledge`]), the oldest first.
    pub alarms: Vec<Alarm>,
    /// The device set's operations open after the pass.
    pub operations: Vec<Open>,
    /// When the log took each operation this pass read, by index.
    pub taken: Vec<(u64, u64)>,
    /// The nodes this device's pushes delivered, and the envelopes read
    /// with their bytes.
    pub pushed: usize,
    pub envelopes: usize,
    pub bytes: usize,
    /// The operations read that are held or quarantined.
    pub held: usize,
    pub quarantined: usize,
    /// A scope's reading still waiting when the pass ended.
    pub waiting: Vec<(InstanceId, Waiting)>,
    /// Each device's last call the agent took, by its batch time (0 before
    /// any).
    pub seen: Vec<(DeviceId, u64)>,
    /// The agent's batch time.
    pub at: u64,
    /// Where the device is after the pass.
    pub course: group::Course,
    /// The commit owed after the pass, if one is.
    pub commit: Option<Commit>,
}

impl Pass {
    /// What the chrome raises for it.
    pub fn notices(&self) -> Vec<Notice> {
        let mut notices: Vec<Notice> = self
            .operations
            .iter()
            .filter(|open| open.verified)
            .map(|open| Notice::Operation {
                index: open.index,
                by: open.by,
                kind: Kind::of(&open.op),
                matures: open.matures,
                contested: open.contested,
                targeted: open.targeted,
                kit_only: open.kit_only,
                at: self
                    .taken
                    .iter()
                    .find(|(index, _)| *index == open.index)
                    .map(|(_, at)| *at),
            })
            .collect();
        if let Some(index) = self.restore {
            notices.push(Notice::Restore { index });
        }
        match self.course {
            group::Course::Out => notices.push(Notice::Removed),
            group::Course::Stuck { .. } => notices.push(Notice::Stuck),
            group::Course::Following => {}
        }
        if let Some(commit) = self.commit {
            notices.push(Notice::Commit(commit));
        }
        notices.extend(self.alarms.iter().copied().map(Notice::Alarm));
        notices
    }

    fn raise(&mut self, alarm: Alarm) {
        if !self.alarms.contains(&alarm) {
            self.alarms.push(alarm);
        }
    }

    /// `events` the device group gave outside the log's reading.
    fn saw(&mut self, events: Vec<Event>) {
        for event in events {
            match event {
                Event::Alarm(alarm) => self.raise(alarm),
                other if !self.events.contains(&other) => self.events.push(other),
                _ => {}
            }
        }
    }
}

/// A pass that stopped on `error`, and what it had found by then.
#[derive(Debug)]
pub struct Stopped<E> {
    pub pass: Box<Pass>,
    pub error: SyncError<E>,
}

/// One pass of the background job for `instances` of `light`, through
/// `group`'s agent over `link`, at the device's time `now` (milliseconds):
/// refused before anything is sent unless the link reaches the agent
/// through the onion.
pub fn run<L: Control>(
    light: &Light,
    group: &mut DeviceGroup,
    link: &mut L,
    instances: &[InstanceId],
    now: u64,
) -> Result<Pass, Stopped<L::Error>> {
    let mut pass = Pass::default();
    let mut done = passing(light, group, link, instances, now, &mut pass);
    if let Err(SyncError::Refused(PersonalError::NotAdmitted | PersonalError::Removed)) = &done {
        // Turned away though once added: out, its removal settled unread.
        done = group
            .turned_away()
            .map(|events| pass.saw(events))
            .map_err(SyncError::Group);
    }
    pass.course = group.course();
    pass.operations = group.operations();
    pass.commit = owed_commit(group);
    // Every alarm raised was kept in the batch that consumed its evidence;
    // the rest (the clock's) are kept now, and the pass reports every one
    // kept until the chrome acknowledges it.
    let kept = group.keep(&pass.alarms).and_then(|()| group.alarms());
    let done = match (done, kept) {
        (Ok(()), Ok(kept)) => {
            pass.alarms = kept;
            Ok(())
        }
        (Ok(()), Err(error)) => Err(SyncError::Group(error)),
        (Err(error), kept) => {
            if let Ok(kept) = kept {
                pass.alarms = kept;
            }
            Err(error)
        }
    };
    match done {
        Ok(()) => Ok(pass),
        Err(error) => Err(Stopped {
            pass: Box::new(pass),
            error,
        }),
    }
}

/// The commit `group` owes, if it follows, is in the set and no
/// candidate is pending (which may be the one carrying it).
pub fn owed_commit(group: &DeviceGroup) -> Option<Commit> {
    if group.course() != group::Course::Following || group.id().is_none() || group.pending() {
        return None;
    }
    if !group.owed().is_empty() {
        Some(Commit::Removals)
    } else if group.reseal_owed() {
        Some(Commit::Reseal)
    } else {
        None
    }
}

fn passing<L: Control>(
    light: &Light,
    group: &mut DeviceGroup,
    link: &mut L,
    instances: &[InstanceId],
    now: u64,
    pass: &mut Pass,
) -> Result<(), SyncError<L::Error>> {
    onion(link)?;
    follow(light, group, link, pass)?;
    if group.course() == group::Course::Out {
        return Ok(());
    }
    let mut overview = answer(link.overview())?;
    if pass.posts == 0 && due(group, &overview, now) {
        // A quiet home's reads are at its last batch's time, and what fell
        // due since is settled by a call alone: a wake, then the log again
        // for what it settled.
        wake(link)?;
        follow(light, group, link, pass)?;
        if group.course() == group::Course::Out {
            return Ok(());
        }
        overview = answer(link.overview())?;
    }
    for alarm in group.head(overview.next, overview.chain)? {
        pass.raise(alarm);
    }
    if group.cursor() < overview.next && group.course() != group::Course::Out {
        // A head past what was read: read on, and the head again must be
        // reached ([`Alarm::Unserved`]).
        follow(light, group, link, pass)?;
        if group.course() == group::Course::Out {
            return Ok(());
        }
        overview = answer(link.overview())?;
        for alarm in group.head(overview.next, overview.chain)? {
            pass.raise(alarm);
        }
    }
    pass.at = overview.at;
    if let Some(alarm) = group::clock(now, overview.at) {
        pass.raise(alarm);
    }
    if group.course() == group::Course::Following {
        sealed(light, group, link, instances, pass)?;
    }
    pass.seen = answer(link.devices())?
        .into_iter()
        .map(|view| (view.id, view.seen))
        .collect();
    Ok(())
}

/// Whether a pass that posted nothing wakes the agent: its batch time is
/// older than [`STALE_MS`] by the device's clock (the device set's
/// standing and the clock alarm read at that time); or an uncontested
/// operation open has matured by either clock, which only a call settles
/// (a removal's commit owed).
fn due(group: &DeviceGroup, overview: &Overview, now: u64) -> bool {
    overview.at.saturating_add(STALE_MS) < now
        || group
            .operations()
            .iter()
            .any(|open| !open.contested && open.matures <= now.max(overview.at))
}

/// Wake the agent until nothing due is left. A wake does not count the
/// device seen: the confirming set is the devices that voted, pushed or
/// lived (`alive`) in its window, not those that only read.
fn wake<L: Link>(link: &mut L) -> Result<(), SyncError<L::Error>> {
    for _ in 0..WAKES {
        onion(link)?;
        if answer(link.wake())?.settled {
            return Ok(());
        }
    }
    Err(SyncError::Settling)
}

/// The scopes pushed and read, the archive and the recovery envelopes
/// kept, and one own push audited.
fn sealed<L: Control>(
    light: &Light,
    group: &mut DeviceGroup,
    link: &mut L,
    instances: &[InstanceId],
    pass: &mut Pass,
) -> Result<(), SyncError<L::Error>> {
    for instance in instances {
        scope(light, group, link, instances, *instance, pass)?;
    }
    keep(light, group, link, instances, pass)?;
    for instance in instances {
        let audited = SealedSync::new(light, group, link, instances.to_vec())?
            .audit(*instance, AUDIT_SAMPLE)?;
        for alarm in audited.alarms {
            pass.raise(alarm);
        }
    }
    Ok(())
}

fn onion<L: Link>(link: &L) -> Result<(), SyncError<L::Error>> {
    if link.route() != Route::Onion {
        return Err(SyncError::Clearnet);
    }
    Ok(())
}

fn answer<T, E>(answer: Answer<T, E>) -> Result<T, SyncError<E>> {
    answer.map_err(SyncError::Link)?.map_err(SyncError::Refused)
}

/// Read the log from the cursor to its head and act on it, posting what it
/// asks for until it asks for nothing.
fn follow<L: Control>(
    light: &Light,
    group: &mut DeviceGroup,
    link: &mut L,
    pass: &mut Pass,
) -> Result<(), SyncError<L::Error>> {
    for _ in 0..ROUNDS {
        let entries = log(link, group.cursor())?;
        pass.entries += entries.len();
        for (index, entry) in &entries {
            if matches!(entry.body, Body::Operation { .. }) {
                pass.taken.retain(|(taken, _)| taken != index);
                pass.taken.push((*index, entry.at));
            }
        }
        let mut posted = false;
        let mut events = group.follow(entries)?;
        // `alive` first: a later post refused stops the pass.
        events.sort_by_key(|event| *event != Event::Alive);
        for event in events {
            let post = match event {
                Event::Vote {
                    epoch,
                    vote,
                    message,
                } => {
                    let signature = light.sync_key().sign(&message).to_bytes();
                    match vote {
                        Vote::Confirm(h) => Post::Confirm {
                            epoch,
                            h,
                            signature,
                        },
                        Vote::Nack => Post::Nack { epoch, signature },
                    }
                }
                Event::Evidence {
                    index,
                    message,
                    signature,
                    attached,
                } => Post::Evidence {
                    index,
                    message,
                    signature,
                    attached,
                },
                Event::Alive => {
                    pass.alive = true;
                    pass.restore = group
                        .operations()
                        .iter()
                        .find(|open| matches!(open.op, Op::Restore { .. }))
                        .map(|open| open.index)
                        .or(pass.restore);
                    Post::Alive
                }
                Event::Alarm(alarm) => {
                    pass.raise(alarm);
                    continue;
                }
                other => {
                    if !pass.events.contains(&other) {
                        pass.events.push(other);
                    }
                    continue;
                }
            };
            // Taken before (a kill between the post and its answer), or its
            // candidate decided meanwhile: the log says which, read on. An
            // evidence the agent refuses is posted no more, and the pass
            // goes on: the operation it is of is cancelled at its due time.
            match (post_settled(link, &post), &post) {
                (Ok(Some(at)), _) => {
                    group.called(at);
                    pass.posts += 1;
                }
                (Ok(None), _) => {}
                (Err(SyncError::Refused(_)), Post::Evidence { index, .. }) => {
                    group.evidence_refused(*index)?;
                }
                (Err(error), _) => return Err(error),
            }
            posted = true;
        }
        if !posted || group.course() == group::Course::Out {
            return Ok(());
        }
    }
    Ok(())
}

/// The log from `from` to its head, page by page.
fn log<L: Control>(link: &mut L, from: u64) -> Result<Vec<(u64, Entry)>, SyncError<L::Error>> {
    let mut entries = Vec::new();
    let mut next = from;
    loop {
        onion(link)?;
        let page = answer(link.log(next))?;
        let Some((last, _)) = page.last() else {
            return Ok(entries);
        };
        if *last < next {
            return Err(SyncError::Disordered);
        }
        next = last + 1;
        entries.extend(page);
    }
}

/// `post`, the agent woken and the post made again while it answers
/// `Settling`: the batch time it was taken at, or `None` when the agent
/// holds it already or decided its candidate meanwhile.
fn post_settled<L: Control>(link: &mut L, post: &Post) -> Result<Option<u64>, SyncError<L::Error>> {
    for _ in 0..=WAKES {
        onion(link)?;
        match link.post(post).map_err(SyncError::Link)? {
            Ok(at) => return Ok(Some(at)),
            Err(
                PersonalError::Voted
                | PersonalError::Evidenced
                | PersonalError::NoCandidate
                | PersonalError::NotConfirming,
            ) => return Ok(None),
            Err(PersonalError::Settling) => {
                onion(link)?;
                answer(link.wake())?;
            }
            Err(error) => return Err(SyncError::Refused(error)),
        }
    }
    Err(SyncError::Settling)
}

/// Push `instance`'s scope and read it by its cursor, following the log or
/// reading the archive where either waits for it.
fn scope<L: Control>(
    light: &Light,
    group: &mut DeviceGroup,
    link: &mut L,
    instances: &[InstanceId],
    instance: InstanceId,
    pass: &mut Pass,
) -> Result<(), SyncError<L::Error>> {
    let pushing = SealedSync::new(light, group, link, instances.to_vec())?.push(instance)?;
    pass.pushed += pushing.pushed.len();
    if pushing.stale.is_some() {
        follow(light, group, link, pass)?;
        let again = SealedSync::new(light, group, link, instances.to_vec())?.push(instance)?;
        pass.pushed += again.pushed.len();
    }
    let mut waiting = None;
    let mut withheld = false;
    for _ in 0..READINGS {
        let caught = SealedSync::new(light, group, link, instances.to_vec())?.catch_up(instance)?;
        pass.envelopes += caught.envelopes;
        pass.bytes += caught.bytes;
        pass.held += caught.held.len();
        pass.quarantined += caught.quarantined.len();
        for alarm in caught.alarms {
            pass.raise(alarm);
        }
        waiting = caught.waiting;
        match waiting {
            None => break,
            Some(Waiting::Epoch(_)) => follow(light, group, link, pass)?,
            Some(Waiting::Key(_)) => {
                SealedSync::new(light, group, link, instances.to_vec())?.archive()?;
            }
            // Read again once: a page withheld twice waits for the next pass.
            Some(Waiting::Withheld(_)) if withheld => break,
            Some(Waiting::Withheld(_)) => withheld = true,
        }
    }
    if let Some(waiting) = waiting {
        pass.waiting.push((instance, waiting));
    }
    Ok(())
}

/// Keep the archive and the recovery envelopes, following the log where a
/// push of either is stale.
fn keep<L: Control>(
    light: &Light,
    group: &mut DeviceGroup,
    link: &mut L,
    instances: &[InstanceId],
    pass: &mut Pass,
) -> Result<(), SyncError<L::Error>> {
    for _ in 0..2 {
        let mut sync = SealedSync::new(light, group, link, instances.to_vec())?;
        let archive = sync.archive()?;
        let recovery = sync.recovery()?;
        if archive.stale.is_none() && recovery.stale.is_none() {
            return Ok(());
        }
        follow(light, group, link, pass)?;
    }
    Ok(())
}
