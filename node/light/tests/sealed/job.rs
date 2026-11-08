//! The background job's pass (`light-node.md` §3.6, "Background sync")
//! against `Personal` in a home: a pass with nothing new reads only the
//! log's head, the overview, each scope's empty page and the device set;
//! a pass pushes what was queued and reads what others pushed, each
//! device's last call read back; a pending restore is answered with
//! `alive`; an open operation is a notice with the time the log took it;
//! and a pass killed before or after any of its requests leaves a store
//! the next pass finishes from, every phone converging and nothing stored
//! twice (§2.2, D6).

use vos_light::group::Alarm;
use vos_light::job::{self, Control, Kind, Notice, Pass, Post};
use vos_light::kit::KitSecret;
use vos_wire::personal::{Cancel, DeviceView, Entry, OpState, Operation, Overview};

use super::kit::{household_with, open_restore, operate};
use super::*;

/// Where a link dies: at its `n`th request, before the agent sees it, or
/// after the agent took it and before its answer arrives.
#[derive(Clone, Copy, Debug)]
enum Death {
    Before(usize),
    After(usize),
}

#[derive(Debug, PartialEq, Eq)]
struct Killed;

/// An answer's bytes, as the agent encodes it.
trait Measured {
    fn bytes(&self) -> usize;
}

impl<T: Encode> Measured for Result<T, PersonalError> {
    fn bytes(&self) -> usize {
        match self {
            Ok(value) => value.encode().len(),
            Err(error) => error.encode().len(),
        }
    }
}

impl<T: Encode> Measured for Vec<Result<T, PersonalError>> {
    fn bytes(&self) -> usize {
        self.iter().map(Measured::bytes).sum()
    }
}

/// The link to the home's agent as a phone's sync key, counting its
/// requests and the bytes of the answers it reads; it dies as `death`
/// says, and answers nothing after.
struct JobLink<'a> {
    home: &'a mut Home,
    sync: SigningKey,
    requests: usize,
    down: usize,
    death: Option<Death>,
    dead: bool,
}

impl<'a> JobLink<'a> {
    fn new(home: &'a mut Home, phone: &Phone) -> Self {
        Self {
            home,
            sync: phone.sync.clone(),
            requests: 0,
            down: 0,
            death: None,
            dead: false,
        }
    }

    fn key(&self) -> [u8; 32] {
        self.sync.verifying_key().to_bytes()
    }

    /// One request: `f`'s answer, its bytes counted, unless the link dies
    /// there.
    fn request<T: Measured>(
        &mut self,
        f: impl FnOnce(&mut Home, &SigningKey) -> T,
    ) -> Result<T, Killed> {
        if self.dead {
            return Err(Killed);
        }
        let n = self.requests;
        self.requests += 1;
        if matches!(self.death, Some(Death::Before(at)) if at == n) {
            self.dead = true;
            return Err(Killed);
        }
        let answer = f(self.home, &self.sync);
        if matches!(self.death, Some(Death::After(at)) if at == n) {
            self.dead = true;
            return Err(Killed);
        }
        self.down += answer.bytes();
        Ok(answer)
    }
}

impl Link for JobLink<'_> {
    type Error = Killed;

    fn route(&self) -> Route {
        Route::Onion
    }

    fn push(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, Killed> {
        self.request(|home, sync| {
            envelopes
                .iter()
                .map(|envelope| {
                    home.call(sync, "push", envelope.encode())
                        .answer::<Pushed>()
                })
                .collect::<Vec<_>>()
        })
    }

    fn since(&mut self, scope: Scope, position: u64) -> Answer<Vec<Envelope>, Killed> {
        let key = self.key();
        self.request(|home, _| home.query(key, "since", (scope, position).encode()))
    }

    fn wake(&mut self) -> Answer<Woken, Killed> {
        self.request(|home, sync| home.call(sync, "wake", ().encode()).answer())
    }

    fn frontier(&mut self, device: u32) -> Answer<Frontier, Killed> {
        let key = self.key();
        self.request(|home, _| home.query(key, "frontier", device.encode()))
    }
}

impl Control for JobLink<'_> {
    fn log(&mut self, from: u64) -> Answer<Vec<(u64, Entry)>, Killed> {
        let key = self.key();
        self.request(|home, _| home.query(key, "log", from.encode()))
    }

    fn overview(&mut self) -> Answer<Overview, Killed> {
        let key = self.key();
        self.request(|home, _| home.query(key, "overview", ().encode()))
    }

    fn devices(&mut self) -> Answer<Vec<DeviceView>, Killed> {
        let key = self.key();
        self.request(|home, _| home.query(key, "devices", ().encode()))
    }

    fn post(&mut self, post: &Post) -> Answer<u64, Killed> {
        self.request(|home, sync| {
            let reply = home.call(sync, post.name(), post.arguments());
            match &reply.outcome {
                Outcome::Done(bytes) => Ok(post.at(bytes).expect("the reply decodes")),
                _ => Err(reply.answer::<()>().unwrap_err()),
            }
        })
    }
}

/// What a pass over a fresh link did: the pass, its requests and the
/// bytes it read.
struct Run {
    pass: Pass,
    requests: usize,
    down: usize,
}

/// One pass of `phone`'s job over `instances`, its link dying as `death`
/// says.
fn pass_with(
    home: &mut Home,
    phone: &mut Phone,
    instances: &[InstanceId],
    death: Option<Death>,
) -> Result<Run, vos_light::personal::SyncError<Killed>> {
    let now = home.now;
    let mut link = JobLink::new(home, phone);
    link.death = death;
    let Phone { light, group, .. } = phone;
    let pass = job::run(light, group.as_mut().unwrap(), &mut link, instances, now)?;
    Ok(Run {
        pass,
        requests: link.requests,
        down: link.down,
    })
}

fn pass(home: &mut Home, phone: &mut Phone) -> Run {
    pass_with(home, phone, &[NOTES], None).unwrap()
}

/// A pass with nothing new, each phone having passed once: no post, no
/// push, no envelope; the log's head, the overview, the scope's empty
/// pages and the device set. Its requests and bytes are what PG6's job
/// reads on a quiet day, before the transport's framing.
#[test]
fn a_pass_with_nothing_new_reads_little() {
    let (mut home, mut phones) = household(2);
    set(&phones[0].light, NOTES, 1, 10);
    for phone in phones.iter_mut() {
        pass(&mut home, phone);
    }
    for phone in phones.iter_mut() {
        pass(&mut home, phone);
    }
    home.pass(15 * MIN);
    let quiet = pass(&mut home, &mut phones[1]);
    assert_eq!(quiet.pass.posts, 0);
    assert_eq!(quiet.pass.pushed, 0);
    assert_eq!(quiet.pass.envelopes, 0);
    assert!(quiet.pass.alarms.is_empty(), "{:?}", quiet.pass.alarms);
    assert!(
        quiet.pass.notices().is_empty(),
        "{:?}",
        quiet.pass.notices()
    );
    eprintln!(
        "quiet pass: {} requests, {} bytes of answers",
        quiet.requests, quiet.down
    );
    assert!(quiet.down < 64 << 10, "{} bytes", quiet.down);
    assert!(quiet.requests <= 12, "{} requests", quiet.requests);
}

/// A pass pushes the scope's queued operations and reads what the other
/// phone pushed; each device's last call is read back, the pushing
/// phone's at its push.
#[test]
fn a_pass_pushes_and_reads_the_scopes() {
    let (mut home, mut phones) = household(2);
    for key in 0..3 {
        set(&phones[0].light, NOTES, key, key + 100);
    }
    let pushed_at = home.now;
    let first = pass(&mut home, &mut phones[0]);
    assert_eq!(first.pass.pushed, 3);
    assert!(phones[0].light.queued(NOTES).unwrap().is_empty());
    let second = pass(&mut home, &mut phones[1]);
    assert_eq!(second.pass.envelopes, 3);
    assert!(second.pass.alarms.is_empty(), "{:?}", second.pass.alarms);
    for key in 0..3 {
        assert_eq!(count(&phones[1].light, NOTES, key), Some(key + 100));
    }
    let writer_key = phones[0].sync_key();
    let writer = phones[1]
        .group()
        .author(&writer_key)
        .expect("the writer is of the set")
        .0;
    let seen = second
        .pass
        .seen
        .iter()
        .find(|(device, _)| *device == writer)
        .expect("the writer's last call")
        .1;
    assert!(seen >= pushed_at, "{seen} before {pushed_at}");
}

/// A restore signed by a leaked kit is pending: the pass posts `alive`,
/// which cancels it, and raises the restore and the kit's operation.
#[test]
fn a_pending_restore_is_answered_with_alive() {
    let leaked = KitSecret::phrase().unwrap();
    let (mut home, mut phones, _) = household_with(2, vec![leaked.key()]);
    let next = KitSecret::phrase().unwrap();
    let (_, _, index) = open_restore(&mut home, &leaked, &next, 9);
    let run = pass(&mut home, &mut phones[0]);
    assert!(run.pass.alive);
    let notices = run.pass.notices();
    assert!(notices.contains(&Notice::Restore), "{notices:?}");
    assert!(
        notices.contains(&Notice::Alarm(Alarm::Kit { index })),
        "{notices:?}"
    );
    let state = home
        .query::<Operation>(phones[0].sync_key(), "operation", index.encode())
        .unwrap()
        .state;
    assert!(
        matches!(
            state,
            OpState::Cancelled {
                why: Cancel::Alive,
                ..
            }
        ),
        "{state:?}"
    );
}

/// Another phone's removal of this one is open: the pass raises it with
/// the time the log took it, which the notification's latency is measured
/// from, until it is closed.
#[test]
fn an_open_operation_is_a_notice() {
    let (mut home, mut phones, _) = household_with(2, vec![KitSecret::phrase().unwrap().key()]);
    let (admin, sync) = (phones[1].admin.clone(), phones[1].sync.clone());
    let taken = home.now;
    let index = operate(&mut home, &admin, &sync, "remove", 0u32.encode(), None);
    home.pass(MIN);
    let run = pass(&mut home, &mut phones[0]);
    let notice = run
        .pass
        .notices()
        .into_iter()
        .find(|notice| matches!(notice, Notice::Operation { index: at, .. } if *at == index))
        .expect("the removal is raised");
    let Notice::Operation {
        kind, at, matures, ..
    } = notice
    else {
        unreachable!()
    };
    assert_eq!(kind, Kind::Remove);
    let at = at.expect("this pass read it");
    assert!(at >= taken && at < home.now, "{at}");
    assert_eq!(matures, at + policy().operation_delay_ms);
    let latency = home.now - at;
    eprintln!("operation to notice: {latency} ms of the home's clock");
}

/// The work a killed pass is given: phone 1 pushed two notes, phone 0 has
/// three queued and reads phone 1's.
fn killable() -> (Home, Vec<Phone>) {
    let (mut home, mut phones) = household(2);
    for key in 0..2 {
        set(&phones[1].light, NOTES, 10 + key, key);
    }
    pass(&mut home, &mut phones[1]);
    for key in 0..3 {
        set(&phones[0].light, NOTES, key, key + 1);
    }
    (home, phones)
}

/// Each phone converged: phone 0's queue empty, both reading all five
/// notes, the agent holding each once.
fn converged(home: &mut Home, phones: &mut [Phone]) {
    let finished = pass(home, &mut phones[0]);
    assert!(
        finished.pass.alarms.is_empty(),
        "{:?}",
        finished.pass.alarms
    );
    assert!(phones[0].light.queued(NOTES).unwrap().is_empty());
    assert!(phones[0].light.outbox(NOTES).unwrap().is_empty());
    let other = pass(home, &mut phones[1]);
    assert!(other.pass.alarms.is_empty(), "{:?}", other.pass.alarms);
    for phone in phones.iter() {
        for key in 0..3 {
            assert_eq!(count(&phone.light, NOTES, key), Some(key + 1));
        }
        for key in 0..2 {
            assert_eq!(count(&phone.light, NOTES, 10 + key), Some(key));
        }
    }
    let scope = scope_of(&phones[0], NOTES);
    assert_eq!(
        stored(home, &phones[0], scope).len(),
        5,
        "each node stored once"
    );
}

/// A pass killed before and after each of its requests, as Android kills
/// a job's process: the phone restarted from its store, the next pass
/// finishes the work, and the phones converge with nothing stored twice.
#[test]
fn a_killed_pass_leaves_the_store_consistent() {
    let requests = {
        let (mut home, mut phones) = killable();
        let whole = pass(&mut home, &mut phones[0]);
        converged(&mut home, &mut phones);
        whole.requests
    };
    assert!(requests >= 6, "{requests} requests");
    for n in 0..requests {
        for death in [Death::Before(n), Death::After(n)] {
            let (mut home, mut phones) = killable();
            let killed = pass_with(&mut home, &mut phones[0], &[NOTES], Some(death));
            assert!(
                matches!(killed, Err(vos_light::personal::SyncError::Link(Killed))),
                "{death:?}: {:?}",
                killed.map(|run| run.requests)
            );
            restart(&mut phones[0]);
            assert!(phones[0].group.is_some(), "{death:?}: the group reopens");
            converged(&mut home, &mut phones);
        }
    }
}
