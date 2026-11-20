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
use vos_light::job::{self, Commit, Control, Kind, Notice, Pass, Post};
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
    /// An envelope the operators place in a scope at its position, then
    /// fail the next request.
    placed: Option<(Scope, Envelope)>,
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
            placed: None,
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
        let mut answer = self.request(|home, _| {
            home.query::<Vec<Envelope>>(key, "since", (scope, position).encode())
        })?;
        if let (Ok(page), Some((at, envelope))) = (&mut answer, &self.placed)
            && *at == scope
            && position < envelope.position
        {
            page.retain(|held| held.position < envelope.position);
            page.push(envelope.clone());
            self.death = Some(Death::Before(self.requests));
        }
        Ok(answer)
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
            let reply = home.call(sync, named(post.method()), post.arguments());
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
) -> Result<Run, job::Stopped<Killed>> {
    let now = home.now();
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
    assert_eq!(quiet.requests, 6);
    assert!(quiet.down < 1 << 10, "{} bytes", quiet.down);
}

/// A quiet home, no call for hours: its agent reads at its last batch's
/// time, before the removal one phone made of the other matured. The pass
/// wakes it, which settles the removal: the commit it owes is raised on
/// the pass after it matured, the device set read at the home's time now,
/// and no clock alarm for the hours no call moved the batch time. The next
/// pass, a minute on, wakes nothing.
#[test]
fn a_pass_wakes_a_quiet_home() {
    let (mut home, mut phones, _) = household_with(2, vec![KitSecret::phrase().unwrap().key()]);
    let (admin, sync) = (phones[0].admin.clone(), phones[0].sync.clone());
    operate(&mut home, &admin, &sync, "remove", 1u32.encode(), None);
    let open = pass(&mut home, &mut phones[0]);
    assert_eq!(open.pass.commit, None);
    home.pass(3 * 60 * MIN);
    let now = home.now();
    let run = pass(&mut home, &mut phones[0]);
    assert_eq!(run.pass.commit, Some(Commit::Removals));
    assert!(
        run.pass
            .notices()
            .contains(&Notice::Commit(Commit::Removals)),
        "{:?}",
        run.pass.notices()
    );
    assert!(
        run.pass.at >= now,
        "the overview at {} before {now}",
        run.pass.at
    );
    assert!(
        !run.pass
            .alarms
            .iter()
            .any(|alarm| matches!(alarm, Alarm::Clock { .. })),
        "{:?}",
        run.pass.alarms
    );
    home.pass(MIN);
    let before = home.now();
    let next = pass(&mut home, &mut phones[0]);
    assert!(next.pass.at + MIN / 2 < before, "no wake a minute on");
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
    let pushed_at = home.now();
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
/// which cancels it, and raises the restore and the kit's operation; the
/// other phone's pass raises the kit's operation too, and a pass after
/// posts nothing.
#[test]
fn a_pending_restore_is_answered_with_alive() {
    let leaked = KitSecret::phrase().unwrap();
    let (mut home, mut phones, _) = household_with(2, vec![leaked.key()]);
    let next = KitSecret::phrase().unwrap();
    let (_, _, index) = open_restore(&mut home, &leaked, &next, 9);
    let run = pass(&mut home, &mut phones[0]);
    assert!(run.pass.alive);
    let notices = run.pass.notices();
    assert!(notices.contains(&Notice::Restore { index }), "{notices:?}");
    assert!(
        notices.contains(&Notice::Alarm(Alarm::Kit { index })),
        "{notices:?}"
    );
    let other = pass(&mut home, &mut phones[1]);
    assert!(!other.pass.alive, "the restore was cancelled already");
    assert!(
        other
            .pass
            .notices()
            .contains(&Notice::Alarm(Alarm::Kit { index })),
        "the kit's restore is raised on every phone"
    );
    let again = pass(&mut home, &mut phones[0]);
    assert!(!again.pass.alive && again.pass.posts == 0);
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
    let taken = home.now();
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
    assert!(at >= taken && at < home.now(), "{at}");
    assert_eq!(matures, at + policy().operation_delay_ms);
    let latency = home.now() - at;
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
                matches!(
                    &killed,
                    Err(job::Stopped {
                        error: vos_light::personal::SyncError::Link(Killed),
                        ..
                    })
                ),
                "{death:?}: {:?}",
                killed.map(|run| run.requests)
            );
            restart(&mut phones[0]);
            assert!(phones[0].group.is_some(), "{death:?}: the group reopens");
            converged(&mut home, &mut phones);
        }
    }
}

/// A candidate waits for this phone's vote: the pass votes, the other
/// phone's pass sees it confirmed. Killed before and after each request,
/// the next pass still votes once, refused as done where the agent took
/// the vote already, and the epoch confirms.
#[test]
fn a_pass_killed_around_its_vote_votes_once() {
    let requests = {
        let (mut home, mut phones) = household(2);
        let epoch = phones[0].group().confirmed();
        phones[1].update(&mut home).unwrap();
        let whole = pass(&mut home, &mut phones[0]);
        assert!(whole.pass.posts >= 1, "it voted");
        pass(&mut home, &mut phones[1]);
        assert_eq!(phones[1].group().confirmed(), epoch + 1);
        whole.requests
    };
    for n in 0..requests {
        for death in [Death::Before(n), Death::After(n)] {
            let (mut home, mut phones) = household(2);
            let epoch = phones[0].group().confirmed();
            phones[1].update(&mut home).unwrap();
            assert!(pass_with(&mut home, &mut phones[0], &[NOTES], Some(death)).is_err());
            restart(&mut phones[0]);
            let next = pass(&mut home, &mut phones[0]);
            assert!(
                next.pass.alarms.is_empty(),
                "{death:?}: {:?}",
                next.pass.alarms
            );
            pass(&mut home, &mut phones[1]);
            pass(&mut home, &mut phones[0]);
            for phone in phones.iter_mut() {
                assert_eq!(phone.group().confirmed(), epoch + 1, "{death:?}");
            }
        }
    }
}

/// A link that is not the onion's: the pass sends nothing.
#[test]
fn a_pass_over_the_clearnet_sends_nothing() {
    struct Clear<'a>(JobLink<'a>);
    impl Link for Clear<'_> {
        type Error = Killed;
        fn route(&self) -> Route {
            Route::Clearnet
        }
        fn push(
            &mut self,
            envelopes: &[Vec<u8>],
        ) -> Result<Vec<Result<Pushed, PersonalError>>, Killed> {
            self.0.push(envelopes)
        }
        fn since(&mut self, scope: Scope, position: u64) -> Answer<Vec<Envelope>, Killed> {
            self.0.since(scope, position)
        }
        fn wake(&mut self) -> Answer<Woken, Killed> {
            self.0.wake()
        }
        fn frontier(&mut self, device: u32) -> Answer<Frontier, Killed> {
            self.0.frontier(device)
        }
    }
    impl Control for Clear<'_> {
        fn log(&mut self, from: u64) -> Answer<Vec<(u64, Entry)>, Killed> {
            self.0.log(from)
        }
        fn overview(&mut self) -> Answer<Overview, Killed> {
            self.0.overview()
        }
        fn devices(&mut self) -> Answer<Vec<DeviceView>, Killed> {
            self.0.devices()
        }
        fn post(&mut self, post: &Post) -> Answer<u64, Killed> {
            self.0.post(post)
        }
    }
    let (mut home, mut phones) = household(2);
    let now = home.now();
    let mut link = Clear(JobLink::new(&mut home, &phones[0]));
    let Phone { light, group, .. } = &mut phones[0];
    let stopped = job::run(light, group.as_mut().unwrap(), &mut link, &[NOTES], now).unwrap_err();
    assert!(matches!(
        stopped.error,
        vos_light::personal::SyncError::Clearnet
    ));
    assert_eq!(link.0.requests, 0);
}

/// The kit's removal of phone 1, open, which phone 0 has yet to read: the
/// household and the operation's index.
fn kit_removal() -> (Home, Vec<Phone>, u64) {
    let (mut home, phones) = household(2);
    let kit = super::phone::kit(0);
    let index = operate(&mut home, &kit, &kit, "remove", 1u32.encode(), None);
    (home, phones, index)
}

/// J1 (§8 B3, B4, B19): an alarm is kept from the batch that consumed its
/// evidence. A pass killed before or after any of its requests, its
/// process dead with what it found, leaves the kit's operation's alarm to
/// the next pass, which reports it until the chrome acknowledges it.
#[test]
fn an_alarm_survives_a_killed_pass() {
    let requests = {
        let (mut home, mut phones, _) = kit_removal();
        pass(&mut home, &mut phones[0]).requests
    };
    for n in 0..requests {
        for death in [Death::Before(n), Death::After(n)] {
            let (mut home, mut phones, index) = kit_removal();
            let _dead = pass_with(&mut home, &mut phones[0], &[NOTES], Some(death));
            restart(&mut phones[0]);
            let next = pass(&mut home, &mut phones[0]);
            assert!(
                next.pass.alarms.contains(&Alarm::Kit { index }),
                "{death:?}: {:?}",
                next.pass.alarms
            );
        }
    }
    let (mut home, mut phones, index) = kit_removal();
    let first = pass(&mut home, &mut phones[0]);
    assert!(first.pass.alarms.contains(&Alarm::Kit { index }));
    let again = pass(&mut home, &mut phones[0]);
    assert!(again.pass.alarms.contains(&Alarm::Kit { index }), "kept");
    phones[0].group().acknowledge(&again.pass.alarms).unwrap();
    let after = pass(&mut home, &mut phones[0]);
    assert!(after.pass.alarms.is_empty(), "{:?}", after.pass.alarms);
}

/// C3: the operators serve a stale envelope, then fail the next request.
/// The stopped pass reports the alarm the page raised, and so does the
/// next pass, though its reading starts past the envelope.
#[test]
fn an_alarm_outlives_the_request_failed_after_it() {
    let (mut home, mut phones) = household(2);
    let scope = scope_of(&phones[0], NOTES);
    let old = phones[0].group().confirmed();
    let old_key = phones[0].group().key(scope).unwrap();
    phones[1].update(&mut home).unwrap();
    settle(&mut home, &mut phones);
    set(&phones[0].light, NOTES, 1, 10);
    with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    let bytes = super::detection::sealed_by(&phones[0], NOTES, &old_key, old, 7, |_| {});
    let position = stored(&home, &phones[1], scope).len() as u64 + 1;
    let stale = Alarm::Stale { scope, position };
    let now = home.now();
    let mut link = JobLink::new(&mut home, &phones[1]);
    link.placed = Some((
        scope,
        Envelope {
            position,
            id: vos_wire::personal::envelope_id(&bytes),
            bytes,
        },
    ));
    let Phone { light, group, .. } = &mut phones[1];
    let stopped = job::run(light, group.as_mut().unwrap(), &mut link, &[NOTES], now)
        .expect_err("the request after the page fails");
    assert!(
        stopped.pass.alarms.contains(&stale),
        "{:?}",
        stopped.pass.alarms
    );
    restart(&mut phones[1]);
    let next = pass(&mut home, &mut phones[1]);
    assert!(next.pass.alarms.contains(&stale), "{:?}", next.pass.alarms);
}

/// The name of `Personal`'s method `id`, as the world calls it.
fn named(id: vos_abi::ids::MethodId) -> &'static str {
    vos_wire::personal::method::ALL
        .iter()
        .find(|(_, method)| *method == id)
        .map(|(name, _)| *name)
        .expect("a method of `Personal`")
}
