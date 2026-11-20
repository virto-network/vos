//! Sealed sync (`light-node.md` §3.6) against `Personal` in a home: paired
//! phones' local actors syncing through sealed envelopes, each pushed
//! under the confirmed epoch and read by its cursor; and the §8 scenarios
//! naming it: a push resealed only after `StaleEpoch` (A8, A10), retries
//! deduplicated (A10), forged and replayed envelopes (B5), archives pushed
//! at confirmed epochs, chunked and merged, and archives that disagree
//! (C9), recovery envelopes under `R` (D1), and no request over the
//! clearnet (E17).

#[path = "../common/mod.rs"]
mod common;
#[allow(dead_code)]
#[path = "../group/home.rs"]
mod home;
#[allow(dead_code)]
#[path = "../group/phone.rs"]
mod phone;

mod kit;

use std::cell::Cell;
use std::rc::Rc;

use ed25519_dalek::SigningKey;
use vos_abi::ids::{InstanceId, MethodId};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_light::personal::{
    Answer, Frontier, Link, SealedSync, SyncError, Unusable, Waiting, open_recovery, recovery_key,
};
use vos_light::route::Route;
use vos_light::sealed::{self, OpenError};
use vos_light::{Error, Light, MAX_ARGUMENTS};
use vos_wire::personal::{Envelope, PersonalError, Policy, Pushed, RECOVERY, Scope, Woken};

use home::Home;
use phone::Phone;

mod detection;
mod job;
mod pairing;

const MIN: u64 = 60_000;
const NOTES: InstanceId = InstanceId(1);
const OTHER: InstanceId = InstanceId(2);

fn policy() -> Policy {
    Policy {
        operation_delay_ms: 10 * MIN,
        kit_delay_ms: 20 * MIN,
        probation_ms: 5 * MIN,
        seasoning_ms: 10 * MIN,
        confirm_window_ms: 30 * MIN,
        ..Policy::DEFAULT
    }
}

fn method(name: &str) -> MethodId {
    MethodId(vos_light::method_id(name))
}

fn install(light: &Light, instance: InstanceId) {
    let outcome = light
        .install(instance, common::notes(), Vec::new())
        .unwrap();
    assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
}

fn set(light: &Light, instance: InstanceId, key: u64, value: u64) {
    let outcome = light
        .call(instance, method("set"), (key, value).encode())
        .unwrap();
    assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
}

fn count(light: &Light, instance: InstanceId, key: u64) -> Option<u64> {
    let outcome = light
        .query(
            vos_abi::ids::Principal::Client([0xd1; 32]),
            instance,
            method("count"),
            key.encode(),
        )
        .unwrap();
    let Outcome::Done(bytes) = outcome else {
        panic!("{outcome:?}")
    };
    Option::<u64>::decode_exact(&bytes).unwrap()
}

/// How a link fails a push.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fail {
    /// The agent took the pushes, and their answers were lost.
    Lost,
    /// The pushes never reached the agent.
    Unreached,
}

/// The link to the home's agent, as a phone's sync key: a push a call, a
/// read a query; failing the next push as `fail` says.
struct HomeLink<'a> {
    home: &'a mut Home,
    sync: SigningKey,
    route: Rc<Cell<Route>>,
    fail: Option<Fail>,
    requests: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct Broken;

impl<'a> HomeLink<'a> {
    fn new(home: &'a mut Home, phone: &Phone) -> Self {
        Self {
            home,
            sync: phone.sync.clone(),
            route: Rc::new(Cell::new(Route::Onion)),
            fail: None,
            requests: 0,
        }
    }
}

impl Link for HomeLink<'_> {
    type Error = Broken;

    fn route(&self) -> Route {
        self.route.get()
    }

    fn push(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, Broken> {
        self.requests += 1;
        if self.fail == Some(Fail::Unreached) {
            self.fail = None;
            return Err(Broken);
        }
        let answers = envelopes
            .iter()
            .map(|envelope| {
                self.home
                    .call(&self.sync, "push", envelope.encode())
                    .answer::<Pushed>()
            })
            .collect();
        if self.fail.take() == Some(Fail::Lost) {
            return Err(Broken);
        }
        Ok(answers)
    }

    fn since(
        &mut self,
        scope: Scope,
        position: u64,
    ) -> Result<Result<Vec<Envelope>, PersonalError>, Broken> {
        self.requests += 1;
        let key = self.sync.verifying_key().to_bytes();
        Ok(self.home.query(key, "since", (scope, position).encode()))
    }

    fn wake(&mut self) -> Result<Result<Woken, PersonalError>, Broken> {
        self.requests += 1;
        Ok(self.home.call(&self.sync, "wake", ().encode()).answer())
    }

    fn frontier(&mut self, device: u32) -> Answer<Frontier, Broken> {
        self.requests += 1;
        let key = self.sync.verifying_key().to_bytes();
        Ok(self.home.query(key, "frontier", device.encode()))
    }
}

/// A home claimed by phone 1 and `count - 1` more phones paired and
/// confirmed, each past its probation, the notes actor installed on each
/// as [`NOTES`] and its scope tracked: its key archived at every confirmed
/// epoch from now.
fn household(count: u8) -> (Home, Vec<Phone>) {
    let mut home = Home::new(policy());
    let mut phones: Vec<Phone> = (1..=count).map(Phone::new).collect();
    phones[0].claim(&mut home);
    for n in 1..count as usize {
        let (paired, rest) = phones.split_at_mut(n);
        paired[0].pair(&mut home, &mut rest[0]);
        settle(&mut home, &mut phones[..=n]);
        phones[n].alive(&mut home);
    }
    home.pass(policy().probation_ms);
    for phone in &mut phones {
        phone.alive(&mut home);
        install(&phone.light, NOTES);
        let scope = scope_of(phone, NOTES);
        phone.group().key(scope).unwrap();
    }
    (home, phones)
}

/// Read every phone until none posts anything.
fn settle(home: &mut Home, phones: &mut [Phone]) {
    for _ in 0..4 {
        for phone in phones.iter_mut() {
            phone.read(home);
        }
    }
}

/// `phone` restarted: its light node and its device group reopened from
/// its store, as after its process's death.
fn restart(phone: &mut Phone) {
    let scratch = tempfile::tempdir().unwrap();
    let artifacts = common::agent();
    phone.group = None;
    let stand_in = Light::open(scratch.path(), artifacts, Default::default()).unwrap();
    phone.store = stand_in.store().clone();
    drop(std::mem::replace(&mut phone.light, stand_in));
    phone.light = Light::open(phone._dir.path(), artifacts, Default::default()).unwrap();
    phone.store = phone.light.store().clone();
    phone.group = vos_light::group::DeviceGroup::open(&phone.store).unwrap();
}

/// Run `f` with `phone`'s sealed sync of `instances` over `link`.
fn over<T>(
    link: &mut HomeLink<'_>,
    phone: &mut Phone,
    instances: &[InstanceId],
    f: impl FnOnce(&mut SealedSync<'_, HomeLink<'_>>) -> T,
) -> T {
    let Phone { light, group, .. } = phone;
    let mut sync =
        SealedSync::new(light, group.as_mut().unwrap(), link, instances.to_vec()).unwrap();
    f(&mut sync)
}

/// Run `f` with `phone`'s sealed sync of `instances` over the home.
fn with<T>(
    home: &mut Home,
    phone: &mut Phone,
    instances: &[InstanceId],
    f: impl FnOnce(&mut SealedSync<'_, HomeLink<'_>>) -> T,
) -> T {
    let mut link = HomeLink::new(home, phone);
    over(&mut link, phone, instances, f)
}

/// The envelopes of `scope` the agent holds, read as `phone`.
fn stored(home: &Home, phone: &Phone, scope: Scope) -> Vec<Envelope> {
    let mut all = Vec::new();
    loop {
        let after = all
            .last()
            .map_or(0, |envelope: &Envelope| envelope.position);
        let page: Vec<Envelope> = home
            .query(phone.sync_key(), "since", (scope, after).encode())
            .unwrap();
        if page.is_empty() {
            return all;
        }
        all.extend(page);
    }
}

fn scope_of(phone: &Phone, instance: InstanceId) -> Scope {
    phone.light.scope_id(instance).unwrap().0
}

/// Paired phones sync a local actor's scope both ways through sealed
/// envelopes: what one sets, the other reads after its catch-up; the agent
/// holds each node once, under the scope's opaque id and the confirmed
/// epoch, its bytes padded; each envelope carries its writer's view of the
/// control log and `seen` positions; and a read from the cursor again
/// brings nothing new.
#[test]
fn paired_phones_sync_sealed_scopes() {
    let (mut home, mut phones) = household(2);
    let epoch = phones[0].group().confirmed();
    for key in 0..5 {
        set(&phones[0].light, NOTES, key, key * 10);
    }
    let pushed = with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    assert_eq!(pushed.pushed.len(), 5);
    assert_eq!(pushed.stale, None);
    assert!(phones[0].light.queued(NOTES).unwrap().is_empty());
    assert!(phones[0].light.outbox(NOTES).unwrap().is_empty());

    let scope = scope_of(&phones[0], NOTES);
    assert_eq!(scope_of(&phones[1], NOTES), scope);
    let held = stored(&home, &phones[1], scope);
    assert_eq!(held.len(), 5);
    for envelope in &held {
        let header = sealed::header_of(&envelope.bytes).unwrap();
        assert_eq!((header.scope, header.epoch), (scope, epoch));
        let padded = envelope.bytes.len() - vos_wire::personal::Header::BYTES - sealed::TAG;
        assert_eq!(sealed::padme(padded), padded);
    }

    let caught = with(&mut home, &mut phones[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(caught.envelopes, 5);
    assert_eq!(caught.ingested.as_ref().unwrap().applied.len(), 5);
    assert!(caught.passed.is_empty() && caught.waiting.is_none());
    assert!(caught.alarms.is_empty(), "{:?}", caught.alarms);
    let view = phones[0].group().view();
    for heard in &caught.heard {
        assert_eq!((heard.view.index, heard.view.chain), view);
        assert_eq!(heard.seen, vec![(scope, 0)]);
    }
    for key in 0..5 {
        assert_eq!(count(&phones[1].light, NOTES, key), Some(key * 10));
    }
    assert_eq!(phones[1].light.cursor(NOTES).unwrap(), Some(5));

    set(&phones[1].light, NOTES, 7, 70);
    with(&mut home, &mut phones[1], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    let caught = with(&mut home, &mut phones[0], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(caught.envelopes, 6, "its own five read back");
    assert!(caught.alarms.is_empty(), "{:?}", caught.alarms);
    assert_eq!(caught.ingested.as_ref().unwrap().duplicates, 5);
    assert_eq!(caught.heard[5].seen, vec![(scope, 5)]);
    assert_eq!(count(&phones[0].light, NOTES, 7), Some(70));
    let again = with(&mut home, &mut phones[0], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(again.envelopes, 0);
}

/// A8 and A10: a node is sealed when it is pushed, under the confirmed
/// epoch, and its sealed bytes are queued before they are sent. An answer
/// lost after the agent took them is retried with the same bytes, after a
/// restart too, and the agent answers them by id: one envelope. Bytes
/// sealed under an epoch since replaced are resealed only after the
/// agent's `StaleEpoch`; a push that meets an epoch this device has not
/// confirmed stops for the log, and once the device follows it the node is
/// sealed under the new epoch, which the old epoch's key does not open.
#[test]
fn pushes_are_sealed_at_push_and_resealed_only_after_stale_epoch() {
    let (mut home, mut phones) = household(2);
    let first = phones[0].group().confirmed();
    let scope = scope_of(&phones[0], NOTES);
    set(&phones[0].light, NOTES, 1, 1);
    let mut link = HomeLink::new(&mut home, &phones[0]);
    link.fail = Some(Fail::Lost);
    let lost = over(&mut link, &mut phones[0], &[NOTES], |sync| sync.push(NOTES));
    assert!(matches!(lost, Err(SyncError::Link(Broken))));
    let queued = phones[0].light.queued(NOTES).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].1.epoch, first);
    restart(&mut phones[0]);
    assert_eq!(phones[0].light.queued(NOTES).unwrap(), queued);
    let pushed = with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    assert_eq!(pushed.pushed[0].1.position, 1);
    let held = stored(&home, &phones[0], scope);
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].bytes, queued[0].1.envelope);

    // Sealed under the first epoch and never sent; the other phone commits
    // an update, which this phone confirms with it.
    set(&phones[0].light, NOTES, 2, 2);
    let mut link = HomeLink::new(&mut home, &phones[0]);
    link.fail = Some(Fail::Unreached);
    assert!(over(&mut link, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).is_err());
    phones[1].update(&mut home).unwrap();
    settle(&mut home, &mut phones);
    let second = phones[0].group().confirmed();
    assert_eq!(second, first + 1);
    assert_eq!(phones[0].light.queued(NOTES).unwrap()[0].1.epoch, first);
    let pushed = with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    assert_eq!(pushed.pushed.len(), 1);
    let held = stored(&home, &phones[0], scope);
    assert_eq!(sealed::header_of(&held[1].bytes).unwrap().epoch, second);

    // This phone sleeps through the next epoch, which the other confirms
    // alone: its push meets an epoch it has not confirmed, and stops.
    home.pass(policy().confirm_window_ms + 1);
    phones[1].alive(&mut home);
    let old = phones[0].group().key(scope).unwrap();
    set(&phones[0].light, NOTES, 3, 3);
    let mut link = HomeLink::new(&mut home, &phones[0]);
    link.fail = Some(Fail::Unreached);
    assert!(over(&mut link, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).is_err());
    phones[1].update(&mut home).unwrap();
    phones[1].read(&mut home);
    let third = phones[1].group().confirmed();
    assert_eq!(third, second + 1);
    let stale = with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    assert_eq!((stale.pushed.len(), stale.stale), (0, Some(third)));
    phones[0].read(&mut home);
    assert_eq!(phones[0].group().confirmed(), third);
    let pushed = with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    assert_eq!(pushed.pushed.len(), 1);
    let held = stored(&home, &phones[0], scope);
    let last = &held[2].bytes;
    assert_eq!(sealed::header_of(last).unwrap().epoch, third);
    assert_eq!(
        sealed::open(&[old], &home::IDENTITY, last).map(|_| ()),
        Err(OpenError::Unopened),
        "a device holding only the earlier epoch's key reads nothing of it"
    );

    let caught = with(&mut home, &mut phones[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(caught.ingested.unwrap().applied.len(), 3);
    for key in 1..=3 {
        assert_eq!(count(&phones[1].light, NOTES, key), Some(key));
    }
}

/// B5: an envelope the operators inject does not open, or opens to no
/// node, and is passed over; a replay is the same envelope, answered by
/// id; the reading goes on past them.
#[test]
fn forged_and_replayed_envelopes_are_passed_over() {
    let (mut home, mut phones) = household(2);
    let epoch = phones[0].group().confirmed();
    let scope = scope_of(&phones[0], NOTES);
    set(&phones[0].light, NOTES, 1, 1);
    with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    let key = phones[0].group().key(scope).unwrap();
    let sync = phones[0].sync.clone();
    let push = |home: &mut Home, envelope: &Vec<u8>| {
        home.call(&sync, "push", envelope.encode())
            .answer::<Pushed>()
            .unwrap()
            .position
    };
    let forged = sealed::seal(&[9; 32], &home::IDENTITY, scope, epoch, b"forged").unwrap();
    let elsewhere = sealed::seal(&key, &[0; 32], scope, epoch, b"another agent's").unwrap();
    let junk = sealed::seal(&key, &home::IDENTITY, scope, epoch, b"no node").unwrap();
    assert_eq!(push(&mut home, &forged), 2);
    assert_eq!(push(&mut home, &elsewhere), 3);
    assert_eq!(push(&mut home, &junk), 4);
    let first = stored(&home, &phones[0], scope)[0].bytes.clone();
    assert_eq!(push(&mut home, &first), 1, "a replay is a duplicate");
    set(&phones[0].light, NOTES, 2, 2);
    with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();

    let caught = with(&mut home, &mut phones[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    let passed: Vec<(u64, Unusable)> = caught
        .passed
        .iter()
        .map(|passed| (passed.position, passed.why))
        .collect();
    assert_eq!(
        passed,
        vec![
            (2, Unusable::Opened(OpenError::Unopened)),
            (3, Unusable::Opened(OpenError::Unopened)),
            (4, Unusable::Body),
        ]
    );
    assert_eq!(caught.ingested.unwrap().applied.len(), 2);
    assert_eq!(phones[1].light.cursor(NOTES).unwrap(), Some(5));
    assert_eq!(count(&phones[1].light, NOTES, 2), Some(2));
}

/// The archive at confirmed epochs, and C9: a phone that tracks a scope
/// the other does not seals under keys the other never derived; the
/// other's reading waits for the key, until the first phone's archive,
/// pushed at the confirmed epoch and chunked past an envelope, is merged.
/// A device that finds its whole archive there pushes none. An archive
/// with a wrong candidate key beside the right one opens all the same: the
/// AEAD decides.
#[test]
fn archives_are_pushed_at_confirmed_epochs_and_merged() {
    let (mut home, mut phones) = household(2);
    let first = phones[0].group().confirmed();
    install(&phones[0].light, OTHER);
    set(&phones[0].light, OTHER, 1, 11);
    with(&mut home, &mut phones[0], &[OTHER], |sync| sync.push(OTHER)).unwrap();
    phones[0].update(&mut home).unwrap();
    settle(&mut home, &mut phones);
    let second = phones[0].group().confirmed();
    assert_eq!(second, first + 1);

    install(&phones[1].light, OTHER);
    let other = scope_of(&phones[1], OTHER);
    let caught = with(&mut home, &mut phones[1], &[OTHER], |sync| {
        sync.catch_up(OTHER)
    })
    .unwrap();
    assert_eq!(caught.waiting, Some(Waiting::Key(first)));
    assert_eq!(caught.envelopes, 0);
    assert_eq!(phones[1].light.cursor(OTHER).unwrap(), None);

    // A large archive: many scopes' keys, past one envelope.
    let mut large = phones[0].group().archive().clone();
    for n in 0..1500u32 {
        let mut scope = [0x5c; 16];
        scope[..4].copy_from_slice(&n.to_be_bytes());
        large.record(first, scope, [n as u8; 32]);
    }
    phones[0].group().merge_archive(&large).unwrap();
    let kept = with(&mut home, &mut phones[0], &[], |sync| sync.archive()).unwrap();
    assert_eq!((kept.found, kept.stale), (0, None));
    assert!(kept.pushed >= 2, "chunked: {kept:?}");
    let again = with(&mut home, &mut phones[0], &[], |sync| sync.archive()).unwrap();
    assert_eq!(
        (again.found, again.pushed),
        (1, 0),
        "its own read back, none pushed"
    );
    let again = with(&mut home, &mut phones[0], &[], |sync| sync.archive()).unwrap();
    assert_eq!((again.found, again.pushed), (0, 0));

    // A wrong candidate for the key, then the real one beside it.
    let mut wrong = phones[1].group().archive().clone();
    wrong.record(first, other, [0xee; 32]);
    phones[1].group().merge_archive(&wrong).unwrap();
    let kept = with(&mut home, &mut phones[1], &[], |sync| sync.archive()).unwrap();
    assert_eq!(kept.found, 1);
    assert!(
        kept.pushed > 0,
        "it holds a candidate the agent's archive lacks"
    );
    assert_eq!(phones[1].group().archive().keys(first, &other).len(), 2);
    let caught = with(&mut home, &mut phones[1], &[OTHER], |sync| {
        sync.catch_up(OTHER)
    })
    .unwrap();
    assert_eq!(caught.ingested.unwrap().applied.len(), 1);
    assert_eq!(count(&phones[1].light, OTHER, 1), Some(11));
    let mut probe = [0x5c; 16];
    probe[..4].copy_from_slice(&1499u32.to_be_bytes());
    assert_eq!(
        phones[1].group().archive().keys(first, &probe),
        &[[0xdb; 32]]
    );

    // An archive the agent holds under an epoch since replaced opens to no
    // device: the next epoch's is pushed by the first to read.
    phones[1].update(&mut home).unwrap();
    settle(&mut home, &mut phones);
    let kept = with(&mut home, &mut phones[1], &[], |sync| sync.archive()).unwrap();
    assert_eq!((kept.found, kept.pushed > 0), (0, true));
    let kept = with(&mut home, &mut phones[0], &[], |sync| sync.archive()).unwrap();
    assert_eq!((kept.found, kept.pushed), (1, 0));
}

/// C9's other order: the device lacking a key pushes the epoch's archive
/// first; the device holding it finds that archive short of its keys and
/// pushes its own, which the first then merges. An `R` the log did not
/// name travels through the agent to no other device.
#[test]
fn a_device_holding_keys_the_agents_archive_lacks_pushes_its_own() {
    let (mut home, mut phones) = household(2);
    let first = phones[0].group().confirmed();
    let claimed = phones[1].group().archive().recovery.clone().unwrap();
    phones[0].group().set_recovery(5, [0x52; 32]).unwrap();
    install(&phones[0].light, OTHER);
    set(&phones[0].light, OTHER, 1, 11);
    with(&mut home, &mut phones[0], &[OTHER], |sync| sync.push(OTHER)).unwrap();
    phones[1].update(&mut home).unwrap();
    settle(&mut home, &mut phones);
    let kept = with(&mut home, &mut phones[1], &[], |sync| sync.archive()).unwrap();
    assert_eq!((kept.found, kept.pushed), (0, 1));
    let kept = with(&mut home, &mut phones[0], &[], |sync| sync.archive()).unwrap();
    assert_eq!((kept.found, kept.pushed), (1, 1));
    let kept = with(&mut home, &mut phones[1], &[], |sync| sync.archive()).unwrap();
    assert_eq!(
        (kept.found, kept.pushed),
        (2, 1),
        "its own and the other's, and its own again: the other's holds an R it does not take"
    );
    let other = scope_of(&phones[0], OTHER);
    assert!(!phones[1].group().archive().keys(first, &other).is_empty());
    assert!(
        phones[1].group().archive().recovery == Some(claimed),
        "the claim's R stands"
    );
    install(&phones[1].light, OTHER);
    let caught = with(&mut home, &mut phones[1], &[OTHER], |sync| {
        sync.catch_up(OTHER)
    })
    .unwrap();
    assert_eq!(caught.ingested.unwrap().applied.len(), 1);
}

/// A catch-up longer than one answer reads it page after page, each
/// page's position stored with its nodes.
#[test]
fn a_catch_up_reads_page_after_page() {
    let (mut home, mut phones) = household(2);
    for key in 0..40u64 {
        let outcome = phones[0]
            .light
            .call(NOTES, method("title"), (key, "x".repeat(2000)).encode())
            .unwrap();
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
    }
    with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    let caught = with(&mut home, &mut phones[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.bytes > vos_wire::personal::ANSWER_BYTES);
    assert!(caught.alarms.is_empty(), "{:?}", caught.alarms);
    assert_eq!(caught.ingested.unwrap().applied.len(), 40);
    assert_eq!(phones[1].light.cursor(NOTES).unwrap(), Some(40));
}

/// D1's envelopes: once a device holds `R`, the claim's, what the agent
/// holds under it is kept whole: the naming secret and every scope key,
/// pushed as the device's archive gains them (a confirmed epoch's keys, a
/// scope tracked mid-epoch), each push only what the recovery scope lacks.
/// A kit holding `R` reads the scope and merges it; another `R` opens
/// nothing; a new `R` reads the scope again and seals the whole archive
/// under it.
#[test]
fn recovery_envelopes_keep_every_key_under_r() {
    let (mut home, mut phones) = household(2);
    let epoch = phones[0].group().confirmed();
    let r = phones[0].group().archive().recovery.as_ref().unwrap().r;
    assert_eq!(phones[1].group().archive().recovery.as_ref().unwrap().r, r);
    let scope = scope_of(&phones[0], NOTES);
    let key = phones[0].group().key(scope).unwrap();
    let kept = with(&mut home, &mut phones[0], &[], |sync| sync.recovery()).unwrap();
    assert_eq!((kept.found, kept.pushed), (0, 1));
    let kept = with(&mut home, &mut phones[0], &[], |sync| sync.recovery()).unwrap();
    assert_eq!((kept.found, kept.pushed), (1, 0));
    let kept = with(&mut home, &mut phones[1], &[], |sync| sync.recovery()).unwrap();
    assert_eq!((kept.found, kept.pushed), (1, 0));

    let kit = phone::kit(0).verifying_key().to_bytes();
    let read = |home: &Home| -> Vec<Envelope> {
        home.query(kit, "since", (RECOVERY, 0u64).encode()).unwrap()
    };
    let recovered = open_recovery(&r, &home::IDENTITY, &read(&home)).unwrap();
    assert_eq!(recovered.naming, phones[0].group().archive().naming);
    assert_eq!(recovered.keys(epoch, &scope), &[key]);
    assert!(recovered.recovery.is_none());
    assert!(open_recovery(&[0x53; 32], &home::IDENTITY, &read(&home)).is_none());
    assert_ne!(*recovery_key(&r), r);

    // A scope tracked mid-epoch, then the next epoch's keys.
    install(&phones[0].light, OTHER);
    let other = scope_of(&phones[0], OTHER);
    let other_key = phones[0].group().key(other).unwrap();
    let kept = with(&mut home, &mut phones[0], &[], |sync| sync.recovery()).unwrap();
    assert_eq!((kept.found, kept.pushed), (0, 1));
    phones[0].update(&mut home).unwrap();
    settle(&mut home, &mut phones);
    let kept = with(&mut home, &mut phones[1], &[], |sync| sync.recovery()).unwrap();
    assert_eq!(kept.pushed, 1);
    let recovered = open_recovery(&r, &home::IDENTITY, &read(&home)).unwrap();
    assert_eq!(recovered.keys(epoch, &other), &[other_key]);
    assert_eq!(
        recovered.keys(epoch + 1, &scope),
        &[phones[1].group().key(scope).unwrap()]
    );

    // A rotation's new `R`: the whole archive again, under it.
    let rotated = [0x54; 32];
    phones[0].group().set_recovery(7, rotated).unwrap();
    let kept = with(&mut home, &mut phones[0], &[], |sync| sync.recovery()).unwrap();
    assert_eq!((kept.found, kept.pushed), (0, 1));
    let recovered = open_recovery(&rotated, &home::IDENTITY, &read(&home)).unwrap();
    assert_eq!(recovered.keys(epoch, &scope), &[key]);
}

/// E17: the personal agent is reached through the onion alone. A link
/// over the clearnet is refused before any request leaves, and so is every
/// request once a link's route is the clearnet.
#[test]
fn the_personal_agent_is_reached_through_the_onion_alone() {
    let (mut home, mut phones) = household(2);
    set(&phones[0].light, NOTES, 1, 1);
    let mut link = HomeLink::new(&mut home, &phones[0]);
    link.route.set(Route::Clearnet);
    let Phone { light, group, .. } = &mut phones[0];
    let refused = SealedSync::new(light, group.as_mut().unwrap(), &mut link, vec![NOTES]);
    assert!(matches!(refused, Err(SyncError::Clearnet)));
    link.route.set(Route::Onion);
    let route = Rc::clone(&link.route);
    let mut sync = SealedSync::new(light, group.as_mut().unwrap(), &mut link, vec![NOTES]).unwrap();
    // The route the link reports moves under the sync.
    route.set(Route::Clearnet);
    assert!(matches!(sync.push(NOTES), Err(SyncError::Clearnet)));
    assert!(matches!(sync.catch_up(NOTES), Err(SyncError::Clearnet)));
    assert!(matches!(sync.archive(), Err(SyncError::Clearnet)));
    drop(sync);
    assert_eq!(link.requests, 0);
    assert_eq!(phones[0].light.outbox(NOTES).unwrap().len(), 1);
}

/// A call's arguments are bounded so that its node always fits an
/// envelope: the largest is sealed and pushed, one byte more is refused
/// before anything is recorded.
#[test]
fn the_largest_call_fits_an_envelope() {
    let (mut home, mut phones) = household(2);
    let title = "t".repeat(MAX_ARGUMENTS - 8 - 4);
    let arguments = (1u64, title).encode();
    assert_eq!(arguments.len(), MAX_ARGUMENTS);
    let outcome = phones[0]
        .light
        .call(NOTES, method("title"), arguments)
        .unwrap();
    assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
    assert!(matches!(
        phones[0]
            .light
            .call(NOTES, method("title"), vec![0; MAX_ARGUMENTS + 1]),
        Err(Error::TooLarge)
    ));
    let pushed = with(&mut home, &mut phones[0], &[NOTES], |sync| sync.push(NOTES)).unwrap();
    assert_eq!(pushed.pushed.len(), 1);
    let caught = with(&mut home, &mut phones[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(caught.ingested.unwrap().applied.len(), 1);
}
