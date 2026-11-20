//! Sealed sync through a node's socket and the onion's mark
//! (`light-node.md` §3.6): two phones' light nodes, one device group at a
//! personal agent on a node, one phone writing a mebibyte into a local
//! actor's scope and pushing it sealed, the other catching it up from its
//! cursor, every envelope opened and its node applied through the merge
//! entry. PG6's 1 MiB catch-up in its clearnet form, timed: run in release
//! for the gate's numbers, `VOS_CATCH_UP_ROUNDS` catch-ups of each shape
//! (one by default).

use std::time::{Duration, Instant};

use ed25519_dalek::Signer as _;
use vos_light::group::{Agent, DeviceGroup, Event};
use vos_light::personal::{Answer, Frontier, Link, SealedSync};
use vos_light::release::{self, Package};
use vos_light::route::Route;
use vos_light::{Config, Light};
use vos_testkit::programs;
use vos_wire::personal::{
    Candidacy, Entry, Envelope, PersonalError, Policy, Pushed, Recorded, Scope, Vote, Voted, Woken,
};

use super::personal::{Keys, PERSONAL, Personal, Signer, kit, method, outcome};
use super::*;

/// A phone: its light node, its device group and its keys' sessions.
struct Phone {
    light: Light,
    group: Option<DeviceGroup>,
    keys: Keys,
    sync: Signer,
    admin: Signer,
    _dir: tempfile::TempDir,
}

impl Phone {
    fn new(personal: &Personal, seed: u8, agent: &[u8]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let light = Light::open(dir.path(), agent, Config::default()).unwrap();
        // The sync key is the light node's: its scopes' author.
        let keys = Keys {
            sync: light.sync_key().clone(),
            ..Keys::of(seed)
        };
        Self {
            light,
            group: None,
            sync: personal.signer(&keys.sync, seed),
            admin: personal.signer(&keys.admin, seed ^ 0x80),
            keys,
            _dir: dir,
        }
    }

    fn group(&mut self) -> &mut DeviceGroup {
        self.group.as_mut().expect("a device group")
    }
}

/// The link to the agent through the node's socket, every request marked
/// as the gateway marks one its onion received: a push a call under the
/// phone's sync key in its session, a read a query under it.
struct Socket<'a> {
    personal: &'a mut Personal,
    sync: &'a mut Signer,
    key: SigningKey,
}

impl Link for Socket<'_> {
    type Error = std::convert::Infallible;

    fn route(&self) -> Route {
        Route::Onion
    }

    fn push(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, Self::Error> {
        Ok(envelopes
            .iter()
            .map(|envelope| outcome(self.personal.call(self.sync, "push", envelope.encode()).1))
            .collect())
    }

    fn since(
        &mut self,
        scope: Scope,
        position: u64,
    ) -> Result<Result<Vec<Envelope>, PersonalError>, Self::Error> {
        Ok(self.personal.query(&self.key, "since", (scope, position)))
    }

    fn wake(&mut self) -> Result<Result<Woken, PersonalError>, Self::Error> {
        Ok(outcome(self.personal.call(self.sync, "wake", Vec::new()).1))
    }

    fn frontier(&mut self, device: u32) -> Answer<Frontier, Self::Error> {
        Ok(self.personal.query(&self.key, "frontier", device))
    }
}

/// Run `f` with `phone`'s sealed sync of `instance` through the socket.
fn sealed<T>(
    personal: &mut Personal,
    phone: &mut Phone,
    instance: InstanceId,
    f: impl FnOnce(&mut SealedSync<'_, Socket<'_>>) -> T,
) -> T {
    let Phone {
        light,
        group,
        keys,
        sync,
        ..
    } = phone;
    let mut socket = Socket {
        personal,
        sync,
        key: keys.sync.clone(),
    };
    let mut sync =
        SealedSync::new(light, group.as_mut().unwrap(), &mut socket, vec![instance]).unwrap();
    f(&mut sync)
}

/// The control log from `from` to its head, read as `key`.
fn log(personal: &mut Personal, key: &SigningKey, from: u64) -> Vec<(u64, Entry)> {
    let mut entries = Vec::new();
    let mut next = from;
    loop {
        let page: Vec<(u64, Entry)> = personal.query(key, "log", next).unwrap();
        let Some((last, _)) = page.last() else {
            return entries;
        };
        next = last + 1;
        entries.extend(page);
    }
}

/// Read the log and act on it, posting every vote and evidence it asks
/// for, until it asks for none.
fn read(personal: &mut Personal, phone: &mut Phone) {
    for _ in 0..8 {
        let cursor = phone.group().cursor();
        let entries = log(personal, &phone.keys.sync, cursor);
        let events = phone.group().follow(entries).unwrap();
        let mut posted = false;
        for event in events {
            let at = match event {
                Event::Vote {
                    epoch,
                    vote,
                    message,
                } => {
                    let signature = phone.keys.sync.sign(&message).to_bytes();
                    let arguments = match vote {
                        Vote::Confirm(h) => ("confirm", (epoch, h, signature).encode()),
                        Vote::Nack => ("nack", (epoch, signature).encode()),
                    };
                    let answer = personal.call(&mut phone.sync, arguments.0, arguments.1).1;
                    outcome::<Voted>(answer).unwrap().at
                }
                Event::Evidence {
                    index,
                    message,
                    signature,
                    attached,
                } => {
                    personal
                        .answer::<Recorded>(
                            &mut phone.sync,
                            "evidence",
                            ((index, message), (signature, attached)),
                        )
                        .unwrap()
                        .at
                }
                _ => continue,
            };
            phone.group().called(at);
            posted = true;
        }
        if !posted {
            return;
        }
    }
    panic!("the phone keeps posting");
}

/// The release artifacts: the default agent, linked, and the notes
/// actor's package.
fn artifacts() -> (Vec<u8>, Package) {
    let read = |path: std::path::PathBuf| std::fs::read(path).unwrap();
    let agent = release::agent(&read(programs::program_elf("vos-agent"))).unwrap();
    let notes = release::package(&read(programs::actor_elf("notes")), 1).unwrap();
    (agent, notes)
}

/// A home with room for the runs: its quotas past what they push.
fn roomy() -> Policy {
    Policy {
        bytes_new: 256 << 20,
        envelopes_per_day: 1 << 20,
        ..Policy::DEFAULT
    }
}

/// Two phones in one device group at a personal agent on the node: the
/// first claimed it, and paired the second, each step through the socket.
fn household(agent: &[u8]) -> (Personal, Phone, Phone) {
    let mut personal = Personal::start();
    let mut first = Phone::new(&personal, 51, agent);
    let mut second = Phone::new(&personal, 52, agent);
    personal.home("claim", (first.keys.device(), kit(), roomy()));
    let alive: Recorded = personal
        .admitted(&mut first.sync, "alive", Vec::new())
        .unwrap();
    let identity = Agent {
        identity: personal.identity,
        instance: PERSONAL,
    };
    first.group = Some(
        DeviceGroup::create(
            first.light.store(),
            identity,
            first.keys.device(),
            Vec::new(),
            alive.at,
        )
        .unwrap(),
    );
    first.group().called(alive.at);
    let now = personal.served.now();
    let package =
        DeviceGroup::key_package(second.light.store(), &second.keys.device(), now).unwrap();
    let (prepared, pairing) = first
        .group()
        .pair(second.keys.device(), package, now)
        .unwrap();
    second.group = Some(
        DeviceGroup::join(
            second.light.store(),
            second.keys.device(),
            pairing,
            Vec::new(),
        )
        .unwrap(),
    );
    let (call, answer) = personal.call(&mut first.admin, "commit", prepared.arguments());
    first
        .group()
        .signed_commit(call.message(&personal.identity), call.signature)
        .unwrap();
    let candidacy: Candidacy = outcome(answer).unwrap();
    let Event::Evidence {
        index,
        message,
        signature,
        attached,
    } = first.group().called_commit(candidacy.index).unwrap()
    else {
        unreachable!()
    };
    personal
        .answer::<Recorded>(
            &mut first.sync,
            "evidence",
            ((index, message), (signature, attached)),
        )
        .unwrap();
    read(&mut personal, &mut first);
    personal
        .admitted::<Recorded>(&mut second.sync, "alive", Vec::new())
        .unwrap();
    read(&mut personal, &mut second);
    assert_eq!(second.group().id(), Some(1));
    assert_eq!(second.group().confirmed(), 1);
    assert_eq!(first.group().confirmed(), 1);
    (personal, first, second)
}

fn quantile(times: &mut [Duration], q: usize) -> Duration {
    times.sort_unstable();
    times[(times.len() * q / 100).min(times.len() - 1)]
}

/// PG6's 1 MiB catch-up on the clearnet: a phone writes a mebibyte of
/// titles into a fresh scope, in small operations (1,000 bytes each) and in
/// the largest a call takes, and pushes them sealed; the other phone reads
/// the scope from its start, opening every envelope and applying its node.
/// The catch-up's time is the gate's (≤ 20 s at p50); the push's is
/// recorded beside it.
#[test]
fn a_mebibyte_catch_up_through_the_socket() {
    let rounds: usize = std::env::var("VOS_CATCH_UP_ROUNDS")
        .ok()
        .and_then(|rounds| rounds.parse().ok())
        .unwrap_or(1);
    let (agent, notes) = artifacts();
    let (mut personal, mut writer, mut reader) = household(&agent);
    let title = method("title");
    for (shape, len) in [
        ("small", 1000usize),
        ("large", vos_light::MAX_ARGUMENTS - 12),
    ] {
        let (mut catch_ups, mut pushes) = (Vec::new(), Vec::new());
        let mut read_bytes = 0;
        let mut envelopes = 0;
        for round in 0..rounds {
            let instance = InstanceId(100 + 16 * (len > 1000) as u32 + round as u32);
            for phone in [&mut writer, &mut reader] {
                let outcome = phone.light.install(instance, &notes, Vec::new()).unwrap();
                assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
                let scope = phone.light.scope_id(instance).unwrap().0;
                phone.group().key(scope).unwrap();
            }
            let operations = (1 << 20) / len + 1;
            for key in 0..operations as u64 {
                let text = format!("{key:08}").repeat(len / 8);
                let outcome = writer
                    .light
                    .call(instance, title, (key, text).encode())
                    .unwrap();
                assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
            }
            let started = Instant::now();
            let pushed = sealed(&mut personal, &mut writer, instance, |sync| {
                sync.push(instance)
            })
            .unwrap();
            pushes.push(started.elapsed());
            assert_eq!(pushed.pushed.len(), operations);
            let started = Instant::now();
            let caught = sealed(&mut personal, &mut reader, instance, |sync| {
                sync.catch_up(instance)
            })
            .unwrap();
            catch_ups.push(started.elapsed());
            assert!(caught.passed.is_empty() && caught.waiting.is_none());
            assert_eq!(caught.ingested.unwrap().applied.len(), operations);
            assert!(caught.bytes >= 1 << 20, "{} bytes", caught.bytes);
            read_bytes = caught.bytes;
            envelopes = caught.envelopes;
        }
        let p50 = quantile(&mut catch_ups, 50);
        eprintln!(
            "{shape}: {envelopes} envelopes, {read_bytes} bytes; the catch-up {p50:?} p50, {:?} \
             p95; the push {:?} p50, over {rounds} rounds",
            quantile(&mut catch_ups, 95),
            quantile(&mut pushes, 50),
        );
        assert!(p50 <= Duration::from_secs(20), "PG6's catch-up: {p50:?}");
    }
}
