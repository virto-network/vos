//! The model test of detection (`light-node.md` §8): two devices of one
//! group and a hostile agent, which shows each device what it likes of the
//! control log and of each scope, answers calls it never logs, and places
//! envelopes it should have refused. Each scenario is detected or refused
//! as §8 says: a rollback (B3); equivocation on commits and on operations
//! (B4); a partition (B19); a dropped veto (B8); a forged operation (B6);
//! a stale-epoch push (A8, B8); and a backdated envelope (A7); beside the
//! sample audit of a device's own pushes (B2).

use ed25519_dalek::SigningKey;
use vos_abi::Encode;
use vos_abi::ids::InstanceId;
use vos_light::group::{Alarm, DeviceGroup, Event};
use vos_light::personal::{Answer, Frontier, Link, SealedSync, Unusable, Waiting};
use vos_light::route::Route;
use vos_light::sealed::{self, Body as Sealed, View};
use vos_light::sync::Quarantine;
use vos_wire::personal::{
    AdminCall, Attached, Body, Entry, Op, OpState, Overview, PersonalError, Pushed, Recorded,
    Scope, Signer, Woken, chain,
};

use super::home::{self, Home};
use super::phone::{Phone, kit_key};
use super::{
    Broken, HomeLink, MIN, NOTES, OTHER, count, household, install, policy, scope_of, set, settle,
    stored, with,
};

/// The link to a hostile agent: what `serve` makes of each scope's
/// envelopes as the agent holds them is what this device is shown;
/// everything else goes to the home.
struct Shown<'a> {
    link: HomeLink<'a>,
    serve: Box<
        dyn FnMut(Scope, Vec<vos_wire::personal::Envelope>) -> Vec<vos_wire::personal::Envelope>
            + 'a,
    >,
}

impl Link for Shown<'_> {
    type Error = Broken;

    fn route(&self) -> Route {
        Route::Onion
    }

    fn push(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, Broken> {
        self.link.push(envelopes)
    }

    fn since(
        &mut self,
        scope: Scope,
        position: u64,
    ) -> Result<Result<Vec<vos_wire::personal::Envelope>, PersonalError>, Broken> {
        let key = self.link.sync.verifying_key().to_bytes();
        let held = all_of(self.link.home, key, scope);
        Ok(Ok((self.serve)(scope, held)
            .into_iter()
            .filter(|envelope| envelope.position > position)
            .collect()))
    }

    fn wake(&mut self) -> Result<Result<Woken, PersonalError>, Broken> {
        self.link.wake()
    }

    fn frontier(&mut self, device: u32) -> Answer<Frontier, Broken> {
        self.link.frontier(device)
    }
}

/// Every envelope of `scope` the agent holds, read as `key`.
fn all_of(home: &Home, key: [u8; 32], scope: Scope) -> Vec<vos_wire::personal::Envelope> {
    let mut all: Vec<vos_wire::personal::Envelope> = Vec::new();
    loop {
        let after = all.last().map_or(0, |envelope| envelope.position);
        let page: Vec<vos_wire::personal::Envelope> =
            home.query(key, "since", (scope, after).encode()).unwrap();
        if page.is_empty() {
            return all;
        }
        all.extend(page);
    }
}

/// Run `f` with `phone`'s sealed sync of `instances`, each scope shown as
/// `serve` makes it.
fn shown<T>(
    home: &mut Home,
    phone: &mut Phone,
    instances: &[InstanceId],
    serve: impl FnMut(Scope, Vec<vos_wire::personal::Envelope>) -> Vec<vos_wire::personal::Envelope>,
    f: impl FnOnce(&mut SealedSync<'_, Shown<'_>>) -> T,
) -> T {
    let mut link = Shown {
        link: HomeLink::new(home, phone),
        serve: Box::new(serve),
    };
    let Phone { light, group, .. } = phone;
    let mut sync = SealedSync::new(
        light,
        group.as_mut().unwrap(),
        &mut link,
        instances.to_vec(),
    )
    .unwrap();
    f(&mut sync)
}

/// `entries` with each index renumbered from 0 and each chain linked
/// again: a log the operators show.
fn relink(entries: Vec<(u64, Entry)>) -> Vec<(u64, Entry)> {
    let mut before = [0; 32];
    entries
        .into_iter()
        .enumerate()
        .map(|(index, (_, mut entry))| {
            let index = index as u64;
            entry.chain = chain(&before, index, entry.at, &entry.body);
            before = entry.chain;
            (index, entry)
        })
        .collect()
}

/// The control log as `phone` is shown it: the agent's, `edit` applied,
/// linked again.
fn shown_log(
    home: &Home,
    phone: &Phone,
    edit: impl FnOnce(&mut Vec<(u64, Entry)>),
) -> Vec<(u64, Entry)> {
    let mut entries = home.log(phone.sync_key(), 0).unwrap();
    edit(&mut entries);
    relink(entries)
}

/// `phone` reading `entries`, the log as it is shown, posting what it is
/// asked to post, then checking the head they end at: every other event.
fn follow_shown(home: &mut Home, phone: &mut Phone, entries: Vec<(u64, Entry)>) -> Vec<Event> {
    let head = entries
        .last()
        .map_or((0, [0; 32]), |(index, entry)| (index + 1, entry.chain));
    let cursor = phone.group().cursor();
    let fresh = entries.into_iter().filter(|(index, _)| *index >= cursor);
    let mut seen = Vec::new();
    for event in phone.group().follow(fresh).unwrap() {
        match event {
            Event::Vote {
                epoch,
                vote,
                message,
            } => phone.vote(home, epoch, vote, &message),
            Event::Evidence {
                index,
                message,
                signature,
                attached,
            } => phone.evidence(home, index, message, signature, attached),
            other => seen.push(other),
        }
    }
    let alarms = phone.group().head(head.0, head.1).unwrap();
    seen.extend(alarms.into_iter().map(Event::Alarm));
    seen
}

/// `phone` reading the agent's log, then checking the agent's head.
fn read(home: &mut Home, phone: &mut Phone) -> Vec<Event> {
    let mut events = phone.read(home);
    let overview: Overview = home
        .query(phone.sync_key(), "overview", ().encode())
        .unwrap();
    let alarms = phone.group().head(overview.next, overview.chain).unwrap();
    events.extend(alarms.into_iter().map(Event::Alarm));
    events
}

fn alarmed(events: &[Event], alarm: Alarm) -> bool {
    events.contains(&Event::Alarm(alarm))
}

/// `signer`'s admin call of `name` with `arguments`, its evidence posted
/// under `poster`: its log index.
fn operate(
    home: &mut Home,
    signer: &SigningKey,
    poster: &SigningKey,
    name: &str,
    arguments: Vec<u8>,
    r2: Option<[u8; 32]>,
) -> u64 {
    let reply = home.call(signer, name, arguments);
    let index = reply.answer::<Recorded>().unwrap().index;
    let attached = Attached { welcome: None, r2 };
    home.call(
        poster,
        "evidence",
        ((index, reply.message), (reply.signature, attached)).encode(),
    )
    .answer::<Recorded>()
    .unwrap();
    index
}

/// Wake the agent as `key` until nothing is left due.
fn woken(home: &mut Home, key: &SigningKey) {
    loop {
        let woken: Woken = home.call(key, "wake", ().encode()).answer().unwrap();
        if woken.settled {
            return;
        }
    }
}

/// `phone`'s node `key → value` of `instance`, recorded and pushed.
fn write(
    home: &mut Home,
    phone: &mut Phone,
    instances: &[InstanceId],
    instance: InstanceId,
    key: u64,
) {
    set(&phone.light, instance, key, key * 10);
    let pushed = with(home, phone, instances, |sync| sync.push(instance)).unwrap();
    assert_eq!(pushed.stale, None);
}

/// A node of `instance` by `phone`, `edit` applied to its bytes, sealed for
/// the agent under `key` at `epoch` with the writer's view and `seen`
/// positions it has: what one holding that key could have pushed.
pub(super) fn sealed_by(
    phone: &Phone,
    instance: InstanceId,
    key: &[u8; 32],
    epoch: u64,
    value: u64,
    edit: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    set(&phone.light, instance, 99, value);
    let node = phone.light.outbox(instance).unwrap().pop().unwrap();
    phone
        .light
        .pushed(instance, &[(node.author, node.seq)])
        .unwrap();
    let mut node = node.bytes;
    edit(&mut node);
    seal_node(phone, instance, key, epoch, node)
}

/// `node` sealed by `phone` for the agent under `key` at `epoch`, with the
/// writer's view and `seen` positions it has.
fn seal_node(
    phone: &Phone,
    instance: InstanceId,
    key: &[u8; 32],
    epoch: u64,
    node: Vec<u8>,
) -> Vec<u8> {
    let scope = scope_of(phone, instance);
    let (index, chain) = phone.group.as_ref().unwrap().view();
    let body = Sealed {
        node,
        view: View { index, chain },
        seen: vec![(scope, phone.light.cursor(instance).unwrap().unwrap_or(0))],
    }
    .sealable(&scope)
    .unwrap();
    sealed::seal(key, &home::IDENTITY, scope, epoch, &body).unwrap()
}

/// `envelope` placed after the agent's last in `scope`, at the next
/// position.
fn placed(
    scope: Scope,
    envelope: Vec<u8>,
) -> impl FnMut(Scope, Vec<vos_wire::personal::Envelope>) -> Vec<vos_wire::personal::Envelope> {
    move |at, mut held| {
        if at == scope {
            let position = held.last().map_or(0, |last| last.position) + 1;
            held.push(vos_wire::personal::Envelope {
                position,
                id: vos_wire::personal::envelope_id(&envelope),
                bytes: envelope.clone(),
            });
        }
        held
    }
}

/// B3: the operators roll the agent back. A head behind what the device
/// read, or diverging at it, raises the rollback alarm; a log rewritten
/// behind the cursor and grown again does not chain where the device read
/// it; and the honest head raises nothing.
#[test]
fn a_rolled_back_log_raises_the_alarm() {
    let (mut home, mut phones) = household(2);
    let phone = &mut phones[0];
    let events = read(&mut home, phone);
    assert!(
        !events.iter().any(|event| matches!(event, Event::Alarm(_))),
        "{events:?}"
    );
    let log = home.log(phone.sync_key(), 0).unwrap();
    let (next, read_chain) = phone.group().view();
    assert_eq!(next, log.len() as u64);

    let (index, entry) = &log[log.len() - 3];
    assert_eq!(
        phone.group().head(index + 1, entry.chain).unwrap(),
        vec![Alarm::Rollback { next: index + 1 }]
    );
    let mut other = read_chain;
    other[0] ^= 1;
    assert_eq!(
        phone.group().head(next, other).unwrap(),
        vec![Alarm::Rollback { next }]
    );

    // Rolled back to an entry, rewritten from there and grown past the
    // cursor: the device reads the rewritten entries behind its cursor
    // against its own reading, and the first stops it.
    let at = log.len() - 3;
    let rewritten = shown_log(&home, phone, |entries| {
        entries[at].1.body = Body::Alive { device: 1 };
        entries[at].1.at += 1;
        let (_, mut last) = entries.last().cloned().unwrap();
        last.body = Body::Alive { device: 0 };
        entries.push((0, last));
    });
    let events = phone.group().follow(rewritten).unwrap();
    assert!(
        alarmed(&events, Alarm::Log { index: at as u64 }),
        "{events:?}"
    );
    assert_eq!(
        phone.group().view(),
        (next, read_chain),
        "it read nothing of it"
    );
}

/// B4 for operations: the operators show one device an operation they hide
/// from the other, a split control log. Each envelope carries its writer's
/// view: the device shown the operation raises the alarm at the other's
/// view, a chain its log does not have there, and the other at a view past
/// what it is served.
#[test]
fn an_operation_shown_to_one_device_alone_is_caught_by_views() {
    let (mut home, mut phones) = household(2);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    // An hour on, B's next `alive` is logged: the entry after the operation,
    // which the operators show B in its place.
    home.pass(60 * MIN + 1);
    let index = operate(
        &mut home,
        &a.admin.clone(),
        &a.sync.clone(),
        "remove",
        1u32.encode(),
        None,
    );
    b.alive(&mut home);
    let events = read(&mut home, a);
    assert!(
        !events.iter().any(|event| matches!(event, Event::Alarm(_))),
        "{events:?}"
    );
    let hidden = |entries: &mut Vec<(u64, Entry)>| {
        entries.retain(|(at, entry)| {
            *at != index && !matches!(entry.body, Body::Evidence { index: of, .. } if of == index)
        })
    };
    let log = shown_log(&home, b, hidden);
    let events = follow_shown(&mut home, b, log);
    assert!(
        !events.iter().any(|event| matches!(event, Event::Alarm(_))),
        "{events:?}"
    );

    write(&mut home, a, &[NOTES], NOTES, 1);
    let caught = with(&mut home, b, &[NOTES], |sync| sync.catch_up(NOTES)).unwrap();
    assert!(caught.alarms.is_empty(), "a view past the cursor waits");
    let (a_next, _) = a.group().view();
    let log = shown_log(&home, b, hidden);
    let events = follow_shown(&mut home, b, log);
    assert!(
        alarmed(&events, Alarm::View { index: a_next }),
        "{events:?}"
    );

    write(&mut home, b, &[NOTES], NOTES, 2);
    let caught = with(&mut home, a, &[NOTES], |sync| sync.catch_up(NOTES)).unwrap();
    let (b_next, _) = b.group().view();
    assert_eq!(caught.alarms, vec![Alarm::View { index: b_next }]);
}

/// B4 for commits: the operators show each device a commit of its own for
/// one epoch, two candidates. Each vote binds its voter's log, so each
/// device's vote fails to verify at the other: both raise the split-log
/// alarm, and neither confirms.
#[test]
fn two_commits_for_one_epoch_raise_the_split_log_alarm() {
    let (mut home, mut phones) = household(2);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    let confirmed = a.group().confirmed();
    let candidacy = a.update(&mut home).unwrap();

    // B's own commit for the epoch, never sent: the operators log it in
    // A's place in what they show B.
    let prepared = b.group().commit(None, home.now()).unwrap();
    let signed = home.sign(&b.admin, "commit", prepared.arguments());
    b.group()
        .signed_commit(signed.message.clone(), signed.signature)
        .unwrap();
    let theirs = Body::Candidate {
        call: AdminCall {
            origin: b.admin.verifying_key().to_bytes(),
            method: home.method("commit").0,
            arguments: prepared.arguments(),
        },
        by: 1,
        epoch: prepared.epoch,
        added: None,
        set: vec![0, 1],
    };
    let evidence = Body::Evidence {
        index: candidacy.index,
        message: signed.message,
        signature: signed.signature,
        welcome: None,
    };
    let swap = |entries: &mut Vec<(u64, Entry)>| {
        for (at, entry) in entries.iter_mut() {
            if *at == candidacy.index {
                entry.body = theirs.clone();
            } else if matches!(entry.body, Body::Evidence { index, .. } if index == candidacy.index)
            {
                entry.body = evidence.clone();
            }
        }
    };
    let log = shown_log(&home, b, swap);
    follow_shown(&mut home, b, log);
    let events = read(&mut home, a);
    assert!(
        alarmed(
            &events,
            Alarm::SplitLog {
                epoch: prepared.epoch,
                device: 1
            }
        ),
        "{events:?}"
    );
    let log = shown_log(&home, b, swap);
    let events = follow_shown(&mut home, b, log);
    assert!(
        alarmed(
            &events,
            Alarm::SplitLog {
                epoch: prepared.epoch,
                device: 0
            }
        ),
        "{events:?}"
    );
    assert_eq!(a.group().confirmed(), confirmed);
    assert_eq!(b.group().confirmed(), confirmed);
}

/// Two phones syncing the notes and the other scope: A's envelopes at 1
/// and 2, B's at 3 (B had read 2), A's at 4 and 5 (A had read 3).
fn scene() -> (Home, Vec<Phone>, Scope) {
    let (mut home, mut phones) = household(2);
    for phone in &mut phones {
        install(&phone.light, OTHER);
        let scope = scope_of(phone, OTHER);
        phone.group().key(scope).unwrap();
    }
    let scope = scope_of(&phones[0], NOTES);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    write(&mut home, a, &BOTH, NOTES, 1);
    write(&mut home, a, &BOTH, NOTES, 2);
    with(&mut home, b, &BOTH, |sync| sync.catch_up(NOTES)).unwrap();
    write(&mut home, b, &BOTH, NOTES, 3);
    with(&mut home, a, &BOTH, |sync| sync.catch_up(NOTES)).unwrap();
    write(&mut home, a, &BOTH, NOTES, 4);
    write(&mut home, a, &BOTH, NOTES, 5);
    (home, phones, scope)
}

const BOTH: [InstanceId; 2] = [NOTES, OTHER];

/// B19: the operators show a device part of a scope. A position skipped
/// is withheld; a writer's envelope numbered at or before a position it
/// had read there is renumbered; and a scope served to its end short of
/// where a writer, read in another scope, had read it is a partition.
#[test]
fn a_partitioned_scope_raises_the_alarm() {
    let (mut home, mut phones, scope) = scene();
    let caught = shown(
        &mut home,
        &mut phones[1],
        &BOTH,
        |_, mut held| {
            held.retain(|envelope| envelope.position != 4);
            held
        },
        |sync| sync.catch_up(NOTES),
    )
    .unwrap();
    assert_eq!(caught.alarms, vec![Alarm::Withheld { scope, position: 4 }]);

    // B's own hidden, and A's renumbered to 3 and 4.
    let (mut home, mut phones, scope) = scene();
    let caught = shown(
        &mut home,
        &mut phones[1],
        &BOTH,
        |at, held| {
            if at != scope {
                return held;
            }
            held.into_iter()
                .filter(|envelope| envelope.position != 3)
                .enumerate()
                .map(|(n, mut envelope)| {
                    envelope.position = n as u64 + 1;
                    envelope
                })
                .collect()
        },
        |sync| sync.catch_up(NOTES),
    )
    .unwrap();
    assert_eq!(caught.alarms, vec![Alarm::Partition { scope, position: 3 }]);

    // A's later envelopes hidden from B altogether, consistently. A has
    // read its own to 5 when it writes in the other scope, which B is
    // served whole.
    let (mut home, mut phones, scope) = scene();
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    with(&mut home, a, &BOTH, |sync| sync.catch_up(NOTES)).unwrap();
    write(&mut home, a, &BOTH, OTHER, 1);
    let hide = |at: Scope, mut held: Vec<vos_wire::personal::Envelope>| {
        if at == scope {
            held.retain(|envelope| envelope.position <= 3);
        }
        held
    };
    let caught = shown(&mut home, b, &BOTH, hide, |sync| sync.catch_up(OTHER)).unwrap();
    assert!(caught.alarms.is_empty(), "{:?}", caught.alarms);
    let caught = shown(&mut home, b, &BOTH, hide, |sync| sync.catch_up(NOTES)).unwrap();
    assert_eq!(caught.alarms, vec![Alarm::Partition { scope, position: 5 }]);
    let caught = with(&mut home, b, &BOTH, |sync| sync.catch_up(NOTES)).unwrap();
    assert!(caught.alarms.is_empty(), "served whole, it reads on");
    assert_eq!(count(&b.light, NOTES, 5), Some(50));
}

/// `phone` reading the agent's log as `reader` reads it (the agent
/// admits `phone` no more), then checking the agent's head.
fn relayed(home: &mut Home, reader: &Phone, phone: &mut Phone) -> Vec<Event> {
    let cursor = phone.group().cursor();
    let entries = home.log(reader.sync_key(), cursor).unwrap();
    let mut events = phone.group().follow(entries).unwrap();
    let overview: Overview = home
        .query(reader.sync_key(), "overview", ().encode())
        .unwrap();
    let alarms = phone.group().head(overview.next, overview.chain).unwrap();
    events.extend(alarms.into_iter().map(Event::Alarm));
    events
}

/// B8: the operators answer a device's veto with a log index and never log
/// it, letting the removal it vetoed mature. The device finds another entry
/// at that index, raises the alarm, and does not honour the maturity: it
/// keeps its voice.
#[test]
fn a_dropped_veto_raises_the_alarm_and_holds_its_removal_back() {
    let (mut home, mut phones) = household(2);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    let op = operate(
        &mut home,
        &a.admin.clone(),
        &a.sync.clone(),
        "remove",
        1u32.encode(),
        None,
    );
    read(&mut home, b);
    let veto = home.sign(&b.admin, "veto", op.encode());
    let overview: Overview = home.query(b.sync_key(), "overview", ().encode()).unwrap();
    b.group().made(overview.next, &veto.message).unwrap();

    home.pass(policy().operation_delay_ms);
    woken(&mut home, &a.sync);
    let events = relayed(&mut home, a, b);
    assert!(
        alarmed(
            &events,
            Alarm::Dropped {
                index: overview.next
            }
        ),
        "{events:?}"
    );
    assert!(!events.contains(&Event::Removed), "{events:?}");
    assert!(
        b.group
            .as_ref()
            .unwrap()
            .author(&b.keys.sync)
            .is_some_and(|(_, removed)| !removed)
    );
    let events = read(&mut home, a);
    assert!(
        !events.iter().any(|event| matches!(event, Event::Alarm(_))),
        "{events:?}"
    );
    assert!(
        a.group()
            .author(&b.sync_key())
            .is_some_and(|(_, removed)| removed)
    );
}

/// B8 and the views (§3.6): the operators claim a head one past what they
/// serve, so a head at or behind the cursor never comes. The device reads
/// the log again; a head it still does not reach is entries withheld, and
/// the veto the agent took and the writer's view it holds past the cursor
/// count as unreached. A head the log reaches when read again, as when an
/// entry lands between the reading and the head, raises nothing.
#[test]
fn a_head_claimed_past_what_is_served_silences_nothing() {
    let (mut home, mut phones) = household(2);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    let op = operate(
        &mut home,
        &a.admin.clone(),
        &a.sync.clone(),
        "remove",
        1u32.encode(),
        None,
    );
    read(&mut home, b);
    let cursor = b.group().cursor();
    let veto = home.sign(&b.admin, "veto", op.encode());
    b.group().made(cursor, &veto.message).unwrap();
    assert_eq!(b.group().check_view(cursor + 1, [7; 32]).unwrap(), None);
    let mut alarms = Vec::new();
    for _ in 0..2 {
        assert!(b.group().follow(Vec::new()).unwrap().is_empty());
        alarms.extend(b.group().head(cursor + 1, [9; 32]).unwrap());
    }
    for alarm in [
        Alarm::Unserved { next: cursor + 1 },
        Alarm::Dropped { index: cursor },
        Alarm::View { index: cursor + 1 },
    ] {
        assert!(alarms.contains(&alarm), "{alarm:?}: {alarms:?}");
    }

    let cursor = a.group().cursor();
    home.pass(61 * MIN);
    a.alive(&mut home);
    let overview: Overview = home.query(a.sync_key(), "overview", ().encode()).unwrap();
    assert!(overview.next > cursor);
    assert!(
        a.group()
            .head(overview.next, overview.chain)
            .unwrap()
            .is_empty()
    );
    let events = read(&mut home, a);
    assert!(
        !events.iter().any(|event| matches!(event, Event::Alarm(_))),
        "{events:?}"
    );
}

/// L6: a configuration logged after the claim's lowers no delay. The
/// operators log one with every delay zero, then an operation a stolen
/// admin key signed, asserted matured at once: the device raises the
/// alarm on the configuration, keeps its delays, and honours nothing.
#[test]
fn a_later_configuration_lowers_no_delay() {
    let (mut home, mut phones) = household(2);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    let at = home.now();
    // Placed at the log's head, where the operators' entries follow.
    let stolen = home.sign(&a.admin, "remove", 1u32.encode());
    let call = AdminCall {
        origin: a.admin.verifying_key().to_bytes(),
        method: home.method("remove").0,
        arguments: stolen.call.arguments.clone(),
    };
    let zero = vos_wire::personal::Policy {
        operation_delay_ms: 0,
        kit_delay_ms: 0,
        probation_ms: 0,
        seasoning_ms: 0,
        confirm_window_ms: 0,
        ..policy()
    };
    let mut configured = 0;
    let log = shown_log(&home, b, |entries| {
        let (_, last) = entries.last().cloned().unwrap();
        configured = entries.len() as u64;
        let index = configured + 1;
        let mut entry = |body: Body| {
            let mut entry = last.clone();
            entry.at = at;
            entry.body = body;
            entries.push((0, entry));
        };
        entry(Body::Configured(zero));
        entry(Body::Operation {
            call,
            by: Signer::Device(0),
            op: Op::Remove(1),
            matures: at,
        });
        entry(Body::Evidence {
            index,
            message: stolen.message,
            signature: stolen.signature,
            welcome: None,
        });
        entry(Body::Settled {
            op: index,
            state: OpState::Matured { at },
        });
        entry(Body::Matured { device: 1 });
    });
    let events = follow_shown(&mut home, b, log);
    assert!(!events.contains(&Event::Removed), "{events:?}");
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Alarm(Alarm::Unsigned { .. }))),
        "{events:?}"
    );
    assert!(
        alarmed(&events, Alarm::Policy { index: configured }),
        "{events:?}"
    );
    assert_eq!(
        b.group().policy().operation_delay_ms,
        policy().operation_delay_ms
    );
    assert!(
        b.group
            .as_ref()
            .unwrap()
            .author(&b.keys.sync)
            .is_some_and(|(_, removed)| !removed)
    );
}

/// A7 for archives (§3.4, §3.6): a phone of the group plants candidate
/// keys of later epochs in the archive it pushes, and seals a node of an
/// author no device's keys name under the epoch's key. The other phones
/// take from an archive read only the keys of the epochs before their
/// confirmed one, and no archive names an author: the node is passed over
/// while the phone has a voice, and so is one the planted author wrote
/// under the key of an epoch the phone was in, placed by the operators
/// after its removal.
#[test]
fn an_archive_plants_no_author_and_no_later_key() {
    let (mut home, mut phones, _) = super::kit::household_with(3, vec![kit_key(0)]);
    let scope = scope_of(&phones[0], NOTES);
    let epoch = phones[0].group().confirmed();
    let stranger = Phone::new(9);
    assert!(stranger.store.adopt(phones[0].group().archive()).unwrap());
    install(&stranger.light, NOTES);
    assert_eq!(scope_of(&stranger, NOTES), scope);
    let planted_key = [0x77; 32];
    let mut planted = phones[2].group().archive().shareable();
    for later in epoch + 1..epoch + 3 {
        planted.record(later, scope, planted_key);
    }
    phones[2].group().merge_archive(&planted).unwrap();
    with(&mut home, &mut phones[2], &[], |sync| sync.archive()).unwrap();
    for phone in &mut phones[..2] {
        let kept = with(&mut home, phone, &[], |sync| sync.archive()).unwrap();
        assert!(kept.found > 0);
        let archive = phone.group().archive();
        assert!(!archive.keys(epoch + 1, &scope).contains(&planted_key));
    }

    // The stranger's node sealed under the epoch's key while the phone
    // that planted the archive has a voice, read by another.
    let known_key = phones[0].group().key(scope).unwrap();
    let sealed_node = |phones: &mut [Phone], key: u64| {
        set(&stranger.light, NOTES, key, key * 10);
        let node = stranger.light.outbox(NOTES).unwrap().pop().unwrap().bytes;
        let (index, chain) = phones[0].group().view();
        let body = Sealed {
            node,
            view: View { index, chain },
            seen: vec![(scope, 0)],
        }
        .sealable(&scope)
        .unwrap();
        sealed::seal(&known_key, &home::IDENTITY, scope, epoch, &body).unwrap()
    };
    let envelope = sealed_node(&mut phones, 98);
    let caught = shown(
        &mut home,
        &mut phones[0],
        &[NOTES],
        placed(scope, envelope),
        |sync| sync.catch_up(NOTES),
    )
    .unwrap();
    assert_eq!(caught.passed.len(), 1);
    assert_eq!(caught.passed[0].why, Unusable::Author);
    assert_eq!(count(&phones[0].light, NOTES, 98), None);

    let removal = operate(
        &mut home,
        &phones[0].admin.clone(),
        &phones[0].sync.clone(),
        "remove",
        2u32.encode(),
        None,
    );
    operate(
        &mut home,
        &phones[1].admin.clone(),
        &phones[1].sync.clone(),
        "cosign",
        removal.encode(),
        None,
    );
    settle(&mut home, &mut phones[..2]);
    phones[0].update(&mut home).unwrap();
    settle(&mut home, &mut phones[..2]);
    assert_eq!(phones[1].group().confirmed(), epoch + 1);

    let envelope = sealed_node(&mut phones, 99);
    let caught = shown(
        &mut home,
        &mut phones[1],
        &[NOTES],
        placed(scope, envelope),
        |sync| sync.catch_up(NOTES),
    )
    .unwrap();
    assert_eq!(caught.passed.len(), 1);
    assert_eq!(caught.passed[0].why, Unusable::Author);
    assert_eq!(count(&phones[1].light, NOTES, 99), None);
}

/// B6: the operators forge a device-set operation, a removal with evidence
/// no admin key signed, and assert its maturity: no device moves, and the
/// maturity raises the alarm. And a node no device of the set wrote,
/// sealed under the scope's key by one who holds it, is refused.
#[test]
fn a_forged_operation_moves_nothing() {
    let (mut home, mut phones) = household(2);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    let at = home.now();
    // Placed at the log's head, where the operators' entries follow.
    let forged = home.sign(&a.sync, "remove", 1u32.encode());
    let call = AdminCall {
        origin: a.admin.verifying_key().to_bytes(),
        method: home.method("remove").0,
        arguments: forged.call.arguments.clone(),
    };
    let mut index = 0;
    let log = shown_log(&home, b, |entries| {
        let (_, last) = entries.last().cloned().unwrap();
        index = entries.len() as u64;
        let mut entry = |body: Body| {
            let mut entry = last.clone();
            entry.at = at;
            entry.body = body;
            entries.push((0, entry));
        };
        entry(Body::Operation {
            call,
            by: Signer::Device(0),
            op: Op::Remove(1),
            matures: at,
        });
        entry(Body::Evidence {
            index,
            message: forged.message,
            signature: forged.signature,
            welcome: None,
        });
        entry(Body::Settled {
            op: index,
            state: OpState::Matured { at },
        });
        entry(Body::Matured { device: 1 });
    });
    let events = follow_shown(&mut home, b, log);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Alarm(Alarm::Unsigned { .. }))),
        "{events:?}"
    );
    assert!(!events.contains(&Event::Removed), "{events:?}");
    assert!(
        b.group
            .as_ref()
            .unwrap()
            .author(&b.keys.sync)
            .is_some_and(|(_, removed)| !removed)
    );

    // A stranger holding the scope's key: its node is no device's.
    let mut stranger = Phone::new(9);
    assert!(stranger.store.adopt(a.group().archive()).unwrap());
    install(&stranger.light, NOTES);
    let scope = scope_of(a, NOTES);
    assert_eq!(scope_of(&stranger, NOTES), scope);
    stranger.group = Some(
        DeviceGroup::create(
            &stranger.store,
            home.agent(),
            stranger.keys.clone(),
            vec![kit_key(0)],
            home.now(),
        )
        .unwrap(),
    );
    let epoch = a.group().confirmed();
    let key = a.group().key(scope).unwrap();
    let envelope = sealed_by(&stranger, NOTES, &key, epoch, 7, |_| {});
    let caught = shown(&mut home, a, &[NOTES], placed(scope, envelope), |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(caught.passed.len(), 1);
    assert_eq!(caught.passed[0].why, Unusable::Author);
    assert_eq!(caught.alarms, vec![Alarm::Author { scope, position: 1 }]);
    assert_eq!(count(&a.light, NOTES, 99), None);

    // A device's node with an operation changed: its header names the
    // device, and its signature is no longer the device's.
    let (mut home, mut phones) = household(2);
    let scope = scope_of(&phones[0], NOTES);
    write(&mut home, &mut phones[0], &[NOTES], NOTES, 1);
    let epoch = phones[1].group().confirmed();
    let key = phones[1].group().key(scope).unwrap();
    let envelope = sealed_by(&phones[1], NOTES, &key, epoch, 7, |node| {
        let shown = (99u64, 7u64).encode();
        let at = node
            .windows(shown.len())
            .position(|window| window == shown)
            .expect("the operation's arguments");
        node[at + shown.len() - 8] = 8;
    });
    let caught = shown(
        &mut home,
        &mut phones[0],
        &[NOTES],
        placed(scope, envelope),
        |sync| sync.catch_up(NOTES),
    )
    .unwrap();
    assert_eq!(caught.alarms, vec![Alarm::Author { scope, position: 2 }]);
    assert_eq!(caught.passed[0].why, Unusable::Author);
    assert_eq!(count(&phones[0].light, NOTES, 99), None);
}

/// A8 and B8 for epochs: a push under an epoch since replaced is refused
/// with `StaleEpoch` (the device reseals it); one the operators take
/// anyway and place after the scope's envelopes of the later epoch is
/// passed over with the alarm, as the agent's order never goes back on an
/// epoch.
#[test]
fn a_stale_epoch_push_is_refused_and_one_placed_anyway_is_passed_over() {
    let (mut home, mut phones) = household(2);
    let scope = scope_of(&phones[0], NOTES);
    let old = phones[0].group().confirmed();
    let old_key = phones[0].group().key(scope).unwrap();
    phones[1].update(&mut home).unwrap();
    settle(&mut home, &mut phones);
    assert_eq!(phones[0].group().confirmed(), old + 1);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    write(&mut home, a, &[NOTES], NOTES, 1);
    let envelope = sealed_by(a, NOTES, &old_key, old, 7, |_| {});
    assert_eq!(
        home.call(&a.sync, "push", envelope.encode())
            .answer::<Pushed>(),
        Err(PersonalError::StaleEpoch { confirmed: old + 1 })
    );
    let caught = shown(&mut home, b, &[NOTES], placed(scope, envelope), |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(caught.alarms, vec![Alarm::Stale { scope, position: 2 }]);
    assert_eq!(caught.passed[0].why, Unusable::Stale);
    assert_eq!(count(&b.light, NOTES, 1), Some(10));
    assert_eq!(count(&b.light, NOTES, 99), None);
}

/// A7: a removed device, which still holds its last epoch's key, writes
/// after its removal, and the operators place the envelope after its
/// frontier: the reader refuses it, as the device's frontier is the
/// position of its last envelope the agent took.
#[test]
fn a_backdated_envelope_past_its_frontier_is_refused() {
    let (mut home, mut phones) = household(2);
    let scope = scope_of(&phones[0], NOTES);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    write(&mut home, b, &[NOTES], NOTES, 1);
    let epoch = b.group().confirmed();
    let key = b.group().key(scope).unwrap();
    operate(
        &mut home,
        &a.admin.clone(),
        &a.sync.clone(),
        "remove",
        1u32.encode(),
        None,
    );
    home.pass(policy().operation_delay_ms);
    woken(&mut home, &a.sync);
    read(&mut home, a);
    assert!(
        a.group()
            .author(&b.sync_key())
            .is_some_and(|(_, removed)| removed)
    );

    // A node it wrote after its removal, which the agent never took.
    set(&b.light, NOTES, 98, 980);
    let late = b.light.outbox(NOTES).unwrap().pop().unwrap().bytes;
    let envelope = sealed_by(b, NOTES, &key, epoch, 7, |_| {});
    let caught = shown(&mut home, a, &[NOTES], placed(scope, envelope), |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(
        caught.ingested.as_ref().unwrap().applied.len(),
        1,
        "within its frontier"
    );
    assert_eq!(caught.alarms, vec![Alarm::Author { scope, position: 2 }]);
    assert_eq!(caught.passed[0].why, Unusable::Author);
    assert_eq!(count(&a.light, NOTES, 1), Some(10));
    assert_eq!(count(&a.light, NOTES, 99), None);
    // The frontier is the removed author's cutoff too: one past its node at
    // its last position, whose number is 0.
    let author = merkle_crdt::Author(b.sync_key());
    assert_eq!(a.light.cutoff(NOTES, &author).unwrap(), Some(1));
    // So a later node of its, met outside the agent's order, is
    // quarantined, never applied.
    let ingested = a.light.ingest(NOTES, [late], None).unwrap();
    assert_eq!(ingested.nodes.applied.len(), 1);
    assert_eq!(ingested.quarantined.len(), 1);
    assert_eq!(ingested.quarantined[0].why, Quarantine::CutOff);
    assert_eq!(count(&a.light, NOTES, 98), None);
}

/// A removed device's envelope at its frontier carries a node at the last
/// sequence number, signed by its key, which no chain reaches: the reader
/// cuts its author off from there, one past it saturating, and refuses
/// the node.
#[test]
fn a_frontier_node_at_the_last_number_cuts_its_author_off() {
    let (mut home, mut phones) = household(2);
    let scope = scope_of(&phones[0], NOTES);
    let (a, b) = phones.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    write(&mut home, b, &[NOTES], NOTES, 1);
    let epoch = b.group().confirmed();
    let key = b.group().key(scope).unwrap();
    operate(
        &mut home,
        &a.admin.clone(),
        &a.sync.clone(),
        "remove",
        1u32.encode(),
        None,
    );
    home.pass(policy().operation_delay_ms);
    woken(&mut home, &a.sync);
    read(&mut home, a);

    // The operators show, at its frontier, a node of its own at the last
    // number in place of the one the agent took.
    let last = merkle_crdt::Node::<vos_light::sync::Blake2b256, vos_light::sync::Ops>::sign(
        &b.sync,
        &merkle_crdt::Scope(scope),
        u64::MAX,
        vec![],
        Default::default(),
    );
    let envelope = seal_node(b, NOTES, &key, epoch, last.to_bytes());
    let swapped = move |at: Scope, mut held: Vec<vos_wire::personal::Envelope>| {
        if at == scope {
            let frontier = held
                .iter_mut()
                .find(|envelope| envelope.position == 1)
                .unwrap();
            frontier.id = vos_wire::personal::envelope_id(&envelope);
            frontier.bytes = envelope.clone();
        }
        held
    };
    let caught = shown(&mut home, a, &[NOTES], swapped, |sync| sync.catch_up(NOTES)).unwrap();
    let ingested = caught.ingested.unwrap();
    assert!(ingested.applied.is_empty());
    assert_eq!(
        ingested.refused,
        vec![(Some(last.cid()), merkle_crdt::Refusal::BrokenChain)]
    );
    let author = merkle_crdt::Author(b.sync_key());
    assert_eq!(a.light.cutoff(NOTES, &author).unwrap(), Some(u64::MAX));
}

/// B2: the operators delete a device's envelope. Its sample audit fetches
/// its own positions, finds the one gone, and pushes its node again.
#[test]
fn the_audit_of_a_devices_own_pushes_pushes_a_deleted_one_again() {
    let (mut home, mut phones) = household(2);
    let scope = scope_of(&phones[0], NOTES);
    for key in 1..=3 {
        write(&mut home, &mut phones[0], &[NOTES], NOTES, key);
    }
    let audited = with(&mut home, &mut phones[0], &[NOTES], |sync| {
        sync.audit(NOTES, 8)
    })
    .unwrap();
    assert_eq!(audited.checked.len(), 3);
    assert!(audited.alarms.is_empty());
    let deleted = |_: Scope, mut held: Vec<vos_wire::personal::Envelope>| {
        held.retain(|envelope| envelope.position != 2);
        held
    };
    let audited = shown(&mut home, &mut phones[0], &[NOTES], deleted, |sync| {
        sync.audit(NOTES, 8)
    })
    .unwrap();
    assert_eq!(audited.alarms, vec![Alarm::Deleted { scope, position: 2 }]);
    assert_eq!(stored(&home, &phones[0], scope).len(), 4, "pushed again");
    let caught = shown(&mut home, &mut phones[1], &[NOTES], deleted, |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert_eq!(caught.alarms, vec![Alarm::Withheld { scope, position: 2 }]);
    assert_eq!(caught.waiting, Some(Waiting::Withheld(2)));
    assert_eq!(
        phones[1].light.cursor(NOTES).unwrap(),
        Some(1),
        "it stops at the gap"
    );
    let caught = with(&mut home, &mut phones[1], &[NOTES], |sync| {
        sync.catch_up(NOTES)
    })
    .unwrap();
    assert!(caught.alarms.is_empty(), "{:?}", caught.alarms);
    assert_eq!(count(&phones[1].light, NOTES, 2), Some(20));
}
