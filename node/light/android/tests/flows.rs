// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A member's flows timed over Tor's delays (`World::delay`, `Delays::ONION`:
//! a new connection 4 s to its stream, a round trip 0.5 s), every stream
//! delayed from the first contact on: enroll and the first sign-in after
//! the invitation, the claim of a personal space (also with the proofs'
//! upload at the desktop's median rate), a
//! pairing from each side, the job's pass, a retirement and its commit, the
//! removed device's pass, a restore from the kit (also with a mistyped
//! word) and a move to another home. Each flow prints a `flow:` line (its
//! time, the connections it opened, its requests) and, under it, each
//! dial, request and prompt with its time from the flow's start. The test
//! policy's waits (its delays and probation, seconds here) are left out of
//! the flows' times: each is waited for between two timed stages.

mod common;

use std::collections::HashMap;
use std::time::Instant;

use common::phone::*;
use common::*;
use s4_credential_contract::KeyAnswer;
use vos_facility::node::{Node, Prompts};
use vos_facility::personal::{Claim, KitKind};
use vos_facility::source::Kind as KeyKind;
use vos_facility::{Answer, Form};
use world::{Delays, Logged};

/// The rate the desktop's onion circuits sustained at the median
/// (`light-node.md` §6.3), bytes a second.
const MEDIAN_RATE: u64 = 150_000;

/// A phone's prompts, each stamped as it is shown: the user's part of a
/// flow (a form read, a key's unlock), the prompts answered at once.
struct Stamped {
    phone: Arc<Phone>,
    prompts: Mutex<Vec<(Instant, String)>>,
}

impl Stamped {
    fn new(phone: &Arc<Phone>) -> Arc<Self> {
        Arc::new(Self {
            phone: Arc::clone(phone),
            prompts: Mutex::new(Vec::new()),
        })
    }

    fn stamp(&self, what: String) {
        self.prompts.lock().unwrap().push((Instant::now(), what));
    }
}

impl Prompts for Stamped {
    fn confirm(&self, form: Form) -> Answer {
        self.stamp(format!("form \"{}\"", form.title));
        Prompts::confirm(&*self.phone, form)
    }

    fn create_key(&self, kind: KeyKind) -> KeyAnswer {
        self.stamp(format!("create key {kind:?}"));
        self.phone.create_key(kind)
    }

    fn evaluate_key(&self, kind: KeyKind, key: &[u8], input: &[u8; 32]) -> KeyAnswer {
        self.stamp(format!("unlock {kind:?} (evaluate)"));
        self.phone.evaluate_key(kind, key, input)
    }

    fn sign_key(&self, kind: KeyKind, key: &[u8], message: &[u8]) -> KeyAnswer {
        self.stamp(format!("unlock {kind:?} (sign)"));
        self.phone.sign_key(kind, key, message)
    }
}

/// A request's name: its kind, and the method it names, by the module
/// whose methods hold it (`p.` the personal agent, `c.` the credential
/// actor, `h.` `Homes`).
fn named(step: world::Step) -> String {
    let kind = match step.kind {
        0x0002 => "Time",
        0x0003 => "AgentInfo",
        0x0005 => "Devices",
        0x0101 => "Call",
        0x0102 => "Query",
        0x0104 => "Proven",
        _ => "Other",
    };
    if step.method == 0 {
        return kind.into();
    }
    let modules: [(&str, &[(&str, vos_abi::ids::MethodId)]); 3] = [
        ("p", vos_wire::personal::method::ALL),
        ("c", vos_wire::credentials::method::ALL),
        ("h", vos_wire::homes::method::ALL),
    ];
    let names: Vec<String> = modules
        .iter()
        .flat_map(|(module, all)| {
            all.iter()
                .filter(|(_, id)| id.0 == step.method)
                .map(move |(name, _)| format!("{module}.{name}"))
        })
        .collect();
    format!("{kind} {}", names.join("|"))
}

/// One flow's measurement from its start: the world's log and the prompts
/// from here.
struct Meter {
    from: usize,
    start: Instant,
    prompts: Vec<(Arc<Stamped>, usize)>,
}

impl Meter {
    fn start(world: &World, prompts: &[&Arc<Stamped>]) -> Self {
        Self {
            from: world.state.lock().unwrap().log.len(),
            start: Instant::now(),
            prompts: prompts
                .iter()
                .map(|stamped| (Arc::clone(stamped), stamped.prompts.lock().unwrap().len()))
                .collect(),
        }
    }

    /// The flow's line, then its dials, requests and prompts in order.
    fn print(&self, world: &World, flow: &str) -> Duration {
        let took = self.start.elapsed();
        let log: Vec<Logged> = world.state.lock().unwrap().log[self.from..].to_vec();
        let dials = log.iter().filter(|logged| logged.step.is_none()).count();
        let requests = log.len() - dials;
        let times = log
            .iter()
            .filter(|logged| logged.step.is_some_and(|step| step.kind == 0x0002))
            .count();
        let mut prompts = 0;
        let mut lines: Vec<(Instant, String)> = Vec::new();
        let mut connections: HashMap<usize, usize> = HashMap::new();
        for logged in &log {
            let next = connections.len();
            let connection = *connections.entry(logged.connection).or_insert(next);
            let what = match logged.step {
                None => "dial".to_string(),
                Some(step) => named(step),
            };
            lines.push((
                logged.at,
                format!("phone {:#04x} #{connection} {what}", logged.tag),
            ));
        }
        for (stamped, from) in &self.prompts {
            for (at, what) in &stamped.prompts.lock().unwrap()[*from..] {
                prompts += 1;
                lines.push((*at, format!("prompt: {what}")));
            }
        }
        lines.sort_by_key(|(at, _)| *at);
        println!(
            "flow: {flow}: {} ms, {dials} connections opened, {requests} requests ({times} \
             of them the node's time), {prompts} prompts",
            took.as_millis()
        );
        for (at, line) in lines {
            println!(
                "flow:   +{:>6} ms {line}",
                at.saturating_duration_since(self.start).as_millis()
            );
        }
        took
    }
}

/// The phone tagged `seed` with its stamped prompts, the app in the
/// foreground (its sessions keep spares, as `:vos` does while s4 shows).
fn held(world: &Arc<World>, seed: u8) -> (Held, Arc<Stamped>) {
    let phone = phone(world, seed);
    phone.node.foreground(true);
    let stamped = Stamped::new(&phone.hand);
    (phone, stamped)
}

fn claim_at(world: &World, home: u32, label: &str) -> Claim {
    Claim {
        home: home_of(world, home),
        kit: KitKind::Phrase,
        label: label.into(),
    }
}

/// `node` signs in on a session of its own, granted `open` before, asked
/// again every 2 s (a member tapping again) while the device has no path:
/// the attempts.
fn signs_in_from(node: &Node, prompts: &Arc<Stamped>, open: Duration) -> usize {
    let session = node.open_session(gateway());
    node.granted(session).unwrap();
    std::thread::sleep(open);
    for attempt in 1..=60 {
        let lent = Arc::clone(prompts) as Arc<dyn Prompts>;
        match node.sign_in(session, sign_in(), lent) {
            Err(refusal) if matches!(refusal.code, Code::NoPath | Code::Unclaimed) => {
                println!(
                    "flow:   attempt {attempt}: {:?} {}",
                    refusal.code, refusal.message
                );
                std::thread::sleep(Duration::from_secs(2));
            }
            signed => {
                signed.unwrap();
                node.close(session);
                return attempt;
            }
        }
    }
    panic!("never signed in");
}

/// Enroll through an s4 session, then the first sign-in right after the
/// operator's invitation: the device reads its leaf at its tree's next
/// read, the member tapping again meanwhile.
#[test]
fn enroll_and_the_first_sign_in() {
    let world = world();
    world.delay(Delays::ONION);
    let (phone, stamped) = held(&world, 0x11);

    let meter = Meter::start(&world, &[&stamped]);
    let session = phone.node.open_session(gateway());
    let enrolled = phone
        .node
        .enroll(
            session,
            vos_facility::Enroll::read(&enrollment()).unwrap(),
            Arc::clone(&stamped) as Arc<dyn Prompts>,
        )
        .unwrap();
    meter.print(&world, "enroll (the session granted at once)");
    phone.node.close(session);

    // The operator invites: the leaf is in the tree from now.
    world.enroll(AGENT, &enrolled.member);
    let meter = Meter::start(&world, &[&stamped]);
    let attempts = signs_in_from(&phone.node, &stamped, Duration::ZERO);
    meter.print(
        &world,
        &format!("first sign-in after the invitation, tapped at once ({attempts} attempts)"),
    );

    let meter = Meter::start(&world, &[&stamped]);
    signs_in_from(&phone.node, &stamped, Duration::from_secs(15));
    meter.print(&world, "a sign-in on a session open 15 s");
}

/// The claim of a personal space.
#[test]
fn claim_a_personal_space() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    world.delay(Delays::ONION);

    let (first, stamped) = held(&world, 0x21);
    let meter = Meter::start(&world, &[&stamped]);
    let claimed = first
        .node
        .personal()
        .unwrap()
        .claim(&*stamped, claim_at(&world, home, "first"))
        .unwrap();
    meter.print(&world, "claim (kit: phrase)");
    assert_eq!(claimed.device, 0);
}

/// The same claim with the proofs' upload at the median rate.
#[test]
fn claim_over_slow_circuits() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    world.delay(Delays {
        rate: MEDIAN_RATE,
        ..Delays::ONION
    });
    let (phone, stamped) = held(&world, 0x23);
    let meter = Meter::start(&world, &[&stamped]);
    phone
        .node
        .personal()
        .unwrap()
        .claim(&*stamped, claim_at(&world, home, "slow"))
        .unwrap();
    meter.print(&world, "claim, the circuits at 0.15 MB/s");
}

/// A pairing timed from each side, the job's pass on both, a retirement
/// and its commit, and the retired phone's pass.
#[test]
fn pair_sync_retire_and_the_removed_phone() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    // Delayed from the claim on: the opener's connections are Tor's too.
    world.delay(Delays::ONION);
    let (opener, opening) = held(&world, 0x31);
    opener
        .node
        .personal()
        .unwrap()
        .claim(&*opening, claim_at(&world, home, "opener"))
        .unwrap();
    let (joiner, joining) = held(&world, 0x32);

    let meter = Meter::start(&world, &[&opening]);
    let code = opener
        .node
        .personal()
        .unwrap()
        .pair_offer(&*opening)
        .unwrap();
    meter.print(&world, "pair: the opener's code (the QR shown)");

    let meter = Meter::start(&world, &[&opening, &joining]);
    let (opened, joined) = std::thread::scope(|scope| {
        let opened = scope.spawn(|| {
            let opened = opener.node.personal().unwrap().pair_await(&*opening);
            (opened, meter.start.elapsed())
        });
        let joined = joiner
            .node
            .personal()
            .unwrap()
            .pair_join(&*joining, &code.code, "joiner");
        let joined_at = meter.start.elapsed();
        let (opened, opened_at) = opened.join().unwrap();
        println!(
            "flow: pair: from the scan, the opener done at {} ms, the joiner at {} ms",
            opened_at.as_millis(),
            joined_at.as_millis()
        );
        (opened.unwrap(), joined.unwrap())
    });
    meter.print(&world, "pair: from the scan to both done");
    assert_eq!(opened.device, joined.device);

    for (phone, stamped, name) in [
        (&opener, &opening, "the opener"),
        (&joiner, &joining, "the joiner"),
    ] {
        let meter = Meter::start(&world, &[stamped]);
        let synced = phone.node.sync_personal().unwrap();
        meter.print(
            &world,
            &format!(
                "sync: {name}'s pass ({} synced, {} failed)",
                synced.synced, synced.failed
            ),
        );
    }
    let meter = Meter::start(&world, &[&opening]);
    let devices = opener.node.personal().unwrap().devices().unwrap();
    meter.print(
        &world,
        &format!("devices: the list ({} devices)", devices.len()),
    );

    // Retired once the joiner is past its probation and seasoned.
    after(policy().probation_ms.max(policy().seasoning_ms));
    opener.node.sync_personal().unwrap();
    let meter = Meter::start(&world, &[&opening]);
    opener
        .node
        .personal()
        .unwrap()
        .remove(&*opening, joined.device)
        .unwrap();
    meter.print(&world, "retire: the removal posted");
    after(policy().operation_delay_ms);
    let meter = Meter::start(&world, &[&opening]);
    let synced = opener.node.sync_personal().unwrap();
    meter.print(
        &world,
        &format!(
            "retire: the pass after the delay ({} notices)",
            synced.notices.len()
        ),
    );
    let meter = Meter::start(&world, &[&opening]);
    opener.node.personal().unwrap().update(&*opening).unwrap();
    meter.print(&world, "retire: commit now");

    let meter = Meter::start(&world, &[&joining]);
    let synced = joiner.node.sync_personal();
    meter.print(
        &world,
        &format!(
            "removed: the retired phone's pass ({:?})",
            synced.map(|synced| (synced.synced, synced.failed))
        ),
    );
}

/// A restore on a fresh phone, its screen's sitting open: the words
/// mistyped first, then the restore opened, the kit's view read, and the
/// restore finished after the kit's delay, the kit entered again only
/// after the mistyped words; then a move to another home.
#[test]
fn restore_from_the_kit_and_move() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let elsewhere = world.home(ELSEWHERE, 3, 1);
    let (lost, lost_stamped) = held(&world, 0x41);
    lost.node
        .personal()
        .unwrap()
        .claim(&*lost_stamped, claim_at(&world, home, "lost"))
        .unwrap();
    let words = lost.hand.phrase();
    drop(lost);
    world.delay(Delays::ONION);
    let (fresh, stamped) = held(&world, 0x42);
    fresh.node.space().unwrap().hold_kit();

    // One word replaced by another of the list: the checksum fails, or in
    // one try of 256 holds and names another kit.
    let mut typed: Vec<&str> = words.split(' ').collect();
    typed[7] = if typed[7] == "abandon" {
        "ability"
    } else {
        "abandon"
    };
    fresh.hand.will_enter(typed.join(" "));
    let meter = Meter::start(&world, &[&stamped]);
    let refused = fresh
        .node
        .personal()
        .unwrap()
        .restore(&*stamped, claim_at(&world, home, "new"), KitKind::Phrase)
        .unwrap_err();
    meter.print(
        &world,
        &format!(
            "restore: a mistyped word ({:?}: {})",
            refused.why, refused.detail
        ),
    );

    fresh.hand.will_enter(words.clone());
    let meter = Meter::start(&world, &[&stamped]);
    let view = fresh
        .node
        .personal()
        .unwrap()
        .kit_view(&*stamped, home_of(&world, home), KitKind::Phrase)
        .unwrap();
    meter.print(
        &world,
        &format!("restore: the kit's view ({} devices)", view.devices.len()),
    );

    fresh.hand.will_enter(words.clone());
    let meter = Meter::start(&world, &[&stamped]);
    fresh
        .node
        .personal()
        .unwrap()
        .restore(&*stamped, claim_at(&world, home, "new"), KitKind::Phrase)
        .unwrap();
    meter.print(&world, "restore: opened");
    after(policy().kit_delay_ms);
    fresh.hand.will_enter(words);
    let meter = Meter::start(&world, &[&stamped]);
    fresh
        .node
        .personal()
        .unwrap()
        .restored(&*stamped, KitKind::Phrase)
        .unwrap();
    meter.print(&world, "restore: finished after the kit's delay");
    println!(
        "flow: restore: the kit entered {} times in the sitting (once mistyped)",
        fresh.hand.entered.lock().unwrap()
    );
    fresh.node.space().unwrap().forget_kit();

    let meter = Meter::start(&world, &[&stamped]);
    fresh
        .node
        .personal()
        .unwrap()
        .move_home(&*stamped, claim_at(&world, elsewhere, "new"))
        .unwrap();
    meter.print(&world, "move: leave and claim at another home");
}
