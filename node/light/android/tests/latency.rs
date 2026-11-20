// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A payment and a sign-in timed over Tor's delays (`World::delay`: a new
//! connection 4 s to its stream, a round trip 0.5 s, `light-node.md` §6.3),
//! the session open a few seconds first: from the tap to the form, nothing
//! is read; from the confirm to the answer, the one request sent is the
//! proven call, on a connection opened before the confirm. The stages'
//! times are printed (`latency:` lines).

mod common;

use common::*;
use std::time::Instant;

/// Answers its forms from a script after the user's reading time, noting
/// when each was shown and answered.
struct Reading {
    answers: Mutex<VecDeque<Answer>>,
    read: Duration,
    shown: Mutex<Vec<Instant>>,
    answered: Mutex<Vec<Instant>>,
}

impl Reading {
    fn new(read: Duration) -> Self {
        Self {
            answers: Mutex::default(),
            read,
            shown: Mutex::default(),
            answered: Mutex::default(),
        }
    }

    fn will(&self, answer: Answer) {
        self.answers.lock().unwrap().push_back(answer);
    }

    fn last_shown(&self) -> Instant {
        *self.shown.lock().unwrap().last().unwrap()
    }

    fn last_answered(&self) -> Instant {
        *self.answered.lock().unwrap().last().unwrap()
    }
}

impl Chrome for Reading {
    fn confirm(&self, _: Form) -> BoxFuture<'_, Answer> {
        self.shown.lock().unwrap().push(Instant::now());
        let answer = self.answers.lock().unwrap().pop_front();
        Box::pin(async move {
            if answer.is_some() {
                tokio::time::sleep(self.read).await;
            }
            self.answered.lock().unwrap().push(Instant::now());
            answer.unwrap_or(Answer::Declined)
        })
    }
}

/// Each connection's requests so far, by kind.
fn requests(world: &World) -> Vec<Vec<u16>> {
    world
        .state
        .lock()
        .unwrap()
        .seen
        .iter()
        .map(|seen| seen.requests.iter().map(|(kind, _)| *kind).collect())
        .collect()
}

/// The requests made since `before`, each with its connection's index,
/// leaving out the feed's connection (the tree's reads, on their own
/// timer): the one connection that carried a `Query` and no call.
fn since(before: &[Vec<u16>], after: &[Vec<u16>]) -> Vec<(usize, u16)> {
    let feed = |kinds: &Vec<u16>| {
        kinds.contains(&(ApiKind::Query as u16))
            && !kinds.contains(&(ApiKind::Credentialed as u16))
            && !kinds.contains(&(ApiKind::Call as u16))
    };
    let mut made = Vec::new();
    for (index, kinds) in after.iter().enumerate() {
        if feed(kinds) {
            continue;
        }
        let from = before.get(index).map_or(0, Vec::len);
        made.extend(kinds[from..].iter().map(|kind| (index, *kind)));
    }
    made
}

fn ms(duration: Duration) -> u128 {
    duration.as_millis()
}

/// What one timed call showed: its stages' times, and the requests made
/// before its form and after its confirm.
struct Timed {
    open: Duration,
    to_form: Duration,
    to_answer: Duration,
    proving: Duration,
    before_form: Vec<(usize, u16)>,
    after_confirm: Vec<(usize, u16)>,
    /// The connections open as the form was shown.
    connections: usize,
}

/// `operation` asked of `session` with `arguments`, the session granted
/// `open` before, the form confirmed with `values` after a reading time.
async fn timed(
    world: &World,
    session: &Session,
    operation: &str,
    arguments: &Value,
    values: &[&str],
    open: Duration,
) -> Timed {
    let granted = Instant::now();
    session.granted();
    tokio::time::sleep(open).await;
    let chrome = Reading::new(Duration::from_secs(3));
    chrome.will(confirm(values));
    let before = requests(world);
    let tap = Instant::now();
    let mut asked = std::pin::pin!(session.ask(operation, arguments, &chrome));
    let mut at_form = None;
    let answer = loop {
        tokio::select! {
            answer = &mut asked => break answer.unwrap(),
            _ = tokio::time::sleep(Duration::from_millis(5)) => {
                if at_form.is_none() && !chrome.shown.lock().unwrap().is_empty() {
                    at_form = Some(requests(world));
                }
            }
        }
    };
    let done = Instant::now();
    let after = requests(world);
    let at_form = at_form.expect("the form was shown before the answer");
    let proving = match field(&answer, "proving_ms") {
        Value::Integer(Integer::Unsigned(ms)) => Duration::from_millis(*ms),
        other => panic!("{other:?}"),
    };
    Timed {
        open: tap - granted,
        to_form: chrome.last_shown() - tap,
        to_answer: done - chrome.last_answered(),
        proving,
        before_form: since(&before, &at_form),
        after_confirm: since(&at_form, &after),
        connections: at_form.len(),
    }
}

impl Timed {
    fn print(&self, what: &str) {
        println!(
            "latency: {what}, session open {} ms: tap→form {} ms, confirm→answer {} ms (proof {} \
             ms, the rest {} ms); before the form {:?}, after the confirm {:?}",
            ms(self.open),
            ms(self.to_form),
            ms(self.to_answer),
            ms(self.proving),
            ms(self.to_answer.saturating_sub(self.proving)),
            self.before_form,
            self.after_confirm,
        );
    }

    /// Nothing read before the form; after the confirm, the one proven
    /// call, on a connection open before it.
    fn one_send(&self, what: &str) {
        assert!(
            self.before_form.is_empty(),
            "{what}: {:?}",
            self.before_form
        );
        let [(connection, kind)] = self.after_confirm[..] else {
            panic!("{what}: {:?}", self.after_confirm);
        };
        assert_eq!(kind, ApiKind::Credentialed as u16, "{what}");
        assert!(connection < self.connections, "{what}: on a spare");
        // A round trip is 0.5 s: a form waits for nothing (the target
        // 0.5 s), an answer for the proof and one trip, room left for a
        // loaded host.
        assert!(self.to_form < Duration::from_secs(1), "{what}");
        assert!(
            self.to_answer.saturating_sub(self.proving) < Duration::from_secs(2),
            "{what}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payment_and_a_sign_in_wait_for_one_send_after_the_confirm() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(Phone::new(9));
    let facility = facility(
        &world,
        directory.path(),
        Arc::clone(&source) as Arc<dyn Source>,
    );
    let chrome = Scripted::default();
    let named = facility.session(gateway());
    chrome.will(confirm(&[]));
    chrome.will(confirm(&[]));
    let enrolled = named.ask("enroll", &enrollment(), &chrome).await.unwrap();
    world.enroll(
        AGENT,
        &<[u8; 32]>::try_from(bytes(field(&enrolled, "member"))).unwrap(),
    );
    drop(named);

    // From here every stream takes Tor's delays, and each session is open
    // a few seconds before its server asks: time for a connection and its
    // handshake (8 s), drawn delays and the session's reads.
    world.delay(world::Delays::ONION);
    let open = Duration::from_secs(25);
    let pay = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(PAYMENTS)),
        ("method", Value::from("transfer")),
        ("payee", Value::from("shop")),
        ("amount", Value::from(20u64)),
    ]);
    let paying = facility.session(gateway());
    let paid = timed(&world, &paying, "pay", &pay, &["shop", "20"], open).await;
    paid.print("payment");
    let sent = world.last_credentialed().1;
    println!(
        "latency: a payment's proof {} bytes",
        sent.proof.len() + sent.claim.len()
    );

    let login = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(POLL)),
        ("method", Value::from("login")),
        ("arguments", Value::Bytes(Vec::new())),
    ]);
    let signing = facility.session(gateway());
    let signed = timed(&world, &signing, "sign_in", &login, &[], open).await;
    signed.print("sign-in");
    let sent = world.last_credentialed().1;
    println!(
        "latency: a sign-in's proof {} bytes",
        sent.proof.len() + sent.claim.len()
    );
    paid.one_send("the payment");
    signed.one_send("the sign-in");
}
