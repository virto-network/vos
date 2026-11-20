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

    // From here, every stream takes Tor's delays; each session is open a
    // few seconds before its server asks.
    world.delay(world::Delays::ONION);
    let open = Duration::from_secs(25);
    let reading = Duration::from_secs(3);

    let paying = facility.session(gateway());
    let granted = Instant::now();
    paying.granted();
    tokio::time::sleep(open).await;
    let chrome = Reading::new(reading);
    chrome.will(confirm(&["shop", "20"]));
    let pay = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(PAYMENTS)),
        ("method", Value::from("transfer")),
        ("payee", Value::from("shop")),
        ("amount", Value::from(20u64)),
    ]);
    let before = requests(&world);
    let tap = Instant::now();
    let asked = paying.ask("pay", &pay, &chrome);
    let mut asked = std::pin::pin!(asked);
    // The form shown, before the confirm.
    let mut at_form = None;
    let paid = loop {
        tokio::select! {
            paid = &mut asked => break paid.unwrap(),
            _ = tokio::time::sleep(Duration::from_millis(5)) => {
                if at_form.is_none() && !chrome.shown.lock().unwrap().is_empty() {
                    at_form = Some(requests(&world));
                }
            }
        }
    };
    let done = Instant::now();
    let after = requests(&world);
    let (shown, answered) = (chrome.last_shown(), chrome.last_answered());
    let proving = Duration::from_millis(match field(&paid, "proving_ms") {
        Value::Integer(Integer::Unsigned(ms)) => *ms,
        other => panic!("{other:?}"),
    });
    let sent = world.last_credentialed().1;
    let upload = sent.proof.len() + sent.claim.len();
    println!(
        "latency: payment, session open {} ms: tap→form {} ms, confirm→paid {} ms (proof {} ms, \
         the rest {} ms), proof {} bytes",
        ms(tap - granted),
        ms(shown - tap),
        ms(done - answered),
        ms(proving),
        ms((done - answered).saturating_sub(proving)),
        upload,
    );
    let at_form = at_form.expect("the form was shown");
    let before_form = since(&before, &at_form);
    let after_confirm = since(&at_form, &after);
    println!("latency: payment, tap→form requests {before_form:?}, confirm→paid {after_confirm:?}");

    let signing = facility.session(gateway());
    let granted = Instant::now();
    signing.granted();
    tokio::time::sleep(open).await;
    let login = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(POLL)),
        ("method", Value::from("login")),
        ("arguments", Value::Bytes(Vec::new())),
    ]);
    let chrome = Reading::new(reading);
    chrome.will(confirm(&[]));
    let before = requests(&world);
    let tap = Instant::now();
    let signed = signing.ask("sign_in", &login, &chrome).await.unwrap();
    let done = Instant::now();
    let after = requests(&world);
    let (shown, answered) = (chrome.last_shown(), chrome.last_answered());
    let proving = Duration::from_millis(match field(&signed, "proving_ms") {
        Value::Integer(Integer::Unsigned(ms)) => *ms,
        other => panic!("{other:?}"),
    });
    println!(
        "latency: sign-in, session open {} ms: tap→form {} ms, confirm→signed in {} ms (proof {} \
         ms, the rest {} ms)",
        ms(tap - granted),
        ms(shown - tap),
        ms(done - answered),
        ms(proving),
        ms((done - answered).saturating_sub(proving)),
    );
    println!("latency: sign-in, requests {:?}", since(&before, &after));
}
