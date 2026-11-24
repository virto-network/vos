// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A payment is paid once per confirmed form, whatever becomes of its
//! answer: lost on the way (the gateway's to drop), a restart between the
//! send and the answer, or an expiry; the ledger's own word (`paid`) says
//! "paid" or "not paid" before the next form.

mod common;

use common::*;
use vos_facility::enrollment::{Origin, Store};
use world::{Death, Step};

/// The phone's tag, under which the world drops its answers.
const PHONE: u8 = 7;

fn transfer() -> Step {
    Step::proven(vos_abi::ids::MethodId(vos_light::method_id("transfer")))
}

fn pay() -> Value {
    object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(PAYMENTS)),
        ("method", Value::from("transfer")),
        ("payee", Value::from("shop")),
        ("amount", Value::from(20u64)),
    ])
}

/// A facility under `directory` dialling as the phone tagged [`PHONE`],
/// its secrets in `phone`'s keystore (which outlives a process).
fn phone_facility(world: &Arc<World>, directory: &std::path::Path, phone: &Arc<Phone>) -> Facility {
    let net = Arc::new(vos_facility::net::Net::new(world.dial_as(PHONE), directory));
    net.set_foreground(true);
    Facility::new(
        Store::new(directory),
        Arc::clone(phone) as Arc<dyn Source>,
        net,
    )
    .with_tick(Duration::from_millis(100))
}

/// The device enrolled and the world's tree listing it; a granted
/// session.
async fn enrolled(world: &Arc<World>, facility: &Facility, chrome: &Scripted) -> Session {
    let session = facility.session(gateway());
    chrome.will(confirm(&[]));
    chrome.will(confirm(&[]));
    let enrolled = session.ask("enroll", &enrollment(), chrome).await.unwrap();
    world.enroll(
        AGENT,
        &<[u8; 32]>::try_from(bytes(field(&enrolled, "member"))).unwrap(),
    );
    session.granted();
    session
}

fn paid(world: &World) -> usize {
    world.state.lock().unwrap().paid.len()
}

fn origin() -> Origin {
    let gateway = gateway();
    Origin {
        host: gateway.fingerprint,
        application: gateway.application,
    }
}

/// The ledger's error a payment's answer carries, if it carries one.
fn refused(answer: &Value) -> Option<vos_wire::payments::PaymentError> {
    match vos_light::wire::credentialed_answer(&bytes(field(answer, "answer"))) {
        Ok(vos_light::wire::Answer::Ran {
            outcome: Outcome::Failed { detail, .. },
            ..
        }) => vos_wire::payments::PaymentError::decode_exact(&detail),
        _ => None,
    }
}

/// The answer dropped: the payment says so and stays pending. One the
/// ledger took is said paid on the next form, and nothing more is paid
/// unless the user confirms anew; one it never took, confirmed again, is
/// that payment, its proof sent again, paid once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payment_whose_answer_is_lost_is_paid_once() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let phone = Arc::new(Phone::new(9));
    let facility = phone_facility(&world, directory.path(), &phone);
    let chrome = Scripted::default();
    let session = enrolled(&world, &facility, &chrome).await;
    let store = Store::new(directory.path());

    world.kill(PHONE, transfer(), 1, Death::After);
    chrome.will(confirm(&["shop", "20"]));
    let lost = session.ask("pay", &pay(), &chrome).await.unwrap_err();
    assert_eq!(lost.code, Code::Api);
    assert!(lost.message.contains("paid once"), "{lost:?}");
    assert_eq!(paid(&world), 1);
    assert_eq!(store.pending(&origin()).unwrap().len(), 1);
    world.revive(PHONE);
    let declined = session.ask("pay", &pay(), &chrome).await.unwrap_err();
    assert_eq!(declined.code, Code::Declined);
    let form = chrome.last();
    assert!(
        form.notice
            .as_deref()
            .is_some_and(|notice| notice.contains("20 to shop was paid")),
        "{form:?}"
    );
    assert_eq!(paid(&world), 1);
    assert!(store.pending(&origin()).unwrap().is_empty());

    world.kill(PHONE, transfer(), 1, Death::Before);
    chrome.will(confirm(&["shop", "21"]));
    session.ask("pay", &pay(), &chrome).await.unwrap_err();
    world.revive(PHONE);
    let sent = world.state.lock().unwrap().credentialed.len();
    chrome.will(confirm(&["shop", "21"]));
    let again = session.ask("pay", &pay(), &chrome).await.unwrap();
    assert!(
        chrome
            .last()
            .notice
            .as_deref()
            .is_some_and(|notice| notice.contains("21 to shop has no answer yet")),
    );
    assert_eq!(refused(&again), None, "paid now");
    assert_eq!(paid(&world), 2, "once");
    assert_eq!(
        world.state.lock().unwrap().credentialed.len(),
        sent + 1,
        "its proof sent again, no new one"
    );
    assert_eq!(field(&again, "proving_ms"), &Value::from(0u64));
    assert!(store.pending(&origin()).unwrap().is_empty());
}

/// A restart between the send and the answer: the next payment's form
/// says what the ledger answers of the last, paid; one that never reached
/// the ledger, confirmed again, is paid once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_between_send_and_answer_pays_once() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let phone = Arc::new(Phone::new(9));
    let chrome = Scripted::default();
    {
        let facility = phone_facility(&world, directory.path(), &phone);
        let session = enrolled(&world, &facility, &chrome).await;
        world.kill(PHONE, transfer(), 1, Death::After);
        chrome.will(confirm(&["shop", "20"]));
        session.ask("pay", &pay(), &chrome).await.unwrap_err();
    }
    world.revive(PHONE);
    assert_eq!(paid(&world), 1);

    // The next process: the form says it was paid, and a decline pays
    // nothing more.
    let facility = phone_facility(&world, directory.path(), &phone);
    let session = facility.session(gateway());
    session.granted();
    session.ask("pay", &pay(), &chrome).await.unwrap_err();
    let form = chrome.last();
    assert!(
        form.notice
            .as_deref()
            .is_some_and(|notice| notice.contains("20 to shop was paid")),
        "{form:?}"
    );
    assert_eq!(paid(&world), 1);
    assert!(
        Store::new(directory.path())
            .pending(&origin())
            .unwrap()
            .is_empty()
    );

    // A payment cut before the ledger took it, then a restart: within its
    // expiry it stays pending, and the same form pays it once.
    drop(session);
    drop(facility);
    {
        let facility = phone_facility(&world, directory.path(), &phone);
        let session = facility.session(gateway());
        session.granted();
        world.kill(PHONE, transfer(), 1, Death::Before);
        chrome.will(confirm(&["shop", "21"]));
        session.ask("pay", &pay(), &chrome).await.unwrap_err();
    }
    world.revive(PHONE);
    let facility = phone_facility(&world, directory.path(), &phone);
    let session = facility.session(gateway());
    session.granted();
    chrome.will(confirm(&["shop", "21"]));
    let answer = session.ask("pay", &pay(), &chrome).await.unwrap();
    assert!(
        chrome
            .last()
            .notice
            .as_deref()
            .is_some_and(|notice| notice.contains("21 to shop has no answer yet")),
    );
    assert_eq!(refused(&answer), None, "paid now");
    assert_eq!(paid(&world), 2);
}

/// Past its proof's expiry, a pending payment the ledger never took is
/// said not paid and forgotten, and one it took is said paid: a new form
/// then pays anew, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_payment_is_settled_by_the_ledgers_word() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let phone = Arc::new(Phone::new(9));
    let facility = phone_facility(&world, directory.path(), &phone);
    let chrome = Scripted::default();
    let session = enrolled(&world, &facility, &chrome).await;
    let store = Store::new(directory.path());
    let expire = || {
        for mut pending in store.pending(&origin()).unwrap() {
            pending.expires_ms = 0;
            store.keep_pending(&origin(), &pending).unwrap();
        }
    };

    world.kill(PHONE, transfer(), 1, Death::Before);
    chrome.will(confirm(&["shop", "20"]));
    session.ask("pay", &pay(), &chrome).await.unwrap_err();
    world.revive(PHONE);
    expire();
    chrome.will(confirm(&["shop", "20"]));
    session.ask("pay", &pay(), &chrome).await.unwrap();
    let form = chrome.last();
    assert!(
        form.notice
            .as_deref()
            .is_some_and(|notice| notice.contains("20 to shop was not paid")),
        "{form:?}"
    );
    assert_eq!(paid(&world), 1, "the new form paid, once");

    world.kill(PHONE, transfer(), 1, Death::After);
    chrome.will(confirm(&["shop", "22"]));
    session.ask("pay", &pay(), &chrome).await.unwrap_err();
    world.revive(PHONE);
    assert_eq!(paid(&world), 2);
    expire();
    session.ask("pay", &pay(), &chrome).await.unwrap_err();
    let form = chrome.last();
    assert!(
        form.notice
            .as_deref()
            .is_some_and(|notice| notice.contains("22 to shop was paid")),
        "{form:?}"
    );
    assert_eq!(paid(&world), 2);
    assert!(store.pending(&origin()).unwrap().is_empty());
}

/// A source that answers only after the user took `wait` to consent, and
/// notes when it last answered.
struct Slow {
    phone: Arc<Phone>,
    wait: Duration,
    answered: Mutex<Option<std::time::Instant>>,
}

impl Source for Slow {
    fn kinds(&self) -> Vec<Kind> {
        self.phone.kinds()
    }

    fn create(&self, kind: Kind) -> BoxFuture<'_, Result<Reference, SourceError>> {
        self.phone.create(kind)
    }

    fn evaluate<'a>(
        &'a self,
        reference: &'a Reference,
        input: [u8; 32],
    ) -> BoxFuture<'a, Result<Output, SourceError>> {
        Box::pin(async move {
            tokio::time::sleep(self.wait).await;
            let output = self.phone.evaluate(reference, input).await;
            *self.answered.lock().unwrap() = Some(std::time::Instant::now());
            output
        })
    }
}

/// A payment's proving time is the proof's: from the key's answer on, not
/// the user's wait at the source before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payments_proving_time_leaves_out_the_wait_for_the_key() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let slow = Arc::new(Slow {
        phone: Arc::new(Phone::new(9)),
        wait: Duration::from_secs(2),
        answered: Mutex::new(None),
    });
    let net = Arc::new(vos_facility::net::Net::new(
        world.dial_as(PHONE),
        directory.path(),
    ));
    net.set_foreground(true);
    let facility = Facility::new(
        Store::new(directory.path()),
        Arc::clone(&slow) as Arc<dyn Source>,
        net,
    )
    .with_tick(Duration::from_millis(100));
    let chrome = Scripted::default();
    let session = enrolled(&world, &facility, &chrome).await;
    chrome.will(confirm(&["shop", "20"]));
    let paid = session.ask("pay", &pay(), &chrome).await.unwrap();
    let after_the_key = slow.answered.lock().unwrap().unwrap().elapsed();
    let Value::Integer(Integer::Unsigned(proving_ms)) = field(&paid, "proving_ms") else {
        panic!("{paid:?}");
    };
    assert!(
        u128::from(*proving_ms) <= after_the_key.as_millis(),
        "proved in {proving_ms} ms, {} ms after the key answered",
        after_the_key.as_millis()
    );
}

/// A session the facility carries over Tor names, in its forms, the onion
/// it reaches the gateway at, not the address s4 was given.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_form_names_the_onion_a_carried_session_reaches() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let phone = Arc::new(Phone::new(9));
    let facility = phone_facility(&world, directory.path(), &phone);
    let chrome = Scripted::default();
    enrolled(&world, &facility, &chrome).await;
    let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    let session = facility.session(vos_facility::Gateway {
        onion: onion.into(),
        ..gateway()
    });
    session.granted();
    chrome.will(confirm(&["shop", "20"]));
    session.ask("pay", &pay(), &chrome).await.unwrap();
    let detail = chrome.last().detail;
    assert!(
        detail.starts_with(&format!("vos.test at {onion}, over Tor, asks")),
        "{detail}"
    );
    assert!(!detail.contains("gateway.test"), "{detail}");
}
