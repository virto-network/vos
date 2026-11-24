//! The client over arti against an in-process gateway: each dial a stream
//! to an SSH server of its own serving `vos-api`, the gateway's capture
//! recording each connection's target, its circuit (the isolation token
//! the dial was given, as arti's circuit manager reads it), the SSH key it
//! authenticated with and the kinds it carried. No network. That
//! `vos_light::tor::Tor` hands each connection's token to arti
//! (`StreamPrefs::set_isolation`) is the one line the capture does not
//! reach; the onion example exercises it over the live network.

mod common;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arti_client::isolation::Isolation;
use russh::keys::{PublicKeyOrCertificate, ssh_key};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vos_abi::credentials;
use vos_abi::ids::AgentId;
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_api::{Framing, Kind, frame};
use vos_light::route::{Clearnet, Purpose, Refused, Route, Routes};
use vos_light::testing::ssh::{self, Answer};
use vos_light::testing::{Held, Seen};
use vos_light::tor::{
    Circuit, Client, Config, Dial, Dialing, Error, Registrar, SSH_PORT, Stream, Target,
    onion_address,
};
use vos_light::{DeviceError, TreeKeeper, wire};
use vos_wire::credentials::{Change, Onion};
use vos_wire::ingress::{QueryCall, Response};

use common::tree::{Writes, serve_feed};

/// What a dial does instead of connecting.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// Fail at once, as a rendezvous that failed.
    Fail,
    /// Never answer, as a rendezvous that hangs.
    Hang,
    /// Fail at once, the onion service not found: not yet published.
    Unpublished,
}

struct Gateway {
    host_key: ssh_key::PrivateKey,
    seen: Mutex<Vec<Seen>>,
    faults: Mutex<VecDeque<Fault>>,
    /// Answer no request.
    silent: AtomicBool,
    /// What `onions` answers.
    onions: Mutex<Vec<Onion>>,
    /// What the client told the dialer of its dormancy, in order.
    dormant: Mutex<Vec<bool>>,
    /// The credential actor's feed, which `feed` answers three changes a
    /// page.
    feed: Mutex<Vec<Change>>,
}

/// An ed25519 SSH key's public half.
fn public(key: &ssh_key::PublicKey) -> [u8; 32] {
    key.key_data().ed25519().unwrap().0
}

impl Gateway {
    fn new() -> Arc<Self> {
        let host_key =
            ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]));
        Arc::new(Self {
            host_key,
            seen: Mutex::new(Vec::new()),
            faults: Mutex::new(VecDeque::new()),
            silent: AtomicBool::new(false),
            onions: Mutex::new(Vec::new()),
            dormant: Mutex::new(Vec::new()),
            feed: Mutex::new(Vec::new()),
        })
    }

    fn host_key(&self) -> [u8; 32] {
        public(self.host_key.public_key())
    }

    /// An onion of this gateway, by its key's byte.
    fn onion(&self, byte: u8) -> Onion {
        Onion {
            key: [byte; 32],
            ssh_host_key: self.host_key(),
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn dials(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// A query's reply: a page of the feed for `feed(from)`, and after the
    /// last change that left the root for `feed_after(root)`; else the
    /// onion set.
    fn answer(&self, body: &[u8]) -> Vec<u8> {
        let Some((_, query)) = <(AgentId, QueryCall)>::decode_exact(body) else {
            return self.onions.lock().unwrap().encode();
        };
        let feed = self.feed.lock().unwrap();
        serve_feed(&feed, &query, 3).unwrap_or_else(|| self.onions.lock().unwrap().encode())
    }

    fn fault(&self, faults: &[Fault]) {
        self.faults.lock().unwrap().extend(faults);
    }
}

struct Dialer(Arc<Gateway>);

impl Dial for Dialer {
    fn dial(&self, target: &Target, circuit: Circuit) -> Dialing {
        let gateway = Arc::clone(&self.0);
        let index = {
            let mut seen = gateway.seen.lock().unwrap();
            seen.push(Seen::new(target, circuit));
            seen.len() - 1
        };
        let fault = gateway.faults.lock().unwrap().pop_front();
        Box::pin(async move {
            match fault {
                Some(Fault::Fail) => {
                    return Err(std::io::Error::other(
                        "failed to obtain hidden service circuit",
                    ));
                }
                Some(Fault::Hang) => std::future::pending::<()>().await,
                Some(Fault::Unpublished) => {
                    return Err(vos_light::tor::Unpublished::error(
                        "Onion Service not found: failed to obtain hidden service circuit",
                    ));
                }
                None => {}
            }
            let host_key = gateway.host_key.clone();
            let ours = ssh::dialed(&host_key, Connection { gateway, index });
            // Each end holds its writes until flushed, as Tor's streams do.
            Ok(Box::new(Held::new(ours)) as Stream)
        })
    }

    fn set_dormant(&self, dormant: bool) {
        self.0.dormant.lock().unwrap().push(dormant);
    }
}

/// One connection of the gateway's.
struct Connection {
    gateway: Arc<Gateway>,
    index: usize,
}

impl ssh::Connection for Connection {
    fn seen(&self, f: impl FnOnce(&mut Seen)) {
        f(&mut self.gateway.seen.lock().unwrap()[self.index]);
    }

    /// `Time` answers 42, a query of `feed` its page, any other query the
    /// registrar's onion set, anything else its own body back; nothing
    /// while the gateway is silent.
    fn answer(&self, kind: u16, body: &[u8]) -> Answer {
        self.seen(|seen| seen.carried(kind, body));
        if self.gateway.silent.load(Ordering::SeqCst) {
            return Answer::Silent;
        }
        Answer::Body(match Kind::from_u16(kind) {
            Some(Kind::Time) => 42u64.encode(),
            Some(Kind::Query) => Response::Ran {
                outcome: Outcome::Done(self.gateway.answer(body)),
                at: 1,
            }
            .encode(),
            _ => body.to_vec(),
        })
    }
}

/// A space's handle, by a byte.
fn space(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// The test's deadlines: short, so a hang is a fault in a second.
fn config() -> Config {
    Config {
        connect: Duration::from_millis(500),
        handshake: Duration::from_secs(5),
        request: Duration::from_secs(5),
        proven: Duration::from_secs(5),
        attempts: 3,
        again: Duration::from_millis(200),
        agains: 2,
        idle: Duration::from_secs(60),
        spare_gap: Duration::from_millis(20),
        spare_idle: Duration::from_secs(60),
    }
}

/// A client through `gateway`, the app in the foreground.
fn client(gateway: &Arc<Gateway>, config: Config) -> Client {
    let client = Client::new(Arc::new(Dialer(Arc::clone(gateway))), config);
    client.set_foreground(true);
    client
}

/// A proven call's request: its kind and a stand-in body (the gateway
/// echoes it).
fn proven() -> Vec<u8> {
    let mut request = (Kind::Credentialed as u16).to_le_bytes().to_vec();
    request.extend_from_slice(&[0xab; 64]);
    request
}

fn query() -> Vec<u8> {
    let mut request = (Kind::Query as u16).to_le_bytes().to_vec();
    request.extend_from_slice(&[1, 2, 3]);
    request
}

/// Wait until `done`, at most five seconds.
async fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("not done within five seconds");
}

/// Every connection's circuit is its own: no two isolation tokens equal,
/// and arti's circuit manager takes no two as compatible; and every
/// connection authenticated under a key of its own.
fn assert_isolated(seen: &[Seen]) {
    for (at, one) in seen.iter().enumerate() {
        for other in &seen[..at] {
            assert_ne!(one.circuit, other.circuit);
            assert!(!one.circuit.token().compatible(&other.circuit.token()));
            if let (Some(one), Some(other)) = (one.key, other.key) {
                assert_ne!(one, other, "two connections under one SSH key");
            }
        }
        assert!(one.circuit.token().compatible(&one.circuit.token()));
    }
}

/// The gate's capture: two isolation groups (and every purpose) never
/// share a circuit or an SSH key; a kept-open purpose's requests share its
/// connection, and a one-shot purpose's each take their own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn isolation_groups_never_share_a_circuit_or_an_ssh_key() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let (a, b, home) = (space(1), space(2), space(3));
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    client.set_space(b, Routes::onions(vec![gateway.onion(2)]));
    client.set_space(home, Routes::new(vec![gateway.onion(3)], None, true));
    let time = wire::time_request();
    let mut groups = Vec::new();
    for (space, purpose, request, times) in [
        (a, Purpose::Member, query(), 3),
        (a, Purpose::Feed, query(), 2),
        (a, Purpose::Fetch, time.clone(), 2),
        (a, Purpose::Proven, proven(), 2),
        (b, Purpose::Member, query(), 2),
        (home, Purpose::Personal, query(), 2),
        (home, Purpose::Background, query(), 2),
    ] {
        for _ in 0..times {
            let (kind, _) = client.request(space, purpose, &request).await.unwrap();
            assert_eq!(kind.to_le_bytes(), request[..2]);
            groups.push((space, purpose));
        }
    }
    let seen = gateway.seen();
    // One connection a kept-open group, one a one-shot request.
    assert_eq!(seen.len(), 1 + 1 + 2 + 2 + 1 + 1 + 1);
    assert_isolated(&seen);
    assert!(seen.iter().all(|seen| seen.key.is_some()));
    // Each connection carried one group's requests: its kinds, in order.
    let carried: Vec<usize> = seen.iter().map(|seen| seen.kinds().len()).collect();
    assert_eq!(carried, [3, 2, 1, 1, 1, 1, 2, 2, 2]);
    let proven = Kind::Credentialed as u16;
    for (at, seen) in seen.iter().enumerate() {
        let carries_proofs = seen.kinds().contains(&proven);
        assert_eq!(carries_proofs, at == 4 || at == 5, "{at}");
        if carries_proofs {
            assert_eq!(seen.kinds(), [proven]);
        }
        let Target::Onion { port, .. } = &seen.target else {
            panic!("a clearnet dial");
        };
        assert_eq!(*port, SSH_PORT);
    }
    // A one-shot connection closes once answered.
    until(|| gateway.seen()[2..6].iter().all(|seen| seen.ended)).await;
}

/// A spare is built ahead, its SSH done; the next proven call takes it
/// without a dial, and the next spare is built once it is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proven_call_takes_the_spare_built_ahead() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    client.keep_spares(Some(a), &[Purpose::Proven]);
    until(|| client.spare_ready(Purpose::Proven)).await;
    assert_eq!(gateway.dials(), 1);
    assert!(gateway.seen()[0].key.is_some(), "the handshake is done");
    assert!(gateway.seen()[0].requests.is_empty());
    client.request(a, Purpose::Proven, &proven()).await.unwrap();
    assert_eq!(gateway.seen()[0].kinds(), [Kind::Credentialed as u16]);
    // The next spare, on a circuit and key of its own.
    until(|| client.spare_ready(Purpose::Proven)).await;
    assert_eq!(gateway.dials(), 2);
    client.request(a, Purpose::Proven, &proven()).await.unwrap();
    assert_eq!(gateway.seen()[1].kinds(), [Kind::Credentialed as u16]);
    until(|| client.spare_ready(Purpose::Proven)).await;
    // A key-signed call never takes the spare.
    client.request(a, Purpose::Member, &query()).await.unwrap();
    let seen = gateway.seen();
    assert_eq!(seen.len(), 4);
    assert!(seen[2].requests.is_empty() && seen[3].kinds() == [Kind::Query as u16]);
    assert_isolated(&seen);
    // No spare for a space it is not kept for.
    client.keep_spares(None, &[]);
    assert!(!client.spare_ready(Purpose::Proven));
}

/// A fetch takes a spare of its own, kept beside the proven calls': used
/// once and closed, the next built after it on a circuit and key of its
/// own. A request that may take no spare opens its own connection and
/// leaves the spare built.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fetch_takes_its_own_spare_once() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    client.keep_spares(Some(a), &[Purpose::Proven, Purpose::Fetch]);
    let ready = || client.spare_ready(Purpose::Proven) && client.spare_ready(Purpose::Fetch);
    until(ready).await;
    assert_eq!(gateway.dials(), 2);
    assert!(gateway.seen().iter().all(|seen| seen.requests.is_empty()));
    client
        .request(a, Purpose::Fetch, &wire::time_request())
        .await
        .unwrap();
    let carried: Vec<Seen> = gateway
        .seen()
        .into_iter()
        .filter(|seen| !seen.requests.is_empty())
        .collect();
    assert_eq!(carried.len(), 1, "the spare carried it");
    assert_eq!(carried[0].kinds(), [Kind::Time as u16]);
    until(ready).await;
    assert_eq!(gateway.dials(), 3);
    until(|| {
        gateway
            .seen()
            .iter()
            .any(|seen| seen.kinds() == [Kind::Time as u16] && seen.ended)
    })
    .await;
    client
        .request_with(a, Purpose::Fetch, &wire::time_request(), None)
        .await
        .unwrap();
    assert_eq!(gateway.dials(), 4, "a connection of its own");
    assert!(client.spare_ready(Purpose::Fetch));
    assert_isolated(&gateway.seen());
}

/// Spares are built only in the foreground, and leaving it closes them; a
/// spare left unused past its life is closed and built anew, so none is
/// held open for long.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spares_live_in_the_foreground_and_not_for_long() {
    let gateway = Gateway::new();
    let client = client(
        &gateway,
        Config {
            spare_idle: Duration::from_millis(400),
            ..config()
        },
    );
    client.set_foreground(false);
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    client.keep_spares(Some(a), &[Purpose::Proven]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(gateway.dials(), 0, "nothing built in the background");
    client.set_foreground(true);
    until(|| client.spare_ready(Purpose::Proven)).await;
    assert_eq!(gateway.dials(), 1);
    // Its life is 200 to 600 ms: then it closes, and another is built.
    until(|| gateway.dials() == 2 && gateway.seen()[0].ended).await;
    until(|| client.spare_ready(Purpose::Proven)).await;
    assert!(gateway.seen().iter().all(|seen| seen.requests.is_empty()));
    client.set_foreground(false);
    assert!(!client.spare_ready(Purpose::Proven));
    until(|| gateway.seen().iter().all(|seen| seen.ended)).await;
    let dials = gateway.dials();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(gateway.dials(), dials);
    assert_isolated(&gateway.seen());
}

/// A fresh connection that fails, or hangs past its deadline, is retried
/// on a new circuit through the next onion of the pinned set; past its
/// attempts the request fails, naming the last failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_connection_is_retried_on_a_new_circuit() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1), gateway.onion(2)]));
    gateway.fault(&[Fault::Fail, Fault::Hang]);
    client.request(a, Purpose::Member, &query()).await.unwrap();
    let seen = gateway.seen();
    assert_eq!(seen.len(), 3);
    assert_isolated(&seen);
    let onions: Vec<&Target> = seen.iter().map(|seen| &seen.target).collect();
    assert_ne!(onions[0], onions[1]);
    assert_eq!(onions[0], onions[2]);
    assert!(seen[..2].iter().all(|seen| seen.key.is_none()));
    assert_eq!(seen[2].kinds(), [Kind::Query as u16]);
    gateway.fault(&[Fault::Fail; 3]);
    match client.request(a, Purpose::Fetch, &query()).await {
        Err(Error::Unreachable(why)) => assert!(why.contains("hidden service"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(gateway.dials(), 6);
}

/// An onion service not yet published fails every attempt of a burst:
/// once each did, more are made after longer pauses, and go through. Past
/// them the request fails; a burst that failed otherwise is not tried
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unpublished_onion_is_tried_again_after_growing_pauses() {
    let gateway = Gateway::new();
    let config = config();
    let client = client(&gateway, config);
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    gateway.fault(&[Fault::Unpublished; 4]);
    let started = std::time::Instant::now();
    client.request(a, Purpose::Fetch, &query()).await.unwrap();
    assert!(
        started.elapsed() >= config.again * 3,
        "pauses of 1 and 2 times `again`"
    );
    assert_eq!(gateway.dials(), 5);
    gateway.fault(&[Fault::Unpublished; 5]);
    match client.request(a, Purpose::Fetch, &query()).await {
        Err(Error::Unreachable(why)) => assert!(why.contains("not found"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(gateway.dials(), 10);
    gateway.fault(&[Fault::Unpublished, Fault::Fail, Fault::Unpublished]);
    assert!(client.request(a, Purpose::Fetch, &query()).await.is_err());
    assert_eq!(gateway.dials(), 13);
}

/// A gateway presenting another host key than the pinned one is not
/// spoken to: every attempt fails at the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gateway_whose_host_key_is_not_pinned_is_refused() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    let mut onion = gateway.onion(1);
    onion.ssh_host_key[0] ^= 1;
    client.set_space(a, Routes::onions(vec![onion]));
    assert!(matches!(
        client.request(a, Purpose::Member, &query()).await,
        Err(Error::Unreachable(_))
    ));
    let seen = gateway.seen();
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter()
            .all(|seen| seen.key.is_none() && seen.requests.is_empty())
    );
}

/// The gate's refusal: on a clearnet-only path (the space pins no onion,
/// the user opted it out of Tor), a proven call, a fetch, the feed and the
/// personal agent's traffic are refused by the client with nothing
/// dialed; a key-signed call takes the clearnet port, and a proven call's
/// kind under its purpose is refused too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_call_is_refused_on_a_clearnet_only_path() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    let clearnet = Clearnet {
        host: "gateway.example".into(),
        port: 2222,
        ssh_host_key: gateway.host_key(),
    };
    let mut routes = Routes::new(Vec::new(), Some(clearnet), false);
    routes.opt_out().unwrap();
    client.set_space(a, routes);
    client.keep_spares(Some(a), &[Purpose::Proven]);
    for (purpose, request, refused) in [
        (Purpose::Proven, proven(), Refused::Anonymous),
        (Purpose::Fetch, query(), Refused::Anonymous),
        (Purpose::Feed, query(), Refused::Anonymous),
        (Purpose::Personal, query(), Refused::OnionOnly),
        (Purpose::Background, query(), Refused::OnionOnly),
        (Purpose::Member, proven(), Refused::Kind),
        (Purpose::Fetch, proven(), Refused::Kind),
    ] {
        match client.request(a, purpose, &request).await {
            Err(Error::Refused(why)) => assert_eq!(why, refused, "{purpose:?}"),
            other => panic!("{purpose:?}: {other:?}"),
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(gateway.dials(), 0, "nothing left the client");
    assert!(!client.spare_ready(Purpose::Proven));
    client.request(a, Purpose::Member, &query()).await.unwrap();
    let seen = gateway.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].target,
        Target::Clearnet {
            host: "gateway.example".into(),
            port: 2222
        }
    );
}

/// Dormant: every connection, the spare and the screens closed, arti told,
/// nothing dialed or sent; woken, the spare is built again and a request
/// opens a new connection on a new circuit and key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dormant_holds_no_connection_and_sends_nothing() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    client.keep_spares(Some(a), &[Purpose::Proven]);
    client.request(a, Purpose::Member, &query()).await.unwrap();
    until(|| client.spare_ready(Purpose::Proven)).await;
    assert_eq!(gateway.dials(), 2);
    client.set_dormant(true);
    assert!(client.is_dormant());
    until(|| gateway.seen().iter().all(|seen| seen.ended)).await;
    for purpose in [Purpose::Member, Purpose::Proven] {
        let request = if purpose == Purpose::Proven {
            proven()
        } else {
            query()
        };
        assert!(matches!(
            client.request(a, purpose, &request).await,
            Err(Error::Dormant)
        ));
    }
    let (ours, _theirs) = tokio::io::duplex(64);
    assert!(matches!(client.screens(a, ours).await, Err(Error::Dormant)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(gateway.dials(), 2);
    assert!(!client.spare_ready(Purpose::Proven));
    client.set_dormant(false);
    assert_eq!(*gateway.dormant.lock().unwrap(), [true, false]);
    until(|| client.spare_ready(Purpose::Proven)).await;
    client.request(a, Purpose::Member, &query()).await.unwrap();
    let seen = gateway.seen();
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[3].kinds(), [Kind::Query as u16]);
    assert_isolated(&seen);
}

/// A request past its deadline loses its connection; the next request
/// opens another. A kept-open connection idle past its time is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadlines_and_idleness_close_a_connection() {
    let gateway = Gateway::new();
    let client = client(
        &gateway,
        Config {
            request: Duration::from_millis(300),
            idle: Duration::from_millis(400),
            ..config()
        },
    );
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    gateway.silent.store(true, Ordering::SeqCst);
    assert!(matches!(
        client.request(a, Purpose::Member, &query()).await,
        Err(Error::Lost)
    ));
    until(|| gateway.seen()[0].ended).await;
    gateway.silent.store(false, Ordering::SeqCst);
    client.request(a, Purpose::Member, &query()).await.unwrap();
    assert_eq!(gateway.dials(), 2);
    // Kept open while used.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        client.request(a, Purpose::Member, &query()).await.unwrap();
    }
    assert_eq!(gateway.dials(), 2);
    until(|| gateway.seen()[1].ended).await;
    client.request(a, Purpose::Member, &query()).await.unwrap();
    assert_eq!(gateway.dials(), 3);
    assert_isolated(&gateway.seen());
}

/// s4's screen session, handed over as one end of a socketpair: s4's own
/// SSH runs over it to the gateway's onion, on a circuit of its own under
/// s4's key, and the host key returned is the pinned one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s4s_screens_are_carried_over_a_circuit_of_their_own() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    client.request(a, Purpose::Member, &query()).await.unwrap();
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let screens = client.screens_fd(a, theirs.into()).await.unwrap();
    assert_eq!(screens.ssh_host_key, gateway.host_key());
    assert_eq!(screens.route, Route::Onion);
    assert!(client.screens_open());
    // s4's side: its SSH over its end, its own key.
    ours.set_nonblocking(true).unwrap();
    let ours = tokio::net::UnixStream::from_std(ours).unwrap();
    struct Trusting;
    impl russh::client::Handler for Trusting {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }
    let config = Arc::new(russh::client::Config::default());
    let mut ssh = russh::client::connect_stream(config, ours, Trusting)
        .await
        .unwrap();
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[4; 32]));
    let s4_key = public(key.public_key());
    let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
    assert!(
        ssh.authenticate_publickey("s4", key)
            .await
            .unwrap()
            .success()
    );
    let mut channel = ssh.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "vos-api").await.unwrap();
    assert!(matches!(
        channel.wait().await,
        Some(russh::ChannelMsg::Success)
    ));
    let mut stream = channel.into_stream();
    stream
        .write_all(&frame(Framing::Stream, Kind::Time as u16, 7, &[]))
        .await
        .unwrap();
    let mut answer = vec![0u8; 64];
    let read = stream.read(&mut answer).await.unwrap();
    assert!(read > 0);
    let seen = gateway.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].key, Some(s4_key));
    assert_eq!(seen[1].kinds(), [Kind::Time as u16]);
    assert_isolated(&seen);
    // Dormant ends it.
    client.set_dormant(true);
    assert!(!client.screens_open());
    until(|| gateway.seen()[1].ended).await;
}

/// The pinned set is refreshed from the registrar through a fetch of its
/// own: a usable set replaces it, and the next connection goes to an onion
/// of the new set; an empty set or one naming an onion twice is refused
/// and the pinned set kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pinned_onion_set_is_refreshed_from_the_registrar() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    let registrar = Registrar {
        agent: 1,
        instance: 1,
        identity: [5; 32],
    };
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    client.request(a, Purpose::Member, &query()).await.unwrap();
    let fresh = vec![gateway.onion(7), gateway.onion(8)];
    *gateway.onions.lock().unwrap() = fresh.clone();
    assert_eq!(client.refresh_onions(a, &registrar).await.unwrap(), fresh);
    assert_eq!(client.routes(&a).unwrap().onions, fresh);
    // The time and the query on one fetch of their own; the member's
    // connection closed with the set it was made from.
    let seen = gateway.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].kinds(), [Kind::Time as u16, Kind::Query as u16]);
    until(|| gateway.seen()[0].ended).await;
    client.request(a, Purpose::Member, &query()).await.unwrap();
    let addresses: Vec<String> = fresh
        .iter()
        .map(|onion| onion_address(&onion.key))
        .collect();
    let Target::Onion { address, .. } = &gateway.seen()[2].target else {
        panic!("a clearnet dial");
    };
    assert!(addresses.contains(address));
    for bad in [Vec::new(), vec![gateway.onion(9), gateway.onion(9)]] {
        *gateway.onions.lock().unwrap() = bad;
        assert!(matches!(
            client.refresh_onions(a, &registrar).await,
            Err(Error::Onions)
        ));
        assert_eq!(client.routes(&a).unwrap().onions, fresh);
    }
    assert_isolated(&gateway.seen());
}

/// Requests of one group at once share the connection one of them opens:
/// one dial, every request on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_groups_concurrent_requests_open_one_connection() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let client = client.clone();
        requests.spawn(async move { client.request(a, Purpose::Member, &query()).await });
    }
    while let Some(answered) = requests.join_next().await {
        answered.unwrap().unwrap();
    }
    let seen = gateway.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].kinds().len(), 8);
}

/// Opting back into Tor closes the clearnet connection, a request in
/// flight on it included, and the next key-signed call takes the onion; a
/// dormancy ends a request in flight at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_change_or_a_dormancy_ends_what_the_old_route_carried() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    let clearnet = Clearnet {
        host: "gateway.example".into(),
        port: 2222,
        ssh_host_key: gateway.host_key(),
    };
    let mut routes = Routes::new(vec![gateway.onion(1)], Some(clearnet), false);
    routes.opt_out().unwrap();
    client.set_space(a, routes.clone());
    client.request(a, Purpose::Member, &query()).await.unwrap();
    assert!(matches!(gateway.seen()[0].target, Target::Clearnet { .. }));
    gateway.silent.store(true, Ordering::SeqCst);
    let waiting = {
        let client = client.clone();
        tokio::spawn(async move { client.request(a, Purpose::Member, &query()).await })
    };
    until(|| gateway.seen()[0].kinds().len() == 2).await;
    routes.opt_in();
    client.set_space(a, routes);
    let started = std::time::Instant::now();
    assert!(matches!(waiting.await.unwrap(), Err(Error::Lost)));
    assert!(started.elapsed() < Duration::from_secs(2));
    until(|| gateway.seen()[0].ended).await;
    gateway.silent.store(false, Ordering::SeqCst);
    client.request(a, Purpose::Member, &query()).await.unwrap();
    let seen = gateway.seen();
    assert_eq!(seen.len(), 2);
    assert!(matches!(seen[1].target, Target::Onion { .. }));
    // A request in flight when the client goes dormant ends at once.
    gateway.silent.store(true, Ordering::SeqCst);
    let waiting = {
        let client = client.clone();
        tokio::spawn(async move { client.request(a, Purpose::Member, &query()).await })
    };
    until(|| gateway.seen()[1].kinds().len() == 2).await;
    client.set_dormant(true);
    let started = std::time::Instant::now();
    assert!(matches!(waiting.await.unwrap(), Err(Error::Lost)));
    assert!(started.elapsed() < Duration::from_secs(2));
    until(|| gateway.seen()[1].ended).await;
}

/// A new screen session ends the last, each on a circuit of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_screen_session_ends_the_last() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    let (first, _first) = tokio::io::duplex(1 << 16);
    client.screens(a, first).await.unwrap();
    let (second, _second) = tokio::io::duplex(1 << 16);
    client.screens(a, second).await.unwrap();
    until(|| gateway.seen()[0].ended).await;
    let seen = gateway.seen();
    assert_eq!(seen.len(), 2);
    assert!(!seen[1].ended && client.screens_open());
    assert_isolated(&seen);
}

/// `count` enrollments at slots `0..count`, one change each.
fn enrollments(count: u32) -> Vec<Change> {
    let mut writes = Writes::default();
    for slot in 0..count {
        writes.write(
            u64::from(slot),
            &[(slot, credentials::leaf(&[slot + 1; 8]))],
        );
    }
    writes.changes
}

/// The tree is read on the space's one feed connection: the time and every
/// page on it, one circuit and one SSH key however many pages and reads,
/// carrying reads alone and no query naming the member; the tree the
/// feed's; a page that does not check refused, the tree as the pages
/// before it left it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tree_is_read_on_one_feed_connection() {
    let gateway = Gateway::new();
    let client = client(&gateway, config());
    let a = space(1);
    let credentials = Registrar {
        agent: 1,
        instance: 9,
        identity: [5; 32],
    };
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    let changes = enrollments(10);
    *gateway.feed.lock().unwrap() = changes[..7].to_vec();
    let mine = vos_light::Digest([3; 8]);
    let mut keeper = TreeKeeper::new(mine);
    assert_eq!(
        client
            .read_tree(a, &credentials, &mut keeper, || 0)
            .await
            .unwrap(),
        7
    );
    assert_eq!(keeper.root(), changes[6].root);
    *gateway.feed.lock().unwrap() = changes.clone();
    assert_eq!(
        client
            .read_tree(a, &credentials, &mut keeper, || 0)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        client
            .read_tree(a, &credentials, &mut keeper, || 0)
            .await
            .unwrap(),
        0
    );
    assert_eq!(keeper.root(), changes[9].root);
    let witness = keeper.witness().expect("the member's leaf, slot 2");
    assert_eq!(witness.slot, 2);
    assert!(witness.proves(&mine));

    let seen = gateway.seen();
    assert_eq!(seen.len(), 1, "one connection for every read");
    let (time, query) = (Kind::Time as u16, Kind::Query as u16);
    assert_eq!(
        seen[0].kinds(),
        [time, query, query, query, time, query, time, query]
    );

    let mut forged = enrollments(12);
    forged[11].root.root = [1; 32];
    *gateway.feed.lock().unwrap() = forged;
    assert!(matches!(
        client.read_tree(a, &credentials, &mut keeper, || 0).await,
        Err(Error::Answer(DeviceError::Witness))
    ));
    assert_eq!(keeper.cursor(), 10);
    assert_eq!(keeper.root(), changes[9].root);
    assert_eq!(gateway.seen().len(), 1);
}

/// A foreground hour's schedule, on a clock a thousand times faster (a
/// second a millisecond: the hour 3.6 s, the feed's timer 30 ms, drawn
/// between 15 and 45; the kept-open connections' idle limit a second, past
/// any stall of a loaded host): the feed read on its timer, the member's
/// calls and the personal agent's every minute, a facility session's
/// clock read every eight minutes (a fetch), and twelve sign-ins (one every
/// four minutes), each a proven call, spares kept for both, each living
/// longer than the gaps between its purpose's requests and the last
/// one's to the hour's end. The hour's
/// rendezvous are one a kept-open group (its connection outlives the gaps
/// between its requests), one a sign-in and one a clock reading (each takes
/// its purpose's spare, built anew after it), and the two spares left
/// built: 3 + 12 + 8 + 2 = 25, within the bound of 30 an hour. Counted as
/// the foreground's; a background run after it as the background's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreground_hour_opens_a_rendezvous_a_kept_group_a_sign_in_and_a_clock_reading() {
    const SIGN_INS: u32 = 12;
    const READINGS: u32 = 8;
    let gateway = Gateway::new();
    let client = client(
        &gateway,
        Config {
            idle: Duration::from_secs(1),
            spare_idle: Duration::from_millis(3_000),
            ..config()
        },
    );
    let (a, home) = (space(1), space(3));
    client.set_space(a, Routes::onions(vec![gateway.onion(1)]));
    client.set_space(home, Routes::new(vec![gateway.onion(3)], None, true));
    client.keep_spares(Some(a), &[Purpose::Proven, Purpose::Fetch]);
    let ready = || client.spare_ready(Purpose::Proven) && client.spare_ready(Purpose::Fetch);
    until(ready).await;
    let start = std::time::Instant::now();
    let hour = start + Duration::from_millis(3_600);
    let (mut feed, mut minute) = (start, start);
    let (mut signed, mut read) = (0u32, 0u32);
    let mut draw = 7u64;
    while std::time::Instant::now() < hour {
        let now = std::time::Instant::now();
        if now >= feed {
            client.request(a, Purpose::Feed, &query()).await.unwrap();
            draw = draw.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            feed = now + Duration::from_millis(15 + (draw >> 33) % 31);
        }
        if now >= minute {
            client.request(a, Purpose::Member, &query()).await.unwrap();
            client
                .request(home, Purpose::Personal, &query())
                .await
                .unwrap();
            minute = now + Duration::from_millis(60);
        }
        // A sign-in every four minutes, a clock reading every eight, each
        // on its purpose's spare, rebuilt between them.
        if signed < SIGN_INS && start + Duration::from_millis(240 * u64::from(signed) + 100) <= now
        {
            until(|| client.spare_ready(Purpose::Proven)).await;
            client.request(a, Purpose::Proven, &proven()).await.unwrap();
            signed += 1;
        }
        if read < READINGS && start + Duration::from_millis(480 * u64::from(read) + 220) <= now {
            until(|| client.spare_ready(Purpose::Fetch)).await;
            client
                .request(a, Purpose::Fetch, &wire::time_request())
                .await
                .unwrap();
            read += 1;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!((signed, read), (SIGN_INS, READINGS));
    until(ready).await;
    let hours = client.opened();
    let foreground: u32 = hours.iter().map(|hour| hour.foreground.rendezvous()).sum();
    let of = |purpose| -> u32 { hours.iter().map(|hour| hour.foreground.of(purpose)).sum() };
    // Every request took a spare; the last spares are built.
    assert_eq!(of(Purpose::Proven), SIGN_INS + 1);
    assert_eq!(of(Purpose::Fetch), READINGS + 1);
    for purpose in [Purpose::Feed, Purpose::Member, Purpose::Personal] {
        assert_eq!(of(purpose), 1, "{purpose:?} kept open across the hour");
    }
    assert_eq!(foreground, 3 + SIGN_INS + READINGS + 2);
    assert!(foreground <= 30, "{foreground} rendezvous in the hour");
    assert_eq!(foreground as usize, gateway.dials());
    assert!(hours.iter().all(|hour| hour.foreground.failed == 0));

    // In the background, a job's run on its own group.
    client.set_foreground(false);
    client
        .request(home, Purpose::Background, &query())
        .await
        .unwrap();
    let hours = client.opened();
    let background: u32 = hours.iter().map(|hour| hour.background.rendezvous()).sum();
    assert_eq!(background, 1);
    let line = hours.last().unwrap().to_string();
    assert!(line.starts_with("rendezvous hour "), "{line}");
    assert!(line.contains("; background 1 rendezvous"), "{line}");
}
