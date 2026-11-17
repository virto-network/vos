//! The demo's test home end to end as far as it runs without a phone: the
//! home founded on the demo's node as `vos-gateway-demo --homes` founds it
//! (its agent with the credential actor and `Homes`, the keeper's pool of
//! personal agents, the open claim admitted at a low difficulty, the
//! gateway's onion as its onion set), its code as the app reads it, and
//! two phones, each s4's facility as `:vos` serves it, every request over
//! the gateway's onion in process (each dial a stream handed to the
//! onion's SSH port on a circuit of its own, as arti hands them): the
//! first claims a personal agent with a phrase kit, the second is paired
//! from it, and both sync.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use vos_facility::node::{Device, Node};
use vos_facility::personal::{Claim, Home as Code, KitKind};
use vos_facility::testing::Phone;
use vos_gateway_demo::home::{HOME_CREDENTIALS, HOMES, Home};
use vos_gateway_demo::{LocalSpace, Rate, Served, random};
use vos_light::tor::{Circuit, Dial, Dialing, Stream, Target};
use vos_wire::credentials::Onion;
use vos_wire::personal::Policy;

/// The test's policy: the session's, in seconds.
const POLICY: Policy = Policy {
    operation_delay_ms: 3_000,
    kit_delay_ms: 6_000,
    probation_ms: 2_000,
    seasoning_ms: 3_000,
    confirm_window_ms: 120_000,
    lease_ms: 600_000,
    slot_ttl_ms: 120_000,
    ..Policy::DEFAULT
};

/// Every stream a phone dials goes to the gateway's onion in process, on
/// a circuit of its own: Tor's part played by the onion's front.
struct Onions {
    front: Arc<vos_gateway::served::Front>,
    circuits: AtomicU32,
}

impl Dial for Onions {
    fn dial(&self, target: &Target, _circuit: Circuit) -> Dialing {
        let Target::Onion { port, .. } = target.clone() else {
            panic!("a phone's personal space goes to the onion alone: {target:?}");
        };
        let front = Arc::clone(&self.front);
        let circuit = self.circuits.fetch_add(1, Ordering::Relaxed) + 1;
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(1 << 20);
            front.onion.serve(theirs, circuit, port).await;
            Ok(Box::new(ours) as Stream)
        })
    }
}

/// A phone: its facility as `:vos` serves it, over `dial`, its store
/// under a directory of its own.
fn phone(dial: &Arc<Onions>, hand: &Arc<Phone>) -> (Node, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let net = {
        let _entered = runtime.enter();
        Arc::new(vos_facility::net::Net::new(
            Arc::clone(dial) as Arc<dyn Dial>,
            directory.path(),
        ))
    };
    let node = Node::over(
        runtime,
        directory.path().to_owned(),
        Arc::clone(hand) as Arc<dyn Device>,
        net,
        vos_facility::personal::embedded(),
    )
    .unwrap();
    (node, directory)
}

/// `text`, a home's code, read as s4's `Codes.home` reads it.
fn read_code(text: &str) -> Code {
    let bytes = hex::decode(text.strip_prefix("VOSHOME1:").expect("the prefix")).unwrap();
    let key = |at: usize| -> [u8; 32] { bytes[at..at + 32].try_into().unwrap() };
    let id = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    let count = bytes[32 + 32 + 4 + 32 + 4 + 4] as usize;
    let at = 32 + 32 + 4 + 32 + 4 + 4 + 1;
    assert_eq!(bytes.len(), at + count * 64, "the code's length");
    Code {
        space: key(0),
        handle: key(32),
        agent: id(64),
        identity: key(68),
        homes: id(100),
        credentials: id(104),
        onions: (0..count)
            .map(|n| s4_credential_contract::Onion {
                key: key(at + 64 * n),
                ssh_host_key: key(at + 64 * n + 32),
            })
            .collect(),
    }
}

#[test]
fn a_phone_claims_at_the_demos_home_and_pairs_a_second_over_the_onion() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    let data = tempfile::tempdir().unwrap();
    let space = LocalSpace::found(&data.path().join("space"), random(), random()).unwrap();
    // The demo's space grown as `members` grows it, for a catch-up.
    space.members(300).unwrap();
    let handle = random();
    let home: Home = space.found_home(handle, POLICY, 3).unwrap();
    let counts = space.tally(&home).unwrap();
    assert_eq!((counts.pooled, counts.assigned), (3, 0));

    // The gateway's onion in process, its servers on a runtime of their own.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (front, pinned) = runtime
        .block_on(space.onion_front(
            Served::Homes,
            data.path(),
            &space.socket(),
            // In process a pass's requests arrive back to back, with none
            // of Tor's round trips between them.
            Some(Rate {
                rate: 1_000,
                burst: 1_000,
            }),
        ))
        .unwrap();
    space
        .set_onions(&home, std::slice::from_ref(&pinned))
        .unwrap();
    let code = read_code(&space.home_code(&home, std::slice::from_ref(&pinned)));
    assert_eq!(code.handle, handle);
    assert_eq!(
        (code.agent, code.homes, code.credentials),
        (home.agent.0, HOMES.0, HOME_CREDENTIALS.0)
    );
    assert_eq!(code.identity, home.identity);
    let Onion { key, ssh_host_key } = pinned;
    assert_eq!(
        (code.onions[0].key, code.onions[0].ssh_host_key),
        (key, ssh_host_key)
    );
    let dial = Arc::new(Onions {
        front: Arc::new(front),
        circuits: AtomicU32::new(0),
    });

    // The first phone claims with a phrase kit: its open claim's work
    // first, then the pooled agent `Homes` names, sealed to it.
    let first_hand = Arc::new(Phone::new(0x11));
    let (first, _first_store) = phone(&dial, &first_hand);
    let claimed = first
        .personal()
        .unwrap()
        .claim(
            &*first_hand,
            Claim {
                home: code.clone(),
                kit: KitKind::Phrase,
                label: "first phone".into(),
            },
        )
        .unwrap();
    assert_eq!(claimed.device, 0);
    assert_eq!(
        first_hand.phrases.lock().unwrap().len(),
        1,
        "the kit's phrase shown"
    );
    vos_checker::wait_until(
        "the claim assigned",
        std::time::Duration::from_secs(60),
        || space.tally(&home).unwrap().assigned == 1,
    );

    // The second paired from it through the inbox's slot.
    let second_hand = Arc::new(Phone::new(0x22));
    let (second, _second_store) = phone(&dial, &second_hand);
    let offer = first.personal().unwrap().pair_offer(&*first_hand).unwrap();
    let (opened, joined) = std::thread::scope(|scope| {
        let opener = scope.spawn(|| first.personal().unwrap().pair_await(&*first_hand));
        let joined =
            second
                .personal()
                .unwrap()
                .pair_join(&*second_hand, &offer.code, "second phone");
        (opener.join().unwrap().unwrap(), joined.unwrap())
    });
    assert_eq!((opened.device, joined.device), (1, 1));
    assert_eq!(second.personal().unwrap().devices().unwrap().len(), 2);

    // Both phones' jobs sync.
    for phone in [&first, &second] {
        let synced = phone.sync_personal().unwrap();
        assert_eq!((synced.synced, synced.failed), (1, 0));
    }
    let counts = space.tally(&home).unwrap();
    assert_eq!((counts.pooled, counts.assigned), (2, 1));
    drop((first, second));
    space.shutdown();
}
