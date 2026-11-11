//! The demo's test home end to end as far as it runs without a phone: the
//! home founded on the demo's node as `vos-gateway-demo --homes` founds it
//! (its agent with the credential actor and `Homes`, the keeper's pool of
//! personal agents, the open claim admitted at a low difficulty, the
//! gateway's onion as its onion set), its code as the app reads it, and
//! two phones, each s4's facility as `:vos` serves it, every request over
//! the gateway's onion in process (each dial a stream handed to the
//! onion's SSH port on a circuit of its own, as arti hands them): the
//! first claims a personal agent with a phrase kit, the second is paired
//! from it, makes its open claim from its background job and re-proves the
//! lease, and both sync.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use hmac::{Hmac, Mac as _};
use s4_credential::chrome::{Answer, Form};
use s4_credential::node::{Device, Node, Prompts};
use s4_credential::source::Kind;
use s4_credential_contract::KeyAnswer;
use s4_credential_contract::personal::{Claim, Home as Code, KitKind};
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

struct Phone;

impl Device for Phone {
    fn kinds(&self) -> Vec<Kind> {
        vec![Kind::Keystore]
    }
}

/// A user and their phone's keys, in memory: the Keystore's HMAC key and
/// the admin keys made behind the biometric. It confirms every form and
/// writes down each phrase it is shown.
struct Hand {
    source: [u8; 32],
    admins: Mutex<HashMap<[u8; 32], SigningKey>>,
    made: Mutex<u8>,
    phrases: Mutex<Vec<String>>,
}

impl Hand {
    fn new(seed: u8) -> Arc<Self> {
        Arc::new(Self {
            source: [seed; 32],
            admins: Mutex::new(HashMap::new()),
            made: Mutex::new(seed.wrapping_mul(16)),
            phrases: Mutex::new(Vec::new()),
        })
    }
}

impl Prompts for Hand {
    fn confirm(&self, form: Form) -> Answer {
        if form.title == "Your recovery phrase" {
            let words: Vec<String> = form
                .rows
                .iter()
                .filter(|(label, _)| label.parse::<u8>().is_ok())
                .map(|(_, word)| word.clone())
                .collect();
            assert_eq!(words.len(), 24);
            self.phrases.lock().unwrap().push(words.join(" "));
        }
        let values = form
            .fields
            .iter()
            .map(|field| field.value.clone())
            .collect();
        Answer::Confirmed { choice: 0, values }
    }

    fn create_key(&self, kind: Kind) -> KeyAnswer {
        let mut made = self.made.lock().unwrap();
        *made = made.wrapping_add(1);
        match kind {
            Kind::Admin => {
                let key = SigningKey::from_bytes(&[*made; 32]);
                let public = key.verifying_key().to_bytes();
                self.admins.lock().unwrap().insert(public, key);
                // Hardware-backed, verified boot.
                KeyAnswer::Done([&public[..], &[3]].concat().into())
            }
            _ => KeyAnswer::Done(format!("vos.device.{made}").into_bytes().into()),
        }
    }

    fn evaluate_key(&self, _kind: Kind, _key: &[u8], input: &[u8; 32]) -> KeyAnswer {
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.source).unwrap();
        mac.update(input);
        KeyAnswer::Done(mac.finalize().into_bytes().to_vec().into())
    }

    fn sign_key(&self, kind: Kind, key: &[u8], message: &[u8]) -> KeyAnswer {
        assert_eq!(kind, Kind::Admin, "only the admin key signs");
        let admins = self.admins.lock().unwrap();
        match <[u8; 32]>::try_from(key)
            .ok()
            .and_then(|key| admins.get(&key))
        {
            Some(admin) => KeyAnswer::Done(admin.sign(message).to_bytes().to_vec().into()),
            None => KeyAnswer::Failed("no such key".into()),
        }
    }
}

/// A phone: its facility as `:vos` serves it, over `dial`, its store
/// under a directory of its own.
fn phone(dial: &Arc<Onions>) -> (Node, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let net = {
        let _entered = runtime.enter();
        Arc::new(s4_credential::net::Net::new(
            Arc::clone(dial) as Arc<dyn Dial>,
            directory.path(),
        ))
    };
    let node = Node::over(
        runtime,
        directory.path().to_owned(),
        Arc::new(Phone),
        net,
        s4_credential::personal::Artifacts::embedded(),
    )
    .unwrap();
    // The joiner's open claim at its next background pass, not hours on.
    node.set_claim_delay(0..0).unwrap();
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
    let (first, _first_store) = phone(&dial);
    let first_hand = Hand::new(0x11);
    let claimed = first
        .claim(
            Claim {
                home: code.clone(),
                kit: KitKind::Phrase,
                label: "first phone".into(),
            },
            &*first_hand,
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
    let (second, _second_store) = phone(&dial);
    let second_hand = Hand::new(0x22);
    let offer = first.pair_offer(&*first_hand).unwrap();
    let (opened, joined) = std::thread::scope(|scope| {
        let opener = scope.spawn(|| first.pair_await(&*first_hand));
        let joined = second.pair_join(&offer.code, "second phone", &*second_hand);
        (opener.join().unwrap().unwrap(), joined.unwrap())
    });
    assert_eq!((opened.device, joined.device), (1, 1));
    assert_eq!(second.devices().unwrap().len(), 2);

    // Its open claim by its background job, then, past its probation, its
    // re-proof of the lease under its own nullifier; both phones' jobs sync.
    second.sync_personal().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(POLICY.probation_ms + 500));
    second.sync_personal().unwrap();
    second.renew(&*second_hand).unwrap();
    for phone in [&first, &second] {
        let synced = phone.sync_personal().unwrap();
        assert_eq!((synced.synced, synced.failed), (1, 0));
    }
    let counts = space.tally(&home).unwrap();
    assert_eq!((counts.pooled, counts.assigned), (2, 1));
    drop((first, second));
    space.shutdown();
}
