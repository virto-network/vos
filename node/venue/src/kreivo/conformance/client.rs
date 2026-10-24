//! G1–G19 through the node's client: each vector's calls decoded and
//! encoded again by the client's own types ([`calls`]), sent by its
//! [`Sender`] through the transport over the mock, and what came back read
//! by the client: the result from its decode of the dispatch error, the
//! events from its decode of the pallet's, and every storage write as the
//! client reads it, its key rebuilt by the client's key builders and its
//! value decoded as the client's type of the item; and what each call Ok
//! means, read from its own arguments (a registration's space, an anchor's
//! record, a submit's payer, a window's spend), so two fields of one type
//! swapped in the client's types do not pass.

use std::time::Duration;

use parity_scale_codec::{Decode, Encode};

use super::{Entry, File, Fixtures, ResultJson, SPACES, assemble, directory, hex, load, unhex};
use vos_anchor::SpaceGenesis;

use crate::kreivo::calls::{
    self, Active, AnchorRecord, AuthorityInfo, Call, Event, Evidence, Failure, PALLET, ProgramInfo,
    RuntimeCall, SpaceInfo, Spend, keys,
};
use crate::kreivo::mock::Constants;
use crate::kreivo::mock::transport::{MockChain, MockTransport};
use crate::kreivo::transport::{Invalid, Sender, Sent, Transport, Unsent};

/// The result a call's failure reports, as the vectors write it.
fn result_of(failure: Option<Failure>) -> ResultJson {
    match failure {
        None => ResultJson::Ok,
        Some(Failure::Module { pallet, error }) if pallet == PALLET => ResultJson::Module(error),
        Some(Failure::BadOrigin) => ResultJson::BadOrigin,
        Some(Failure::Token(0)) => ResultJson::FundsUnavailable,
        Some(other) => panic!("a failure the vectors do not hold: {other:?}"),
    }
}

/// `T` decoded from all of `value`, and encoded again.
fn again<T: Decode + Encode>(value: &[u8]) -> Option<Vec<u8>> {
    calls::read::<T>(value).map(|value| value.encode())
}

fn array<const N: usize>(key: &[u8], at: usize) -> [u8; N] {
    key[at..at + N].try_into().expect("a key part")
}

/// Each item the vectors write: its name, its key rebuilt by the client's
/// builder from the parts the key holds in the clear, and its value
/// through the client's type.
type Item = (
    &'static str,
    fn(&[u8]) -> Vec<u8>,
    fn(&[u8]) -> Option<Vec<u8>>,
);

const ITEMS: [Item; 12] = [
    (
        "Spaces",
        |k| keys::spaces(&array(k, 32)),
        again::<SpaceInfo>,
    ),
    (
        "SovereignOf",
        |k| keys::sovereign_of(&array(k, 48)),
        again::<[u8; 32]>,
    ),
    (
        "Authorities",
        |k| keys::authorities(&array(k, 32), &array(k, 80)),
        again::<AuthorityInfo>,
    ),
    (
        "AnchorKeys",
        |k| keys::anchor_keys(&array(k, 32), &array(k, 64)),
        again::<Option<[u8; 32]>>,
    ),
    (
        "Anchors",
        |k| keys::anchors(&array(k, 32), k[72], u64::from_le_bytes(array(k, 81))),
        again::<AnchorRecord>,
    ),
    ("Last", |k| keys::last(&array(k, 32), k[72]), again::<u64>),
    (
        "Equivocations",
        |k| keys::equivocations(&array(k, 32), k[72], u64::from_le_bytes(array(k, 81))),
        again::<Evidence>,
    ),
    ("Budget", |k| keys::budget(&array(k, 32)), again::<Spend>),
    (
        "Formats",
        |k| keys::formats(u32::from_le_bytes(array(k, 40))),
        again::<Active>,
    ),
    (
        "Programs",
        |k| {
            let words: [u8; 32] = array(k, 48);
            let program = std::array::from_fn(|i| u32::from_le_bytes(array(&words, 4 * i)));
            keys::programs(&program)
        },
        again::<ProgramInfo>,
    ),
    ("Seen", |k| keys::seen(&array(k, 32)), again::<u64>),
    ("Paused", |_| keys::paused(), again::<u8>),
];

/// A storage write as the client reads it: the value it reads at the key,
/// the key its builder makes, the value its type.
fn read_back(transport: &MockTransport, entry: &Entry, at: &str) {
    let key = unhex(&entry.key);
    let stored = transport.storage(&key).unwrap();
    if let Some(masked) = entry.value.as_ref().filter(|value| value.contains('?')) {
        let read = hex(&stored.unwrap_or_default());
        let held = read.len() == masked.len()
            && read
                .bytes()
                .zip(masked.bytes())
                .all(|(read, masked)| masked == b'?' || read == masked);
        assert!(held, "{at}: {}: {read} is not {masked}", entry.key);
        return;
    }
    let value = entry.value.as_deref().map(unhex);
    assert_eq!(stored, value, "{at}: {}", entry.key);
    let (name, rebuild, decode) = ITEMS
        .iter()
        .find(|(name, ..)| key.starts_with(&keys::plain("Spaces", name)))
        .unwrap_or_else(|| panic!("{at}: {}: no item's key", entry.key));
    assert_eq!(rebuild(&key), key, "{at}: {name}'s key");
    if let Some(value) = value {
        assert_eq!(decode(&value), Some(value), "{at}: {name}'s value");
    }
}

/// The value at `key` as the client reads it, as `T`.
fn read_as<T: Decode>(transport: &dyn Transport, key: &[u8], at: &str) -> T {
    let bytes = transport.storage(key).unwrap();
    calls::read(&bytes.unwrap_or_else(|| panic!("{at}: nothing at {}", hex(key))))
        .unwrap_or_else(|| panic!("{at}: {} does not decode", hex(key)))
}

/// What a call Ok did, as the client reads it, from the call's own
/// arguments: no two fields of one type swapped passes.
fn means(transport: &dyn Transport, call: &Call, events: &[Event], now_ms: u64, at: &str) {
    match call {
        Call::Register {
            genesis,
            controller,
            start_window,
            ..
        } => {
            let genesis = SpaceGenesis::decode(genesis).expect("a registered genesis");
            let space = vos_anchor::space_id(&genesis);
            let info: SpaceInfo = read_as(transport, &keys::spaces(&space.0), at);
            let sovereign = calls::sovereign(&space);
            assert_eq!(info.sovereign, sovereign, "{at}: the sovereign");
            assert_eq!(info.controller, *controller, "{at}: the controller");
            assert_eq!(info.origin_ms, genesis.clock.origin_ms, "{at}: the origin");
            assert_eq!(info.length_ms, genesis.clock.length_ms, "{at}: the length");
            assert_eq!(info.start_window, *start_window, "{at}: the start");
            assert_eq!(info.registered_ms, now_ms, "{at}: registered at");
            assert_eq!(info.end_window, None, "{at}");
            assert!(
                events.contains(&Event::SpaceRegistered {
                    space: space.0,
                    sovereign,
                    controller: *controller,
                    origin_ms: genesis.clock.origin_ms,
                    length_ms: genesis.clock.length_ms,
                    start_window: *start_window,
                }),
                "{at}: SpaceRegistered"
            );
        }
        Call::Anchor { anchor } => {
            let anchored = Event::Anchored {
                space: anchor.space,
                kind: anchor.kind,
                window: anchor.window,
                root: anchor.root,
            };
            if events.contains(&anchored) {
                let key = keys::anchors(&anchor.space, anchor.kind, anchor.window);
                let record: AnchorRecord = read_as(transport, &key, at);
                assert_eq!(record.root, anchor.root, "{at}: the root");
                assert_eq!(record.signer, anchor.signer, "{at}: the signer");
                assert_eq!(record.at_ms, now_ms, "{at}: anchored at");
                let last: u64 = read_as(transport, &keys::last(&anchor.space, anchor.kind), at);
                assert_eq!(last, anchor.window, "{at}: Last");
            } else {
                assert!(
                    events.iter().any(
                        |event| matches!(event, Event::Equivocated { space, window, .. }
                            if *space == anchor.space && *window == anchor.window)
                    ),
                    "{at}: an anchor Ok is anchored or equivocates"
                );
            }
        }
        Call::Submit { payer, .. } => {
            for event in events {
                if let Event::Accepted { payer: of, .. } | Event::Refused { payer: of, .. } = event
                {
                    assert_eq!(of, payer, "{at}: the payer");
                }
            }
        }
        Call::AddAuthority {
            space,
            who,
            anchor_key,
        } => {
            let info: AuthorityInfo = read_as(transport, &keys::authorities(space, who), at);
            assert_eq!(info.anchor_key, *anchor_key, "{at}: the paired key");
        }
        Call::SetBudget {
            space,
            max_spend_per_window,
        } => {
            let info: SpaceInfo = read_as(transport, &keys::spaces(space), at);
            assert_eq!(info.max_spend_per_window, *max_spend_per_window, "{at}");
        }
        _ => {}
    }
}

/// Every `Budget` written is the window's by the venue's time, through the
/// space's clock.
fn spends(transport: &dyn Transport, written: &[Entry], now_ms: u64, at: &str) {
    let prefix = keys::plain("Spaces", "Budget");
    for entry in written {
        let key = unhex(&entry.key);
        let (true, Some(value)) = (key.starts_with(&prefix), &entry.value) else {
            continue;
        };
        let space: [u8; 32] = array(&key, 32);
        // Its `window`, the value's first field: its `spent` may be masked.
        let window: [u8; 8] = unhex(&value[..16]).try_into().expect("a window");
        let window = u64::from_le_bytes(window);
        let info: SpaceInfo = read_as(transport, &keys::spaces(&space), at);
        assert_eq!(
            Some(window),
            info.clock().window(now_ms),
            "{at}: the spend's window"
        );
    }
}

/// Every vector, its calls sent through the client over a fresh mock in
/// the vector's pre-state, does what it says as the client reads it.
#[test]
fn the_client_passes_every_vector() {
    let fixtures = Fixtures::load();
    let text = std::fs::read_to_string(directory().join(SPACES)).expect("the vectors");
    let file: File = serde_json::from_str(&text).expect("the vectors parse");
    let constants = Constants::kreivo(fixtures.venue);
    let mut calls = 0;
    for vector in &file.vectors {
        let chain = MockChain::new(load(&constants, vector.fees, &vector.pre));
        for (n, step) in vector.steps.iter().enumerate() {
            let at = format!("{} step {n}", vector.id);
            chain.with(|chain| chain.set_now(step.now_ms));
            let (Some(parts), Some(origin)) = (&step.call, step.origin) else {
                chain.with(|chain| chain.on_idle());
                let reader = chain.transport(crate::kreivo::mock::Origin::Root);
                step.storage
                    .iter()
                    .for_each(|entry| read_back(&reader, entry, &at));
                continue;
            };
            let bytes = assemble(parts, &fixtures.files);
            let decoded = calls::read::<RuntimeCall>(&bytes).filter(|call| match call {
                RuntimeCall::Spaces(call) => call.within(),
                RuntimeCall::Balances(_) => false,
            });
            match &decoded {
                Some(RuntimeCall::Spaces(call)) => assert_eq!(call.bytes(), bytes, "{at}"),
                _ => assert_eq!(step.result, Some(ResultJson::Undecodable), "{at}"),
            }
            let transport = chain.transport(origin.into());
            let sender = Sender::new(transport.clone(), Duration::from_millis(1));
            let mut events = Vec::new();
            let result = match sender.call(&bytes) {
                Ok(Sent::Included(outcome)) => {
                    events.clone_from(&outcome.events);
                    assert!(outcome.unread.is_empty(), "{at}: {:?}", outcome.unread);
                    let encoded: Vec<String> = outcome
                        .events
                        .iter()
                        .map(|event| hex(&event.encode()))
                        .collect();
                    assert_eq!(encoded, step.events, "{at}: the events");
                    result_of(outcome.failure)
                }
                Err(Unsent::Invalid(Invalid::Payment)) => ResultJson::InvalidPayment,
                Err(Unsent::Invalid(Invalid::Call)) => ResultJson::Undecodable,
                other => panic!("{at}: {other:?}"),
            };
            assert_eq!(Some(result), step.result, "{at}: the result");
            step.storage
                .iter()
                .for_each(|entry| read_back(&transport, entry, &at));
            if let (Some(RuntimeCall::Spaces(call)), ResultJson::Ok) = (&decoded, result) {
                means(&*transport, call, &events, step.now_ms, &at);
            }
            spends(&*transport, &step.storage, step.now_ms, &at);
            calls += 1;
        }
    }
    assert!(calls > 100, "{calls} calls");
}
