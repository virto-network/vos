// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The stand-ins the facility's tests share: a software secret source, a
//! scripted chrome, and the spaces in process behind a gateway its Tor
//! client dials ([`world`]): the credential actor's tree from its feed, a
//! home's `Homes`, personal agents running `Personal`.

#![allow(dead_code, unused_imports)]

pub use std::collections::VecDeque;
pub use std::sync::{Arc, Mutex};
pub use std::time::Duration;

pub use hmac::{Hmac, Mac as _};
pub use russh::keys::ssh_key;
pub use s4_credential::chrome::{Answer, Chrome, Form};
pub use s4_credential::enrollment::Store;
pub use s4_credential::source::{BoxFuture, Kind, Output, Reference, Source, SourceError};
pub use s4_credential::{Code, Facility, Operation, Refusal, Session, Stock};
pub use s4_protocol::{Integer, Value};
pub use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
pub use vos_api::Kind as ApiKind;
pub use vos_wire::credentials::{self as tree, RootEntry};
pub use vos_wire::ids::AgentId;
pub use vos_wire::ingress::{self, Credentialed, QueryCall, Response};
pub use vos_wire::result::Outcome;
pub use vos_wire::{Decode, Encode};

pub const AGENT: u32 = 5;
pub const IDENTITY: [u8; 32] = [0x1d; 32];
pub const CREDENTIALS: u32 = 9;
pub const POLL: u32 = 3;
pub const PAYMENTS: u32 = 2;
pub const HANDLE: [u8; 32] = [0x42; 32];
pub const SPACE: [u8; 32] = [0x51; 32];
/// The stand-in node's clock: this run's start, so it is the device's.
pub fn now() -> u64 {
    static NOW: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *NOW.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    })
}

/// An HMAC-SHA-256 key in memory, standing in for the Keystore's.
pub struct Software {
    pub key: [u8; 32],
    pub uses: Mutex<usize>,
}

impl Source for Software {
    fn kinds(&self) -> Vec<Kind> {
        vec![Kind::Keystore]
    }

    fn create(&self, _kind: Kind) -> BoxFuture<'_, Result<Reference, SourceError>> {
        Box::pin(async {
            Ok(Reference::Keystore {
                alias: "test".into(),
            })
        })
    }

    fn evaluate<'a>(
        &'a self,
        _reference: &'a Reference,
        input: [u8; 32],
    ) -> BoxFuture<'a, Result<Output, SourceError>> {
        Box::pin(async move {
            *self.uses.lock().unwrap() += 1;
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.key).unwrap();
            mac.update(&input);
            Ok(Output::new(zeroize::Zeroizing::new(
                mac.finalize().into_bytes().into(),
            )))
        })
    }
}

/// Answers its forms from a script, keeping what it was shown.
#[derive(Default)]
pub struct Scripted {
    pub answers: Mutex<VecDeque<Answer>>,
    pub shown: Mutex<Vec<Form>>,
}

impl Scripted {
    pub fn will(&self, answer: Answer) {
        self.answers.lock().unwrap().push_back(answer);
    }

    pub fn last(&self) -> Form {
        self.shown.lock().unwrap().last().cloned().unwrap()
    }
}

impl Chrome for Scripted {
    fn confirm(&self, form: Form) -> BoxFuture<'_, Answer> {
        self.shown.lock().unwrap().push(form);
        let answer = self.answers.lock().unwrap().pop_front();
        Box::pin(async move { answer.unwrap_or(Answer::Declined) })
    }
}

pub fn confirm(values: &[&str]) -> Answer {
    Answer::Confirmed {
        choice: 0,
        values: values.iter().map(|value| value.to_string()).collect(),
    }
}

pub mod host;
pub mod phone;
pub mod world;

pub use world::{World, policy, wall};

/// The world with the tests' one space: its agent [`AGENT`], identity
/// [`IDENTITY`], handle [`HANDLE`] and id [`SPACE`], through onion 1.
pub fn world() -> Arc<World> {
    let world = World::new();
    world.space_at(AGENT, IDENTITY, HANDLE, SPACE, 1);
    world
}

/// The client every request of a facility under `directory` goes through,
/// over `world`'s gateway. On the test's runtime.
pub fn net(world: &Arc<World>, directory: &std::path::Path) -> Arc<s4_credential::net::Net> {
    Arc::new(s4_credential::net::Net::new(world.dial(), directory))
}

/// A facility under `directory`, its source `source`, over `world`, its
/// refreshers ticking every 100 ms.
pub fn facility(
    world: &Arc<World>,
    directory: &std::path::Path,
    source: Arc<dyn Source>,
) -> Facility {
    Facility::new(Store::new(directory), source, net(world, directory))
        .with_tick(Duration::from_millis(100))
}

/// A facility as `:vos` serves it, its store under `directory`, every
/// request through `world`'s gateway, on a runtime of its own.
pub fn node(
    world: &Arc<World>,
    directory: &std::path::Path,
    device: Arc<dyn s4_credential::node::Device>,
) -> s4_credential::node::Node {
    node_over(world.dial(), directory, device)
}

/// The same, its client dialling through `dial`.
pub fn node_over(
    dial: Arc<dyn vos_light::tor::Dial>,
    directory: &std::path::Path,
    device: Arc<dyn s4_credential::node::Device>,
) -> s4_credential::node::Node {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let net = {
        let _entered = runtime.enter();
        Arc::new(s4_credential::net::Net::new(dial, directory))
    };
    s4_credential::node::Node::over(
        runtime,
        directory.to_owned(),
        device,
        net,
        s4_credential::personal::Artifacts::embedded(),
    )
    .unwrap()
}

/// The s4 session's gateway, as the client verified it.
pub fn gateway() -> s4_credential::Gateway {
    s4_credential::Gateway {
        host: "gateway.test".into(),
        port: 2222,
        fingerprint: "SHA256:test".into(),
        application: "vos.test".into(),
        host_key: None,
    }
}

/// The SSH host key the world's gateway presents.
pub fn ssh_host_key() -> [u8; 32] {
    ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]))
        .public_key()
        .key_data()
        .ed25519()
        .unwrap()
        .0
}

pub fn object(entries: &[(&str, Value)]) -> Value {
    Value::object(
        entries
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone())),
    )
}

pub fn method(instance: u32, name: &str, guard: &str, scope: Option<(&str, bool)>) -> Value {
    let mut entries = vec![
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(instance)),
        ("name", Value::from(name)),
        ("guard", Value::from(guard)),
    ];
    if let Some((scope, once)) = scope {
        entries.push(("scope", Value::from(scope)));
        entries.push(("once", Value::Bool(once)));
    }
    object(&entries)
}

pub fn enrollment() -> Value {
    enrollment_at(HANDLE, SPACE, AGENT, IDENTITY, 1)
}

/// The enrollment in the space `space`, its handle `handle`, its agent
/// `agent` whose identity is `identity`, pinning onion `onion` (its key
/// that byte's) of the world's gateway.
pub fn enrollment_at(
    handle: [u8; 32],
    space: [u8; 32],
    agent: u32,
    identity: [u8; 32],
    onion: u8,
) -> Value {
    let method = |instance: u32, name: &str, guard: &str, scope: Option<(&str, bool)>| {
        let mut entries = vec![
            ("agent", Value::from(agent)),
            ("instance", Value::from(instance)),
            ("name", Value::from(name)),
            ("guard", Value::from(guard)),
        ];
        if let Some((scope, once)) = scope {
            entries.push(("scope", Value::from(scope)));
            entries.push(("once", Value::Bool(once)));
        }
        object(&entries)
    };
    object(&[
        ("handle", Value::Bytes(handle.to_vec())),
        ("space", Value::Bytes(space.to_vec())),
        (
            "agents",
            Value::Array(vec![object(&[
                ("agent", Value::from(agent)),
                ("identity", Value::Bytes(identity.to_vec())),
            ])]),
        ),
        (
            "methods",
            Value::Array(vec![
                method(POLL, "login", "auth", Some(("login", false))),
                method(POLL, "vote", "auth", Some(("vote", true))),
                method(PAYMENTS, "transfer", "owner", None),
            ]),
        ),
        (
            "credentials",
            object(&[
                ("agent", Value::from(agent)),
                ("instance", Value::from(CREDENTIALS)),
            ]),
        ),
        (
            "onions",
            Value::Array(vec![object(&[
                ("key", Value::Bytes(vec![onion; 32])),
                ("ssh_host_key", Value::Bytes(ssh_host_key().to_vec())),
            ])]),
        ),
        ("onion_only", Value::Bool(false)),
    ])
}

pub fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(map) = value else {
        panic!("a map: {value:?}")
    };
    map.get(name).unwrap()
}

pub fn bytes(value: &Value) -> Vec<u8> {
    let Value::Bytes(bytes) = value else {
        panic!("bytes: {value:?}")
    };
    bytes.clone()
}

/// The request's agent and body, from the kind and body the facility
/// answered.
pub fn credentialed(request: &[u8]) -> (AgentId, Credentialed) {
    assert_eq!(
        u16::from_le_bytes([request[0], request[1]]),
        ApiKind::Credentialed as u16
    );
    <(AgentId, Credentialed)>::decode_exact(&request[2..]).expect("a credentialed body")
}

/// The program of the release artifact `artifact`.
pub fn program(artifact: &[u8]) -> vos_light::DeviceProgram {
    let device = vos_light::release::Device::decode_exact(artifact).expect("a release artifact");
    vos_light::DeviceProgram::released(&device).expect("its program")
}

/// The request's proof checked as ingress's stateless checks do, under the
/// program of the release artifact `kernel`.
pub fn verified(request: &Credentialed, agent: AgentId, kernel: &[u8], name: Option<&[u8]>) {
    let proof = vos_light::Proven {
        format: request.format,
        claim: request.claim.clone(),
        proof: request.proof.clone(),
    };
    let call = vos_light::Call {
        space: SPACE,
        agent: agent.0,
        instance: request.instance.0,
        method: request.method.0,
        arguments: request.arguments.clone(),
        nonce: request.nonce,
        expires_ms: request.expires_ms,
    };
    vos_light::verify(&proof, &call, &program(kernel), name)
        .expect("the proof verifies against its call");
    assert!(request.expires_ms > wall() && request.expires_ms <= wall() + 60_000);
}

/// A server's call as s4's protocol carries it: read into its operation,
/// called, and answered as the server is.
pub trait Ask {
    fn ask<'a>(
        &'a self,
        operation: &'a str,
        arguments: &'a Value,
        chrome: &'a dyn Chrome,
    ) -> BoxFuture<'a, Result<Value, Refusal>>;
}

impl Ask for Session {
    fn ask<'a>(
        &'a self,
        operation: &'a str,
        arguments: &'a Value,
        chrome: &'a dyn Chrome,
    ) -> BoxFuture<'a, Result<Value, Refusal>> {
        Box::pin(async move {
            let operation = Operation::read(operation, arguments)?;
            Ok(self.call(operation, chrome).await?.to_value())
        })
    }
}
