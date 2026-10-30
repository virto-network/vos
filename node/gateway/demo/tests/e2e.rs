//! The demo end to end as far as it runs without a phone: one node of a
//! founded space, the gateway's SSH port serving the screens, and a
//! headless s4 client under a key drawn for its connection, its
//! `vos.credential` facility s4's own (`s4-credential`) proving with this
//! tree's device library, its secret source a software HMAC key and its
//! chrome a script. The client enrolls, the operator invites the two
//! digests it shows, it claims them, signs in on the path it fetched apart
//! and pays: what the chrome confirmed is paid, whatever the document's
//! fields held, and a request naming another method is refused by the
//! gateway before any node.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, Mac as _};
use russh::keys::ssh_key;
use russh::{ChannelMsg, client};
use s4_credential::api::Gateway;
use s4_credential::chrome::{Answer, Chrome, Form};
use s4_credential::enrollment::Store;
use s4_credential::source::{BoxFuture, Kind, Output, Reference, Source, SourceError};
use s4_credential::{Facility, Session};
use s4_protocol::{Message, Value};
use vos_gateway_demo::{LocalSpace, host_key, local, random};

/// An HMAC-SHA-256 key in memory, standing in for the phone's Keystore.
struct Software([u8; 32]);

impl Source for Software {
    fn kinds(&self) -> Vec<Kind> {
        vec![Kind::Keystore]
    }

    fn create(&self, _kind: Kind) -> BoxFuture<'_, Result<Reference, SourceError>> {
        Box::pin(async {
            Ok(Reference::Keystore {
                alias: "vos.device.test".into(),
            })
        })
    }

    fn evaluate<'a>(
        &'a self,
        _reference: &'a Reference,
        input: [u8; 32],
    ) -> BoxFuture<'a, Result<Output, SourceError>> {
        Box::pin(async move {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.0).expect("any key");
            mac.update(&input);
            Ok(Output::new(mac.finalize().into_bytes().into()))
        })
    }
}

/// The user, as a script: each form answered in turn, each kept.
#[derive(Default)]
struct User {
    answers: Mutex<VecDeque<Answer>>,
    shown: Mutex<Vec<Form>>,
}

impl User {
    fn will(&self, answer: Answer) {
        self.answers.lock().unwrap().push_back(answer);
    }
}

impl Chrome for User {
    fn confirm(&self, form: Form) -> BoxFuture<'_, Answer> {
        self.shown.lock().unwrap().push(form);
        let answer = self.answers.lock().unwrap().pop_front();
        Box::pin(async move { answer.unwrap_or(Answer::Declined) })
    }
}

fn confirm(values: &[&str]) -> Answer {
    Answer::Confirmed {
        choice: 0,
        values: values.iter().map(|value| value.to_string()).collect(),
    }
}

/// Pins the host key it first sees.
struct Pinning(Arc<Mutex<Option<String>>>);

impl client::Handler for Pinning {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        *self.0.lock().unwrap() = Some(key.fingerprint(ssh_key::HashAlg::Sha256).to_string());
        Ok(true)
    }
}

fn ty(id: &str) -> s4_protocol::TypeRef {
    s4_protocol::TypeRef::new(s4_protocol::Identifier::new(id).unwrap(), 1).unwrap()
}

/// A headless s4 client on the direct binding: the protocol's state, the
/// documents, and the facility's session once the server selected it.
struct Headless {
    channel: russh::Channel<client::Msg>,
    state: s4_protocol::SessionState,
    decoder: s4_protocol::DirectDecoder,
    limits: s4_protocol::Limits,
    facility: Facility,
    gateway: Gateway,
    session: Option<Session>,
    user: Arc<User>,
    /// A request to answer every facility call with, as a hostile client
    /// would.
    hostile: Option<Vec<u8>>,
    _handle: client::Handle<Pinning>,
}

/// Find a node of `kind` whose property `name` is `value`.
fn find<'a>(
    node: &'a s4_protocol::WidgetInstance,
    kind: &str,
    name: &str,
    value: &str,
) -> Option<&'a s4_protocol::WidgetInstance> {
    let matches = node.kind.as_str() == kind
        && node
            .props
            .get(name)
            .is_some_and(|found| *found == Value::from(value));
    if matches {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find(child, kind, name, value))
}

fn texts(node: &s4_protocol::WidgetInstance, out: &mut Vec<String>) {
    for (_, value) in node.props.iter() {
        if let Value::Text(text) = value {
            out.push(text.clone());
        }
    }
    for child in &node.children {
        texts(child, out);
    }
}

impl Headless {
    async fn connect(address: std::net::SocketAddr, facility: Facility, user: Arc<User>) -> Self {
        let pinned = Arc::new(Mutex::new(None));
        let mut handle = client::connect(
            Arc::new(client::Config::default()),
            address,
            Pinning(Arc::clone(&pinned)),
        )
        .await
        .unwrap();
        // A key drawn for this connection alone.
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&random()));
        let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
        assert!(
            handle
                .authenticate_publickey("anonymous", key)
                .await
                .unwrap()
                .success()
        );
        let mut channel = handle.channel_open_session().await.unwrap();
        channel.request_subsystem(true, "s4-ui").await.unwrap();
        assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
        let limits = s4_protocol::Limits::default();
        let hello = Message::ClientHello(s4_protocol::ClientHello {
            application: None,
            route: s4_protocol::Route::root(),
            limits,
            capabilities: s4_protocol::Capabilities {
                facilities: vec![ty(s4_credential::FACILITY)],
                ..Default::default()
            },
            grants: s4_protocol::Grants {
                facilities: vec![s4_protocol::Permission {
                    ty: ty(s4_credential::FACILITY),
                    grant: s4_protocol::Grant::Prompt,
                }],
                ..Default::default()
            },
            viewport: s4_protocol::Viewport {
                columns: 80,
                rows: 40,
                pixel_width: 640,
                pixel_height: 960,
            },
            resume: None,
        });
        let mut state = s4_protocol::SessionState::new(s4_protocol::Peer::Client, limits);
        state.sent(&hello).unwrap();
        channel
            .data_bytes(s4_protocol::encode_direct(&hello, limits).unwrap())
            .await
            .unwrap();
        let fingerprint = pinned.lock().unwrap().clone().expect("a host key");
        let mut headless = Self {
            channel,
            state,
            decoder: s4_protocol::DirectDecoder::new(limits),
            limits,
            facility,
            gateway: Gateway {
                host: address.ip().to_string(),
                port: address.port(),
                fingerprint,
            },
            session: None,
            user,
            hostile: None,
            _handle: handle,
        };
        headless.settle(0, &["VOS"]).await;
        headless
    }

    async fn send(&mut self, message: Message) {
        self.state.sent(&message).unwrap();
        self.channel
            .data_bytes(s4_protocol::encode_direct(&message, self.limits).unwrap())
            .await
            .unwrap();
    }

    /// Take one message from the server, answering a facility call.
    async fn step(&mut self, deadline: tokio::time::Instant) {
        let message = tokio::time::timeout_at(deadline, self.channel.wait())
            .await
            .unwrap_or_else(|_| panic!("nothing in time; shown {:?}", self.shown()))
            .expect("the channel open");
        let ChannelMsg::Data { data } = message else {
            return;
        };
        for message in self.decoder.push(&data).unwrap() {
            self.state.received(&message).unwrap();
            match message {
                Message::ServerHello(hello) => {
                    assert!(
                        hello
                            .capabilities
                            .facilities
                            .contains(&ty(s4_credential::FACILITY))
                    );
                    let session = self
                        .facility
                        .session(self.gateway.clone(), hello.application.as_str().to_owned());
                    // The user grants the facility for this session.
                    session.granted();
                    self.session = Some(session);
                }
                Message::FacilityCall(call) => {
                    let result = match &self.hostile {
                        Some(request) => Ok(Value::object([
                            ("request".to_owned(), Value::Bytes(request.clone())),
                            ("proving_ms".to_owned(), Value::from(0u64)),
                        ])),
                        None => {
                            let session = self.session.as_ref().expect("granted");
                            session
                                .call(call.operation.as_str(), &call.args, &*self.user)
                                .await
                        }
                    };
                    self.send(Message::FacilityResult(s4_protocol::FacilityResult {
                        call: call.call,
                        result,
                    }))
                    .await;
                }
                _ => {}
            }
        }
    }

    fn revision(&self) -> u64 {
        self.state
            .documents()
            .document()
            .map_or(0, |document| document.revision)
    }

    fn shown(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(document) = self.state.documents().document() {
            texts(&document.root, &mut out);
        }
        out
    }

    /// Take messages until a document past revision `after` shows a text
    /// holding one of `needles`: that text.
    async fn settle(&mut self, after: u64, needles: &[&str]) -> String {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        loop {
            if self.revision() > after
                && let Some(found) = self
                    .shown()
                    .into_iter()
                    .find(|text| needles.iter().any(|needle| text.contains(needle)))
            {
                return found;
            }
            self.step(deadline).await;
        }
    }

    async fn event(
        &mut self,
        kind: &str,
        name: &str,
        value: &str,
        event: impl FnOnce(u64) -> s4_protocol::UiEvent,
    ) -> u64 {
        let document = self
            .state
            .documents()
            .document()
            .expect("a document")
            .clone();
        let node = find(&document.root, kind, name, value)
            .unwrap_or_else(|| panic!("no {kind} {name}={value:?} in {:?}", self.shown()))
            .id;
        let sequence = self.state.next_client_event_sequence().unwrap();
        let event = Message::Event(s4_protocol::Event {
            sequence,
            context: s4_protocol::EventContext {
                document: document.document,
                revision: document.revision,
                target_generation: self.state.documents().generation(node),
            },
            event: event(node),
        });
        self.send(event).await;
        document.revision
    }

    /// Activate the button `label`: the revision it acted on.
    async fn click(&mut self, label: &str) -> u64 {
        self.event("s4.button", "label", label, |node| {
            s4_protocol::UiEvent::Activate { node }
        })
        .await
    }

    /// Type `value` into the field whose placeholder is `placeholder`, and
    /// wait until the server has it.
    async fn type_into(&mut self, placeholder: &str, value: &str) {
        let typed = value.to_owned();
        let at = self
            .event("s4.field", "placeholder", placeholder, move |node| {
                s4_protocol::UiEvent::Input { node, value: typed }
            })
            .await;
        self.settle(at, &[value]).await;
    }
}

fn digest(shown: &str) -> [u8; 32] {
    let hex = shown.rsplit(' ').next().unwrap();
    hex::decode(hex).unwrap().try_into().unwrap()
}

/// A local space and its gateway, and a headless client on its SSH port.
async fn demo(user: Arc<User>) -> (Arc<LocalSpace>, Headless, [tempfile::TempDir; 2]) {
    let data = tempfile::tempdir().unwrap();
    let space = tokio::task::block_in_place(|| {
        Arc::new(LocalSpace::found(data.path(), random(), random()).unwrap())
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = local(&listener);
    let _gateway = space.gateway(listener, host_key(), random());
    let store = tempfile::tempdir().unwrap();
    let facility = Facility::with_root_poll(
        Store::new(store.path()),
        Arc::new(Software(random())),
        Duration::from_millis(200),
    );
    let phone = Headless::connect(address, facility, user).await;
    (space, phone, [data, store])
}

/// A digest of 32 random bytes, each word below p.
fn some_owner() -> [u8; 32] {
    random::<32>().map(|byte| byte & 0x3f)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_sign_in_and_pay_through_the_gateways_ssh_port() {
    let user = Arc::new(User::default());
    let (space, mut phone, _dirs) = demo(Arc::clone(&user)).await;

    // Enroll: the chrome shows what is pinned; the device answers its two
    // digests, which the operator invites before the claim.
    phone.type_into("Your row's name", "alice").await;
    user.will(confirm(&[]));
    let at = phone.click("Enroll this device").await;
    let member = digest(&phone.settle(at, &["Member digest"]).await);
    let owner = digest(&phone.settle(0, &["Owner digest"]).await);
    let enrolled = user.shown.lock().unwrap()[0].clone();
    assert_eq!(enrolled.title, "Enroll this device");
    assert!(
        enrolled
            .rows
            .iter()
            .any(|(_, value)| value.contains("vote (once in scope “vote”)"))
    );
    tokio::task::block_in_place(|| {
        space.invite(member, "alice", owner).unwrap();
        space.open_row("shop", some_owner(), 50).unwrap();
        space.open_row("mallory", some_owner(), 0).unwrap();
    });
    let at = phone.click("Claim").await;
    let claimed = phone
        .settle(at, &["Claimed", "refused", "failed", "Not"])
        .await;
    assert!(claimed.starts_with("Claimed: member at slot"), "{claimed}");
    tokio::task::block_in_place(|| space.mint("alice", 50).unwrap());

    // Sign in, on the path the device fetched apart from its proofs: tried
    // again while the device is still fetching it.
    let at = phone.click("Sign in").await;
    phone.settle(at, &["Sign in with your device"]).await;
    let signed = loop {
        user.will(confirm(&[]));
        let at = phone.click("Sign in with my device").await;
        let shown = phone
            .settle(
                at,
                &["Signed in as", "no-path", "Not done", "refused", "failed"],
            )
            .await;
        if shown.contains("Signed in as") {
            break shown;
        }
        assert!(shown.contains("no-path"), "{shown}");
        user.answers.lock().unwrap().clear();
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    assert!(signed.contains("proved in"), "{signed}");
    let sign_in = user.shown.lock().unwrap().last().cloned().unwrap();
    assert!(sign_in.notice.is_none(), "a sign-in spends no admission");
    assert!(
        sign_in
            .rows
            .iter()
            .any(|(_, value)| value.contains("login (scope “login”)"))
    );

    // Pay: the document's fields say 999 to mallory; the user confirms 20
    // to shop in the chrome, and that is what is paid.
    let at = phone.click("Pay").await;
    phone.settle(at, &["Pay from your row"]).await;
    phone.type_into("To row", "mallory").await;
    phone.type_into("Amount", "999").await;
    user.will(confirm(&["shop", "20"]));
    let at = phone.click("Send the payment").await;
    let paid = phone
        .settle(at, &["Paid", "Not done", "refused", "failed"])
        .await;
    assert!(paid.starts_with("Paid 20 to shop"), "{paid}");
    let form = user.shown.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        form.fields[0].value, "mallory",
        "the document's pre-fill, shown"
    );
    assert_eq!(form.fields[1].value, "999");
    phone.settle(0, &["Balance of alice: 30"]).await;
    let balances = tokio::task::block_in_place(|| {
        (
            space.balance("alice").unwrap(),
            space.balance("shop").unwrap(),
            space.balance("mallory").unwrap(),
        )
    });
    assert_eq!(balances, (Some(30), Some(70), Some(0)));
}

/// A client that answers the sign-in with a request for another method
/// (a once guard's next round, `vote_again`) is refused by the gateway, and
/// no frame reaches the node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_naming_another_method_never_reaches_the_node() {
    let user = Arc::new(User::default());
    let (space, mut phone, _dirs) = demo(Arc::clone(&user)).await;
    let request = |instance: u32, name: &str| {
        let body = vos_wire::ingress::Credentialed {
            instance: vos_wire::ids::InstanceId(instance),
            method: vos_wire::ids::MethodId(vos_wire::ids::derive_id("vos/method/", name)),
            arguments: Vec::new(),
            nonce: [7; 16],
            expires_ms: 0,
            format: 44,
            public: vos_wire::ingress::CredentialPublic::Owner {
                owner: [0; 32],
                binding: [0; 32],
            },
            proof: vec![0; 64],
        };
        let mut bytes = (vos_api::Kind::Credentialed as u16).to_le_bytes().to_vec();
        vos_wire::Encode::encode_to(&(space.agent(), body), &mut bytes);
        bytes
    };
    let at = phone.click("Sign in").await;
    phone.settle(at, &["Sign in with your device"]).await;
    for (instance, name) in [
        (vos_gateway_demo::POLL.0, "vote_again"),
        (vos_gateway_demo::PURSES.0, "transfer"),
        (vos_gateway_demo::CREDENTIALS.0, "claim"),
    ] {
        phone.hostile = Some(request(instance, name));
        let frames = space.node().api_frames();
        let at = phone.click("Sign in with my device").await;
        let shown = phone
            .settle(at, &["names another", "refused", "Signed in", "Not done"])
            .await;
        assert!(
            shown.contains("names another agent or method"),
            "{name}: {shown}"
        );
        assert_eq!(space.node().api_frames(), frames, "{name} reached the node");
    }
}
