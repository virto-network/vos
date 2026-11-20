//! The demo end to end as far as it runs without a phone: one node of a
//! founded space, the gateway's SSH port serving the screens, and a
//! headless s4 client under a key drawn for its connection, its
//! `vos.credential` facility s4's own (`s4-credential`) proving with this
//! tree's device library, its secret source a software HMAC key and its
//! chrome a script, the stock kernels' release artifacts this tree's
//! credential actor's. The client enrolls, the operator invites the two
//! digests it shows, it claims them, signs in on the path it fetched apart
//! by the stock auth kernel, and pays from its account by the stock owner
//! kernel: what the chrome confirmed is paid, whatever the document's fields
//! held. The facility sends each proof itself, to the onion its enrollment
//! pinned (here a dial to the gateway's port in process), and hands the
//! screen the node's answer; a client that hands back a request instead is
//! refused by the gateway before any node.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{PublicKeyOrCertificate, ssh_key};
use russh::{ChannelMsg, client};
use s4_protocol::{Message, Value};
use vos_facility::chrome::{Answer, Chrome, Form};
use vos_facility::enrollment::Store;
use vos_facility::net::Net;
use vos_facility::source::BoxFuture;
use vos_facility::{Facility, Gateway, Operation, Session, Stock};
use vos_gateway_demo::{LocalSpace, host_key, local, random};
use vos_light::tor::{Circuit, Dial, Dialing, Stream, Target};

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

/// Every stream the facility dials, to the onion it pinned, goes to the
/// gateway's SSH port in process: Tor's part played by a socket.
struct Local(std::net::SocketAddr);

impl Dial for Local {
    fn dial(&self, target: &Target, _circuit: Circuit) -> Dialing {
        let (address, onion) = (self.0, matches!(target, Target::Onion { .. }));
        Box::pin(async move {
            assert!(onion, "the facility's requests go to the onion alone");
            let stream = tokio::net::TcpStream::connect(address).await?;
            Ok(Box::new(stream) as Stream)
        })
    }
}

/// A host key seen: its fingerprint and its Ed25519 key.
type Seen = Arc<Mutex<Option<(String, Option<[u8; 32]>)>>>;

/// Pins the host key it first sees.
struct Pinning(Seen);

impl client::Handler for Pinning {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };
        *self.0.lock().unwrap() = Some((
            key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            key.key_data().ed25519().map(|key| key.0),
        ));
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
    /// A result to answer every facility call with, as a hostile client
    /// would.
    hostile: Option<Value>,
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
                facilities: vec![ty(vos_facility::FACILITY)],
                ..Default::default()
            },
            grants: s4_protocol::Grants {
                facilities: vec![s4_protocol::Permission {
                    ty: ty(vos_facility::FACILITY),
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
        let (fingerprint, host_key) = pinned.lock().unwrap().clone().expect("a host key");
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
                application: String::new(),
                host_key,
                // The facility's dial plays Tor's part: the session is
                // carried.
                carried: true,
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
                            .contains(&ty(vos_facility::FACILITY))
                    );
                    let session = self.facility.session(Gateway {
                        application: hello.application.as_str().to_owned(),
                        ..self.gateway.clone()
                    });
                    // The user grants the facility for this session.
                    session.granted();
                    self.session = Some(session);
                }
                Message::FacilityCall(call) => {
                    let result = match &self.hostile {
                        Some(result) => Ok(result.clone()),
                        None => {
                            let session = self.session.as_ref().expect("granted");
                            match Operation::read(call.operation.as_str(), &call.args) {
                                Ok(operation) => session
                                    .call(operation, &*self.user)
                                    .await
                                    .map(|outcome| outcome.to_value())
                                    .map_err(Into::into),
                                Err(refusal) => Err(refusal.into()),
                            }
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
    hex::decode(shown).unwrap().try_into().unwrap()
}

/// The stock kernels' release artifacts of this tree's credential actor,
/// which the space installs: the ones s4's facility embeds, so a pin of s4
/// whose artifacts are another credential actor's fails here. They follow
/// the actor's code and data and the transpiler, never another crate's
/// edit that leaves those as they are.
fn stock() -> Stock {
    let elf = std::fs::read(vos_testkit::programs::program_elf("vos-credentials")).unwrap();
    let artifact =
        |kernel| vos_abi::Encode::encode(&vos_light::release::device(&elf, kernel).unwrap());
    let stock = Stock {
        auth: artifact("auth"),
        owner: artifact("owner"),
    };
    assert!(
        stock == Stock::embedded(),
        "s4's embedded stock artifacts are not this tree's: the credential actor's code or the \
         transpiler moved; run s4's `just vos-release` at this tree and re-pin s4"
    );
    stock
}

/// A local space and its gateway, and a headless client on its SSH port.
async fn demo(user: Arc<User>) -> (Arc<LocalSpace>, Headless, [tempfile::TempDir; 2]) {
    let data = tempfile::tempdir().unwrap();
    let space = tokio::task::block_in_place(|| {
        Arc::new(LocalSpace::found(data.path(), random(), random()).unwrap())
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = local(&listener);
    let _gateway = space.gateway(listener, host_key(), random(), vec![random()]);
    let store = tempfile::tempdir().unwrap();
    let net = Arc::new(Net::new(Arc::new(Local(address)), store.path()));
    let facility = Facility::new(
        Store::new(store.path()),
        Arc::new(vos_facility::testing::Phone::new(random::<1>()[0])),
        net,
    )
    .with_stock(stock())
    .with_tick(Duration::from_millis(200));
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
    user.will(confirm(&[]));
    user.will(confirm(&[]));
    let at = phone.click("Enroll this device").await;
    phone.settle(at, &["in its own window"]).await;
    let enrolled = user.shown.lock().unwrap()[0].clone();
    let digests = user.shown.lock().unwrap()[1].clone();
    assert_eq!(digests.title, "This device's digests");
    let member = digest(&digests.rows[0].1);
    let owner = digest(&digests.rows[1].1);
    assert_eq!(enrolled.title, "Enroll this device");
    assert!(
        enrolled
            .rows
            .iter()
            .any(|(_, value)| value.contains("vote (once in scope “vote”)"))
    );
    phone.settle(0, &["sign in from the next session"]).await;
    tokio::task::block_in_place(|| {
        assert!(
            space.invite(member, "alice", owner).unwrap(),
            "the invitation claims the device the screens enrolled"
        );
        space.open_account("shop", some_owner(), 50).unwrap();
        space.open_account("mallory", some_owner(), 0).unwrap();
    });
    tokio::task::block_in_place(|| space.mint("alice", 50).unwrap());

    // Pay: the document's fields say 999 to mallory; the user confirms 20
    // to shop in the chrome, and that is what is paid.
    let at = phone.click("Pay").await;
    phone.settle(at, &["Pay from this device's account"]).await;
    phone.type_into("To account", "mallory").await;
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

    // This session showed the device's digests: it signs in nothing, so
    // the server cannot join the sign-in to them. A new session signs in.
    let at = phone.click("Sign in").await;
    phone
        .settle(at, &["reconnect, and sign in from the new session"])
        .await;
    let facility = phone.facility.clone();
    let address =
        std::net::SocketAddr::new(phone.gateway.host.parse().unwrap(), phone.gateway.port);
    drop(phone);
    let mut phone = Headless::connect(address, facility, Arc::clone(&user)).await;
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
                &[
                    "Signed in as",
                    "no-path",
                    "unclaimed",
                    "Not done",
                    "refused",
                    "failed",
                ],
            )
            .await;
        if shown.contains("Signed in as") {
            break shown;
        }
        // The tree not read to its end, or read before the claim.
        assert!(
            shown.contains("no-path") || shown.contains("unclaimed"),
            "{shown}"
        );
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
}

/// After an enrollment s4 connects again (over Tor on a phone, carried):
/// the new session, the device's digests never shown in it nor named by
/// it, signs in once the operator's invitation claimed the device the
/// screens enrolled; before that, a sign-in says to claim first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_after_the_enrollment_signs_in_once_invited() {
    let user = Arc::new(User::default());
    let (space, mut phone, _dirs) = demo(Arc::clone(&user)).await;
    user.will(confirm(&[]));
    user.will(confirm(&[]));
    let at = phone.click("Enroll this device").await;
    phone.settle(at, &["sign in from the next session"]).await;
    let digests = user.shown.lock().unwrap()[1].clone();
    let member = digest(&digests.rows[0].1);
    let owner = digest(&digests.rows[1].1);
    let facility = phone.facility.clone();
    let address =
        std::net::SocketAddr::new(phone.gateway.host.parse().unwrap(), phone.gateway.port);
    drop(phone);
    let mut phone = Headless::connect(address, facility, Arc::clone(&user)).await;
    let at = phone.click("Sign in").await;
    phone.settle(at, &["Sign in with your device"]).await;
    let unclaimed = loop {
        user.will(confirm(&[]));
        let at = phone.click("Sign in with my device").await;
        let shown = phone
            .settle(
                at,
                &[
                    "no-path",
                    "unclaimed",
                    "Signed in as",
                    "Not done",
                    "refused",
                ],
            )
            .await;
        if !shown.contains("no-path") {
            break shown;
        }
        user.answers.lock().unwrap().clear();
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    assert!(
        unclaimed.contains("claim your invitation first"),
        "{unclaimed}"
    );
    user.answers.lock().unwrap().clear();

    assert!(tokio::task::block_in_place(|| space
        .invite(member, "bob", owner)
        .unwrap()));
    assert_eq!(
        tokio::task::block_in_place(|| space.balance("bob").unwrap()),
        Some(0),
        "the account the invitation named, opened"
    );

    let signed = loop {
        user.will(confirm(&[]));
        let at = phone.click("Sign in with my device").await;
        let shown = phone
            .settle(
                at,
                &[
                    "Signed in as",
                    "no-path",
                    "unclaimed",
                    "Not done",
                    "refused",
                    "failed",
                ],
            )
            .await;
        if shown.contains("Signed in as") {
            break shown;
        }
        assert!(
            shown.contains("no-path") || shown.contains("unclaimed"),
            "{shown}"
        );
        user.answers.lock().unwrap().clear();
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    assert!(signed.contains("proved in"), "{signed}");
}

/// A client that answers the sign-in with a request of its own, for another
/// method (a once guard's next round, `vote_again`), where the node's answer
/// belongs, is refused by the gateway, and no frame reaches the node: the
/// screens relay nothing a client hands back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_naming_another_method_never_reaches_the_node() {
    let user = Arc::new(User::default());
    let (space, mut phone, _dirs) = demo(Arc::clone(&user)).await;
    let request = |instance: u32, name: &str| {
        let body = vos_wire::ingress::Credentialed {
            instance: vos_abi::ids::InstanceId(instance),
            method: vos_abi::ids::MethodId(vos_abi::ids::derive_id("vos/method/", name)),
            arguments: Vec::new(),
            nonce: [7; 16],
            expires_ms: 0,
            format: 47,
            claim: vec![0; 64],
            proof: vec![0; 64],
        };
        let mut bytes = (vos_api::Kind::Credentialed as u16).to_le_bytes().to_vec();
        vos_abi::Encode::encode_to(&(space.agent(), body), &mut bytes);
        bytes
    };
    let at = phone.click("Sign in").await;
    phone.settle(at, &["Sign in with your device"]).await;
    for (instance, name) in [
        (vos_gateway_demo::POLL.0, "vote_again"),
        (vos_gateway_demo::PAYMENTS.0, "transfer"),
        (vos_gateway_demo::CREDENTIALS.0, "claim"),
    ] {
        for field in ["request", "answer"] {
            phone.hostile = Some(Value::object([
                (field.to_owned(), Value::Bytes(request(instance, name))),
                ("proving_ms".to_owned(), Value::from(0u64)),
            ]));
            let frames = space.node().probes().api_frames();
            let at = phone.click("Sign in with my device").await;
            let shown = phone
                .settle(at, &["node's answer", "refused", "Signed in", "Not done"])
                .await;
            assert!(
                shown.contains("holds no node's answer"),
                "{name} as {field}: {shown}"
            );
            assert_eq!(
                space.node().probes().api_frames(),
                frames,
                "{name} as {field} reached the node"
            );
        }
    }
}
