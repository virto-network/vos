//! The demo's three screens on the SSH port (`slice-7-mobile.md` 7.13):
//! *Enroll*, *Sign in* and *Pay*, server-owned s4 documents over the
//! credential actor and the `purses` ledger of one agent. The proofs are
//! the member's device's: the client's `vos.credential` facility, which the
//! app asks and whose answer, a node-API `Credentialed` request, the gateway
//! relays as it is after checking it names this agent and the screen's
//! method. The gateway builds no credential bytes and holds no authority;
//! its app key sends only the claims an operator's invitations allow.

use std::sync::Arc;

use s4_server::rui::{App, Cx, Effect, EffectOutput, EffectRequest, View, ViewContext, view};
use s4_server::{HostServiceError, HostServiceRequest, Identifier, Value};
use tokio::sync::{Mutex, OnceCell};
use vos_api::{FRAME_ERROR, Kind};
use vos_wire::abi::Failure;
use vos_wire::credentials::{CredentialError, RootEntry};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session, derive_id};
use vos_wire::ingress::{AgentInfo, CredentialRefusal, Credentialed, Rejection, Response};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, SpaceId};

use crate::Gateway;
use crate::app::AppClient;

/// The host service the screens call, server-side.
pub const SERVICE: &str = "vos.gateway";
/// The client facility that proves.
pub const FACILITY: &str = "vos.credential";
/// The application identity the screens are served as.
pub const APPLICATION: &str = "vos.gateway";

/// The agent the demo serves and its actors' instances, from the gateway's
/// file.
#[derive(Clone, Copy, Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Demo {
    pub agent: u32,
    pub credentials: u32,
    pub purses: u32,
    pub poll: u32,
}

/// The guarded methods the device is asked to pin, and the ledger's.
const LOGIN: &str = "login";
const VOTE: &str = "vote";
const TRANSFER: &str = "transfer";

fn method(name: &str) -> MethodId {
    MethodId(derive_id("vos/method/", name))
}

/// What the app learned of the space, once.
#[derive(Clone, Copy)]
struct Space {
    identity: [u8; 32],
    space: SpaceId,
    handle: [u8; 32],
}

/// The screens' server side: reads, the claims under the app's key, and the
/// relay of what the device proved.
pub struct Service {
    demo: Demo,
    gateway: Arc<Gateway>,
    app: Arc<AppClient>,
    space: OnceCell<Space>,
    /// The app key's session with the agent and its next sequence: one
    /// claim at a time, in order.
    session: Mutex<Option<(Session, u64)>>,
}

fn identifier(text: &str) -> Identifier {
    Identifier::new(text).expect("a valid identifier")
}

fn failed(message: impl Into<String>) -> HostServiceError {
    HostServiceError::new(identifier("vos.gateway.failed"), message)
}

fn field<'a>(args: &'a Value, name: &str) -> Result<&'a Value, HostServiceError> {
    match args {
        Value::Map(map) => map
            .get(name)
            .ok_or_else(|| failed(format!("`{name}` is missing"))),
        _ => Err(failed("the arguments are a map")),
    }
}

fn bytes<'a>(args: &'a Value, name: &str) -> Result<&'a [u8], HostServiceError> {
    match field(args, name)? {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(failed(format!("`{name}` is bytes"))),
    }
}

fn text<'a>(args: &'a Value, name: &str) -> Result<&'a str, HostServiceError> {
    match field(args, name)? {
        Value::Text(text) => Ok(text),
        _ => Err(failed(format!("`{name}` is text"))),
    }
}

fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::object(
        entries
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value)),
    )
}

/// A frame's body, or why there is none.
fn answered((kind, body): vos_api::client::Answer) -> Result<Vec<u8>, HostServiceError> {
    if kind == FRAME_ERROR {
        return Err(failed("the node is unavailable"));
    }
    Ok(body)
}

/// How a method's own error reads on the screen.
type Errors = fn(&[u8]) -> String;

fn method_error(_detail: &[u8]) -> String {
    "the method refused".into()
}

/// The names of the `purses` ledger's errors, by index.
const PURSE_ERRORS: [&str; 9] = [
    "a bad row name",
    "the row exists",
    "no such row",
    "not invited",
    "the invitation expired",
    "not the row's owner",
    "the row is frozen",
    "insufficient balance",
    "the balance would overflow",
];

/// A method's outcome, as the screen says it.
fn outcome(outcome: &Outcome, errors: Errors) -> Result<Vec<u8>, String> {
    match outcome {
        Outcome::Done(reply) => Ok(reply.clone()),
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } => Err(errors(detail)),
        Outcome::Failed { code, .. } => Err(format!("failed: {code:?}")),
        Outcome::Started(_) => Err("started a workflow".into()),
    }
}

fn purse_error(detail: &[u8]) -> String {
    detail
        .first()
        .and_then(|index| PURSE_ERRORS.get(usize::from(*index)))
        .map_or_else(|| "the ledger refused".into(), |name| (*name).into())
}

fn credential_error(detail: &[u8]) -> String {
    CredentialError::decode_exact(detail).map_or_else(
        || "the credential actor refused".into(),
        |error| format!("{error:?}"),
    )
}

/// A node's answer, as the screen says it.
fn response(answer: &Response, errors: Errors) -> Result<Vec<u8>, String> {
    match answer {
        Response::Ran { outcome: ran, .. } => outcome(ran, errors),
        Response::Rejected(Rejection::Credential(refusal)) => {
            Err(format!("refused at ingress: {refusal:?}"))
        }
        Response::Refused(refusal) => Err(format!("refused at apply: {refusal:?}")),
        other => Err(format!("{other:?}")),
    }
}

impl Service {
    pub fn new(demo: Demo, gateway: Arc<Gateway>, app: Arc<AppClient>) -> Self {
        Self {
            demo,
            gateway,
            app,
            space: OnceCell::new(),
            session: Mutex::new(None),
        }
    }

    fn agent(&self) -> AgentId {
        AgentId(self.demo.agent)
    }

    async fn time(&self) -> Result<u64, HostServiceError> {
        let body = answered(self.gateway.relay(Kind::Time, &[]).await)?;
        u64::decode_exact(&body).ok_or_else(|| failed("the node's time does not decode"))
    }

    async fn space(&self) -> Result<Space, HostServiceError> {
        self.space
            .get_or_try_init(|| async {
                let body = answered(
                    self.gateway
                        .relay(Kind::AgentInfo, &self.agent().encode())
                        .await,
                )?;
                let info = Option::<AgentInfo>::decode_exact(&body)
                    .flatten()
                    .ok_or_else(|| failed("the node serves no such agent"))?;
                let identity = vos_pvm_precompiles::blake2b_256(&info.record.encode());
                let handle: [u8; 32] = self
                    .query(
                        &identity,
                        self.demo.credentials,
                        "handle",
                        Vec::new(),
                        credential_error,
                    )
                    .await?
                    .as_slice()
                    .try_into()
                    .map_err(|_| failed("the handle does not decode"))?;
                Ok(Space {
                    identity,
                    space: info.record.space,
                    handle,
                })
            })
            .await
            .copied()
    }

    async fn query(
        &self,
        identity: &[u8; 32],
        instance: u32,
        name: &str,
        arguments: Vec<u8>,
        errors: Errors,
    ) -> Result<Vec<u8>, HostServiceError> {
        let now = self.time().await?;
        let body = answered(
            self.app
                .query(
                    self.agent(),
                    identity,
                    now + 60_000,
                    InstanceId(instance),
                    method(name),
                    arguments,
                )
                .await,
        )?;
        let answer = Response::decode_exact(&body)
            .ok_or_else(|| failed("an answer that does not decode"))?;
        response(&answer, errors).map_err(failed)
    }

    /// One call under the app's key, in its session: a new session when the
    /// agent refuses the one held for good.
    async fn call(
        &self,
        instance: u32,
        name: &str,
        arguments: Vec<u8>,
        errors: Errors,
    ) -> Result<Vec<u8>, HostServiceError> {
        let space = self.space().await?;
        let mut held = self.session.lock().await;
        for _ in 0..2 {
            let (session, sequence) = match *held {
                Some(kept) => kept,
                None => {
                    let mut name = [0u8; 16];
                    getrandom::getrandom(&mut name).map_err(|error| failed(error.to_string()))?;
                    let session = Session {
                        key: self.app.key(),
                        name,
                        t0: self.time().await?,
                    };
                    (session, 1)
                }
            };
            let body = answered(
                self.app
                    .call(
                        self.agent(),
                        &space.identity,
                        session,
                        sequence,
                        InstanceId(instance),
                        method(name),
                        arguments.clone(),
                    )
                    .await,
            )?;
            let answer = Response::decode_exact(&body)
                .ok_or_else(|| failed("an answer that does not decode"))?;
            match answer {
                Response::Ran { .. } => {
                    *held = Some((session, sequence + 1));
                    return response(&answer, errors).map_err(failed);
                }
                Response::Rejected(Rejection::StaleSession { .. }) => *held = None,
                other => return Err(failed(format!("{other:?}"))),
            }
        }
        Err(failed("the agent refused the app's session"))
    }

    /// The facility's `enroll` arguments: the space, the agent and what
    /// the device may prove for.
    async fn enrollment(&self) -> Result<Value, HostServiceError> {
        let space = self.space().await?;
        let demo = self.demo;
        let guarded = |instance: u32, name: &str, guard: &str, scope: Option<(&str, bool)>| {
            let mut entries = vec![
                ("agent", Value::from(demo.agent)),
                ("instance", Value::from(instance)),
                ("name", Value::from(name)),
                ("guard", Value::from(guard)),
            ];
            if let Some((scope, once)) = scope {
                entries.push(("scope", Value::from(scope)));
                entries.push(("once", Value::Bool(once)));
            }
            object(entries)
        };
        Ok(object([
            ("handle", Value::Bytes(space.handle.to_vec())),
            ("space", Value::Bytes(space.space.0.to_vec())),
            (
                "agents",
                Value::Array(vec![object([
                    ("agent", Value::from(demo.agent)),
                    ("identity", Value::Bytes(space.identity.to_vec())),
                ])]),
            ),
            (
                "methods",
                Value::Array(vec![
                    guarded(demo.poll, LOGIN, "auth", Some((LOGIN, false))),
                    guarded(demo.poll, VOTE, "auth", Some((VOTE, true))),
                    guarded(demo.purses, TRANSFER, "owner", None),
                ]),
            ),
            (
                "credentials",
                object([
                    ("agent", Value::from(demo.agent)),
                    ("instance", Value::from(demo.credentials)),
                ]),
            ),
        ]))
    }

    /// The member's and the row's claims, which the operator's invitations
    /// name: the credential actor's `claim(member)`, then the ledger's
    /// `claim_row(row, owner)`.
    async fn claim(&self, args: &Value) -> Result<Value, HostServiceError> {
        let member: [u8; 32] = bytes(args, "member")?
            .try_into()
            .map_err(|_| failed("`member` is 32 bytes"))?;
        let owner: [u8; 32] = bytes(args, "owner")?
            .try_into()
            .map_err(|_| failed("`owner` is 32 bytes"))?;
        let row = text(args, "row")?.as_bytes().to_vec();
        let slot = self
            .call(
                self.demo.credentials,
                "claim",
                member.encode(),
                credential_error,
            )
            .await?;
        let slot = u32::decode_exact(&slot).ok_or_else(|| failed("the slot does not decode"))?;
        self.call(
            self.demo.purses,
            "claim_row",
            (row, owner).encode(),
            purse_error,
        )
        .await?;
        Ok(Value::from(slot))
    }

    /// Relay a credentialed request the facility made, if it names this
    /// agent and the screen's method; refuse any other before it reaches a
    /// node.
    async fn relay(&self, args: &Value) -> Result<Value, HostServiceError> {
        let request = bytes(args, "request")?;
        let allowed: &[(u32, &str)] = match text(args, "screen")? {
            "sign_in" => &[(self.demo.poll, LOGIN), (self.demo.poll, VOTE)],
            "pay" => &[(self.demo.purses, TRANSFER)],
            _ => return Err(failed("no such screen")),
        };
        let (kind, body) = request
            .split_first_chunk::<2>()
            .ok_or_else(|| failed("a request names its kind"))?;
        if u16::from_le_bytes(*kind) != Kind::Credentialed as u16 {
            return Err(failed("not a credentialed request"));
        }
        let (agent, call) = <(AgentId, Credentialed)>::decode_exact(body)
            .ok_or_else(|| failed("the request does not decode"))?;
        let named = allowed.iter().any(|(instance, name)| {
            call.instance == InstanceId(*instance) && call.method == method(name)
        });
        if agent != self.agent() || !named {
            return Err(failed(
                "the request names another agent or method than this screen's",
            ));
        }
        let answer = answered(self.gateway.relay(Kind::Credentialed, body).await)?;
        let answer = Response::decode_exact(&answer)
            .ok_or_else(|| failed("an answer that does not decode"))?;
        let root_unknown = matches!(
            answer,
            Response::Rejected(Rejection::Credential(
                CredentialRefusal::RootUnknown | CredentialRefusal::RootStale
            ))
        );
        let errors: Errors = if call.instance == InstanceId(self.demo.purses) {
            purse_error
        } else {
            method_error
        };
        Ok(match response(&answer, errors) {
            Ok(reply) => object([("ran", Value::Bool(true)), ("reply", Value::Bytes(reply))]),
            Err(why) => object([
                ("ran", Value::Bool(false)),
                ("why", Value::from(why)),
                ("root_unknown", Value::Bool(root_unknown)),
            ]),
        })
    }

    /// The row's balance, `null` when there is no such row.
    async fn balance(&self, args: &Value) -> Result<Value, HostServiceError> {
        let space = self.space().await?;
        let row = text(args, "row")?.as_bytes().to_vec();
        let reply = self
            .query(
                &space.identity,
                self.demo.purses,
                "balance",
                row.encode(),
                purse_error,
            )
            .await?;
        Ok(match Option::<u64>::decode_exact(&reply) {
            Some(Some(balance)) => Value::from(balance),
            Some(None) => Value::Null,
            None => return Err(failed("the balance does not decode")),
        })
    }

    /// The tree's root now: what a member's device refreshes from.
    async fn root(&self) -> Result<Value, HostServiceError> {
        let space = self.space().await?;
        let reply = self
            .query(
                &space.identity,
                self.demo.credentials,
                "root",
                Vec::new(),
                credential_error,
            )
            .await?;
        let entry =
            RootEntry::decode_exact(&reply).ok_or_else(|| failed("the root does not decode"))?;
        Ok(Value::Bytes(entry.root.to_vec()))
    }

    /// One operation of the host service.
    pub async fn serve(
        self: Arc<Self>,
        request: HostServiceRequest,
    ) -> Result<Value, HostServiceError> {
        let args = &request.args;
        match request.operation.as_str() {
            "enrollment" => self.enrollment().await,
            "claim" => self.claim(args).await,
            "relay" => self.relay(args).await,
            "balance" => self.balance(args).await,
            "root" => self.root().await,
            other => Err(failed(format!("no operation `{other}`"))),
        }
    }
}

/// Which screen is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Enroll,
    SignIn,
    Pay,
}

#[derive(Clone)]
pub enum Message {
    Show(Screen),
    Row(String),
    Payee(String),
    Amount(String),
    Enroll,
    Enrollment(EffectOutput),
    Enrolled(EffectOutput),
    Claim,
    Claimed(EffectOutput),
    SignIn,
    Proved(Screen, EffectOutput),
    Relayed(Screen, EffectOutput),
    Pay,
    Balance(EffectOutput),
    Refreshed(EffectOutput),
}

/// One connection's screens.
pub struct Screens {
    demo: Demo,
    screen: Screen,
    row: String,
    payee: String,
    amount: String,
    /// The device's member and owner digests, once it enrolled.
    digests: Option<([u8; 32], [u8; 32])>,
    status: String,
    proving: Option<u64>,
    balance: Option<String>,
}

impl Screens {
    pub fn new(demo: Demo) -> Self {
        Self {
            demo,
            screen: Screen::Enroll,
            row: String::new(),
            payee: String::new(),
            amount: String::new(),
            digests: None,
            status: String::new(),
            proving: None,
            balance: None,
        }
    }
}

fn service(operation: &str, args: Value, done: fn(EffectOutput) -> Message) -> Effect<Message> {
    Effect::host_service(
        operation,
        identifier(SERVICE),
        identifier(operation),
        args,
        done,
    )
}

fn facility(
    operation: &str,
    args: Value,
    done: impl Fn(EffectOutput) -> Message + Send + 'static,
) -> Effect<Message> {
    Effect::new(
        operation,
        EffectRequest::Facility {
            facility: s4_server::rui::protocol::TypeRef::new(identifier(FACILITY), 1)
                .expect("major 1"),
            operation: identifier(operation),
            args,
        },
        done,
    )
}

fn map_bytes(value: &Value, name: &str) -> Option<Vec<u8>> {
    match value {
        Value::Map(map) => match map.get(name)? {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn map_unsigned(value: &Value, name: &str) -> Option<u64> {
    match value {
        Value::Map(map) => match map.get(name)? {
            Value::Integer(s4_server::rui::protocol::Integer::Unsigned(value)) => Some(*value),
            _ => None,
        },
        _ => None,
    }
}

fn map_text(value: &Value, name: &str) -> Option<String> {
    match value {
        Value::Map(map) => match map.get(name)? {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn short(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(8)])
}

impl Screens {
    fn failed(&mut self, output: EffectOutput) {
        self.status = match output {
            EffectOutput::HostService(Err(error)) => error.message,
            EffectOutput::Facility(Err(error)) => format!("{}: {}", error.code, error.message),
            _ => "an unexpected answer".into(),
        };
    }

    fn proved(&mut self, screen: Screen, output: EffectOutput, cx: &mut Cx<Message>) {
        let EffectOutput::Facility(Ok(answer)) = output else {
            return self.failed(output);
        };
        let Some(request) = map_bytes(&answer, "request") else {
            self.status = "the device's answer holds no request".into();
            return;
        };
        self.proving = map_unsigned(&answer, "proving_ms");
        if screen == Screen::Pay
            && let (Some(payee), Some(amount)) =
                (map_text(&answer, "payee"), map_unsigned(&answer, "amount"))
        {
            // What the device confirmed, whatever this document held.
            self.payee = payee;
            self.amount = amount.to_string();
        }
        self.status = "Sending the proof…".into();
        let screen_name = match screen {
            Screen::Pay => "pay",
            _ => "sign_in",
        };
        cx.effect(Effect::host_service(
            "relay",
            identifier(SERVICE),
            identifier("relay"),
            object([
                ("request", Value::Bytes(request)),
                ("screen", Value::from(screen_name)),
            ]),
            move |output| Message::Relayed(screen, output),
        ));
    }

    fn relayed(&mut self, screen: Screen, output: EffectOutput, cx: &mut Cx<Message>) {
        let EffectOutput::HostService(Ok(answer)) = output else {
            return self.failed(output);
        };
        let proving = self
            .proving
            .map_or_else(String::new, |ms| format!(" (proved in {ms} ms)"));
        let ran = matches!(&answer, Value::Map(map) if map.get("ran") == Some(&Value::Bool(true)));
        if !ran {
            let why = map_text(&answer, "why").unwrap_or_default();
            let unknown = matches!(&answer, Value::Map(map) if map.get("root_unknown") == Some(&Value::Bool(true)));
            if unknown {
                cx.effect(facility("refresh", Value::Null, Message::Refreshed));
                self.status =
                    format!("{why}: the device fetches its path again; try again shortly");
            } else {
                self.status = format!("Not done: {why}{proving}");
            }
            return;
        }
        let reply = map_bytes(&answer, "reply").unwrap_or_default();
        match screen {
            Screen::Pay => {
                self.status = format!("Paid {} to {}{proving}", self.amount, self.payee);
                cx.effect(service(
                    "balance",
                    object([("row", Value::from(self.row.clone()))]),
                    Message::Balance,
                ));
            }
            _ => {
                let pseudonym = Option::<[u8; 32]>::decode_exact(&reply)
                    .flatten()
                    .map_or_else(|| "a member".into(), |nullifier| short(&nullifier));
                self.status = format!("Signed in as {pseudonym}{proving}");
            }
        }
    }
}

impl App for Screens {
    type Message = Message;

    fn view(&self, _context: &ViewContext) -> View<Message> {
        let mut page = view::column()
            .gap(1.0)
            .padding(2.0)
            .text("VOS: a member's device proves; this server only relays")
            .row(|row| {
                row.gap(1.0)
                    .button("Enroll", Message::Show(Screen::Enroll))
                    .button("Sign in", Message::Show(Screen::SignIn))
                    .button("Pay", Message::Show(Screen::Pay))
            });
        page = match self.screen {
            Screen::Enroll => {
                let page = page
                    .text("Enroll this device")
                    .child(
                        view::field(self.row.clone(), Message::Row).placeholder("Your row's name"),
                    )
                    .button("Enroll this device", Message::Enroll);
                match self.digests {
                    Some(_) => page
                        .text(
                            "Your device showed its two digests in its own window: read \
                             them from there to the space's operator, then claim them.",
                        )
                        .button("Claim", Message::Claim),
                    None => page,
                }
            }
            Screen::SignIn => page
                .text("Sign in with your device")
                .button("Sign in with my device", Message::SignIn),
            Screen::Pay => {
                let page = page
                    .text("Pay from your row")
                    .child(view::field(self.row.clone(), Message::Row).placeholder("From row"))
                    .child(view::field(self.payee.clone(), Message::Payee).placeholder("To row"))
                    .child(view::field(self.amount.clone(), Message::Amount).placeholder("Amount"))
                    .button("Send the payment", Message::Pay);
                match &self.balance {
                    Some(balance) => page.text(format!("Balance of {}: {balance}", self.row)),
                    None => page,
                }
            }
        };
        View::new(page.text(self.status.clone()))
    }

    fn update(&mut self, message: Message, cx: &mut Cx<Message>) {
        match message {
            Message::Show(screen) => {
                self.screen = screen;
                self.status.clear();
            }
            Message::Row(row) => self.row = row,
            Message::Payee(payee) => self.payee = payee,
            Message::Amount(amount) => self.amount = amount,
            Message::Enroll => {
                self.status = "Asking the device…".into();
                cx.effect(service("enrollment", Value::Null, Message::Enrollment));
            }
            Message::Enrollment(output) => {
                let EffectOutput::HostService(Ok(args)) = output else {
                    return self.failed(output);
                };
                cx.effect(facility("enroll", args, Message::Enrolled));
            }
            Message::Enrolled(output) => {
                let EffectOutput::Facility(Ok(answer)) = &output else {
                    return self.failed(output);
                };
                let digest = |name| {
                    map_bytes(answer, name).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                };
                match (digest("member"), digest("owner")) {
                    (Some(member), Some(owner)) => {
                        self.digests = Some((member, owner));
                        self.status = "Enrolled on this device".into();
                    }
                    _ => self.status = "the device's digests do not decode".into(),
                }
            }
            Message::Claim => {
                let Some((member, owner)) = self.digests else {
                    return;
                };
                self.status = "Claiming…".into();
                cx.effect(service(
                    "claim",
                    object([
                        ("member", Value::Bytes(member.to_vec())),
                        ("owner", Value::Bytes(owner.to_vec())),
                        ("row", Value::from(self.row.clone())),
                    ]),
                    Message::Claimed,
                ));
            }
            Message::Claimed(output) => match output {
                EffectOutput::HostService(Ok(slot)) => {
                    self.status = format!(
                        "Claimed: member at slot {}, row {}",
                        display(&slot),
                        self.row
                    );
                }
                other => self.failed(other),
            },
            Message::SignIn => {
                self.status = "Asking the device…".into();
                self.proving = None;
                cx.effect(facility(
                    "sign_in",
                    object([
                        ("agent", Value::from(self.demo.agent)),
                        ("instance", Value::from(self.demo.poll)),
                        ("method", Value::from(LOGIN)),
                        ("arguments", Value::Bytes(().encode())),
                    ]),
                    |output| Message::Proved(Screen::SignIn, output),
                ));
            }
            Message::Pay => {
                let Ok(amount) = self.amount.trim().parse::<u64>() else {
                    self.status = "The amount is a whole number".into();
                    return;
                };
                self.status = "Asking the device…".into();
                self.proving = None;
                cx.effect(facility(
                    "pay",
                    object([
                        ("agent", Value::from(self.demo.agent)),
                        ("instance", Value::from(self.demo.purses)),
                        ("method", Value::from(TRANSFER)),
                        ("payer", Value::from(self.row.clone())),
                        ("payee", Value::from(self.payee.clone())),
                        ("amount", Value::from(amount)),
                    ]),
                    |output| Message::Proved(Screen::Pay, output),
                ));
            }
            Message::Proved(screen, output) => self.proved(screen, output, cx),
            Message::Relayed(screen, output) => self.relayed(screen, output, cx),
            Message::Balance(output) => match output {
                EffectOutput::HostService(Ok(balance)) => self.balance = Some(display(&balance)),
                other => self.failed(other),
            },
            Message::Refreshed(_) => {}
        }
    }
}

fn display(value: &Value) -> String {
    match value {
        Value::Integer(s4_server::rui::protocol::Integer::Unsigned(value)) => value.to_string(),
        Value::Null => "no such row".into(),
        other => format!("{other:?}"),
    }
}
