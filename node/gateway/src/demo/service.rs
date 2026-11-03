//! The demo's host service: the app's operations over the node API.

use super::*;

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
    /// The transport of the port the screens are served on.
    mark: Mark,
    app: Arc<AppClient>,
    space: OnceCell<Space>,
    /// The app key's session with the agent and its next sequence: one
    /// claim at a time, in order.
    session: Mutex<Option<(Session, u64)>>,
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
    pub fn new(demo: Demo, gateway: Arc<Gateway>, mark: Mark, app: Arc<AppClient>) -> Self {
        Self {
            demo,
            gateway,
            mark,
            app,
            space: OnceCell::new(),
            session: Mutex::new(None),
        }
    }

    fn agent(&self) -> AgentId {
        AgentId(self.demo.agent)
    }

    async fn time(&self) -> Result<u64, HostServiceError> {
        let body = answered(self.gateway.relay(Kind::Time, self.mark, &[]).await)?;
        u64::decode_exact(&body).ok_or_else(|| failed("the node's time does not decode"))
    }

    async fn space(&self) -> Result<Space, HostServiceError> {
        self.space
            .get_or_try_init(|| async {
                let body = answered(
                    self.gateway
                        .relay(Kind::AgentInfo, self.mark, &self.agent().encode())
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
        let demo = &self.demo;
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
            entries
        };
        let mut methods = vec![
            object(guarded(demo.poll, LOGIN, "auth", Some((LOGIN, false)))),
            object(guarded(demo.poll, VOTE, "auth", Some((VOTE, true)))),
            object(guarded(demo.purses, TRANSFER, "owner", None)),
        ];
        // The device actor's `login`, its device kernel pinned with it.
        if let Some(device) = &demo.device {
            let kernel = std::fs::read(&device.kernel)
                .map_err(|error| failed(format!("the device kernel: {error}")))?;
            let mut login = guarded(device.instance, LOGIN, "auth", Some((LOGIN, false)));
            login.push(("kernel", Value::Bytes(kernel)));
            methods.push(object(login));
        }
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
            ("methods", Value::Array(methods)),
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
        let device = self
            .demo
            .device
            .as_ref()
            .map(|device| (device.instance, LOGIN));
        let allowed: Vec<(u32, &str)> = match text(args, "screen")? {
            "sign_in" => [(self.demo.poll, LOGIN), (self.demo.poll, VOTE)]
                .into_iter()
                .chain(device)
                .collect(),
            "pay" => vec![(self.demo.purses, TRANSFER)],
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
        let answer = answered(
            self.gateway
                .relay(Kind::Credentialed, self.mark, body)
                .await,
        )?;
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
