//! The demo's host service: the app's operations over the node API.

use super::*;

/// What the app learned of the space, once.
#[derive(Clone, Copy)]
struct Space {
    identity: [u8; 32],
    space: SpaceId,
    handle: [u8; 32],
}

/// The screens' server side: reads, and the claims under the app's key.
pub struct Service {
    demo: Demo,
    /// The SSH host key the gateway's onions present on port 22.
    ssh_host_key: Option<[u8; 32]>,
    gateway: Arc<Gateway>,
    /// The transport of the port the screens are served on.
    mark: Mark,
    app: Arc<AppClient>,
    space: OnceCell<Space>,
    /// The app key's session with the agent and its next sequence: one
    /// claim at a time, in order.
    session: Mutex<Option<(Session, u64)>>,
    held: Held,
}

/// The enrollments a session's screens hold (the member and owner digests
/// its device showed, the account typed) until a claim makes them: after
/// a clearnet enrollment s4 connects again over the onion, carried, and
/// the claim is made from there without the digests shown in it, so that
/// session signs in. At most [`HELD`], the oldest dropped first.
#[derive(Clone, Default)]
pub struct Held(Arc<std::sync::Mutex<Vec<([u8; 32], [u8; 32], Vec<u8>)>>>);

/// The enrollments held at most.
const HELD: usize = 32;

/// How long a claim waits for the session, held by another client's: the
/// session is one for all clients.
const SESSION_WAIT: std::time::Duration = std::time::Duration::from_secs(20);
/// How long a call under the session may take: past it, the session is
/// dropped, as its sequence's fate is unknown.
const CALL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

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
/// An enrollment's member and owner digests and account, as `args` name
/// them.
fn enrollment(args: &Value) -> Result<([u8; 32], [u8; 32], Vec<u8>), HostServiceError> {
    let member: [u8; 32] = bytes(args, "member")?
        .try_into()
        .map_err(|_| failed("`member` is 32 bytes"))?;
    let owner: [u8; 32] = bytes(args, "owner")?
        .try_into()
        .map_err(|_| failed("`owner` is 32 bytes"))?;
    let account = text(args, "account")?.as_bytes().to_vec();
    Ok((member, owner, account))
}

fn answered((kind, body): vos_api::client::Answer) -> Result<Vec<u8>, HostServiceError> {
    if kind == FRAME_ERROR {
        return Err(failed("the node is unavailable"));
    }
    Ok(body)
}

/// How a method's own error reads on the screen.
pub(super) type Errors = fn(&[u8]) -> String;

pub(super) fn method_error(_detail: &[u8]) -> String {
    "the method refused".into()
}

/// The names of the ledger's errors, by index.
const PAYMENT_ERRORS: [&str; 13] = [
    "a bad account name",
    "the account exists",
    "no such account",
    "not invited",
    "the invitation expired",
    "this device holds no account",
    "the account is frozen",
    "insufficient balance",
    "the balance would overflow",
    "the ledger refused",
    "not an owner digest",
    "a payment to your own account",
    "an amount of nothing",
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

pub(super) fn payment_error(detail: &[u8]) -> String {
    detail
        .first()
        .and_then(|index| PAYMENT_ERRORS.get(usize::from(*index)))
        .map_or_else(|| "the ledger refused".into(), |name| (*name).into())
}

fn credential_error(detail: &[u8]) -> String {
    CredentialError::decode_exact(detail).map_or_else(
        || "the credential actor refused".into(),
        |error| format!("{error:?}"),
    )
}

/// A node's answer, as the screen says it.
pub(super) fn response(answer: &Response, errors: Errors) -> Result<Vec<u8>, String> {
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
    pub fn new(
        demo: Demo,
        ssh_host_key: Option<[u8; 32]>,
        gateway: Arc<Gateway>,
        mark: Mark,
        app: Arc<AppClient>,
        held: Held,
    ) -> Self {
        Self {
            demo,
            ssh_host_key,
            gateway,
            mark,
            app,
            space: OnceCell::new(),
            session: Mutex::new(None),
            held,
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
    /// agent refuses the one held for good, and after any answer that does
    /// not say whether the call ran (a frame error, an answer that does not
    /// decode, a call past [`CALL_DEADLINE`]), so no later call reuses a
    /// sequence that may be taken. Waits for the session at most
    /// [`SESSION_WAIT`].
    async fn call(
        &self,
        instance: u32,
        name: &str,
        arguments: Vec<u8>,
        errors: Errors,
    ) -> Result<Vec<u8>, HostServiceError> {
        let space = self.space().await?;
        let mut held = tokio::time::timeout(SESSION_WAIT, self.session.lock())
            .await
            .map_err(|_| failed("the app is busy with another claim: try again"))?;
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
            let called = self.app.call(
                self.agent(),
                &space.identity,
                session,
                sequence,
                InstanceId(instance),
                method(name),
                arguments.clone(),
            );
            let answer = tokio::time::timeout(CALL_DEADLINE, called)
                .await
                .map_err(|_| failed("the node did not answer in time"))
                .and_then(answered)
                .and_then(|body| {
                    Response::decode_exact(&body)
                        .ok_or_else(|| failed("an answer that does not decode"))
                });
            let answer = match answer {
                Ok(answer) => answer,
                Err(error) => {
                    // The call may have run under this sequence.
                    *held = None;
                    return Err(error);
                }
            };
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
    /// the device may prove for, and the gateway's onions, which the device
    /// pins and sends its proofs to.
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
        let methods = vec![
            object(guarded(demo.poll, LOGIN, "auth", Some((LOGIN, false)))),
            object(guarded(demo.poll, VOTE, "auth", Some((VOTE, true)))),
            object(guarded(demo.payments, TRANSFER, "owner", None)),
        ];
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
            (
                "onions",
                Value::Array(
                    self.ssh_host_key
                        .iter()
                        .flat_map(|host| {
                            demo.onions.iter().map(|key| {
                                object([
                                    ("key", Value::Bytes(key.to_vec())),
                                    ("ssh_host_key", Value::Bytes(host.to_vec())),
                                ])
                            })
                        })
                        .collect(),
                ),
            ),
            ("onion_only", Value::Bool(false)),
        ]))
    }

    /// An enrollment held for a claim from a later session: its member
    /// and owner digests, and the account's name.
    fn hold(&self, args: &Value) -> Result<Value, HostServiceError> {
        let (member, owner, account) = enrollment(args)?;
        let mut held = self.held.0.lock().expect("held poisoned");
        held.retain(|(kept, ..)| *kept != member);
        held.push((member, owner, account));
        if held.len() > HELD {
            held.remove(0);
        }
        Ok(Value::Null)
    }

    /// The claim of the enrollment `args` names, or with `null` of every
    /// one held whose invitation stands: the slots claimed, each then held
    /// no more. One not invited yet stays held.
    async fn claim(&self, args: &Value) -> Result<Value, HostServiceError> {
        if *args != Value::Null {
            let (member, owner, account) = enrollment(args)?;
            let slot = self.claimed(member, owner, account).await?;
            self.held
                .0
                .lock()
                .expect("held poisoned")
                .retain(|(kept, ..)| *kept != member);
            return Ok(Value::Array(vec![Value::from(slot)]));
        }
        let held = self.held.0.lock().expect("held poisoned").clone();
        let mut slots = Vec::new();
        let mut why = None;
        for (member, owner, account) in held {
            match self.claimed(member, owner, account).await {
                Ok(slot) => {
                    self.held
                        .0
                        .lock()
                        .expect("held poisoned")
                        .retain(|(kept, ..)| *kept != member);
                    slots.push(Value::from(slot));
                }
                Err(error) => why = Some(error),
            }
        }
        match (slots.is_empty(), why) {
            (true, Some(error)) => Err(error),
            (true, None) => Err(failed(
                "no enrollment is held for a claim: enroll this device first",
            )),
            (false, _) => Ok(Value::Array(slots)),
        }
    }

    /// The member's claim and the account's opening, which the operator's
    /// invitations name: the credential actor's `claim(member)`, then the
    /// ledger's `open(account, owner)`.
    async fn claimed(
        &self,
        member: [u8; 32],
        owner: [u8; 32],
        account: Vec<u8>,
    ) -> Result<u32, HostServiceError> {
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
            self.demo.payments,
            "open",
            (account, owner).encode(),
            payment_error,
        )
        .await?;
        Ok(slot)
    }

    /// The name and balance of the account the owner digest `owner`
    /// holds, `null` when it holds none.
    async fn balance(&self, args: &Value) -> Result<Value, HostServiceError> {
        let space = self.space().await?;
        let owner: [u8; 32] = bytes(args, "owner")?
            .try_into()
            .map_err(|_| failed("`owner` is 32 bytes"))?;
        let reply = self
            .query(
                &space.identity,
                self.demo.payments,
                "held",
                owner.encode(),
                payment_error,
            )
            .await?;
        type Held = Option<(Vec<u8>, ([u8; 32], u64, bool))>;
        Ok(match Held::decode_exact(&reply) {
            Some(Some((name, (_, balance, _)))) => object([
                (
                    "name",
                    Value::from(String::from_utf8_lossy(&name).into_owned()),
                ),
                ("balance", Value::from(balance)),
            ]),
            Some(None) => Value::Null,
            None => return Err(failed("the account does not decode")),
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
            "hold" => self.hold(args),
            "claim" => self.claim(args).await,
            "balance" => self.balance(args).await,
            "root" => self.root().await,
            other => Err(failed(format!("no operation `{other}`"))),
        }
    }
}
