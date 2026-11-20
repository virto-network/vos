//! The demo's host service: the app's operations over the node API.

use super::*;
use vos_wire::payments::PaymentError;

/// What the app learned of the space, once.
#[derive(Clone, Copy)]
struct Space {
    identity: [u8; 32],
    space: SpaceId,
    handle: [u8; 32],
}

/// The screens' server side: reads under the app's key, and the
/// enrollments held for the operator's invitations.
pub struct Service {
    demo: Demo,
    /// The SSH host key the gateway's onions present on port 22.
    ssh_host_key: Option<[u8; 32]>,
    gateway: Arc<Gateway>,
    /// The transport of the port the screens are served on.
    mark: Mark,
    app: Arc<AppClient>,
    space: OnceCell<Space>,
    held: Held,
}

/// The enrollments the screens hold (the member and owner digests a
/// device showed) until the operator invites them: the invitation claims
/// them then ([`crate::LocalSpace::invite`]), no session asking for it, so
/// the session s4 carries over the onion after a clearnet enrollment
/// signs in with nothing of the digests in it. At most [`HELD`], the
/// oldest dropped first.
#[derive(Clone, Default)]
pub struct Held(Arc<std::sync::Mutex<Vec<Enrolled>>>);

/// An enrollment's member and owner digests.
type Enrolled = ([u8; 32], [u8; 32]);

impl Held {
    /// The enrollment of `member` with `owner`, if one is held: taken.
    pub fn take(&self, member: &[u8; 32], owner: &[u8; 32]) -> bool {
        let mut held = self.0.lock().expect("held poisoned");
        let before = held.len();
        held.retain(|kept| kept != &(*member, *owner));
        held.len() != before
    }
}

/// The enrollments held at most.
const HELD: usize = 32;

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
    let Ok((error, _)) = PaymentError::decode(detail) else {
        return "the ledger refused".into();
    };
    match error {
        PaymentError::BadName => "a bad account name",
        PaymentError::Exists => "the account exists",
        PaymentError::NoAccount => "no such account",
        PaymentError::NotInvited => "not invited",
        PaymentError::Expired => "the invitation expired",
        PaymentError::NotOwner => "this device holds no account",
        PaymentError::Frozen => "the account is frozen",
        PaymentError::Insufficient => "insufficient balance",
        PaymentError::Overflow => "the balance would overflow",
        PaymentError::Refused(_) => "the ledger refused",
        PaymentError::BadOwner => "not an owner digest",
        PaymentError::SamePayee => "a payment to your own account",
        PaymentError::NoAmount => "an amount of nothing",
    }
    .into()
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

    /// An enrollment held until the operator's invitation claims it: its
    /// member and owner digests.
    fn hold(&self, args: &Value) -> Result<Value, HostServiceError> {
        let digest = |name| -> Result<[u8; 32], HostServiceError> {
            bytes(args, name)?
                .try_into()
                .map_err(|_| failed(format!("`{name}` is 32 bytes")))
        };
        let (member, owner) = (digest("member")?, digest("owner")?);
        let mut held = self.held.0.lock().expect("held poisoned");
        held.retain(|(kept, _)| *kept != member);
        held.push((member, owner));
        if held.len() > HELD {
            held.remove(0);
        }
        Ok(Value::Null)
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
            "balance" => self.balance(args).await,
            "root" => self.root().await,
            other => Err(failed(format!("no operation `{other}`"))),
        }
    }
}
