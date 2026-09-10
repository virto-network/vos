//! Built-in SSH ingress serving the semantic VOS space shell.
//!
//! The listener owns SSH framing, public-key authentication, quotas, and
//! resumable UI sessions. Durable actions still enter the ordinary root
//! service path with a stable member subject and exact idempotency key.

use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use s4_server::rui::{App, Cx, Effect, EffectOutput, View, view};
use s4_server::{
    AppContext, AppFactory, AuthError, AuthenticatedIdentity, Credential, HostServiceError,
    HostServiceRequest, Identifier, Identity, Router, Server, ServerLimits, Value,
    load_or_create_host_key,
};

use crate::actors::context::ServiceId;
use crate::node::{IngressAuthenticationError, IngressHandle};
use crate::service::ServiceWire;
use crate::{Decode, Encode};

const SHELL_SERVICE: &str = "vos.space";
const LOAD_EFFECT: &str = "space.load";
const INVOKE_EFFECT: &str = "space.invoke";
const MAX_BLOCKING_OPERATIONS: usize = 32;
/// VOS root admission has no cancellation boundary after acceptance. A
/// shorter S4 deadline could report failure while the invocation remains live
/// and later commits. Tokio represents this as a far-future timer; the global
/// blocking semaphore remains the resource bound for accepted work.
const ACCEPTED_WORK_TIMEOUT: Duration = Duration::MAX;

/// Extract the sole SSH credential shape admitted by the clean authority.
/// Comments, SSH wire wrappers, and alternate algorithms never contribute to
/// identity. Weak Ed25519 encodings fail closed before authority lookup.
pub fn canonical_ssh_ed25519_public_key(public_key: &ssh_key::PublicKey) -> Option<[u8; 32]> {
    let ssh_key::public::KeyData::Ed25519(public_key) = public_key.key_data() else {
        return None;
    };
    let public_key = public_key.0;
    ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .is_ok_and(|key| !key.is_weak())
        .then_some(public_key)
}

fn default_max_connections() -> usize {
    128
}

fn default_max_sessions_per_member() -> usize {
    4
}

/// One node-local SSH listener. Host keys are deliberately explicit so a
/// restored space retains host identity and two listeners cannot accidentally
/// share a key outside the space's private directory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SshIngressConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub host_key: PathBuf,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_max_sessions_per_member")]
    pub max_sessions_per_member: usize,
}

#[derive(Debug)]
pub enum SshIngressError {
    InvalidConfig(&'static str),
    Io(io::Error),
    Server(String),
}

impl std::fmt::Display for SshIngressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => formatter.write_str(message),
            Self::Io(error) => error.fmt(formatter),
            Self::Server(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for SshIngressError {}

impl From<io::Error> for SshIngressError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) fn start(
    config: SshIngressConfig,
    handle: IngressHandle,
) -> Result<thread::JoinHandle<()>, SshIngressError> {
    validate_config(&config)?;
    let host_key = load_or_create_host_key(&config.host_key)
        .map_err(|error| SshIngressError::Server(error.to_string()))?;
    let listener = StdTcpListener::bind(config.listen)?;
    listener.set_nonblocking(true)?;
    let name = config.name.clone();
    thread::Builder::new()
        .name(format!("vos-ssh-{name}"))
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .thread_name(format!("vos-ssh-{name}-io"))
                .build()
                .expect("SSH ingress Tokio runtime");
            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(error) => {
                        crate::log::error!("SSH ingress {name} failed: {error}");
                        return;
                    }
                };
                let blocking = Arc::new(tokio::sync::Semaphore::new(MAX_BLOCKING_OPERATIONS));
                let server = build_server(&config, handle.clone(), blocking).host_key(host_key);
                let shutdown_handle = handle.clone();
                let shutdown = async move {
                    while !shutdown_handle.is_shutting_down() {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                };
                if let Err(error) = server.serve_on_with_shutdown(listener, shutdown).await {
                    crate::log::error!("SSH ingress {name} stopped: {error}");
                }
            });
        })
        .map_err(SshIngressError::Io)
}

fn validate_config(config: &SshIngressConfig) -> Result<(), SshIngressError> {
    if config.name.is_empty()
        || !config
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SshIngressError::InvalidConfig(
            "SSH ingress name must contain only ASCII letters, digits, '-' or '_'",
        ));
    }
    if config.max_connections == 0 || config.max_sessions_per_member == 0 {
        return Err(SshIngressError::InvalidConfig(
            "SSH ingress connection and session limits must be nonzero",
        ));
    }
    if config.host_key.as_os_str().is_empty() {
        return Err(SshIngressError::InvalidConfig("SSH host-key path is empty"));
    }
    Ok(())
}

fn build_server(
    config: &SshIngressConfig,
    handle: IngressHandle,
    blocking: Arc<tokio::sync::Semaphore>,
) -> Server {
    let limits = server_limits(config);

    let auth_handle = handle.clone();
    let auth_blocking = blocking.clone();
    let service_handle = handle;
    let service_blocking = blocking;
    Server::router(format!("vos.space.{}", config.name), shell_router())
        .authenticator_fn(move |request| {
            let handle = auth_handle.clone();
            let blocking = auth_blocking.clone();
            async move {
                let Credential::PublicKey(public_key) = request.credential else {
                    return Ok(None);
                };
                let Some(public_key) = canonical_ssh_ed25519_public_key(&public_key) else {
                    return Ok(None);
                };
                let permit = blocking
                    .acquire_owned()
                    .await
                    .map_err(|_| AuthError::new("space is shutting down"))?;
                let access = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    handle.authenticate_ssh_public_key(&public_key)
                })
                .await
                .map_err(|_| AuthError::new("authentication worker failed"))?;
                let access = match access {
                    Ok(access) if access.expires_at > now_unix() => access,
                    Ok(_) | Err(IngressAuthenticationError::Invalid) => return Ok(None),
                    Err(IngressAuthenticationError::AuthorityUnavailable) => {
                        return Err(AuthError::new("space authority is unavailable"));
                    }
                };
                Ok(Some(AuthenticatedIdentity::new(
                    identity("member", &access.subject)?,
                    identity("ssh-ed25519", &public_key)?,
                )))
            }
        })
        .host_service_fn(SHELL_SERVICE, move |request| {
            host_service(service_handle.clone(), service_blocking.clone(), request)
        })
        .limits(limits)
}

fn server_limits(config: &SshIngressConfig) -> ServerLimits {
    let mut limits = ServerLimits {
        max_connections: config.max_connections,
        max_sessions_per_identity: config.max_sessions_per_member,
        ..ServerLimits::default()
    };
    limits.host_services.timeout = ACCEPTED_WORK_TIMEOUT;
    limits
}

#[derive(Clone)]
enum Message {
    Loaded(EffectOutput),
    IdempotencyKey(String),
    Invoke,
    Invoked(EffectOutput),
    RoleName(String),
    RolePower(String),
    RoleCapabilities(String),
    MemberSubject(String),
    MemberRoles(String),
    OperationKey(String),
    SaveRole,
    DeleteRole,
    AssignRoles,
    RevokeRoles,
    Managed(EffectOutput),
}

/// Canonical nested RUI navigation below `/agents`.
///
/// The literals between identifiers make every level explicit: an Agent is
/// not an Actor, and an Actor overview is never itself an invocation target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentShellRoute<'a> {
    Agent {
        agent: &'a str,
    },
    Actors {
        agent: &'a str,
    },
    Actor {
        agent: &'a str,
        actor: &'a str,
    },
    Methods {
        agent: &'a str,
        actor: &'a str,
    },
    Method {
        agent: &'a str,
        actor: &'a str,
        method: &'a str,
    },
}

fn parse_agent_shell_route(route: &str) -> Option<AgentShellRoute<'_>> {
    let rest = route.strip_prefix("/agents/")?;
    let mut segments = rest.split('/');
    let agent = segments.next()?;
    if !is_canonical_agent_name(agent) {
        return None;
    }
    let Some(level) = segments.next() else {
        return Some(AgentShellRoute::Agent { agent });
    };
    if level != "actors" {
        return None;
    }
    let Some(actor) = segments.next() else {
        return Some(AgentShellRoute::Actors { agent });
    };
    if !is_canonical_schema_name(actor) {
        return None;
    }
    let Some(level) = segments.next() else {
        return Some(AgentShellRoute::Actor { agent, actor });
    };
    if level != "methods" {
        return None;
    }
    let Some(method) = segments.next() else {
        return Some(AgentShellRoute::Methods { agent, actor });
    };
    if !is_canonical_schema_name(method) || segments.next().is_some() {
        return None;
    }
    Some(AgentShellRoute::Method {
        agent,
        actor,
        method,
    })
}

fn is_canonical_agent_name(name: &str) -> bool {
    crate::registry::is_canonical_registry_slug(name)
}

fn is_canonical_schema_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=vos_agent_sdk::MAX_ACTOR_NAME_BYTES).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn shell_metadata_is_canonical(meta: &crate::metadata::ParsedMeta) -> bool {
    is_canonical_schema_name(&meta.actor_name)
        && meta.messages.iter().enumerate().all(|(index, method)| {
            is_canonical_schema_name(&method.name)
                && method.mode <= 1
                && meta.messages[index + 1..]
                    .iter()
                    .all(|other| other.name != method.name)
        })
}

struct SpaceApp {
    route: String,
    content: String,
    idempotency_key: String,
    role_name: String,
    role_power: String,
    role_capabilities: String,
    member_subject: String,
    member_roles: String,
    operation_key: String,
}

impl SpaceApp {
    fn new(context: &AppContext) -> Self {
        Self {
            route: context.route().as_str().to_owned(),
            content: "Loading space…".into(),
            idempotency_key: String::new(),
            role_name: String::new(),
            role_power: String::new(),
            role_capabilities: String::new(),
            member_subject: String::new(),
            member_roles: String::new(),
            operation_key: String::new(),
        }
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value).expect("built-in S4 identifier")
    }
}

impl App for SpaceApp {
    type Message = Message;

    fn view(&self) -> View<Message> {
        let mut page = view::column()
            .gap(1.0)
            .padding(2.0)
            .text("VOS space")
            .row(|row| {
                row.gap(1.0)
                    .link("Home", "s4:/")
                    .link("Members", "s4:/members")
                    .link("Roles", "s4:/roles")
                    .link("Catalog", "s4:/catalog")
                    .link("Agents", "s4:/agents")
            })
            .text(self.content.clone());
        if matches!(
            parse_agent_shell_route(&self.route),
            Some(AgentShellRoute::Method { .. })
        ) {
            page = page
                .text("Invoke this no-argument method")
                .field(self.idempotency_key.clone(), Message::IdempotencyKey)
                .button("Invoke", Message::Invoke);
        }
        if self.route == "/roles" {
            page = page
                .text("Define or delete a role")
                .field(self.role_name.clone(), Message::RoleName)
                .field(self.role_power.clone(), Message::RolePower)
                .field(self.role_capabilities.clone(), Message::RoleCapabilities)
                .field(self.operation_key.clone(), Message::OperationKey)
                .row(|row| {
                    row.gap(1.0)
                        .button("Save role", Message::SaveRole)
                        .button("Delete role", Message::DeleteRole)
                })
                .text("Assign roles to a member subject")
                .field(self.member_subject.clone(), Message::MemberSubject)
                .field(self.member_roles.clone(), Message::MemberRoles)
                .row(|row| {
                    row.gap(1.0)
                        .button("Assign roles", Message::AssignRoles)
                        .button("Revoke roles", Message::RevokeRoles)
                });
        }
        View::new(page)
    }

    fn update(&mut self, message: Message, cx: &mut Cx<Message>) {
        match message {
            Message::Loaded(output) | Message::Invoked(output) | Message::Managed(output) => {
                self.content = effect_text(output);
            }
            Message::IdempotencyKey(key) => self.idempotency_key = key,
            Message::RoleName(value) => self.role_name = value,
            Message::RolePower(value) => self.role_power = value,
            Message::RoleCapabilities(value) => self.role_capabilities = value,
            Message::MemberSubject(value) => self.member_subject = value,
            Message::MemberRoles(value) => self.member_roles = value,
            Message::OperationKey(value) => self.operation_key = value,
            Message::Invoke => {
                let Some(AgentShellRoute::Method {
                    agent,
                    actor,
                    method,
                }) = parse_agent_shell_route(&self.route)
                else {
                    return;
                };
                self.content = "Invoking…".into();
                cx.effect(Effect::host_service(
                    INVOKE_EFFECT,
                    Self::identifier(SHELL_SERVICE),
                    Self::identifier("invoke"),
                    Value::object([
                        ("agent".into(), Value::Text(agent.into())),
                        ("actor".into(), Value::Text(actor.into())),
                        ("method".into(), Value::Text(method.into())),
                        (
                            "idempotency_key".into(),
                            Value::Text(self.idempotency_key.clone()),
                        ),
                    ]),
                    Message::Invoked,
                ));
            }
            Message::SaveRole => self.manage_role(cx, "put-role"),
            Message::DeleteRole => self.manage_role(cx, "delete-role"),
            Message::AssignRoles => self.manage_role(cx, "set-member-roles"),
            Message::RevokeRoles => self.manage_role(cx, "revoke-member-roles"),
        }
    }

    fn start(&mut self, cx: &mut Cx<Message>) {
        cx.effect(Effect::host_service(
            LOAD_EFFECT,
            Self::identifier(SHELL_SERVICE),
            Self::identifier("describe"),
            Value::Text(self.route.clone()),
            Message::Loaded,
        ));
    }
}

impl SpaceApp {
    fn manage_role(&mut self, cx: &mut Cx<Message>, operation: &str) {
        self.content = "Applying authority change…".into();
        cx.effect(Effect::host_service(
            "space.manage",
            Self::identifier(SHELL_SERVICE),
            Self::identifier(operation),
            Value::object([
                ("role".into(), Value::Text(self.role_name.clone())),
                ("power".into(), Value::Text(self.role_power.clone())),
                (
                    "capabilities".into(),
                    Value::Text(self.role_capabilities.clone()),
                ),
                ("subject".into(), Value::Text(self.member_subject.clone())),
                ("roles".into(), Value::Text(self.member_roles.clone())),
                (
                    "operation_key".into(),
                    Value::Text(self.operation_key.clone()),
                ),
            ]),
            Message::Managed,
        ));
    }
}

fn effect_text(output: EffectOutput) -> String {
    match output {
        EffectOutput::HostService(Ok(Value::Text(text))) => text,
        EffectOutput::HostService(Ok(Value::Map(fields))) => {
            match (fields.get("reply"), fields.get("attestation_wire")) {
                (Some(Value::Text(reply)), Some(Value::Bytes(wire))) => format!(
                    "{reply}\n\nAttestation (canonical VARW wire, hex):\n{}",
                    hex(wire),
                ),
                _ => "Unexpected space-shell response".into(),
            }
        }
        EffectOutput::HostService(Err(error)) => format!("{}: {}", error.code, error.message),
        EffectOutput::Cancelled => "Operation cancelled".into(),
        _ => "Unexpected space-shell response".into(),
    }
}

fn shell_router() -> Router {
    let factory = || AppFactory::with_context(SpaceApp::new);
    Router::single(factory())
        .route("/members", factory())
        .and_then(|router| router.route("/roles", factory()))
        .and_then(|router| router.route("/catalog", factory()))
        .and_then(|router| router.route("/agents", factory()))
        .and_then(|router| router.fallback(factory()))
        .expect("built-in shell routes are canonical")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn identity(prefix: &str, bytes: &[u8; 32]) -> Result<Identity, AuthError> {
    Identity::new(format!("{prefix}:{}", hex(bytes)))
        .map_err(|error| AuthError::new(error.to_string()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out[index] = (hi << 4) | lo;
    }
    Some(out)
}

fn service_error(code: &str, message: impl Into<String>) -> HostServiceError {
    HostServiceError::new(
        Identifier::new(code).expect("built-in error identifier"),
        message,
    )
}

fn access_for_request(
    handle: &IngressHandle,
    request: &HostServiceRequest,
) -> Result<crate::IngressAccessStatus, HostServiceError> {
    let public_key = request
        .credential
        .as_str()
        .strip_prefix("ssh-ed25519:")
        .and_then(decode_hex_32)
        .ok_or_else(|| service_error("vos.invalid-credential", "invalid SSH credential"))?;
    let access = handle
        .authenticate_ssh_public_key(&public_key)
        .map_err(|_| service_error("vos.authority-unavailable", "credential is no longer live"))?;
    if access.expires_at <= now_unix()
        || request.principal.as_str() != format!("member:{}", hex(&access.subject))
    {
        return Err(service_error(
            "vos.invalid-credential",
            "credential is expired or belongs to another member",
        ));
    }
    Ok(access)
}

fn require(access: &crate::IngressAccessStatus, capability: &str) -> Result<(), HostServiceError> {
    access
        .has_capability(crate::CapabilityId::named(capability))
        .then_some(())
        .ok_or_else(|| service_error("vos.forbidden", "member lacks the required capability"))
}

fn host_service(
    handle: IngressHandle,
    blocking: Arc<tokio::sync::Semaphore>,
    request: HostServiceRequest,
) -> impl std::future::Future<Output = Result<Value, HostServiceError>> + Send {
    async move {
        let permit = blocking
            .acquire_owned()
            .await
            .map_err(|_| service_error("vos.shutting-down", "space is shutting down"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let access = access_for_request(&handle, &request)?;
            match request.operation.as_str() {
                "describe" => {
                    let Value::Text(route) = request.args else {
                        return Err(service_error("vos.invalid-request", "route must be text"));
                    };
                    describe(&handle, &access, &route).map(Value::Text)
                }
                "invoke" => invoke(&handle, &access, request.args),
                "put-role" => put_role(&handle, &access, request.args).map(Value::Text),
                "delete-role" => delete_role(&handle, &access, request.args).map(Value::Text),
                "set-member-roles" => {
                    set_member_roles(&handle, &access, request.args).map(Value::Text)
                }
                "revoke-member-roles" => {
                    revoke_member_roles(&handle, &access, request.args).map(Value::Text)
                }
                _ => Err(service_error("vos.unknown-operation", "unknown operation")),
            }
        })
        .await
        .map_err(|_| service_error("vos.worker-failed", "space worker failed"))?
    }
}

fn object_text<'a>(args: &'a Value, key: &str) -> Result<&'a str, HostServiceError> {
    let Value::Map(args) = args else {
        return Err(service_error(
            "vos.invalid-request",
            "arguments must be an object",
        ));
    };
    match args.get(key) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(service_error(
            "vos.invalid-request",
            format!("missing {key}"),
        )),
    }
}

fn authority_target(handle: &IngressHandle) -> Result<crate::ActorId, HostServiceError> {
    handle
        .resolve_actor(crate::service::ROLE_AUTHORITY_INSTANCE_)
        .ok_or_else(|| service_error("vos.authority-unavailable", "role authority unavailable"))
}

fn role_catalogue(
    handle: &IngressHandle,
    access: &crate::IngressAccessStatus,
) -> Result<Vec<crate::SpaceRoleDefinition>, HostServiceError> {
    let reply = handle
        .invoke_actor(
            crate::SubjectId(access.subject),
            authority_target(handle)?,
            dynamic_payload(crate::value::Msg::new("list_roles")),
            false,
        )
        .map_err(|_| service_error("vos.authority-unavailable", "role catalogue unavailable"))?;
    let crate::value::Value::Bytes(bytes) = crate::value::Value::try_decode(&reply)
        .ok_or_else(|| service_error("vos.invalid-reply", "invalid role catalogue"))?
    else {
        return Err(service_error("vos.invalid-reply", "invalid role catalogue"));
    };
    Vec::<crate::SpaceRoleDefinition>::try_decode(&bytes)
        .ok_or_else(|| service_error("vos.invalid-reply", "invalid role catalogue"))
}

fn authority_mutation(
    handle: &IngressHandle,
    access: &crate::IngressAccessStatus,
    message: crate::value::Msg,
    operation_key: &str,
) -> Result<String, HostServiceError> {
    if operation_key.trim().is_empty() || operation_key.len() > 128 {
        return Err(service_error(
            "vos.invalid-request",
            "operation key must contain 1..=128 characters",
        ));
    }
    let reply = handle
        .invoke_actor_idempotent(
            crate::SubjectId(access.subject),
            authority_target(handle)?,
            dynamic_payload(message),
            false,
            "ssh",
            operation_key,
        )
        .map_err(|error| service_error("vos.authority-failed", format!("{error:?}")))?;
    match crate::value::Value::try_decode(&reply) {
        Some(crate::value::Value::Bool(true)) => Ok("Authority change committed".into()),
        _ => Err(service_error(
            "vos.forbidden",
            "authority refused the requested change",
        )),
    }
}

fn put_role(
    handle: &IngressHandle,
    access: &crate::IngressAccessStatus,
    args: Value,
) -> Result<String, HostServiceError> {
    require(access, crate::capability::SPACE_ROLES_MANAGE)?;
    let name = object_text(&args, "role")?.trim();
    let power = object_text(&args, "power")?
        .trim()
        .parse::<u16>()
        .map_err(|_| service_error("vos.invalid-request", "power must be a u16"))?;
    let operation_key = object_text(&args, "operation_key")?;
    let target = authority_target(handle)?;
    let space = handle.actor_space(target).ok_or_else(|| {
        service_error(
            "vos.authority-unavailable",
            "authority identity unavailable",
        )
    })?;
    let mut pairs: Vec<_> = object_text(&args, "capabilities")?
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| (crate::CapabilityId::named(name).0, name.to_owned()))
        .collect();
    pairs.sort_unstable_by_key(|(id, _)| *id);
    pairs.dedup_by_key(|(id, _)| *id);
    if pairs.is_empty() {
        return Err(service_error(
            "vos.invalid-request",
            "at least one capability is required",
        ));
    }
    let (capabilities, capability_names) = pairs.into_iter().unzip();
    let definition = crate::SpaceRoleDefinition {
        id: crate::RoleId::named(space, name).0,
        name: name.to_owned(),
        power,
        capabilities,
        capability_names,
    };
    authority_mutation(
        handle,
        access,
        crate::value::Msg::new("put_role").with("definition", definition.encode()),
        operation_key,
    )
}

fn delete_role(
    handle: &IngressHandle,
    access: &crate::IngressAccessStatus,
    args: Value,
) -> Result<String, HostServiceError> {
    require(access, crate::capability::SPACE_ROLES_MANAGE)?;
    let name = object_text(&args, "role")?.trim();
    let operation_key = object_text(&args, "operation_key")?;
    let role = role_catalogue(handle, access)?
        .into_iter()
        .find(|role| role.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| service_error("vos.not-found", "unknown role"))?;
    authority_mutation(
        handle,
        access,
        crate::value::Msg::new("delete_role").with("role", role.id.to_vec()),
        operation_key,
    )
}

fn set_member_roles(
    handle: &IngressHandle,
    access: &crate::IngressAccessStatus,
    args: Value,
) -> Result<String, HostServiceError> {
    require(access, crate::capability::SPACE_MEMBERS_MANAGE)?;
    let subject = decode_hex_32(object_text(&args, "subject")?.trim())
        .ok_or_else(|| service_error("vos.invalid-request", "subject must be 64 hex characters"))?;
    let catalogue = role_catalogue(handle, access)?;
    let mut roles = Vec::new();
    for name in object_text(&args, "roles")?
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        roles.push(
            catalogue
                .iter()
                .find(|role| role.name.eq_ignore_ascii_case(name))
                .ok_or_else(|| service_error("vos.not-found", format!("unknown role {name}")))?
                .id,
        );
    }
    roles.sort_unstable();
    roles.dedup();
    let encoded = crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(&roles)
        .map_err(|_| service_error("vos.invalid-request", "cannot encode roles"))?;
    authority_mutation(
        handle,
        access,
        crate::value::Msg::new("set_member_roles")
            .with("subject", subject.to_vec())
            .with("roles", crate::value::Value::Bytes(encoded.to_vec())),
        object_text(&args, "operation_key")?,
    )
}

fn revoke_member_roles(
    handle: &IngressHandle,
    access: &crate::IngressAccessStatus,
    args: Value,
) -> Result<String, HostServiceError> {
    require(access, crate::capability::SPACE_MEMBERS_MANAGE)?;
    let subject = decode_hex_32(object_text(&args, "subject")?.trim())
        .ok_or_else(|| service_error("vos.invalid-request", "subject must be 64 hex characters"))?;
    authority_mutation(
        handle,
        access,
        crate::value::Msg::new("revoke_member_roles").with("subject", subject.to_vec()),
        object_text(&args, "operation_key")?,
    )
}

fn describe(
    handle: &IngressHandle,
    access: &crate::IngressAccessStatus,
    route: &str,
) -> Result<String, HostServiceError> {
    match route {
        "/" => {
            require(access, crate::capability::SPACE_DISCOVER)?;
            Ok(format!(
                "Signed in as member {}\n{} active role(s), {} capability/capabilities",
                &hex(&access.subject)[..12],
                access.roles.len(),
                access.capabilities.len(),
            ))
        }
        "/members" => {
            require(access, crate::capability::SPACE_MEMBERS_MANAGE)?;
            describe_members(handle)
        }
        "/roles" => {
            require(access, crate::capability::SPACE_DISCOVER)?;
            describe_roles(handle, access)
        }
        "/catalog" => {
            require(access, crate::capability::AGENT_DISCOVER)?;
            describe_programs(handle)
        }
        "/agents" => {
            require(access, crate::capability::AGENT_DISCOVER)?;
            describe_agents(handle)
        }
        path if path.starts_with("/agents/") => {
            require(access, crate::capability::AGENT_DISCOVER)?;
            match parse_agent_shell_route(path) {
                Some(AgentShellRoute::Agent { agent }) => describe_agent(handle, agent),
                Some(AgentShellRoute::Actors { agent }) => describe_actors(handle, agent),
                Some(AgentShellRoute::Actor { agent, actor }) => {
                    describe_actor(handle, agent, actor)
                }
                Some(AgentShellRoute::Methods { agent, actor }) => {
                    describe_methods(handle, agent, actor)
                }
                Some(AgentShellRoute::Method {
                    agent,
                    actor,
                    method,
                }) => describe_method(handle, agent, actor, method),
                None => Err(service_error(
                    "vos.not-found",
                    "unknown or non-canonical Agent → Actor → Method route",
                )),
            }
        }
        _ => Err(service_error("vos.not-found", "unknown space route")),
    }
}

fn registry_value(
    handle: &IngressHandle,
    message: crate::value::Msg,
) -> Option<crate::value::Value> {
    let encoded = message.encode();
    let mut payload = Vec::with_capacity(encoded.len() + 1);
    payload.push(crate::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    let reply =
        handle.invoke_host_service(ServiceId::REGISTRY, payload, Duration::from_secs(10))?;
    crate::value::Value::try_decode(&reply)
}

fn registry_page<T: Decode>(handle: &IngressHandle, message: crate::value::Msg) -> Option<T> {
    decode_registry_page_value(registry_value(handle, message)?)
}

fn decode_registry_page_value<T: Decode>(value: crate::value::Value) -> Option<T> {
    let crate::value::Value::Bytes(bytes) = value else {
        return None;
    };
    T::try_decode(&bytes)
}

fn agent_page_advances(after: &str, page: &crate::registry::AgentPage) -> bool {
    page.protocol.is_current()
        && !page.rows.iter().any(|row| {
            !crate::registry::is_canonical_registry_slug(&row.instance_name)
                || !crate::registry::is_canonical_registry_slug(&row.program_name)
        })
        && !page
            .rows
            .first()
            .is_some_and(|row| !after.is_empty() && row.instance_name.as_str() <= after)
        && !page
            .rows
            .windows(2)
            .any(|pair| pair[0].instance_name >= pair[1].instance_name)
        && !(page.more && page.rows.is_empty())
}

fn agent_page_is_acceptable(
    after: &str,
    drain: &mut crate::registry::RegistryDrainBudget,
    page: &crate::registry::AgentPage,
) -> bool {
    drain.record_page(page.rows.len(), page.encode().len()) && agent_page_advances(after, page)
}

fn program_page_advances(after: &str, page: &crate::registry::ProgramPage) -> bool {
    page.protocol.is_current()
        && !page
            .rows
            .iter()
            .any(|row| !crate::registry::is_canonical_registry_slug(&row.name))
        && !page
            .rows
            .first()
            .is_some_and(|row| !after.is_empty() && row.name.as_str() <= after)
        && !page
            .rows
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        && !(page.more && page.rows.is_empty())
}

fn program_page_is_acceptable(
    after: &str,
    drain: &mut crate::registry::RegistryDrainBudget,
    page: &crate::registry::ProgramPage,
) -> bool {
    drain.record_page(page.rows.len(), page.encode().len()) && program_page_advances(after, page)
}

fn member_page_is_acceptable(
    after_kind: u8,
    after_key: &[u8],
    drain: &mut crate::registry::RegistryDrainBudget,
    page: &crate::registry::MemberPage,
) -> bool {
    drain.record_page(page.members.len(), page.encode().len())
        && crate::registry::member_page_advances(after_kind, after_key, page)
}

fn describe_agents(handle: &IngressHandle) -> Result<String, HostServiceError> {
    let mut after = String::new();
    let mut rows = Vec::new();
    let mut drain = crate::registry::RegistryDrainBudget::default();
    loop {
        let page: crate::registry::AgentPage = registry_page(
            handle,
            crate::value::Msg::new("service_actors")
                .with("after_name", after.clone())
                .with("budget", 128_u32),
        )
        .ok_or_else(|| service_error("vos.registry-unavailable", "agent catalogue unavailable"))?;
        if !agent_page_is_acceptable(&after, &mut drain, &page) {
            return Err(service_error(
                "vos.registry-protocol",
                "agent catalogue returned an invalid, non-advancing, or oversized page stream",
            ));
        }
        let more = page.more;
        after = page
            .rows
            .last()
            .map(|row| row.instance_name.clone())
            .unwrap_or_default();
        rows.extend(page.rows);
        if !more {
            break;
        }
    }
    if rows.is_empty() {
        return Ok("No agents installed".into());
    }
    Ok(rows
        .into_iter()
        .map(|row| {
            format!(
                "{}  {}  consistency={}\n  s4:/agents/{}",
                row.instance_name, row.program_name, row.consistency, row.instance_name
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn describe_programs(handle: &IngressHandle) -> Result<String, HostServiceError> {
    let mut after = String::new();
    let mut rows = Vec::new();
    let mut drain = crate::registry::RegistryDrainBudget::default();
    loop {
        let page: crate::registry::ProgramPage = registry_page(
            handle,
            crate::value::Msg::new("catalog_programs")
                .with("after_name", after.clone())
                .with("budget", 128_u32),
        )
        .ok_or_else(|| {
            service_error("vos.registry-unavailable", "program catalogue unavailable")
        })?;
        if !program_page_is_acceptable(&after, &mut drain, &page) {
            return Err(service_error(
                "vos.registry-protocol",
                "program catalogue returned an invalid, non-advancing, or oversized page stream",
            ));
        }
        let more = page.more;
        after = page
            .rows
            .last()
            .map(|row| row.name.clone())
            .unwrap_or_default();
        rows.extend(page.rows);
        if !more {
            break;
        }
    }
    Ok(if rows.is_empty() {
        "No packages published".into()
    } else {
        rows.into_iter()
            .map(|row| format!("{}  {}", row.name, &hex(&row.hash)[..12]))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

fn describe_members(handle: &IngressHandle) -> Result<String, HostServiceError> {
    let mut kind = 0_u8;
    let mut key = Vec::new();
    let mut rows = Vec::new();
    let mut drain = crate::registry::RegistryDrainBudget::default();
    loop {
        let page: crate::registry::MemberPage = registry_page(
            handle,
            crate::value::Msg::new("members")
                .with("after_kind", kind)
                .with("after_key", key.clone())
                .with("budget", 128_u32),
        )
        .ok_or_else(|| service_error("vos.registry-unavailable", "member roster unavailable"))?;
        if !member_page_is_acceptable(kind, &key, &mut drain, &page) {
            return Err(service_error(
                "vos.registry-protocol",
                "member roster returned an invalid, non-advancing, or oversized page stream",
            ));
        }
        let more = page.more;
        kind = page.next_kind;
        key = page.next_key;
        rows.extend(page.members);
        if !more {
            break;
        }
    }
    Ok(if rows.is_empty() {
        "No enrolled nodes or identities".into()
    } else {
        rows.into_iter()
            .map(|row| {
                let key = hex(&row.key);
                format!("kind={}  {}", row.kind, &key[..key.len().min(20)])
            })
            .collect::<Vec<_>>()
            .join("\n")
    })
}

fn describe_roles(
    handle: &IngressHandle,
    access: &crate::IngressAccessStatus,
) -> Result<String, HostServiceError> {
    let target = handle
        .resolve_actor(crate::service::ROLE_AUTHORITY_INSTANCE_)
        .ok_or_else(|| service_error("vos.authority-unavailable", "role authority unavailable"))?;
    let payload = dynamic_payload(crate::value::Msg::new("list_roles"));
    let reply = handle
        .invoke_actor(crate::SubjectId(access.subject), target, payload, false)
        .map_err(|_| service_error("vos.authority-unavailable", "role catalogue unavailable"))?;
    let crate::value::Value::Bytes(bytes) = crate::value::Value::try_decode(&reply)
        .ok_or_else(|| service_error("vos.invalid-reply", "invalid role catalogue"))?
    else {
        return Err(service_error("vos.invalid-reply", "invalid role catalogue"));
    };
    let roles = Vec::<crate::SpaceRoleDefinition>::try_decode(&bytes)
        .ok_or_else(|| service_error("vos.invalid-reply", "invalid role catalogue"))?;
    Ok(roles
        .into_iter()
        .map(|role| {
            format!(
                "{}  power={}  capabilities={}",
                role.name,
                role.power,
                role.capability_names.join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn describe_agent(handle: &IngressHandle, name: &str) -> Result<String, HostServiceError> {
    let meta = agent_metadata(handle, name)?;
    Ok(format!(
        "Agent {name}\n\nActors:\n{}\n  s4:/agents/{name}/actors",
        meta.actor_name,
    ))
}

fn describe_actors(handle: &IngressHandle, agent: &str) -> Result<String, HostServiceError> {
    let meta = agent_metadata(handle, agent)?;
    Ok(format!(
        "Actors in {agent}:\n{}\n  s4:/agents/{agent}/actors/{}",
        meta.actor_name, meta.actor_name,
    ))
}

fn require_signed_actor<'a>(
    meta: &'a crate::metadata::ParsedMeta,
    actor: &str,
) -> Result<&'a crate::metadata::ParsedMeta, HostServiceError> {
    if !is_canonical_schema_name(actor) || meta.actor_name != actor {
        return Err(service_error(
            "vos.not-found",
            "actor is not present in the Agent's signed directory schema",
        ));
    }
    Ok(meta)
}

fn describe_actor(
    handle: &IngressHandle,
    agent: &str,
    actor: &str,
) -> Result<String, HostServiceError> {
    let meta = agent_metadata(handle, agent)?;
    require_signed_actor(&meta, actor)?;
    Ok(format!(
        "Actor {agent}/{actor}\n{}\n\nMethods: {}\n  s4:/agents/{agent}/actors/{actor}/methods",
        meta.doc,
        meta.messages.len(),
    ))
}

fn describe_methods(
    handle: &IngressHandle,
    agent: &str,
    actor: &str,
) -> Result<String, HostServiceError> {
    let meta = agent_metadata(handle, agent)?;
    require_signed_actor(&meta, actor)?;
    if meta.messages.is_empty() {
        return Ok(format!("Actor {agent}/{actor} exposes no methods"));
    }
    Ok(meta
        .messages
        .iter()
        .map(|message| {
            format!(
                "{}{} -> {}\n  s4:/agents/{agent}/actors/{actor}/methods/{}",
                message.name,
                if message.is_query {
                    " [query]"
                } else {
                    " [mutation]"
                },
                message.returns,
                message.name,
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn describe_method(
    handle: &IngressHandle,
    agent: &str,
    actor: &str,
    method: &str,
) -> Result<String, HostServiceError> {
    let meta = agent_metadata(handle, agent)?;
    require_signed_actor(&meta, actor)?;
    let method = meta
        .messages
        .iter()
        .find(|candidate| candidate.name == method && is_canonical_schema_name(&candidate.name))
        .ok_or_else(|| {
            service_error(
                "vos.not-found",
                "method is not present in the Actor's signed schema",
            )
        })?;
    Ok(render_method_description(agent, actor, method))
}

fn render_method_description(
    agent: &str,
    actor: &str,
    method: &crate::metadata::ParsedMessage,
) -> String {
    let invocation_kind = if method.is_query { "query" } else { "mutation" };
    let dispatch = match method.mode {
        0 => "synchronous",
        1 => "durable job",
        _ => "unknown (refused by dispatch)",
    };
    let attestation = if method.attested {
        "required"
    } else {
        "not requested"
    };
    let idempotency = if method.is_query {
        "optional"
    } else {
        "required"
    };
    let authorization = if let Some(capability) = &method.capability {
        format!("capability {capability}")
    } else if let Some(role) = method.actor_role {
        format!("actor role {role}")
    } else if let Some(role) = method.space_role {
        format!("space role {role}")
    } else {
        "signed package policy".into()
    };
    format!(
        "Method {agent}/{actor}/{}\n{}\n\nkind: {invocation_kind}\ndispatch: {dispatch}\nreturns: {}\ntimeout_ms: {}\nauthorization: {authorization}\nattestation: {attestation}\nidempotency key: {idempotency}",
        method.name, method.doc, method.returns, method.timeout_ms,
    )
}

fn agent_metadata(
    handle: &IngressHandle,
    name: &str,
) -> Result<crate::metadata::ParsedMeta, HostServiceError> {
    require_canonical_agent_name(name)?;
    if handle.resolve_actor(name).is_none() {
        return Err(service_error(
            "vos.not-found",
            "agent is not attached to this node",
        ));
    }
    let value = registry_value(
        handle,
        crate::value::Msg::new("meta_for_instance").with("name", name.to_owned()),
    )
    .ok_or_else(|| service_error("vos.registry-unavailable", "agent schema unavailable"))?;
    let crate::value::Value::Bytes(bytes) = value else {
        return Err(service_error("vos.invalid-reply", "invalid agent schema"));
    };
    let meta = crate::metadata::decode(&bytes)
        .ok_or_else(|| service_error("vos.not-found", "agent has no canonical schema"))?;
    if !shell_metadata_is_canonical(&meta) {
        return Err(service_error(
            "vos.invalid-reply",
            "agent schema contains non-canonical or ambiguous names",
        ));
    }
    Ok(meta)
}

fn dynamic_payload(message: crate::value::Msg) -> Vec<u8> {
    let encoded = message.encode();
    let mut payload = Vec::with_capacity(encoded.len() + 1);
    payload.push(crate::value::TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    payload
}

fn invoke(
    handle: &IngressHandle,
    access: &crate::IngressAccessStatus,
    args: Value,
) -> Result<Value, HostServiceError> {
    require(access, crate::capability::AGENT_INVOKE)?;
    let Value::Map(args) = args else {
        return Err(service_error(
            "vos.invalid-request",
            "invoke arguments must be an object",
        ));
    };
    let text = |key: &str| match args.get(key) {
        Some(Value::Text(value)) => Some(value.as_str()),
        _ => None,
    };
    let agent =
        text("agent").ok_or_else(|| service_error("vos.invalid-request", "missing agent"))?;
    require_canonical_agent_name(agent)?;
    let actor = text("actor")
        .filter(|value| is_canonical_schema_name(value))
        .ok_or_else(|| service_error("vos.invalid-request", "missing or invalid actor"))?;
    let method = text("method")
        .filter(|value| is_canonical_schema_name(value))
        .ok_or_else(|| service_error("vos.invalid-request", "missing or invalid method"))?;
    let key = text("idempotency_key").unwrap_or_default();
    let target = handle
        .resolve_actor(agent)
        .ok_or_else(|| service_error("vos.not-found", "agent is not attached to this node"))?;
    let meta = agent_metadata(handle, agent)?;
    require_signed_actor(&meta, actor)?;
    let method_meta = meta
        .messages
        .iter()
        .find(|candidate| candidate.name == method)
        .ok_or_else(|| {
            service_error("vos.not-found", "method is not in the signed actor schema")
        })?;
    let idempotency_key = ssh_invocation_key(method_meta, key)?;
    let payload = dynamic_payload(crate::value::Msg::new(method));
    let reply = if let Some(key) = idempotency_key {
        handle.invoke_actor_idempotent(
            crate::SubjectId(access.subject),
            target,
            payload,
            method_meta.attested,
            "ssh",
            key,
        )
    } else {
        handle.invoke_actor(
            crate::SubjectId(access.subject),
            target,
            payload,
            method_meta.attested,
        )
    }
    .map_err(|error| service_error("vos.invoke-failed", format!("{error:?}")))?;
    ssh_invoke_result(reply, method_meta.attested)
}

fn require_canonical_agent_name(name: &str) -> Result<(), HostServiceError> {
    if is_canonical_agent_name(name) {
        Ok(())
    } else {
        Err(service_error(
            "vos.invalid-request",
            "agent name is not a canonical registry slug",
        ))
    }
}

fn ssh_invoke_result(reply: Vec<u8>, attested: bool) -> Result<Value, HostServiceError> {
    if attested {
        let result = crate::service::RootTreeAttestedResult::decode(&reply).map_err(|_| {
            service_error("vos.invalid-reply", "actor returned invalid attestation")
        })?;
        let rendered = render_actor_reply(&result.reply)?;
        return Ok(attested_invoke_value(rendered, reply));
    }
    render_actor_reply(&reply).map(Value::Text)
}

fn render_actor_reply(reply: &[u8]) -> Result<String, HostServiceError> {
    if reply.is_empty() {
        return Ok("Completed".into());
    }
    let value = crate::value::Value::try_decode(reply)
        .ok_or_else(|| service_error("vos.invalid-reply", "actor returned invalid data"))?;
    Ok(format!("{value:?}"))
}

fn attested_invoke_value(reply: String, wire: Vec<u8>) -> Value {
    Value::object([
        ("reply".into(), Value::Text(reply)),
        ("attestation_wire".into(), Value::Bytes(wire)),
    ])
}

fn ssh_invocation_key<'a>(
    method: &crate::metadata::ParsedMessage,
    key: &'a str,
) -> Result<Option<&'a str>, HostServiceError> {
    if key.len() > 128 || !key.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(service_error(
            "vos.invalid-request",
            "idempotency key must contain 1..=128 visible ASCII characters",
        ));
    }
    if !method.is_query && key.is_empty() {
        return Err(service_error(
            "vos.idempotency-required",
            "mutating methods require an idempotency key",
        ));
    }
    Ok((!key.is_empty()).then_some(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SshIngressConfig {
        SshIngressConfig {
            name: "space-shell".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            host_key: "/tmp/vos-ssh-test-key".into(),
            max_connections: 8,
            max_sessions_per_member: 2,
        }
    }

    #[test]
    fn agent_shell_routes_are_exactly_nested() {
        assert_eq!(
            parse_agent_shell_route("/agents/notes"),
            Some(AgentShellRoute::Agent { agent: "notes" }),
        );
        assert_eq!(
            parse_agent_shell_route("/agents/notes/actors"),
            Some(AgentShellRoute::Actors { agent: "notes" }),
        );
        assert_eq!(
            parse_agent_shell_route("/agents/notes/actors/Board"),
            Some(AgentShellRoute::Actor {
                agent: "notes",
                actor: "Board",
            }),
        );
        assert_eq!(
            parse_agent_shell_route("/agents/notes/actors/Board/methods"),
            Some(AgentShellRoute::Methods {
                agent: "notes",
                actor: "Board",
            }),
        );
        assert_eq!(
            parse_agent_shell_route("/agents/notes/actors/Board/methods/add_task"),
            Some(AgentShellRoute::Method {
                agent: "notes",
                actor: "Board",
                method: "add_task",
            }),
        );
    }

    #[test]
    fn agent_shell_routes_reject_legacy_alias_and_traversal_shapes() {
        for route in [
            "/agents/notes/add_task",
            "/agents/notes/actors/Board/add_task",
            "/agents/notes/actors/Board/methods/add_task/extra",
            "/agents//actors/Board",
            "/agents/notes/actors//methods/add_task",
            "/agents/notes/actors/Board/methods/",
            "/agents/notes/actors/../methods/add_task",
            "/agents/notes/actors/Board%2fOther/methods/add_task",
            "/agents/notes/actors/Board/methods/%61dd_task",
            "/agents/Bad_Name/actors/Board",
            "/agents/notes\\alias/actors/Board",
        ] {
            assert!(
                parse_agent_shell_route(route).is_none(),
                "accepted non-canonical shell route {route:?}",
            );
        }
    }

    #[test]
    fn listener_configuration_is_fail_closed() {
        assert!(validate_config(&config()).is_ok());
        let mut invalid = config();
        invalid.name.clear();
        assert!(matches!(
            validate_config(&invalid),
            Err(SshIngressError::InvalidConfig(_))
        ));
        let mut invalid = config();
        invalid.name = "../escape".into();
        assert!(validate_config(&invalid).is_err());
        let mut invalid = config();
        invalid.max_connections = 0;
        assert!(validate_config(&invalid).is_err());
        let mut invalid = config();
        invalid.host_key.clear();
        assert!(validate_config(&invalid).is_err());
    }

    #[test]
    fn accepted_work_outlives_the_s4_default_deadline() {
        let limits = server_limits(&config());
        assert_eq!(limits.host_services.timeout, Duration::MAX);
        assert!(limits.host_services.timeout > Duration::from_secs(35));
    }

    #[test]
    fn ssh_identities_separate_member_and_device() {
        let subject = [0x11; 32];
        let first = [0x22; 32];
        let second = [0x33; 32];
        let principal = identity("member", &subject).unwrap();
        assert_eq!(principal.as_str(), format!("member:{}", hex(&subject)));
        assert_ne!(
            identity("ssh-ed25519", &first).unwrap(),
            identity("ssh-ed25519", &second).unwrap()
        );
        assert_eq!(decode_hex_32(&hex(&subject)), Some(subject));
        assert_eq!(decode_hex_32("not-a-subject"), None);
    }

    #[test]
    fn ssh_credentials_use_only_canonical_nonweak_ed25519_keys() {
        use ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};

        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x62; 32]);
        let raw = signing.verifying_key().to_bytes();
        let plain = ssh_key::PublicKey::new(
            KeyData::Ed25519(Ed25519PublicKey(raw)),
            "comment-is-not-identity",
        );
        assert_eq!(canonical_ssh_ed25519_public_key(&plain), Some(raw));
        assert_eq!(
            crate::agent::sdk::CredentialId::of_public_key(&raw),
            crate::agent::sdk::CredentialId::of_public_key(
                &canonical_ssh_ed25519_public_key(&plain).unwrap()
            )
        );

        let security_key = ssh_key::PublicKey::new(
            KeyData::SkEd25519(SkEd25519::new(Ed25519PublicKey(raw), "ssh:")),
            "",
        );
        assert!(canonical_ssh_ed25519_public_key(&security_key).is_none());

        let weak = ssh_key::PublicKey::new(KeyData::Ed25519(Ed25519PublicKey([0; 32])), "");
        assert!(canonical_ssh_ed25519_public_key(&weak).is_none());
    }

    #[test]
    fn capability_checks_use_the_authenticated_union() {
        let capability = crate::CapabilityId::named(crate::capability::AGENT_INVOKE);
        let allowed = crate::IngressAccessStatus {
            credential_id: [1; 32],
            subject: [2; 32],
            roles: Vec::new(),
            capabilities: vec![capability.0],
            power: 100,
            expires_at: u64::MAX,
        };
        assert!(require(&allowed, crate::capability::AGENT_INVOKE).is_ok());
        assert!(require(&allowed, crate::capability::AGENT_UPGRADE).is_err());
    }

    #[test]
    fn signed_method_metadata_controls_idempotency_and_attestation() {
        let method = |is_query, attested| crate::metadata::ParsedMessage {
            name: "call".into(),
            is_query,
            fields: Vec::new(),
            exposed_to_cli: false,
            returns: "()".into(),
            doc: String::new(),
            timeout_ms: 0,
            mode: 0,
            attested,
            space_role: None,
            actor_role: None,
            capability: None,
        };
        assert_eq!(ssh_invocation_key(&method(true, false), "").unwrap(), None);
        assert!(ssh_invocation_key(&method(false, false), "").is_err());
        assert_eq!(
            ssh_invocation_key(&method(false, true), "transfer-42").unwrap(),
            Some("transfer-42"),
        );
        assert!(ssh_invocation_key(&method(false, false), &"x".repeat(129)).is_err());
        assert!(method(false, true).attested);
    }

    #[test]
    fn method_screen_displays_signed_invocation_requirements() {
        let method = crate::metadata::ParsedMessage {
            name: "add_task".into(),
            is_query: false,
            fields: Vec::new(),
            exposed_to_cli: false,
            returns: "TaskId".into(),
            doc: "Create one task".into(),
            timeout_ms: 5_000,
            mode: 1,
            attested: true,
            space_role: None,
            actor_role: None,
            capability: Some("board.write".into()),
        };
        let rendered = render_method_description("notes", "Board", &method);
        for expected in [
            "Method notes/Board/add_task",
            "kind: mutation",
            "dispatch: durable job",
            "authorization: capability board.write",
            "attestation: required",
            "idempotency key: required",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected:?}: {rendered}"
            );
        }
    }

    #[test]
    fn shell_metadata_rejects_name_aliases_duplicate_methods_and_unknown_dispatch() {
        let method = crate::metadata::ParsedMessage {
            name: "get_value".into(),
            is_query: true,
            fields: Vec::new(),
            exposed_to_cli: false,
            returns: "u64".into(),
            doc: String::new(),
            timeout_ms: 1_000,
            mode: 0,
            attested: false,
            space_role: None,
            actor_role: None,
            capability: None,
        };
        let mut meta = crate::metadata::ParsedMeta {
            actor_name: "Counter".into(),
            messages: vec![method.clone()],
            constructor: Vec::new(),
            doc: String::new(),
            crdt: false,
            provable: false,
        };
        assert!(shell_metadata_is_canonical(&meta));

        meta.messages.push(method.clone());
        assert!(!shell_metadata_is_canonical(&meta));
        meta.messages.pop();
        meta.messages[0].name = "../get".into();
        assert!(!shell_metadata_is_canonical(&meta));
        meta.messages[0] = method;
        meta.messages[0].mode = 2;
        assert!(!shell_metadata_is_canonical(&meta));
        meta.messages[0].mode = 0;
        meta.actor_name = "Counter%2fOther".into();
        assert!(!shell_metadata_is_canonical(&meta));
    }

    #[test]
    fn ssh_registry_pages_fail_closed_on_protocol_or_progress_faults() {
        use crate::registry::{AgentPage, AgentRow, ProgramKind, ProgramPage, ProgramRow};
        use crate::service::InstallationId;

        let agent = |name: &str| AgentRow {
            instance_name: name.into(),
            installation_id: InstallationId::new([0x11; 32]),
            revision: 0,
            program_hash: [0x22; 32],
            program_name: "worker-program".into(),
            program_publication_id: crate::registry::PublicationId::new([0x33; 32]),
            replication_id: [0x44; 32],
            consistency: crate::node::Consistency::Local as u8,
            network_reachable: false,
            sync_role: crate::registry::SyncFloor::Member,
        };
        let program = |name: &str| ProgramRow {
            name: name.into(),
            hash: [0x55; 32],
            publication_id: crate::registry::PublicationId::new([0x66; 32]),
            kind: ProgramKind::Service { crdt: false },
        };
        let current = crate::registry::RegistryProtocol::CURRENT;

        assert!(agent_page_advances(
            "a",
            &AgentPage {
                protocol: current,
                rows: vec![agent("b")],
                more: false,
            }
        ));
        assert!(!agent_page_advances(
            "",
            &AgentPage {
                protocol: crate::registry::RegistryProtocol::UNSUPPORTED,
                rows: vec![agent("a")],
                more: false,
            }
        ));
        assert!(!agent_page_advances(
            "a",
            &AgentPage {
                protocol: current,
                rows: vec![agent("a")],
                more: false,
            }
        ));
        assert!(!agent_page_advances(
            "",
            &AgentPage {
                protocol: current,
                rows: vec![agent("Bad_Name")],
                more: false,
            }
        ));
        let mut bad_program = agent("worker");
        bad_program.program_name = "bad/program".into();
        assert!(!agent_page_advances(
            "",
            &AgentPage {
                protocol: current,
                rows: vec![bad_program],
                more: false,
            }
        ));
        assert!(!agent_page_advances(
            "",
            &AgentPage {
                protocol: current,
                rows: Vec::new(),
                more: true,
            }
        ));

        assert!(program_page_advances(
            "a",
            &ProgramPage {
                protocol: current,
                rows: vec![program("b")],
                more: false,
            }
        ));
        assert!(!program_page_advances(
            "",
            &ProgramPage {
                protocol: crate::registry::RegistryProtocol::UNSUPPORTED,
                rows: vec![program("a")],
                more: false,
            }
        ));
        assert!(!program_page_advances(
            "a",
            &ProgramPage {
                protocol: current,
                rows: vec![program("a")],
                more: false,
            }
        ));
        assert!(!program_page_advances(
            "",
            &ProgramPage {
                protocol: current,
                rows: vec![program("Bad_Name")],
                more: false,
            }
        ));
        assert!(!program_page_advances(
            "",
            &ProgramPage {
                protocol: current,
                rows: Vec::new(),
                more: true,
            }
        ));
    }

    #[test]
    fn ssh_catalog_drains_reject_endless_full_pages_and_byte_overflow() {
        use crate::registry::{AgentPage, AgentRow, ProgramKind, ProgramPage, ProgramRow};
        use crate::service::InstallationId;

        let names = |prefix: char, page: usize| {
            (0..128)
                .map(|offset| format!("{prefix}{:05}", page * 128 + offset))
                .collect::<Vec<_>>()
        };
        let agent_page = |page: usize| AgentPage {
            protocol: crate::registry::RegistryProtocol::CURRENT,
            rows: names('a', page)
                .into_iter()
                .map(|instance_name| AgentRow {
                    instance_name,
                    installation_id: InstallationId::new([0x11; 32]),
                    revision: 0,
                    program_hash: [0x12; 32],
                    program_name: "worker-program".into(),
                    program_publication_id: crate::registry::PublicationId::new([0x13; 32]),
                    replication_id: [0x14; 32],
                    consistency: crate::node::Consistency::Local as u8,
                    network_reachable: false,
                    sync_role: crate::registry::SyncFloor::Member,
                })
                .collect(),
            more: true,
        };
        let mut agent_budget =
            crate::registry::RegistryDrainBudget::with_limits(2, 256, usize::MAX);
        let first = agent_page(0);
        assert!(agent_page_is_acceptable("", &mut agent_budget, &first));
        let second = agent_page(1);
        assert!(agent_page_is_acceptable(
            &first.rows.last().unwrap().instance_name,
            &mut agent_budget,
            &second,
        ));
        let third = agent_page(2);
        assert!(!agent_page_is_acceptable(
            &second.rows.last().unwrap().instance_name,
            &mut agent_budget,
            &third,
        ));

        let program_page = |page: usize| ProgramPage {
            protocol: crate::registry::RegistryProtocol::CURRENT,
            rows: names('p', page)
                .into_iter()
                .map(|name| ProgramRow {
                    name,
                    hash: [0x21; 32],
                    publication_id: crate::registry::PublicationId::new([0x22; 32]),
                    kind: ProgramKind::Service { crdt: false },
                })
                .collect(),
            more: true,
        };
        let mut program_budget =
            crate::registry::RegistryDrainBudget::with_limits(2, 256, usize::MAX);
        let first = program_page(0);
        assert!(program_page_is_acceptable("", &mut program_budget, &first,));
        let second = program_page(1);
        assert!(program_page_is_acceptable(
            &first.rows.last().unwrap().name,
            &mut program_budget,
            &second,
        ));
        let third = program_page(2);
        assert!(!program_page_is_acceptable(
            &second.rows.last().unwrap().name,
            &mut program_budget,
            &third,
        ));

        let terminal = ProgramPage {
            protocol: crate::registry::RegistryProtocol::CURRENT,
            rows: vec![ProgramRow {
                name: "worker".into(),
                hash: [0x31; 32],
                publication_id: crate::registry::PublicationId::new([0x32; 32]),
                kind: ProgramKind::Service { crdt: false },
            }],
            more: false,
        };
        let mut byte_limited =
            crate::registry::RegistryDrainBudget::with_limits(1, 1, terminal.encode().len() - 1);
        assert!(!program_page_is_acceptable(
            "",
            &mut byte_limited,
            &terminal,
        ));
    }

    #[test]
    fn ssh_registry_page_decoder_rejects_wrong_shapes_and_malformed_archives() {
        use crate::registry::{ProgramPage, RegistryProtocol};

        assert!(decode_registry_page_value::<ProgramPage>(crate::value::Value::Unit).is_none());
        assert!(
            decode_registry_page_value::<ProgramPage>(crate::value::Value::Bytes(vec![1, 2, 3]))
                .is_none()
        );

        let page = ProgramPage {
            protocol: RegistryProtocol::CURRENT,
            rows: Vec::new(),
            more: false,
        };
        assert_eq!(
            decode_registry_page_value::<ProgramPage>(crate::value::Value::Bytes(page.encode())),
            Some(page),
        );
    }

    #[test]
    fn ssh_member_pages_fail_closed_on_progress_shape_and_bounds_faults() {
        use crate::registry::{
            MEMBER_KIND_IDENTITY, MEMBER_KIND_NODE, MemberPage, MemberRow, NODE_ROLE_VOTER,
        };

        let node = |prefix: u16| MemberRow {
            kind: MEMBER_KIND_NODE,
            key: vec![prefix as u8 + 1],
            prefix,
            role: NODE_ROLE_VOTER,
            proof_kind: 0,
            proof_data: Vec::new(),
        };
        let valid = MemberPage {
            members: vec![node(1)],
            next_kind: MEMBER_KIND_IDENTITY,
            next_key: Vec::new(),
            more: true,
        };
        let mut budget = crate::registry::RegistryDrainBudget::default();
        assert!(member_page_is_acceptable(0, &[], &mut budget, &valid,));
        let mut budget = crate::registry::RegistryDrainBudget::default();
        assert!(!member_page_is_acceptable(
            MEMBER_KIND_NODE,
            &1_u16.to_be_bytes(),
            &mut budget,
            &valid,
        ));

        let empty_more = MemberPage {
            members: Vec::new(),
            next_kind: MEMBER_KIND_IDENTITY,
            next_key: Vec::new(),
            more: true,
        };
        let mut budget = crate::registry::RegistryDrainBudget::default();
        assert!(!member_page_is_acceptable(
            MEMBER_KIND_NODE,
            &[],
            &mut budget,
            &empty_more,
        ));

        let mut malformed = valid.clone();
        malformed.members[0].kind = 99;
        let mut budget = crate::registry::RegistryDrainBudget::default();
        assert!(!member_page_is_acceptable(
            MEMBER_KIND_NODE,
            &[],
            &mut budget,
            &malformed,
        ));
        let mut exhausted =
            crate::registry::RegistryDrainBudget::with_limits(0, usize::MAX, usize::MAX);
        assert!(!member_page_is_acceptable(
            MEMBER_KIND_NODE,
            &[],
            &mut exhausted,
            &valid,
        ));
    }

    #[test]
    fn direct_ssh_actor_names_share_the_registry_slug_boundary() {
        for valid in ["a", "worker-01", "space-authority"] {
            assert!(require_canonical_agent_name(valid).is_ok());
        }
        for invalid in ["", "Bad_Name", "worker/other", "é"] {
            assert!(require_canonical_agent_name(invalid).is_err());
        }
    }

    #[test]
    fn attested_shell_results_preserve_and_render_the_complete_wire() {
        let wire = b"VARW-complete-proof-package".to_vec();
        let value = attested_invoke_value("U64(7)".into(), wire.clone());
        let Value::Map(fields) = &value else {
            panic!("attested result must be structured");
        };
        assert_eq!(fields.get("reply"), Some(&Value::Text("U64(7)".into())));
        assert_eq!(
            fields.get("attestation_wire"),
            Some(&Value::Bytes(wire.clone())),
        );
        let rendered = effect_text(EffectOutput::HostService(Ok(value)));
        assert!(rendered.contains("U64(7)"));
        assert!(rendered.contains(&hex(&wire)));
    }
}
