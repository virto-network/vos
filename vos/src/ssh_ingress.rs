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
    let limits = ServerLimits {
        max_connections: config.max_connections,
        max_sessions_per_identity: config.max_sessions_per_member,
        ..ServerLimits::default()
    };

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
                let public_key = public_key
                    .to_bytes()
                    .map_err(|error| AuthError::new(error.to_string()))?;
                let credential_id = crate::ssh_credential_id(&public_key);
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
                    identity("ssh", &credential_id)?,
                )))
            }
        })
        .host_service_fn(SHELL_SERVICE, move |request| {
            host_service(service_handle.clone(), service_blocking.clone(), request)
        })
        .limits(limits)
}

#[derive(Clone)]
enum Message {
    Loaded(EffectOutput),
    Method(String),
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

struct SpaceApp {
    route: String,
    content: String,
    method: String,
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
            method: String::new(),
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
        if self.route.starts_with("/agents/") {
            page = page
                .text("Invoke a no-argument method")
                .field(self.method.clone(), Message::Method)
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
            Message::Method(method) => self.method = method,
            Message::IdempotencyKey(key) => self.idempotency_key = key,
            Message::RoleName(value) => self.role_name = value,
            Message::RolePower(value) => self.role_power = value,
            Message::RoleCapabilities(value) => self.role_capabilities = value,
            Message::MemberSubject(value) => self.member_subject = value,
            Message::MemberRoles(value) => self.member_roles = value,
            Message::OperationKey(value) => self.operation_key = value,
            Message::Invoke => {
                let Some(agent) = self.route.strip_prefix("/agents/") else {
                    return;
                };
                self.content = "Invoking…".into();
                cx.effect(Effect::host_service(
                    INVOKE_EFFECT,
                    Self::identifier(SHELL_SERVICE),
                    Self::identifier("invoke"),
                    Value::object([
                        ("agent".into(), Value::Text(agent.into())),
                        ("method".into(), Value::Text(self.method.clone())),
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
    let credential = request
        .credential
        .as_str()
        .strip_prefix("ssh:")
        .and_then(decode_hex_32)
        .ok_or_else(|| service_error("vos.invalid-credential", "invalid SSH credential"))?;
    let access = handle
        .authenticate_credential(credential)
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
                "invoke" => invoke(&handle, &access, request.args).map(Value::Text),
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
            describe_agent(handle, &path[8..])
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
    let crate::value::Value::Bytes(bytes) = registry_value(handle, message)? else {
        return None;
    };
    T::try_decode(&bytes)
}

fn describe_agents(handle: &IngressHandle) -> Result<String, HostServiceError> {
    let mut after = String::new();
    let mut rows = Vec::new();
    loop {
        let page: crate::registry::AgentPage = registry_page(
            handle,
            crate::value::Msg::new("agents")
                .with("after_name", after)
                .with("budget", 128_u32),
        )
        .ok_or_else(|| service_error("vos.registry-unavailable", "agent catalogue unavailable"))?;
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
    loop {
        let page: crate::registry::ProgramPage = registry_page(
            handle,
            crate::value::Msg::new("programs")
                .with("after_name", after)
                .with("budget", 128_u32),
        )
        .ok_or_else(|| {
            service_error("vos.registry-unavailable", "program catalogue unavailable")
        })?;
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
    loop {
        let page: crate::registry::MemberPage = registry_page(
            handle,
            crate::value::Msg::new("members")
                .with("after_kind", kind)
                .with("after_key", key)
                .with("budget", 128_u32),
        )
        .ok_or_else(|| service_error("vos.registry-unavailable", "member roster unavailable"))?;
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
        "{}\n{}\n\nMethods:\n{}",
        meta.actor_name,
        meta.doc,
        meta.messages
            .into_iter()
            .map(|message| {
                format!(
                    "{}{} -> {}",
                    message.name,
                    if message.is_query { " [query]" } else { "" },
                    message.returns
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

fn agent_metadata(
    handle: &IngressHandle,
    name: &str,
) -> Result<crate::metadata::ParsedMeta, HostServiceError> {
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
    crate::metadata::decode(&bytes)
        .ok_or_else(|| service_error("vos.not-found", "agent has no canonical schema"))
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
) -> Result<String, HostServiceError> {
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
    let method = text("method")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| service_error("vos.invalid-request", "method must not be empty"))?;
    let key = text("idempotency_key").unwrap_or_default();
    let target = handle
        .resolve_actor(agent)
        .ok_or_else(|| service_error("vos.not-found", "agent is not attached to this node"))?;
    let meta = agent_metadata(handle, agent)?;
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
    let reply = if method_meta.attested {
        crate::service::RootTreeAttestedResult::decode(&reply)
            .map_err(|_| service_error("vos.invalid-reply", "actor returned invalid attestation"))?
            .reply
    } else {
        reply
    };
    if reply.is_empty() {
        return Ok("Completed".into());
    }
    let value = crate::value::Value::try_decode(&reply)
        .ok_or_else(|| service_error("vos.invalid-reply", "actor returned invalid data"))?;
    Ok(format!("{value:?}"))
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
    fn ssh_identities_separate_member_and_device() {
        let subject = [0x11; 32];
        let first = [0x22; 32];
        let second = [0x33; 32];
        let principal = identity("member", &subject).unwrap();
        assert_eq!(principal.as_str(), format!("member:{}", hex(&subject)));
        assert_ne!(
            identity("ssh", &first).unwrap(),
            identity("ssh", &second).unwrap()
        );
        assert_eq!(decode_hex_32(&hex(&subject)), Some(subject));
        assert_eq!(decode_hex_32("not-a-subject"), None);
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
}
