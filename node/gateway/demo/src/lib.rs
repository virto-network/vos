//! The s4 demo on a local space: one node of a
//! founded space whose agent holds the credential actor, the poll and the
//! ledger (`Payments`), an operator who
//! invites members and mints, and the
//! gateway's SSH port serving the demo's screens over the node's socket.
//! A phone runs it through `adb reverse`; the end-to-end test
//! drives it with a headless client.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use vos_gateway::Gateway;
use vos_gateway::app::AppClient;
use vos_gateway::demo::Demo;
use vos_gateway::limits::{Limits, PerAddress};
use vos_gateway::upstream::{Address, Upstream};
use vos_node::client::{self, Client, Operator, Target};
use vos_node::{Config, Node};
use vos_testkit::programs::{actor_elf, agent, method};
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::ingress::{Install, Response};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, WindowClock};

/// The instances the agent holds.
pub const CREDENTIALS: InstanceId = InstanceId(9);
pub const PAYMENTS: InstanceId = InstanceId(2);
pub const POLL: InstanceId = InstanceId(3);
/// The operator's role byte, the registrar's too: one key holds both.
const ROLE: u8 = 1;
/// How long an invitation stands.
pub const INVITATION_MS: u64 = 600_000;

/// One node of a founded space, its agent and its operator.
pub struct LocalSpace {
    node: Node,
    socket: PathBuf,
    agent: AgentId,
    operator: Mutex<Client>,
    programs: [(InstanceId, Vec<u8>); 3],
}

fn ran(name: &str, answer: Result<Response, client::ClientError>) -> Result<Vec<u8>, String> {
    match answer {
        Ok(Response::Ran {
            outcome: Outcome::Done(reply),
            ..
        }) => Ok(reply),
        other => Err(format!("{name}: {other:?}")),
    }
}

impl LocalSpace {
    /// Found a space of one node at `data`, the credential actor's handle
    /// `handle`, the operator's key `operator`.
    pub fn found(data: &Path, handle: [u8; 32], operator: [u8; 32]) -> Result<Self, String> {
        let program = agent();
        let space = {
            let mut config = Config::new(program.clone());
            config.executors = 2;
            let node = Node::open(data, config).map_err(|error| format!("{error:?}"))?;
            let key = node.id().0;
            node.shutdown();
            let peer = std::net::UdpSocket::bind("127.0.0.1:0")
                .and_then(|socket| socket.local_addr())
                .map_err(|error| error.to_string())?;
            let space = vos_node::Space::new(vec![vos_node::SpaceNode {
                number: 1,
                key,
                peer,
                contact: "http://127.0.0.1:1".into(),
            }])?;
            let genesis = space.found(WindowClock::DEFAULT, vos_node::wall_clock(), random())?;
            space.with_genesis(genesis)?
        };
        let key = SigningKey::from_bytes(&operator);
        let mut config = Config::new(program);
        config.executors = 2;
        config.space = Some(space);
        config.operators = vec![key.verifying_key().to_bytes()];
        let node = Node::open(data, config).map_err(|error| format!("{error:?}"))?;
        let socket = data.join("api.sock");
        node.serve_socket(&socket, 0o600)
            .map_err(|error| format!("{error:?}"))?;
        let target = Target::socket(socket.clone());
        let signed = Operator::signing(&target, key.clone(), node.id());
        let agent = match signed.create_agent(vec![1]) {
            Ok(Response::Created(agent)) => agent,
            other => return Err(format!("the agent: {other:?}")),
        };
        let elf =
            |path: PathBuf| std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()));
        let installs = [
            (
                CREDENTIALS,
                elf(vos_testkit::programs::credentials_elf())?,
                "registrar",
            ),
            (POLL, elf(actor_elf("poll"))?, "operator"),
            (
                PAYMENTS,
                elf(vos_testkit::programs::payments_elf())?,
                "operator",
            ),
        ];
        for (instance, elf, role) in &installs {
            let install = Install {
                instance: *instance,
                elf: elf.clone(),
                roles: vec![(role.as_bytes().to_vec(), ROLE)],
            };
            match signed.install(agent, &install) {
                Ok(Response::Ran { .. }) => {}
                other => return Err(format!("installing {role}: {other:?}")),
            }
        }
        let principal = Principal::Client(key.verifying_key().to_bytes());
        match signed.grant(agent, principal, Some(ROLE)) {
            Ok(Response::Ran { .. }) => {}
            other => return Err(format!("the operator's role: {other:?}")),
        }
        let space = Self {
            node,
            socket,
            agent,
            operator: Mutex::new(Client::new(&target, key)),
            programs: [
                (CREDENTIALS, vos_testkit::programs::credentials()),
                (POLL, vos_testkit::programs::actor("poll")),
                (PAYMENTS, vos_testkit::programs::payments()),
            ],
        };
        space.write(CREDENTIALS, "found", handle)?;
        Ok(space)
    }

    pub fn agent(&self) -> AgentId {
        self.agent
    }

    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn shutdown(self) {
        self.node.shutdown();
    }

    /// The demo the gateway's file names for this space.
    pub fn demo(&self) -> Demo {
        Demo {
            agent: self.agent.0,
            credentials: CREDENTIALS.0,
            payments: PAYMENTS.0,
            poll: POLL.0,
            onions: Vec::new(),
        }
    }

    fn program(&self, instance: InstanceId) -> &[u8] {
        &self
            .programs
            .iter()
            .find(|(at, _)| *at == instance)
            .expect("an installed instance")
            .1
    }

    /// The operator's call of `name` at `instance`: its reply.
    pub fn write<A: Encode>(
        &self,
        instance: InstanceId,
        name: &str,
        arguments: A,
    ) -> Result<Vec<u8>, String> {
        let method = method(self.program(instance), name);
        let answer = self.operator.lock().expect("operator poisoned").call(
            self.agent,
            instance,
            method,
            &arguments.encode(),
        );
        ran(name, answer)
    }

    /// The operator's query of `name` at `instance`, decoded.
    pub fn read<A: Encode, R: Decode>(
        &self,
        instance: InstanceId,
        name: &str,
        arguments: A,
    ) -> Result<R, String> {
        let method = method(self.program(instance), name);
        let not_after = self.now()? + 60_000;
        let answer = self.operator.lock().expect("operator poisoned").query(
            self.agent,
            instance,
            method,
            &arguments.encode(),
            not_after,
        );
        R::decode_exact(&ran(name, answer)?)
            .ok_or_else(|| format!("{name}: the reply does not decode"))
    }

    pub fn now(&self) -> Result<u64, String> {
        client::time(&Target::socket(self.socket.clone())).map_err(|error| format!("{error:?}"))
    }

    /// Invite a member's two digests: `member` into the credential actor's
    /// tree, recorded with `owner` as its person's first device, so the
    /// member's devices enroll one another (a member registered already is
    /// refused there, `Held`); and the account `account` for `owner`.
    pub fn invite(&self, member: [u8; 32], account: &str, owner: [u8; 32]) -> Result<(), String> {
        let expires = self.now()? + INVITATION_MS;
        self.write(CREDENTIALS, "invite", (member, expires))?;
        self.write(
            CREDENTIALS,
            "register",
            (member, owner, vos_wire::credentials::MAX_DEVICES),
        )?;
        self.write(
            PAYMENTS,
            "invite",
            (account.as_bytes().to_vec(), owner, expires),
        )?;
        Ok(())
    }

    /// An account opened by the operator's invitation for `owner`, as a
    /// shop or another member would hold, minted `amount` unless nothing.
    pub fn open_account(&self, account: &str, owner: [u8; 32], amount: u64) -> Result<(), String> {
        let expires = self.now()? + INVITATION_MS;
        let name = account.as_bytes().to_vec();
        self.write(PAYMENTS, "invite", (name.clone(), owner, expires))?;
        self.write(PAYMENTS, "open", (name, owner))?;
        match amount {
            0 => Ok(()),
            _ => self.mint(account, amount),
        }
    }

    pub fn mint(&self, account: &str, amount: u64) -> Result<(), String> {
        self.write(PAYMENTS, "mint", (account.as_bytes().to_vec(), amount))
            .map(|_| ())
    }

    /// `account`'s balance, `None` for no such account.
    pub fn balance(&self, account: &str) -> Result<Option<u64>, String> {
        self.read(PAYMENTS, "balance", account.as_bytes().to_vec())
    }

    /// The gateway on this node's socket, its SSH port on `listener`
    /// serving the demo, its host key `host_key` and the app's key
    /// `app`; the enrollment pins `onions`, the onion keys a device sends
    /// its proofs to (an onion in front of this port).
    pub fn gateway(
        &self,
        listener: tokio::net::TcpListener,
        host_key: russh::keys::PrivateKey,
        app: [u8; 32],
        onions: Vec<[u8; 32]>,
    ) -> tokio::task::JoinHandle<()> {
        let gateway = Arc::new(Gateway::new(vec![Upstream::new(
            self.node.id().0,
            Address::Socket(self.socket.clone()),
            random(),
        )]));
        let mark = vos_api::Mark::Clearnet;
        let app = Arc::new(AppClient::new(app, Arc::clone(&gateway), mark));
        let port = vos_gateway::ssh::Port::new(
            mark,
            Limits::new(PerAddress::default()),
            vos_gateway::caps::Caps::none(),
            vos_gateway::caps::bodies(),
        );
        let demo = Demo {
            onions,
            ..self.demo()
        };
        let server = vos_gateway::ssh::server(host_key, gateway, port, Some((demo, app)));
        tokio::spawn(async move {
            if let Err(error) = server.serve_on(listener).await {
                eprintln!("the SSH port ended: {error}");
            }
        })
    }
}

/// The demo's gateway as `vos-gateway` serves it: its SSH port and the
/// onion arti hosts for it, each serving the demo's screens.
pub struct Hosted {
    /// The onion's address, `….onion`.
    pub onion: String,
    /// The SSH host key both ports present, its fingerprint.
    pub fingerprint: String,
    ssh: tokio::task::JoinHandle<()>,
    _served: vos_gateway::served::Served,
}

impl Drop for Hosted {
    fn drop(&mut self) {
        self.ssh.abort();
    }
}

impl LocalSpace {
    /// The gateway's file for this space, its keys and arti's state under
    /// `data`, its SSH port on `ssh`.
    fn gateway_file(
        &self,
        data: &Path,
        ssh: SocketAddr,
    ) -> Result<vos_gateway::config::Config, String> {
        let demo = self.demo();
        let at = |name: &str| data.join(name).display().to_string();
        let text = format!(
            r#"
key = "{key}"
http = "127.0.0.1:0"
nodes = [{{ key = "{node}", address = "unix:{socket}" }}]
ssh = "{ssh}"
ssh_host_key = "{host_key}"
app_key = "{app_key}"

[demo]
agent = {agent}
credentials = {credentials}
payments = {payments}
poll = {poll}

[onion]
state = "{state}"
cache = "{cache}"
key = "{onion}"
"#,
            key = at("gateway.key"),
            node = hex::encode(self.node.id().0),
            socket = self.socket.display(),
            host_key = at("ssh_host_key"),
            app_key = at("app.key"),
            agent = demo.agent,
            credentials = demo.credentials,
            payments = demo.payments,
            poll = demo.poll,
            state = at("onion/state"),
            cache = at("onion/cache"),
            onion = at("onion.key"),
        );
        let config: vos_gateway::config::Config =
            toml::from_str(&text).map_err(|error| error.to_string())?;
        config.check()?;
        Ok(config)
    }

    /// The gateway `vos-gateway` would serve for this space, its keys and
    /// arti's state kept under `data`: its SSH port on `ssh` and its onion,
    /// hosted by arti over the live Tor network, the enrollment pinning
    /// that onion and the SSH host key both present.
    pub async fn host(&self, data: &Path, ssh: SocketAddr) -> Result<Hosted, String> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(data.join("onion"))
            .map_err(|error| error.to_string())?;
        let config = self.gateway_file(data, ssh)?;
        let gateway = Arc::new(Gateway::new(
            config
                .upstreams()?
                .into_iter()
                .map(|(key, address)| Upstream::new(key, address, random()))
                .collect(),
        ));
        let mark = vos_api::Mark::Clearnet;
        let app = vos_gateway::config::seed(config.app_key.as_ref().expect("the file's app key"))?;
        let app = Arc::new(AppClient::new(app, Arc::clone(&gateway), mark));
        let port = vos_gateway::ssh::Port::new(
            mark,
            Limits::new(PerAddress::default()),
            vos_gateway::caps::Caps::none(),
            vos_gateway::caps::bodies(),
        );
        let listener = tokio::net::TcpListener::bind(ssh)
            .await
            .map_err(|error| format!("{ssh}: {error}"))?;
        let ssh =
            vos_gateway::ssh::serve(&config, Arc::clone(&gateway), port, Some(app), listener)?;
        let onion = config.onion.as_ref().expect("the file's onion");
        let served = vos_gateway::served::onion(&config, onion, gateway).await?;
        let host_key = config.ssh_host_key.as_ref().expect("the file's host key");
        let fingerprint = russh::keys::load_secret_key(host_key, None)
            .map_err(|error| format!("{}: {error}", host_key.display()))?
            .public_key()
            .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
            .to_string();
        Ok(Hosted {
            onion: served.hosted.address.clone(),
            fingerprint,
            ssh,
            _served: served,
        })
    }
}

/// `N` bytes from the operating system.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).expect("the operating system's randomness");
    bytes
}

/// An Ed25519 host key, made at random.
pub fn host_key() -> russh::keys::PrivateKey {
    russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(
        &random(),
    ))
}

/// Where a listener is.
pub fn local(listener: &tokio::net::TcpListener) -> SocketAddr {
    listener.local_addr().expect("a bound listener")
}
