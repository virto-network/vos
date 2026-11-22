//! The s4 demo on a local space: one node of a
//! founded space whose agent holds the credential actor, the poll and the
//! ledger (`Payments`), an operator who
//! invites members and mints, and the
//! gateway's SSH port serving the demo's screens ([`app`], an s4 app on the
//! gateway's library) over the node's socket.
//! A phone runs it through `adb reverse`; the end-to-end test
//! drives it with a headless client. Beside it, on the same node, test
//! homes ([`home`]): home-only spaces of personal agents. Its screens trust
//! whoever reaches them (an enrollment held for the operator's invitation
//! can be pushed out by any session), so its port is never exposed.

pub mod app;
pub mod home;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use vos_abi::ids::{AgentId, InstanceId, Principal};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode, WindowClock};
use vos_gateway::Gateway;
use vos_gateway::limits::{Limits, PerAddress};
use vos_gateway::ssh::{App, Placeholder};
use vos_gateway::upstream::{Address, Upstream};
use vos_node::client::{self, Client, Operator, Target};
use vos_node::{Config, Node};
use vos_testkit::programs::{actor_elf, agent, method};
use vos_wire::ingress::{Install, Response};

use crate::app::{Demo, DemoApp};

/// The instances the agent holds.
pub const CREDENTIALS: InstanceId = InstanceId(9);
pub const PAYMENTS: InstanceId = InstanceId(2);
pub const POLL: InstanceId = InstanceId(3);
/// The operator's role byte, the registrar's too: one key holds both.
pub(crate) const ROLE: u8 = 1;
/// How long an invitation stands.
pub const INVITATION_MS: u64 = 600_000;

/// One node of a founded space, its agent and its operator.
pub struct LocalSpace {
    node: Node,
    socket: PathBuf,
    space: vos_abi::SpaceId,
    key: SigningKey,
    agent: AgentId,
    operator: Mutex<Client>,
    programs: [(InstanceId, Vec<u8>); 3],
    /// The enrollments the screens hold for the operator's invitations,
    /// every port's ([`app::Held`]).
    held: app::Held,
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

/// A new agent at `signed`'s node holding each `(instance, ELF path,
/// role)`, its schema's role mapped to [`ROLE`], which the operator's
/// `key` is granted; `what` names the agent in an error.
pub(crate) fn agent_with(
    signed: &Operator,
    key: &SigningKey,
    what: &str,
    installs: &[(InstanceId, PathBuf, &str)],
) -> Result<AgentId, String> {
    let agent = match signed.create_agent(vec![1]) {
        Ok(Response::Created(agent)) => agent,
        other => return Err(format!("{what}: {other:?}")),
    };
    for (instance, path, role) in installs {
        let elf = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let install = Install {
            instance: *instance,
            elf,
            roles: vec![(role.as_bytes().to_vec(), ROLE)],
        };
        match signed.install(agent, &install) {
            Ok(Response::Ran { .. }) => {}
            other => return Err(format!("installing {role}: {other:?}")),
        }
    }
    let principal = Principal::Client(key.verifying_key().to_bytes());
    match signed.grant(agent, principal, Some(ROLE)) {
        Ok(Response::Ran { .. }) => Ok(agent),
        other => Err(format!("the operator's role: {other:?}")),
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
        let space_id = space.id();
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
        let agent = agent_with(
            &signed,
            &key,
            "the agent",
            &[
                (
                    CREDENTIALS,
                    vos_testkit::programs::program_elf("vos-credentials"),
                    "registrar",
                ),
                (POLL, actor_elf("poll"), "operator"),
                (
                    PAYMENTS,
                    vos_testkit::programs::program_elf("vos-payments"),
                    "operator",
                ),
            ],
        )?;
        let space = Self {
            node,
            socket,
            space: space_id,
            key: key.clone(),
            agent,
            operator: Mutex::new(Client::new(&target, key)),
            programs: [
                (
                    CREDENTIALS,
                    vos_testkit::programs::program("vos-credentials"),
                ),
                (POLL, vos_testkit::programs::actor("poll")),
                (PAYMENTS, vos_testkit::programs::program("vos-payments")),
            ],
            held: app::Held::default(),
        };
        space.write(CREDENTIALS, "found", handle)?;
        Ok(space)
    }

    pub fn agent(&self) -> AgentId {
        self.agent
    }

    /// The founded space's id.
    pub fn space_id(&self) -> [u8; 32] {
        self.space.0
    }

    /// The node's API socket.
    pub fn socket(&self) -> PathBuf {
        self.socket.clone()
    }

    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn shutdown(self) {
        self.node.shutdown();
    }

    /// The demo this space serves.
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
    /// refused there, `Held`); and the account `account` for `owner`. A
    /// device that enrolled through the screens is claimed at once (the
    /// member placed in the tree, the account opened, each on its
    /// invitation's authority): whether it was. No session asks for the
    /// claim, so none joins it to the device's sign-in.
    pub fn invite(&self, member: [u8; 32], account: &str, owner: [u8; 32]) -> Result<bool, String> {
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
        if !self.held.take(&member, &owner) {
            return Ok(false);
        }
        self.write(CREDENTIALS, "claim", member)?;
        self.write(PAYMENTS, "open", (account.as_bytes().to_vec(), owner))?;
        Ok(true)
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

    /// `count` members of random digests enrolled in the credential
    /// actor's tree, 256 a call: a tree whose feed a new device reads
    /// whole, about 77 bytes a member.
    pub fn members(&self, count: u32) -> Result<(), String> {
        let mut left = count as usize;
        while left > 0 {
            let at_once = left.min(vos_wire::credentials::ENROLL_MANY);
            let digests: Vec<[u8; 32]> = (0..at_once)
                .map(|_| random::<32>().map(|byte| byte & 0x3f))
                .collect();
            self.write(CREDENTIALS, "enroll_many", digests)?;
            left -= at_once;
        }
        Ok(())
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
    /// serving the demo as a port of transport `mark`, its host key
    /// `host_key` and the app's key `app`; the enrollment pins `onions`,
    /// the onion keys a device sends its proofs to (an onion in front of
    /// this port).
    pub fn gateway(
        &self,
        listener: tokio::net::TcpListener,
        mark: vos_api::Mark,
        host_key: russh::keys::PrivateKey,
        app: [u8; 32],
        onions: Vec<[u8; 32]>,
    ) -> tokio::task::JoinHandle<()> {
        let gateway = Arc::new(Gateway::new(vec![Upstream::new(
            self.node.id().0,
            Address::Socket(self.socket.clone()),
            random(),
        )]));
        let port = vos_gateway::ssh::Port::new(
            mark,
            Limits::new(PerAddress::default()),
            vos_gateway::caps::Caps::none(),
        );
        let demo = Demo {
            onions,
            ..self.demo()
        };
        let app = DemoApp {
            demo,
            key: app,
            held: self.held.clone(),
        };
        let server = vos_gateway::ssh::server(host_key, gateway, port, &app);
        tokio::spawn(async move {
            if let Err(error) = server.serve_on(listener).await {
                eprintln!("the SSH port ended: {error}");
            }
        })
    }
}

/// Which gateway a file describes: the demo's space's (its SSH port and its
/// onion, serving its screens), or the test homes' (an onion of its own,
/// its own SSH host key, no clearnet port and no screens but the
/// gateway's), so no host key joins a home to a space its members use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Served {
    Demo,
    Homes,
}

impl Served {
    /// Its circuits' request rate: the gateway's own for the space's; for
    /// the homes', 100 a second and a burst of 200, as a personal pass's
    /// requests follow one another on one connection as fast as Tor
    /// answers them, a circuit's channel closed past its rate.
    fn rate(self) -> Option<Rate> {
        match self {
            Served::Demo => None,
            Served::Homes => Some(Rate {
                rate: 100,
                burst: 200,
            }),
        }
    }

    /// The name of its file `name` under the data directory.
    fn file(self, name: &str) -> String {
        match self {
            Served::Demo => name.to_owned(),
            Served::Homes => format!("homes-{name}"),
        }
    }
}

/// A circuit's requests a second, and their burst.
#[derive(Clone, Copy, Debug)]
pub struct Rate {
    pub rate: u32,
    pub burst: u32,
}

/// An onion hosted by arti, and how a device pins it.
pub struct Onion {
    /// Its address, `….onion`.
    pub address: String,
    /// Its key and the SSH host key its port 22 presents, as the
    /// registrar's onion set and a home's code name them.
    pub pinned: vos_wire::credentials::Onion,
    _served: vos_gateway::served::Served,
}

/// The demo's gateways as `vos-gateway` serves them: the space's SSH port
/// and onion, each serving the demo's screens, and the homes' onion.
pub struct Hosted {
    /// The space's onion.
    pub onion: Onion,
    /// The SSH host key the space's ports present, its fingerprint.
    pub fingerprint: String,
    /// The homes' onion, if asked for.
    pub homes: Option<Onion>,
    ssh: tokio::task::JoinHandle<()>,
}

impl Drop for Hosted {
    fn drop(&mut self) {
        self.ssh.abort();
    }
}

impl LocalSpace {
    /// `served`'s gateway file for this space, its keys and arti's state
    /// under `data`, its one upstream the node's API at `socket`; the
    /// demo's names its SSH port on `ssh`.
    fn gateway_file(
        &self,
        served: Served,
        data: &Path,
        ssh: SocketAddr,
        socket: &Path,
        rate: Option<Rate>,
    ) -> Result<vos_gateway::config::Config, String> {
        let at = |name: &str| data.join(served.file(name)).display().to_string();
        let text = format!(
            r#"
key = "{key}"
http = "127.0.0.1:0"
nodes = [{{ key = "{node}", address = "unix:{socket}" }}]
ssh = "{ssh}"
ssh_host_key = "{host_key}"

[onion]
state = "{state}"
cache = "{cache}"
key = "{onion}"
{rate}"#,
            key = at("gateway.key"),
            node = hex::encode(self.node.id().0),
            socket = socket.display(),
            host_key = at("ssh_host_key"),
            state = at("onion/state"),
            cache = at("onion/cache"),
            onion = at("onion.key"),
            rate = rate.map_or(String::new(), |Rate { rate, burst }| format!(
                "circuit_rate = {rate}\ncircuit_burst = {burst}\n"
            )),
        );
        let config: vos_gateway::config::Config =
            toml::from_str(&text).map_err(|error| error.to_string())?;
        config.check()?;
        Ok(config)
    }

    /// `served`'s screens: for the space's gateway the demo's, its claims
    /// going as the app key kept under `data`, the enrollment pinning the
    /// file `config`'s onion; for the homes', the gateway's placeholder.
    fn app(
        &self,
        served: Served,
        data: &Path,
        config: &vos_gateway::config::Config,
    ) -> Result<Box<dyn App>, String> {
        if served == Served::Homes {
            return Ok(Box::new(Placeholder));
        }
        let key = vos_gateway::config::seed(&data.join(served.file("app.key")))?;
        let onion = config
            .onion
            .as_ref()
            .and_then(|onion| onion.key.as_ref())
            .expect("the file's onion key");
        let onion = SigningKey::from_bytes(&vos_gateway::config::seed(onion)?).verifying_key();
        let demo = Demo {
            onions: vec![onion.to_bytes()],
            ..self.demo()
        };
        Ok(Box::new(DemoApp {
            demo,
            key,
            held: self.held.clone(),
        }))
    }

    /// A gateway in front of this node as the file `config` names it.
    fn front_gateway(config: &vos_gateway::config::Config) -> Result<Arc<Gateway>, String> {
        config.gateway(random())
    }

    /// `served`'s onion, hosted by arti over the live Tor network, its keys
    /// and arti's state under `data`. Each onion is an arti client of its
    /// own, its state, cache and keystore under its own directory
    /// (`onion/`, `homes-onion/`), so the nickname both services take
    /// (`vos-gateway`) names a key in two keystores apart and neither
    /// takes the other's. Until a launch's descriptor reaches its
    /// directories a device's first contact finds the service missing,
    /// which the light node tries once more for.
    async fn launch(&self, served: Served, data: &Path) -> Result<Onion, String> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(data.join(served.file("onion")))
            .map_err(|error| error.to_string())?;
        let config = self.gateway_file(served, data, unbound(), &self.socket, served.rate())?;
        let gateway = Self::front_gateway(&config)?;
        let onion = config.onion.as_ref().expect("the file's onion");
        let app = self.app(served, data, &config)?;
        let hosted = vos_gateway::served::onion(&config, onion, gateway, &*app).await?;
        Ok(Onion {
            address: hosted.hosted.address.clone(),
            pinned: pinned(&config)?.1,
            _served: hosted,
        })
    }

    /// The gateways `vos-gateway` would serve for this space, their keys
    /// and arti's state kept under `data`: the space's SSH port on `ssh`
    /// and its onion, the enrollment pinning that onion and the SSH host
    /// key both present; with `homes`, the homes' onion beside it.
    pub async fn host(&self, data: &Path, ssh: SocketAddr, homes: bool) -> Result<Hosted, String> {
        let config = self.gateway_file(Served::Demo, data, ssh, &self.socket, None)?;
        let gateway = Self::front_gateway(&config)?;
        let app = self.app(Served::Demo, data, &config)?;
        let port = vos_gateway::ssh::Port::new(
            vos_api::Mark::Clearnet,
            Limits::new(PerAddress::default()),
            vos_gateway::caps::Caps::none(),
        )
        .with_connections(config.ssh_connections);
        let listener = tokio::net::TcpListener::bind(ssh)
            .await
            .map_err(|error| format!("{ssh}: {error}"))?;
        let ssh = vos_gateway::ssh::serve(&config, gateway, port, &*app, listener)?;
        let (fingerprint, _) = pinned(&config)?;
        let onion = self.launch(Served::Demo, data).await?;
        let homes = match homes {
            true => Some(self.launch(Served::Homes, data).await?),
            false => None,
        };
        Ok(Hosted {
            onion,
            fingerprint,
            homes,
            ssh,
        })
    }

    /// `served`'s onion for this space, its keys under `data`, served in
    /// process: the servers its streams are handed to, as arti hands them
    /// ([`vos_gateway::circuits::Onion::serve`]), relaying to the node's
    /// API at `socket`, each circuit's requests held to `rate` if given,
    /// else to the gateway's own; and the onion as the registrar's set
    /// names it. On a runtime; no Tor.
    pub async fn onion_front(
        &self,
        served: Served,
        data: &Path,
        socket: &Path,
        rate: Option<Rate>,
    ) -> Result<(vos_gateway::served::Front, vos_wire::credentials::Onion), String> {
        let config = self.gateway_file(served, data, unbound(), socket, rate)?;
        let gateway = Self::front_gateway(&config)?;
        let onion = config.onion.as_ref().expect("the file's onion");
        let app = self.app(served, data, &config)?;
        let front = vos_gateway::served::front(&config, onion, gateway, &*app)?;
        Ok((front, pinned(&config)?.1))
    }
}

/// An SSH address no listener is bound to: the onion's SSH server takes
/// only the streams the onion hands it.
fn unbound() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// The file's SSH host key's fingerprint, once its SSH server made it, and
/// its onion as a device pins it: the onion's key and the SSH host key its
/// port 22 presents.
fn pinned(
    config: &vos_gateway::config::Config,
) -> Result<(String, vos_wire::credentials::Onion), String> {
    let path = config.ssh_host_key.as_ref().expect("the file's host key");
    let host_key = russh::keys::load_secret_key(path, None)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let public = host_key.public_key();
    let fingerprint = public
        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
        .to_string();
    let ssh_host_key = public
        .key_data()
        .ed25519()
        .map(|key| key.0)
        .ok_or("the SSH host key is not Ed25519")?;
    let key = config
        .onion
        .as_ref()
        .and_then(|onion| onion.key.as_ref())
        .expect("the file's onion key");
    let key = SigningKey::from_bytes(&vos_gateway::config::seed(key)?)
        .verifying_key()
        .to_bytes();
    Ok((
        fingerprint,
        vos_wire::credentials::Onion { key, ssh_host_key },
    ))
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
