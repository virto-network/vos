//! The s4 demo on a local space (`slice-7-mobile.md` 7.13): one node of a
//! founded space whose agent holds the credential actor, the poll and the
//! `purses` ledger, an operator who invites members and mints, and the
//! gateway's SSH port serving the demo's screens over the node's socket.
//! The phone gate (PG3) runs it through `adb reverse`; the end-to-end test
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
pub const PURSES: InstanceId = InstanceId(2);
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
                ingress: "http://127.0.0.1:1".into(),
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
            (PURSES, elf(actor_elf("purses"))?, "operator"),
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
                (PURSES, vos_testkit::programs::actor("purses")),
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
            purses: PURSES.0,
            poll: POLL.0,
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
    /// tree, and the row `row` for `owner`, minted `mint` once claimed.
    pub fn invite(&self, member: [u8; 32], row: &str, owner: [u8; 32]) -> Result<(), String> {
        let expires = self.now()? + INVITATION_MS;
        self.write(CREDENTIALS, "invite", (member, expires))?;
        self.write(
            PURSES,
            "invite_row",
            (row.as_bytes().to_vec(), owner, expires),
        )?;
        Ok(())
    }

    /// A row claimed by the operator's invitation for `owner`, as a shop
    /// or another member would hold, minted `amount`.
    pub fn open_row(&self, row: &str, owner: [u8; 32], amount: u64) -> Result<(), String> {
        let expires = self.now()? + INVITATION_MS;
        let name = row.as_bytes().to_vec();
        self.write(PURSES, "invite_row", (name.clone(), owner, expires))?;
        self.write(PURSES, "claim_row", (name.clone(), owner))?;
        self.mint(row, amount)
    }

    pub fn mint(&self, row: &str, amount: u64) -> Result<(), String> {
        self.write(PURSES, "mint", (row.as_bytes().to_vec(), amount))
            .map(|_| ())
    }

    /// `row`'s balance, `None` for no such row.
    pub fn balance(&self, row: &str) -> Result<Option<u64>, String> {
        self.read(PURSES, "balance", row.as_bytes().to_vec())
    }

    /// The gateway on this node's socket, its SSH port on `listener`
    /// serving the demo, its host key `host_key` and the app's key
    /// `app`.
    pub fn gateway(
        &self,
        listener: tokio::net::TcpListener,
        host_key: russh::keys::PrivateKey,
        app: [u8; 32],
    ) -> tokio::task::JoinHandle<()> {
        let gateway = Arc::new(Gateway::new(vec![Upstream::new(
            self.node.id().0,
            Address::Socket(self.socket.clone()),
            random(),
        )]));
        let app = Arc::new(AppClient::new(app, Arc::clone(&gateway)));
        let server = vos_gateway::ssh::server(
            host_key,
            gateway,
            Limits::new(PerAddress::default()),
            Some((self.demo(), app)),
        );
        tokio::spawn(async move {
            if let Err(error) = server.serve_on(listener).await {
                eprintln!("the SSH port ended: {error}");
            }
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
