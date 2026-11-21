//! The spaces a phone reaches, in process, behind a gateway that serves
//! `vos-api` over SSH on each stream a Tor client dials, as a gateway's
//! onion does. No network: a dial is an in-memory stream to an
//! SSH server of its own, which records the connection's target, circuit,
//! SSH key and every request it carried.
//!
//! - **A space** ([`World::space`]): its agent, its credential actor (the
//!   tree served from its feed (`feed`, `feed_after`), an open claim's work and `enroll_device`
//!   placing a leaf, `revoke_device` clearing one), its onions; a home's
//!   `Homes` too ([`World::home`]): a pool of personal agents, each one a
//!   personal agent running `Personal` ([`vos_testkit::personal::Agent`]),
//!   claimed by a proof in the scope "home",
//!   which `Homes` here answers by `Personal`'s `assign`.
//! - **Every proof is checked** as ingress's stateless checks do, under
//!   the stock kernels' programs ([`Kernels`]), and recorded.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use russh::keys::ssh_key;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use vos_abi::credentials as tree;
use vos_abi::credentials::{DEPTH, EMPTY, Words};
use vos_abi::ids::{AgentId, InstanceId, MethodId, ProgramHash};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode, SpaceId};
use vos_api::Kind;
use vos_testkit::personal::Agent;
use vos_wire::credentials::method as credentials;
use vos_wire::personal::method as personal;

use super::held::Held;
pub use super::ssh::Seen;
use super::ssh::{self, Answer};
use crate::release::{Package, Release};
use crate::space::Kept;
use crate::tor::{Circuit, Dial, Dialing, Stream, Target, onion_address};
use vos_wire::credentials::{Change, Feed, Onion, Open, RootEntry};
use vos_wire::ingress::{self, AgentInfo, Credentialed, QueryCall, Response};
use vos_wire::peer::CreationRecord;
use vos_wire::personal::{Kit, NewDevice, Policy};

/// A test home's policy: seconds, not days, and no field its default, so
/// a device that takes `Policy::DEFAULT` for the home's is seen to. A
/// device seasons in long enough that a loaded machine still sees it
/// unseasoned right after its pairing.
pub fn policy() -> Policy {
    let policy = Policy {
        operation_delay_ms: 1_500,
        kit_delay_ms: 2_500,
        probation_ms: 500,
        seasoning_ms: 3_000,
        confirm_window_ms: 60_000,
        lease_ms: 600_000,
        bytes_new: 6 << 20,
        bytes_full: 48 << 20,
        envelopes_per_day: 8_000,
        commits_per_day: 48,
        kit_operations_per_day: 12,
        inbox_items: 60,
        inbox_item_bytes: 15 << 10,
        inbox_ttl_ms: 3_600_000,
        slot_ttl_ms: 120_000,
    };
    assert_ne!(policy, Policy::DEFAULT);
    policy
}

/// What a request asks: its kind, and the method it names (0: none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Step {
    pub kind: u16,
    pub method: u32,
}

impl Step {
    /// A call of `method`.
    pub fn call(method: MethodId) -> Self {
        Self {
            kind: Kind::Call as u16,
            method: method.0,
        }
    }

    /// A query of `method`.
    pub fn query(method: MethodId) -> Self {
        Self {
            kind: Kind::Query as u16,
            method: method.0,
        }
    }

    /// A proven call of `method`.
    pub fn proven(method: MethodId) -> Self {
        Self {
            kind: Kind::Credentialed as u16,
            method: method.0,
        }
    }

    /// Whether it changes what the world holds: a call, signed or proven.
    pub fn writes(&self) -> bool {
        self.kind == Kind::Call as u16 || self.kind == Kind::Credentialed as u16
    }

    fn of(kind: u16, body: &[u8]) -> Self {
        let method =
            match Kind::from_u16(kind) {
                Some(Kind::Call) => <(AgentId, ingress::Call)>::decode_exact(body)
                    .map_or(0, |(_, call)| call.method.0),
                Some(Kind::Query) => <(AgentId, QueryCall)>::decode_exact(body)
                    .map_or(0, |(_, query)| query.method.0),
                Some(Kind::Credentialed) => <(AgentId, Credentialed)>::decode_exact(body)
                    .map_or(0, |(_, request)| request.method.0),
                _ => 0,
            };
        Self { kind, method }
    }
}

/// A dial or a request as the world saw it come.
#[derive(Clone, Copy, Debug)]
pub struct Logged {
    pub at: std::time::Instant,
    pub tag: u8,
    /// The connection's index in [`State::seen`].
    pub connection: usize,
    /// The request's step; `None` for the dial that opened the connection.
    pub step: Option<Step>,
}

/// Where a phone's process dies, as Android kills `:vos`: at the `nth`
/// request (from 1) asking `step`, before the world takes it, or after the
/// world took it and before its answer leaves. From then on the phone's
/// every connection is cut, until [`World::revive`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Death {
    Before,
    After,
}

#[derive(Clone, Copy, Debug)]
struct Kill {
    step: Step,
    nth: usize,
    death: Death,
    seen: usize,
    fired: bool,
}

/// What the world does with a phone's request.
enum Fate {
    Answer,
    Drop,
    TakeAndDrop,
    /// Answered as taken, never applied: the operators answer a call and
    /// never log it.
    Forge,
    /// Answered with the agent's refusal, made up on the route.
    Refuse(vos_wire::personal::PersonalError),
}

/// The device's clock, in milliseconds: the world runs on it, offset.
pub fn wall() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A credential actor's tree, kept as the feed serves it.
#[derive(Default)]
pub struct Tree {
    leaves: Vec<Words>,
    changes: Vec<Change>,
}

impl Tree {
    fn root(&self) -> Words {
        fn of(leaves: &[Words], level: usize, index: usize) -> Words {
            let first = index << level;
            if first >= leaves.len() {
                return EMPTY[level];
            }
            if level == 0 {
                return leaves[index];
            }
            tree::compress(
                &of(leaves, level - 1, 2 * index),
                &of(leaves, level - 1, 2 * index + 1),
            )
        }
        of(&self.leaves, DEPTH, 0)
    }

    /// `member` placed at the lowest free slot: its slot.
    pub fn enroll(&mut self, member: &[u8; 32], now: u64) -> u32 {
        let leaf = tree::leaf(&tree::words(member).expect("a digest"));
        if let Some(slot) = self.leaves.iter().position(|held| *held == leaf) {
            return slot as u32;
        }
        let slot = self
            .leaves
            .iter()
            .position(|held| *held == EMPTY[0])
            .unwrap_or(self.leaves.len());
        if slot == self.leaves.len() {
            self.leaves.push(leaf);
        } else {
            self.leaves[slot] = leaf;
        }
        self.change(slot as u32, now);
        slot as u32
    }

    /// `member`'s leaf cleared.
    pub fn revoke(&mut self, member: &[u8; 32], now: u64) {
        let leaf = tree::leaf(&tree::words(member).expect("a digest"));
        if let Some(slot) = self.leaves.iter().position(|held| *held == leaf) {
            self.leaves[slot] = EMPTY[0];
            self.change(slot as u32, now);
        }
    }

    /// The members the tree holds.
    pub fn members(&self) -> usize {
        self.leaves.iter().filter(|leaf| **leaf != EMPTY[0]).count()
    }

    pub fn holds(&self, member: &[u8; 32]) -> bool {
        let leaf = tree::leaf(&tree::words(member).expect("a digest"));
        self.leaves.contains(&leaf)
    }

    fn change(&mut self, slot: u32, now: u64) {
        let since = self
            .changes
            .last()
            .map_or(now, |last| last.root.since.max(now));
        self.changes.push(Change {
            leaves: vec![(slot, tree::digest(&self.leaves[slot as usize]))],
            root: RootEntry {
                root: tree::digest(&self.root()),
                since,
            },
        });
    }

    /// The feed after the last change that left `root`, as
    /// `feed_after(root)` serves it: none for a root no change left.
    fn after(&self, root: &[u8; 32]) -> Option<Feed> {
        let last = self
            .changes
            .iter()
            .rposition(|change| change.root.root == *root)?;
        Some(self.page(last as u64 + 1))
    }

    fn page(&self, from: u64) -> Feed {
        let start = (from as usize).min(self.changes.len());
        let end = (start + 8).min(self.changes.len());
        Feed {
            from,
            changes: self.changes[start..end].to_vec(),
            length: self.changes.len() as u64,
        }
    }
}

/// A home's `Homes`: its pool of personal agents, and what its claims
/// recorded.
pub struct Homes {
    pub instance: u32,
    pub pool: Vec<u32>,
    pub kits: HashMap<[u8; 32], u32>,
    /// The agent each claiming device's nullifier holds.
    pub nullifiers: HashMap<[u8; 32], u32>,
}

/// A space's agent: its identity, its credential actor and its tree, its
/// `Homes` if it is a home.
pub struct Space {
    pub space: [u8; 32],
    pub handle: [u8; 32],
    pub agent: u32,
    pub identity: [u8; 32],
    pub credentials: u32,
    pub tree: Tree,
    pub homes: Option<Homes>,
    pub onions: Vec<Onion>,
}

/// What the world holds.
#[derive(Default)]
pub struct State {
    pub spaces: HashMap<u32, Space>,
    pub personal: HashMap<u32, Agent>,
    pub records: HashMap<u32, CreationRecord>,
    pub seen: Vec<Seen>,
    pub credentialed: Vec<(AgentId, Credentialed)>,
    /// Answer the node's time with bytes that are no time.
    pub bad_time: bool,
    /// The answers the next proven calls get in place of running, as a
    /// node's ingress or agent refuses them, each with the member the
    /// space's tree enrolls as it answers, if any: a root superseded.
    pub refusing: std::collections::VecDeque<(Response, Option<[u8; 32]>)>,
    pub feed_reads: usize,
    /// The policy each personal agent is configured with at its claim,
    /// [`policy`] unless set.
    pub policy: Option<Policy>,
    /// The device window every space answers, its stock kernels' programs
    /// in their format unless set.
    pub window: Option<vos_wire::ingress::DeviceWindow>,
    /// The agent and instance of each device window asked, in order.
    pub windows_asked: Vec<(u32, u32)>,
    /// Each phone's requests, by its tag, as it asked them.
    pub traces: HashMap<u8, Vec<Step>>,
    /// Every dial and every request the world took, as it came, with the
    /// phone's tag and its connection's index: the flows' timings.
    pub log: Vec<Logged>,
    kills: HashMap<u8, Kill>,
    /// The next call each phone asks of a step, answered as taken and never
    /// applied ([`World::forge`]).
    forging: HashMap<u8, Step>,
    /// Each phone's requests of a step the route answers with a refusal of
    /// the agent's it made up, and how many more ([`World::refuse`]).
    made_up: HashMap<u8, (Step, vos_wire::personal::PersonalError, usize)>,
    /// Each phone whose reads of the control log a route forks, by the
    /// operation it logs again ([`World::relog`]).
    relogs: HashMap<u8, u64>,
    /// The next call each phone asks of a step, its agent's lease renewed
    /// before the world takes it ([`World::renew_before`]).
    renewing: HashMap<u8, Step>,
    /// The next request each phone asks of a step, the world's time moved
    /// on before it is taken ([`World::pass_at`]).
    passing: HashMap<u8, (Step, u64)>,
    /// The next dials of each phone that find the onion service
    /// unpublished ([`World::unpublished`]).
    unpublished: HashMap<u8, usize>,
    /// What Tor's delays the world's streams take ([`World::delay`]).
    delays: Delays,
    /// Each connection's `Time` answered this far ahead of the world's
    /// ([`World::skew_times`]), its connection's index times this.
    time_skew_ms: u64,
    next_agent: u32,
}

/// Tor's delays as the world's streams take them: a new connection's
/// (the descriptor, the introduction and the rendezvous before the stream
/// opens), and each byte's way across the circuit, so the SSH handshake's
/// round trips and a proof's upload cost what they do over an onion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Delays {
    /// From the dial to the stream.
    pub connect: std::time::Duration,
    /// Each write's way to the other end: half a round trip.
    pub one_way: std::time::Duration,
    /// The circuit's rate, bytes a second, each way (0: unbounded).
    pub rate: u64,
}

impl Delays {
    /// The desktop's onion figures (`light-node.md` §6.3, a warm client):
    /// a connection 4 s to the stream, a round trip 0.5 s, so the SSH
    /// handshake's six round trips take about 3 s; the rate unbounded, as a
    /// proof's upload is measured on the phone.
    pub const ONION: Delays = Delays {
        connect: std::time::Duration::from_secs(4),
        one_way: std::time::Duration::from_millis(250),
        rate: 0,
    };

    fn none(&self) -> bool {
        *self == Delays::default()
    }
}

/// The release artifacts of the stock kernels a space's ingress checks
/// proofs under, each an encoded [`Release`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kernels {
    pub auth: Vec<u8>,
    pub owner: Vec<u8>,
}

impl Kernels {
    /// The device window of a space whose guards admit these kernels'
    /// programs alone, each in its format.
    pub fn window(&self) -> vos_wire::ingress::DeviceWindow {
        use vos_wire::ingress::{DeviceWindow, FormatWindow, KernelWindow, ProgramWindow};
        let releases: Vec<Release> = [&self.auth, &self.owner]
            .into_iter()
            .map(|artifact| Release::decode_exact(artifact).expect("a release artifact"))
            .collect();
        let mut formats: Vec<FormatWindow> = Vec::new();
        for release in &releases {
            if !formats.iter().any(|format| format.format == release.format) {
                formats.push(FormatWindow {
                    format: release.format,
                    retires_ms: None,
                });
            }
        }
        DeviceWindow {
            formats,
            kernels: releases
                .iter()
                .map(|release| KernelWindow {
                    method: release.method,
                    programs: vec![ProgramWindow {
                        id: release.id,
                        format: release.format,
                        retires_ms: None,
                    }],
                    unavailable: false,
                })
                .collect(),
        }
    }
}

impl Kernels {
    /// The artifacts of this tree's credential actor (`just
    /// build-programs`).
    pub fn built() -> Self {
        let elf = std::fs::read(vos_testkit::programs::program_elf("vos-credentials"))
            .expect("the credential actor's ELF");
        let kernel = |name| {
            crate::release::device(&elf, name)
                .expect("its kernel")
                .encode()
        };
        Self {
            auth: kernel("auth"),
            owner: kernel("owner"),
        }
    }
}

/// The program of the release artifact `artifact`.
pub fn program(artifact: &[u8]) -> crate::DeviceProgram {
    let device = Release::decode_exact(artifact).expect("a release artifact");
    crate::DeviceProgram::from_release(&device).expect("its program")
}

/// `Personal`'s package, as a release makes it from this tree's personal
/// agent (`just build-programs`).
pub fn personal_package() -> &'static Package {
    static PACKAGE: std::sync::OnceLock<Package> = std::sync::OnceLock::new();
    PACKAGE.get_or_init(|| {
        let elf = std::fs::read(vos_testkit::programs::program_elf("vos-personal"))
            .expect("the personal agent's ELF");
        crate::release::package(&elf, 1).expect("its package")
    })
}

/// The light node's artifacts from this tree's guests: the default agent
/// and the two books' packages.
pub fn artifacts() -> &'static crate::space::Artifacts {
    static ARTIFACTS: std::sync::OnceLock<crate::space::Artifacts> = std::sync::OnceLock::new();
    ARTIFACTS.get_or_init(|| {
        let read = |name| std::fs::read(vos_testkit::programs::program_elf(name)).unwrap();
        let package = |name| crate::release::package(&read(name), 1).unwrap().encode();
        crate::space::Artifacts {
            agent: crate::release::agent(&read("vos-agent")).unwrap(),
            books: vec![
                (
                    crate::space::CREDENTIAL_BOOK,
                    package("vos-credential-book"),
                ),
                (crate::space::DEVICE_BOOK, package("vos-device-book")),
            ],
        }
    })
}

/// A personal agent of `Personal`'s package at `agent`, its identity
/// `identity`, its role `homes` the home's agent `homes`'.
fn personal_agent(agent: u32, identity: [u8; 32], homes: u32, now: u64) -> Agent {
    let package = personal_package();
    let checked = package.checked().expect("a checked package");
    let programs: Vec<&[u8]> = checked.iter().map(|(_, program)| *program).collect();
    Agent::new(
        AgentId(agent),
        identity,
        package.derivation.clone(),
        &programs,
        AgentId(homes),
        now,
    )
}

/// The world, and the gateway in front of it.
pub struct World {
    host_key: ssh_key::PrivateKey,
    pub state: Mutex<State>,
    /// Added to the device's clock: the world's time.
    pub offset: AtomicI64,
    pub stock: Kernels,
}

impl World {
    /// The world, its proofs checked under this tree's stock kernels.
    pub fn new() -> Arc<Self> {
        Self::with(Kernels::built())
    }

    /// The world, its proofs checked under `stock`.
    pub fn with(stock: Kernels) -> Arc<Self> {
        Arc::new(Self {
            host_key: ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(
                &[7; 32],
            )),
            state: Mutex::new(State {
                next_agent: 10,
                ..State::default()
            }),
            offset: AtomicI64::new(0),
            stock,
        })
    }

    /// The world's time.
    pub fn now(&self) -> u64 {
        (wall() as i64 + self.offset.load(Ordering::SeqCst)) as u64
    }

    /// The world's time moved on by `ms`.
    pub fn pass(&self, ms: u64) {
        self.offset.fetch_add(ms as i64, Ordering::SeqCst);
    }

    /// The gateway's SSH host key, as an onion's pins it.
    pub fn ssh_host_key(&self) -> [u8; 32] {
        self.host_key.public_key().key_data().ed25519().unwrap().0
    }

    /// The onion numbered `n`, served by this gateway.
    pub fn onion(&self, n: u8) -> Onion {
        Onion {
            key: [n; 32],
            ssh_host_key: self.ssh_host_key(),
        }
    }

    /// A new agent's id and identity, its record's hash.
    fn agent(state: &mut State) -> (u32, [u8; 32]) {
        let agent = state.next_agent;
        state.next_agent += 1;
        let record = CreationRecord {
            agent: AgentId(agent),
            replicas: vec![1],
            creator: 1,
            time: u64::from(agent),
            program: ProgramHash([0; 32]),
            accumulate_gas: 0,
            space: SpaceId::NONE,
        };
        let identity = vos_pvm::precompile::blake2b_256(&record.encode());
        state.records.insert(agent, record);
        (agent, identity)
    }

    /// A space whose handle is `handle`, reached through onion `onion`: its
    /// agent's id.
    pub fn space(&self, handle: [u8; 32], onion: u8) -> u32 {
        let (agent, identity) = Self::agent(&mut self.state.lock().unwrap());
        self.space_at(agent, identity, handle, [handle[0] ^ 0x55; 32], onion);
        agent
    }

    /// The space `space` whose handle is `handle` at `agent`, whose
    /// identity is `identity`, reached through onion `onion`.
    pub fn space_at(
        &self,
        agent: u32,
        identity: [u8; 32],
        handle: [u8; 32],
        space: [u8; 32],
        onion: u8,
    ) {
        let onions = vec![self.onion(onion)];
        self.state.lock().unwrap().spaces.insert(
            agent,
            Space {
                space,
                handle,
                agent,
                identity,
                credentials: 9,
                tree: Tree::default(),
                homes: None,
                onions,
            },
        );
    }

    /// `member` enrolled in the space at `agent`, as its operator invites
    /// and the registrar places it.
    pub fn enroll(&self, agent: u32, member: &[u8; 32]) {
        let now = self.now();
        self.state
            .lock()
            .unwrap()
            .spaces
            .get_mut(&agent)
            .unwrap()
            .tree
            .enroll(member, now);
    }

    /// A home-only space whose handle is `handle`: its agent holding the
    /// credential actor and `Homes`, and a pool of `pool` personal agents.
    pub fn home(&self, handle: [u8; 32], onion: u8, pool: usize) -> u32 {
        let agent = self.space(handle, onion);
        let now = self.now();
        let mut state = self.state.lock().unwrap();
        let mut agents = Vec::new();
        for _ in 0..pool {
            let (id, identity) = Self::agent(&mut state);
            state
                .personal
                .insert(id, personal_agent(id, identity, agent, now));
            agents.push(id);
        }
        state.spaces.get_mut(&agent).unwrap().homes = Some(Homes {
            instance: 3,
            pool: agents,
            kits: HashMap::new(),
            nullifiers: HashMap::new(),
        });
        agent
    }

    /// The home at `agent`, as a claim names it.
    pub fn home_of(&self, agent: u32) -> Kept {
        let state = self.state.lock().unwrap();
        let space = &state.spaces[&agent];
        Kept {
            home: crate::home::Home {
                space: space.space,
                handle: space.handle,
                agent,
                identity: space.identity,
                homes: vos_abi::ids::InstanceId(space.homes.as_ref().unwrap().instance),
                credentials: vos_abi::ids::InstanceId(space.credentials),
            },
            onions: space.onions.clone(),
        }
    }

    /// The last proof the world took, and its agent.
    pub fn last_credentialed(&self) -> (AgentId, Credentialed) {
        self.state
            .lock()
            .unwrap()
            .credentialed
            .last()
            .cloned()
            .expect("a proof")
    }

    /// The root of the tree of the space at `agent`.
    pub fn root(&self, agent: u32) -> tree::Digest {
        tree::digest(&self.state.lock().unwrap().spaces[&agent].tree.root())
    }

    /// The gateway on a loopback port as well, for a facility in another
    /// process ([`Loopback`]): the port.
    pub async fn listen(self: &Arc<Self>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let world = Arc::clone(self);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let target = Target::Clearnet {
                    host: "127.0.0.1".into(),
                    port,
                };
                let connection = world.connection(&target, Circuit::new(), 0);
                ssh::serve(&world.host_key, connection, stream);
            }
        });
        port
    }

    /// The feed's pages read so far.
    pub fn feed_reads(&self) -> usize {
        self.state.lock().unwrap().feed_reads
    }

    /// The dial the facility's client goes through.
    pub fn dial(self: &Arc<Self>) -> Arc<dyn Dial> {
        self.dial_as(0)
    }

    /// The dial of the phone tagged `tag` (not 0): its requests traced,
    /// and cut where [`World::kill`] says.
    pub fn dial_as(self: &Arc<Self>, tag: u8) -> Arc<dyn Dial> {
        Arc::new(Gateway(Arc::clone(self), tag))
    }

    /// The phone tagged `tag` dies at the `nth` request asking `step`.
    pub fn kill(&self, tag: u8, step: Step, nth: usize, death: Death) {
        self.state.lock().unwrap().kills.insert(
            tag,
            Kill {
                step,
                nth,
                death,
                seen: 0,
                fired: false,
            },
        );
    }

    /// The next call of `step` the phone tagged `tag` makes is answered as
    /// taken at the agent's head and never applied: the operators answer a
    /// call and never log it.
    pub fn forge(&self, tag: u8, step: Step) {
        self.state.lock().unwrap().forging.insert(tag, step);
    }

    /// The phone tagged `tag`'s next `times` requests of `step` answered by
    /// the route with `refusal`, as if the agent refused them, never taken:
    /// a gateway forging an answer nobody signs.
    pub fn refuse(
        &self,
        tag: u8,
        step: Step,
        refusal: vos_wire::personal::PersonalError,
        times: usize,
    ) {
        self.state
            .lock()
            .unwrap()
            .made_up
            .insert(tag, (step, refusal, times));
    }

    /// The phone tagged `tag`'s reads of the control log and of the
    /// overview answered from a fork of the agent's log: the device-set
    /// operation at `op` and its evidence logged again at the log's end,
    /// then matured after its delay, unvetoed. A route forking the log a
    /// device reads, to mature a removal once signed and vetoed.
    pub fn relog(&self, tag: u8, op: u64) {
        self.state.lock().unwrap().relogs.insert(tag, op);
    }

    /// The home renews the lease of the agent the phone tagged `tag` calls
    /// as it asks its next call of `step`, before the world takes it: an
    /// entry logged between the phone's reading of the log and its call.
    pub fn renew_before(&self, tag: u8, step: Step) {
        self.state.lock().unwrap().renewing.insert(tag, step);
    }

    /// The world's time moves on by `ms` as the phone tagged `tag` asks its
    /// next request of `step`, before the world takes it: what fell due
    /// meanwhile settles at that request.
    pub fn pass_at(&self, tag: u8, step: Step, ms: u64) {
        self.state.lock().unwrap().passing.insert(tag, (step, ms));
    }

    /// The next `dials` of the phone tagged `tag` find the onion service
    /// unpublished, as arti does for a service just launched.
    pub fn unpublished(&self, tag: u8, dials: usize) {
        self.state.lock().unwrap().unpublished.insert(tag, dials);
    }

    /// Every stream from now on takes `delays`.
    pub fn delay(&self, delays: Delays) {
        self.state.lock().unwrap().delays = delays;
    }

    /// Each connection's `Time` answered `ms` times its index ahead of the
    /// world's time: a gateway marking each connection's answer, to find it
    /// again in a proof's expiry.
    pub fn skew_times(&self, ms: u64) {
        self.state.lock().unwrap().time_skew_ms = ms;
    }

    /// Whether the phone tagged `tag` died.
    pub fn died(&self, tag: u8) -> bool {
        self.state
            .lock()
            .unwrap()
            .kills
            .get(&tag)
            .is_some_and(|kill| kill.fired)
    }

    /// The phone tagged `tag` reached again, as its next process is.
    pub fn revive(&self, tag: u8) {
        self.state.lock().unwrap().kills.remove(&tag);
    }

    /// The requests the phone tagged `tag` asked, from the last
    /// [`World::trace_from_now`].
    pub fn trace(&self, tag: u8) -> Vec<Step> {
        self.state
            .lock()
            .unwrap()
            .traces
            .get(&tag)
            .cloned()
            .unwrap_or_default()
    }

    pub fn trace_from_now(&self, tag: u8) {
        self.state.lock().unwrap().traces.remove(&tag);
    }

    /// What becomes of a request asking `step` from the phone `tag`.
    fn fate(&self, tag: u8, step: Step) -> Fate {
        let mut state = self.state.lock().unwrap();
        if tag == 0 {
            return Fate::Answer;
        }
        if let Some((at, ms)) = state.passing.get(&tag).copied()
            && at == step
        {
            state.passing.remove(&tag);
            self.pass(ms);
        }
        if state.forging.get(&tag) == Some(&step) {
            state.forging.remove(&tag);
            return Fate::Forge;
        }
        if let Some((refused, refusal, times)) = state.made_up.get_mut(&tag)
            && *refused == step
            && *times > 0
        {
            *times -= 1;
            return Fate::Refuse(*refusal);
        }
        if let Some(kill) = state.kills.get_mut(&tag) {
            if kill.fired {
                return Fate::Drop;
            }
            if kill.step == step {
                kill.seen += 1;
                if kill.seen == kill.nth {
                    kill.fired = true;
                    return match kill.death {
                        Death::Before => Fate::Drop,
                        Death::After => Fate::TakeAndDrop,
                    };
                }
            }
        }
        state.traces.entry(tag).or_default().push(step);
        Fate::Answer
    }

    /// Every connection that carried a request to `agent`.
    pub fn carrying(&self, agent: u32) -> Vec<Seen> {
        self.state
            .lock()
            .unwrap()
            .seen
            .iter()
            .filter(|seen| seen.requests.iter().any(|(_, to)| *to == agent))
            .cloned()
            .collect()
    }

    /// The world's answer to a request of `kind` with `body`, on the
    /// connection `index`.
    fn answer(&self, kind: u16, body: &[u8], index: usize) -> Vec<u8> {
        let now = self.now();
        let mut state = self.state.lock().unwrap();
        match Kind::from_u16(kind) {
            Some(Kind::Time) if state.bad_time => vec![0xff],
            Some(Kind::Time) => (now + state.time_skew_ms * index as u64).encode(),
            Some(Kind::AgentInfo) => {
                let agent = AgentId::decode_exact(body).expect("an agent");
                state
                    .records
                    .get(&agent.0)
                    .map(|record| AgentInfo {
                        record: record.clone(),
                        replicas: Vec::new(),
                    })
                    .encode()
            }
            Some(Kind::Devices) => {
                let (agent, instance) =
                    <(AgentId, InstanceId)>::decode_exact(body).expect("a devices request");
                state.windows_asked.push((agent.0, instance.0));
                let window = state.window.clone().unwrap_or_else(|| self.stock.window());
                Some(window).encode()
            }
            Some(Kind::Query) => {
                let (agent, query) = <(AgentId, QueryCall)>::decode_exact(body).expect("a query");
                let outcome = state.query(agent.0, &query);
                Response::Ran { outcome, at: 1 }.encode()
            }
            Some(Kind::Call) => {
                let (agent, call) = <(AgentId, ingress::Call)>::decode_exact(body).expect("a call");
                let outcome = state.call(agent.0, call, now);
                Response::Ran { outcome, at: 1 }.encode()
            }
            Some(Kind::Credentialed) => {
                let (agent, request) =
                    <(AgentId, Credentialed)>::decode_exact(body).expect("a credentialed call");
                if let Some((refused, member)) = state.refusing.pop_front() {
                    if let Some(member) = member {
                        state
                            .spaces
                            .get_mut(&agent.0)
                            .unwrap()
                            .tree
                            .enroll(&member, now);
                    }
                    state.credentialed.push((agent, request));
                    return refused.encode();
                }
                let outcome = state.credentialed(&self.stock, agent.0, &request, now);
                state.credentialed.push((agent, request));
                Response::Ran { outcome, at: 1 }.encode()
            }
            other => panic!("the gateway relays no {other:?}"),
        }
    }
}

impl World {
    /// The lease of the agent the call `body` goes to renewed, if it is
    /// the call [`World::renew_before`] names.
    fn renew_if(&self, tag: u8, kind: u16, body: &[u8]) {
        let now = self.now();
        let mut state = self.state.lock().unwrap();
        if state.renewing.get(&tag) != Some(&Step::of(kind, body)) {
            return;
        }
        state.renewing.remove(&tag);
        let (agent, _) = <(AgentId, ingress::Call)>::decode_exact(body).expect("a call");
        if let Some(host) = state.personal.get_mut(&agent.0) {
            host.renew(now);
        }
    }

    /// The answer to a read of the control log or the overview by the
    /// phone tagged `tag`, from the fork [`World::relog`] makes, if it
    /// makes one for that phone.
    fn forked(&self, tag: u8, kind: u16, body: &[u8]) -> Option<Vec<u8>> {
        use vos_wire::personal::{Body, Entry, Op, OpState, Overview, chain};
        let state = self.state.lock().unwrap();
        let op = *state.relogs.get(&tag)?;
        if Kind::from_u16(kind) != Some(Kind::Query) {
            return None;
        }
        let (agent, query) = <(AgentId, QueryCall)>::decode_exact(body)?;
        let host = state.personal.get(&agent.0)?;
        if query.method != personal::LOG && query.method != personal::OVERVIEW {
            return None;
        }
        // Read as the phone reads it, its signature checked.
        let Outcome::Done(answered) = host.query(&query) else {
            return None;
        };
        let mut log: Vec<(u64, Entry)> = Vec::new();
        loop {
            let from = log.last().map_or(0, |(index, _)| index + 1);
            let Outcome::Done(page) = host.read(query.key, personal::LOG, from.encode()) else {
                panic!("the log");
            };
            let page = Vec::<(u64, Entry)>::decode_exact(&page).expect("a page");
            if page.is_empty() {
                break;
            }
            log.extend(page);
        }
        let operation = log.iter().find(|(index, _)| *index == op)?.1.clone();
        let Body::Operation {
            call,
            by,
            op: relogged,
            matures,
        } = operation.body
        else {
            panic!("an operation at {op}");
        };
        let evidence = log.iter().find_map(|(_, entry)| match &entry.body {
            Body::Evidence { index, .. } if *index == op => Some(entry.body.clone()),
            _ => None,
        })?;
        let delay = matures - operation.at;
        let (last, head) = log.last().cloned().expect("a log");
        let start = head.at + 1;
        let again = last + 1;
        let Body::Evidence {
            message,
            signature,
            welcome,
            ..
        } = evidence
        else {
            unreachable!("evidence");
        };
        let mut bodies = vec![
            (
                start,
                Body::Operation {
                    call,
                    by,
                    op: relogged.clone(),
                    matures: start + delay,
                },
            ),
            (
                start,
                Body::Evidence {
                    index: again,
                    message,
                    signature,
                    welcome,
                },
            ),
            (
                start + delay,
                Body::Settled {
                    op: again,
                    state: OpState::Matured { at: start + delay },
                },
            ),
        ];
        if let Op::Remove(device) = relogged {
            bodies.push((start + delay, Body::Matured { device }));
        }
        let mut linked = head.chain;
        for (i, (at, body)) in bodies.into_iter().enumerate() {
            let index = again + i as u64;
            linked = chain(&linked, index, at, &body);
            log.push((
                index,
                Entry {
                    at,
                    body,
                    chain: linked,
                },
            ));
        }
        let (next_at, head) = log.last().cloned().expect("a log");
        let outcome = if query.method == personal::LOG {
            let from = u64::decode_exact(&query.arguments).expect("a log read");
            let page: Vec<(u64, Entry)> = log
                .into_iter()
                .filter(|(index, _)| *index >= from)
                .collect();
            done(page)
        } else {
            let mut overview = Overview::decode_exact(&answered).expect("an overview");
            overview.next = next_at + 1;
            overview.chain = head.chain;
            done(overview)
        };
        Some(Response::Ran { outcome, at: 1 }.encode())
    }

    /// A call answered as the agent's next log entry, at the world's time,
    /// and never applied.
    fn forged(&self, body: &[u8]) -> Vec<u8> {
        let now = self.now();
        let state = self.state.lock().unwrap();
        let (agent, call) = <(AgentId, ingress::Call)>::decode_exact(body).expect("a call");
        let host = state.personal.get(&agent.0).expect("a personal agent");
        let Outcome::Done(overview) = host.read(call.session.key, personal::OVERVIEW, ().encode())
        else {
            panic!("the agent's overview");
        };
        let next = vos_wire::personal::Overview::decode_exact(&overview)
            .expect("an overview")
            .next;
        let recorded = vos_wire::personal::Recorded {
            at: now,
            index: next,
        };
        Response::Ran {
            outcome: done(recorded),
            at: 1,
        }
        .encode()
    }
}

fn done(reply: impl Encode) -> Outcome {
    Outcome::Done(reply.encode())
}

fn verified(query_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) {
    use ed25519_dalek::Verifier as _;
    ed25519_dalek::VerifyingKey::from_bytes(query_key)
        .unwrap()
        .verify(message, &ed25519_dalek::Signature::from_bytes(signature))
        .expect("ingress verifies the signature");
}

impl State {
    fn query(&mut self, agent: u32, query: &QueryCall) -> Outcome {
        if let Some(host) = self.personal.get(&agent) {
            return host.query(query);
        }
        let space = self.spaces.get_mut(&agent).expect("a space's agent");
        verified(
            &query.key,
            &query.message(&space.identity),
            &query.signature,
        );
        let named = |id: MethodId| query.method == id;
        if query.instance.0 == space.credentials {
            if named(credentials::FEED) {
                self.feed_reads += 1;
                let space = self.spaces.get_mut(&agent).unwrap();
                return done(
                    space
                        .tree
                        .page(u64::decode_exact(&query.arguments).unwrap()),
                );
            }
            if named(credentials::FEED_AFTER) {
                self.feed_reads += 1;
                let space = self.spaces.get_mut(&agent).unwrap();
                return done(
                    space
                        .tree
                        .after(&<[u8; 32]>::decode_exact(&query.arguments).unwrap()),
                );
            }
            if named(credentials::OPENING) {
                return done(Some(Open {
                    salt: [3; 32],
                    difficulty: 2,
                    period_ms: 86_400_000,
                    cap: 16,
                    left: 16,
                }));
            }
            if named(credentials::ONIONS) {
                return done(space.onions.clone());
            }
        }
        let homes = space.homes.as_ref().expect("a home's `Homes`");
        assert_eq!(query.instance.0, homes.instance);
        if named(vos_wire::homes::method::POOLED) {
            return done(homes.pool.first().copied());
        }
        if named(vos_wire::homes::method::FIND) {
            let index = <[u8; 32]>::decode_exact(&query.arguments).unwrap();
            return done(homes.kits.get(&index).copied());
        }
        if named(vos_wire::homes::method::AGENT) {
            let nullifier = <[u8; 32]>::decode_exact(&query.arguments).unwrap();
            return done(homes.nullifiers.get(&nullifier).copied());
        }
        panic!("no such query")
    }

    fn call(&mut self, agent: u32, call: ingress::Call, now: u64) -> Outcome {
        if let Some(host) = self.personal.get_mut(&agent) {
            return host.call(now, call).0;
        }
        let space = self.spaces.get_mut(&agent).expect("a space's agent");
        verified(
            &call.session.key,
            &call.message(&space.identity),
            &call.signature,
        );
        assert_eq!(call.method, credentials::CLAIM_OPEN);
        let (member, nonce) = <([u8; 32], u64)>::decode_exact(&call.arguments).unwrap();
        assert!(vos_wire::credentials::meets(
            &vos_wire::credentials::open_work(&space.handle, &member, &[3; 32], nonce),
            2
        ));
        done(space.tree.enroll(&member, now))
    }

    fn credentialed(
        &mut self,
        stock: &Kernels,
        agent: u32,
        request: &Credentialed,
        now: u64,
    ) -> Outcome {
        let space = self.spaces.get_mut(&agent).expect("a space's agent");
        let proof = crate::Proven {
            format: request.format,
            claim: request.claim.clone(),
            proof: request.proof.clone(),
        };
        let call = crate::Call {
            space: space.space,
            agent,
            instance: request.instance.0,
            method: request.method.0,
            arguments: request.arguments.clone(),
            nonce: request.nonce,
            expires_ms: request.expires_ms,
        };
        let named = |id: MethodId| request.method == id;
        let homes = space.homes.as_ref().map(|homes| homes.instance) == Some(request.instance.0);
        let (kernel, scope): (&[u8], Option<&[u8]>) = if homes {
            (&stock.auth, Some(b"home"))
        } else if named(credentials::ENROLL_DEVICE)
            || named(credentials::CONFIRM_DEVICE)
            || named(credentials::REVOKE_DEVICE)
            || request.method.0 == crate::method_id("transfer")
        {
            (&stock.owner, None)
        } else {
            (&stock.auth, None)
        };
        if let Some(scope) = scope {
            crate::verify(&proof, &call, &program(kernel), Some(scope))
                .expect("the proof verifies against its call");
        } else if kernel == stock.owner.as_slice() {
            crate::verify(&proof, &call, &program(kernel), None)
                .expect("the proof verifies against its call");
        }
        if homes && named(vos_wire::homes::method::CLAIM) {
            let (device, kit, chosen) =
                <(NewDevice, Kit, u32)>::decode_exact(&request.arguments).unwrap();
            let homes = space.homes.as_mut().unwrap();
            let Some(at) = homes.pool.iter().position(|agent| *agent == chosen) else {
                return Outcome::Failed {
                    code: vos_abi::abi::Failure::Handler,
                    detail: vos_wire::homes::HomesError::Claimed.encode(),
                };
            };
            homes.pool.remove(at);
            homes.nullifiers.insert(device.nullifier, chosen);
            for entry in &kit.entries {
                homes.kits.insert(crate::kit::index(&entry.signing), chosen);
            }
            let policy = self.policy.unwrap_or_else(policy);
            let host = self.personal.get_mut(&chosen).unwrap();
            host.claim(now, device, kit, policy)
                .expect("the claim taken");
            return done(chosen);
        }
        if named(credentials::ENROLL_DEVICE) {
            let (member, _owner) =
                <([u8; 32], [u8; 32])>::decode_exact(&request.arguments).unwrap();
            return done(space.tree.enroll(&member, now));
        }
        if named(credentials::REVOKE_DEVICE) {
            let member = <[u8; 32]>::decode_exact(&request.arguments).unwrap();
            space.tree.revoke(&member, now);
            return done(());
        }
        done(())
    }
}

/// The gateway's dial: each stream an SSH server of its own; the phone's
/// tag on each.
struct Gateway(Arc<World>, u8);

impl Dial for Gateway {
    fn dial(&self, target: &Target, circuit: Circuit) -> Dialing {
        let (world, target, tag) = (Arc::clone(&self.0), target.clone(), self.1);
        Box::pin(async move {
            if world.died(tag) {
                return Err(std::io::Error::other("the phone's process is gone"));
            }
            if let Some(left) = world.state.lock().unwrap().unpublished.get_mut(&tag)
                && *left > 0
            {
                *left -= 1;
                return Err(crate::tor::Unpublished::error(
                    "Onion Service not found: failed to obtain hidden service circuit",
                ));
            }
            let delays = world.state.lock().unwrap().delays;
            tokio::time::sleep(delays.connect).await;
            let ours = ssh::dialed(&world.host_key, world.connection(&target, circuit, tag));
            if delays.none() {
                return Ok(Box::new(Held::new(ours)) as Stream);
            }
            Ok(Box::new(Held::new(delayed(ours, delays))) as Stream)
        })
    }
}

/// `stream` behind a circuit taking `delays`: each write reaches the other
/// end its one-way delay later, at the circuit's rate, in order.
fn delayed(stream: tokio::io::DuplexStream, delays: Delays) -> tokio::io::DuplexStream {
    let (ours, relay) = tokio::io::duplex(1 << 20);
    let (relay_read, relay_write) = tokio::io::split(relay);
    let (stream_read, stream_write) = tokio::io::split(stream);
    tokio::spawn(carry(relay_read, stream_write, delays));
    tokio::spawn(carry(stream_read, relay_write, delays));
    ours
}

/// What `from` reads, written to `to` as the circuit's delays say.
async fn carry(
    mut from: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    mut to: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
    delays: Delays,
) {
    let (send, mut receive) =
        tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    let reading = tokio::spawn(async move {
        let mut chunk = vec![0u8; 16 << 10];
        let mut free = tokio::time::Instant::now();
        loop {
            let read = match from.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            };
            let now = tokio::time::Instant::now();
            // The circuit carries one chunk at a time at its rate.
            let carried = match delays.rate {
                0 => std::time::Duration::ZERO,
                rate => std::time::Duration::from_micros(read as u64 * 1_000_000 / rate),
            };
            free = free.max(now) + carried;
            if send
                .send((free + delays.one_way, chunk[..read].to_vec()))
                .is_err()
            {
                return;
            }
        }
    });
    while let Some((at, bytes)) = receive.recv().await {
        tokio::time::sleep_until(at).await;
        if to.write_all(&bytes).await.is_err() || to.flush().await.is_err() {
            break;
        }
    }
    reading.abort();
    let _ = to.shutdown().await;
}

/// Every target through the gateway's loopback port: a facility in another
/// process reaching the world.
pub struct Loopback(pub u16);

impl Dial for Loopback {
    fn dial(&self, _: &Target, _: Circuit) -> Dialing {
        let port = self.0;
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
            Ok(Box::new(stream) as Stream)
        })
    }
}

impl World {
    /// A connection of the phone tagged `tag` to `target`, recorded.
    fn connection(self: &Arc<Self>, target: &Target, circuit: Circuit, tag: u8) -> Connection {
        let mut state = self.state.lock().unwrap();
        state.seen.push(Seen::new(target, circuit));
        let index = state.seen.len() - 1;
        state.log.push(Logged {
            at: std::time::Instant::now(),
            tag,
            connection: index,
            step: None,
        });
        Connection {
            world: Arc::clone(self),
            index,
            tag,
        }
    }
}

/// One connection of the gateway's, the phone's tag on it.
struct Connection {
    world: Arc<World>,
    index: usize,
    tag: u8,
}

impl ssh::Connection for Connection {
    fn seen(&self, f: impl FnOnce(&mut Seen)) {
        f(&mut self.world.state.lock().unwrap().seen[self.index]);
    }

    /// A request as its fate says: answered by the world, forged, or the
    /// phone's process dying before the world takes it or after.
    fn answer(&self, kind: u16, body: &[u8]) -> Answer {
        let step = Step::of(kind, body);
        let fate = self.world.fate(self.tag, step);
        if matches!(fate, Fate::Drop) {
            return Answer::Cut;
        }
        self.world.state.lock().unwrap().log.push(Logged {
            at: std::time::Instant::now(),
            tag: self.tag,
            connection: self.index,
            step: Some(step),
        });
        self.seen(|seen| seen.carried(kind, body));
        if matches!(fate, Fate::Answer | Fate::TakeAndDrop) {
            self.world.renew_if(self.tag, kind, body);
        }
        let answer = match fate {
            Fate::Forge => self.world.forged(body),
            Fate::Refuse(refusal) => Response::Ran {
                outcome: Outcome::Failed {
                    code: vos_abi::abi::Failure::Handler,
                    detail: refusal.encode(),
                },
                at: 1,
            }
            .encode(),
            _ => match self.world.forked(self.tag, kind, body) {
                Some(forked) => forked,
                None => self.world.answer(kind, body, self.index),
            },
        };
        if matches!(fate, Fate::TakeAndDrop) {
            return Answer::Cut;
        }
        Answer::Body(answer)
    }
}

/// The onion addresses a connection's target names.
pub fn onion_of(target: &Target) -> Option<String> {
    match target {
        Target::Onion { address, .. } => Some(address.clone()),
        Target::Clearnet { .. } => None,
    }
}

/// The onion address of the world's onion `n`.
pub fn address(world: &World, n: u8) -> String {
    onion_address(&world.onion(n).key)
}
