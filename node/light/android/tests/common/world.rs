// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The spaces a facility reaches, in process, behind a gateway that serves
//! `vos-api` over SSH on each stream the facility's Tor client dials, as a
//! gateway's onion does. No network: a dial is an in-memory stream to an
//! SSH server of its own, which records the connection's target, circuit,
//! SSH key and every request it carried.
//!
//! - **A space** ([`World::space`]): its agent, its credential actor (the
//!   tree served from its feed (`feed`, `feed_after`), an open claim's work and `enroll_device`
//!   placing a leaf, `revoke_device` clearing one), its onions; a home's
//!   `Homes` too ([`World::home`]): a pool of personal agents, each one a
//!   [`Host`] running `Personal`, claimed by a proof in the scope "home",
//!   which `Homes` here answers by `Personal`'s `assign`.
//! - **Every proof is checked** as ingress's stateless checks do, under
//!   the stock kernels' programs, and recorded.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use russh::keys::ssh_key;
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use vos_abi::credentials as tree;
use vos_abi::credentials::{DEPTH, EMPTY, Words};
use vos_abi::ids::{AgentId, ProgramHash};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode, SpaceId};
use vos_api::{Event, Framing, Kind, Reader, Requests, frame};
use vos_light::tor::{Circuit, Dial, Dialing, Stream, Target, onion_address};
use vos_wire::credentials::{Change, Feed, Onion, Open, RootEntry};
use vos_wire::ingress::{self, AgentInfo, Credentialed, QueryCall, Response};
use vos_wire::peer::CreationRecord;
use vos_wire::personal::{Kit, NewDevice, Policy};

use super::host::Host;

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
    /// A call of `name`.
    pub fn call(name: &str) -> Self {
        Self {
            kind: Kind::Call as u16,
            method: vos_light::method_id(name),
        }
    }

    /// A query of `name`.
    pub fn query(name: &str) -> Self {
        Self {
            kind: Kind::Query as u16,
            method: vos_light::method_id(name),
        }
    }

    /// A proven call of `name`.
    pub fn proven(name: &str) -> Self {
        Self {
            kind: Kind::Credentialed as u16,
            method: vos_light::method_id(name),
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
}

/// The device's clock, in milliseconds: the world runs on it, offset.
pub fn wall() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// What one connection carried.
#[derive(Clone, Debug)]
pub struct Seen {
    pub target: Target,
    pub circuit: Circuit,
    /// The ed25519 key it authenticated with.
    pub key: Option<[u8; 32]>,
    /// Each request's kind and the agent it named (0: none).
    pub requests: Vec<(u16, u32)>,
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
    key: SigningKey,
    pub pool: Vec<u32>,
    pub kits: HashMap<[u8; 32], u32>,
    pub renewed: Vec<u32>,
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
    pub personal: HashMap<u32, Host>,
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
    /// Admit no open claim, and count the terms asked.
    pub closed: bool,
    pub openings: usize,
    /// The policy each personal agent is configured with at its claim,
    /// [`policy`] unless set.
    pub policy: Option<Policy>,
    /// Each phone's requests, by its tag, as it asked them.
    pub traces: HashMap<u8, Vec<Step>>,
    kills: HashMap<u8, Kill>,
    next_agent: u32,
}

/// The world, and the gateway in front of it.
pub struct World {
    host_key: ssh_key::PrivateKey,
    pub state: Mutex<State>,
    /// Added to the device's clock: the world's time.
    pub offset: AtomicI64,
    pub stock: vos_facility::Stock,
}

impl World {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            host_key: ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(
                &[7; 32],
            )),
            state: Mutex::new(State {
                next_agent: 10,
                ..State::default()
            }),
            offset: AtomicI64::new(0),
            stock: vos_facility::Stock::embedded(),
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
        let key = SigningKey::from_bytes(&[handle[0] ^ 0x77; 32]);
        let mut agents = Vec::new();
        for _ in 0..pool {
            let (id, identity) = Self::agent(&mut state);
            state
                .personal
                .insert(id, Host::new(id, identity, &key, now));
            agents.push(id);
        }
        state.spaces.get_mut(&agent).unwrap().homes = Some(Homes {
            instance: 3,
            key,
            pool: agents,
            kits: HashMap::new(),
            renewed: Vec::new(),
        });
        agent
    }

    /// The home at `agent` as the chrome names it.
    pub fn home_of(&self, agent: u32) -> vos_facility::personal::Home {
        let state = self.state.lock().unwrap();
        let space = &state.spaces[&agent];
        vos_facility::personal::Home {
            space: space.space,
            handle: space.handle,
            agent,
            identity: space.identity,
            homes: space.homes.as_ref().unwrap().instance,
            credentials: space.credentials,
            onions: space
                .onions
                .iter()
                .map(|onion| s4_credential_contract::Onion {
                    key: onion.key,
                    ssh_host_key: onion.ssh_host_key,
                })
                .collect(),
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
                serve_ssh(Arc::clone(&world), &target, Circuit::new(), stream, 0);
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

    /// The world's answer to a request of `kind` with `body`.
    fn answer(&self, kind: u16, body: &[u8]) -> Vec<u8> {
        let now = self.now();
        let mut state = self.state.lock().unwrap();
        match Kind::from_u16(kind) {
            Some(Kind::Time) if state.bad_time => vec![0xff],
            Some(Kind::Time) => now.encode(),
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
            Some(Kind::Query) => {
                let (agent, query) = <(AgentId, QueryCall)>::decode_exact(body).expect("a query");
                let outcome = state.query(agent.0, &query, now);
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
    fn query(&mut self, agent: u32, query: &QueryCall, now: u64) -> Outcome {
        if let Some(host) = self.personal.get(&agent) {
            return host.query(now, query);
        }
        let space = self.spaces.get_mut(&agent).expect("a space's agent");
        verified(
            &query.key,
            &query.message(&space.identity),
            &query.signature,
        );
        let method = query.method.0;
        let named = |name: &str| method == vos_light::method_id(name);
        if query.instance.0 == space.credentials {
            if named("feed") {
                self.feed_reads += 1;
                let space = self.spaces.get_mut(&agent).unwrap();
                return done(
                    space
                        .tree
                        .page(u64::decode_exact(&query.arguments).unwrap()),
                );
            }
            if named("feed_after") {
                self.feed_reads += 1;
                let space = self.spaces.get_mut(&agent).unwrap();
                return done(
                    space
                        .tree
                        .after(&<[u8; 32]>::decode_exact(&query.arguments).unwrap()),
                );
            }
            if named("opening") {
                self.openings += 1;
                if self.closed {
                    return done(Option::<Open>::None);
                }
                return done(Some(Open {
                    salt: [3; 32],
                    difficulty: 2,
                    period_ms: 86_400_000,
                    cap: 16,
                    left: 16,
                }));
            }
            if named("onions") {
                return done(space.onions.clone());
            }
        }
        let homes = space.homes.as_ref().expect("a home's `Homes`");
        assert_eq!(query.instance.0, homes.instance);
        if named("pooled") {
            return done(homes.pool.first().copied());
        }
        if named("find") {
            let index = <[u8; 32]>::decode_exact(&query.arguments).unwrap();
            return done(homes.kits.get(&index).copied());
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
        assert_eq!(call.method.0, vos_light::method_id("claim_open"));
        let (member, nonce) = <([u8; 32], u64)>::decode_exact(&call.arguments).unwrap();
        assert!(vos_wire::credentials::meets(
            &vos_wire::credentials::open_work(&space.handle, &member, &[3; 32], nonce),
            2
        ));
        done(space.tree.enroll(&member, now))
    }

    fn credentialed(
        &mut self,
        stock: &vos_facility::Stock,
        agent: u32,
        request: &Credentialed,
        now: u64,
    ) -> Outcome {
        let space = self.spaces.get_mut(&agent).expect("a space's agent");
        let proof = vos_light::Proven {
            format: request.format,
            claim: request.claim.clone(),
            proof: request.proof.clone(),
        };
        let call = vos_light::Call {
            space: space.space,
            agent,
            instance: request.instance.0,
            method: request.method.0,
            arguments: request.arguments.clone(),
            nonce: request.nonce,
            expires_ms: request.expires_ms,
        };
        let named = |name: &str| request.method.0 == vos_light::method_id(name);
        let homes = space.homes.as_ref().map(|homes| homes.instance) == Some(request.instance.0);
        let (kernel, scope): (&[u8], Option<&[u8]>) = if homes {
            (&stock.auth, Some(b"home"))
        } else if named("enroll_device")
            || named("confirm_device")
            || named("revoke_device")
            || named("transfer")
        {
            (&stock.owner, None)
        } else {
            (&stock.auth, None)
        };
        if let Some(scope) = scope {
            vos_light::verify(&proof, &call, &super::program(kernel), Some(scope))
                .expect("the proof verifies against its call");
        } else if kernel == stock.owner.as_slice() {
            vos_light::verify(&proof, &call, &super::program(kernel), None)
                .expect("the proof verifies against its call");
        }
        if homes && named("claim") {
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
            for entry in &kit.entries {
                homes
                    .kits
                    .insert(vos_light::kit::index(&entry.signing), chosen);
            }
            let key = homes.key.clone();
            let policy = self.policy.unwrap_or_else(policy);
            let host = self.personal.get_mut(&chosen).unwrap();
            host.configure(now, &key, policy);
            let assigned = host.homes(now, &key, "assign", (device, kit).encode());
            assert!(matches!(assigned, Outcome::Done(_)), "{assigned:?}");
            return done(chosen);
        }
        if homes && named("renew") {
            let chosen = u32::decode_exact(&request.arguments).unwrap();
            let homes = space.homes.as_mut().unwrap();
            homes.renewed.push(chosen);
            let key = homes.key.clone();
            let renewed =
                self.personal
                    .get_mut(&chosen)
                    .unwrap()
                    .homes(now, &key, "renew", Vec::new());
            assert!(matches!(renewed, Outcome::Done(_)), "{renewed:?}");
            return done(());
        }
        if named("enroll_device") {
            let (member, _owner) =
                <([u8; 32], [u8; 32])>::decode_exact(&request.arguments).unwrap();
            return done(space.tree.enroll(&member, now));
        }
        if named("revoke_device") {
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
            let (ours, theirs) = tokio::io::duplex(1 << 20);
            serve_ssh(world, &target, circuit, theirs, tag);
            Ok(Box::new(ours) as Stream)
        })
    }
}

/// An SSH server of the gateway's on `stream`, its connection recorded.
fn serve_ssh(
    world: Arc<World>,
    target: &Target,
    circuit: Circuit,
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    tag: u8,
) {
    let index = {
        let mut state = world.state.lock().unwrap();
        state.seen.push(Seen {
            target: target.clone(),
            circuit,
            key: None,
            requests: Vec::new(),
        });
        state.seen.len() - 1
    };
    let config = Arc::new(russh::server::Config {
        keys: vec![world.host_key.clone()],
        ..russh::server::Config::default()
    });
    let handler = Handler {
        world,
        index,
        tag,
        channels: HashMap::new(),
    };
    tokio::spawn(async move {
        if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
            let _ = session.await;
        }
    });
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

struct Handler {
    world: Arc<World>,
    index: usize,
    tag: u8,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        verified: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.world.state.lock().unwrap().seen[self.index].key =
            Some(verified.public_key.key_data().ed25519().unwrap().0);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(channel) = self.channels.remove(&id) else {
            return Ok(());
        };
        if name != "vos-api" {
            session.channel_failure(id)?;
            return Ok(());
        }
        session.channel_success(id)?;
        tokio::spawn(serve(
            channel.into_stream(),
            Arc::clone(&self.world),
            self.index,
            self.tag,
        ));
        Ok(())
    }
}

/// The agent a request names, if it names one.
fn agent_of(body: &[u8]) -> u32 {
    body.get(..4)
        .map_or(0, |bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// The `vos-api` subsystem: each frame answered by the world, on a thread
/// of its own (a personal agent's batch runs the interpreter).
async fn serve(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    world: Arc<World>,
    index: usize,
    tag: u8,
) {
    let mut reader = Reader::requests(Framing::Stream, Requests::All);
    let mut chunk = vec![0u8; 64 << 10];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        reader.push(&chunk[..read]);
        while let Some(Event::Frame(request)) = reader.event() {
            let fate = world.fate(tag, Step::of(request.kind, &request.body));
            if matches!(fate, Fate::Drop) {
                return;
            }
            world.state.lock().unwrap().seen[index]
                .requests
                .push((request.kind, agent_of(&request.body)));
            let answering = Arc::clone(&world);
            let (kind, body) = (request.kind, request.body.clone());
            let answer = tokio::task::spawn_blocking(move || answering.answer(kind, &body))
                .await
                .expect("the world answered");
            if matches!(fate, Fate::TakeAndDrop) {
                return;
            }
            let bytes = frame(Framing::Stream, request.kind, request.id, &answer);
            if stream.write_all(&bytes).await.is_err() {
                return;
            }
        }
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
