//! `Personal`, the personal agent's actor (`agent/personal`, built by `just
//! build-programs`), in the default agent on a VOS host, call by call at
//! batch times a test sets: the commit log, the device set's origins, the
//! votes and verdicts, evidence, sealed scopes, quotas, the inbox, the
//! lapsed agent's grace, the reads only admitted keys get, the layout read
//! back after the next version's install, and a push's and a read's cost;
//! the device set's operations, and the adversaries its rules are
//! property-tested against. Each `light-node.md` §8 scenario a test
//! answers is named in its doc.

mod adversaries;
mod commits;
mod devices;
mod evidence;
mod grace;
mod inbox;
mod reads;
mod scopes;
mod upgrade;

use std::borrow::{Borrow, BorrowMut};
use std::collections::BTreeMap;

use vos_abi::abi::Failure;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_abi::result::{Outcome, Run};
use vos_abi::{Decode, Encode};
use vos_testkit::World;
use vos_testkit::programs::program_elf;
use vos_wire::batch::{Query, Work};
use vos_wire::ingress::call_message;
use vos_wire::personal::{
    AdminClass, Attached, Attestation, Body, Candidacy, DeviceId, DeviceView, Effect, Entry,
    HOUR_MS, Header, Kit, KitEntry, KitKind, NewDevice, NewKit, Operation, Overview, PersonalError,
    Place, Policy, Pushed, Recorded, RecoveryView, Scope, Voted, Woken, r_hash, r2_hash,
};

use crate::common::{AGENT, Node};

pub use vos_wire::personal::PERSONAL;
/// The principal holding the role `homes`: the home's agent, whose
/// `Homes` claims the agent.
pub const HOMES: Principal = Principal::Agent(AgentId(0x50));
/// `Homes`' instance in the home's agent, which a claim's answer goes to.
pub const HOMES_AT: u32 = 3;
const HOMES_ROLE: u8 = 1;
/// The batch time a test's agent starts at.
pub const T0: u64 = 1_800_000_000_000;
pub const DAY: u64 = 24 * HOUR_MS;
/// The agent's identity, as calls are signed for it.
pub const IDENTITY: [u8; 32] = [0x1d; 32];

/// Device `n`'s keys: its sync key `[n; 31] ‖ 1`, its admin key `[n; 31] ‖
/// 2`.
pub fn device(n: u8) -> NewDevice {
    let key = |last: u8| {
        let mut key = [n; 32];
        key[31] = last;
        key
    };
    NewDevice {
        sync: key(1),
        admin: key(2),
        class: AdminClass::Strong,
        attestation: Attestation {
            hardware: true,
            verified_boot: true,
        },
        nullifier: key(3),
        label: vec![n; 24],
    }
}

/// A delayed admin's keys.
pub fn delayed(n: u8) -> NewDevice {
    NewDevice {
        class: AdminClass::Delayed,
        ..device(n)
    }
}

pub fn sync(n: u8) -> Principal {
    Principal::Client(device(n).sync)
}

pub fn admin(n: u8) -> Principal {
    Principal::Client(device(n).admin)
}

/// The recovery kit's signing key.
pub const KIT_KEY: [u8; 32] = [0xc1; 32];
pub const KIT: Principal = Principal::Client(KIT_KEY);
/// A key the agent never admitted.
pub const STRANGER: Principal = Principal::Client([0xee; 32]);

pub fn kit() -> Kit {
    Kit {
        entries: vec![KitEntry {
            kind: KitKind::Phrase,
            signing: KIT_KEY,
            sealing: [0xc2; 32],
            sealed_r1: vec![0xc3; 80],
        }],
        r2: [0xc4; 32],
    }
}

/// A minute of batch time: a day of a test home's policy.
pub const MINUTE: u64 = 60_000;

/// A test home's policy, a day of the default's a minute: operations wait
/// 3, the kit's 7, a probation is 3 and seasoning 7.
pub fn minutes() -> Policy {
    Policy {
        operation_delay_ms: 3 * MINUTE,
        kit_delay_ms: 7 * MINUTE,
        probation_ms: 3 * MINUTE,
        seasoning_ms: 7 * MINUTE,
        confirm_window_ms: 3 * MINUTE,
        kit_operations_per_day: 64,
        ..Policy::DEFAULT
    }
}

/// Kit `n`'s entry `entry`'s signing key: `[0xd0 + n; 31] ‖ entry`, `n`
/// below 32.
pub fn kit_signing(n: u8, entry: u8) -> [u8; 32] {
    let mut key = [0xd0 + n % 0x20; 32];
    key[31] = entry;
    key
}

pub fn kit_key(n: u8, entry: u8) -> Principal {
    Principal::Client(kit_signing(n, entry))
}

/// Kit `n`, a phrase's entry and a security key's, and its `R2`.
pub fn new_kit(n: u8) -> (NewKit, [u8; 32]) {
    let r2 = [n; 32];
    let entries = [KitKind::Phrase, KitKind::SecurityKey]
        .into_iter()
        .enumerate()
        .map(|(i, kind)| KitEntry {
            kind,
            signing: kit_signing(n, i as u8),
            sealing: [n ^ 0x55; 32],
            sealed_r1: vec![n; 80],
        })
        .collect();
    (
        NewKit {
            entries,
            r2_hash: r2_hash(&r2),
            r_hash: r_hash(&[n ^ 0x0f; 32]),
        },
        r2,
    )
}

/// The message `key` signs for `method` with `arguments`, as a client
/// signs a call.
pub fn message(key: [u8; 32], method: MethodId, arguments: &[u8]) -> Vec<u8> {
    let session = Session {
        key,
        name: [7; 16],
        t0: T0,
    };
    call_message(&IDENTITY, &session, 4, PERSONAL, method, arguments)
}

/// The evidence call's arguments.
pub fn evidence(index: u64, message: Vec<u8>, attached: Attached) -> impl Encode {
    ((index, message), ([0x5a_u8; 64], attached))
}

/// What rides beside an evidence: an `R2`.
pub fn with_r2(r2: [u8; 32]) -> Attached {
    Attached {
        welcome: None,
        r2: Some(r2),
    }
}

/// A scope's id.
pub fn scope(n: u8) -> Scope {
    [n; 16]
}

/// An envelope of `len` bytes in `scope` at `epoch`, its body `fill`.
pub fn envelope(scope: Scope, epoch: u64, fill: u8, len: usize) -> Vec<u8> {
    let header = Header {
        scope,
        epoch,
        nonce: [fill; 24],
        len_class: 0,
    };
    let mut bytes = header.to_bytes().to_vec();
    bytes.resize(len.max(Header::BYTES), fill);
    bytes
}

/// A commit's arguments: `epoch`, `effect`, `handshake` and the Welcome's
/// hash, as its message encodes them.
pub type Commit = ((u64, Effect), (Vec<u8>, Option<[u8; 32]>));

pub fn commit(epoch: u64, effect: Effect, handshake: Vec<u8>) -> Commit {
    ((epoch, effect), (handshake, None))
}

/// The update commit `n` for `epoch`: no add, no removal.
pub fn update(epoch: u64, n: u8) -> Commit {
    commit(epoch, Effect::default(), vec![n; 600])
}

/// Arguments already encoded.
pub struct Raw<'a>(pub &'a [u8]);

impl Encode for Raw<'_> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0);
    }
}

/// A step's answer: its reply, or the actor's error.
pub fn answer<T: Decode>(name: &str, outcome: &Outcome) -> Result<T, PersonalError> {
    match outcome {
        Outcome::Done(bytes) => Ok(T::decode_exact(bytes).expect("the reply decodes")),
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } => Err(PersonalError::decode_exact(detail).expect("the error decodes")),
        other => panic!("{name}: {other:?}"),
    }
}

/// A personal agent in a [`World`]: `Personal` installed in its agent, the
/// role `homes` granted, calls in one session per caller, each a batch at
/// the world's clock. Over a world of its own, or a view of an agent of a
/// world several share.
pub struct Home<W: Borrow<World> = World> {
    world: W,
    agent: AgentId,
    /// The most gas each method's call used.
    pub gas: BTreeMap<String, u64>,
}

/// `Personal`, derived once a run: a pool's agents each install it.
fn personal_derived() -> &'static vos_pvm_compiler::Derived {
    static DERIVED: std::sync::OnceLock<vos_pvm_compiler::Derived> = std::sync::OnceLock::new();
    DERIVED.get_or_init(|| {
        vos_pvm_compiler::derive(&std::fs::read(program_elf("vos-personal")).unwrap())
            .expect("derives")
    })
}

impl Home {
    /// Installed, not assigned.
    pub fn installed() -> Self {
        Self::installed_for(HOMES)
    }

    /// Installed, the role `homes` granted to `homes`.
    pub fn installed_for(homes: Principal) -> Self {
        let mut world = World::at(T0 - 2);
        install(&mut world, AGENT, homes);
        world.now = T0;
        Home::on(world, AGENT)
    }

    /// Claimed by device 0 with [`kit`], under `policy`, as `Homes`
    /// claims it.
    pub fn with(policy: Policy) -> Self {
        let mut home = Self::installed();
        home.claim(device(0), kit(), policy).unwrap();
        home
    }

    /// Assigned under the default policy.
    pub fn new() -> Self {
        Self::with(Policy::DEFAULT)
    }
}

/// `Personal` installed in `world`'s agent `agent`, the role `homes`
/// granted to `homes`.
pub fn install(world: &mut World, agent: AgentId, homes: Principal) {
    world
        .agent(agent)
        .install(PERSONAL, personal_derived(), &[("homes", HOMES_ROLE)])
        .grant(homes, HOMES_ROLE);
}

impl<W: Borrow<World>> Home<W> {
    /// `world`'s agent `agent`, where [`install`] installed `Personal`.
    pub fn on(world: W, agent: AgentId) -> Self {
        Self {
            world,
            agent,
            gas: BTreeMap::new(),
        }
    }

    /// The next batch's time.
    pub fn now(&self) -> u64 {
        self.world.borrow().now
    }

    /// The agent's node.
    pub fn node(&self) -> &Node {
        self.world.borrow().node(self.agent)
    }

    pub fn method(&self, name: &str) -> MethodId {
        self.world.borrow().method(self.agent, PERSONAL, name)
    }

    /// The log's head, read as `caller` or, refused, as the kit or the
    /// first device the agent answers: the start of the log before a claim.
    pub fn head(&self, caller: Principal) -> Place {
        let readers = [caller, KIT].into_iter().chain((0..32).map(sync));
        readers
            .filter_map(|reader| self.query::<Overview>(reader, "overview", ()).ok())
            .map(|overview| Place {
                next: overview.next,
                chain: overview.chain,
            })
            .next()
            .unwrap_or(Place {
                next: 0,
                chain: [0; 32],
            })
    }

    /// `arguments` of `name` as `caller` signs them: placed at the log's
    /// head first for an admin call.
    pub fn placed(&self, caller: Principal, name: &str, arguments: &[u8]) -> Vec<u8> {
        if vos_wire::personal::method::PLACED.contains(&self.method(name)) {
            self.head(caller).arguments(arguments)
        } else {
            arguments.to_vec()
        }
    }

    /// The arguments of the admin call the log holds at `index`, as its
    /// signer signed them, read as the kit or the first device the agent
    /// answers.
    pub fn logged(&self, index: u64) -> Vec<u8> {
        let entry = [KIT]
            .into_iter()
            .chain((0..32).map(sync))
            .find_map(|reader| self.query::<Vec<(u64, Entry)>>(reader, "log", index).ok())
            .and_then(|page| page.into_iter().next())
            .filter(|(at, _)| *at == index)
            .expect("the entry")
            .1;
        match entry.body {
            Body::Operation { call, .. }
            | Body::Veto { call, .. }
            | Body::Cosign { call, .. }
            | Body::Resolve { call, .. }
            | Body::Candidate { call, .. } => call.arguments,
            other => panic!("no admin call at {index}: {other:?}"),
        }
    }

    /// `caller`'s query of `name` at the current batch time.
    pub fn query<T: Decode>(
        &self,
        caller: Principal,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, PersonalError> {
        let outcome = self
            .world
            .borrow()
            .query(self.agent, caller, PERSONAL, name, arguments);
        answer(name, &outcome)
    }
}

impl<W: BorrowMut<World>> Home<W> {
    /// The world the agent is in.
    pub fn world(&mut self) -> &mut World {
        self.world.borrow_mut()
    }

    /// Move the batch time on by `ms`.
    pub fn pass(&mut self, ms: u64) {
        self.world().pass(ms);
    }

    /// `caller`'s call of `name`, alone in a batch, a device-set admin
    /// call placed at the log's head: its run.
    pub fn run(&mut self, caller: Principal, name: &str, arguments: impl Encode) -> Run {
        let arguments = self.placed(caller, name, &arguments.encode());
        self.run_as(caller, name, arguments)
    }

    /// `caller`'s call of `name` with `arguments` as given, alone in a
    /// batch: its run.
    pub fn run_as(&mut self, caller: Principal, name: &str, arguments: Vec<u8>) -> Run {
        let agent = self.agent;
        self.world()
            .agent(agent)
            .call(caller, PERSONAL, name, Raw(&arguments))
    }

    /// `caller`'s call of `name`: its reply, or the actor's error. Refused
    /// `Settling`, the caller wakes the agent until it settled what was due
    /// and calls again, as a device does.
    pub fn call<T: Decode>(
        &mut self,
        caller: Principal,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, PersonalError> {
        self.call_encoded(caller, name, &arguments.encode())
    }

    /// [`Home::call`] with its arguments encoded.
    fn call_encoded<T: Decode>(
        &mut self,
        caller: Principal,
        name: &str,
        arguments: &[u8],
    ) -> Result<T, PersonalError> {
        let answered = self.once(caller, name, arguments);
        if answered.as_ref().err() == Some(&PersonalError::Settling) && self.wake(caller).is_ok() {
            return self.once(caller, name, arguments);
        }
        answered
    }

    fn once<T: Decode>(
        &mut self,
        caller: Principal,
        name: &str,
        arguments: &[u8],
    ) -> Result<T, PersonalError> {
        let run = self.run(caller, name, Raw(arguments));
        let gas = run.instances.iter().map(|used| used.gas).sum();
        let most = self.gas.entry(name.to_string()).or_default();
        *most = (*most).max(gas);
        answer(name, &run.outcome)
    }

    /// `caller`'s wakes until the agent settled everything due.
    pub fn wake(&mut self, caller: Principal) -> Result<Woken, PersonalError> {
        loop {
            let woken: Woken = self.once(caller, "wake", &[])?;
            if woken.settled {
                return Ok(woken);
            }
        }
    }

    /// `caller`'s call of `name`, refused before the handler ran: its
    /// failure.
    /// The home's claim of the agent for `device` with `kit` under
    /// `policy`, as `Homes` sends it: the answer it sends back, `assigned`
    /// or the error `refused` carries.
    pub fn claim(
        &mut self,
        device: NewDevice,
        kit: Kit,
        policy: Policy,
    ) -> Result<(), PersonalError> {
        self.call::<()>(HOMES, "claim", ((device, kit), (policy, HOMES_AT)))?;
        let Principal::Agent(home) = HOMES else {
            unreachable!("the home is an agent")
        };
        let (_, sent) = self
            .world()
            .sent()
            .filter(|(_, sent)| sent.to == home)
            .last()
            .expect("the claim's answer")
            .clone();
        let vos_abi::message::Body::Call {
            method, arguments, ..
        } = sent.body
        else {
            panic!("a call: {sent:?}")
        };
        if method == vos_wire::homes::method::ASSIGNED {
            Ok(())
        } else {
            Err(PersonalError::decode_exact(&arguments).expect("a refusal"))
        }
    }

    pub fn refused(&mut self, caller: Principal, name: &str, arguments: impl Encode) -> Failure {
        match self.run(caller, name, arguments).outcome {
            Outcome::Failed { code, .. } => code,
            other => panic!("ran: {other:?}"),
        }
    }
}

impl<W: BorrowMut<World>> Home<W> {
    pub fn overview(&self) -> Overview {
        self.query(sync(0), "overview", ()).unwrap()
    }

    /// Device `n` paired by device `by`'s add, its commit confirmed by
    /// every device of its set: the epoch confirmed.
    pub fn pair(&mut self, by: u8, n: u8) -> u64 {
        self.pair_keys(by, device(n))
    }

    /// [`Home::pair`] for `keys`.
    pub fn pair_keys(&mut self, by: u8, keys: NewDevice) -> u64 {
        let epoch = self.overview().confirmed + 1;
        let effect = Effect {
            add: Some(keys),
            ..Effect::default()
        };
        let candidacy: Candidacy = self
            .call(
                admin(by),
                "commit",
                commit(epoch, effect, vec![epoch as u8; 700]),
            )
            .unwrap();
        self.confirm_all(epoch, &candidacy.set);
        epoch
    }

    /// Every device of `set` confirms `epoch` with one `h`.
    pub fn confirm_all(&mut self, epoch: u64, set: &[DeviceId]) {
        for device in set {
            let voted: Voted = self
                .call(
                    Principal::Client(device_keys(*device).sync),
                    "confirm",
                    (epoch, [epoch as u8; 32], [0u8; 64]),
                )
                .unwrap();
            if *device == *set.last().unwrap() {
                assert!(voted.verdict.is_some(), "the set's last vote decides");
            }
        }
        assert_eq!(self.overview().confirmed, epoch);
    }

    /// A commit by device `by` for the next epoch carrying `remove`, the
    /// kit re-sealed, confirmed by its set.
    pub fn commit_removing(&mut self, by: u8, remove: Vec<DeviceId>) -> Candidacy {
        let epoch = self.overview().confirmed + 1;
        let effect = Effect {
            add: None,
            remove,
            rekey: Some(self.rekey(sync(by), 0x3e).0),
        };
        let candidacy: Candidacy = self
            .call(
                admin(by),
                "commit",
                commit(epoch, effect, vec![0x80 | epoch as u8; 650]),
            )
            .unwrap();
        self.confirm_all(epoch, &candidacy.set);
        candidacy
    }

    /// `caller`'s operation `name`: its log index. A removal's, an add's,
    /// a replacement's, a regroup's, a second signature's or a resolution's
    /// evidence is posted beside it, by the device's sync key or the kit,
    /// as a device's flow posts it; a rotation's and a restore's carry an
    /// `R2`, which the test deposits.
    pub fn operate(
        &mut self,
        caller: Principal,
        name: &str,
        arguments: impl Encode,
    ) -> Result<u64, PersonalError> {
        let arguments = arguments.encode();
        let index = self
            .call_encoded::<Recorded>(caller, name, &arguments)?
            .index;
        if matches!(
            name,
            "remove" | "add" | "replace" | "regroup" | "cosign" | "resolve"
        ) {
            let Principal::Client(key) = caller else {
                return Ok(index);
            };
            let signed = message(key, self.method(name), &self.logged(index));
            let attached = Attached {
                welcome: None,
                r2: None,
            };
            self.call::<Recorded>(
                self.poster(caller),
                "evidence",
                evidence(index, signed, attached),
            )?;
        }
        Ok(index)
    }

    /// Who posts the evidence of `caller`'s admin call: the device's sync
    /// key for its admin key, as the set shows it; else the caller itself
    /// (the kit).
    fn poster(&self, caller: Principal) -> Principal {
        let views: Vec<DeviceView> = self.query(caller, "devices", ()).unwrap_or_default();
        views
            .into_iter()
            .find(|view| Principal::Client(view.device.keys.admin) == caller)
            .map_or(caller, |view| Principal::Client(view.device.keys.sync))
    }

    /// `caller`'s operation `name` with no evidence posted: its log index.
    pub fn unevidenced(
        &mut self,
        caller: Principal,
        name: &str,
        arguments: impl Encode,
    ) -> Result<u64, PersonalError> {
        self.call::<Recorded>(caller, name, arguments)
            .map(|recorded| recorded.index)
    }

    /// The operation at `index`, read by `reader`.
    pub fn operation(&self, reader: Principal, index: u64) -> Operation {
        self.query(reader, "operation", index).unwrap()
    }

    /// The evidence of the operation at `index`, `name` with `arguments`
    /// signed by `key`, posted by `poster` with `R2` beside it.
    pub fn deposit(
        &mut self,
        poster: Principal,
        key: [u8; 32],
        index: u64,
        name: &str,
        arguments: impl Encode,
        r2: [u8; 32],
    ) -> Result<Recorded, PersonalError> {
        // An admin call's arguments are as the log holds them, placed.
        let arguments = match vos_wire::personal::method::PLACED.contains(&self.method(name)) {
            true => self.logged(index),
            false => arguments.encode(),
        };
        let signed = message(key, self.method(name), &arguments);
        self.call(poster, "evidence", evidence(index, signed, with_r2(r2)))
    }

    /// The kit as `reader` reads it re-sealed under a new `R`, each `R1`
    /// `fill`, and its `R2`: what a commit carrying a removal brings.
    pub fn rekey(&self, reader: Principal, fill: u8) -> (NewKit, [u8; 32]) {
        let view: RecoveryView = self.query(reader, "recovery", ()).unwrap();
        let entries = view
            .entries
            .into_iter()
            .map(|entry| KitEntry {
                sealed_r1: vec![fill; 80],
                ..entry
            })
            .collect();
        let r2 = [fill ^ 0x77; 32];
        let kit = NewKit {
            entries,
            r2_hash: r2_hash(&r2),
            r_hash: r_hash(&[fill; 32]),
        };
        (kit, r2)
    }

    /// `envelope` pushed by device `n`.
    pub fn push(&mut self, n: u8, envelope: Vec<u8>) -> Result<Pushed, PersonalError> {
        self.call(sync(n), "push", envelope)
    }
}

/// The keys of device number `id`, which the tests' devices are added in
/// order of.
pub fn device_keys(id: DeviceId) -> NewDevice {
    device(id as u8)
}
