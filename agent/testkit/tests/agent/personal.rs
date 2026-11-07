//! `Personal`, the personal agent's actor (`agent/personal`, built by `just
//! build-personal`), in the default agent on a VOS host, call by call at
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

use std::collections::BTreeMap;
use vos_testkit::programs::{method, personal, personal_elf};
use vos_wire::abi::Failure;
use vos_wire::abi::cap::Target;

use vos_wire::batch::{Admin, Body, Input, Message, Query, Request, Work};
use vos_wire::defaults::SESSION_EXPIRY_MS;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::ingress::{Grant, call_message};
use vos_wire::personal::{
    AdminClass, Attached, Attestation, Candidacy, DeviceId, Effect, HOUR_MS, Header, Kit, KitEntry,
    KitKind, NewDevice, NewKit, Operation, Overview, PersonalError, Policy, Pushed, Recorded,
    RecoveryView, Scope, Voted, Woken, r_hash, r2_hash,
};
use vos_wire::result::{Outcome, Outgoing, Run, Step};
use vos_wire::{Decode, Encode, SpaceId, WindowClock};

use crate::common::{Node, ran};

pub const PERSONAL: InstanceId = InstanceId(5);
/// The principal holding the role `homes`, as the home's `Homes` does.
pub const HOMES: Principal = Principal::Client([0x50; 32]);
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
struct Raw<'a>(&'a [u8]);

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

/// A personal agent in the default agent: `Personal` installed, the role
/// `homes` granted to [`HOMES`], calls in one session per caller, each a
/// batch at the test's batch time.
pub struct Home {
    pub node: Node,
    program: Vec<u8>,
    /// Each caller's session, its last sequence and its last call's time.
    sessions: BTreeMap<Principal, (Session, u64, u64)>,
    /// The next batch's time; each batch moves it a millisecond on.
    pub now: u64,
    /// The most gas each method's call used.
    pub gas: BTreeMap<String, u64>,
    /// The messages its steps sent, for a test that relays them.
    pub outbox: Vec<Outgoing>,
}

impl Home {
    /// Installed, not assigned.
    pub fn installed() -> Self {
        Self::installed_for(HOMES)
    }

    /// Installed, the role `homes` granted to `homes`.
    pub fn installed_for(homes: Principal) -> Self {
        // Derived once a run: a pool's agents each install it.
        static DERIVED: std::sync::OnceLock<(Vec<u8>, vos_pvm_compiler::Derived)> =
            std::sync::OnceLock::new();
        let (elf, derived) = DERIVED.get_or_init(|| {
            let elf = std::fs::read(personal_elf()).unwrap();
            let derived = vos_pvm_compiler::derive(&elf).expect("derives");
            (elf, derived)
        });
        let mut node = Node::new();
        node.add(&derived.actor);
        let install = Input::Admin(Admin::Install {
            instance: PERSONAL,
            derivation: derived.derivation(elf),
            roles: vec![(b"homes".to_vec(), HOMES_ROLE)],
            target: Target::Vos,
            space: SpaceId::NONE,
            clock: WindowClock::DEFAULT,
        });
        let grant = Input::Admin(Admin::SetRole(Grant {
            principal: homes,
            role: Some(HOMES_ROLE),
        }));
        let result = node.batch(T0 - 1, vec![install, grant]);
        for step in &result.steps {
            assert!(matches!(ran(step).outcome, Outcome::Done(_)), "{step:?}");
        }
        Self {
            node,
            program: personal(),
            sessions: BTreeMap::new(),
            now: T0,
            gas: BTreeMap::new(),
            outbox: Vec::new(),
        }
    }

    /// Assigned to device 0 with [`kit`], under `policy`.
    pub fn with(policy: Policy) -> Self {
        let mut home = Self::installed();
        home.call::<Recorded>(HOMES, "configure", policy).unwrap();
        home.call::<Recorded>(HOMES, "assign", (device(0), kit()))
            .unwrap();
        home
    }

    /// Assigned under the default policy.
    pub fn new() -> Self {
        Self::with(Policy::DEFAULT)
    }

    pub fn method(&self, name: &str) -> MethodId {
        method(&self.program, name)
    }

    /// Move the batch time on by `ms`.
    pub fn pass(&mut self, ms: u64) {
        self.now += ms;
    }

    /// `caller`'s call of `name`, alone in a batch: its run.
    pub fn run(&mut self, caller: Principal, name: &str, arguments: impl Encode) -> Run {
        let method = self.method(name);
        let session = self.session(caller);
        let input = Input::Request(Request {
            session,
            sequence: self.sessions[&caller].1,
            caller,
            instance: PERSONAL,
            method,
            arguments: arguments.encode(),
        });
        let result = self.node.batch(self.now, vec![input]);
        self.now += 1;
        match result.steps.into_iter().next() {
            Some(Step::Ran(run)) => {
                self.outbox.extend(run.messages.iter().cloned());
                run
            }
            other => panic!("{name}: {other:?}"),
        }
    }

    /// A message from agent `from`, its `sequence`-th to this one, alone in
    /// a batch: its run.
    pub fn deliver(&mut self, from: AgentId, sequence: u64, body: Body) -> Run {
        let input = Input::Message(Message {
            from,
            sequence,
            body,
        });
        let result = self.node.batch(self.now, vec![input]);
        self.now += 1;
        match result.steps.into_iter().next() {
            Some(Step::Ran(run)) => {
                self.outbox.extend(run.messages.iter().cloned());
                run
            }
            other => panic!("a message: {other:?}"),
        }
    }

    /// `caller`'s session for a call now, its sequence moved on: a new one
    /// when its last call is older than the session's expiry allows.
    fn session(&mut self, caller: Principal) -> Session {
        let now = self.now;
        let fresh = || {
            let key = match caller {
                Principal::Client(key) => key,
                _ => [0; 32],
            };
            let mut name = [0; 16];
            name[..8].copy_from_slice(&now.to_le_bytes());
            (Session { key, name, t0: now }, 0, now)
        };
        let entry = self.sessions.entry(caller).or_insert_with(fresh);
        if entry.2 + SESSION_EXPIRY_MS / 2 < now {
            *entry = fresh();
        }
        entry.1 += 1;
        entry.2 = now;
        entry.0
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
        let arguments = arguments.encode();
        let answered = self.once(caller, name, &arguments);
        if answered.as_ref().err() == Some(&PersonalError::Settling) && self.wake(caller).is_ok() {
            return self.once(caller, name, &arguments);
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
    pub fn refused(&mut self, caller: Principal, name: &str, arguments: impl Encode) -> Failure {
        match self.run(caller, name, arguments).outcome {
            Outcome::Failed { code, .. } => code,
            other => panic!("ran: {other:?}"),
        }
    }

    /// `caller`'s query of `name` at the current batch time.
    pub fn query<T: Decode>(
        &self,
        caller: Principal,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, PersonalError> {
        let work = Work::Query(Query {
            time: self.now,
            seed: [0; 32],
            caller,
            instance: PERSONAL,
            method: self.method(name),
            arguments: arguments.encode(),
        });
        answer(name, &Outcome::decode(&self.node.refine(&work)).unwrap().0)
    }

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

    /// `caller`'s operation `name`: its log index.
    pub fn operate(
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
        let signed = message(key, self.method(name), &arguments.encode());
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
