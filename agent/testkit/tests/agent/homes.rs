//! `Homes`, the home's actor (`agent/homes`, built by `just build-homes`),
//! in the default agent beside the credential actor, and its pool's agents,
//! each `Personal` in an agent of its own, the messages between them
//! relayed as the nodes deliver them: a pool of 200 stocked and claimed; a
//! double claim, a kit's key twice and a claim `Personal` refuses; a
//! lapsed agent's reads, restore and removal and its refused pushes, ended
//! by a re-proof under a nullifier its add recorded; the quota raised at
//! the first re-proof; the registrar's open claim refused without its
//! work, closed or past its cap; and the cap below the keeper's refill
//! rate, a pool the keeper stops filling ending `PoolEmpty`.

use std::collections::{BTreeMap, VecDeque};

use vos_testkit::programs::{credentials, credentials_elf, homes, homes_elf, method};
use vos_wire::abi::Failure;
use vos_wire::abi::cap::Target;
use vos_wire::batch::{Admin, Body, CredentialedInput, Input, Message, Query, Request, Work};
use vos_wire::credentials::{
    self as tree, CredentialError, Digest, Open, RootEntry, meets, open_work,
};
use vos_wire::homes::{AgentsPage, Counts, HomesError, Standing, Terms};
use vos_wire::ids::{AgentId, InstanceId, Principal, Session};
use vos_wire::ingress::Grant;
use vos_wire::personal::{
    AdminClass, Attestation, Envelope, Kit, KitEntry, KitKind, NewDevice, Overview, PersonalError,
    Policy, RECOVERY, Recorded, kit_index,
};
use vos_wire::result::{Outcome, Outgoing, Run, Step};
use vos_wire::{Decode, Encode, SpaceId, WindowClock};

use crate::common::{AGENT, ALICE, BOB, Node};
use crate::personal::{
    self, Home, KIT, KIT_KEY, MINUTE, PERSONAL, admin, device, envelope, kit, kit_key, kit_signing,
    minutes, new_kit, scope, sync,
};

/// The home's agent as its pool's agents name it.
const HOME: AgentId = AgentId(1);
const CREDENTIALS: InstanceId = InstanceId(9);
const HOMES: InstanceId = InstanceId(3);
/// The registrar's and the operator's role byte: `ALICE` holds both.
const ROLE: u8 = 1;
const SPACE: SpaceId = SpaceId([0x5a; 32]);
const HANDLE: [u8; 32] = [0x42; 32];
/// The first pool agent's id.
const FIRST: u32 = 100;

/// Claim `n`'s nullifier in the scope "home".
fn nullifier(n: u32) -> [u8; 32] {
    let mut bytes = [0xa0; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    bytes
}

/// Claim `n`'s device: a strong admin whose keys are its own.
fn claimant(n: u32) -> NewDevice {
    let key = |kind: u8| {
        let mut key = [kind; 32];
        key[..4].copy_from_slice(&n.to_le_bytes());
        key
    };
    NewDevice {
        sync: key(0xb1),
        admin: key(0xb2),
        class: AdminClass::Strong,
        attestation: Attestation {
            hardware: true,
            verified_boot: true,
        },
        nullifier: nullifier(n),
        label: vec![7; 24],
    }
}

/// Claim `n`'s kit: a phrase's entry.
fn kit_of(n: u32) -> Kit {
    let mut signing = [0xc5; 32];
    signing[..4].copy_from_slice(&n.to_le_bytes());
    Kit {
        entries: vec![KitEntry {
            kind: KitKind::Phrase,
            signing,
            sealing: [0xc6; 32],
            sealed_r1: vec![0xc7; 80],
        }],
        r2: [0xc8; 32],
    }
}

/// A member digest for `seed`: eight words below p.
fn member(seed: u32) -> Digest {
    tree::digest(&[seed, 11, 12, 13, 14, 15, 16, 17])
}

/// A nonce whose work for `member` meets `open`'s difficulty.
fn work(member: &Digest, open: &Open) -> u64 {
    (0..)
        .find(|nonce| {
            meets(
                &open_work(&HANDLE, member, &open.salt, *nonce),
                open.difficulty,
            )
        })
        .unwrap()
}

/// A step's answer: its reply, or the handler's error.
fn answer<T: Decode, E: Decode>(outcome: &Outcome) -> Result<T, E> {
    match outcome {
        Outcome::Done(bytes) => Ok(T::decode_exact(bytes).expect("the reply decodes")),
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } => Err(E::decode_exact(detail).expect("the error decodes")),
        other => panic!("{other:?}"),
    }
}

/// The home's agent, the credential actor and `Homes` installed, `ALICE`
/// its registrar and operator; and the pool's agents, each a [`Home`]
/// whose role `homes` the home's agent holds.
struct Space {
    node: Node,
    credentials: Vec<u8>,
    homes: Vec<u8>,
    agents: BTreeMap<u32, Home>,
    /// The next message's number, by sender and receiver.
    sequences: BTreeMap<(u32, u32), u64>,
    now: u64,
    sessions: u64,
    nonce: u64,
}

impl Space {
    /// Founded, `Homes` configured with `policy` and `Personal` at
    /// [`PERSONAL`].
    fn new(policy: Policy) -> Self {
        let mut space = Self::installed();
        space.configure(policy);
        space
    }

    /// Founded, `Homes` not configured.
    fn installed() -> Self {
        let mut node = Node::new();
        let mut installs = Vec::new();
        for (instance, elf, role) in [
            (CREDENTIALS, credentials_elf(), "registrar"),
            (HOMES, homes_elf(), "operator"),
        ] {
            let elf = std::fs::read(elf).unwrap();
            let derived = vos_pvm_compiler::derive(&elf).expect("derives");
            node.add(&derived.actor);
            installs.push(Input::Admin(Admin::Install {
                instance,
                derivation: derived.derivation(&elf),
                roles: vec![(role.as_bytes().to_vec(), ROLE)],
                target: Target::Vos,
                space: SPACE,
                clock: WindowClock::DEFAULT,
            }));
        }
        installs.push(Input::Admin(Admin::SetRole(Grant {
            principal: ALICE,
            role: Some(ROLE),
        })));
        let mut space = Self {
            node,
            credentials: credentials(),
            homes: homes(),
            agents: BTreeMap::new(),
            sequences: BTreeMap::new(),
            now: personal::T0,
            sessions: 0,
            nonce: 0,
        };
        for step in space.node.batch(personal::T0 - 2, installs).steps {
            assert!(matches!(ran(&step).outcome, Outcome::Done(_)), "{step:?}");
        }
        space
            .operate::<(), CredentialError>(CREDENTIALS, "found", HANDLE)
            .unwrap();
        space
    }

    fn configure(&mut self, policy: Policy) {
        let terms = Terms {
            instance: PERSONAL.0,
            policy,
        };
        self.operate::<(), HomesError>(HOMES, "configure", terms)
            .unwrap();
    }

    fn program(&self, instance: InstanceId) -> &[u8] {
        if instance == CREDENTIALS {
            &self.credentials
        } else {
            &self.homes
        }
    }

    fn pass(&mut self, ms: u64) {
        self.now += ms;
    }

    /// One input alone in a batch at now: its run.
    fn step(&mut self, input: Input) -> Run {
        let result = self.node.batch(self.now, vec![input]);
        self.now += 1;
        match result.steps.into_iter().next() {
            Some(Step::Ran(run)) => run,
            other => panic!("{other:?}"),
        }
    }

    /// `caller`'s request of `name` in a session of its own.
    fn request<A: Encode>(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        name: &str,
        arguments: A,
    ) -> Run {
        self.sessions += 1;
        let Principal::Client(key) = caller else {
            panic!("a client's request")
        };
        let mut session = [0u8; 16];
        session[..8].copy_from_slice(&self.sessions.to_le_bytes());
        let method = method(self.program(instance), name);
        self.step(Input::Request(Request {
            session: Session {
                key,
                name: session,
                t0: self.now,
            },
            sequence: 1,
            caller,
            instance,
            method,
            arguments: arguments.encode(),
        }))
    }

    /// The operator's (and registrar's) call of `name`.
    fn operate<T: Decode, E: Decode>(
        &mut self,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, E> {
        answer(&self.request(ALICE, instance, name, arguments).outcome)
    }

    /// A query of `name` at now.
    fn query<T: Decode>(&self, instance: InstanceId, name: &str, arguments: impl Encode) -> T {
        let work = Work::Query(Query {
            time: self.now,
            seed: [0; 32],
            caller: BOB,
            instance,
            method: method(self.program(instance), name),
            arguments: arguments.encode(),
        });
        match Outcome::decode(&self.node.refine(&work)).unwrap().0 {
            Outcome::Done(bytes) => T::decode_exact(&bytes).expect("decodes"),
            other => panic!("{name}: {other:?}"),
        }
    }

    /// A proven call of `Homes`' `name` by the member whose nullifier in
    /// the scope "home" is `nullifier`: its run, and every message it set
    /// off relayed.
    fn proven<A: Encode>(&mut self, nullifier: [u8; 32], name: &str, arguments: A) -> Run {
        self.nonce += 1;
        let mut binding = [0x3b; 32];
        binding[..8].copy_from_slice(&self.nonce.to_le_bytes());
        let root: RootEntry = self.query(CREDENTIALS, "root", ());
        let scope = tree::scope(&SPACE, AGENT, HOMES, b"home");
        let claim = tree::AuthClaim {
            map_root: root.root,
            scope,
            nullifier,
            binding,
        };
        let call = CredentialedInput {
            origin: Principal::Anonymous { scope, nullifier },
            instance: HOMES,
            method: method(&self.homes, name),
            arguments: arguments.encode(),
            binding,
            expires_ms: self.now + 60_000,
            claim: claim.encode(),
            kernel: method(&self.credentials, "auth"),
        };
        let run = self.step(Input::Credentialed(Box::new(call)));
        self.relay(run.messages.clone());
        run
    }

    fn claim(&mut self, n: u32) -> Result<u32, HomesError> {
        self.claim_with(nullifier(n), claimant(n), kit_of(n))
    }

    fn claim_with(
        &mut self,
        nullifier: [u8; 32],
        device: NewDevice,
        kit: Kit,
    ) -> Result<u32, HomesError> {
        answer(&self.proven(nullifier, "claim", (device, kit)).outcome)
    }

    fn renew(&mut self, nullifier: [u8; 32], agent: u32) -> Result<(), HomesError> {
        answer(&self.proven(nullifier, "renew", agent).outcome)
    }

    /// The keeper's batch: `count` agents with `Personal` installed, the
    /// home's agent granted their role `homes`, stocked: the pooled count.
    fn make(&mut self, count: u32) -> u32 {
        let first = FIRST + self.agents.len() as u32;
        let ids: Vec<u32> = (first..first + count).collect();
        for id in &ids {
            let mut home = Home::installed_for(Principal::Agent(HOME));
            home.now = self.now;
            self.agents.insert(*id, home);
        }
        self.operate::<u32, HomesError>(HOMES, "stock", ids)
            .unwrap()
    }

    /// Deliver `messages` from the home's agent, and every message their
    /// steps send, in order, until none is left.
    fn relay(&mut self, messages: Vec<Outgoing>) {
        let mut queue: VecDeque<(u32, Outgoing)> = messages
            .into_iter()
            .map(|message| (HOME.0, message))
            .collect();
        while let Some((from, Outgoing { to, body })) = queue.pop_front() {
            let sequence = self.sequences.entry((from, to.0)).or_insert(0);
            *sequence += 1;
            let sequence = *sequence;
            if to == HOME {
                let run = self.step(Input::Message(Message {
                    from: AgentId(from),
                    sequence,
                    body,
                }));
                assert!(
                    matches!(run.outcome, Outcome::Done(_)),
                    "Homes took agent {from}'s message: {:?}",
                    run.outcome
                );
                queue.extend(run.messages.into_iter().map(|message| (HOME.0, message)));
            } else {
                let now = self.now;
                let home = self.agents.get_mut(&to.0).expect("a pool agent");
                home.now = home.now.max(now);
                home.deliver(HOME, sequence, body);
                let sent: Vec<Outgoing> = home.outbox.drain(..).collect();
                queue.extend(sent.into_iter().map(|message| (to.0, message)));
            }
        }
    }

    /// Pool agent `agent`, its batch time now.
    fn agent(&mut self, agent: u32) -> &mut Home {
        let now = self.now;
        let home = self.agents.get_mut(&agent).expect("a pool agent");
        home.now = home.now.max(now);
        home
    }

    /// Relay what agent `agent`'s calls sent.
    fn flush(&mut self, agent: u32) {
        let sent: Vec<Outgoing> = self.agent(agent).outbox.drain(..).collect();
        let mut queue = Vec::new();
        for Outgoing { to, body } in sent {
            assert_eq!(to, HOME, "a pool agent sends only to its home");
            let sequence = self.sequences.entry((agent, HOME.0)).or_insert(0);
            *sequence += 1;
            let sequence = *sequence;
            let run = self.step(Input::Message(Message {
                from: AgentId(agent),
                sequence,
                body,
            }));
            assert!(matches!(run.outcome, Outcome::Done(_)), "{:?}", run.outcome);
            queue.extend(run.messages);
        }
        self.relay(queue);
    }

    fn opening(&self) -> Open {
        self.query::<Option<Open>>(CREDENTIALS, "opening", ())
            .expect("the open claim opened")
    }

    fn standing(&self, agent: u32) -> Option<Standing> {
        self.query(HOMES, "standing_of", agent)
    }

    fn tally(&self) -> Counts {
        self.query(HOMES, "tally", ())
    }

    fn found(&self, nullifier: [u8; 32]) -> Option<u32> {
        self.query(HOMES, "agent", nullifier)
    }

    fn kit_finds(&self, signing: &[u8; 32]) -> Option<u32> {
        self.query(HOMES, "find", kit_index(signing))
    }
}

fn ran(step: &Step) -> &Run {
    crate::common::ran(step)
}

/// A pool of 200 made by the keeper in one batch and claimed, each claim
/// assigned by its agent's answer, indexed under its nullifier and its
/// kit's key, its agent configured with the home's policy; the pool then
/// empty, `PoolEmpty`.
#[test]
fn a_pool_of_200_is_made_and_claimed() {
    let policy = minutes();
    let mut space = Space::new(policy);
    assert_eq!(space.make(200), 200);
    for n in 0..200 {
        let agent = space.claim(n).unwrap();
        assert_eq!(agent, FIRST + n, "the lowest pooled agent");
        assert!(matches!(
            space.standing(agent),
            Some(Standing::Assigned { .. })
        ));
        assert_eq!(space.found(nullifier(n)), Some(agent));
        assert_eq!(space.kit_finds(&kit_of(n).entries[0].signing), Some(agent));
    }
    assert_eq!(
        space.tally(),
        Counts {
            pooled: 0,
            claimed: 0,
            assigned: 200,
        }
    );
    for n in [0, 99, 199] {
        let device = Principal::Client(claimant(n).sync);
        let overview: Overview = space
            .agent(FIRST + n)
            .query(device, "overview", ())
            .unwrap();
        assert!(
            overview.lease_until > personal::T0 + policy.lease_ms,
            "assigned under the policy"
        );
        assert!(!overview.lapsed);
    }
    assert_eq!(space.claim(200), Err(HomesError::PoolEmpty));
    let page: AgentsPage = space.query(HOMES, "agents", Option::<u32>::None);
    assert_eq!(page.agents.len(), 200);
    assert!(!page.more);
}

/// B12: one nullifier holds one agent and a kit's key indexes one; a
/// device whose nullifier is not the proof's is refused; a claim
/// `Personal` refuses is released, its agent pooled again; a stocked agent
/// is not stocked again; and only a pool agent's answer is taken.
#[test]
fn a_double_claim_is_refused() {
    let mut space = Space::new(minutes());
    space.make(3);
    let first = space.claim(1).unwrap();
    assert_eq!(space.claim(1), Err(HomesError::Claimed));
    assert_eq!(
        space.claim_with(nullifier(2), claimant(2), kit_of(1)),
        Err(HomesError::KitTaken),
        "another claim's kit"
    );
    assert_eq!(
        space.claim_with(nullifier(3), claimant(2), kit_of(3)),
        Err(HomesError::Nullifier),
        "a device naming another nullifier"
    );
    // `Personal` refuses a device whose two keys are one: the agent goes
    // back to the pool and the claim's indexes with it.
    let one_key = NewDevice {
        admin: claimant(4).sync,
        ..claimant(4)
    };
    let refused = space.claim_with(nullifier(4), one_key, kit_of(4)).unwrap();
    assert_eq!(refused, first + 1);
    assert_eq!(space.standing(refused), Some(Standing::Pooled));
    assert_eq!(space.found(nullifier(4)), None);
    assert_eq!(space.kit_finds(&kit_of(4).entries[0].signing), None);
    assert_eq!(space.claim(4), Ok(refused), "claimed again, properly");
    assert_eq!(
        space.operate::<u32, HomesError>(HOMES, "stock", vec![first]),
        Err(HomesError::Stocked)
    );
    let many: Vec<u32> = (1000..1257).collect();
    assert_eq!(
        space.operate::<u32, HomesError>(HOMES, "stock", many),
        Err(HomesError::TooMany)
    );
    // A stranger's answer is not taken.
    let stranger = space.step(Input::Message(Message {
        from: AgentId(9_999),
        sequence: 1,
        body: Body::Call {
            instance: HOMES,
            method: method(&space.homes, "assigned"),
            arguments: Vec::new(),
            awaiting: None,
        },
    }));
    assert_eq!(
        answer::<(), HomesError>(&stranger.outcome),
        Err(HomesError::Unknown)
    );
    assert_eq!(
        space.tally(),
        Counts {
            pooled: 1,
            claimed: 0,
            assigned: 2,
        }
    );
}

/// A claim before the operator set the terms is refused, and so is a
/// re-proof of an agent the nullifier is not recorded for.
#[test]
fn a_claim_needs_the_terms_and_a_re_proof_a_recorded_nullifier() {
    let mut space = Space::installed();
    space.make(1);
    assert_eq!(space.claim(1), Err(HomesError::Unconfigured));
    space.configure(minutes());
    let agent = space.claim(1).unwrap();
    assert_eq!(
        space.renew(nullifier(2), agent),
        Err(HomesError::NotRecorded)
    );
    assert_eq!(
        space.renew(nullifier(1), agent + 1),
        Err(HomesError::NotRecorded)
    );
    space.renew(nullifier(1), agent).unwrap();
}

/// B14, B15: past its lease a claimed agent is in its grace: it refuses
/// pushes and still serves reads, a removal and a restore. Its second
/// device's nullifier was recorded at Homes when its add was confirmed,
/// and the restore's device's at its maturity, with the next kit's keys
/// indexed in place of the old: the restore's device re-proves under its
/// own nullifier, and the grace ends.
#[test]
fn a_lapsed_agent_serves_reads_a_restore_and_a_removal_and_refuses_pushes() {
    let policy = Policy {
        lease_ms: 30 * MINUTE,
        ..minutes()
    };
    let mut space = Space::new(policy);
    space.make(1);
    let agent = space
        .claim_with(device(0).nullifier, device(0), kit())
        .unwrap();
    assert_eq!(space.kit_finds(&KIT_KEY), Some(agent));
    space.agent(agent).pair(0, 1);
    space.flush(agent);
    assert_eq!(
        space.found(device(1).nullifier),
        Some(agent),
        "the second device's nullifier, recorded at its add"
    );
    space
        .agent(agent)
        .push(0, envelope(scope(1), 1, 1, 100))
        .unwrap();
    space.pass(30 * MINUTE);
    let home = space.agent(agent);
    home.now += 1;
    assert!(home.overview().lapsed);
    assert_eq!(
        home.push(0, envelope(scope(1), 1, 2, 100)),
        Err(PersonalError::Lapsed)
    );
    let read: Vec<Envelope> = home.query(sync(1), "since", (scope(1), 0u64)).unwrap();
    assert_eq!(read.len(), 1, "reads are served");
    // A stolen phone is removed.
    home.call::<Recorded>(admin(0), "remove", 1u32).unwrap();
    home.pass(3 * MINUTE);
    let removal = home.commit_removing(0, vec![1]);
    assert_eq!(removal.set, vec![0]);
    home.push(0, envelope(RECOVERY, 2, 3, 100)).unwrap();
    // Every device is lost: the kit restores onto a new one.
    let (next, r2) = new_kit(1);
    let restore = (device(5), next);
    let index = home.operate(KIT, "restore", restore.clone()).unwrap();
    home.deposit(KIT, KIT_KEY, index, "restore", restore, r2)
        .unwrap();
    home.pass(7 * MINUTE);
    // The kit's wake settles the restore, which replaces it.
    home.wake(KIT)
        .or_else(|_| home.wake(kit_key(1, 0)))
        .unwrap();
    let recovered: Vec<Envelope> = home.query(sync(5), "since", (RECOVERY, 0u64)).unwrap();
    assert_eq!(
        recovered.len(),
        1,
        "the restored device reads the recovery scope"
    );
    space.flush(agent);
    assert_eq!(space.found(device(5).nullifier), Some(agent));
    assert_eq!(space.kit_finds(&kit_signing(1, 0)), Some(agent));
    assert_eq!(space.kit_finds(&kit_signing(1, 1)), Some(agent));
    assert_eq!(space.kit_finds(&KIT_KEY), None, "the replaced kit's index");
    // The restored device re-proves: the grace ends.
    space.renew(device(5).nullifier, agent).unwrap();
    let home = space.agent(agent);
    let overview: Overview = home.query(sync(5), "overview", ()).unwrap();
    assert!(!overview.lapsed);
    home.push(5, envelope(scope(2), overview.confirmed, 4, 100))
        .unwrap();
}

/// The registrar's open claim: closed until it opens; refused without its
/// work, and with work under a salt neither the period's nor the one
/// before; taken within its cap a period, `Cap` past it; and the period
/// after takes the cap again, work under the salt before included.
#[test]
fn an_open_claim_without_its_work_is_refused() {
    let mut space = Space::new(minutes());
    let period = 10 * MINUTE;
    let opening: Option<Open> = space.query(CREDENTIALS, "opening", ());
    assert_eq!(opening, None);
    assert_eq!(
        space.operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(1), 0u64)),
        Err(CredentialError::Closed)
    );
    space
        .operate::<(), CredentialError>(CREDENTIALS, "open", (8u8, 3u32, period))
        .unwrap();
    assert_eq!(
        space.operate::<(), CredentialError>(CREDENTIALS, "open", (65u8, 3u32, period)),
        Err(CredentialError::Terms)
    );
    let open: Open = space.opening();
    assert_eq!((open.difficulty, open.left, open.period_ms), (8, 3, period));
    let without = (0..)
        .find(|nonce| !meets(&open_work(&HANDLE, &member(1), &open.salt, *nonce), 8))
        .unwrap();
    assert_eq!(
        space.operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(1), without)),
        Err(CredentialError::Work)
    );
    let foreign = Open {
        salt: [9; 32],
        ..open
    };
    let elsewhere = (0..)
        .find(|nonce| {
            meets(&open_work(&HANDLE, &member(1), &foreign.salt, *nonce), 8)
                && !meets(&open_work(&HANDLE, &member(1), &open.salt, *nonce), 8)
        })
        .unwrap();
    assert_eq!(
        space.operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(1), elsewhere)),
        Err(CredentialError::Work),
        "work under another salt"
    );
    let before = space.query::<RootEntry>(CREDENTIALS, "root", ());
    for seed in 1..=3 {
        let nonce = work(&member(seed), &open);
        space
            .operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(seed), nonce))
            .unwrap();
    }
    assert_ne!(space.query::<RootEntry>(CREDENTIALS, "root", ()), before);
    assert_eq!(space.query::<u64>(CREDENTIALS, "count", ()), 3);
    let fourth = work(&member(4), &open);
    assert_eq!(
        space.operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(4), fourth)),
        Err(CredentialError::Cap)
    );
    let left = space.opening();
    assert_eq!(left.left, 0);
    // The next period: the work made under the salt before still counts.
    space.pass(period);
    let next = space.opening();
    assert_ne!(next.salt, open.salt);
    assert_eq!(next.left, 3);
    space
        .operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(4), fourth))
        .unwrap();
    // Two periods on, it does not.
    space.pass(2 * period);
    let late = work(&member(5), &open);
    let current = space.opening();
    if !meets(&open_work(&HANDLE, &member(5), &current.salt, late), 8) {
        assert_eq!(
            space.operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(5), late)),
            Err(CredentialError::Work)
        );
    }
    assert_eq!(
        space.operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(4), fourth)),
        Err(CredentialError::Enrolled)
    );
    // A cap of zero closes it.
    space
        .operate::<(), CredentialError>(CREDENTIALS, "open", (8u8, 0u32, period))
        .unwrap();
    assert_eq!(
        space.query::<Option<Open>>(CREDENTIALS, "opening", ()),
        None
    );
}

/// B11: the open claims' cap sized below the keeper's refill rate keeps
/// the pool from draining (each period the cap's members join and claim,
/// the next open claim `Cap`); a keeper that stops filling shows as
/// `PoolEmpty` once the pool runs dry, and its refill ends it.
#[test]
fn the_cap_keeps_the_pool_and_an_empty_pool_is_pool_empty() {
    let mut space = Space::new(minutes());
    let period = 10 * MINUTE;
    let (cap, refill) = (4u32, 5u32);
    space
        .operate::<(), CredentialError>(CREDENTIALS, "open", (8u8, cap, period))
        .unwrap();
    let mut seed = 0;
    for _ in 0..3 {
        space.make(refill);
        let open = space.opening();
        for _ in 0..cap {
            seed += 1;
            let nonce = work(&member(seed), &open);
            space
                .operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(seed), nonce))
                .unwrap();
            space.claim(seed).unwrap();
        }
        let over = work(&member(1000), &open);
        assert_eq!(
            space.operate::<u32, CredentialError>(CREDENTIALS, "claim_open", (member(1000), over)),
            Err(CredentialError::Cap)
        );
        space.pass(period);
    }
    assert_eq!(space.tally().pooled, 3 * (refill - cap));
    // The keeper stops: the pool's last agents go, then `PoolEmpty`.
    for _ in 0..3 {
        seed += 1;
        space.claim(seed).unwrap();
    }
    seed += 1;
    assert_eq!(space.claim(seed), Err(HomesError::PoolEmpty));
    assert_eq!(space.found(nullifier(seed)), None, "nothing written");
    space.make(1);
    space.claim(seed).unwrap();
}

/// The quota ramps: a claimed agent holds the policy's smaller quota until
/// its first re-proof through `Homes`, and the larger one after.
#[test]
fn the_quota_ramps_at_the_first_re_proof() {
    let policy = Policy {
        bytes_new: 1_000,
        bytes_full: 4_000,
        ..minutes()
    };
    let mut space = Space::new(policy);
    space.make(1);
    let agent = space
        .claim_with(device(0).nullifier, device(0), kit())
        .unwrap();
    let home = space.agent(agent);
    home.push(0, envelope(scope(1), 0, 1, 900)).unwrap();
    assert_eq!(
        home.push(0, envelope(scope(1), 0, 2, 900)),
        Err(PersonalError::Quota)
    );
    space.renew(device(0).nullifier, agent).unwrap();
    let home = space.agent(agent);
    home.push(0, envelope(scope(1), 0, 2, 900)).unwrap();
    home.push(0, envelope(scope(1), 0, 3, 900)).unwrap();
}
