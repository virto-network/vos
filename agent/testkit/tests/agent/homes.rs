//! `Homes`, the home's actor (`agent/homes`, built by `just build-programs`),
//! in the default agent beside the credential actor, and its pool's agents,
//! each `Personal` in an agent of its own, the messages between them
//! relayed as the nodes deliver them: a pool of 200 stocked and claimed; a
//! double claim, a kit's key twice and a claim `Personal` refuses; a
//! lapsed agent's reads, restore and removal and its refused pushes, ended
//! by a re-proof under a nullifier its add recorded; the quota raised at
//! the first yearly re-proof; the registrar's open claim refused without its
//! work, closed or past its cap; and the cap below the keeper's refill
//! rate, a pool the keeper stops filling ending `PoolEmpty`.

use tree::Digest;
use vos_abi::credentials as tree;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_abi::message::Body;
use vos_abi::result::{Outcome, Outgoing, Run};
use vos_abi::{Decode, Encode, SpaceId};
use vos_testkit::{World, answer};
use vos_wire::batch::{Input, Message};
use vos_wire::credentials::{CredentialError, Open, RootEntry, meets, open_work};
use vos_wire::homes::{AgentsPage, Counts, HomesError, Standing, Terms};
use vos_wire::personal::{
    AdminClass, Attestation, Envelope, Kit, KitEntry, KitKind, NewDevice, Overview, PersonalError,
    Policy, RECOVERY, kit_index,
};

use crate::common::ALICE;
use crate::personal::{
    self, Home, KIT, KIT_KEY, MINUTE, PERSONAL, Raw, admin, device, envelope, kit, kit_key,
    kit_signing, minutes, new_kit, scope, sync,
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

/// The home's agent, the credential actor and `Homes` installed, `ALICE`
/// its registrar and operator; and the pool's agents, each `Personal` in
/// an agent of the same world, whose role `homes` the home's agent holds.
struct Space {
    world: World,
    /// The pool's agents made.
    made: u32,
    /// The outcomes of messages to `Homes` that did not run to `Done`.
    unanswered: Vec<Outcome>,
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
        let mut world = World::at(personal::T0 - 3);
        for (instance, name, role) in [
            (CREDENTIALS, "vos-credentials", "registrar"),
            (HOMES, "vos-homes", "operator"),
        ] {
            let derived = vos_testkit::programs::program_derived(name);
            world
                .agent(HOME)
                .install_in(SPACE, instance, &derived, &[(role, ROLE)]);
        }
        world.agent(HOME).grant(ALICE, ROLE);
        world.now = personal::T0;
        let mut space = Self {
            world,
            made: 0,
            unanswered: Vec::new(),
        };
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

    /// The id of the home's `instance`'s method `name`.
    fn method(&self, instance: InstanceId, name: &str) -> MethodId {
        self.world.method(HOME, instance, name)
    }

    fn pass(&mut self, ms: u64) {
        self.world.pass(ms);
    }

    /// One input alone in a batch of the home's agent at now: its run.
    fn step(&mut self, input: Input) -> Run {
        self.world.agent(HOME).step(input)
    }

    /// The operator's (and registrar's) call of `name`.
    fn operate<T: Decode, E: Decode>(
        &mut self,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, E> {
        answer(
            &self
                .world
                .agent(HOME)
                .call(ALICE, instance, name, arguments)
                .outcome,
        )
    }

    /// A query of `name` at now.
    fn query<T: Decode>(&self, instance: InstanceId, name: &str, arguments: impl Encode) -> T {
        self.world.read(HOME, instance, name, arguments)
    }

    /// A proven call of `Homes`' `name` by the member whose nullifier in
    /// the scope "home" is `nullifier`: its run, and every message it set
    /// off relayed.
    fn proven<A: Encode>(&mut self, nullifier: [u8; 32], name: &str, arguments: A) -> Run {
        let run = self.world.agent(HOME).proven(
            CREDENTIALS,
            (b"home", nullifier),
            HOMES,
            name,
            arguments,
        );
        self.relay(Vec::new());
        run
    }

    fn claim(&mut self, n: u32) -> Result<u32, HomesError> {
        self.claim_with(nullifier(n), claimant(n), kit_of(n))
    }

    /// A device's claim: of the agent its nullifier holds, as a device
    /// retrying its claim names the agent it sealed its kit to, else of
    /// the lowest pooled.
    fn claim_with(
        &mut self,
        nullifier: [u8; 32],
        device: NewDevice,
        kit: Kit,
    ) -> Result<u32, HomesError> {
        let agent = match self.found(nullifier) {
            Some(agent) => agent,
            // Agent 0 is never stocked here, so naming it meets an empty
            // pool.
            None => self.query::<Option<u32>>(HOMES, "pooled", ()).unwrap_or(0),
        };
        self.claim_of(nullifier, device, kit, agent)
    }

    fn claim_of(
        &mut self,
        nullifier: [u8; 32],
        device: NewDevice,
        kit: Kit,
        agent: u32,
    ) -> Result<u32, HomesError> {
        answer(
            &self
                .proven(nullifier, "claim", (device, kit, agent))
                .outcome,
        )
    }

    fn renew(&mut self, nullifier: [u8; 32], agent: u32) -> Result<(), HomesError> {
        answer(&self.proven(nullifier, "renew", agent).outcome)
    }

    /// The keeper's batch: `count` agents with `Personal` installed, the
    /// home's agent granted their role `homes`, stocked: the pooled count.
    fn make(&mut self, count: u32) -> u32 {
        let first = FIRST + self.made;
        let ids: Vec<u32> = (first..first + count).collect();
        for id in &ids {
            self.add(*id, Principal::Agent(HOME));
        }
        self.operate::<u32, HomesError>(HOMES, "stock", ids)
            .unwrap()
    }

    /// Agent `id` with `Personal` installed, its role `homes` granted to
    /// `homes`: one of the pool's, not yet stocked.
    fn add(&mut self, id: u32, homes: Principal) {
        personal::install(&mut self.world, AgentId(id), homes);
        self.made += 1;
    }

    /// Deliver `messages` as the home's agent's, with those it sent, and
    /// every message their steps send, in order, until none is left.
    fn relay(&mut self, messages: Vec<Outgoing>) {
        for message in messages {
            self.world.send(HOME, message);
        }
        self.delivered(HOME);
    }

    /// Deliver what `from` sent and all it sets off; an answer to the
    /// home's agent that did not run to `Done` is kept.
    fn delivered(&mut self, from: AgentId) -> Vec<(AgentId, Run)> {
        let delivered = self.world.deliver_from(from);
        self.unanswered.extend(
            delivered
                .iter()
                .filter(|(to, run)| *to == HOME && !matches!(run.outcome, Outcome::Done(_)))
                .map(|(_, run)| run.outcome.clone()),
        );
        delivered
    }

    /// Pool agent `agent`.
    fn agent(&mut self, agent: u32) -> Home<&mut World> {
        Home::on(&mut self.world, AgentId(agent))
    }

    /// Relay what agent `agent`'s calls sent.
    fn flush(&mut self, agent: u32) {
        let sent = self
            .world
            .sent()
            .filter(|(from, _)| *from == AgentId(agent))
            .count();
        assert!(
            self.world
                .sent()
                .all(|(from, message)| *from != AgentId(agent) || message.to == HOME),
            "a pool agent sends only to its home"
        );
        let before = self.unanswered.len();
        let delivered = self.delivered(AgentId(agent));
        assert!(delivered.len() >= sent);
        assert_eq!(
            self.unanswered.len(),
            before,
            "{:?}",
            self.unanswered.last()
        );
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
        assert!(matches!(space.standing(agent), Some(Standing::Assigned)));
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
/// device whose nullifier is not the proof's, or keys `Personal` would
/// refuse, are refused; an agent stocked again is left as it is; and only
/// a pool agent's answer is taken.
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
    let one_key = NewDevice {
        admin: claimant(4).sync,
        ..claimant(4)
    };
    assert_eq!(
        space.claim_with(nullifier(4), one_key, kit_of(4)),
        Err(HomesError::Malformed),
        "one key twice"
    );
    let mut kit_key_twice = kit_of(4);
    kit_key_twice.entries[0].signing = claimant(4).admin;
    assert_eq!(
        space.claim_with(nullifier(4), claimant(4), kit_key_twice),
        Err(HomesError::Malformed)
    );
    assert_eq!(
        space.claim_of(nullifier(4), claimant(4), kit_of(4), first),
        Err(HomesError::Taken),
        "an agent another claim took"
    );
    assert_eq!(
        space.claim_of(nullifier(4), claimant(4), kit_of(4), 9_999),
        Err(HomesError::Taken),
        "an agent never stocked"
    );
    assert_eq!(space.claim(4), Ok(first + 1));
    assert_eq!(
        space.claim_of(nullifier(5), claimant(5), kit_of(5), first + 2),
        Ok(first + 2),
        "any pooled agent, not only the lowest"
    );
    assert_eq!(
        space.operate::<u32, HomesError>(HOMES, "stock", vec![first, first + 2]),
        Ok(0),
        "stocked again, left as they are"
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
            method: space.method(HOMES, "assigned"),
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
            pooled: 0,
            claimed: 0,
            assigned: 3,
        }
    );
}

/// A claim `Personal` refuses as assigned already retires its agent, and
/// the claim takes the next; a claim never answered (the agent's role not
/// granted) is sent again when its nullifier claims again, and the
/// operator releases it, its agent retired; and an agent not assigned has
/// no nullifier recorded and no kit indexed.
#[test]
fn a_refused_or_unanswered_claim_is_released() {
    let mut space = Space::new(minutes());
    space.make(2);
    // Agent `FIRST` was assigned behind `Homes`' back.
    let claim = ((claimant(90), kit_of(90)), (minutes(), HOMES.0));
    space.relay(vec![Outgoing {
        to: AgentId(FIRST),
        body: Body::Call {
            instance: PERSONAL,
            method: space.world.method(AgentId(FIRST), PERSONAL, "claim"),
            arguments: claim.encode(),
            awaiting: None,
        },
    }]);
    assert_eq!(space.unanswered.len(), 1, "its answer is not Homes'");
    space.unanswered.clear();
    assert_eq!(space.claim(1), Ok(FIRST));
    assert_eq!(space.standing(FIRST), Some(Standing::Retired));
    assert_eq!(space.found(nullifier(1)), None);
    assert_eq!(space.claim(1), Ok(FIRST + 1), "the next agent");
    assert_eq!(space.standing(FIRST + 1), Some(Standing::Assigned));

    // An agent whose role `homes` was never granted answers nothing.
    let stray = FIRST + 2;
    space.add(stray, Principal::Client([0x99; 32]));
    space
        .operate::<u32, HomesError>(HOMES, "stock", vec![stray])
        .unwrap();
    assert_eq!(space.claim(2), Ok(stray));
    assert_eq!(space.standing(stray), Some(Standing::Claimed));
    assert_eq!(space.claim(2), Ok(stray), "sent again");
    assert_eq!(
        space.claim_with(nullifier(2), claimant(2), kit_of(3)),
        Err(HomesError::Claimed),
        "not the same claim"
    );
    assert_eq!(space.renew(nullifier(2), stray), Err(HomesError::Unknown));
    space
        .operate::<(), HomesError>(HOMES, "release", stray)
        .unwrap();
    assert_eq!(space.standing(stray), Some(Standing::Retired));
    assert_eq!(space.found(nullifier(2)), None);
    assert_eq!(space.kit_finds(&kit_of(2).entries[0].signing), None);
    assert_eq!(
        space.operate::<(), HomesError>(HOMES, "release", FIRST + 1),
        Err(HomesError::Unknown),
        "an answered claim stays"
    );
    assert_eq!(space.claim(2), Err(HomesError::PoolEmpty));
    assert_eq!(
        space.tally(),
        Counts {
            pooled: 0,
            claimed: 0,
            assigned: 1,
        }
    );
    // Messages from an agent not assigned are refused.
    for (sequence, (name, arguments)) in (1..).zip([
        ("record", nullifier(7).encode()),
        ("rekey", vec![[1u8; 32]].encode()),
        ("forget", nullifier(1).encode()),
    ]) {
        let run = space.step(Input::Message(Message {
            from: AgentId(stray),
            sequence,
            body: Body::Call {
                instance: HOMES,
                method: space.method(HOMES, name),
                arguments,
                awaiting: None,
            },
        }));
        assert_eq!(
            answer::<(), HomesError>(&run.outcome),
            Err(HomesError::Unknown),
            "{name}"
        );
    }
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
    let mut home = space.agent(agent);
    home.pass(1);
    assert!(home.overview().lapsed);
    assert_eq!(
        home.push(0, envelope(scope(1), 1, 2, 100)),
        Err(PersonalError::Lapsed)
    );
    let read: Vec<Envelope> = home.query(sync(1), "since", (scope(1), 0u64)).unwrap();
    assert_eq!(read.len(), 1, "reads are served");
    // A stolen phone is removed.
    home.operate(admin(0), "remove", 1u32).unwrap();
    home.pass(3 * MINUTE);
    let removal = home.commit_removing(0, vec![1]);
    assert_eq!(removal.set, vec![0]);
    space.flush(agent);
    assert_eq!(
        space.found(device(1).nullifier),
        None,
        "a removed device re-proves no more"
    );
    let mut home = space.agent(agent);
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
    assert_eq!(
        space.found(device(0).nullifier),
        None,
        "the restore removed it"
    );
    // The restored device re-proves: the grace ends.
    space.renew(device(5).nullifier, agent).unwrap();
    let mut home = space.agent(agent);
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
    // Opened again with the same terms, the period counts from none.
    space
        .operate::<(), CredentialError>(CREDENTIALS, "open", (8u8, 3u32, period))
        .unwrap();
    assert_eq!((space.opening().left, space.opening().cap), (3, 3));
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
/// a re-proof through `Homes` five sixths of a lease after its claim, in
/// the lease's last sixth, and the larger one after; a
/// re-proof made at once renews the lease and lifts nothing.
#[test]
fn the_quota_ramps_at_the_first_yearly_re_proof() {
    let policy = Policy {
        bytes_new: 1_000,
        bytes_full: 4_000,
        lease_ms: 60 * MINUTE,
        ..minutes()
    };
    let mut space = Space::new(policy);
    space.make(1);
    let agent = space
        .claim_with(device(0).nullifier, device(0), kit())
        .unwrap();
    let mut home = space.agent(agent);
    home.push(0, envelope(scope(1), 0, 1, 900)).unwrap();
    assert_eq!(
        home.push(0, envelope(scope(1), 0, 2, 900)),
        Err(PersonalError::Quota)
    );
    space.renew(device(0).nullifier, agent).unwrap();
    assert_eq!(
        space.agent(agent).push(0, envelope(scope(1), 0, 2, 900)),
        Err(PersonalError::Quota),
        "a re-proof at once"
    );
    space.pass(50 * MINUTE);
    space.renew(device(0).nullifier, agent).unwrap();
    let mut home = space.agent(agent);
    home.push(0, envelope(scope(1), 0, 2, 900)).unwrap();
    home.push(0, envelope(scope(1), 0, 3, 900)).unwrap();
}

/// An owner digest for `seed`, apart from every [`member`].
fn owner(seed: u32) -> Digest {
    tree::digest(&[seed, 1, 2, 3, 4, 5, 6, 7])
}

/// A person's limit.
const LIMIT: u8 = 2;
const REPLACEMENTS: u8 = vos_wire::credentials::REPLACEMENTS;

/// B13 at a home that is the user's own space: a person of limit 2 whose
/// device enrolls a new device, which claims a pooled agent under its own
/// nullifier, and revokes it, again and again, takes at most its
/// enrollments of the period's agents, its limit and its replacements;
/// the rest of the pool stays.
#[test]
fn device_churn_takes_no_more_agents_than_the_persons_enrollments() {
    let mut space = Space::new(minutes());
    space.make(20);
    let owned = |space: &mut Space, name: &str, arguments: Vec<u8>| -> Run {
        let call = space.world.agent(HOME).owned(
            CREDENTIALS,
            owner(1),
            CREDENTIALS,
            name,
            Raw(&arguments),
        );
        space.step(Input::Credentialed(Box::new(call)))
    };
    space
        .operate::<u32, CredentialError>(CREDENTIALS, "enroll", member(1))
        .unwrap();
    space
        .operate::<(), CredentialError>(CREDENTIALS, "register", (member(1), owner(1), LIMIT))
        .unwrap();
    space.claim(1).unwrap();
    let mut claimed = 1u32;
    for device in 2..20 {
        let enrolled = owned(
            &mut space,
            "enroll_device",
            (member(device), owner(device)).encode(),
        );
        if answer::<u32, CredentialError>(&enrolled.outcome).is_err() {
            break;
        }
        space.claim(device).unwrap();
        claimed += 1;
        let revoked = owned(&mut space, "revoke_device", member(device).encode());
        answer::<(), CredentialError>(&revoked.outcome).unwrap();
    }
    assert_eq!(claimed, u32::from(LIMIT + REPLACEMENTS));
    assert_eq!(space.tally().pooled, 20 - claimed);
}
