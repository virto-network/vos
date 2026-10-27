//! Credentialed calls at apply (`identity-and-authority.md` §5), in the
//! default agent: the refusals by the batch's time (an expired call, a
//! recorded binding digest, a stale root, an admitted `once` nullifier),
//! each writing nothing; the binding digest recorded whatever the method
//! does, and forgotten by the sweep; a `once` nullifier recorded only on
//! `Ok`; the guards (an origin admitted by its guard alone, an auth scope
//! the guard's); the credential actor's row and its install's refusals;
//! and the demo's ledger of named rows, paid by its owners' proofs.

use vos_testkit::programs::{actor, actor_elf, credentials, credentials_elf, method};
use vos_wire::abi::cap::Target;
use vos_wire::abi::{Failure, Refusal};
use vos_wire::batch::{Admin, CredentialedInput, Input, Request};
use vos_wire::credentials::{self, Digest, RootEntry};
use vos_wire::defaults::{BINDING_KEPT_MS, ROOT_MAX_AGE};
use vos_wire::ids::{InstanceId, Principal, Session};
use vos_wire::ingress::Grant;
use vos_wire::keys::{self, Due};
use vos_wire::result::{Outcome, Step};
use vos_wire::{Decode, Encode, SpaceId, WindowClock};

use crate::common::{AGENT, ALICE, BOB, Node, failed, ran, refused};

const CREDENTIALS: InstanceId = InstanceId(9);
const PURSES: InstanceId = InstanceId(2);
const POLL: InstanceId = InstanceId(3);
/// One role byte for both names: a principal holds one role, and `ALICE`
/// is the registrar and the operator.
const REGISTRAR: u8 = 1;
const OPERATOR: u8 = 1;
const SPACE: SpaceId = SpaceId([0x5a; 32]);
const START: u64 = 1_000_000;

/// The owner digest of a secret, as an owner proof states it.
fn owner(seed: u32) -> Digest {
    credentials::digest(&[seed, 1, 2, 3, 4, 5, 6, 7])
}

/// A node holding the credential actor (a member enrolled), the purses'
/// ledger and the poll, in `SPACE`; `ALICE` the registrar and the operator.
struct Agent {
    node: Node,
    credentials: Vec<u8>,
    purses: Vec<u8>,
    poll: Vec<u8>,
    sessions: u64,
    nonce: u8,
}

impl Agent {
    fn install(node: &mut Node, instance: InstanceId, elf: &[u8], roles: &[(&str, u8)]) -> Step {
        let derived = vos_pvm_compiler::derive(elf).expect("derives");
        node.add(&derived.actor);
        let install = Input::Admin(Admin::Install {
            instance,
            derivation: derived.derivation(elf),
            roles: roles
                .iter()
                .map(|(name, role)| (name.as_bytes().to_vec(), *role))
                .collect(),
            target: Target::Vos,
            space: SPACE,
            clock: WindowClock::DEFAULT,
        });
        node.batch(START, vec![install]).steps.remove(0)
    }

    fn new() -> Self {
        let mut node = Node::new();
        let poll_elf = std::fs::read(actor_elf("poll")).unwrap();
        let purses_elf = std::fs::read(actor_elf("purses")).unwrap();
        let credentials_elf = std::fs::read(credentials_elf()).unwrap();
        // An auth guard needs the agent's credential actor.
        let before = Self::install(&mut node, POLL, &poll_elf, &[]);
        assert_eq!(failed(&before), Failure::Credentials);
        let registrar = [("registrar", REGISTRAR)];
        assert!(matches!(
            ran(&Self::install(
                &mut node,
                CREDENTIALS,
                &credentials_elf,
                &registrar
            ))
            .outcome,
            Outcome::Done(_)
        ));
        assert_eq!(
            node.value::<InstanceId>(&keys::credentials()),
            Some(CREDENTIALS)
        );
        // One credential actor an agent.
        let second = Self::install(&mut node, InstanceId(10), &credentials_elf, &registrar);
        assert_eq!(failed(&second), Failure::Credentials);
        // Its instance replaced by a program that is not one.
        let operator = [("operator", OPERATOR)];
        let replaced = Self::install(&mut node, CREDENTIALS, &purses_elf, &operator);
        assert_eq!(failed(&replaced), Failure::Credentials);
        for (instance, elf) in [(POLL, &poll_elf), (PURSES, &purses_elf)] {
            let step = Self::install(&mut node, instance, elf, &operator);
            assert!(matches!(ran(&step).outcome, Outcome::Done(_)));
        }
        let roles = [(ALICE, REGISTRAR)].map(|(principal, role)| {
            Input::Admin(Admin::SetRole(Grant {
                principal,
                role: Some(role),
            }))
        });
        node.batch(START, roles.to_vec());
        let mut agent = Self {
            node,
            credentials: credentials(),
            purses: actor("purses"),
            poll: actor("poll"),
            sessions: 0,
            nonce: 0,
        };
        let found = agent.request(ALICE, CREDENTIALS, "found", [0x42u8; 32], START);
        let enroll = agent.request(ALICE, CREDENTIALS, "enroll", owner(99), START + 1);
        agent.done(START, vec![found]);
        agent.done(START + 1, vec![enroll]);
        agent
    }

    fn program(&self, instance: InstanceId) -> &[u8] {
        match instance {
            CREDENTIALS => &self.credentials,
            PURSES => &self.purses,
            _ => &self.poll,
        }
    }

    /// `caller`'s request of `name`, in a session of its own from `time`.
    fn request<A: Encode>(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        name: &str,
        arguments: A,
        time: u64,
    ) -> Input {
        self.sessions += 1;
        let Principal::Client(key) = caller else {
            panic!("a client's request")
        };
        let mut name_bytes = [0u8; 16];
        name_bytes[..8].copy_from_slice(&self.sessions.to_le_bytes());
        Input::Request(Request {
            session: Session {
                key,
                name: name_bytes,
                t0: time,
            },
            sequence: 1,
            caller,
            instance,
            method: method(self.program(instance), name),
            arguments: arguments.encode(),
        })
    }

    /// A credentialed call of `name` by `origin`, a fresh binding digest,
    /// good until `expires_ms`.
    fn call<A: Encode>(
        &mut self,
        origin: Principal,
        instance: InstanceId,
        name: &str,
        arguments: A,
        expires_ms: u64,
        root: Option<Digest>,
    ) -> CredentialedInput {
        self.nonce += 1;
        CredentialedInput {
            origin,
            instance,
            method: method(self.program(instance), name),
            arguments: arguments.encode(),
            binding: [self.nonce; 32],
            expires_ms,
            root,
        }
    }

    /// A batch at `time` whose every step ran to `Done`.
    fn done(&mut self, time: u64, inputs: Vec<Input>) {
        for step in self.node.batch(time, inputs).steps {
            assert!(matches!(ran(&step).outcome, Outcome::Done(_)), "{step:?}");
        }
    }

    /// The one step of `call` in a batch at `time`.
    fn step(&mut self, time: u64, call: &CredentialedInput) -> Step {
        let result = self
            .node
            .batch(time, vec![Input::Credentialed(Box::new(call.clone()))]);
        result.steps.into_iter().next().expect("one step")
    }

    fn query<A: Encode, R: Decode>(&self, instance: InstanceId, name: &str, arguments: A) -> R {
        let method = method(self.program(instance), name);
        match self.node.query(BOB, instance, method, arguments.encode()) {
            Outcome::Done(bytes) => R::decode_exact(&bytes).expect("decodes"),
            other => panic!("{name}: {other:?}"),
        }
    }

    fn root(&self) -> RootEntry {
        self.query(CREDENTIALS, "root", ())
    }

    fn balance(&self, name: &str) -> Option<u64> {
        self.query(PURSES, "balance", name.as_bytes().to_vec())
    }

    /// A row `name` invited for `owner` and claimed, holding `amount`.
    fn row(&mut self, time: u64, name: &str, owner: Digest, amount: u64) {
        let name = name.as_bytes().to_vec();
        let invite = self.request(
            ALICE,
            PURSES,
            "invite_row",
            (name.clone(), owner, time),
            time,
        );
        let claim = self.request(BOB, PURSES, "claim_row", (name.clone(), owner), time);
        let mint = self.request(ALICE, PURSES, "mint", (name.clone(), amount), time);
        self.done(time, vec![invite, claim, mint]);
    }

    fn scope(&self, name: &str) -> Digest {
        credentials::scope(&SPACE, AGENT, POLL, name.as_bytes())
    }

    fn anonymous(&self, scope: &str, nullifier: u8) -> Principal {
        Principal::Anonymous {
            scope: self.scope(scope),
            nullifier: [nullifier; 32],
        }
    }
}

/// The purses' errors and the poll's, by their codec index.
const NOT_INVITED: u8 = 3;
const EXPIRED: u8 = 4;
const NOT_OWNER: u8 = 5;
const FROZEN: u8 = 6;
const NO_ROW: u8 = 2;
const NO_CHOICE: u8 = 0;

/// The handler's failure detail: its error's one byte.
fn detail(step: &Step) -> u8 {
    match &ran(step).outcome {
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } if detail.len() == 1 => detail[0],
        other => panic!("not a handler's failure: {other:?}"),
    }
}

/// A step that ran and wrote nothing.
fn writes(step: &Step) -> usize {
    ran(step).writes.len()
}

/// Owner proofs pay from their rows: the live owner's alone, nothing from a
/// frozen row, a rekeyed row from its new owner; a transfer to a row that
/// does not exist refused, the payer's balance kept; a claim of a digest
/// the invitation does not name refused.
#[test]
fn owner_proofs_pay_from_the_rows_they_own() {
    let mut agent = Agent::new();
    let time = START + 10;
    let (alice, bob) = (owner(1), owner(2));
    agent.row(time, "alice", alice, 100);
    agent.row(time, "bob", bob, 0);

    let pay = |agent: &mut Agent, by: Digest, from: &str, to: &str, amount: u64| {
        let from = from.as_bytes().to_vec();
        let to = to.as_bytes().to_vec();
        let call = agent.call(
            Principal::Owner(by),
            PURSES,
            "transfer",
            (from, to, amount),
            time + 60_000,
            None,
        );
        agent.step(time, &call)
    };
    assert!(matches!(
        ran(&pay(&mut agent, alice, "alice", "bob", 30)).outcome,
        Outcome::Done(_)
    ));
    assert_eq!(
        (agent.balance("alice"), agent.balance("bob")),
        (Some(70), Some(30))
    );
    let stranger = pay(&mut agent, bob, "alice", "bob", 1);
    assert_eq!(detail(&stranger), NOT_OWNER);
    // Its binding digest recorded all the same, and its due row.
    assert_eq!(writes(&stranger), 2);

    let nowhere = pay(&mut agent, alice, "alice", "nobody", 5);
    assert_eq!(detail(&nowhere), NO_ROW);
    assert_eq!(agent.balance("alice"), Some(70), "the payer's balance kept");

    let freeze = agent.request(ALICE, PURSES, "freeze", b"alice".to_vec(), time);
    agent.done(time, vec![freeze]);
    let frozen = pay(&mut agent, alice, "alice", "bob", 1);
    assert_eq!(detail(&frozen), FROZEN);

    // A rekey moves the row to a new owner, its balance kept, the freeze
    // lifted: the old owner's proof fails, the new one's pays.
    let renewed = owner(5);
    let rekey = agent.request(ALICE, PURSES, "rekey", (b"alice".to_vec(), renewed), time);
    agent.done(time, vec![rekey]);
    let old = pay(&mut agent, alice, "alice", "bob", 1);
    assert_eq!(detail(&old), NOT_OWNER);
    assert!(matches!(
        ran(&pay(&mut agent, renewed, "alice", "bob", 20)).outcome,
        Outcome::Done(_)
    ));
    assert_eq!(
        (agent.balance("alice"), agent.balance("bob")),
        (Some(50), Some(50))
    );

    // The operator's methods are under its role.
    let mint = agent.request(BOB, PURSES, "mint", (b"bob".to_vec(), 1u64), time);
    let result = agent.node.batch(time, vec![mint]);
    assert_eq!(failed(&result.steps[0]), Failure::Forbidden);

    // The invitation names the digest: another's claim is refused.
    let name = b"carol".to_vec();
    let invite = agent.request(
        ALICE,
        PURSES,
        "invite_row",
        (name.clone(), owner(3), time + 5),
        time,
    );
    agent.done(time, vec![invite]);
    let wrong = agent.request(BOB, PURSES, "claim_row", (name.clone(), owner(4)), time);
    let late = agent.request(BOB, PURSES, "claim_row", (name.clone(), owner(3)), time + 6);
    let result = agent.node.batch(time, vec![wrong]);
    assert_eq!(detail(&result.steps[0]), NOT_INVITED);
    let result = agent.node.batch(time + 6, vec![late]);
    assert_eq!(detail(&result.steps[0]), EXPIRED);
}

/// An origin is admitted by its guard alone: an owner proof's to a method
/// with no guard, or an auth proof's to an owner guard, is `Forbidden`, as
/// is a client calling a guarded method; and no role is granted to one.
#[test]
fn an_origin_is_admitted_by_its_guard_alone() {
    let mut agent = Agent::new();
    let time = START + 10;
    agent.row(time, "alice", owner(1), 10);
    let unguarded = agent.call(
        Principal::Owner(owner(1)),
        PURSES,
        "mint",
        (b"alice".to_vec(), 1u64),
        time + 1_000,
        None,
    );
    let step = agent.step(time, &unguarded);
    assert_eq!(failed(&step), Failure::Forbidden);
    assert_eq!(writes(&step), 2, "its binding digest recorded");
    let anonymous = agent.anonymous("login", 1);
    let other = agent.call(
        anonymous,
        PURSES,
        "transfer",
        (b"alice".to_vec(), b"alice".to_vec(), 1u64),
        time + 1_000,
        None,
    );
    assert_eq!(failed(&agent.step(time, &other)), Failure::Forbidden);
    let client = agent.request(
        BOB,
        PURSES,
        "transfer",
        (b"alice".to_vec(), b"alice".to_vec(), 1u64),
        time,
    );
    let result = agent.node.batch(time, vec![client]);
    assert_eq!(failed(&result.steps[0]), Failure::Forbidden);
    let grant = Input::Admin(Admin::SetRole(Grant {
        principal: Principal::Owner(owner(1)),
        role: Some(OPERATOR),
    }));
    let result = agent.node.batch(time, vec![grant]);
    assert_eq!(failed(&result.steps[0]), Failure::Forbidden);
    assert_eq!(
        agent.node.get(&keys::member(&Principal::Owner(owner(1)))),
        None
    );
}

/// Apply refuses by the batch's time, writing nothing: an expired call, a
/// binding digest recorded (here or by another replica's copy), a root the
/// ring does not hold. A duplicate is `Replayed`, without the first
/// outcome. The sweep forgets a binding digest at its `expires_ms` plus a
/// minute.
#[test]
fn apply_refuses_by_the_batchs_time_and_records_each_binding() {
    let mut agent = Agent::new();
    let time = START + 10;
    agent.row(time, "alice", owner(1), 10);
    agent.row(time, "bob", owner(2), 0);
    let transfer = (b"alice".to_vec(), b"bob".to_vec(), 1u64);
    let expired = agent.call(
        Principal::Owner(owner(1)),
        PURSES,
        "transfer",
        transfer.clone(),
        time - 1,
        None,
    );
    let late = agent.step(time, &expired);
    assert_eq!(refused(&late), Refusal::CredentialExpired);
    assert!(
        !agent
            .node
            .state
            .contains_key(&keys::binding(&expired.binding))
    );
    let call = agent.call(
        Principal::Owner(owner(1)),
        PURSES,
        "transfer",
        transfer.clone(),
        time,
        None,
    );

    assert!(matches!(
        ran(&agent.step(time, &call)).outcome,
        Outcome::Done(_)
    ));
    assert_eq!(
        agent.node.value::<u64>(&keys::binding(&call.binding)),
        Some(time)
    );
    let due = keys::due(time + BINDING_KEPT_MS, Due::Binding(call.binding));
    assert!(agent.node.state.contains_key(&due));
    // Another replica's copy of the same call, in a later batch: refused,
    // nothing run.
    let again = agent.step(time, &call);
    assert_eq!(refused(&again), Refusal::Replayed);
    assert_eq!(agent.balance("alice"), Some(9));
    // Two copies in one batch: the second refused.
    let twice = agent.call(
        Principal::Owner(owner(1)),
        PURSES,
        "transfer",
        transfer,
        time,
        None,
    );
    let result = agent.node.batch(
        time,
        vec![
            Input::Credentialed(Box::new(twice.clone())),
            Input::Credentialed(Box::new(twice)),
        ],
    );
    assert!(matches!(ran(&result.steps[0]).outcome, Outcome::Done(_)));
    assert_eq!(refused(&result.steps[1]), Refusal::Replayed);
    assert_eq!(agent.balance("alice"), Some(8));

    // An auth call on a root the ring never held.
    let unknown = agent.call(
        agent.anonymous("login", 1),
        POLL,
        "login",
        (),
        time + 1_000,
        Some([3; 32]),
    );
    assert_eq!(refused(&agent.step(time, &unknown)), Refusal::StaleRoot);

    // The sweep at the binding's time forgets it, and its row.
    let forgotten = time + BINDING_KEPT_MS;
    let sweep = agent.node.sweep(forgotten);
    let result = agent.node.batch(forgotten, vec![sweep]);
    let Step::Swept { bindings, .. } = &result.steps[0] else {
        panic!("a sweep")
    };
    assert!(
        bindings.contains(&(forgotten, call.binding)),
        "{bindings:?}"
    );
    assert!(!agent.node.state.contains_key(&keys::binding(&call.binding)));
    assert!(!agent.node.state.contains_key(&due));
}

/// An auth call is admitted on the ring's newest root, and on a superseded
/// one for `ROOT_MAX_AGE` after it was superseded, by the batch's time: a
/// revoked member's proof on the root before its revocation is refused
/// once that has passed. An origin whose scope is not its guard's is
/// `Forbidden`.
#[test]
fn an_auth_root_is_fresh_by_the_batchs_time_and_a_scope_is_its_guards() {
    let mut agent = Agent::new();
    let before = agent.root();
    let revoked = START + 100;
    let revoke = agent.request(ALICE, CREDENTIALS, "revoke", owner(99), revoked);
    agent.done(revoked, vec![revoke]);
    let after = agent.root();
    assert_ne!(after.root, before.root);
    assert_eq!(after.since, revoked);
    let horizon = revoked + ROOT_MAX_AGE + 10_000;
    let login = |agent: &mut Agent, nullifier: u8, root: Digest, time: u64| {
        let origin = agent.anonymous("login", nullifier);
        let call = agent.call(origin, POLL, "login", (), time + 1_000, Some(root));
        agent.step(time, &call)
    };
    let within = login(&mut agent, 1, before.root, revoked + ROOT_MAX_AGE);
    assert!(
        matches!(ran(&within).outcome, Outcome::Done(_)),
        "{within:?}"
    );
    let past = login(&mut agent, 1, before.root, revoked + ROOT_MAX_AGE + 1);
    assert_eq!(refused(&past), Refusal::StaleRoot);
    let newest = login(&mut agent, 2, after.root, horizon);
    match &ran(&newest).outcome {
        Outcome::Done(bytes) => {
            assert_eq!(Option::<Digest>::decode_exact(bytes), Some(Some([2; 32])));
        }
        other => panic!("{other:?}"),
    }
    // A scope of another guard's name, at apply.
    let elsewhere = Principal::Anonymous {
        scope: agent.scope("vote"),
        nullifier: [3; 32],
    };
    let call = agent.call(
        elsewhere,
        POLL,
        "login",
        (),
        horizon + 1_000,
        Some(after.root),
    );
    let step = agent.step(horizon, &call);
    assert_eq!(failed(&step), Failure::Forbidden);
    assert_eq!(agent.query::<_, u64>(POLL, "logins", ()), 2);
}

/// A `once` guard admits a nullifier once in its scope, its row written
/// only when the handler returns `Ok`: a refused vote leaves it free (a
/// second proof of it admitted) while the first call's binding is
/// `Replayed`; a second admitted vote of it is `Once`; another scope's
/// guard admits it.
#[test]
fn a_once_guard_admits_a_nullifier_once_on_ok_alone() {
    let mut agent = Agent::new();
    let time = START + 10;
    let root = agent.root().root;
    let vote = |agent: &mut Agent, method: &str, scope: &str, choice: u8| {
        let origin = agent.anonymous(scope, 7);
        agent.call(origin, POLL, method, choice, time + 1_000, Some(root))
    };
    let once = keys::once(&agent.scope("vote"), &[7; 32]);
    let refused_vote = vote(&mut agent, "vote", "vote", 0);
    let step = agent.step(time, &refused_vote);
    assert_eq!(detail(&step), NO_CHOICE);
    assert!(!agent.node.state.contains_key(&once), "free again");
    assert_eq!(refused(&agent.step(time, &refused_vote)), Refusal::Replayed);

    let cast = vote(&mut agent, "vote", "vote", 4);
    assert!(matches!(
        ran(&agent.step(time, &cast)).outcome,
        Outcome::Done(_)
    ));
    assert_eq!(agent.node.value::<u64>(&once), Some(time));
    let again = vote(&mut agent, "vote", "vote", 4);
    let step = agent.step(time, &again);
    assert_eq!(refused(&step), Refusal::Once);
    assert!(
        !agent
            .node
            .state
            .contains_key(&keys::binding(&again.binding))
    );

    let next_round = vote(&mut agent, "vote_again", "vote/2", 4);
    assert!(matches!(
        ran(&agent.step(time, &next_round)).outcome,
        Outcome::Done(_)
    ));
    assert_eq!(agent.query::<_, u32>(POLL, "tally", 4u8), 2);
}
