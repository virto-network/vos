//! Proven calls at apply (`identity-and-authority.md` §5), in the default
//! agent: the refusals by the batch's time (an expired call, a recorded
//! binding digest, a stale root, an admitted `once` nullifier), each
//! writing nothing; the binding digest recorded whatever the method does,
//! and forgotten by the sweep; a `once` nullifier recorded only on `Ok`;
//! the guards (an origin admitted by its guard alone, an auth scope the
//! guard's, a kernel guard's handler taking the claim first); the
//! credential actor's row and its install's refusals; the ledger,
//! `Payments`, paid from by its owners' proofs; and the credential actor's
//! persons, whose devices enroll and revoke each other by their owner
//! proofs.

use vos_abi::abi::cap::Target;
use vos_abi::abi::{Failure, Refusal};
use vos_abi::credentials::Digest;
use vos_abi::ids::{InstanceId, Principal, Session};
use vos_abi::keys::{self, Due};
use vos_abi::result::{Outcome, Step};
use vos_abi::{Decode, Encode, SpaceId, WindowClock};
use vos_testkit::programs::{actor, actor_elf, method, program, program_elf};
use vos_wire::batch::{Admin, CredentialedInput, Input, Request};
use vos_wire::credentials::{self, AuthClaim, CredentialError, OwnerClaim, Ring, RootEntry};
use vos_wire::defaults::{self, BINDING_KEPT_MS, CREDENTIAL_HORIZON_MS, ROOT_GRACE_MS};
use vos_wire::ingress::Grant;
use vos_wire::payments::PaymentError;

use crate::common::{AGENT, ALICE, BOB, Node, failed, ran, refused};

const CREDENTIALS: InstanceId = InstanceId(9);
const PAYMENTS: InstanceId = InstanceId(2);
const POLL: InstanceId = InstanceId(3);
/// One role byte for both names: a principal holds one role, and `ALICE`
/// is the registrar and the operator.
const REGISTRAR: u8 = 1;
const OPERATOR: u8 = 1;
const SPACE: SpaceId = SpaceId([0x5a; 32]);
const START: u64 = 1_000_000;

/// The owner digest of a secret, as an owner proof states it.
fn owner(seed: u32) -> Digest {
    vos_abi::credentials::digest(&[seed, 1, 2, 3, 4, 5, 6, 7])
}

/// A node holding the credential actor (a member enrolled), the ledger
/// and the poll, in `SPACE`; `ALICE` the registrar and the operator.
struct Agent {
    node: Node,
    credentials: Vec<u8>,
    payments: Vec<u8>,
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
            derivation: derived.derivation(),
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
        Self::on(Node::new())
    }

    fn on(mut node: Node) -> Self {
        let poll_elf = std::fs::read(actor_elf("poll")).unwrap();
        let payments_elf = std::fs::read(program_elf("vos-payments")).unwrap();
        let credentials_elf = std::fs::read(program_elf("vos-credentials")).unwrap();
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
        let replaced = Self::install(&mut node, CREDENTIALS, &payments_elf, &operator);
        assert_eq!(failed(&replaced), Failure::Credentials);
        for (instance, elf) in [(POLL, &poll_elf), (PAYMENTS, &payments_elf)] {
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
            credentials: program("vos-credentials"),
            payments: program("vos-payments"),
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
            PAYMENTS => &self.payments,
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

    /// `caller`'s request of the ledger's `name` with encoded `arguments`.
    fn request_raw(
        &mut self,
        caller: Principal,
        name: &str,
        arguments: Vec<u8>,
        time: u64,
    ) -> Input {
        let mut request = self.request(caller, PAYMENTS, name, (), time);
        if let Input::Request(request) = &mut request {
            request.arguments = arguments;
        }
        request
    }

    /// A proven call of `name` by `origin`, a fresh binding digest, good
    /// until `expires_ms`: its claim the stock kernel's the origin is of,
    /// an auth claim's root `root` (zeros if none).
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
        let binding = [self.nonce; 32];
        let claim = match origin {
            Principal::Anonymous { scope, nullifier } => AuthClaim {
                map_root: root.unwrap_or([0; 32]),
                scope,
                nullifier,
                binding,
            }
            .encode(),
            Principal::Owner(owner) => OwnerClaim { owner, binding }.encode(),
            _ => binding.to_vec(),
        };
        let kernel = match origin {
            Principal::Owner(_) => "owner",
            _ => "auth",
        };
        let kernel = method(&self.credentials, kernel);
        CredentialedInput {
            origin,
            instance,
            method: method(self.program(instance), name),
            arguments: arguments.encode(),
            binding,
            expires_ms,
            claim,
            kernel,
            format: defaults::DEVICE_FORMATS[0].0,
            release: self.node.release(CREDENTIALS, kernel),
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
        self.query(PAYMENTS, "balance", name.as_bytes().to_vec())
    }

    /// An account `name` invited for `owner` and opened, minted `amount`.
    fn account(&mut self, time: u64, name: &str, owner: Digest, amount: u64) {
        let name = name.as_bytes().to_vec();
        let invite = self.request(ALICE, PAYMENTS, "invite", (name.clone(), owner, time), time);
        let open = self.request(BOB, PAYMENTS, "open", (name.clone(), owner), time);
        let mut inputs = vec![invite, open];
        if amount > 0 {
            inputs.push(self.request(ALICE, PAYMENTS, "mint", (name.clone(), amount), time));
        }
        self.done(time, inputs);
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

/// The poll's error, by its codec index.
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

/// The ledger's error a step failed with.
fn payment_error(step: &Step) -> PaymentError {
    match &ran(step).outcome {
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } => PaymentError::decode_exact(detail).expect("a payment error"),
        other => panic!("not a handler's failure: {other:?}"),
    }
}

/// A step that ran and wrote nothing.
fn writes(step: &Step) -> usize {
    ran(step).writes.len()
}

/// Owner proofs pay from the accounts their digests hold: nothing from a
/// digest that holds none or from a frozen account, a rekeyed account from
/// its new owner; a transfer to an account that does not exist refused,
/// the payer's balance kept; an opening for a digest the invitation does
/// not name, or past its expiry, refused.
#[test]
fn owner_proofs_pay_from_the_accounts_they_hold() {
    let mut agent = Agent::new();
    let time = START + 10;
    let (alice, bob) = (owner(1), owner(2));
    agent.account(time, "alice", alice, 100);
    agent.account(time, "bob", bob, 0);

    let pay = |agent: &mut Agent, by: Digest, to: &str, amount: u64| {
        let to = to.as_bytes().to_vec();
        let call = agent.call(
            Principal::Owner(by),
            PAYMENTS,
            "transfer",
            (to, amount),
            time + 60_000,
            None,
        );
        agent.step(time, &call)
    };
    assert!(matches!(
        ran(&pay(&mut agent, alice, "bob", 30)).outcome,
        Outcome::Done(_)
    ));
    assert_eq!(
        (agent.balance("alice"), agent.balance("bob")),
        (Some(70), Some(30))
    );
    let stranger = pay(&mut agent, owner(7), "bob", 1);
    assert_eq!(payment_error(&stranger), PaymentError::NotOwner);
    // Its binding digest recorded all the same, and its due row.
    assert_eq!(writes(&stranger), 2);
    let short = pay(&mut agent, bob, "alice", 31);
    assert_eq!(payment_error(&short), PaymentError::Insufficient);
    assert_eq!(
        agent.balance("bob"),
        Some(30),
        "an account never below zero"
    );

    let nowhere = pay(&mut agent, alice, "nobody", 5);
    assert_eq!(payment_error(&nowhere), PaymentError::NoAccount);
    assert_eq!(agent.balance("alice"), Some(70), "the payer's balance kept");

    let freeze = agent.request(ALICE, PAYMENTS, "freeze", b"alice".to_vec(), time);
    agent.done(time, vec![freeze]);
    let frozen = pay(&mut agent, alice, "bob", 1);
    assert_eq!(payment_error(&frozen), PaymentError::Frozen);

    // A rekey moves the account to a new owner, its balance kept, the
    // freeze lifted: the old owner's proof holds nothing, the new one's
    // pays.
    let renewed = owner(5);
    let rekey = agent.request(ALICE, PAYMENTS, "rekey", (b"alice".to_vec(), renewed), time);
    agent.done(time, vec![rekey]);
    let old = pay(&mut agent, alice, "bob", 1);
    assert_eq!(payment_error(&old), PaymentError::NotOwner);
    assert!(matches!(
        ran(&pay(&mut agent, renewed, "bob", 20)).outcome,
        Outcome::Done(_)
    ));
    assert_eq!(
        (agent.balance("alice"), agent.balance("bob")),
        (Some(50), Some(50))
    );

    // The operator's methods are under its role.
    let mint = agent.request(BOB, PAYMENTS, "mint", (b"bob".to_vec(), 1u64), time);
    let result = agent.node.batch(time, vec![mint]);
    assert_eq!(failed(&result.steps[0]), Failure::Forbidden);

    // The invitation names the digest: another's opening is refused.
    let name = b"carol".to_vec();
    let invite = agent.request(
        ALICE,
        PAYMENTS,
        "invite",
        (name.clone(), owner(3), time + 5),
        time,
    );
    agent.done(time, vec![invite]);
    let wrong = agent.request(BOB, PAYMENTS, "open", (name.clone(), owner(4)), time);
    let late = agent.request(BOB, PAYMENTS, "open", (name.clone(), owner(3)), time + 6);
    let result = agent.node.batch(time, vec![wrong]);
    assert_eq!(payment_error(&result.steps[0]), PaymentError::NotInvited);
    let result = agent.node.batch(time + 6, vec![late]);
    assert_eq!(payment_error(&result.steps[0]), PaymentError::Expired);
}

/// The ledger's own refusals: a name or an owner it does not take, a
/// second account for one digest, a rekey onto a digest that holds one, a
/// payment to oneself or of nothing, a mint past `u64::MAX`; a frozen
/// account still credited; a digest's own account read by it; and every
/// balance the issuance's mints, so the ledger conserves.
#[test]
fn the_ledger_refuses_what_its_rules_refuse_and_conserves() {
    let mut agent = Agent::new();
    let time = START + 10;
    let (alice, bob) = (owner(1), owner(2));
    agent.account(time, "alice", alice, 100);
    agent.account(time, "bob", bob, 5);
    let refusal = |agent: &mut Agent, caller, name: &str, arguments: Vec<u8>| {
        let request = agent.request_raw(caller, name, arguments, time);
        let result = agent.node.batch(time, vec![request]);
        payment_error(&result.steps[0])
    };
    let invite = |name: &[u8], owner: Digest| (name.to_vec(), owner, time + 5).encode();
    assert_eq!(
        refusal(&mut agent, ALICE, "invite", invite(b"", owner(3))),
        PaymentError::BadName
    );
    assert_eq!(
        refusal(&mut agent, ALICE, "invite", invite(b"a b", owner(3))),
        PaymentError::BadName
    );
    assert_eq!(
        refusal(&mut agent, ALICE, "invite", invite(b"carol", [0xff; 32])),
        PaymentError::BadOwner
    );
    assert_eq!(
        refusal(&mut agent, ALICE, "invite", invite(b"bob2", bob)),
        PaymentError::Exists
    );
    let rekey = |name: &[u8], owner: Digest| (name.to_vec(), owner).encode();
    assert_eq!(
        refusal(&mut agent, ALICE, "rekey", rekey(b"alice", bob)),
        PaymentError::Exists
    );
    assert_eq!(
        refusal(&mut agent, ALICE, "rekey", rekey(b"alice", [0xff; 32])),
        PaymentError::BadOwner
    );
    let mint = (b"bob".to_vec(), u64::MAX).encode();
    assert_eq!(
        refusal(&mut agent, ALICE, "mint", mint),
        PaymentError::Overflow
    );
    let mint = (b"bob".to_vec(), 0u64).encode();
    assert_eq!(
        refusal(&mut agent, ALICE, "mint", mint),
        PaymentError::NoAmount
    );

    let pay = |agent: &mut Agent, to: &str, amount: u64| {
        let call = agent.call(
            Principal::Owner(alice),
            PAYMENTS,
            "transfer",
            (to.as_bytes().to_vec(), amount),
            time + 60_000,
            None,
        );
        agent.step(time, &call)
    };
    assert_eq!(
        payment_error(&pay(&mut agent, "alice", 1)),
        PaymentError::SamePayee
    );
    assert_eq!(
        payment_error(&pay(&mut agent, "bob", 0)),
        PaymentError::NoAmount
    );

    // A frozen account takes credits; its debits wait for a rekey.
    let freeze = agent.request(ALICE, PAYMENTS, "freeze", b"bob".to_vec(), time);
    agent.done(time, vec![freeze]);
    assert!(matches!(
        ran(&pay(&mut agent, "bob", 10)).outcome,
        Outcome::Done(_)
    ));
    let held: Option<(Vec<u8>, (Digest, u64, bool))> = agent.query(PAYMENTS, "held", bob);
    assert_eq!(held, Some((b"bob".to_vec(), (bob, 15, true))));
    let account: Option<(Digest, u64, bool)> = agent.query(PAYMENTS, "account", b"alice".to_vec());
    assert_eq!(account, Some((alice, 90, false)));
    let none: Option<(Vec<u8>, (Digest, u64, bool))> = agent.query(PAYMENTS, "held", owner(9));
    assert_eq!(none, None);
    // What was minted, 105, is what the accounts hold.
    assert_eq!(
        agent.balance("alice").unwrap() + agent.balance("bob").unwrap(),
        105
    );
}

/// An origin is admitted by its guard alone: an owner proof's to a method
/// with no guard, or an auth proof's to an owner guard, is `Forbidden`, as
/// is a client calling a guarded method; and no role is granted to one.
#[test]
fn an_origin_is_admitted_by_its_guard_alone() {
    let mut agent = Agent::new();
    let time = START + 10;
    agent.account(time, "alice", owner(1), 10);
    let unguarded = agent.call(
        Principal::Owner(owner(1)),
        PAYMENTS,
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
        PAYMENTS,
        "transfer",
        (b"alice".to_vec(), 1u64),
        time + 1_000,
        None,
    );
    assert_eq!(failed(&agent.step(time, &other)), Failure::Forbidden);
    let client = agent.request(BOB, PAYMENTS, "transfer", (b"alice".to_vec(), 1u64), time);
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
    agent.account(time, "alice", owner(1), 10);
    agent.account(time, "bob", owner(2), 0);
    let transfer = (b"bob".to_vec(), 1u64);
    let expired = agent.call(
        Principal::Owner(owner(1)),
        PAYMENTS,
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
        PAYMENTS,
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
        PAYMENTS,
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
/// one for `ROOT_GRACE_MS` after it was superseded, judged at the latest
/// time an ingress could have admitted it, its expiry less
/// `CREDENTIAL_HORIZON_MS`, or the batch's time if earlier: a revoked
/// member's proof on the root before its revocation is refused once that
/// has passed, well inside the ring's 64 roots. A call of the shortest
/// expiry, which an ingress could have admitted `CREDENTIAL_HORIZON_MS`
/// before its batch, runs at the window's end by that time, so a replica
/// never refuses at apply what ingress admitted. An origin whose scope is
/// not its guard's is `Forbidden`.
#[test]
fn an_auth_root_is_fresh_for_the_grace_by_the_calls_time_and_a_scope_is_its_guards() {
    let mut agent = Agent::new();
    let before = agent.root();
    let revoked = START + 100;
    let revoke = agent.request(ALICE, CREDENTIALS, "revoke", owner(99), revoked);
    agent.done(revoked, vec![revoke]);
    let after = agent.root();
    assert_ne!(after.root, before.root);
    assert_eq!(after.since, revoked);
    let long_after = revoked + 6 * 60_000;
    let login = |agent: &mut Agent, nullifier: u8, root: Digest, (time, expires): (u64, u64)| {
        let origin = agent.anonymous("login", nullifier);
        let call = agent.call(origin, POLL, "login", (), expires, Some(root));
        agent.step(time, &call)
    };
    // Expiring a horizon after the batch: judged at the batch's time.
    let a_horizon_ahead = |time| (time, time + CREDENTIAL_HORIZON_MS);
    let within = login(
        &mut agent,
        1,
        before.root,
        a_horizon_ahead(revoked + ROOT_GRACE_MS),
    );
    assert!(
        matches!(ran(&within).outcome, Outcome::Done(_)),
        "{within:?}"
    );
    let past = login(
        &mut agent,
        1,
        before.root,
        a_horizon_ahead(revoked + ROOT_GRACE_MS + 1),
    );
    assert_eq!(refused(&past), Refusal::StaleRoot);
    // Expiring at the batch's time: an ingress a horizon before admitted it.
    let edge = revoked + ROOT_GRACE_MS + CREDENTIAL_HORIZON_MS;
    let late = login(&mut agent, 3, before.root, (edge, edge));
    assert!(matches!(ran(&late).outcome, Outcome::Done(_)), "{late:?}");
    let beyond = login(&mut agent, 4, before.root, (edge + 1, edge + 1));
    assert_eq!(refused(&beyond), Refusal::StaleRoot);
    let later = login(
        &mut agent,
        1,
        before.root,
        a_horizon_ahead(revoked + 5 * 60_000),
    );
    assert_eq!(
        refused(&later),
        Refusal::StaleRoot,
        "inside the ring, past the grace"
    );
    let newest = login(&mut agent, 2, after.root, a_horizon_ahead(long_after));
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
        long_after + 1_000,
        Some(after.root),
    );
    let step = agent.step(long_after, &call);
    assert_eq!(failed(&step), Failure::Forbidden);
    assert_eq!(agent.query::<_, u64>(POLL, "logins", ()), 3);
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

/// The agent's own work on a credentialed auth call, its scope computed
/// again and the credential actor's ring read beside the handler's run,
/// leaves a fifth of a step's reserve spare, on a VOS host and on a JAM
/// host, whose Poseidon2 compression is software, with the ring full: the
/// ring is paid for once a refine, by the batch's first auth call.
#[test]
fn a_credentialed_calls_own_work_is_within_a_steps_reserve() {
    for (host, node) in [("VOS", Node::new()), ("JAM", Node::jam(true))] {
        let mut agent = Agent::on(node);
        // A root a batch, each at its own time, until the ring is full: one
        // session's requests in sequence.
        let Input::Request(first) = agent.request(ALICE, CREDENTIALS, "enroll", (), START + 2)
        else {
            unreachable!()
        };
        for at in 0..credentials::RING as u32 {
            let enroll = Request {
                sequence: u64::from(at) + 1,
                arguments: owner(1_000 + at).encode(),
                ..first.clone()
            };
            agent.done(START + 2 + u64::from(at), vec![Input::Request(enroll)]);
        }
        let ring: Ring = agent
            .node
            .value(&credentials::ring_key(CREDENTIALS))
            .expect("the ring");
        assert_eq!(ring.0.len(), credentials::RING);
        let root = agent.root().root;
        let calls: Vec<Input> = (1..=21u8)
            .map(|nullifier| {
                let origin = agent.anonymous("login", nullifier);
                let call = agent.call(origin, POLL, "login", (), u64::MAX, Some(root));
                Input::Credentialed(Box::new(call))
            })
            .collect();
        let empty = agent.node.agent_gas(vec![]);
        let one = agent.node.agent_gas(calls[..1].to_vec()) - empty;
        let each = (agent.node.agent_gas(calls) - empty - one) / 20;
        println!(
            "{host}: a credentialed call costs the agent {each}, the first, paying the full \
             ring, {one}"
        );
        assert!(
            each <= (vos_wire::defaults::STEP_RESERVE * 4 / 5) as i64,
            "{host}: {each}"
        );
    }
}

/// A kernel guard's handler takes the claim before the call's arguments,
/// its caller the kernel's program, and checks the claim itself: the
/// `device` actor's `login` records each nullifier and refuses it the
/// second time, the binding digest recorded all the same. Its agent needs
/// no credential actor, and an auth origin is no kernel's.
#[test]
fn a_kernel_guards_handler_takes_the_claim_first() {
    let mut node = Node::new();
    let device = InstanceId(4);
    let elf = std::fs::read(actor_elf("device")).unwrap();
    let step = Agent::install(&mut node, device, &elf, &[]);
    assert!(matches!(ran(&step).outcome, Outcome::Done(_)), "{step:?}");
    let login = method(&actor("device"), "login");
    let claim = |nullifier: u8, binding: u8| {
        [
            &[0u8][..],
            &[1; 32],
            &[2; 32],
            &[nullifier; 32],
            &[binding; 32],
        ]
        .concat()
    };
    let auth = method(&actor("device"), "auth");
    let release = node.release(device, auth);
    let call = |origin, claim: Vec<u8>, binding| CredentialedInput {
        origin,
        instance: device,
        method: login,
        arguments: Vec::new(),
        binding,
        expires_ms: START + 1_000,
        claim,
        kernel: auth,
        format: defaults::DEVICE_FORMATS[0].0,
        release,
    };
    let program = [0x70; 32];
    let kernel = Principal::Kernel { program };
    let step = |node: &mut Node, call: CredentialedInput| {
        node.batch(START, vec![Input::Credentialed(Box::new(call))])
            .steps
            .remove(0)
    };
    let first = step(&mut node, call(kernel, claim(7, 1), [1; 32]));
    match &ran(&first).outcome {
        Outcome::Done(reply) => assert_eq!(
            <([u8; 32], [u8; 32])>::decode_exact(reply),
            Some(([7; 32], program)),
            "the claim's nullifier, and the program its caller names"
        ),
        other => panic!("the first sign-in: {other:?}"),
    }
    let seen = step(&mut node, call(kernel, claim(7, 2), [2; 32]));
    assert_eq!(detail(&seen), 0, "the handler refuses a nullifier it saw");
    assert_eq!(writes(&seen), 2, "the binding digest recorded all the same");
    let other = step(&mut node, call(kernel, claim(8, 3), [3; 32]));
    assert!(matches!(ran(&other).outcome, Outcome::Done(_)));
    let anonymous = Principal::Anonymous {
        scope: [2; 32],
        nullifier: [9; 32],
    };
    let wrong = step(&mut node, call(anonymous, claim(9, 4), [4; 32]));
    assert_eq!(failed(&wrong), Failure::Forbidden, "an auth origin");
    let short = step(&mut node, call(kernel, claim(9, 5)[..64].to_vec(), [5; 32]));
    assert!(
        matches!(ran(&short).outcome, Outcome::Failed { .. }),
        "a claim the handler cannot decode"
    );
    let long = [claim(9, 6), vec![0]].concat();
    let long = step(&mut node, call(kernel, long, [6; 32]));
    assert!(
        matches!(ran(&long).outcome, Outcome::Failed { .. }),
        "a claim with bytes past its kernel's public arguments"
    );
    let mut elsewhere = call(kernel, claim(9, 7), [7; 32]);
    elsewhere.kernel = login;
    let elsewhere = step(&mut node, elsewhere);
    assert_eq!(
        failed(&elsewhere),
        Failure::Forbidden,
        "a proof of another kernel than the guard names"
    );
}

/// A batch runs at most `BATCH_CREDENTIALED` credentialed calls: the first
/// past them cuts it short, and runs in the next batch.
#[test]
fn a_batch_runs_at_most_its_credentialed_calls() {
    let mut agent = Agent::new();
    let time = START + 10;
    agent.account(time, "alice", owner(1), 100);
    agent.account(time, "bob", owner(2), 0);
    let calls: Vec<CredentialedInput> = (0..=defaults::BATCH_CREDENTIALED)
        .map(|_| {
            let transfer = (b"bob".to_vec(), 1u64);
            agent.call(
                Principal::Owner(owner(1)),
                PAYMENTS,
                "transfer",
                transfer,
                time,
                None,
            )
        })
        .collect();
    let inputs = calls
        .iter()
        .map(|call| Input::Credentialed(Box::new(call.clone())))
        .collect();
    let result = agent.node.batch(time, inputs);
    assert_eq!(result.steps.len(), defaults::BATCH_CREDENTIALED);
    for step in &result.steps {
        assert!(matches!(ran(step).outcome, Outcome::Done(_)), "{step:?}");
    }
    let last = agent.step(time, calls.last().unwrap());
    assert!(matches!(ran(&last).outcome, Outcome::Done(_)), "{last:?}");
    assert_eq!(
        agent.balance("bob"),
        Some(defaults::BATCH_CREDENTIALED as u64 + 1)
    );
}

/// A device's member digest, apart from every [`owner`].
fn member(seed: u32) -> Digest {
    vos_abi::credentials::digest(&[seed, 11, 12, 13, 14, 15, 16, 17])
}

/// A person's devices enroll and revoke each other by their owner proofs
/// (`light-node.md` §3.8): the registrar registers the first, which
/// enrolls a second, whose owner digest acts for the person once its own
/// proof confirms it; the person's limit, then a raised one; the second
/// revokes the first, whose proof then holds no person, and the first is
/// enrolled again; a registered invitation claimed and revoked; a
/// registrar's revocation drops a device from its person, and the last
/// device's the person. Refused: an owner digest no person holds or not
/// yet confirmed, a member enrolled or invited, a member or owner digest a
/// person holds or awaits, another person's device, an expired
/// invitation's registration, the registrar's writes by anyone else, and
/// the device methods by a client. An owner digest another person named
/// first gives way to the registrar's.
#[test]
fn a_persons_devices_enroll_and_revoke_each_other_by_their_owner_proofs() {
    let mut agent = Agent::new();
    let time = START + 10;
    let by = |agent: &mut Agent, by: u32, name: &str, arguments: Vec<u8>| {
        let mut call = agent.call(
            Principal::Owner(owner(by)),
            CREDENTIALS,
            name,
            (),
            time + 60_000,
            None,
        );
        call.arguments = arguments;
        agent.step(time, &call)
    };
    let enroll = |agent: &mut Agent, caller: u32, device: u32| {
        by(
            agent,
            caller,
            "enroll_device",
            (member(device), owner(device)).encode(),
        )
    };
    let confirm = |agent: &mut Agent, device: u32| {
        by(agent, device, "confirm_device", member(device).encode())
    };
    let revoke = |agent: &mut Agent, caller: u32, device: u32| {
        by(agent, caller, "revoke_device", member(device).encode())
    };
    let register = |agent: &mut Agent, device: u32, owner_of: u32, limit: u8| {
        let input = agent.request(
            ALICE,
            CREDENTIALS,
            "register",
            (member(device), owner(owner_of), limit),
            time,
        );
        agent.node.batch(time, vec![input]).steps.remove(0)
    };
    let ok = |step: Step| assert!(matches!(ran(&step).outcome, Outcome::Done(_)), "{step:?}");
    let error = |error: CredentialError| error as u8;
    let enrolled = |agent: &Agent, device: u32| {
        agent
            .query::<_, Option<credentials::Path>>(CREDENTIALS, "path", member(device))
            .is_some()
    };

    let first = agent.request(ALICE, CREDENTIALS, "enroll", member(1), time);
    agent.done(time, vec![first]);
    ok(register(&mut agent, 1, 1, 2));
    let count: u64 = agent.query(CREDENTIALS, "count", ());

    ok(enroll(&mut agent, 1, 2));
    assert!(enrolled(&agent, 2), "its leaf at once");
    assert_eq!(
        detail(&enroll(&mut agent, 2, 3)),
        error(CredentialError::NoPerson)
    );
    ok(confirm(&mut agent, 2));
    assert_eq!(
        detail(&confirm(&mut agent, 2)),
        error(CredentialError::NoPerson)
    );
    assert_eq!(
        detail(&enroll(&mut agent, 2, 3)),
        error(CredentialError::Limit)
    );
    let raise = agent.request(ALICE, CREDENTIALS, "limit", (member(2), 3u8), time);
    agent.done(time, vec![raise]);
    ok(enroll(&mut agent, 2, 3));
    let after: u64 = agent.query(CREDENTIALS, "count", ());
    assert_eq!(after, count + 2);

    // What the person may not enroll, and who may not.
    assert_eq!(
        detail(&enroll(&mut agent, 7, 4)),
        error(CredentialError::NoPerson)
    );
    let raise = agent.request(ALICE, CREDENTIALS, "limit", (member(1), 8u8), time);
    agent.done(time, vec![raise]);
    // `Agent::on` enrolled `owner(99)` as its first member.
    let registrars = owner(99);
    let taken = by(
        &mut agent,
        1,
        "enroll_device",
        (registrars, owner(5)).encode(),
    );
    assert_eq!(detail(&taken), error(CredentialError::Enrolled));
    let held = by(
        &mut agent,
        1,
        "enroll_device",
        (member(4), owner(2)).encode(),
    );
    assert_eq!(detail(&held), error(CredentialError::Held));
    let awaited = by(
        &mut agent,
        1,
        "enroll_device",
        (member(4), owner(3)).encode(),
    );
    assert_eq!(detail(&awaited), error(CredentialError::Held));
    let invite = agent.request(
        ALICE,
        CREDENTIALS,
        "invite",
        (member(5), time + 1_000),
        time,
    );
    let lapsed = agent.request(ALICE, CREDENTIALS, "invite", (member(6), time - 1), time);
    agent.done(time, vec![invite, lapsed]);
    assert_eq!(
        detail(&enroll(&mut agent, 1, 5)),
        error(CredentialError::Invited)
    );
    assert_eq!(
        detail(&register(&mut agent, 5, 2, 1)),
        error(CredentialError::Held)
    );
    assert_eq!(
        detail(&register(&mut agent, 5, 5, 0)),
        error(CredentialError::Terms)
    );
    assert_eq!(
        detail(&register(&mut agent, 6, 6, 1)),
        error(CredentialError::Expired)
    );
    let stranger = agent.request(
        BOB,
        CREDENTIALS,
        "register",
        (member(5), owner(5), 1u8),
        time,
    );
    let client = agent.request(
        BOB,
        CREDENTIALS,
        "enroll_device",
        (member(6), owner(6)),
        time,
    );
    let steps = agent.node.batch(time, vec![stranger, client]).steps;
    assert_eq!(failed(&steps[0]), Failure::Forbidden);
    assert_eq!(failed(&steps[1]), Failure::Forbidden);

    // A registered invitation, claimed, then revoked by its own proof.
    ok(register(&mut agent, 5, 5, 1));
    let claim = agent.request(BOB, CREDENTIALS, "claim", member(5), time);
    agent.done(time, vec![claim]);
    assert!(enrolled(&agent, 5));
    ok(revoke(&mut agent, 5, 5));
    assert!(!enrolled(&agent, 5));
    assert_eq!(
        detail(&revoke(&mut agent, 5, 5)),
        error(CredentialError::NoPerson)
    );

    // Another person: its device is not this one's to revoke, nor this
    // one's its; and an owner digest it names that the registrar then
    // registers is the registrar's.
    let other = agent.request(ALICE, CREDENTIALS, "enroll", member(8), time);
    agent.done(time, vec![other]);
    ok(register(&mut agent, 8, 8, 2));
    assert_eq!(
        detail(&revoke(&mut agent, 2, 8)),
        error(CredentialError::NotYours)
    );
    assert_eq!(
        detail(&revoke(&mut agent, 8, 2)),
        error(CredentialError::NotYours)
    );
    assert!(enrolled(&agent, 8) && enrolled(&agent, 2));
    let squat = by(
        &mut agent,
        8,
        "enroll_device",
        (member(20), owner(21)).encode(),
    );
    ok(squat);
    let victim = agent.request(ALICE, CREDENTIALS, "enroll", member(21), time);
    agent.done(time, vec![victim]);
    ok(register(&mut agent, 21, 21, 1));
    assert_eq!(
        detail(&confirm(&mut agent, 21)),
        error(CredentialError::NoPerson)
    );
    ok(revoke(&mut agent, 8, 20));
    assert_eq!(
        detail(&revoke(&mut agent, 21, 8)),
        error(CredentialError::NotYours)
    );
    ok(revoke(&mut agent, 21, 21));

    // The second retires the first, whose proof holds no person after;
    // the first enrolled again, its slot reused.
    let slot = agent
        .query::<_, Option<credentials::Path>>(CREDENTIALS, "path", member(1))
        .unwrap()
        .slot;
    ok(revoke(&mut agent, 2, 1));
    assert!(!enrolled(&agent, 1));
    assert_eq!(
        detail(&enroll(&mut agent, 1, 4)),
        error(CredentialError::NoPerson)
    );
    ok(enroll(&mut agent, 2, 1));
    let again = agent.query::<_, Option<credentials::Path>>(CREDENTIALS, "path", member(1));
    assert_eq!(again.map(|path| path.slot), Some(slot));
    ok(confirm(&mut agent, 1));
    ok(revoke(&mut agent, 1, 1));
    // A limit below the devices held: they stay, and none is enrolled.
    let lower = agent.request(ALICE, CREDENTIALS, "limit", (member(2), 1u8), time);
    agent.done(time, vec![lower]);
    assert_eq!(
        detail(&enroll(&mut agent, 2, 4)),
        error(CredentialError::Limit)
    );
    assert!(enrolled(&agent, 2) && enrolled(&agent, 3));
    // The registrar's revocation drops the third, unconfirmed, from the
    // person; the second revokes itself, the person's last device, and
    // the person goes with it.
    let third = agent.request(ALICE, CREDENTIALS, "revoke", member(3), time);
    agent.done(time, vec![third]);
    assert_eq!(
        detail(&confirm(&mut agent, 3)),
        error(CredentialError::NoPerson)
    );
    ok(revoke(&mut agent, 2, 2));
    assert_eq!(
        detail(&enroll(&mut agent, 2, 4)),
        error(CredentialError::NoPerson)
    );
    let gone = agent.request(ALICE, CREDENTIALS, "limit", (member(2), 2u8), time);
    let steps = agent.node.batch(time, vec![gone]).steps;
    assert_eq!(detail(&steps[0]), error(CredentialError::NoPerson));
    let after: u64 = agent.query(CREDENTIALS, "count", ());
    assert_eq!(
        after, count,
        "the other person's device in the first's place"
    );
}

/// A person's limit.
const LIMIT: u8 = 2;
const REPLACEMENTS: u8 = credentials::REPLACEMENTS;
const ENROLLMENTS: u8 = CredentialError::Enrollments as u8;

/// Device churn is held to the person's enrollments of the period
/// (`identity-and-authority.md` §5): a person of limit 2 enrolls a device,
/// which votes under a `once` guard with a nullifier of its own, and
/// revokes it, again and again; its devices of the period, the first among
/// them, are at most its limit and its replacements, so the guard admits
/// it at most that many times, and the next enrollment is refused
/// `Enrollments`. The registrar's reset gives the person a fresh count from
/// the devices it holds; so does the next period.
#[test]
fn a_persons_device_churn_is_held_to_its_enrollments_of_the_period() {
    let mut agent = Agent::new();
    let start = START + 10;
    let owned = |agent: &mut Agent, time: u64, by: u32, name: &str, arguments: Vec<u8>| {
        let mut call = agent.call(
            Principal::Owner(owner(by)),
            CREDENTIALS,
            name,
            (),
            time + 60_000,
            None,
        );
        call.arguments = arguments;
        agent.step(time, &call)
    };
    let enroll = |agent: &mut Agent, time: u64, device: u32| {
        let arguments = (member(device), owner(device)).encode();
        owned(agent, time, 1, "enroll_device", arguments)
    };
    let revoke = |agent: &mut Agent, time: u64, device: u32| {
        let step = owned(agent, time, 1, "revoke_device", member(device).encode());
        assert!(matches!(ran(&step).outcome, Outcome::Done(_)), "{step:?}");
    };
    // The device's vote, its nullifier its own.
    let vote = |agent: &mut Agent, time: u64, device: u32| {
        let root = agent.root().root;
        let origin = Principal::Anonymous {
            scope: agent.scope("vote"),
            nullifier: [device as u8; 32],
        };
        let call = agent.call(origin, POLL, "vote", 4u8, time + 60_000, Some(root));
        matches!(ran(&agent.step(time, &call)).outcome, Outcome::Done(_))
    };
    let first = agent.request(ALICE, CREDENTIALS, "enroll", member(1), start);
    let register = agent.request(
        ALICE,
        CREDENTIALS,
        "register",
        (member(1), owner(1), LIMIT),
        start,
    );
    agent.done(start, vec![first, register]);
    assert!(vote(&mut agent, start, 1));

    // Churn: enroll, vote, revoke, until the person's enrollments run out.
    let mut admitted = 1;
    let mut device = 1;
    let refusal = loop {
        device += 1;
        let step = enroll(&mut agent, start, device);
        if !matches!(ran(&step).outcome, Outcome::Done(_)) {
            break detail(&step);
        }
        assert!(vote(&mut agent, start, device), "a new nullifier");
        admitted += 1;
        revoke(&mut agent, start, device);
        assert!(device < 40, "churn without end: {admitted} admissions");
    };
    assert_eq!(refusal, ENROLLMENTS);
    assert_eq!(admitted, LIMIT + REPLACEMENTS);
    assert_eq!(
        agent.query::<_, u32>(POLL, "tally", 4u8),
        u32::from(admitted)
    );

    // The registrar's reset: the devices held, the first alone, counted.
    let reset = agent.request(ALICE, CREDENTIALS, "reset", member(1), start);
    agent.done(start, vec![reset]);
    for _ in 1..LIMIT + REPLACEMENTS {
        device += 1;
        let step = enroll(&mut agent, start, device);
        assert!(matches!(ran(&step).outcome, Outcome::Done(_)), "{step:?}");
        revoke(&mut agent, start, device);
    }
    let step = enroll(&mut agent, start, device + 1);
    assert_eq!(detail(&step), ENROLLMENTS);

    // The next period counts from the devices held then.
    let next = start + credentials::ENROLLMENT_PERIOD_MS;
    for _ in 1..LIMIT + REPLACEMENTS {
        device += 1;
        let step = enroll(&mut agent, next, device);
        assert!(matches!(ran(&step).outcome, Outcome::Done(_)), "{step:?}");
        revoke(&mut agent, next, device);
    }
    let step = enroll(&mut agent, next, device + 1);
    assert_eq!(detail(&step), ENROLLMENTS);
    // The reset is the registrar's alone.
    let stranger = agent.request(BOB, CREDENTIALS, "reset", member(1), next);
    let steps = agent.node.batch(next, vec![stranger]).steps;
    assert_eq!(failed(&steps[0]), Failure::Forbidden);
}

/// A person's owner call of `name` at `time`, by device `by`'s owner
/// digest.
fn owned(agent: &mut Agent, time: u64, by: u32, name: &str, arguments: Vec<u8>) -> Step {
    let mut call = agent.call(
        Principal::Owner(owner(by)),
        CREDENTIALS,
        name,
        (),
        time + 60_000,
        None,
    );
    call.arguments = arguments;
    agent.step(time, &call)
}

/// Whether `step` ran to `Done`.
fn done(step: &Step) -> bool {
    matches!(ran(step).outcome, Outcome::Done(_))
}

/// The registrar expels a person whole (`identity-and-authority.md` §6):
/// a device revoked alone leaves the person under its limit, so another
/// of its devices enrolls a replacement at once; `revoke_person` revokes
/// every device of the person in one write, and after it no owner digest
/// of the person enrolls and no leaf of it is in the tree. It is the
/// registrar's alone.
#[test]
fn the_registrar_expels_a_person_whole() {
    let mut agent = Agent::new();
    let time = START + 10;
    let enrolled = |agent: &Agent, device: u32| {
        agent
            .query::<_, Option<credentials::Path>>(CREDENTIALS, "path", member(device))
            .is_some()
    };
    let first = agent.request(ALICE, CREDENTIALS, "enroll", member(1), time);
    let register = agent.request(
        ALICE,
        CREDENTIALS,
        "register",
        (member(1), owner(1), 3u8),
        time,
    );
    agent.done(time, vec![first, register]);
    for device in [2, 3] {
        let arguments = (member(device), owner(device)).encode();
        assert!(done(&owned(
            &mut agent,
            time,
            1,
            "enroll_device",
            arguments
        )));
        assert!(done(&owned(
            &mut agent,
            time,
            device,
            "confirm_device",
            member(device).encode()
        )));
    }
    let count: u64 = agent.query(CREDENTIALS, "count", ());

    // One device revoked: another replaces it at once.
    let one = agent.request(ALICE, CREDENTIALS, "revoke", member(1), time);
    agent.done(time, vec![one]);
    let arguments = (member(4), owner(4)).encode();
    assert!(done(&owned(
        &mut agent,
        time,
        2,
        "enroll_device",
        arguments
    )));
    assert!(enrolled(&agent, 4));

    // The person expelled whole, by any device's member digest.
    let stranger = agent.request(BOB, CREDENTIALS, "revoke_person", member(3), time);
    let steps = agent.node.batch(time, vec![stranger]).steps;
    assert_eq!(failed(&steps[0]), Failure::Forbidden);
    let changed: u64 = agent
        .query::<_, credentials::Feed>(CREDENTIALS, "feed", 0u64)
        .length;
    let expel = agent.request(ALICE, CREDENTIALS, "revoke_person", member(3), time);
    agent.done(time, vec![expel]);
    let feed: credentials::Feed = agent.query(CREDENTIALS, "feed", 0u64);
    assert_eq!(feed.length, changed + 1, "one write");
    for device in 1..=4 {
        assert!(!enrolled(&agent, device), "device {device}'s leaf");
        let arguments = (member(10 + device), owner(10 + device)).encode();
        let step = owned(&mut agent, time, device, "enroll_device", arguments);
        assert_eq!(detail(&step), CredentialError::NoPerson as u8);
    }
    let after: u64 = agent.query(CREDENTIALS, "count", ());
    assert_eq!(after, count - 3);
    let again = agent.request(ALICE, CREDENTIALS, "revoke_person", member(3), time);
    let steps = agent.node.batch(time, vec![again]).steps;
    assert_eq!(detail(&steps[0]), CredentialError::NoPerson as u8);
}

/// An owner digest another person named awaits its confirmation for a
/// day at most (`identity-and-authority.md` §6): within it, the digest's
/// own person's enrollment is refused `Held`; past it, that enrollment
/// takes the digest, its confirmation joins it to its own person, and the
/// naming person's revocation of its device leaves it there. A device
/// confirms beside its own member digest, so an enrollment that took its
/// late digest for another member joins it to no person.
#[test]
fn an_owner_digest_another_person_named_is_held_a_day_at_most() {
    let mut agent = Agent::new();
    let time = START + 10;
    for (device, limit) in [(1, 2u8), (40, 2u8)] {
        let enroll = agent.request(ALICE, CREDENTIALS, "enroll", member(device), time);
        let register = agent.request(
            ALICE,
            CREDENTIALS,
            "register",
            (member(device), owner(device), limit),
            time,
        );
        agent.done(time, vec![enroll, register]);
    }
    // Person 1 names person 40's new device's owner digest, read from a
    // ledger's log, for a device of its own.
    let squat = (member(30), owner(31)).encode();
    assert!(done(&owned(&mut agent, time, 1, "enroll_device", squat)));
    let own = (member(31), owner(31)).encode();
    let within = owned(&mut agent, time + 1_000, 40, "enroll_device", own.clone());
    assert_eq!(detail(&within), CredentialError::Held as u8);
    let later = time + credentials::CONFIRM_MS + 1;
    assert!(done(&owned(&mut agent, later, 40, "enroll_device", own)));
    assert!(done(&owned(
        &mut agent,
        later,
        31,
        "confirm_device",
        member(31).encode()
    )));
    assert!(done(&owned(
        &mut agent,
        later,
        1,
        "revoke_device",
        member(30).encode()
    )));
    // The digest acts for person 40: it revokes person 40's first device.
    assert!(done(&owned(
        &mut agent,
        later,
        31,
        "revoke_device",
        member(40).encode()
    )));
    let refused = owned(&mut agent, later, 31, "revoke_device", member(1).encode());
    assert_eq!(detail(&refused), CredentialError::NotYours as u8);

    // The reverse: person 31's enrollment of a device not yet confirmed
    // past its day, its digest then named by person 1 for a device of its
    // own; the device's late confirmation names its own member digest,
    // which person 1 does not hold, so it joins no person.
    let mine = (member(50), owner(51)).encode();
    assert!(done(&owned(&mut agent, later, 31, "enroll_device", mine)));
    let after = later + credentials::CONFIRM_MS + 1;
    let theirs = (member(52), owner(51)).encode();
    assert!(done(&owned(&mut agent, after, 1, "enroll_device", theirs)));
    let confirm = owned(&mut agent, after, 51, "confirm_device", member(50).encode());
    assert_eq!(detail(&confirm), CredentialError::NoPerson as u8);
    let acting = owned(&mut agent, after, 51, "revoke_device", member(52).encode());
    assert_eq!(detail(&acting), CredentialError::NoPerson as u8);
}

/// Apply holds every proven call to its kernel's window, whatever the node
/// that verified it admits: a proof of a release the credential actor's
/// window does not hold is refused `Release`, writing nothing, and one of
/// the release it holds runs.
#[test]
fn apply_refuses_a_release_the_kernels_window_does_not_hold() {
    let mut agent = Agent::new();
    let time = START + 10;
    let root = agent.root().root;
    let origin = agent.anonymous("login", 1);
    let mut call = agent.call(origin, POLL, "login", (), time + 60_000, Some(root));
    let current = call.release;
    call.release.kernel = vos_abi::ids::ProgramHash([0x5e; 32]);
    let step = agent.step(time, &call);
    assert_eq!(refused(&step), Refusal::Release);
    assert!(!agent.node.state.contains_key(&keys::binding(&call.binding)));
    call.release = current;
    assert!(done(&agent.step(time, &call)));
}

/// Apply holds every proven call to the release's device formats and the
/// agent's log, whatever the node that verified it admits: a proof of a
/// format the release does not admit is refused `Format`, writing
/// nothing; a date in the log retires a format from that batch time, so a
/// 47 proof is refused too. Retiring a format the release does not admit
/// fails `Unknown`, and its newest, 47, `Forbidden`: no proven call would
/// run until a release with a newer one.
#[test]
fn apply_refuses_a_device_format_the_release_or_the_log_retired() {
    let mut agent = Agent::new();
    let time = START + 10;
    let root = agent.root().root;
    let login = |agent: &mut Agent, format: u32, nullifier: u8| {
        let origin = agent.anonymous("login", nullifier);
        let mut call = agent.call(origin, POLL, "login", (), time + 60_000, Some(root));
        call.format = format;
        call
    };
    for format in [48, 46, 44] {
        let call = login(&mut agent, format, 1);
        let step = agent.step(time, &call);
        assert_eq!(refused(&step), Refusal::Format, "format {format}");
        assert!(!agent.node.state.contains_key(&keys::binding(&call.binding)));
    }
    let call = login(&mut agent, 47, 2);
    assert!(done(&agent.step(time, &call)));

    let retire = |agent: &mut Agent, format: u32, at_ms: u64| {
        let input = Input::Admin(Admin::RetireFormat { format, at_ms });
        agent.node.batch(time, vec![input]).steps.remove(0)
    };
    assert_eq!(failed(&retire(&mut agent, 44, time)), Failure::Unknown);
    assert_eq!(
        failed(&retire(&mut agent, 47, time + 5)),
        Failure::Forbidden
    );
    assert!(!agent.node.state.contains_key(&keys::format_retired(47)));
    // The row a release with a newer format lets the log write for 47.
    agent.node.state.insert(
        keys::format_retired(47),
        vos_abi::records::stored(&(time + 5).encode()),
    );
    let call = login(&mut agent, 47, 3);
    assert!(done(&agent.step(time + 4, &call)));
    let call = login(&mut agent, 47, 4);
    assert_eq!(refused(&agent.step(time + 5, &call)), Refusal::Format);
}
