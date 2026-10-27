//! Credentialed calls at the node's ingress (`identity-and-authority.md`
//! §5), on three nodes of a founded space, with proofs made as a device
//! makes them: each refusal in its check order; a proof replayed, and a
//! `once` nullifier raced past ingress at another replica, each refused at
//! apply; a root a replica has not applied, one replaced at its own batch
//! time and one pushed out of the ring, each `RootUnknown` and admitted
//! after a path refetch; a revoked member's root refused once
//! `ROOT_MAX_AGE` has passed by batch time; owner proofs paying from their
//! rows; no log entry holding a proof; and a verified call holding no
//! large body's place while it waits to apply.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_checker::Nodes;
use vos_checker::calls::installed;
use vos_checker::programs::{actor, actor_elf, credentials, credentials_elf, method};
use vos_node::client::{self, Client, Target};
use vos_pvm_final_verifier::credential as verifier;
use vos_pvm_recair::credential::{AuthPublic, AuthWitness, OwnerPublic, Statement, prove};
use vos_pvm_recair::masked::MaskRng;
use vos_wire::abi::Refusal;
use vos_wire::credentials::{self as tree, Bound, Digest, Path, RootEntry, Tag, Words};
use vos_wire::defaults::ROOT_MAX_AGE;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::ingress::{CredentialPublic, CredentialRefusal, Credentialed, Rejection, Response};
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, SpaceId, WindowClock};

use crate::harness::{Cluster, NODES};

/// The hub's seed: odd, so clients reach the nodes over the API's sockets.
const SEED: u64 = 11;
const CREDENTIALS: InstanceId = InstanceId(9);
const PURSES: InstanceId = InstanceId(2);
const POLL: InstanceId = InstanceId(3);
/// The registrar's and the operator's role byte: one key holds both.
const ROLE: u8 = 1;
const OPERATOR: [u8; 32] = [21; 32];

fn compress(left: &Words, right: &Words) -> Words {
    tree::compress(left, right)
}

/// A member's device secret, and the digests it gives.
#[derive(Clone, Copy)]
struct Secret(Words);

impl Secret {
    fn new(seed: u32) -> Self {
        Self(core::array::from_fn(|i| seed * 1_000 + i as u32 + 1))
    }

    fn member(&self) -> Digest {
        tree::digest(&compress(&Tag::Member.block(), &self.0))
    }

    fn owner(&self) -> Digest {
        tree::digest(&compress(&Tag::Owner.block(), &self.0))
    }

    fn nullifier(&self, scope: &Digest) -> Digest {
        let key = compress(&Tag::Nf.block(), &self.0);
        tree::digest(&compress(&key, &tree::words(scope).unwrap()))
    }
}

fn words(digest: &Digest) -> Words {
    tree::words(digest).expect("a digest's words")
}

/// The founded space's agent: the credential actor, the poll and the
/// purses' ledger installed, the operator's key their registrar and
/// operator, the actor founded.
struct Founded {
    cluster: Cluster,
    agent: AgentId,
    space: SpaceId,
    operator: Mutex<Client>,
    credentials: Vec<u8>,
    poll: Vec<u8>,
    purses: Vec<u8>,
    nonce: AtomicU64,
}

impl Founded {
    fn new() -> Self {
        let cluster = Cluster::founded(SEED, Some(WindowClock::DEFAULT));
        let agent = cluster
            .node(1)
            .unwrap()
            .create_replicated((1..=NODES).collect())
            .unwrap();
        let elf = |path: std::path::PathBuf| std::fs::read(path).unwrap();
        let installs = [
            (CREDENTIALS, elf(credentials_elf()), "registrar"),
            (POLL, elf(actor_elf("poll")), "operator"),
            (PURSES, elf(actor_elf("purses")), "operator"),
        ];
        for (instance, elf, role) in installs {
            install(&cluster, agent, instance, &elf, role);
        }
        let key = SigningKey::from_bytes(&OPERATOR);
        let principal = Principal::Client(key.verifying_key().to_bytes());
        installed(smol::block_on(cluster.leading(agent).set_role(
            agent,
            principal,
            Some(ROLE),
        )));
        // At the leader: a follower answers a call once it has applied it,
        // and a test holds one back.
        let leader = cluster.leader(agent).unwrap();
        let operator = Client::new(cluster.target(leader), key).with_routes(cluster.routes());
        let space = cluster.space.id();
        assert_ne!(space, SpaceId::NONE);
        let founded = Self {
            cluster,
            agent,
            space,
            operator: Mutex::new(operator),
            credentials: credentials(),
            poll: actor("poll"),
            purses: actor("purses"),
            nonce: AtomicU64::new(0),
        };
        founded.write(CREDENTIALS, "found", [0x42u8; 32]);
        founded
    }

    fn program(&self, instance: InstanceId) -> &[u8] {
        match instance {
            CREDENTIALS => &self.credentials,
            POLL => &self.poll,
            _ => &self.purses,
        }
    }

    fn method(&self, instance: InstanceId, name: &str) -> MethodId {
        method(self.program(instance), name)
    }

    /// The operator's call of `name`, run to `Done`.
    #[track_caller]
    fn write<A: Encode>(&self, instance: InstanceId, name: &str, arguments: A) {
        let answer = self
            .operator
            .lock()
            .unwrap()
            .call(
                self.agent,
                instance,
                self.method(instance, name),
                &arguments.encode(),
            )
            .unwrap();
        assert!(
            matches!(
                answer,
                Response::Ran {
                    outcome: Outcome::Done(_),
                    ..
                }
            ),
            "{name}: {answer:?}"
        );
    }

    fn read<A: Encode, R: Decode>(&self, instance: InstanceId, name: &str, arguments: A) -> R {
        let not_after = client::time(self.cluster.target(1)).unwrap() + 60_000;
        let method = self.method(instance, name);
        let answer = self
            .operator
            .lock()
            .unwrap()
            .query(self.agent, instance, method, &arguments.encode(), not_after)
            .unwrap();
        match answer {
            Response::Ran {
                outcome: Outcome::Done(bytes),
                ..
            } => R::decode_exact(&bytes).expect("decodes"),
            other => panic!("{name}: {other:?}"),
        }
    }

    /// `secret`'s member's path, as the actor serves it now.
    fn path(&self, secret: &Secret) -> Path {
        let path: Option<Path> = self.read(CREDENTIALS, "path", secret.member());
        path.expect("an enrolled member's path")
    }

    fn root(&self) -> RootEntry {
        self.read(CREDENTIALS, "root", ())
    }

    fn scope(&self, instance: InstanceId, name: &str) -> Digest {
        tree::scope(&self.space, self.agent, instance, name.as_bytes())
    }

    /// An auth call of the poll's `name`, in the guard `scope`'s scope, by
    /// `secret` under `path`, good for a minute by node `at`'s clock: its
    /// proof made.
    fn auth<A: Encode>(
        &self,
        at: NodeNumber,
        secret: &Secret,
        path: &Path,
        (name, scope): (&str, &str),
        arguments: A,
    ) -> Credentialed {
        let scope = self.scope(POLL, scope);
        let mut call = self.unproved(at, POLL, name, arguments);
        call.public = CredentialPublic::Auth {
            map_root: path.root,
            scope,
            nullifier: secret.nullifier(&scope),
            binding: self.binding(&call, 0),
        };
        let CredentialPublic::Auth {
            map_root,
            nullifier,
            binding,
            ..
        } = call.public
        else {
            unreachable!()
        };
        let statement = Statement::Auth(
            AuthPublic {
                map_root: words(&map_root),
                scope: words(&scope),
                nullifier: words(&nullifier),
                binding: words(&binding),
            },
            AuthWitness {
                secret: secret.0,
                slot: path.slot,
                siblings: path.siblings.0.map(|sibling| words(&sibling)),
            },
        );
        call.proof = proof(&statement);
        call
    }

    /// An owner call of the purses' `transfer`, by `secret`.
    fn pay(
        &self,
        at: NodeNumber,
        secret: &Secret,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Credentialed {
        let arguments = (from.as_bytes().to_vec(), to.as_bytes().to_vec(), amount);
        let mut call = self.unproved(at, PURSES, "transfer", arguments);
        call.public = CredentialPublic::Owner {
            owner: secret.owner(),
            binding: self.binding(&call, 1),
        };
        let statement = Statement::Owner(
            OwnerPublic {
                owner: words(&secret.owner()),
                binding: words(call.public.binding()),
            },
            secret.0,
        );
        call.proof = proof(&statement);
        call
    }

    /// A call of `instance`'s `name` with a fresh nonce, good for a minute
    /// by node `at`'s clock, its public statement and proof empty.
    fn unproved<A: Encode>(
        &self,
        at: NodeNumber,
        instance: InstanceId,
        name: &str,
        arguments: A,
    ) -> Credentialed {
        let mut nonce = [0u8; 16];
        let count = self.nonce.fetch_add(1, Ordering::SeqCst) + 1;
        nonce[..8].copy_from_slice(&count.to_le_bytes());
        Credentialed {
            instance,
            method: self.method(instance, name),
            arguments: arguments.encode(),
            nonce,
            expires_ms: client::time(self.cluster.target(at)).unwrap() + 60_000,
            format: verifier::FORMAT,
            public: CredentialPublic::Owner {
                owner: [0; 32],
                binding: [0; 32],
            },
            proof: Vec::new(),
        }
    }

    /// The public `binding` of `call` as a statement of `kind` states it.
    fn binding(&self, call: &Credentialed, kind: u8) -> Digest {
        let program = verifier::program(match kind {
            0 => verifier::CredentialKind::Auth,
            _ => verifier::CredentialKind::Owner,
        });
        let b = Bound {
            space: &self.space,
            agent: self.agent,
            instance: call.instance,
            method: call.method,
            program,
            kind,
            arguments: &call.arguments,
            nonce: &call.nonce,
            expires_ms: call.expires_ms,
        }
        .digest();
        tree::binding(&b)
    }

    fn send(&self, at: NodeNumber, call: &Credentialed) -> Response {
        client::credentialed(self.cluster.target(at), self.agent, call).unwrap()
    }

    /// Move every node's clock on by `ms`, and apply a batch after it.
    fn later(&self, ms: i64) {
        self.cluster.offset.fetch_add(ms, Ordering::SeqCst);
        self.write(PURSES, "invite_row", (b"tick".to_vec(), [1u8; 32], 0u64));
    }

    fn follower(&self) -> NodeNumber {
        let leader = self.cluster.leader(self.agent).unwrap();
        leader % NODES + 1
    }
}

/// Install `elf` at `instance` of `agent`, its schema's role `role` mapped
/// to [`ROLE`], at the leader.
fn install(cluster: &Cluster, agent: AgentId, instance: InstanceId, elf: &[u8], role: &str) {
    let roles = vec![(role.as_bytes().to_vec(), ROLE)];
    vos_checker::spaces::wait_in_process("an install", || {
        match smol::block_on(
            cluster
                .leading(agent)
                .install(agent, instance, elf, roles.clone()),
        ) {
            Err(vos_node::CallError::NotLeader(_) | vos_node::CallError::TimedOut) => false,
            answer => {
                installed(answer);
                true
            }
        }
    });
}

fn proof(statement: &Statement) -> Vec<u8> {
    let (proof, _) = prove(statement, MaskRng::default()).expect("proves");
    verifier::encode(&proof).expect("encodes")
}

#[track_caller]
fn refused(answer: Response) -> CredentialRefusal {
    match answer {
        Response::Rejected(Rejection::Credential(code)) => code,
        other => panic!("not a credential refusal: {other:?}"),
    }
}

#[track_caller]
fn done(answer: &Response) -> &[u8] {
    match answer {
        Response::Ran {
            outcome: Outcome::Done(bytes),
            ..
        } => bytes,
        other => panic!("not done: {other:?}"),
    }
}

/// Each check refuses in its order: a request failing every check from
/// one on is refused by that one's code, then mended one check at a time.
/// The frame's size and its decode first, then the agent and its space,
/// the format (a 1.4 MiB device proof's within the frame, refused until a
/// device kernel is admitted), the size (a 600 KiB credential proof), the
/// expiry, the method's guard, the kind, the scope, the binding, a
/// recorded binding digest, an admitted nullifier, an unknown root, and
/// the proof. A verified call runs, as its origin.
#[test]
fn every_ingress_refusal_comes_in_its_check_order() {
    let founded = Founded::new();
    let secret = Secret::new(1);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let at = founded.follower();
    let target = founded.cluster.target(at).clone();
    let agent = founded.agent;

    // Over HTTP: the size refused from the head, the body unread (the
    // API's frames are refused from their header, `ingress::api`).
    let http = Target::loopback(&format!("http://{}", founded.cluster.ingress(at))).unwrap();
    let path = format!("/agents/{}/credentialed", agent.0);
    let largest = vec![0; vos_api::CREDENTIALED_HTTP];
    let (status, _) = client::post(&http, &path, &largest).unwrap();
    assert_eq!(status, 400, "the largest body is read");
    let mut stream = std::net::TcpStream::connect(founded.cluster.ingress(at)).unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n",
        vos_api::CREDENTIALED_HTTP + 1
    );
    std::io::Write::write_all(&mut stream, head.as_bytes()).unwrap();
    let mut answer = [0u8; 12];
    std::io::Read::read_exact(&mut stream, &mut answer).unwrap();
    assert_eq!(
        &answer, b"HTTP/1.1 413",
        "past the frame's size, from the head"
    );
    let (status, body) = client::post(&target, &path, &[0xff]).unwrap();
    assert_eq!(status, 400);
    assert_eq!(
        Response::decode_exact(&body),
        Some(Response::Rejected(Rejection::Malformed))
    );
    let fresh = founded.unproved(at, POLL, "vote", 1u8);
    let nowhere = client::credentialed(&target, AgentId(0x00ff_ffff), &fresh).unwrap();
    assert_eq!(nowhere, Response::NoAgent);
    let bare = founded
        .cluster
        .node(1)
        .unwrap()
        .create_replicated((1..=NODES).collect())
        .unwrap();
    let unfounded = client::credentialed(&target, bare, &fresh).unwrap();
    assert_eq!(refused(unfounded), CredentialRefusal::NoSpace);

    // Every check from the format on fails; each mended in turn.
    let real = founded.auth(at, &secret, &founded.path(&secret), ("vote", "vote"), 3u8);
    let CredentialPublic::Auth {
        scope,
        nullifier,
        binding,
        ..
    } = real.public
    else {
        unreachable!()
    };
    let mut call = Credentialed {
        method: founded.method(POLL, "tally"),
        format: 43,
        proof: vec![7; 1_400 << 10],
        expires_ms: real.expires_ms + 600_000,
        public: CredentialPublic::Owner {
            owner: [1; 32],
            binding: [2; 32],
        },
        ..real.clone()
    };
    let check = |call: &Credentialed, code: CredentialRefusal, what: &str| match (
        refused(founded.send(at, call)),
        code,
    ) {
        (CredentialRefusal::Expiry { .. }, CredentialRefusal::Expiry { .. }) => {}
        (answer, code) => assert_eq!(answer, code, "{what}"),
    };
    check(&call, CredentialRefusal::Format, "a device proof's format");
    call.format = verifier::FORMAT;
    check(
        &call,
        CredentialRefusal::Size,
        "1.4 MiB under the credential format",
    );
    call.proof = vec![7; 600 << 10];
    check(&call, CredentialRefusal::Size, "600 KiB");
    call.proof = vec![7; 64];
    check(
        &call,
        CredentialRefusal::Expiry { now: 0 },
        "ten minutes ahead",
    );
    call.expires_ms = real.expires_ms;
    check(&call, CredentialRefusal::Method, "a method with no guard");
    call.method = real.method;
    check(&call, CredentialRefusal::Kind, "an owner statement");
    call.public = CredentialPublic::Auth {
        map_root: [3; 32],
        scope: [4; 32],
        nullifier,
        binding: [5; 32],
    };
    check(&call, CredentialRefusal::Scope, "another scope");
    call.public = CredentialPublic::Auth {
        map_root: [3; 32],
        scope,
        nullifier,
        binding: [5; 32],
    };
    check(&call, CredentialRefusal::Binding, "another binding");
    call.public = CredentialPublic::Auth {
        map_root: [3; 32],
        scope,
        nullifier,
        binding,
    };
    check(
        &call,
        CredentialRefusal::RootUnknown,
        "a root the ring never held",
    );
    call.public = real.public;
    check(&call, CredentialRefusal::Proof, "no proof");
    // The proof of one call, sent with another's arguments.
    call.proof = real.proof.clone();
    let other = Credentialed {
        arguments: 4u8.encode(),
        ..call.clone()
    };
    check(
        &other,
        CredentialRefusal::Binding,
        "another call's arguments",
    );
    // The proof mended: the call runs, as the member's pseudonym.
    assert_eq!(call, real);
    assert_eq!(u32::decode_exact(done(&founded.send(at, &call))), Some(1));
    // Sent again: replayed, its outcome not repeated.
    assert_eq!(
        refused(founded.send(at, &call)),
        CredentialRefusal::Replayed
    );
    // Another call of the nullifier, on a root unknown: `Once` comes first.
    let mut again = founded.auth(at, &secret, &founded.path(&secret), ("vote", "vote"), 2u8);
    let CredentialPublic::Auth { map_root, .. } = &mut again.public else {
        unreachable!()
    };
    *map_root = [3; 32];
    assert_eq!(refused(founded.send(at, &again)), CredentialRefusal::Once);
    // A proof with a wrong PoW: refused as any proof that fails.
    let mut wrong = founded.auth(at, &secret, &founded.path(&secret), ("login", "login"), ());
    let mut decoded = verifier::decode(&wrong.proof).unwrap();
    decoded.stark_proof.0.proof_of_work ^= 1;
    wrong.proof = verifier::encode(&decoded).unwrap();
    assert_eq!(refused(founded.send(at, &wrong)), CredentialRefusal::Proof);
    // No log entry holds a proof's bytes.
    let node = founded.cluster.node(at).unwrap();
    let applied = node.applied(agent).unwrap();
    let entries = node
        .store()
        .log_range(agent, 1, applied, usize::MAX)
        .unwrap();
    let needle = &real.proof[real.proof.len() / 2..real.proof.len() / 2 + 32];
    for (index, entry) in entries {
        assert!(
            !entry
                .body
                .windows(needle.len())
                .any(|window| window == needle),
            "entry {index} holds the proof"
        );
    }
}

/// A proof sent to two replicas at once passes both ingresses, the leader
/// applying neither before: it runs once, the other copy refused
/// `Replayed` at apply. Likewise two proofs of one `once` nullifier: one
/// runs, the other refused `Once` at apply; another scope's guard admits
/// the nullifier.
#[test]
fn a_replay_and_a_once_race_past_ingress_are_refused_at_apply() {
    let founded = Founded::new();
    let secret = Secret::new(2);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let leader = founded.cluster.leader(founded.agent).unwrap();
    let follower = founded.follower();
    let path = founded.path(&secret);
    let login = founded.auth(leader, &secret, &path, ("login", "login"), ());
    let votes =
        [3u8, 4].map(|choice| founded.auth(leader, &secret, &path, ("vote", "vote"), choice));
    let races = [
        (
            (&login, &login),
            Refusal::Replayed,
            CredentialRefusal::Replayed,
        ),
        (
            (&votes[0], &votes[1]),
            Refusal::Once,
            CredentialRefusal::Once,
        ),
    ];
    for ((one, other), at_apply, at_ingress) in races {
        let gate = &founded.cluster.slot(leader).trip.refines;
        let reached = gate.reached();
        let closed = gate.close();
        let founded = &founded;
        let answers = std::thread::scope(|scope| {
            let a = scope.spawn(move || founded.send(leader, one));
            vos_checker::wait_until("the first held at refine", Duration::from_secs(30), || {
                gate.reached() > reached
            });
            let b = scope.spawn(move || founded.send(follower, other));
            // Through the follower's ingress and queued at the leader.
            std::thread::sleep(Duration::from_millis(500));
            drop(closed);
            [a.join().unwrap(), b.join().unwrap()]
        });
        let mut answers = answers;
        answers.sort_by_key(|answer| !matches!(answer, Response::Ran { .. }));
        done(&answers[0]);
        match &answers[1] {
            Response::Refused(refusal) if *refusal == at_apply => {}
            // The copy reached the follower's ingress once it had applied
            // the first.
            Response::Rejected(Rejection::Credential(refusal)) if *refusal == at_ingress => {}
            other => panic!("the second copy: {other:?}"),
        }
    }
    let tally: u32 = founded.read(POLL, "tally", 3u8);
    let other: u32 = founded.read(POLL, "tally", 4u8);
    assert_eq!(tally + other, 1, "one vote of the nullifier");
    let next = founded.auth(follower, &secret, &path, ("vote_again", "vote/2"), 4u8);
    done(&founded.send(follower, &next));
}

/// A credentialed call's body takes a place among the node's large bodies
/// only until its proof is verified: with the leader's refines held, a call
/// sent to the leader and one sent to a follower and forwarded each give
/// their places back while they wait to apply, and both then run.
#[test]
fn a_verified_call_holds_no_large_place_while_it_waits_to_apply() {
    let founded = Founded::new();
    let secret = Secret::new(10);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let leader = founded.cluster.leader(founded.agent).unwrap();
    let follower = founded.follower();
    let path = founded.path(&secret);
    let [here, forwarded] =
        [leader, follower].map(|at| founded.auth(at, &secret, &path, ("login", "login"), ()));
    let gate = &founded.cluster.slot(leader).trip.refines;
    let reached = gate.reached();
    let closed = gate.close();
    let founded = &founded;
    let free = |at: NodeNumber| {
        let node = founded.cluster.node(at).unwrap();
        node.credentialed_places_free() == vos_http::CREDENTIALED_LARGE
    };
    let verified = |at: NodeNumber| {
        let node = founded.cluster.node(at).unwrap();
        node.stats()
            .stages
            .iter()
            .find(|stage| stage.name == "credential")
            .map_or(0, |stage| stage.counts.iter().sum::<u64>())
    };
    let answers = std::thread::scope(|scope| {
        let a = scope.spawn(move || founded.send(leader, &here));
        vos_checker::wait_until("the call held at refine", Duration::from_secs(30), || {
            gate.reached() > reached
        });
        assert!(free(leader), "the leader's place given back before apply");
        let before = verified(follower);
        let b = scope.spawn(move || founded.send(follower, &forwarded));
        vos_checker::wait_until("the follower verified", Duration::from_secs(30), || {
            verified(follower) > before
        });
        vos_checker::wait_until(
            "the follower's place given back",
            Duration::from_secs(5),
            || free(follower),
        );
        assert!(!a.is_finished() && !b.is_finished(), "neither applied yet");
        drop(closed);
        [a.join().unwrap(), b.join().unwrap()]
    });
    for answer in &answers {
        done(answer);
    }
}

/// A root this replica has not applied is `RootUnknown` there, and
/// admitted at a replica that has; a root a later write replaced at its
/// own batch time, and one pushed out of the ring by 64 later roots, each
/// `RootUnknown`, and admitted on the path fetched again.
#[test]
fn an_unknown_root_is_retried_on_a_path_fetched_again() {
    let founded = Founded::new();
    let leader = founded.cluster.leader(founded.agent).unwrap();
    let lagging = founded.follower();
    let secret = Secret::new(3);
    {
        let _held = founded.cluster.slot(lagging).trip.commits.close();
        founded.write(CREDENTIALS, "enroll", secret.member());
        let path = founded.path(&secret);
        let call = founded.auth(lagging, &secret, &path, ("login", "login"), ());
        assert_eq!(
            refused(founded.send(lagging, &call)),
            CredentialRefusal::RootUnknown
        );
        assert!(done(&founded.send(leader, &call)).len() > 1);
    }

    // Replaced at its own batch time: the clock held back, a later write
    // is timed at the agent's time.
    let replaced = Secret::new(4);
    founded.write(CREDENTIALS, "enroll", replaced.member());
    let stale = founded.path(&replaced);
    let since = founded.root().since;
    founded
        .cluster
        .offset
        .fetch_sub(3_600_000, Ordering::SeqCst);
    founded.write(CREDENTIALS, "enroll", Secret::new(5).member());
    founded
        .cluster
        .offset
        .fetch_add(3_600_000, Ordering::SeqCst);
    let newest = founded.root();
    assert_eq!(newest.since, since, "replaced at its own batch time");
    assert_ne!(newest.root, stale.root);
    let call = founded.auth(leader, &replaced, &stale, ("login", "login"), ());
    assert_eq!(
        refused(founded.send(leader, &call)),
        CredentialRefusal::RootUnknown
    );
    let fetched = founded.path(&replaced);
    let call = founded.auth(leader, &replaced, &fetched, ("login", "login"), ());
    assert!(done(&founded.send(leader, &call)).len() > 1);

    // Pushed out by 64 later roots, each a batch of its own.
    let early = founded.path(&replaced);
    for seed in 100..100 + tree::RING as u32 + 4 {
        founded.write(CREDENTIALS, "enroll", Secret::new(seed).member());
        std::thread::sleep(Duration::from_millis(2));
    }
    let call = founded.auth(leader, &replaced, &early, ("login", "login"), ());
    assert_eq!(
        refused(founded.send(leader, &call)),
        CredentialRefusal::RootUnknown
    );
    let call = founded.auth(
        leader,
        &replaced,
        &founded.path(&replaced),
        ("login", "login"),
        (),
    );
    assert!(done(&founded.send(leader, &call)).len() > 1);
}

/// A revoked member's proof on the root before its revocation is admitted
/// within `ROOT_MAX_AGE` of the revoking batch, and refused `RootStale`
/// once that has passed by the replica's latest batch time; owner proofs
/// pay from the rows they own, and a rekeyed row from its new owner's.
#[test]
fn a_revoked_members_root_goes_stale_and_owners_pay_their_rows() {
    let founded = Founded::new();
    let at = founded.follower();
    let member = Secret::new(6);
    founded.write(CREDENTIALS, "enroll", member.member());
    let before = founded.path(&member);
    founded.write(CREDENTIALS, "revoke", member.member());
    let call = founded.auth(at, &member, &before, ("login", "login"), ());
    assert!(
        done(&founded.send(at, &call)).len() > 1,
        "within the window"
    );
    founded.later(ROOT_MAX_AGE as i64 + 60_000);
    let call = founded.auth(at, &member, &before, ("login", "login"), ());
    assert_eq!(
        refused(founded.send(at, &call)),
        CredentialRefusal::RootStale
    );

    let (alice, renewed) = (Secret::new(7), Secret::new(8));
    let expires = client::time(founded.cluster.target(1)).unwrap() + 60_000;
    for (name, owner) in [("alice", alice.owner()), ("bob", Secret::new(9).owner())] {
        let name = name.as_bytes().to_vec();
        founded.write(PURSES, "invite_row", (name.clone(), owner, expires));
        founded.write(PURSES, "claim_row", (name.clone(), owner));
        founded.write(PURSES, "mint", (name, 50u64));
    }
    let paid = founded.pay(at, &alice, "alice", "bob", 20);
    done(&founded.send(at, &paid));
    founded.write(PURSES, "rekey", (b"alice".to_vec(), renewed.owner()));
    let old = founded.pay(at, &alice, "alice", "bob", 1);
    match founded.send(at, &old) {
        Response::Ran {
            outcome: Outcome::Failed { .. },
            ..
        } => {}
        other => panic!("the old owner's proof: {other:?}"),
    }
    done(&founded.send(at, &founded.pay(at, &renewed, "alice", "bob", 5)));
    let balance: Option<u64> = founded.read(PURSES, "balance", b"bob".to_vec());
    assert_eq!(balance, Some(75));
}
