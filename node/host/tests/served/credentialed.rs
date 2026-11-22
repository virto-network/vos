//! Proven calls at the node's ingress (`identity-and-authority.md` §5,
//! `light-node.md` §4.3), on three nodes of a founded space, with proofs
//! made as a device makes them, by the stock kernels' release artifacts:
//! each refusal in its check order; a proof replayed, and a `once`
//! nullifier raced past ingress at another replica, each refused at apply;
//! a forwarded call whose answer was lost, sent again before its expiry or
//! after it, and a call its leader proposed before it was deposed, each
//! answered its run, not `Replayed` or `CredentialExpired`; a root a
//! replica has not applied and one pushed out of the ring, each
//! `RootUnknown` and admitted after a path refetch, and a root written
//! while the leader's clock trails kept past the next batch; a revoked member's root refused once `ROOT_GRACE_MS` has
//! passed by the node's clock; owner proofs paying from their accounts; no log entry
//! holding a proof; a verified call holding no large body's place while it
//! waits to apply; the device library's requests and proofs admitted as
//! they leave it; an actor's own kernel's proof run by its handler on its
//! claim; compatibility windows across a credential actor's upgrade; and a
//! second device enrolled and revoked by its first device's owner proofs.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tree::Digest;
use vos_abi::abi::{Failure, Refusal};
use vos_abi::credentials as tree;
use vos_abi::ids::{AgentId, InstanceId, MethodId};
use vos_abi::records::RETIREMENT_MS;
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode, SpaceId, WindowClock};
use vos_checker::Nodes;
use vos_checker::programs::{actor, actor_elf, method, program_elf};
use vos_light::release::Release;
use vos_light::{Call, DEVICE_FORMAT, DeviceProgram, Prover, ProverConfig, Threads};
use vos_net::Class;
use vos_node::client::{self, Client};
use vos_wire::credentials::{
    AuthClaim, Bound, CredentialError, ENROLL_MANY, Path, RING, RootEntry, binding, scope,
};
use vos_wire::defaults::ROOT_GRACE_MS;
use vos_wire::ingress::{
    CredentialRefusal, Credentialed, DeviceWindow, FormatWindow, Rejection, Response,
};
use vos_wire::peer::{NodeNumber, PeerMessage};

use crate::harness::{Cluster, NODES, assert_done, witness};

/// The hub's seed: odd, so clients reach the nodes over the API's sockets.
const SEED: u64 = 11;
const CREDENTIALS: InstanceId = InstanceId(9);
const PAYMENTS: InstanceId = InstanceId(2);
const POLL: InstanceId = InstanceId(3);
/// The registrar's and the operator's role byte: one key holds both.
const ROLE: u8 = 1;
const OPERATOR: [u8; 32] = [21; 32];
/// The space's handle, which the credential actor is founded with.
const HANDLE: [u8; 32] = [0x42; 32];

/// A member's device secret, from a source's output of its seed, and the
/// digests it gives.
struct Secret(vos_light::DeviceSecret);

impl Secret {
    fn new(seed: u32) -> Self {
        let mut output = [0u8; 32];
        output[..4].copy_from_slice(&seed.to_le_bytes());
        Self(vos_light::derive_secret(&output, &HANDLE))
    }

    fn member(&self) -> Digest {
        vos_light::member(&self.0).to_bytes()
    }

    fn owner(&self) -> Digest {
        vos_light::owner(&self.0).to_bytes()
    }
}

/// The stock kernel `kernel`'s release artifact, from the credential
/// actor's ELF `elf`, as an app embeds it.
fn stock(elf: &[u8], kernel: &str) -> Release {
    vos_light::release::device(elf, kernel).expect("a stock kernel's release artifact")
}

/// The founded space's agent: the credential actor, the poll and the
/// ledger installed, the operator's key their registrar and
/// operator, the actor founded; the stock kernels' programs, from their
/// release artifacts, and a prover.
struct Founded {
    cluster: Cluster,
    agent: AgentId,
    space: SpaceId,
    operator: Mutex<Client>,
    credentials: Vec<u8>,
    poll: Vec<u8>,
    payments: Vec<u8>,
    nonce: AtomicU64,
    auth: DeviceProgram,
    owner: DeviceProgram,
    prover: Prover,
}

impl Founded {
    fn new() -> Self {
        let cluster = Cluster::founded(SEED, Some(WindowClock::DEFAULT));
        let elf = |path: std::path::PathBuf| std::fs::read(path).unwrap();
        let credentials_elf = elf(program_elf("vos-credentials"));
        let (poll, payments) = (elf(actor_elf("poll")), elf(program_elf("vos-payments")));
        let installs = [
            (CREDENTIALS, &credentials_elf[..], "registrar"),
            (POLL, &poll[..], "operator"),
            (PAYMENTS, &payments[..], "operator"),
        ];
        // At the leader: a follower answers a call once it has applied it,
        // and a test holds one back.
        let (agent, operator) =
            cluster.found_agent(&installs, ROLE, SigningKey::from_bytes(&OPERATOR));
        let space = cluster.space.id();
        assert_ne!(space, SpaceId::NONE);
        let program =
            |kernel| DeviceProgram::from_release(&stock(&credentials_elf, kernel)).unwrap();
        let founded = Self {
            cluster,
            agent,
            space,
            operator: Mutex::new(operator),
            credentials: vos_checker::programs::program("vos-credentials"),
            poll: actor("poll"),
            payments: vos_checker::programs::program("vos-payments"),
            nonce: AtomicU64::new(0),
            auth: program("auth"),
            owner: program("owner"),
            prover: Prover::new(ProverConfig {
                threads: Threads::Count(4),
                ..ProverConfig::default()
            })
            .unwrap(),
        };
        founded.write(CREDENTIALS, "found", HANDLE);
        founded
    }

    /// Install `elf` at `instance`, its schema's role `role` mapped to
    /// [`ROLE`], at the leader.
    fn install(&self, instance: InstanceId, elf: &[u8], role: &str) {
        let roles = vec![(role.as_bytes().to_vec(), ROLE)];
        self.cluster
            .install_at_leader(self.agent, instance, elf, roles);
    }

    fn program(&self, instance: InstanceId) -> &[u8] {
        match instance {
            CREDENTIALS => &self.credentials,
            POLL => &self.poll,
            _ => &self.payments,
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
        assert_done(name, &answer);
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
        scope(&self.space, self.agent, instance, name.as_bytes())
    }

    /// The device library's call of `instance`'s `name` with a fresh nonce,
    /// good for a minute by node `at`'s clock.
    fn call<A: Encode>(
        &self,
        at: NodeNumber,
        instance: InstanceId,
        name: &str,
        arguments: A,
    ) -> Call {
        self.call_of(at, instance, self.method(instance, name), arguments)
    }

    /// [`Founded::call`] of `instance`'s `method`.
    fn call_of<A: Encode>(
        &self,
        at: NodeNumber,
        instance: InstanceId,
        method: MethodId,
        arguments: A,
    ) -> Call {
        let mut nonce = [0u8; 16];
        let count = self.nonce.fetch_add(1, Ordering::SeqCst) + 1;
        nonce[..8].copy_from_slice(&count.to_le_bytes());
        Call {
            space: self.space.0,
            agent: self.agent.0,
            instance: instance.0,
            method: method.0,
            arguments: arguments.encode(),
            nonce,
            expires_ms: client::time(self.cluster.target(at)).unwrap() + 60_000,
        }
    }

    /// An auth call of the poll's `name`, in the guard `scope`'s scope, by
    /// `secret` under `path`, good for a minute by node `at`'s clock: its
    /// proof made by the stock `auth` kernel.
    fn auth<A: Encode>(
        &self,
        at: NodeNumber,
        secret: &Secret,
        path: &Path,
        (name, scope): (&str, &str),
        arguments: A,
    ) -> Credentialed {
        let call = self.call(at, POLL, name, arguments);
        let proof = self
            .prover
            .prove_auth(
                &secret.0,
                &witness(path),
                scope.as_bytes(),
                &call,
                &self.auth,
            )
            .unwrap();
        request(&call, proof)
    }

    /// An owner call of the ledger's `transfer`, by `secret`, under a
    /// payment key of its own.
    fn pay(&self, at: NodeNumber, secret: &Secret, to: &str, amount: u64) -> Credentialed {
        static KEYS: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
        let key = [KEYS.fetch_add(1, std::sync::atomic::Ordering::Relaxed); 32];
        let arguments = (to.as_bytes().to_vec(), amount, key);
        self.owned(at, secret, PAYMENTS, "transfer", arguments)
    }

    /// An owner call of `instance`'s `name` by `secret`, good for a minute
    /// by node `at`'s clock: its proof made by the stock `owner` kernel.
    fn owned<A: Encode>(
        &self,
        at: NodeNumber,
        secret: &Secret,
        instance: InstanceId,
        name: &str,
        arguments: A,
    ) -> Credentialed {
        let call = self.call(at, instance, name, arguments);
        let proof = self
            .prover
            .prove_owner(&secret.0, &call, &self.owner)
            .unwrap();
        request(&call, proof)
    }

    /// A call of `instance`'s `name` as [`Founded::call`] makes it, its
    /// claim and proof empty.
    fn unproved<A: Encode>(
        &self,
        at: NodeNumber,
        instance: InstanceId,
        name: &str,
        arguments: A,
    ) -> Credentialed {
        let call = self.call(at, instance, name, arguments);
        request(
            &call,
            vos_light::Proven {
                format: DEVICE_FORMAT,
                claim: Vec::new(),
                proof: Vec::new(),
            },
        )
    }

    /// The claim's `binding` for `call` under the stock auth kernel's
    /// program.
    fn binding(&self, call: &Credentialed) -> Digest {
        let b = Bound {
            space: &self.space,
            agent: self.agent,
            instance: call.instance,
            method: call.method,
            program: &self.auth.id().0,
            arguments: &call.arguments,
            nonce: &call.nonce,
            expires_ms: call.expires_ms,
        }
        .digest();
        binding(&b)
    }

    fn send(&self, at: NodeNumber, call: &Credentialed) -> Response {
        client::credentialed(self.cluster.target(at), self.agent, call).unwrap()
    }

    /// Move every node's clock on by `ms`, and apply a batch after it.
    fn later(&self, ms: i64) {
        self.cluster.offset.fetch_add(ms, Ordering::SeqCst);
        self.write(PAYMENTS, "invite", (b"tick".to_vec(), [1u8; 32], 0u64));
    }

    fn follower(&self) -> NodeNumber {
        let leader = self.cluster.leader(self.agent).unwrap();
        leader % NODES + 1
    }
}

/// The request the device library sends for `call` under `proof`.
fn request(call: &Call, proof: vos_light::Proven) -> Credentialed {
    Credentialed {
        instance: InstanceId(call.instance),
        method: MethodId(call.method),
        arguments: call.arguments.clone(),
        nonce: call.nonce,
        expires_ms: call.expires_ms,
        format: proof.format,
        claim: proof.claim,
        proof: proof.proof,
    }
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
/// the format (an unregistered one), the sizes (a proof past the device
/// format's cap, a claim past its cap, arguments past theirs), the expiry,
/// the method's guard, the claim (an owner's to an auth guard), the scope,
/// the binding, a recorded binding digest, an admitted nullifier, an
/// unknown root, and the proof. A verified call runs, as its origin.
#[test]
fn every_ingress_refusal_comes_in_its_check_order() {
    let founded = Founded::new();
    let secret = Secret::new(1);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let at = founded.follower();
    let target = founded.cluster.target(at).clone();
    let agent = founded.agent;

    // Over a gateway's HTTP: the size refused from the head, the body
    // unread (the API's frames are refused from their header,
    // `ingress::api`).
    let key = founded.cluster.node(at).unwrap().id().0;
    let socket = founded.cluster.dir(at).join("api.sock");
    let front = vos_checker::processes::Front::serve(
        vec![(key, format!("unix:{}", socket.display()))],
        [0x9a; 32],
    );
    let path = format!("/agents/{}/credentialed", agent.0);
    let largest = client::naming(agent, &vec![0; vos_api::CREDENTIALED_HTTP]);
    let credentialed = vos_api::Kind::Credentialed;
    let (status, _) = client::send(front.target(), credentialed, &largest).unwrap();
    assert_eq!(status, 400, "the largest body is read");
    let mut stream = std::net::TcpStream::connect(front.target().authority()).unwrap();
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
    let malformed = client::naming(agent, &[0xff]);
    let (status, body) = client::send(&target, credentialed, &malformed).unwrap();
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
    // The target answers `NoAgent` until it learns the new agent's placement.
    let mut unfounded = Response::NoAgent;
    vos_checker::wait_until("the bare agent placed", Duration::from_secs(30), || {
        unfounded = client::credentialed(&target, bare, &fresh).unwrap();
        unfounded != Response::NoAgent
    });
    assert_eq!(refused(unfounded), CredentialRefusal::NoSpace);

    // Every check from the format on fails; each mended in turn.
    let real = founded.auth(at, &secret, &founded.path(&secret), ("vote", "vote"), 3u8);
    let claimed = AuthClaim::decode_exact(&real.claim).expect("auth's claim");
    let claim = |claim: AuthClaim| claim.encode();
    let mut call = Credentialed {
        method: founded.method(POLL, "tally"),
        format: 38,
        proof: vec![7; vos_pvm_device::MAX_PROOF_BYTES + 1],
        expires_ms: real.expires_ms + 600_000,
        claim: vec![1; vos_abi::abi::cap::CLAIM + 1],
        arguments: vec![0; vos_abi::abi::cap::REQUEST - vos_abi::abi::cap::CLAIM + 1],
        ..real.clone()
    };
    let check = |call: &Credentialed, code: CredentialRefusal, what: &str| match (
        refused(founded.send(at, call)),
        code,
    ) {
        (CredentialRefusal::Expiry { .. }, CredentialRefusal::Expiry { .. }) => {}
        (answer, code) => assert_eq!(answer, code, "{what}"),
    };
    check(&call, CredentialRefusal::Format, "an unregistered format");
    call.format = DEVICE_FORMAT;
    check(
        &call,
        CredentialRefusal::Size,
        "a proof past the device format's cap",
    );
    call.proof = vec![7; 64];
    check(&call, CredentialRefusal::Size, "a claim past its cap");
    call.claim = vec![1; 64];
    check(&call, CredentialRefusal::Size, "arguments past theirs");
    call.arguments = real.arguments.clone();
    check(
        &call,
        CredentialRefusal::Expiry { now: 0 },
        "ten minutes ahead",
    );
    call.expires_ms = real.expires_ms;
    check(&call, CredentialRefusal::Method, "a method with no guard");
    call.method = real.method;
    check(&call, CredentialRefusal::Kind, "an owner's claim");
    call.claim = claim(AuthClaim {
        map_root: [3; 32],
        scope: [4; 32],
        binding: [5; 32],
        ..claimed
    });
    check(&call, CredentialRefusal::Scope, "another scope");
    call.claim = claim(AuthClaim {
        map_root: [3; 32],
        binding: [5; 32],
        ..claimed
    });
    check(&call, CredentialRefusal::Binding, "another binding");
    assert_eq!(founded.binding(&call), claimed.binding);
    call.claim = claim(AuthClaim {
        map_root: [3; 32],
        ..claimed
    });
    check(
        &call,
        CredentialRefusal::RootUnknown,
        "a root the ring never held",
    );
    call.claim = real.claim.clone();
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
    let again = founded.auth(at, &secret, &founded.path(&secret), ("vote", "vote"), 2u8);
    let again = Credentialed {
        claim: claim(AuthClaim {
            map_root: [3; 32],
            ..AuthClaim::decode_exact(&again.claim).unwrap()
        }),
        ..again
    };
    assert_eq!(refused(founded.send(at, &again)), CredentialRefusal::Once);
    // A proof with a wrong PoW: refused as any proof that fails.
    let mut wrong = founded.auth(at, &secret, &founded.path(&secret), ("login", "login"), ());
    let mut decoded = vos_pvm_device::decode(&vos_pvm_device::FORMAT, &wrong.proof).unwrap();
    decoded.stark_proof.0.proof_of_work ^= 1;
    wrong.proof = vos_pvm_device::encode(&vos_pvm_device::FORMAT, &decoded).unwrap();
    assert_eq!(refused(founded.send(at, &wrong)), CredentialRefusal::Proof);
    // No log entry holds a proof's bytes.
    let node = founded.cluster.node(at).unwrap();
    let applied = node.applied(agent).unwrap();
    let entries = node
        .probes()
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

/// A follower forwards a call whose answer from the leader is lost: it
/// forwards it again, which apply refuses `Replayed`, the first send having
/// run, and the client is answered the run's outcome once the follower has
/// applied it. The client's own repeat is refused `Replayed` at ingress.
#[test]
fn a_forwarded_call_whose_answer_is_lost_is_answered_its_run() {
    let founded = Founded::new();
    let secret = Secret::new(12);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let leader = founded.cluster.leader(founded.agent).unwrap();
    let follower = founded.follower();
    let path = founded.path(&secret);
    let call = founded.auth(follower, &secret, &path, ("login", "login"), ());
    let hub = &founded.cluster.hub;
    let lost = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&lost);
    hub.tap(Arc::new(move |from, to, class, frame| {
        if from == leader
            && to == follower
            && class == Class::Requests
            && matches!(
                PeerMessage::decode_exact(frame),
                Some(PeerMessage::Forwarded { .. })
            )
        {
            seen.store(true, Ordering::SeqCst);
        }
    }));
    hub.cut_class(leader, follower, Class::Requests);
    let founded = &founded;
    let answer = std::thread::scope(|scope| {
        let answer = scope.spawn(|| founded.send(follower, &call));
        vos_checker::wait_until("the leader's answer lost", Duration::from_secs(30), || {
            lost.load(Ordering::SeqCst)
        });
        hub.heal();
        answer.join().unwrap()
    });
    done(&answer);
    assert_eq!(
        refused(founded.send(follower, &call)),
        CredentialRefusal::Replayed
    );
}

/// A follower forwards a call whose answer from the leader is lost, and
/// sends it again once the agent's time is past the call's expiry: apply
/// refuses that send `CredentialExpired`, and the client is answered the
/// first send's run, not the expiry.
#[test]
fn a_forwarded_call_run_before_its_expiry_is_answered_its_run_after_it() {
    let founded = Founded::new();
    let secret = Secret::new(14);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let leader = founded.cluster.leader(founded.agent).unwrap();
    let follower = founded.follower();
    let path = founded.path(&secret);
    let call = founded.auth(follower, &secret, &path, ("login", "login"), ());
    let logins: u64 = founded.read(POLL, "logins", ());
    let hub = &founded.cluster.hub;
    let lost = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&lost);
    hub.tap(Arc::new(move |from, to, class, frame| {
        if from == leader
            && to == follower
            && class == Class::Requests
            && matches!(
                PeerMessage::decode_exact(frame),
                Some(PeerMessage::Forwarded { .. })
            )
        {
            seen.store(true, Ordering::SeqCst);
        }
    }));
    hub.cut_class(leader, follower, Class::Requests);
    let founded = &founded;
    let answer = std::thread::scope(|scope| {
        let answer = scope.spawn(|| founded.send(follower, &call));
        vos_checker::wait_until("the leader's answer lost", Duration::from_secs(30), || {
            lost.load(Ordering::SeqCst)
        });
        founded.later(61_000);
        hub.heal();
        answer.join().unwrap()
    });
    done(&answer);
    let after: u64 = founded.read(POLL, "logins", ());
    assert_eq!(after, logins + 1, "it ran once");
}

/// The leader takes a call at its own ingress and proposes it, its
/// followers' acknowledgements lost: it steps down before the entry
/// commits there, and its successor commits it. Healed, the deposed leader
/// sends the call on, apply refuses it `Replayed`, and the client is
/// answered the run of its own proposal.
#[test]
fn a_leader_deposed_after_proposing_answers_the_run_its_successor_committed() {
    let founded = Founded::new();
    let agent = founded.agent;
    let secret = Secret::new(13);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let leader = founded.cluster.leader(agent).unwrap();
    let others: Vec<NodeNumber> = (1..=NODES).filter(|number| *number != leader).collect();
    let path = founded.path(&secret);
    let call = founded.auth(leader, &secret, &path, ("login", "login"), ());
    let replica = |number| {
        let node = founded.cluster.node(number).unwrap();
        node.replica(agent).unwrap()
    };
    let first = replica(leader);
    let hub = &founded.cluster.hub;
    let gate = &founded.cluster.slot(leader).trip.refines;
    let reached = gate.reached();
    let closed = gate.close();
    let founded = &founded;
    let answer = std::thread::scope(|scope| {
        let answer = scope.spawn(|| founded.send(leader, &call));
        vos_checker::wait_until("the call at refine", Duration::from_secs(30), || {
            gate.reached() > reached
        });
        for other in &others {
            hub.cut_class(*other, leader, Class::Consensus);
        }
        drop(closed);
        let mut proposed = 0;
        vos_checker::wait_until("the call proposed", Duration::from_secs(30), || {
            proposed = replica(leader).last_index;
            proposed > first.last_index
        });
        vos_checker::wait_until("a successor applied it", Duration::from_secs(60), || {
            others.iter().any(|other| {
                let status = replica(*other);
                status.leads && status.term > first.term && status.applied >= proposed
            })
        });
        assert!(
            replica(leader).commit < proposed,
            "not committed at the leader"
        );
        hub.heal();
        answer.join().unwrap()
    });
    done(&answer);
    assert_eq!(
        refused(founded.send(leader, &call)),
        CredentialRefusal::Replayed
    );
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
        node.probes().credentialed_places_free() == vos_node::CREDENTIALED_BODIES
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

/// Two tree-changing batches while the leader's clock reads the agent's
/// time: the second is timed a millisecond past the first, so its root
/// does not replace the one the first wrote (`Ring::record`), which a
/// device that read it still proves against.
#[test]
fn a_batch_at_the_agents_time_is_timed_past_it() {
    let founded = Founded::new();
    let leader = founded.cluster.leader(founded.agent).unwrap();
    let held = vos_node::wall_clock()
        .saturating_add_signed(founded.cluster.offset.load(Ordering::SeqCst))
        + 2_000;
    let first = Secret::new(4);
    let path = {
        let slot = founded.cluster.slot(leader);
        slot.held.store(held, Ordering::SeqCst);
        founded.write(CREDENTIALS, "enroll", first.member());
        let path = founded.path(&first);
        founded.write(CREDENTIALS, "enroll", Secret::new(5).member());
        slot.held.store(0, Ordering::SeqCst);
        path
    };
    let newest = founded.root();
    assert!(newest.since > held, "a batch time past the agent's");
    assert_ne!(newest.root, path.root);
    let call = founded.auth(leader, &first, &path, ("login", "login"), ());
    assert!(done(&founded.send(leader, &call)).len() > 1);
}

/// A root this replica has not applied is `RootUnknown` there, and
/// admitted at a replica that has; a root written while the leader's clock
/// trails the agent's time stays admitted after the next batch's write,
/// each batch timed past the one before; a root pushed out of the ring by
/// 64 later roots is `RootUnknown`, and admitted on the path fetched
/// again.
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

    // The clock held back: a later write is timed past the agent's time,
    // so its root supersedes the one before, which stays admitted.
    let replaced = Secret::new(4);
    founded.write(CREDENTIALS, "enroll", replaced.member());
    let stale = founded.path(&replaced);
    let since = founded.root().since;
    founded
        .cluster
        .offset
        .fetch_sub(3_600_000, Ordering::SeqCst);
    founded.write(CREDENTIALS, "enroll", Secret::new(5).member());
    founded.write(CREDENTIALS, "enroll", Secret::new(6).member());
    founded
        .cluster
        .offset
        .fetch_add(3_600_000, Ordering::SeqCst);
    let newest = founded.root();
    assert!(newest.since > since, "a batch time of its own");
    assert_ne!(newest.root, stale.root);
    let call = founded.auth(leader, &replaced, &stale, ("login", "login"), ());
    assert!(done(&founded.send(leader, &call)).len() > 1);

    // Pushed out by 64 later roots, each a batch of its own.
    let early = founded.path(&replaced);
    for seed in 100..100 + RING as u32 + 4 {
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
/// within `ROOT_GRACE_MS` of the revoking batch, and refused `RootStale`
/// once that has passed by the node's clock, no batch run since; owner proofs
/// pay from the accounts they hold, and a rekeyed account from its new
/// owner's.
#[test]
fn a_revoked_members_root_goes_stale_and_owners_pay_from_their_accounts() {
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
    // The clocks moved on with no batch after: an idle space, whose
    // latest batch time stays at the revocation's.
    let idle = |ms: i64| founded.cluster.offset.fetch_add(ms, Ordering::SeqCst);
    idle(ROOT_GRACE_MS as i64 - 30_000);
    let call = founded.auth(at, &member, &before, ("login", "login"), ());
    assert!(
        done(&founded.send(at, &call)).len() > 1,
        "later, within the grace"
    );
    // Past the grace by the node's clock, long before the ring's 64 roots
    // push it out.
    idle(40_000);
    let call = founded.auth(at, &member, &before, ("login", "login"), ());
    assert_eq!(
        refused(founded.send(at, &call)),
        CredentialRefusal::RootStale
    );

    let (alice, renewed) = (Secret::new(7), Secret::new(8));
    let expires = client::time(founded.cluster.target(1)).unwrap() + 60_000;
    for (name, owner) in [("alice", alice.owner()), ("bob", Secret::new(9).owner())] {
        let name = name.as_bytes().to_vec();
        founded.write(PAYMENTS, "invite", (name.clone(), owner, expires));
        founded.write(PAYMENTS, "open", (name.clone(), owner));
        founded.write(PAYMENTS, "mint", (name, 50u64));
    }
    let paid = founded.pay(at, &alice, "bob", 20);
    done(&founded.send(at, &paid));
    founded.write(PAYMENTS, "rekey", (b"alice".to_vec(), renewed.owner()));
    let old = founded.pay(at, &alice, "bob", 1);
    match founded.send(at, &old) {
        Response::Ran {
            outcome: Outcome::Failed { .. },
            ..
        } => {}
        other => panic!("the old owner's proof: {other:?}"),
    }
    done(&founded.send(at, &founded.pay(at, &renewed, "bob", 5)));
    let balance: Option<u64> = founded.read(PAYMENTS, "balance", b"bob".to_vec());
    assert_eq!(balance, Some(75));
}

/// A second device enrolled and revoked in the space by its first
/// device's owner proofs (`light-node.md` §3.8): the registrar registers
/// the first device's digests as a person, whose owner proof enrolls the
/// second, and the second's confirms its owner digest; each device votes once in the poll's `once` scope, so the
/// person is admitted once a device, the second's repeat refused; the
/// first's owner proof revokes the second, whose path is gone and whose
/// owner proof, which held the person, then holds none.
#[test]
fn a_second_device_is_enrolled_and_revoked_by_its_first_devices_proof() {
    let founded = Founded::new();
    let at = founded.follower();
    let (first, second) = (Secret::new(41), Secret::new(42));
    founded.write(CREDENTIALS, "enroll", first.member());
    founded.write(
        CREDENTIALS,
        "register",
        (first.member(), first.owner(), 2u8),
    );
    let arguments = (second.member(), second.owner());
    let enroll = founded.owned(at, &first, CREDENTIALS, "enroll_device", arguments);
    let slot = u32::decode_exact(done(&founded.send(at, &enroll))).unwrap();
    let path = founded.path(&second);
    assert_eq!(slot, path.slot);
    let confirm = founded.owned(at, &second, CREDENTIALS, "confirm_device", second.member());
    done(&founded.send(at, &confirm));

    for secret in [&first, &second] {
        let vote = founded.auth(at, secret, &founded.path(secret), ("vote", "vote"), 3u8);
        done(&founded.send(at, &vote));
    }
    let tally: u32 = founded.read(POLL, "tally", 3u8);
    assert_eq!(tally, 2, "one admission a device");
    let again = founded.auth(at, &second, &path, ("vote", "vote"), 4u8);
    assert_eq!(refused(founded.send(at, &again)), CredentialRefusal::Once);

    let revoke = founded.owned(at, &first, CREDENTIALS, "revoke_device", second.member());
    done(&founded.send(at, &revoke));
    let gone: Option<Path> = founded.read(CREDENTIALS, "path", second.member());
    assert_eq!(gone, None);
    let back = founded.owned(at, &second, CREDENTIALS, "revoke_device", first.member());
    match founded.send(at, &back) {
        Response::Ran {
            outcome: Outcome::Failed { detail, .. },
            ..
        } => assert_eq!(detail, [CredentialError::NoPerson as u8]),
        other => panic!("a revoked device's revocation: {other:?}"),
    }
    founded.path(&first);
}

/// `vos-light`'s `SCOPE_VECTOR`: `scope([0x51; 32], 4, 2, "login")`, the
/// name in SCALE.
const SCOPE_VECTOR: [u8; 32] = [
    176, 47, 24, 3, 211, 3, 208, 103, 92, 44, 198, 75, 144, 255, 58, 99, 210, 27, 59, 25, 235, 172,
    49, 126, 162, 142, 147, 35, 82, 189, 54, 43,
];

/// A device request's answer, its bytes sent as they leave the library:
/// its kind's two bytes, then its body, the agent's four first.
fn device_send(founded: &Founded, at: NodeNumber, request: &[u8]) -> Vec<u8> {
    let kind = u16::from_le_bytes([request[0], request[1]]);
    let agent = u32::from_le_bytes(request[2..6].try_into().unwrap());
    assert_eq!(agent, founded.agent.0);
    let kind = match vos_api::Kind::from_u16(kind) {
        Some(kind @ (vos_api::Kind::Query | vos_api::Kind::Credentialed)) => kind,
        _ => panic!("not a device request: {kind:#x}"),
    };
    let (_, body) = client::send(founded.cluster.target(at), kind, &request[2..]).unwrap();
    body
}

/// The device library's scope is ingress's, the vector on both sides; its
/// path query, its auth and owner proofs and its requests are admitted by
/// a follower's ingress as they leave it, the poll's `ctx.nullifier` the
/// library's, and the ledger paying from the account its owner digest
/// holds;
/// a `RootUnknown` answer decodes as the library's.
#[test]
fn the_device_librarys_proofs_are_admitted() {
    use vos_light::wire::{self, Answer};

    assert_eq!(
        vos_light::scope(&[0x51; 32], 4, 2, b"login")
            .unwrap()
            .to_bytes(),
        SCOPE_VECTOR
    );
    assert_eq!(
        scope(&SpaceId([0x51; 32]), AgentId(4), InstanceId(2), b"login"),
        SCOPE_VECTOR
    );

    let founded = Founded::new();
    let at = founded.follower();
    let space = founded.space.0;
    let agent = founded.agent;
    let secret = vos_light::derive_secret(&[0x5e; 32], &[0x42; 32]);
    let member = vos_light::member(&secret).to_bytes();
    founded.write(CREDENTIALS, "enroll", member);
    let prover = vos_light::Prover::new(vos_light::ProverConfig {
        threads: vos_light::Threads::Count(4),
        ..vos_light::ProverConfig::default()
    })
    .unwrap();
    let time = || client::time(founded.cluster.target(at)).unwrap();
    let identity = founded.operator.lock().unwrap().identity(agent).unwrap();

    let mut keeper = vos_light::TreeKeeper::new(vos_light::member(&secret));
    let read = |keeper: &mut vos_light::TreeKeeper, node: NodeNumber| loop {
        let query = keeper
            .request(agent.0, &identity, CREDENTIALS.0, time() + 60_000)
            .unwrap();
        if !keeper
            .ingest(&device_send(&founded, node, &query), time())
            .unwrap()
            .more
        {
            break;
        }
    };
    // The follower answers from its applied state, which the enrollment
    // reaches once it replicates.
    vos_checker::wait_until(
        "the follower's feed holds the member",
        Duration::from_secs(30),
        || {
            read(&mut keeper, at);
            keeper.witness().is_some()
        },
    );

    let name = b"login";
    let login = |expires_ms| {
        vos_light::Call::new(
            space,
            agent.0,
            POLL.0,
            founded.method(POLL, "login").0,
            ().encode(),
            expires_ms,
        )
        .unwrap()
    };
    let call = login(time() + 60_000);
    let proof = prover
        .prove_auth(
            &secret,
            &keeper.witness().unwrap(),
            name,
            &call,
            &founded.auth,
        )
        .unwrap();
    vos_light::verify(&proof, &call, &founded.auth, Some(name)).unwrap();
    let AuthClaim {
        scope, nullifier, ..
    } = AuthClaim::decode_exact(&proof.claim).unwrap();
    assert_eq!(scope, founded.scope(POLL, "login"));
    let answer = device_send(&founded, at, &wire::credentialed(&call, &proof));
    let Ok(Answer::Ran {
        outcome: Outcome::Done(reply),
        ..
    }) = wire::credentialed_answer(&answer)
    else {
        panic!("the device's auth call: {answer:?}");
    };
    assert_eq!(
        Option::<[u8; 32]>::decode_exact(&reply).unwrap(),
        Some(nullifier),
        "the poll's `ctx.nullifier` is the library's"
    );
    assert_eq!(
        wire::credentialed_answer(&device_send(
            &founded,
            at,
            &wire::credentialed(&call, &proof)
        )),
        Ok(Answer::Refused(CredentialRefusal::Replayed))
    );

    // Pushed out of the ring: the library's answer, the feed read again,
    // and a new proof at its root admitted.
    for seed in 200..200 + RING as u32 + 4 {
        founded.write(CREDENTIALS, "enroll", Secret::new(seed).member());
        std::thread::sleep(Duration::from_millis(2));
    }
    let call = login(time() + 60_000);
    let proof = prover
        .prove_auth(
            &secret,
            &keeper.witness().unwrap(),
            name,
            &call,
            &founded.auth,
        )
        .unwrap();
    let leader = founded.cluster.leader(agent).unwrap();
    assert_eq!(
        wire::credentialed_answer(&device_send(
            &founded,
            leader,
            &wire::credentialed(&call, &proof)
        )),
        Ok(Answer::RootUnknown)
    );
    keeper.unknown(time());
    read(&mut keeper, leader);
    let proof = prover
        .prove_auth(
            &secret,
            &keeper.witness().unwrap(),
            name,
            &call,
            &founded.auth,
        )
        .unwrap();
    assert!(matches!(
        wire::credentialed_answer(&device_send(
            &founded,
            leader,
            &wire::credentialed(&call, &proof)
        )),
        Ok(Answer::Ran {
            outcome: Outcome::Done(_),
            ..
        })
    ));

    // An owner proof pays from the account its digest holds.
    let owner = vos_light::owner(&secret).to_bytes();
    let expires = time() + 60_000;
    for (name, digest) in [("device", owner), ("shop", Secret::new(9).owner())] {
        let name = name.as_bytes().to_vec();
        founded.write(PAYMENTS, "invite", (name.clone(), digest, expires));
        founded.write(PAYMENTS, "open", (name.clone(), digest));
        founded.write(PAYMENTS, "mint", (name, 50u64));
    }
    let arguments = vos_light::transfer_arguments("shop", 20, &[20; 32]);
    let pay = vos_light::Call::new(
        space,
        agent.0,
        PAYMENTS.0,
        founded.method(PAYMENTS, "transfer").0,
        arguments,
        time() + 60_000,
    )
    .unwrap();
    let proof = prover.prove_owner(&secret, &pay, &founded.owner).unwrap();
    let answer = device_send(&founded, at, &wire::credentialed(&pay, &proof));
    assert!(
        matches!(
            wire::credentialed_answer(&answer),
            Ok(Answer::Ran {
                outcome: Outcome::Done(_),
                ..
            })
        ),
        "the device's payment: {answer:?}"
    );
    let balance: Option<u64> = founded.read(PAYMENTS, "balance", b"shop".to_vec());
    assert_eq!(balance, Some(70));
}

const DEVICE: InstanceId = InstanceId(4);

/// The hand-lean `auth` kernel's claim (the `device` actor's): its kind
/// byte, then the four digests.
fn device_claim(root: &Digest, scope: &Digest, nullifier: &Digest, binding: &Digest) -> Vec<u8> {
    vos_pvm_device::auth_public(root, scope, nullifier, binding).to_vec()
}

/// An actor's own kernel's proof (`#[msg(proven = auth)]`, the `device`
/// actor's hand-lean `auth`): ingress checks the proof and its binding, a
/// follower computing the program the first time and the leader holding
/// it from the install, and the handler takes the claim first and checks
/// it at apply, its caller `Kernel { program }`: it admits the claim's
/// nullifier once, refusing it after as its own check, and the binding
/// digest is `Replayed` sent again. Refused at ingress: the stock guard
/// a claim of the kernel's (`Kind`); a stock auth proof sent to the kernel
/// guard (its binding names the stock program: `Binding`); a claim stating
/// another nullifier, one with a word at `p`, and a proof cut by a byte
/// (`Proof`). Upgraded to `device-next`, whose `auth` is another program
/// with the same claims, the guard admits both releases' proofs, and the
/// handler refuses the second of one nullifier whichever proved it.
#[test]
fn an_actor_kernels_proof_is_checked_by_its_handler_at_apply() {
    use vos_light::wire::{self, Answer};

    let founded = Founded::new();
    let agent = founded.agent;
    let elf = |name: &str| std::fs::read(actor_elf(name)).unwrap();
    founded.install(DEVICE, &elf("device"), "operator");
    let device = actor("device");
    let login = method(&device, "login");
    let at = founded.follower();
    let leader = founded.cluster.leader(agent).unwrap();
    // The kernel takes the secret's words: a test's member, its secret
    // public.
    let words: tree::Words = core::array::from_fn(|i| 0x6d00_0000 + i as u32);
    let compress = tree::compress;
    let member = tree::digest(&compress(&tree::Tag::Member.block(), &words));
    founded.write(CREDENTIALS, "enroll", member);
    let path = {
        let path: Option<Path> = founded.read(CREDENTIALS, "path", member);
        path.expect("an enrolled member's path")
    };
    let one = vos_light::release::device(&elf("device"), "auth").unwrap();
    let program = DeviceProgram::from_release(&one).unwrap();
    let call = |method: MethodId, instance: InstanceId, at: NodeNumber| {
        founded.call_of(at, instance, method, ())
    };
    // The member's nullifier in a scope `name` gives: the handler checks
    // no scope, so each name is another nullifier of one member.
    let nullifier = |name: &str| {
        let scope = founded.scope(DEVICE, name);
        let nullifier = tree::digest(&compress(
            &compress(&tree::Tag::Nf.block(), &words),
            &tree::words(&scope).unwrap(),
        ));
        (scope, nullifier)
    };
    // The kernel's proof of the member for `call`, its claim under
    // `program` in the scope `name` gives.
    let prove = |call: &Call, program: &DeviceProgram, name: &str| {
        let binding = call.binding(&program.id().0).to_bytes();
        let (scope, nullifier) = nullifier(name);
        let claim = device_claim(&path.root, &scope, &nullifier, &binding);
        let siblings = path
            .siblings
            .0
            .map(|sibling| tree::words(&sibling).unwrap());
        let public = claim.clone().try_into().expect("auth's public bytes");
        let arguments = vos_pvm_device::auth_arguments(&siblings, &words, path.slot, &public);
        let proof = founded
            .prover
            .prove_kernel(program, &arguments)
            .expect("the kernel proves");
        vos_light::Proven {
            format: DEVICE_FORMAT,
            claim,
            proof: proof.proof,
        }
    };
    let send = |at: NodeNumber, call: &Call, proof: &vos_light::Proven| {
        wire::credentialed_answer(&device_send(&founded, at, &wire::credentialed(call, proof)))
            .unwrap()
    };
    let signed_in = |answer: Answer| match answer {
        Answer::Ran {
            outcome: Outcome::Done(reply),
            ..
        } => <([u8; 32], [u8; 32])>::decode_exact(&reply).unwrap(),
        other => panic!("not run: {other:?}"),
    };
    let refused_by_handler = |answer: Answer| {
        assert!(
            matches!(
                answer,
                Answer::Ran {
                    outcome: Outcome::Failed { .. },
                    ..
                }
            ),
            "the handler's refusal: {answer:?}"
        )
    };

    let signin = call(login, DEVICE, at);
    let proof = prove(&signin, &program, "login");
    assert_eq!(
        signed_in(send(at, &signin, &proof)),
        (nullifier("login").1, program.id().0),
        "the claim's nullifier, the caller the kernel's program"
    );
    assert_eq!(
        send(leader, &signin, &proof),
        Answer::Refused(CredentialRefusal::Replayed)
    );
    // The leader, which pinned the program at the install, admits another
    // proof; the handler refuses the nullifier it saw.
    let again = call(login, DEVICE, leader);
    refused_by_handler(send(leader, &again, &prove(&again, &program, "login")));

    // Refused at ingress.
    let poll = call(founded.method(POLL, "login"), POLL, at);
    assert_eq!(
        send(at, &poll, &prove(&poll, &program, "login")),
        Answer::Refused(CredentialRefusal::Kind),
        "the kernel's claim to the stock guard"
    );
    let stock = call(login, DEVICE, at);
    let secret = Secret::new(0x6e);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let proved = founded
        .prover
        .prove_auth(
            &secret.0,
            &witness(&founded.path(&secret)),
            b"login",
            &stock,
            &founded.auth,
        )
        .unwrap();
    assert_eq!(
        send(at, &stock, &proved),
        Answer::Refused(CredentialRefusal::Binding),
        "a stock proof's binding names the stock program"
    );
    let fresh = call(login, DEVICE, at);
    let proof = prove(&fresh, &program, "other");
    let mut stated = proof.clone();
    stated.claim[1 + 64] ^= 1;
    assert_eq!(
        send(at, &fresh, &stated),
        Answer::Refused(CredentialRefusal::Proof),
        "another nullifier than the proof's"
    );
    let mut wide = proof.clone();
    wide.claim[1 + 64..1 + 68].copy_from_slice(&tree::P.to_le_bytes());
    assert_eq!(
        send(at, &fresh, &wide),
        Answer::Refused(CredentialRefusal::Proof),
        "a word at p"
    );
    let mut cut = proof.clone();
    cut.proof.pop();
    assert_eq!(
        send(at, &fresh, &cut),
        Answer::Refused(CredentialRefusal::Proof)
    );
    assert_eq!(signed_in(send(at, &fresh, &proof)).0, nullifier("other").1);

    // Upgraded: both releases' proofs admitted, one nullifier once.
    let two = vos_light::release::device(&elf("device-next"), "auth").unwrap();
    assert_ne!(one.id, two.id);
    founded.install(DEVICE, &elf("device-next"), "operator");
    vos_checker::spaces::wait_in_process("the upgrade applied", || {
        window(&founded, at, DEVICE).kernels[0].programs.len() == 2
    });
    let next = DeviceProgram::from_release(&two).unwrap();
    let first = call(login, DEVICE, at);
    assert_eq!(
        signed_in(send(at, &first, &prove(&first, &program, "late"))),
        (nullifier("late").1, one.id),
        "release one's proof, after the upgrade"
    );
    let second = call(login, DEVICE, at);
    refused_by_handler(send(at, &second, &prove(&second, &next, "late")));
    let third = call(login, DEVICE, at);
    assert_eq!(
        signed_in(send(at, &third, &prove(&third, &next, "newest"))),
        (nullifier("newest").1, two.id)
    );
}

/// The device window of `instance`, as node `at` answers it.
fn window(founded: &Founded, at: NodeNumber, instance: InstanceId) -> DeviceWindow {
    client::devices(founded.cluster.target(at), founded.agent, instance)
        .unwrap()
        .expect("an installed instance's window")
}

/// Compatibility windows (`light-node.md` §4.4) of the stock `auth`
/// kernel, on its release artifacts as an app embeds them: the credential
/// actor's (release one) and `credentials-next`'s (release two, its kernel
/// written otherwise, the same claims). The space's window, the credential
/// actor's, names the programs the artifacts name, computed from the same
/// ELFs. An app shipping release one alone signs in at a space upgraded to
/// release two, as the member's pseudonym; an app shipping both proves
/// with release two, and the poll's `once` guard refuses it, the same
/// nullifier in one scope. Retired now, release one leaves the window: the
/// old app refuses before proving, saying which side must update, and its
/// proof made before is refused at ingress. A rollback keeps release two's
/// program until its date, 60 days on: then it leaves the window, by the
/// clock alone. The release's one device format cannot be retired in the
/// agent's log (`Forbidden`): its window keeps it, and a proof runs.
#[test]
fn an_app_one_release_behind_signs_in_until_its_window_closes() {
    use vos_light::wire::{self, Answer};
    use vos_light::{DeviceError, Proven};

    let founded = Founded::new();
    let agent = founded.agent;
    let auth = founded.method(CREDENTIALS, "auth");
    let elf = |path: std::path::PathBuf| std::fs::read(path).unwrap();
    let (release_one, release_two) = (
        elf(program_elf("vos-credentials")),
        elf(actor_elf("credentials-next")),
    );
    let one = stock(&release_one, "auth");
    let two = stock(&release_two, "auth");
    assert_ne!(one.id, two.id);
    let (old_app, new_app) = (vec![one.clone()], vec![two.clone(), one.clone()]);

    let at = founded.follower();
    let secrets = [0x43, 0x44].map(Secret::new);
    for secret in &secrets {
        founded.write(CREDENTIALS, "enroll", secret.member());
    }
    let witnesses = secrets
        .each_ref()
        .map(|secret| witness(&founded.path(secret)));
    // The app's sign-in: the newest program it ships that the space's
    // window admits, chosen before anything is proved.
    let sign_in_as = |member: usize, app: &[Release]| {
        let chosen = vos_light::choose(app, &window(&founded, at, CREDENTIALS), auth)?;
        let program = DeviceProgram::from_release(chosen).unwrap();
        let call = founded.call(at, POLL, "vote", 3u8);
        let proof = founded
            .prover
            .prove_auth(
                &secrets[member].0,
                &witnesses[member],
                b"vote",
                &call,
                &program,
            )
            .unwrap();
        vos_light::verify(&proof, &call, &program, Some(b"vote")).unwrap();
        Ok::<_, DeviceError>((chosen.id, call, proof))
    };
    let sign_in = |app: &[Release]| sign_in_as(0, app);
    let send = |call: &Call, proof: &Proven| {
        wire::credentialed_answer(&device_send(&founded, at, &wire::credentialed(call, proof)))
            .unwrap()
    };
    let nullifier = |proof: &Proven| AuthClaim::decode_exact(&proof.claim).unwrap().nullifier;
    let time = || client::time(founded.cluster.target(at)).unwrap();

    // Release one alone: the window names the artifact's program, the
    // format the device format; the new app proves with release one.
    let before = window(&founded, at, CREDENTIALS);
    let programs = |window: &DeviceWindow| -> Vec<([u8; 32], Option<u64>)> {
        window
            .kernels
            .iter()
            .find(|kernel| kernel.method == auth)
            .unwrap()
            .programs
            .iter()
            .map(|program| (program.id, program.retires_ms))
            .collect()
    };
    assert_eq!(programs(&before), [(one.id, None)]);
    assert_eq!(
        before.formats,
        [FormatWindow {
            format: DEVICE_FORMAT,
            retires_ms: None
        }]
    );
    let (chosen, _, _) = sign_in(&new_app).unwrap();
    assert_eq!(chosen, one.id, "the newest the space admits");

    // The space upgrades its credential actor to release two: both are
    // admitted, release one for 60 days.
    let upgraded = time();
    founded.install(CREDENTIALS, &release_two, "registrar");
    let applied = |first: [u8; 32]| {
        vos_checker::spaces::wait_in_process("the install applied", || {
            programs(&window(&founded, at, CREDENTIALS))[0].0 == first
        });
    };
    applied(two.id);
    let window_two = programs(&window(&founded, at, CREDENTIALS));
    assert_eq!(window_two[0], (two.id, None));
    assert_eq!(window_two[1].0, one.id);
    let retires = window_two[1].1.expect("release one's date");
    // By the leader's batch time, within a second of this node's clock.
    assert!(
        retires + 1_000 >= upgraded + RETIREMENT_MS && retires <= time() + RETIREMENT_MS + 1_000,
        "60 days after the upgrade"
    );

    // The app one release behind signs in, as the member's pseudonym.
    let (chosen, call, proof) = sign_in(&old_app).unwrap();
    assert_eq!(chosen, one.id);
    let made_before = sign_in(&old_app).unwrap();
    match send(&call, &proof) {
        Answer::Ran {
            outcome: Outcome::Done(reply),
            ..
        } => assert_eq!(u32::decode_exact(&reply), Some(1), "the vote counted"),
        other => panic!("the old app's sign-in: {other:?}"),
    }
    // The new app proves with release two: the same nullifier, so the
    // `once` scope admitted it already.
    let (chosen, call, again) = sign_in(&new_app).unwrap();
    assert_eq!(chosen, two.id);
    assert_eq!(
        nullifier(&again),
        nullifier(&proof),
        "one claim in the window"
    );
    assert_eq!(
        send(&call, &again),
        Answer::Refused(CredentialRefusal::Once)
    );
    // The other way round for another member: release two's proof votes,
    // and release one's is refused, its pseudonym admitted once.
    let (chosen, call, proof) = sign_in_as(1, &new_app).unwrap();
    assert_eq!(chosen, two.id);
    assert!(matches!(send(&call, &proof), Answer::Ran { .. }));
    let (_, call, proof) = sign_in_as(1, &old_app).unwrap();
    assert_eq!(
        send(&call, &proof),
        Answer::Refused(CredentialRefusal::Once)
    );

    // The operator retires release one now.
    let retired = smol::block_on(founded.cluster.leading(agent).retire(
        agent,
        CREDENTIALS,
        auth,
        time(),
    ))
    .unwrap();
    assert!(matches!(
        retired,
        vos_node::Reply::Ran(Outcome::Done(ref kept)) if Option::<u64>::decode_exact(kept) == Some(None)
    ));
    vos_checker::spaces::wait_in_process("the retirement applied", || {
        programs(&window(&founded, at, CREDENTIALS)) == [(two.id, None)]
    });
    match sign_in(&old_app) {
        Err(DeviceError::Window) => {}
        other => panic!("the old app proved: {:?}", other.map(|(id, _, _)| id)),
    }
    assert_eq!(
        DeviceError::Window.to_string(),
        "the space admits none of this app's programs for the kernel: the app or the space \
         must update"
    );
    let (_, call, proof) = made_before;
    assert_eq!(
        send(&call, &proof),
        Answer::Refused(CredentialRefusal::Binding),
        "a retired release's proof names a program no guard admits"
    );

    // A rollback to release one keeps release two until its date; then the
    // clock alone closes the window on it.
    founded.install(CREDENTIALS, &release_one, "registrar");
    applied(one.id);
    let two_only = vec![two.clone()];
    assert_eq!(sign_in(&two_only).map(|(id, _, _)| id), Ok(two.id));
    // Ingress and the window read judge a date by the node's clock alone:
    // no batch need run after the clock moves.
    founded
        .cluster
        .offset
        .fetch_add(RETIREMENT_MS as i64 + 60_000, Ordering::SeqCst);
    assert_eq!(
        programs(&window(&founded, at, CREDENTIALS)),
        [(one.id, None)]
    );
    assert!(matches!(sign_in(&two_only), Err(DeviceError::Window)));
    let login = |member: usize| {
        let program = DeviceProgram::from_release(&one).unwrap();
        let call = founded.call(at, POLL, "login", ());
        let proof = founded
            .prover
            .prove_auth(
                &secrets[member].0,
                &witnesses[member],
                b"login",
                &call,
                &program,
            )
            .unwrap();
        (call, proof)
    };
    let (call, proof) = login(0);
    assert!(matches!(send(&call, &proof), Answer::Ran { .. }));

    // The release's one device format cannot be retired in the agent's
    // log: no proven call would run until a release with a newer one.
    let now = time();
    let retire = |format| {
        smol::block_on(
            founded
                .cluster
                .leading(agent)
                .retire_format(agent, format, now),
        )
        .unwrap()
    };
    assert!(matches!(
        retire(DEVICE_FORMAT),
        vos_node::Reply::Ran(Outcome::Failed {
            code: Failure::Forbidden,
            ..
        })
    ));
    assert!(
        matches!(
            retire(44),
            vos_node::Reply::Ran(Outcome::Failed {
                code: Failure::Unknown,
                ..
            })
        ),
        "a format the release never admitted"
    );
    let formats = window(&founded, at, CREDENTIALS).formats;
    assert_eq!(
        formats
            .iter()
            .map(|window| window.format)
            .collect::<Vec<_>>(),
        [DEVICE_FORMAT]
    );
    let (call, proof) = login(1);
    assert!(matches!(send(&call, &proof), Answer::Ran { .. }));
}

/// The device formats' window (`light-node.md` §4.4) at one node: by
/// default it admits 47 alone and refuses a proof of the tests' second
/// format, 48 (`vos_pvm_device::TEST_FORMAT`), `Format`. Restarted admitting both,
/// its window names the stock `auth` kernel's program in each, an app
/// shipping both chooses 47 and one shipping 48 alone chooses 48, and a 47
/// proof is run as its member's pseudonym. Restarted with 48 retired now: a
/// 48 proof made before is refused `Format` at the node's ingress and the
/// app chooses 47. Restarted admitting 48 alone, retired, the node's window
/// is empty. The agent's log retires neither 48, which the release does not
/// admit, nor 47, its newest: 47 proofs still run.
#[test]
fn the_previous_device_format_is_admitted_until_it_is_retired() {
    use vos_light::wire::{self, Answer};
    use vos_light::{DeviceError, Proven};

    let previous = vos_pvm_device::TEST_FORMAT.number;
    assert_eq!((DEVICE_FORMAT, previous), (47, 48));
    let founded = Founded::new();
    let auth = founded.method(CREDENTIALS, "auth");
    let elf = std::fs::read(program_elf("vos-credentials")).unwrap();
    let current = stock(&elf, "auth");
    let other = vos_light::release::devices_in(previous, &elf)
        .unwrap()
        .into_iter()
        .find(|device| device.method == auth)
        .unwrap();
    assert_eq!((current.format, other.format), (DEVICE_FORMAT, previous));
    assert_ne!(current.id, other.id);
    let (both, only_other) = (vec![current.clone(), other.clone()], vec![other.clone()]);

    let at = founded.follower();
    let secrets = [0x51, 0x52, 0x53, 0x54].map(Secret::new);
    for secret in &secrets {
        founded.write(CREDENTIALS, "enroll", secret.member());
    }
    let witnesses = secrets
        .each_ref()
        .map(|secret| witness(&founded.path(secret)));
    let formats = |window: &DeviceWindow| -> Vec<u32> {
        window.formats.iter().map(|format| format.format).collect()
    };
    let programs = |window: &DeviceWindow| -> Vec<([u8; 32], u32)> {
        window
            .kernels
            .iter()
            .find(|kernel| kernel.method == auth)
            .unwrap()
            .programs
            .iter()
            .map(|program| (program.id, program.format))
            .collect()
    };
    // The member's sign-in with the program its app chooses at `at`.
    let sign_in = |member: usize, app: &[Release]| {
        let chosen = vos_light::choose(app, &window(&founded, at, CREDENTIALS), auth)?;
        let program = DeviceProgram::from_release(chosen).unwrap();
        let call = founded.call(at, POLL, "login", ());
        let proof = founded
            .prover
            .prove_auth(
                &secrets[member].0,
                &witnesses[member],
                b"login",
                &call,
                &program,
            )
            .unwrap();
        assert_eq!(proof.format, chosen.format);
        Ok::<_, DeviceError>((chosen.format, call, proof))
    };
    let send = |call: &Call, proof: &Proven| {
        wire::credentialed_answer(&device_send(&founded, at, &wire::credentialed(call, proof)))
            .unwrap()
    };
    // The node restarted admitting `admitted`, then caught up with the
    // leader's applied index, so its forwarded calls reach a leader.
    let restart = |admitted: Vec<(u32, Option<u64>)>| {
        let leading = founded
            .cluster
            .leading(founded.agent)
            .applied(founded.agent);
        founded.cluster.stop(at);
        *founded.cluster.slot(at).device_formats.lock().unwrap() = Some(admitted);
        founded.cluster.start(at);
        vos_checker::spaces::wait_in_process("the node caught up", || {
            founded
                .cluster
                .node(at)
                .is_some_and(|node| node.applied(founded.agent) >= leading)
                && client::devices(founded.cluster.target(at), founded.agent, CREDENTIALS)
                    .ok()
                    .flatten()
                    .is_some_and(|window| {
                        window.formats.is_empty() || !programs(&window).is_empty()
                    })
        });
    };

    // The release's default: 47 alone, a 48 proof refused at once.
    let window_47 = window(&founded, at, CREDENTIALS);
    assert_eq!(formats(&window_47), [DEVICE_FORMAT]);
    assert_eq!(programs(&window_47), [(current.id, DEVICE_FORMAT)]);
    assert!(matches!(sign_in(0, &only_other), Err(DeviceError::Window)));
    let other_program = DeviceProgram::from_release(&other).unwrap();
    let call = founded.call(at, POLL, "login", ());
    let refused = founded
        .prover
        .prove_auth(
            &secrets[0].0,
            &witnesses[0],
            b"login",
            &call,
            &other_program,
        )
        .unwrap();
    assert_eq!(refused.format, previous);
    assert_eq!(
        send(&call, &refused),
        Answer::Refused(CredentialRefusal::Format)
    );

    // Both admitted.
    restart(vec![(DEVICE_FORMAT, None), (previous, None)]);
    let window_both = window(&founded, at, CREDENTIALS);
    assert_eq!(formats(&window_both), [DEVICE_FORMAT, previous]);
    assert_eq!(
        programs(&window_both),
        [(current.id, DEVICE_FORMAT), (other.id, previous)]
    );
    let (format, call, proof) = sign_in(0, &both).unwrap();
    assert_eq!(format, DEVICE_FORMAT, "the newest format admitted");
    assert!(matches!(send(&call, &proof), Answer::Ran { .. }));
    let made_before = sign_in(2, &only_other).unwrap();
    assert_eq!(made_before.0, previous);

    // 48 retired now: its proof refused, the app back on 47.
    let now = client::time(founded.cluster.target(at)).unwrap();
    restart(vec![(DEVICE_FORMAT, None), (previous, Some(now))]);
    assert_eq!(formats(&window(&founded, at, CREDENTIALS)), [DEVICE_FORMAT]);
    let (_, call, proof) = made_before;
    assert_eq!(
        send(&call, &proof),
        Answer::Refused(CredentialRefusal::Format)
    );
    assert!(matches!(sign_in(2, &only_other), Err(DeviceError::Window)));
    let (format, call, proof) = sign_in(2, &both).unwrap();
    assert_eq!(format, DEVICE_FORMAT);
    assert!(matches!(send(&call, &proof), Answer::Ran { .. }));

    // 48 alone, retired: no format.
    restart(vec![(previous, Some(now))]);
    assert!(window(&founded, at, CREDENTIALS).formats.is_empty());
    assert!(matches!(sign_in(3, &both), Err(DeviceError::Window)));

    // The agent's log retires only a format the release admits, and not
    // its newest: 47 stays admitted, through a restart too.
    let retire = |format| {
        smol::block_on(founded.cluster.leading(founded.agent).retire_format(
            founded.agent,
            format,
            now,
        ))
        .unwrap()
    };
    for (format, code) in [
        (previous, Failure::Unknown),
        (DEVICE_FORMAT, Failure::Forbidden),
    ] {
        assert!(
            matches!(
                retire(format),
                vos_node::Reply::Ran(Outcome::Failed { code: failed, .. }) if failed == code
            ),
            "format {format}"
        );
    }
    restart(vec![(DEVICE_FORMAT, None)]);
    assert_eq!(formats(&window(&founded, at, CREDENTIALS)), [DEVICE_FORMAT]);
    let (format, call, proof) = sign_in(3, &both).unwrap();
    assert_eq!(format, DEVICE_FORMAT);
    assert!(matches!(send(&call, &proof), Answer::Ran { .. }));
}

/// A device format the release does not admit binds every replica, whatever
/// one node admits: a follower restarted admitting the tests' 48 passes an
/// honest 48 proof at its ingress and forwards it to the leader, which
/// admits 47 alone, and apply refuses it `Format` on every replica, so it
/// runs nowhere.
#[test]
fn a_format_the_release_does_not_admit_is_refused_at_apply() {
    let previous = vos_pvm_device::TEST_FORMAT.number;
    let founded = Founded::new();
    let auth = founded.method(CREDENTIALS, "auth");
    let elf = std::fs::read(program_elf("vos-credentials")).unwrap();
    let other = vos_light::release::devices_in(previous, &elf)
        .unwrap()
        .into_iter()
        .find(|device| device.method == auth)
        .unwrap();
    let at = founded.follower();
    let secret = Secret::new(0x61);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let leading = founded
        .cluster
        .leading(founded.agent)
        .applied(founded.agent);
    founded.cluster.stop(at);
    *founded.cluster.slot(at).device_formats.lock().unwrap() =
        Some(vec![(DEVICE_FORMAT, None), (previous, None)]);
    founded.cluster.start(at);
    vos_checker::spaces::wait_in_process("the node caught up", || {
        founded
            .cluster
            .node(at)
            .is_some_and(|node| node.applied(founded.agent) >= leading)
    });
    assert_ne!(founded.cluster.leader(founded.agent), Some(at));
    let logins: u64 = founded.read(POLL, "logins", ());
    let path = founded.path(&secret);
    let call = founded.call(at, POLL, "login", ());
    let proof = founded
        .prover
        .prove_auth(
            &secret.0,
            &witness(&path),
            b"login",
            &call,
            &DeviceProgram::from_release(&other).unwrap(),
        )
        .unwrap();
    assert_eq!(proof.format, previous);
    assert_eq!(
        founded.send(at, &request(&call, proof)),
        Response::Refused(Refusal::Format)
    );
    let after: u64 = founded.read(POLL, "logins", ());
    assert_eq!(after, logins, "run nowhere");
}

/// A replica that has not applied the operator's retirement of release one
/// still admits release one's proof at ingress, its window as it applied
/// it, and forwards it; the leader's apply refuses it `Release`, and it
/// runs nowhere.
#[test]
fn a_retired_release_is_refused_at_apply_behind_a_lagging_replica() {
    let founded = Founded::new();
    let agent = founded.agent;
    let auth = founded.method(CREDENTIALS, "auth");
    let elf = |path: std::path::PathBuf| std::fs::read(path).unwrap();
    let one = stock(&elf(program_elf("vos-credentials")), "auth");
    let at = founded.follower();
    let secret = Secret::new(0x62);
    founded.write(CREDENTIALS, "enroll", secret.member());
    let path = founded.path(&secret);
    founded.install(
        CREDENTIALS,
        &elf(actor_elf("credentials-next")),
        "registrar",
    );
    let leading = founded.cluster.leading(agent).applied(agent);
    vos_checker::spaces::wait_in_process("the install applied", || {
        founded
            .cluster
            .node(at)
            .is_some_and(|node| node.applied(agent) >= leading)
    });
    let admits_one = || {
        window(&founded, at, CREDENTIALS)
            .kernels
            .iter()
            .any(|kernel| kernel.programs.iter().any(|program| program.id == one.id))
    };
    assert!(admits_one(), "release one in the window after the upgrade");
    let logins: u64 = founded.read(POLL, "logins", ());
    let call = founded.call(at, POLL, "login", ());
    let proof = founded
        .prover
        .prove_auth(
            &secret.0,
            &witness(&path),
            b"login",
            &call,
            &DeviceProgram::from_release(&one).unwrap(),
        )
        .unwrap();
    let answer = {
        let _held = founded.cluster.slot(at).trip.commits.close();
        let now = client::time(founded.cluster.target(at)).unwrap();
        let retired = smol::block_on(founded.cluster.leading(agent).retire(
            agent,
            CREDENTIALS,
            auth,
            now,
        ))
        .unwrap();
        assert!(matches!(retired, vos_node::Reply::Ran(Outcome::Done(_))));
        assert!(admits_one(), "the lagging replica has not applied it");
        founded.send(at, &request(&call, proof))
    };
    assert_eq!(answer, Response::Refused(Refusal::Release));
    let after: u64 = founded.read(POLL, "logins", ());
    assert_eq!(after, logins, "run nowhere");
}

/// The tree kept from its feed: a follower's feed read page by page into
/// the device's keeper, no query naming the member; the path it computes
/// the actor's `path`; its proof, against the newest root, admitted by a
/// follower's ingress and run. Enrollments since are read alone, from the
/// keeper's place, and a proof at the new root is admitted too.
#[test]
fn a_proof_from_the_tree_kept_from_its_feed_is_admitted() {
    use vos_light::wire::{self, Answer};

    let founded = Founded::new();
    let at = founded.follower();
    let agent = founded.agent;
    let secret = vos_light::derive_secret(&[0x5f; 32], &[0x42; 32]);
    let mine = vos_light::member(&secret);
    for batch in 0..6u32 {
        let members: Vec<Digest> = (0..ENROLL_MANY as u32)
            .map(|seed| Secret::new(1_000 * batch + seed).member())
            .collect();
        founded.write(CREDENTIALS, "enroll_many", members);
    }
    founded.write(CREDENTIALS, "enroll", mine.to_bytes());
    let time = || client::time(founded.cluster.target(at)).unwrap();
    let identity = founded.operator.lock().unwrap().identity(agent).unwrap();
    let mut keeper = vos_light::TreeKeeper::new(mine);
    // Every page from the follower, whose applied state the last
    // enrollment reaches once it replicates.
    let read = |keeper: &mut vos_light::TreeKeeper| {
        let mut pages = 0;
        loop {
            let query = keeper
                .request(agent.0, &identity, CREDENTIALS.0, time() + 60_000)
                .unwrap();
            pages += 1;
            if !keeper
                .ingest(&device_send(&founded, at, &query), time())
                .unwrap()
                .more
            {
                return pages;
            }
        }
    };
    vos_checker::wait_until(
        "the follower's feed holds the member",
        Duration::from_secs(30),
        || {
            read(&mut keeper);
            keeper.slot().is_some()
        },
    );
    assert_eq!(keeper.cursor(), 7);
    let path: Option<Path> = founded.read(CREDENTIALS, "path", mine.to_bytes());
    let witness = keeper.witness().unwrap();
    assert_eq!(Some(witness.clone()), path.as_ref().map(self::witness));
    let root: RootEntry = founded.read(CREDENTIALS, "root", ());
    assert_eq!(keeper.root(), root);

    let prover = vos_light::Prover::new(vos_light::ProverConfig {
        threads: vos_light::Threads::Count(4),
        ..vos_light::ProverConfig::default()
    })
    .unwrap();
    let login = || {
        vos_light::Call::new(
            founded.space.0,
            agent.0,
            POLL.0,
            founded.method(POLL, "login").0,
            ().encode(),
            time() + 60_000,
        )
        .unwrap()
    };
    let prove = |keeper: &vos_light::TreeKeeper| {
        let call = login();
        let proof = prover
            .prove_auth(
                &secret,
                &keeper.witness().unwrap(),
                b"login",
                &call,
                &founded.auth,
            )
            .unwrap();
        let claim = AuthClaim::decode_exact(&proof.claim).unwrap();
        assert_eq!(claim.map_root, keeper.root().root, "the newest root");
        wire::credentialed_answer(&device_send(
            &founded,
            at,
            &wire::credentialed(&call, &proof),
        ))
    };
    assert!(matches!(
        prove(&keeper),
        Ok(Answer::Ran {
            outcome: Outcome::Done(_),
            ..
        })
    ));

    founded.write(CREDENTIALS, "enroll", Secret::new(9_999).member());
    founded.write(CREDENTIALS, "revoke", Secret::new(3).member());
    vos_checker::wait_until(
        "the follower's feed holds the revocation",
        Duration::from_secs(30),
        || {
            assert_eq!(read(&mut keeper), 1, "one page holds what changed since");
            keeper.cursor() == 9
        },
    );
    let root: RootEntry = founded.read(CREDENTIALS, "root", ());
    assert_eq!(keeper.root(), root);
    assert!(matches!(
        prove(&keeper),
        Ok(Answer::Ran {
            outcome: Outcome::Done(_),
            ..
        })
    ));
}
