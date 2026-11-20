//! The carrier audit over proven calls (`identity-and-authority.md` §5,
//! `node/light/SECURITY.md`): three nodes of a founded space with the
//! credential actor, the poll, the ledger and the device actor; a
//! member's device secret derived from a known source output, its path
//! computed from the tree's feed, and its calls proved by the device
//! library as a phone proves them, by the stock kernels' release
//! artifacts, and sent to the nodes over each transport: the API's socket,
//! and a gateway relaying HTTP onto the API over QUIC. Then every carrier the run produced is searched for
//! the member's secret, which only the device holds, and for where the
//! member sits, which a proven call never carries
//! ([`vos_checker::carriers`]).
//!
//! The calls: auth sign-ins by the stock `auth` kernel, a replay
//! (`Replayed`), a `once` vote and a second (`Once`), a proof cut by a
//! byte (`Proof`), another call's arguments (`Binding`), an expired call
//! (`Expiry`), an unregistered format (`Format`), an owner's payment by the
//! stock `owner` kernel, an actor's own kernel's sign-in (the device
//! actor's hand-lean `auth`, its claim checked by the handler), its replay
//! and its proof sent to a stock guard (`Kind`), a frame of no kind and
//! one past its kind's limit (`FrameError`), each on a connection the
//! device keeps for its calls; its time and the tree's feed read on one of
//! their own.
//!
//! Carriers that leave the device: every byte of each API connection each
//! way, every request and its answer's status and body through the
//! gateway, each
//! credentialed call's log entry on each node, the device library's
//! values as its `Debug` and `Display` show them, every log line of the
//! process at every level (the nodes', the gateway's), and standard
//! error. Searched there: the secret (`s`'s single words among it), the
//! proofs' masks and the member's place, but in the feed's connection,
//! which holds the whole tree by design.
//! Carriers within the replicas (their stores, logs, work results, disks
//! and frames), which hold the members' digests and the tree, are searched
//! for the secret and the masks.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_abi::credentials as tree;
use vos_abi::credentials::{Tag, Words};
use vos_abi::ids::{AgentId, InstanceId};
use vos_abi::result::{InputRef, Outcome, Step, WorkResult};
use vos_abi::{Decode, Encode, SpaceId, WindowClock};
use vos_api::{Event, FRAME_ERROR, Frame, FrameError, Framing, Kind as ApiKind, Reader};
use vos_checker::Nodes;
use vos_checker::carriers::{self, Audit, Kind, Logs, Reach};
use vos_checker::processes::Front;
use vos_checker::programs::{actor, actor_elf, method, program, program_elf};
use vos_light::wire::{self, Answer};
use vos_light::{
    AuthWitness, Call, DEVICE_FORMAT, DeviceError, DeviceProgram, Proven, Prover, ProverConfig,
    Threads, TreeKeeper,
};
use vos_node::client::{self, Client, Target};
use vos_node::store::EntryKind;
use vos_pvm_recair::masked::{MaskRng, drawn_in};
use vos_wire::credentials::{AuthClaim, Path, Siblings, scope};
use vos_wire::ingress::{CredentialRefusal, Credentialed, Response};
use vos_wire::peer::NodeNumber;

use crate::harness::{Cluster, NODES, assert_done};

/// The hub's seed: odd, so the operator's client reaches the nodes over
/// the API's sockets.
const SEED: u64 = 11;
const PAYMENTS: InstanceId = InstanceId(2);
const POLL: InstanceId = InstanceId(3);
const DEVICE: InstanceId = InstanceId(4);
const CREDENTIALS: InstanceId = InstanceId(9);
/// The registrar's and the operator's role byte: one key holds both.
const ROLE: u8 = 1;
const OPERATOR: [u8; 32] = [21; 32];
/// The gateway's QUIC key's seed, which every node lists.
const GATEWAY: [u8; 32] = [0x9a; 32];
/// The space's handle, which the member's secret source is asked for.
const HANDLE: [u8; 32] = [0x48; 32];
/// Members enrolled after the audited one, so its path's lowest siblings
/// are occupied.
const OTHERS: u32 = 7;

/// What each capture path is sent once, to show it captures: a log line
/// from a gateway's task, a line on standard error, and a request on the
/// device's connection.
const CANARY: &str = "credential-carrier-canary";

/// The member's secret source's output: high in entropy, so a carrier
/// holding it is found.
fn source_output() -> [u8; 32] {
    vos_abi::vos_anchor::blake2b_256(&[b"the carrier audit's secret source"])
}

/// One connection to a node's API socket, every byte each way kept: the
/// transport a device's requests take to a node.
struct Socket {
    stream: UnixStream,
    reader: Reader,
    next: u64,
    sent: Vec<u8>,
    received: Vec<u8>,
}

impl Socket {
    fn connect(path: &std::path::Path) -> Self {
        let stream = UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .unwrap();
        Self {
            stream,
            reader: Reader::answers(Framing::Stream),
            next: 0,
            sent: Vec::new(),
            received: Vec::new(),
        }
    }

    /// `bytes` written as they are: the next answer's frame.
    fn write(&mut self, bytes: &[u8]) -> Frame {
        self.stream.write_all(bytes).unwrap();
        self.sent.extend_from_slice(bytes);
        let mut chunk = vec![0; 64 << 10];
        loop {
            match self.reader.event() {
                // The mark carries nothing of the request: an answer's is
                // none.
                Some(Event::Frame(frame)) => {
                    assert_eq!(frame.mark, vos_api::Mark::Unmarked, "an answer's mark");
                    return frame;
                }
                Some(Event::Error { error, .. }) => panic!("an answer's framing: {error:?}"),
                None => {}
            }
            let read = self.stream.read(&mut chunk).unwrap();
            assert!(read > 0, "the node closed the connection");
            self.received.extend_from_slice(&chunk[..read]);
            self.reader.push(&chunk[..read]);
        }
    }

    /// A device request (its kind, then its body) as a frame: the
    /// answer's body.
    fn send(&mut self, request: &[u8]) -> Vec<u8> {
        self.next += 1;
        let kind = u16::from_le_bytes([request[0], request[1]]);
        let frame = self.write(&vos_api::frame(
            Framing::Stream,
            kind,
            self.next,
            &request[2..],
        ));
        assert_eq!(frame.id, self.next);
        assert_ne!(frame.kind, FRAME_ERROR, "a frame error");
        frame.body
    }

    /// Its bytes each way, as carriers that leave the device.
    fn carriers(&self, audit: &mut Audit, name: &str) {
        audit.carrier(format!("{name}: sent"), Reach::Leaves, self.sent.clone());
        audit.carrier(
            format!("{name}: received"),
            Reach::Leaves,
            self.received.clone(),
        );
    }
}

/// The founded space's agent, its programs installed and the operator's
/// client.
struct Founded {
    cluster: Cluster,
    agent: AgentId,
    space: SpaceId,
    operator: std::sync::Mutex<Client>,
}

impl Founded {
    fn new() -> Self {
        let cluster = Cluster::founded(SEED, Some(WindowClock::DEFAULT));
        let elf = |path: std::path::PathBuf| std::fs::read(path).unwrap();
        let elfs = [
            elf(program_elf("vos-credentials")),
            elf(actor_elf("poll")),
            elf(program_elf("vos-payments")),
            elf(actor_elf("device")),
        ];
        let installs = [
            (CREDENTIALS, &elfs[0][..], "registrar"),
            (POLL, &elfs[1][..], "operator"),
            (PAYMENTS, &elfs[2][..], "operator"),
            (DEVICE, &elfs[3][..], "operator"),
        ];
        let (agent, operator) =
            cluster.found_agent(&installs, ROLE, SigningKey::from_bytes(&OPERATOR));
        let space = cluster.space.id();
        let founded = Self {
            cluster,
            agent,
            space,
            operator: std::sync::Mutex::new(operator),
        };
        founded.write(CREDENTIALS, "found", [0x42u8; 32]);
        founded
    }

    fn method(&self, instance: InstanceId, name: &str) -> u32 {
        let program = match instance {
            CREDENTIALS => program("vos-credentials"),
            POLL => actor("poll"),
            PAYMENTS => program("vos-payments"),
            _ => actor("device"),
        };
        method(&program, name).0
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
                vos_abi::ids::MethodId(self.method(instance, name)),
                &arguments.encode(),
            )
            .unwrap();
        assert_done(name, &answer);
    }

    fn time(&self, at: NodeNumber) -> u64 {
        client::time(self.cluster.target(at)).unwrap()
    }

    /// A call of `instance`'s `name` with `arguments`, good for a minute by
    /// node `at`'s clock.
    fn call<A: Encode>(
        &self,
        at: NodeNumber,
        instance: InstanceId,
        name: &str,
        arguments: A,
    ) -> Call {
        Call::new(
            self.space.0,
            self.agent.0,
            instance.0,
            self.method(instance, name),
            arguments.encode(),
            self.time(at) + 60_000,
        )
        .unwrap()
    }
}

/// Another member's secret words.
fn other(seed: u32) -> Words {
    core::array::from_fn(|i| seed * 1_000 + i as u32 + 1)
}

/// The credentialed request `call` under `proof`, as the HTTP routes take
/// it: the device's request after its kind and the agent.
fn request(call: &Call, proof: &Proven) -> Credentialed {
    Credentialed::decode_exact(&wire::credentialed(call, proof)[6..]).unwrap()
}

#[track_caller]
fn ran(answer: Result<Answer, DeviceError>) -> Answer {
    match answer {
        Ok(
            answer @ Answer::Ran {
                outcome: Outcome::Done(_),
                ..
            },
        ) => answer,
        other => panic!("not run: {other:?}"),
    }
}

#[track_caller]
fn refused(answer: Result<Answer, DeviceError>, code: CredentialRefusal) -> Answer {
    assert_eq!(answer, Ok(Answer::Refused(code)));
    answer.unwrap()
}

/// The steps of `agent`'s work results on `node` that ran or refused a
/// credentialed call: its log entries as the operators read them.
fn credentialed_steps(node: &vos_node::Node, agent: AgentId) -> Vec<Step> {
    let through = node.applied(agent).unwrap_or(0);
    (1..=through)
        .filter_map(|index| node.probes().store().log_entry(agent, index).ok().flatten())
        .filter(|entry| entry.kind == EntryKind::Result)
        .filter_map(|entry| WorkResult::decode(&entry.body).ok())
        .flat_map(|(result, _)| result.steps)
        .filter(|step| match step {
            Step::Ran(run) => matches!(run.input, InputRef::Credentialed { .. }),
            Step::Refused { input, .. } => matches!(input, InputRef::Credentialed { .. }),
            Step::Swept { .. } => false,
        })
        .collect()
}

#[test]
fn no_carrier_holds_a_members_device_secret_or_its_place() {
    crate::debug_environment();
    let stderr = carriers::Stderr::capture(std::path::Path::new(env!("CARGO_TARGET_TMPDIR")));
    let logs = Logs::install();
    let founded = Founded::new();
    let frames = carriers::tap_frames(&founded.cluster.hub);
    let agent = founded.agent;
    let leader = founded.cluster.leader(agent).unwrap();
    let at = leader % NODES + 1;

    // The member, enrolled first, then the others after it.
    let mut audit = Audit::default();
    let words = audit
        .needles
        .device_secret("the member", &source_output(), &HANDLE);
    let secret = vos_light::derive_secret(&source_output(), &HANDLE);
    let member = vos_light::member(&secret);
    assert_eq!(
        member.to_bytes(),
        tree::digest(&tree::compress(&Tag::Member.block(), &words)),
        "the audit's secret is the library's"
    );
    founded.write(CREDENTIALS, "enroll", member.to_bytes());
    for seed in 1..=OTHERS {
        let digest = tree::digest(&tree::compress(&Tag::Member.block(), &other(seed)));
        founded.write(CREDENTIALS, "enroll", digest);
    }

    // Its time and the tree's feed, on a connection of their own.
    let mut fetch = Socket::connect(&founded.cluster.dir(at).join("api.sock"));
    let mut device_values: Vec<String> = Vec::new();
    let now = wire::time_answer(&fetch.send(&wire::time_request())).unwrap();
    let identity = founded.operator.lock().unwrap().identity(agent).unwrap();
    let read = |socket: &mut Socket, keeper: &mut TreeKeeper| loop {
        let query = keeper
            .request(agent.0, &identity, CREDENTIALS.0, now + 60_000)
            .unwrap();
        if !keeper.ingest(&socket.send(&query), 0).unwrap().more {
            break;
        }
    };
    let mut leader_tree = TreeKeeper::new(member);
    read(
        &mut Socket::connect(&founded.cluster.dir(leader).join("api.sock")),
        &mut leader_tree,
    );
    let leader_root = leader_tree.root();
    // The follower answers from what it has applied: its feed read again
    // until its tree is at the leader's root.
    let mut keeper = TreeKeeper::new(member);
    vos_checker::wait_until(
        "the follower's tree is at the leader's root",
        Duration::from_secs(60),
        || {
            read(&mut fetch, &mut keeper);
            keeper.root() == leader_root
        },
    );
    let witness: AuthWitness = keeper.witness().expect("an enrolled member's path");
    let root = keeper.root();
    device_values.push(format!("{witness:?} {root:?}"));
    let path = Path {
        root: witness.root.to_bytes(),
        slot: witness.slot,
        siblings: Siblings(witness.siblings.map(|sibling| sibling.to_bytes())),
    };
    audit
        .needles
        .member_place("the member", &member.to_bytes(), &path);
    assert!(
        audit.needles.named(Kind::MemberPlace, "sibling").count() >= 3,
        "the path's lowest siblings are occupied"
    );

    let prover = Prover::new(ProverConfig {
        threads: Threads::Count(4),
        ..ProverConfig::default()
    })
    .unwrap();
    let credentials_elf = std::fs::read(program_elf("vos-credentials")).unwrap();
    let stock = |kernel| vos_light::release::device(&credentials_elf, kernel).unwrap();
    let (auth, owner_kernel) = (stock("auth"), stock("owner"));
    let auth_program = DeviceProgram::from_release(&auth).unwrap();
    let owner_program = DeviceProgram::from_release(&owner_kernel).unwrap();
    let mut calls = Socket::connect(&founded.cluster.dir(at).join("api.sock"));
    let mut send = |call: &Call, proof: &Proven| {
        wire::credentialed_answer(&calls.send(&wire::credentialed(call, proof)))
    };
    let mut answers: Vec<Answer> = Vec::new();

    // Auth: a sign-in, its replay, a `once` vote and a second.
    let login = founded.call(at, POLL, "login", ());
    let signin = prover
        .prove_auth(&secret, &witness, b"login", &login, &auth_program)
        .unwrap();
    answers.push(ran(send(&login, &signin)));
    answers.push(refused(send(&login, &signin), CredentialRefusal::Replayed));
    let vote = founded.call(at, POLL, "vote", 1u8);
    let voted = prover
        .prove_auth(&secret, &witness, b"vote", &vote, &auth_program)
        .unwrap();
    answers.push(ran(send(&vote, &voted)));
    let again = founded.call(at, POLL, "vote", 2u8);
    let voted_again = prover
        .prove_auth(&secret, &witness, b"vote", &again, &auth_program)
        .unwrap();
    answers.push(refused(send(&again, &voted_again), CredentialRefusal::Once));

    // Refused: a proof cut by a byte, another call's arguments, an expired
    // call and an unregistered format.
    let fresh = founded.call(at, POLL, "login", ());
    let mut proof = prover
        .prove_auth(&secret, &witness, b"login", &fresh, &auth_program)
        .unwrap();
    let whole = proof.clone();
    proof.proof.pop();
    answers.push(refused(send(&fresh, &proof), CredentialRefusal::Proof));
    let other_arguments = Call {
        arguments: CANARY.as_bytes().to_vec().encode(),
        ..fresh.clone()
    };
    answers.push(refused(
        send(&other_arguments, &whole),
        CredentialRefusal::Binding,
    ));
    let expired = Call {
        expires_ms: founded.time(at) - 1_000,
        ..fresh.clone()
    };
    let answer = send(&expired, &whole);
    assert!(matches!(answer, Ok(Answer::Expiry { .. })), "{answer:?}");
    answers.push(answer.unwrap());
    let unregistered = Proven {
        format: 38,
        ..whole.clone()
    };
    answers.push(refused(
        send(&fresh, &unregistered),
        CredentialRefusal::Format,
    ));
    answers.push(ran(send(&fresh, &whole)));

    // Owner: a payment from the account the member's owner digest holds.
    let owner = vos_light::owner(&secret).to_bytes();
    let expires = founded.time(at) + 60_000;
    let shop = tree::digest(&tree::compress(&Tag::Owner.block(), &other(1)));
    for (name, digest) in [("device", owner), ("shop", shop)] {
        let name = name.as_bytes().to_vec();
        founded.write(PAYMENTS, "invite", (name.clone(), digest, expires));
        founded.write(PAYMENTS, "open", (name.clone(), digest));
        founded.write(PAYMENTS, "mint", (name, 50u64));
    }
    let pay = founded.call(at, PAYMENTS, "transfer", (b"shop".to_vec(), 20u64));
    let paid = prover.prove_owner(&secret, &pay, &owner_program).unwrap();
    answers.push(ran(send(&pay, &paid)));

    // An actor's own kernel's sign-in, its replay, and its proof sent to a
    // stock guard.
    let device = vos_light::release::device(&vos_testkit::programs::package("device"), "auth");
    let program = DeviceProgram::from_release(&device.unwrap()).unwrap();
    let siblings = witness.siblings.map(|sibling| sibling.0);
    let device_proof_of = |call: &Call| {
        let scope = scope(&founded.space, agent, DEVICE, b"login");
        let nullifier = tree::digest(&tree::compress(
            &tree::compress(&Tag::Nf.block(), &words),
            &tree::words(&scope).unwrap(),
        ));
        let public = vos_pvm_device::auth_public(
            &witness.root.to_bytes(),
            &scope,
            &nullifier,
            &call.binding(&program.id().0).to_bytes(),
        );
        let arguments = vos_pvm_device::auth_arguments(&siblings, &words, witness.slot, &public);
        let proof = prover.prove_kernel(&program, &arguments).unwrap();
        (
            Proven {
                format: DEVICE_FORMAT,
                claim: public.to_vec(),
                proof: proof.proof,
            },
            arguments,
        )
    };
    let device_login = founded.call(at, DEVICE, "login", ());
    let (device_proof, arguments) = device_proof_of(&device_login);
    answers.push(ran(send(&device_login, &device_proof)));
    answers.push(refused(
        send(&device_login, &device_proof),
        CredentialRefusal::Replayed,
    ));
    let to_poll = founded.call(at, POLL, "login", ());
    let (to_poll_proof, _) = device_proof_of(&to_poll);
    answers.push(refused(
        send(&to_poll, &to_poll_proof),
        CredentialRefusal::Kind,
    ));
    audit
        .needles
        .kernel_arguments("the member's device kernel", &arguments, 129);

    // A sign-in by the stock kernel proved on this thread, its masks'
    // randomness watched; its arguments as the kernel reads them.
    let watched = founded.call(at, POLL, "login", ());
    let scope = vos_light::scope(&founded.space.0, agent.0, POLL.0, b"login").unwrap();
    let nullifier = tree::compress(&tree::compress(&Tag::Nf.block(), &words), &scope.0);
    let claim = AuthClaim {
        map_root: witness.root.to_bytes(),
        scope: scope.to_bytes(),
        nullifier: tree::digest(&nullifier),
        binding: watched.binding(&auth_program.id().0).to_bytes(),
    }
    .encode();
    let mut arguments = path.siblings.0.concat();
    arguments.extend_from_slice(&u64::from(witness.slot).to_le_bytes());
    arguments.extend_from_slice(&tree::digest(&words));
    arguments.extend_from_slice(&claim);
    audit
        .needles
        .kernel_arguments("the member", &arguments, claim.len());
    let kernel = vos_pvm_device::Program::from_release(&auth).unwrap();
    // On a prover's pool of this thread's own making: the watch is the
    // thread's, and a prover on a pool of its own (when another caller
    // built rayon's global one first) draws on its workers.
    let pool = vos_light::thread_pool(&vos_light::Threads::Count(2)).unwrap();
    let ((proved, _), drawn) =
        pool.install(|| drawn_in(|| kernel.prove(&arguments, MaskRng::default()).unwrap()));
    let drawn: Vec<(&str, Vec<u8>)> = drawn.into_iter().map(|d| (d.what, d.bytes)).collect();
    for what in [
        "an attempt's entropy",
        "an attempt's seed",
        "the witness digest",
    ] {
        assert!(
            drawn.iter().any(|(drawn, _)| *drawn == what),
            "the watch saw {what}"
        );
    }
    audit.needles.drawn("a sign-in", &drawn);
    let watched_proof = Proven {
        format: DEVICE_FORMAT,
        claim,
        proof: vos_pvm_device::encode(&vos_pvm_device::FORMAT, &proved.proof).unwrap(),
    };
    answers.push(ran(send(&watched, &watched_proof)));

    // A gateway relaying onto the nodes' API over QUIC.
    let gateway_key = SigningKey::from_bytes(&GATEWAY).verifying_key().to_bytes();
    let upstreams = founded
        .cluster
        .space
        .nodes()
        .iter()
        .map(|node| {
            let address = founded
                .cluster
                .node(node.number)
                .unwrap()
                .serve_quic("127.0.0.1:0".parse().unwrap(), vec![gateway_key])
                .unwrap();
            (node.key, format!("quic://{address}"))
        })
        .collect();
    let front = Front::serve(upstreams, GATEWAY);
    // Each request's bytes and each answer's status and body as they came.
    let mut https: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new();
    let mut post = |name: String, target: &Target, call: &Credentialed| {
        let body = call.encode();
        let (status, answer) =
            client::send(target, ApiKind::Credentialed, &client::naming(agent, &body)).unwrap();
        let decoded = Response::decode_exact(&answer).expect("an answer");
        let kept = [
            status.to_string().into_bytes(),
            answer,
            format!("{decoded:?}").into_bytes(),
        ]
        .concat();
        https.push((
            name,
            [body, format!("{call:?}").into_bytes()].concat(),
            kept,
        ));
        decoded
    };
    let target = front.target();
    let call = founded.call(at, POLL, "login", ());
    let proof = prover
        .prove_auth(&secret, &witness, b"login", &call, &auth_program)
        .unwrap();
    let mut cut = request(&call, &proof);
    cut.proof.pop();
    let answer = post("the gateway: a cut proof".to_string(), target, &cut);
    assert_eq!(
        answer,
        Response::Rejected(vos_wire::ingress::Rejection::Credential(
            CredentialRefusal::Proof
        ))
    );
    let answer = post(
        "the gateway: a sign-in".to_string(),
        target,
        &request(&call, &proof),
    );
    assert!(
        matches!(
            answer,
            Response::Ran {
                outcome: Outcome::Done(_),
                ..
            }
        ),
        "{answer:?}"
    );

    // Frame errors, each closing its connection: a frame of no kind, and
    // one past its kind's limit, from its header.
    let mut errors = Vec::new();
    for (name, bytes) in [
        (
            "no kind",
            vos_api::frame(Framing::Stream, 0x7f7f, 1, CANARY.as_bytes()),
        ),
        (
            "past its limit",
            vos_api::Header::of(
                Framing::Stream,
                ApiKind::Credentialed as u16,
                1,
                ApiKind::Credentialed.limit() as usize + 1,
            )
            .encode(Framing::Stream),
        ),
    ] {
        let mut socket = Socket::connect(&founded.cluster.dir(at).join("api.sock"));
        let frame = socket.write(&bytes);
        assert_eq!(frame.kind, FRAME_ERROR, "{name}");
        let error = FrameError::decode_exact(&frame.body).unwrap();
        device_values.push(format!("{error:?}"));
        errors.push((name, socket));
    }

    // The canaries: a request on the device's connection, a log line from
    // a gateway's task and a line on standard error.
    let mut canary = request(&fresh, &whole);
    canary.arguments = CANARY.as_bytes().to_vec();
    let _ = calls.send(
        &[
            (ApiKind::Credentialed as u16).to_le_bytes().to_vec(),
            (agent, canary).encode(),
        ]
        .concat(),
    );
    front.run(async { tracing::trace!(canary = CANARY, "a gateway's task") });
    eprintln!("{CANARY}: standard error");

    // The device library's values, as a client's log would show them.
    for answer in &answers {
        device_values.push(format!("{answer:?}"));
    }
    for call in [&login, &vote, &pay, &device_login, &watched] {
        device_values.push(format!("{call:?}"));
    }
    for proof in [&signin, &paid, &device_proof, &watched_proof] {
        device_values.push(format!(
            "{proof:?} {:?}",
            AuthClaim::decode_exact(&proof.claim)
        ));
    }
    for error in [
        DeviceError::Config,
        DeviceError::Memory,
        DeviceError::Witness,
        DeviceError::Prove,
        DeviceError::Program(vos_pvm_device::Error::Fit),
        DeviceError::Program(vos_pvm_device::Error::Ceiling { chip: 0, needs: 18 }),
        DeviceError::Decode,
        DeviceError::Verify,
    ] {
        device_values.push(format!("{error} {error:?}"));
    }
    let refusals = [
        prover
            .prove_auth(&secret, &witness, b"", &login, &auth_program)
            .unwrap_err(),
        prover
            .prove_auth(
                &vos_light::derive_secret(&[1; 32], &HANDLE),
                &witness,
                b"login",
                &login,
                &auth_program,
            )
            .unwrap_err(),
        wire::feed_answer(&[0xff]).unwrap_err(),
        vos_light::verify(&proof, &fresh, &auth_program, Some(b"login")).unwrap_err(),
    ];
    for error in refusals {
        device_values.push(format!("{error} {error:?}"));
    }
    device_values.push(format!("{:?}", ProverConfig::default()));

    // What leaves the device.
    calls.carriers(&mut audit, "the calls' connection");
    for (name, socket) in &errors {
        socket.carriers(&mut audit, &format!("a frame {name}"));
    }
    for (name, request, answer) in https {
        audit.carrier(format!("{name}: the request"), Reach::Leaves, request);
        audit.carrier(format!("{name}: the answer"), Reach::Leaves, answer);
    }
    audit.carrier(
        "the device library's values",
        Reach::Leaves,
        device_values.join("\n").into_bytes(),
    );
    let applied = credentialed_steps(&founded.cluster.node(at).unwrap(), agent).len();
    assert!(applied >= 7, "the calls run, {applied} logged");
    for number in 1..=NODES {
        let node = founded.cluster.node(number).unwrap();
        vos_checker::wait_until(
            "every replica applied the calls",
            Duration::from_secs(60),
            || credentialed_steps(&node, agent).len() >= applied,
        );
        let steps = credentialed_steps(&node, agent);
        audit.carrier(
            format!("node {number}: the credentialed calls' log entries"),
            Reach::Leaves,
            [steps.encode(), format!("{steps:?}").into_bytes()].concat(),
        );
    }

    // The feed holds the whole tree, the member's leaf and its siblings
    // among it, by design: searched for the secret, the masks and the
    // member's digest, which no query names.
    let mut fetched = Audit::default();
    fetched.needles.0 = audit
        .needles
        .0
        .iter()
        .filter(|needle| {
            needle.kind != Kind::MemberPlace || needle.name.ends_with("the member digest")
        })
        .cloned()
        .collect();
    fetch.carriers(&mut fetched, "the fetch's connection");

    // What stays within the replicas: every frame, each node's log, work
    // results, prover table, store and disk.
    for ((to, class), bytes) in frames.lock().unwrap().iter() {
        audit.carrier(
            format!("frames to node {to}: {class}"),
            Reach::Role,
            bytes.clone(),
        );
    }
    for number in 1..=NODES {
        let node = founded.cluster.node(number).unwrap();
        carriers::node_carriers(&mut audit, number, &node, &[agent], Reach::Role);
    }
    drop(front);
    for number in 1..=NODES {
        founded.cluster.stop(number);
    }
    for number in 1..=NODES {
        for (path, bytes) in carriers::directory(founded.cluster.dir(number)) {
            audit.carrier(format!("node {number}: {path}"), Reach::Role, bytes);
        }
    }
    carriers::finish_logs(&mut audit, &logs, stderr);

    eprintln!("{}", audit.summary());
    eprintln!("{}", fetched.summary());
    audit.assert_searchable(&Kind::CREDENTIAL);
    for carrier in ["the logs", "standard error", "the calls' connection: sent"] {
        audit.assert_captured(carrier, CANARY.as_bytes());
    }
    audit.assert_clean();
    fetched.assert_clean();
}
