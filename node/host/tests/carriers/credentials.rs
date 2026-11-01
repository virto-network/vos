//! The carrier audit over credentialed calls (`identity-and-authority.md`
//! §5, `pvm/device/SECURITY.md`): three nodes of a founded space with the
//! credential actor, the poll, the purses' ledger and the device actor; a
//! member's device secret derived from a known source output, its path
//! fetched, and its calls proved by the device library as a phone proves
//! them and sent to the nodes over each transport: the API's socket, and
//! a gateway relaying HTTP onto the API over QUIC. Then every carrier the
//! run produced is searched for the member's secret, which only the
//! device holds, and for where the member sits, which a credentialed call
//! never carries ([`vos_checker::carriers`]).
//!
//! The calls: auth sign-ins, a replay (`Replayed`), a `once` vote and a
//! second (`Once`), a proof cut by a byte (`Proof`), another call's
//! arguments (`Binding`), an expired call (`Expiry`), a retired format
//! (`Format`), an owner's payment, a device kernel's sign-in (format 46),
//! its replay and its proof sent to a guard naming no kernel (`Kind`), a
//! frame of no kind and one past its kind's limit (`FrameError`), each on
//! a connection the device keeps for its calls; its time, path and root
//! fetched on one of their own.
//!
//! Carriers that leave the device: every byte of each API connection each
//! way, every request and its answer's status and body through the
//! gateway, each
//! credentialed call's log entry on each node, the device library's
//! values as its `Debug` and `Display` show them, every log line of the
//! process at every level (the nodes', the gateway's), and standard
//! error. Searched there: the secret (`s`'s single words among it), the
//! proofs' masks and the member's place, but in the path's own fetch,
//! which holds the place by design.
//! Carriers within the replicas (their stores, logs, work results, disks
//! and frames), which hold the members' digests and the tree, are searched
//! for the secret and the masks.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_api::{Event, FRAME_ERROR, Frame, FrameError, Framing, Kind as ApiKind, Reader};
use vos_checker::Nodes;
use vos_checker::calls::installed;
use vos_checker::carriers::{self, Audit, Kind, Logs, Reach};
use vos_checker::processes::Front;
use vos_checker::programs::{actor, actor_elf, credentials, credentials_elf, method};
use vos_device::wire::{self, Answer};
use vos_device::{
    AuthWitness, Call, CredentialProof, CredentialPublic, DEVICE_PEAK_BYTES, DeviceError,
    DeviceProgram, Prover, ProverConfig, Threads,
};
use vos_node::client::{self, Client, Target};
use vos_node::store::EntryKind;
use vos_pvm_final_verifier::credential as verifier;
use vos_pvm_recair::credential::{AuthPublic, AuthWitness as CircuitWitness, Statement, prove};
use vos_pvm_recair::masked::{MaskRng, drawn_in};
use vos_wire::credentials::{self as tree, Path, Siblings, Tag, Words};
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::ingress::{CredentialRefusal, Credentialed, Response};
use vos_wire::peer::NodeNumber;
use vos_wire::result::{InputRef, Outcome, Step, WorkResult};
use vos_wire::{Decode, Encode, SpaceId, WindowClock};

use crate::harness::{Cluster, NODES};

/// The hub's seed: odd, so the operator's client reaches the nodes over
/// the API's sockets.
const SEED: u64 = 11;
const PURSES: InstanceId = InstanceId(2);
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
    vos_wire::vos_anchor::blake2b_256(&[b"the carrier audit's secret source"])
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
                Some(Event::Frame(frame)) => return frame,
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
        let agent = cluster
            .node(1)
            .unwrap()
            .create_replicated((1..=NODES).collect())
            .unwrap();
        let elf = |path: std::path::PathBuf| std::fs::read(path).unwrap();
        for (instance, elf, role) in [
            (CREDENTIALS, elf(credentials_elf()), "registrar"),
            (POLL, elf(actor_elf("poll")), "operator"),
            (PURSES, elf(actor_elf("purses")), "operator"),
            (DEVICE, elf(actor_elf("device")), "operator"),
        ] {
            let roles = vec![(role.as_bytes().to_vec(), ROLE)];
            vos_checker::spaces::wait_in_process("an install", || {
                match smol::block_on(cluster.leading(agent).install(
                    agent,
                    instance,
                    &elf,
                    roles.clone(),
                )) {
                    Err(vos_node::CallError::NotLeader(_) | vos_node::CallError::TimedOut) => false,
                    answer => {
                        installed(answer);
                        true
                    }
                }
            });
        }
        let key = SigningKey::from_bytes(&OPERATOR);
        let principal = Principal::Client(key.verifying_key().to_bytes());
        installed(smol::block_on(cluster.leading(agent).set_role(
            agent,
            principal,
            Some(ROLE),
        )));
        let leader = cluster.leader(agent).unwrap();
        let operator = Client::new(cluster.target(leader), key).with_routes(cluster.routes());
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
            CREDENTIALS => credentials(),
            POLL => actor("poll"),
            PURSES => actor("purses"),
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
                vos_wire::ids::MethodId(self.method(instance, name)),
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
fn request(call: &Call, proof: &CredentialProof) -> Credentialed {
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
        .filter_map(|index| node.store().log_entry(agent, index).ok().flatten())
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
    let secret = vos_device::derive_secret(&source_output(), &HANDLE);
    let member = vos_device::member(&secret);
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

    // Its time, root and path, on a connection of their own.
    let mut fetch = Socket::connect(&founded.cluster.dir(at).join("api.sock"));
    let mut device_values: Vec<String> = Vec::new();
    let now = wire::time_answer(&fetch.send(&wire::time_request())).unwrap();
    let identity = founded.operator.lock().unwrap().identity(agent).unwrap();
    let root = wire::root_answer(
        &fetch.send(&wire::root_query(agent.0, &identity, CREDENTIALS.0, now + 60_000).unwrap()),
    )
    .unwrap();
    let query = wire::path_query(agent.0, &identity, CREDENTIALS.0, &member, now + 60_000).unwrap();
    let witness: AuthWitness = wire::path_answer(&fetch.send(&query))
        .unwrap()
        .expect("an enrolled member's path");
    assert_eq!(witness.root, root.0);
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
        max_memory: DEVICE_PEAK_BYTES,
    })
    .unwrap();
    let mut calls = Socket::connect(&founded.cluster.dir(at).join("api.sock"));
    let mut send = |call: &Call, proof: &CredentialProof| {
        wire::credentialed_answer(&calls.send(&wire::credentialed(call, proof)))
    };
    let mut answers: Vec<Answer> = Vec::new();

    // Auth: a sign-in, its replay, a `once` vote and a second.
    let login = founded.call(at, POLL, "login", ());
    let signin = prover
        .prove_auth(&secret, &witness, b"login", &login)
        .unwrap();
    answers.push(ran(send(&login, &signin)));
    answers.push(refused(send(&login, &signin), CredentialRefusal::Replayed));
    let vote = founded.call(at, POLL, "vote", 1u8);
    let voted = prover
        .prove_auth(&secret, &witness, b"vote", &vote)
        .unwrap();
    answers.push(ran(send(&vote, &voted)));
    let again = founded.call(at, POLL, "vote", 2u8);
    let voted_again = prover
        .prove_auth(&secret, &witness, b"vote", &again)
        .unwrap();
    answers.push(refused(send(&again, &voted_again), CredentialRefusal::Once));

    // Refused: a proof cut by a byte, another call's arguments, an expired
    // call and a retired format.
    let fresh = founded.call(at, POLL, "login", ());
    let mut proof = prover
        .prove_auth(&secret, &witness, b"login", &fresh)
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
    let retired = CredentialProof {
        format: 42,
        ..whole.clone()
    };
    answers.push(refused(send(&fresh, &retired), CredentialRefusal::Format));
    answers.push(ran(send(&fresh, &whole)));

    // Owner: a payment from the row the member's owner digest claims.
    let owner = vos_device::owner(&secret).to_bytes();
    let expires = founded.time(at) + 60_000;
    let shop = tree::digest(&tree::compress(&Tag::Owner.block(), &other(1)));
    for (row, digest) in [("device", owner), ("shop", shop)] {
        let row = row.as_bytes().to_vec();
        founded.write(PURSES, "invite_row", (row.clone(), digest, expires));
        founded.write(PURSES, "claim_row", (row.clone(), digest));
        founded.write(PURSES, "mint", (row, 50u64));
    }
    let pay = founded.call(
        at,
        PURSES,
        "transfer",
        (b"device".to_vec(), b"shop".to_vec(), 20u64),
    );
    let paid = prover.prove_owner(&secret, &pay).unwrap();
    answers.push(ran(send(&pay, &paid)));

    // A device kernel's sign-in (format 46), its replay, and its proof
    // sent to a guard naming no kernel.
    let kernel = vos_testkit::programs::kernel("device", "auth");
    let program = DeviceProgram::auth(&kernel).unwrap();
    let device_login = founded.call(at, DEVICE, "login", ());
    let device_proof = prover
        .prove_device_auth(&secret, &witness, b"login", &device_login, &program)
        .unwrap();
    answers.push(ran(send(&device_login, &device_proof)));
    answers.push(refused(
        send(&device_login, &device_proof),
        CredentialRefusal::Replayed,
    ));
    let to_poll = founded.call(at, POLL, "login", ());
    let to_poll_proof = prover
        .prove_device_auth(&secret, &witness, b"login", &to_poll, &program)
        .unwrap();
    answers.push(refused(
        send(&to_poll, &to_poll_proof),
        CredentialRefusal::Kind,
    ));
    let CredentialPublic::Auth {
        map_root,
        scope,
        nullifier,
        binding,
    } = device_proof.public
    else {
        unreachable!()
    };
    let public = vos_pvm_recair::device::auth_public(
        &map_root.to_bytes(),
        &scope.to_bytes(),
        &nullifier.to_bytes(),
        &binding.to_bytes(),
    );
    let siblings = witness.siblings.map(|sibling| sibling.0);
    let arguments =
        vos_pvm_recair::device::auth_arguments(&siblings, &words, witness.slot, &public);
    audit
        .needles
        .kernel_arguments("the member", &arguments, public.len());

    // A sign-in proved on this thread, its masks' randomness watched.
    let watched = founded.call(at, POLL, "login", ());
    let scope = vos_device::scope(&founded.space.0, agent.0, POLL.0, b"login").unwrap();
    let nullifier = tree::compress(&tree::compress(&Tag::Nf.block(), &words), &scope.0);
    let binding = watched.binding(verifier::program(verifier::CredentialKind::Auth), 0);
    let statement = Statement::Auth(
        AuthPublic {
            map_root: witness.root.0,
            scope: scope.0,
            nullifier,
            binding: binding.0,
        },
        CircuitWitness {
            secret: words,
            slot: witness.slot,
            siblings,
        },
    );
    let ((proved, _), drawn) = drawn_in(|| prove(&statement, MaskRng::default()).unwrap());
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
    let watched_proof = CredentialProof {
        format: vos_device::FORMAT,
        public: CredentialPublic::Auth {
            map_root: witness.root,
            scope,
            nullifier: vos_device::Digest(nullifier),
            binding,
        },
        proof: verifier::encode(&proved).unwrap(),
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
    let route = format!("/agents/{}/credentialed", agent.0);
    let mut post = |name: String, target: &Target, call: &Credentialed| {
        let body = call.encode();
        let (status, answer) = client::post(target, &route, &body).unwrap();
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
        .prove_auth(&secret, &witness, b"login", &call)
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
        device_values.push(format!("{proof:?} {:?}", proof.public));
    }
    for error in [
        DeviceError::Config,
        DeviceError::Memory,
        DeviceError::Witness,
        DeviceError::Prove,
        DeviceError::Decode,
        DeviceError::Verify,
    ] {
        device_values.push(format!("{error} {error:?}"));
    }
    let refusals = [
        prover
            .prove_auth(&secret, &witness, b"", &login)
            .unwrap_err(),
        prover
            .prove_auth(
                &vos_device::derive_secret(&[1; 32], &HANDLE),
                &witness,
                b"login",
                &login,
            )
            .unwrap_err(),
        wire::path_answer(&[0xff]).unwrap_err(),
        vos_device::verify(&proof, &fresh, Some(b"login")).unwrap_err(),
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

    // The fetch holds the member's place by design: searched for the
    // secret and the masks alone.
    let mut fetched = Audit::default();
    fetched.needles.0 = audit
        .needles
        .0
        .iter()
        .filter(|needle| needle.kind != Kind::MemberPlace)
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
