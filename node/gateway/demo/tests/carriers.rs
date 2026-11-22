//! The carrier audit with the onion in the path (`proving.md` A.5,
//! `node/light/SECURITY.md`): the demo's space on one node, the gateway's
//! onion served in process (each of the device's dials a stream handed to
//! the onion's SSH port on a circuit of its own, as arti hands them, the
//! gateway marking it onion and relaying it to the node), and a member's
//! calls as the light node makes them on the phone: the tree read from its
//! feed on one long-lived connection, the node's time fetched on one of its
//! own, and proven calls each on a connection of its own (sign-ins by the
//! stock `auth` kernel, one of them proved with its masks' randomness
//! watched, an owner's payment by the stock `owner` kernel, a proof cut by
//! a byte). Then every carrier the run produced is searched for the
//! member's device secret, its proofs' masks and where it sits in the tree
//! ([`vos_checker::carriers`]).
//!
//! Carriers that leave the device: each circuit's bytes each way (SSH's),
//! what the device's client sent and read over each purpose's connection,
//! every frame the gateway relayed to the node and its answers, the light
//! node's values as its `Debug` and `Display` show them, every log line of
//! the process at every level (the gateway's, the node's), and standard
//! error. The feed's connection and the gateway's frames to the node hold
//! the whole tree by design, so they are searched for the secret, the
//! masks and the member's digest alone, which no query names. Carriers
//! within the node (its store, its log, its disk) are searched for the
//! secret and the masks.
//!
//! Alone in its process (`just test-carriers`): it captures the whole
//! process's logs and standard error.

use std::io::{Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use vos_abi::credentials as tree;
use vos_abi::credentials::Tag;
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_checker::carriers::{self, Audit, Kind, Logs, Reach};
use vos_gateway_demo::{CREDENTIALS, LocalSpace, PAYMENTS, POLL, Served, random};
use vos_light::route::{Purpose, Routes};
use vos_light::tor::{Circuit, Client, Config, Dial, Dialing, Registrar, Stream, Target};
use vos_light::wire::{self, Answer};
use vos_light::{
    AuthWitness, Call, DEVICE_FORMAT, DeviceProgram, Proven, Prover, ProverConfig, Threads,
    TreeKeeper,
};
use vos_pvm_recair::masked::{MaskRng, drawn_in};
use vos_wire::credentials::{AuthClaim, Path, Siblings};
use vos_wire::ingress::CredentialRefusal;

/// The space's handle, which the member's secret source is asked for.
const HANDLE: [u8; 32] = [0x48; 32];
/// Members enrolled after the audited one, so its path's lowest siblings
/// are occupied.
const OTHERS: u32 = 7;
/// What each capture path is sent once, to show it captures.
const CANARY: &str = "onion-carrier-canary";

/// Bytes kept, shared.
type Kept = Arc<Mutex<Vec<u8>>>;

/// A stream whose bytes each way are kept as they pass.
struct Recorded<S> {
    inner: S,
    sent: Kept,
    received: Kept,
}

impl<S: AsyncRead + Unpin> AsyncRead for Recorded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            let read = buf.filled()[before..].to_vec();
            self.received.lock().unwrap().extend_from_slice(&read);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recorded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            self.sent.lock().unwrap().extend_from_slice(&buf[..written]);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Each dial a stream to the gateway's onion in process, on a circuit of
/// its own, its bytes kept.
struct Onions {
    front: Arc<vos_gateway::served::Front>,
    circuits: AtomicU32,
    recorded: Mutex<Vec<(u32, Kept, Kept)>>,
}

impl Dial for Onions {
    fn dial(&self, target: &Target, _circuit: Circuit) -> Dialing {
        let Target::Onion { port, .. } = target.clone() else {
            panic!("the member's calls go to the onion alone: {target:?}");
        };
        let front = Arc::clone(&self.front);
        let circuit = self.circuits.fetch_add(1, Ordering::Relaxed) + 1;
        let (sent, received) = (Kept::default(), Kept::default());
        self.recorded
            .lock()
            .unwrap()
            .push((circuit, Arc::clone(&sent), Arc::clone(&received)));
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(1 << 20);
            front.onion.serve(theirs, circuit, port).await;
            Ok(Box::new(Recorded {
                inner: ours,
                sent,
                received,
            }) as Stream)
        })
    }
}

/// A socket in front of the node's API: every byte the gateway relays to
/// the node and every byte of its answers, kept.
fn tap(socket: &std::path::Path, node: &std::path::Path) -> (Kept, Kept) {
    let listener = UnixListener::bind(socket).unwrap();
    let (sent, received) = (Kept::default(), Kept::default());
    let (to, from) = (Arc::clone(&sent), Arc::clone(&received));
    let node = node.to_owned();
    std::thread::spawn(move || {
        for gateway in listener.incoming() {
            let Ok(gateway) = gateway else { return };
            let upstream = UnixStream::connect(&node).unwrap();
            for (mut source, mut sink, kept) in [
                (
                    gateway.try_clone().unwrap(),
                    upstream.try_clone().unwrap(),
                    Arc::clone(&to),
                ),
                (upstream, gateway, Arc::clone(&from)),
            ] {
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 1 << 16];
                    while let Ok(read) = source.read(&mut buffer) {
                        if read == 0 || sink.write_all(&buffer[..read]).is_err() {
                            break;
                        }
                        kept.lock().unwrap().extend_from_slice(&buffer[..read]);
                    }
                    let _ = sink.shutdown(std::net::Shutdown::Write);
                });
            }
        }
    });
    (sent, received)
}

/// The proven call ran.
fn ran(answer: &Answer) {
    assert!(
        matches!(
            answer,
            Answer::Ran {
                outcome: Outcome::Done(_),
                ..
            }
        ),
        "{answer:?}"
    );
}

/// The ingress refused the proven call with `refusal`.
fn refused(answer: &Answer, refusal: CredentialRefusal) {
    assert!(
        matches!(answer, Answer::Refused(found) if *found == refusal),
        "{answer:?}"
    );
}

/// Another member's secret words.
fn other(seed: u32) -> tree::Words {
    core::array::from_fn(|i| seed * 1_000 + i as u32 + 1)
}

#[test]
fn no_carrier_through_the_onion_holds_a_members_device_secret_or_its_place() {
    // SAFETY: once, before this process's first thread reads the
    // environment; the process runs this test alone.
    unsafe { carriers::debug_environment_on() };
    let stderr = carriers::Stderr::capture(std::path::Path::new(env!("CARGO_TARGET_TMPDIR")));
    let logs = Logs::install();
    let data = tempfile::tempdir().unwrap();
    let space = LocalSpace::found(&data.path().join("space"), HANDLE, random()).unwrap();
    let agent = space.agent();

    // The member, enrolled first, then the others after it.
    let source_output: [u8; 32] = random();
    let mut audit = Audit::default();
    let words = audit
        .needles
        .device_secret("the member", &source_output, &HANDLE);
    let secret = vos_light::derive_secret(&source_output, &HANDLE);
    let member = vos_light::member(&secret);
    assert_eq!(
        member.to_bytes(),
        tree::digest(&tree::compress(&Tag::Member.block(), &words)),
        "the audit's secret is the library's"
    );
    space
        .write(CREDENTIALS, "enroll", member.to_bytes())
        .unwrap();
    for seed in 1..=OTHERS {
        let digest = tree::digest(&tree::compress(&Tag::Member.block(), &other(seed)));
        space.write(CREDENTIALS, "enroll", digest).unwrap();
    }

    // The gateway's onion in process, relaying through the tap.
    let tapped = data.path().join("tap.sock");
    let (relayed, answered) = tap(&tapped, &space.socket());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (front, pinned) = runtime
        .block_on(space.onion_front(Served::Demo, data.path(), &tapped, None))
        .unwrap();
    let onions = Arc::new(Onions {
        front: Arc::new(front),
        circuits: AtomicU32::new(0),
        recorded: Mutex::new(Vec::new()),
    });
    let client = {
        let _entered = runtime.enter();
        Client::new(Arc::clone(&onions) as Arc<dyn Dial>, Config::default())
    };
    client.set_space(HANDLE, Routes::new(vec![pinned], None, false));
    // What the device's client sent and read, by purpose.
    let mut device = std::collections::BTreeMap::<&str, (Vec<u8>, Vec<u8>)>::new();
    let mut ask = |purpose: Purpose, request: Vec<u8>| -> Vec<u8> {
        let (_, body) = runtime
            .block_on(client.request(HANDLE, purpose, &request))
            .unwrap();
        let name = match purpose {
            Purpose::Feed => "the feed",
            Purpose::Fetch => "the fetches",
            _ => "the proven calls",
        };
        let kept = device.entry(name).or_default();
        kept.0.extend_from_slice(&request);
        kept.1.extend_from_slice(&body);
        body
    };

    // The tree from its feed, on the feed's one connection.
    let identity = vos_node::client::Client::new(
        &vos_node::client::Target::socket(space.socket()),
        ed25519_dalek::SigningKey::from_bytes(&random()),
    )
    .identity(agent)
    .unwrap();
    let registrar = Registrar {
        agent: agent.0,
        instance: CREDENTIALS.0,
        identity,
    };
    let mut keeper = TreeKeeper::new(member);
    let now = wire::time_answer(&ask(Purpose::Fetch, wire::time_request())).unwrap();
    loop {
        let query = keeper
            .request(
                registrar.agent,
                &registrar.identity,
                registrar.instance,
                now + 60_000,
            )
            .unwrap();
        if !keeper.ingest(&ask(Purpose::Feed, query), 0).unwrap().more {
            break;
        }
    }
    let witness: AuthWitness = keeper.witness().expect("an enrolled member's path");
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
    let mut device_values = vec![format!("{witness:?} {:?}", keeper.root())];

    let prover = Prover::new(ProverConfig {
        threads: Threads::Count(4),
        ..ProverConfig::default()
    })
    .unwrap();
    let elf = std::fs::read(vos_testkit::programs::program_elf("vos-credentials")).unwrap();
    let stock = |kernel| vos_light::release::device(&elf, kernel).unwrap();
    let (auth, owner_kernel) = (stock("auth"), stock("owner"));
    let auth_program = DeviceProgram::from_release(&auth).unwrap();
    let owner_program = DeviceProgram::from_release(&owner_kernel).unwrap();
    let space_id = space.space_id();
    let mut answers = Vec::new();
    let mut proven = |call: &Call, proof: &Proven| -> Answer {
        let body = ask(Purpose::Proven, wire::credentialed(call, proof));
        wire::credentialed_answer(&body).unwrap()
    };
    let call_of = |instance: vos_abi::ids::InstanceId, name: &str, arguments: Vec<u8>| {
        Call::new(
            space_id,
            agent.0,
            instance.0,
            vos_light::method_id(name),
            arguments,
            space.now().unwrap() + 60_000,
        )
        .unwrap()
    };

    // Sign-ins, each on a connection of its own; a proof cut by a byte.
    let login = call_of(POLL, "login", ().encode());
    let signin = prover
        .prove_auth(&secret, &witness, b"login", &login, &auth_program)
        .unwrap();
    let answer = proven(&login, &signin);
    ran(&answer);
    answers.push(answer);
    let fresh = call_of(POLL, "login", ().encode());
    let mut cut = prover
        .prove_auth(&secret, &witness, b"login", &fresh, &auth_program)
        .unwrap();
    cut.proof.pop();
    let answer = proven(&fresh, &cut);
    refused(&answer, CredentialRefusal::Proof);
    answers.push(answer);

    // An owner's payment from the account its owner digest holds.
    let owner = vos_light::owner(&secret).to_bytes();
    let shop = tree::digest(&tree::compress(&Tag::Owner.block(), &other(1)));
    space.open_account("device", owner, 50).unwrap();
    space.open_account("shop", shop, 0).unwrap();
    let pay = call_of(
        PAYMENTS,
        "transfer",
        (b"shop".to_vec(), 20u64, [20u8; 32]).encode(),
    );
    let paid = prover.prove_owner(&secret, &pay, &owner_program).unwrap();
    let answer = proven(&pay, &paid);
    ran(&answer);
    answers.push(answer);
    assert_eq!(space.balance("shop").unwrap(), Some(20));

    // A sign-in proved on this thread, its masks' randomness watched; its
    // arguments as the kernel reads them.
    let watched = call_of(POLL, "login", ().encode());
    let scope = vos_light::scope(&space_id, agent.0, POLL.0, b"login").unwrap();
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
    let answer = proven(&watched, &watched_proof);
    ran(&answer);
    answers.push(answer);

    // The canaries: a proven call's arguments, a log line and a line on
    // standard error.
    let canary = Call {
        arguments: CANARY.as_bytes().to_vec(),
        ..call_of(POLL, "login", ().encode())
    };
    answers.push(proven(&canary, &signin));
    tracing::trace!(canary = CANARY, "a gateway's task");
    eprintln!("{CANARY}: standard error");

    // The light node's values, as a client's log would show them.
    for answer in &answers {
        device_values.push(format!("{answer:?}"));
    }
    for call in [&login, &pay, &watched] {
        device_values.push(format!("{call:?}"));
    }
    for proof in [&signin, &paid, &watched_proof] {
        device_values.push(format!(
            "{proof:?} {:?}",
            AuthClaim::decode_exact(&proof.claim)
        ));
    }
    for hour in client.opened() {
        device_values.push(hour.to_string());
    }

    // What leaves the device: each circuit's bytes, what its client sent
    // and read on each purpose's connections, the gateway's frames to the
    // node, the light node's values.
    let recorded = onions.recorded.lock().unwrap().clone();
    assert!(recorded.len() >= 6, "{} circuits", recorded.len());
    for (circuit, sent, received) in &recorded {
        for (way, bytes) in [("sent", sent), ("received", received)] {
            audit.carrier(
                format!("circuit {circuit}: {way}"),
                Reach::Leaves,
                bytes.lock().unwrap().clone(),
            );
        }
    }
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
    for (name, (sent, read)) in device {
        let audit = match name {
            "the feed" => &mut fetched,
            _ => &mut audit,
        };
        audit.carrier(format!("{name}: sent"), Reach::Leaves, sent);
        audit.carrier(format!("{name}: received"), Reach::Leaves, read);
    }
    for (way, bytes) in [("relayed", &relayed), ("answered", &answered)] {
        fetched.carrier(
            format!("the gateway's frames to the node: {way}"),
            Reach::Leaves,
            bytes.lock().unwrap().clone(),
        );
    }
    audit.carrier(
        "the light node's values",
        Reach::Leaves,
        device_values.join("\n").into_bytes(),
    );

    // What stays within the node: its store, its log, its disk.
    carriers::node_carriers(&mut audit, 1, space.node(), &[agent], Reach::Role);
    drop(client);
    drop(onions);
    drop(runtime);
    space.shutdown();
    for (path, bytes) in carriers::directory(data.path()) {
        audit.carrier(format!("the demo's directory: {path}"), Reach::Role, bytes);
    }
    carriers::finish_logs(&mut audit, &logs, stderr);

    eprintln!("{}", audit.summary());
    eprintln!("{}", fetched.summary());
    audit.assert_searchable(&Kind::CREDENTIAL);
    for carrier in ["the logs", "standard error", "the proven calls: sent"] {
        audit.assert_captured(carrier, CANARY.as_bytes());
    }
    audit.assert_clean();
    fetched.assert_clean();
}
