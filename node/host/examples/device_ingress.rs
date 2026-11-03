//! A device proof accepted at a space's ingress (`proving.md` §8), the
//! host's side: one node of a founded space, the credential actor and the device actor installed, a member
//! enrolled; for each round a sign-in to the device actor's `login`, whose
//! guard names its device kernel `auth`. The kernel's release artifact and
//! each round's witness input are written for a prover, the proof it writes back is
//! sent to the node's ingress as a `Credentialed` request under the device
//! format, and the answer printed.
//!
//! `cargo run --release -p vos-node --example device_ingress -- DIR
//! [--rounds N] [--wait S] [--prove]`:
//! - writes `DIR/auth.device`, the kernel's release artifact (the kernel
//!   and its device program as the install computes it, the device
//!   library's `release::Device`), then for round `n`
//!   `DIR/n.input`, the kernel's witness input (the member's path, its
//!   secret, its slot, and auth's public arguments for this round's call,
//!   good for 110 s by the node's clock);
//! - waits up to `S` seconds (90 by default) for `DIR/n.proof`, the proof's
//!   bytes as `vos-phone kernel` writes them (with `--prove`, this process
//!   proves it, through the device library as the phone does);
//! - sends it, and prints one JSON `round` line: the answer, and whether
//!   the call ran as the member's pseudonym.
//!
//! Exits 0 when every round ran. After `just build-agent build-credentials
//! build-test-actors`. `tools/phone/scripts/pg2.sh` drives it with a
//! phone.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use vos_checker::calls::installed;
use vos_checker::programs::{Programs, actor, credentials, credentials_elf, method, package};
use vos_light::{DEVICE_FORMAT, DeviceProgram, Prover, ProverConfig, Threads};
use vos_node::client::{self, Client, Target};
use vos_node::{Config, Node};
use vos_pvm_recair::device::{auth_arguments, auth_public};
use vos_wire::credentials::{self as tree, Bound, Path as TreePath, Tag, Words};
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::ingress::{CredentialPublic, Credentialed, Response};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, SpaceId, WindowClock};

const CREDENTIALS: InstanceId = InstanceId(9);
const DEVICE: InstanceId = InstanceId(4);
/// The registrar's role byte, the operator's key holding it.
const ROLE: u8 = 1;
const OPERATOR: [u8; 32] = [21; 32];
/// The space's handle, which the credential actor is founded with.
const HANDLE: [u8; 32] = [0x42; 32];
/// The member's secret: a public test value, no device's.
const SECRET: Words = [
    0x0711_0001,
    0x0711_0002,
    0x0711_0003,
    0x0711_0004,
    0x0711_0005,
    0x0711_0006,
    0x0711_0007,
    0x0711_0008,
];
/// How long a round's call lives past the node's time when it is written:
/// a margin under the node's horizon (120 s).
const LIFE_MS: u64 = 110_000;

struct Options {
    dir: PathBuf,
    rounds: u32,
    wait: Duration,
    prove: bool,
}

fn options() -> Options {
    let mut args = std::env::args().skip(1);
    let mut options = Options {
        dir: PathBuf::from(args.next().expect("the directory")),
        rounds: 1,
        wait: Duration::from_secs(90),
        prove: false,
    };
    while let Some(flag) = args.next() {
        let mut value = || args.next().expect("a flag's value");
        match flag.as_str() {
            "--rounds" => options.rounds = value().parse().expect("a count"),
            "--wait" => options.wait = Duration::from_secs(value().parse().expect("seconds")),
            "--prove" => options.prove = true,
            other => panic!("unknown flag {other}"),
        }
    }
    options
}

/// One node of a founded space, the credential actor founded with
/// [`HANDLE`] and [`SECRET`]'s member enrolled, the device actor beside it.
struct Served {
    _node: Node,
    socket: Target,
    space: SpaceId,
    agent: AgentId,
    client: Client,
    _dir: tempfile::TempDir,
}

fn start() -> Served {
    let programs = Programs::load();
    let dir = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
    let contact = "http://node-1".to_string();
    let space = vos_checker::spaces::space(&programs.agent, &[dir.path()], |_| contact.clone());
    let genesis = space
        .found(WindowClock::DEFAULT, vos_node::wall_clock(), [3; 16])
        .unwrap();
    let space = space.with_genesis(genesis).unwrap();
    let id = space.id();
    let key = SigningKey::from_bytes(&OPERATOR);
    let operator = key.verifying_key().to_bytes();
    let node = vos_checker::spaces::open_node(1, dir.path(), || {
        let mut config = Config::new(programs.agent.clone());
        config.space = Some(space.clone());
        config.operators = vec![operator];
        config
    });
    let path = dir.path().join("api.sock");
    node.serve_socket(&path, 0o600).unwrap();
    let socket = Target::socket(path);
    let agent = node.create_agent().unwrap();
    let registrar = vec![(b"registrar".to_vec(), ROLE)];
    let elf = std::fs::read(credentials_elf()).unwrap();
    installed(smol::block_on(node.install(
        agent,
        CREDENTIALS,
        &elf,
        registrar,
    )));
    installed(smol::block_on(node.install(
        agent,
        DEVICE,
        &package("device"),
        Vec::new(),
    )));
    installed(smol::block_on(node.set_role(
        agent,
        Principal::Client(operator),
        Some(ROLE),
    )));
    let mut client = Client::new(&socket, key);
    let credentials = credentials();
    for (name, arguments) in [("found", HANDLE.encode()), ("enroll", member().encode())] {
        let answer = client
            .call(agent, CREDENTIALS, method(&credentials, name), &arguments)
            .unwrap();
        assert!(ran(&answer).is_some(), "{name}: {answer:?}");
    }
    Served {
        _node: node,
        socket,
        space: id,
        agent,
        client,
        _dir: dir,
    }
}

fn member() -> tree::Digest {
    tree::digest(&tree::compress(&Tag::Member.block(), &SECRET))
}

/// The reply of a call that ran to `Done`.
fn ran(answer: &Response) -> Option<&[u8]> {
    match answer {
        Response::Ran {
            outcome: Outcome::Done(reply),
            ..
        } => Some(reply),
        _ => None,
    }
}

impl Served {
    /// The member's path, as the credential actor serves it now.
    fn path(&self) -> TreePath {
        let not_after = client::time(&self.socket).unwrap() + 60_000;
        let answer = self
            .client
            .query(
                self.agent,
                CREDENTIALS,
                method(&credentials(), "path"),
                &member().encode(),
                not_after,
            )
            .unwrap();
        let reply = ran(&answer).expect("the path query");
        Option::<TreePath>::decode_exact(reply)
            .flatten()
            .expect("an enrolled member's path")
    }

    /// Round `round`'s call of `login`, its public statement, and the
    /// device kernel's witness input that proves it under `program`.
    fn round(&self, round: u32, program: &[u8; 32]) -> (Credentialed, Vec<u8>) {
        let login = method(&actor("device"), "login");
        let mut nonce = [0u8; 16];
        nonce[..4].copy_from_slice(&round.to_le_bytes());
        getrandom::getrandom(&mut nonce[4..]).expect("the OS's randomness");
        let mut call = Credentialed {
            instance: DEVICE,
            method: login,
            arguments: ().encode(),
            nonce,
            expires_ms: client::time(&self.socket).unwrap() + LIFE_MS,
            format: DEVICE_FORMAT,
            public: CredentialPublic::Owner {
                owner: [0; 32],
                binding: [0; 32],
            },
            proof: Vec::new(),
        };
        let path = self.path();
        let scope = tree::scope(&self.space, self.agent, DEVICE, b"login");
        let words = |digest: &tree::Digest| tree::words(digest).expect("a digest's words");
        let nullifier = tree::digest(&tree::compress(
            &tree::compress(&Tag::Nf.block(), &SECRET),
            &words(&scope),
        ));
        let bound = Bound {
            space: &self.space,
            agent: self.agent,
            instance: call.instance,
            method: call.method,
            program,
            kind: 0,
            arguments: &call.arguments,
            nonce: &call.nonce,
            expires_ms: call.expires_ms,
        }
        .digest();
        let binding = tree::binding(&bound);
        call.public = CredentialPublic::Auth {
            map_root: path.root,
            scope,
            nullifier,
            binding,
        };
        let public = auth_public(&path.root, &scope, &nullifier, &binding);
        let siblings = path.siblings.0.map(|sibling| words(&sibling));
        (call, auth_arguments(&siblings, &SECRET, path.slot, &public))
    }
}

/// The proof's bytes at `path`, once its writer has finished it: waited for
/// up to `wait`.
fn wait_for(path: &Path, wait: Duration) -> Option<Vec<u8>> {
    let started = Instant::now();
    let mut last = None;
    while started.elapsed() < wait {
        if let Ok(metadata) = std::fs::metadata(path) {
            let len = metadata.len();
            if len > 0 && last == Some(len) {
                return std::fs::read(path).ok();
            }
            last = Some(len);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    None
}

fn main() {
    let options = options();
    std::fs::create_dir_all(&options.dir).expect("the directory");
    let device = vos_light::release::device(&package("device"), "auth")
        .expect("the kernel's release artifact");
    let program = DeviceProgram::released(&device).expect("the kernel's program");
    let served = start();
    std::fs::write(
        options.dir.join("auth.device"),
        vos_wire::Encode::encode(&device),
    )
    .expect("the release artifact written");
    let prover = options.prove.then(|| {
        Prover::new(ProverConfig {
            threads: Threads::Auto,
            max_memory: vos_light::DEVICE_PEAK_BYTES,
        })
        .expect("a prover")
    });
    let mut accepted = 0;
    for round in 1..=options.rounds {
        let (mut call, input) = served.round(round, program.id());
        let input_path = options.dir.join(format!("{round}.input"));
        let proof_path = options.dir.join(format!("{round}.proof"));
        let _ = std::fs::remove_file(&proof_path);
        std::fs::write(&input_path, &input).expect("the input written");
        eprintln!("round {round}: {} ready", input_path.display());
        let proof = match &prover {
            Some(prover) => Some(
                prover
                    .prove_kernel(&program, &input)
                    .expect("the kernel proves")
                    .proof,
            ),
            None => wait_for(&proof_path, options.wait),
        };
        let Some(proof) = proof else {
            println!(
                "{{\"kind\":\"round\",\"round\":{round},\"answer\":\"no proof\",\"ran\":false}}"
            );
            continue;
        };
        call.proof = proof;
        let started = Instant::now();
        let answer = client::credentialed(&served.socket, served.agent, &call);
        let answered = started.elapsed();
        let CredentialPublic::Auth { nullifier, .. } = call.public else {
            unreachable!()
        };
        let pseudonym = answer
            .as_ref()
            .ok()
            .and_then(ran)
            .and_then(|reply| Option::<[u8; 32]>::decode_exact(reply).flatten());
        let ran = pseudonym == Some(nullifier);
        accepted += u32::from(ran);
        let shown = match &answer {
            Ok(Response::Ran { outcome, .. }) => format!("Ran({outcome:?})"),
            Ok(other) => format!("{other:?}"),
            Err(error) => format!("{error:?}"),
        };
        println!(
            "{{\"kind\":\"round\",\"round\":{round},\"format\":{},\"proof_bytes\":{},\"answer_ms\":{:.1},\"answer\":{:?},\"ran\":{ran}}}",
            call.format,
            call.proof.len(),
            answered.as_secs_f64() * 1e3,
            shown,
        );
    }
    println!(
        "{{\"kind\":\"done\",\"rounds\":{},\"ran\":{accepted}}}",
        options.rounds
    );
    if accepted != options.rounds {
        std::process::exit(1);
    }
}
