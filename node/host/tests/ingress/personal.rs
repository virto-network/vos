//! A personal agent (`Personal`, `agent/personal`) on a node, through its
//! socket and the onion's mark, beside a home's stand-in (the `home` test
//! actor) granted its role `homes`: its devices admitted once the home
//! assigns it and no key before; its reads for admitted keys alone; admin
//! calls verified at ingress and their origin checked by the agent, their
//! evidence stored as signed and checked by a device; a removed device
//! keeping its session and refused by the agent; and a push and its read
//! timed over the socket.

use std::io::Write;
use std::os::unix::net::UnixStream;

use ed25519_dalek::{Signature, Verifier};
use vos_api::{Framing, Kind, Mark, marked};
use vos_checker::programs::{package, personal_package};
use vos_node::client::{signed_call, signed_query};
use vos_wire::abi::Failure;
use vos_wire::ids::{Principal, derive_id};
use vos_wire::ingress::{AdmissionRefusal, CallMessage, Rejection as Rejected};
use vos_wire::personal::{
    AdminClass, Attestation, Body, Candidacy, Effect, Entry, Envelope, Header, Kit, KitEntry,
    KitKind, NewDevice, Overview, PersonalError, Policy, Pushed, Recorded, Voted,
};

use super::api::{connect, receive};
use super::*;

const PERSONAL: InstanceId = InstanceId(1);
const HOME: InstanceId = InstanceId(1);
const HOMES_ROLE: u8 = 1;

fn method(name: &str) -> MethodId {
    MethodId(derive_id("vos/method/", name))
}

/// A device's two keys, from its seed.
struct Keys {
    sync: SigningKey,
    admin: SigningKey,
}

impl Keys {
    fn of(seed: u8) -> Self {
        Self {
            sync: SigningKey::from_bytes(&[seed; 32]),
            admin: SigningKey::from_bytes(&[seed ^ 0x80; 32]),
        }
    }

    fn device(&self) -> NewDevice {
        NewDevice {
            sync: self.sync.verifying_key().to_bytes(),
            admin: self.admin.verifying_key().to_bytes(),
            class: AdminClass::Strong,
            attestation: Attestation {
                hardware: true,
                verified_boot: true,
            },
            nullifier: [self.sync.to_bytes()[0]; 32],
            label: vec![1; 16],
        }
    }
}

/// A client key's session at the agent, its next sequence.
struct Signer {
    key: SigningKey,
    session: Session,
    next: u64,
}

/// A node serving its socket with a personal agent and the home's agent,
/// the home granted `homes`.
struct Personal {
    served: Served,
    agent: AgentId,
    home: AgentId,
    identity: [u8; 32],
    stream: UnixStream,
}

impl Personal {
    fn start() -> Self {
        let served = Served::plain();
        let node = &served.node;
        let agent = node.create_agent().unwrap();
        installed(smol::block_on(node.install(
            agent,
            PERSONAL,
            &personal_package(),
            vec![(b"homes".to_vec(), HOMES_ROLE)],
        )));
        let home = node.create_agent().unwrap();
        installed(smol::block_on(node.install(
            home,
            HOME,
            &package("home"),
            Vec::new(),
        )));
        installed(smol::block_on(node.set_role(
            agent,
            Principal::Agent(home),
            Some(HOMES_ROLE),
        )));
        let identity = served.client(1).identity(agent).unwrap();
        let stream = connect(&served.socket);
        Self {
            served,
            agent,
            home,
            identity,
            stream,
        }
    }

    /// The home's call `name` on the personal agent's behalf, by a client
    /// of the home's agent.
    fn home(&self, name: &str, arguments: impl Encode) {
        let arguments = ((self.agent.0, PERSONAL.0), arguments).encode();
        let answer = self
            .served
            .client(2)
            .call(self.home, HOME, method(name), &arguments)
            .unwrap();
        assert!(matches!(answer, Response::Ran { .. }), "{answer:?}");
    }

    /// A session of `key`, new.
    fn signer(&self, key: &SigningKey, name: u8) -> Signer {
        Signer {
            key: key.clone(),
            session: Session {
                key: key.verifying_key().to_bytes(),
                name: [name; 16],
                t0: self.served.now(),
            },
            next: 1,
        }
    }

    /// `signer`'s call of `name` through the onion, at its next sequence:
    /// the call as signed, and the answer.
    fn call(&mut self, signer: &mut Signer, name: &str, arguments: Vec<u8>) -> (Call, Response) {
        let call = signed_call(
            &self.identity,
            &signer.key,
            signer.session,
            signer.next,
            PERSONAL,
            method(name),
            arguments,
        );
        let answer = ask(
            &mut self.stream,
            Kind::Call,
            Mark::Onion,
            &(self.agent, call.clone()).encode(),
        );
        if !matches!(answer, Response::Rejected(_)) {
            signer.next += 1;
        }
        (call, answer)
    }

    /// [`Personal::call`]'s answer, as `Personal` answers it.
    fn answer<T: Decode>(
        &mut self,
        signer: &mut Signer,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, PersonalError> {
        outcome(self.call(signer, name, arguments.encode()).1)
    }

    /// `key`'s query of `name` through the onion.
    fn query<T: Decode>(
        &mut self,
        key: &SigningKey,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, PersonalError> {
        let query = signed_query(
            &self.identity,
            key,
            self.served.now() + 10_000,
            Consistency::Applied { at: 0 },
            PERSONAL,
            method(name),
            arguments.encode(),
        );
        outcome(ask(
            &mut self.stream,
            Kind::Query,
            Mark::Onion,
            &(self.agent, query).encode(),
        ))
    }

    /// Wait until `signer`'s call of `name` is no longer refused for an
    /// unknown key: its replica applied the admission.
    fn admitted<T: Decode>(
        &mut self,
        signer: &mut Signer,
        name: &str,
        arguments: Vec<u8>,
    ) -> Result<T, PersonalError> {
        let mut answer = unknown();
        wait_until("the admission applied", || {
            answer = self.call(signer, name, arguments.clone()).1;
            answer != unknown()
        });
        outcome(answer)
    }

    /// Move the node's clock on by `ms`.
    fn pass(&self, ms: u64) {
        self.served.clock.fetch_add(ms, Ordering::SeqCst);
    }
}

fn unknown() -> Response {
    Response::Rejected(Rejected::Admission(AdmissionRefusal::UnknownKey))
}

/// An answer as `Personal` answers it: its reply, or its error.
fn outcome<T: Decode>(answer: Response) -> Result<T, PersonalError> {
    match answer {
        Response::Ran {
            outcome: Outcome::Done(bytes),
            ..
        } => Ok(T::decode_exact(&bytes).expect("the reply decodes")),
        Response::Ran {
            outcome:
                Outcome::Failed {
                    code: Failure::Handler,
                    detail,
                },
            ..
        } => Err(PersonalError::decode_exact(&detail).expect("the error decodes")),
        other => panic!("{other:?}"),
    }
}

/// A request of `kind` marked `mark` holding `body`: its answer.
fn ask(stream: &mut UnixStream, kind: Kind, mark: Mark, body: &[u8]) -> Response {
    stream
        .write_all(&marked(Framing::Stream, kind as u16, mark, 1, body))
        .unwrap();
    let (answered, id, body) = receive(stream).expect("an answer");
    assert_eq!((answered, id), (kind as u16, 1));
    Response::decode_exact(&body).expect("a response")
}

fn kit() -> Kit {
    Kit {
        entries: vec![KitEntry {
            kind: KitKind::Phrase,
            signing: SigningKey::from_bytes(&[0xc1; 32])
                .verifying_key()
                .to_bytes(),
            sealing: [0xc2; 32],
            sealed_r1: vec![0xc3; 80],
        }],
        r2: [0xc4; 32],
    }
}

/// Minutes in place of days: a removal matures in two.
fn policy() -> Policy {
    Policy {
        removal_delay_ms: 2 * 60_000,
        probation_ms: 60_000,
        ..Policy::DEFAULT
    }
}

/// `len` bytes no compression shortens, as a sealed envelope's are.
fn sealed(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn envelope(epoch: u64, seed: u64, len: usize) -> Vec<u8> {
    let header = Header {
        scope: [7; 16],
        epoch,
        nonce: [seed as u8; 24],
        len_class: 0,
    };
    let mut bytes = header.to_bytes().to_vec();
    bytes.extend(sealed(seed, len - Header::BYTES));
    bytes
}

/// A personal agent admits no session before the home assigns it, then
/// its device's keys and the kit's through the onion alone; a stranger's
/// session is refused before its signature is checked, and a stranger's
/// signed query reads nothing, as no read answers a key it does not admit.
#[test]
fn a_personal_agent_admits_its_devices_through_the_onion_alone() {
    let mut personal = Personal::start();
    let phone = Keys::of(11);
    let mut sync = personal.signer(&phone.sync, 1);
    assert_eq!(personal.call(&mut sync, "alive", Vec::new()).1, unknown());
    personal.home("configure", policy());
    personal.home("assign", (phone.device(), kit()));
    let alive: Recorded = personal.admitted(&mut sync, "alive", Vec::new()).unwrap();
    assert!(alive.at > 0);
    // Off the onion: refused before anything is read.
    let call = signed_call(
        &personal.identity,
        &phone.sync,
        sync.session,
        sync.next,
        PERSONAL,
        method("alive"),
        Vec::new(),
    );
    for mark in [Mark::Unmarked, Mark::Clearnet] {
        assert_eq!(
            ask(
                &mut personal.stream,
                Kind::Call,
                mark,
                &(personal.agent, call.clone()).encode()
            ),
            Response::Rejected(Rejected::Admission(AdmissionRefusal::OnionOnly))
        );
    }
    let stranger = SigningKey::from_bytes(&[99; 32]);
    let mut theirs = personal.signer(&stranger, 1);
    assert_eq!(personal.call(&mut theirs, "alive", Vec::new()).1, unknown());
    assert_eq!(
        personal.query::<Overview>(&stranger, "overview", ()),
        Err(PersonalError::NotAdmitted)
    );
    let overview: Overview = personal.query(&phone.sync, "overview", ()).unwrap();
    assert_eq!(overview.confirmed, 0);
    let kit_key = SigningKey::from_bytes(&[0xc1; 32]);
    let entries: Vec<(u64, Entry)> = personal.query(&kit_key, "log", 0u64).unwrap();
    assert!(matches!(
        entries[1].1.body,
        Body::Assigned { device: 0, .. }
    ));
}

/// The gate at ingress: a commit signed by a sync key runs and is refused
/// by the agent, one whose admin signature does not verify never reaches
/// it, and one signed by an active device's admin key is the candidate.
/// Its evidence, the call as signed, is stored, and a device verifies it
/// from the log: the signature against the admin key, the arguments the
/// logged call's.
#[test]
fn admin_calls_are_verified_at_ingress_and_checked_against_the_device_set() {
    let mut personal = Personal::start();
    let phone = Keys::of(21);
    personal.home("configure", policy());
    personal.home("assign", (phone.device(), kit()));
    let mut sync = personal.signer(&phone.sync, 1);
    personal
        .admitted::<Recorded>(&mut sync, "alive", Vec::new())
        .unwrap();
    let update = (
        (1u64, Effect::default()),
        (vec![0x5a_u8; 734], None::<[u8; 32]>),
    );
    assert_eq!(
        personal.answer::<Candidacy>(&mut sync, "commit", update.clone()),
        Err(PersonalError::SyncKey)
    );
    let mut admin = personal.signer(&phone.admin, 2);
    let mut forged = signed_call(
        &personal.identity,
        &phone.admin,
        admin.session,
        admin.next,
        PERSONAL,
        method("commit"),
        update.encode(),
    );
    forged.signature[0] ^= 1;
    assert_eq!(
        ask(
            &mut personal.stream,
            Kind::Call,
            Mark::Onion,
            &(personal.agent, forged).encode()
        ),
        Response::Rejected(Rejected::BadSignature)
    );
    let (call, answer) = personal.call(&mut admin, "commit", update.encode());
    let candidacy: Candidacy = outcome(answer).unwrap();
    assert_eq!(candidacy.set, vec![0]);
    // The evidence, posted under the sync key: the call as signed.
    let message = call.message(&personal.identity);
    let posted: Recorded = personal
        .answer(
            &mut sync,
            "evidence",
            (
                (candidacy.index, message),
                (call.signature, None::<Vec<u8>>),
            ),
        )
        .unwrap();
    // A device reads the log and checks the evidence itself.
    let entries: Vec<(u64, Entry)> = personal.query(&phone.sync, "log", candidacy.index).unwrap();
    let Body::Candidate { call: logged, .. } = &entries[0].1.body else {
        panic!("{:?}", entries[0]);
    };
    let evidence = entries
        .iter()
        .find(|(index, _)| *index == posted.index)
        .expect("the evidence entry");
    let Body::Evidence {
        index,
        message,
        signature,
        ..
    } = &evidence.1.body
    else {
        panic!("{evidence:?}");
    };
    assert_eq!(*index, candidacy.index);
    let admin_key = ed25519_dalek::VerifyingKey::from_bytes(&logged.origin).unwrap();
    admin_key
        .verify(message, &Signature::from_bytes(signature))
        .expect("the admin key signed it");
    let signed = CallMessage::parse(message).expect("a call's message");
    assert_eq!(signed.arguments, logged.arguments);
    assert_eq!(signed.identity, personal.identity);
}

/// A device whose removal matured keeps the session it holds, as a key
/// admitted no more does, and the agent refuses its calls there; it
/// creates no other.
#[test]
fn a_removed_device_keeps_its_session_and_the_agent_refuses_it() {
    let mut personal = Personal::start();
    let (phone, tablet) = (Keys::of(31), Keys::of(32));
    personal.home("configure", policy());
    personal.home("assign", (phone.device(), kit()));
    let mut admin = personal.signer(&phone.admin, 2);
    let add = (
        (
            1u64,
            Effect {
                add: Some(tablet.device()),
                remove: Vec::new(),
            },
        ),
        (vec![0x11_u8; 1374], None::<[u8; 32]>),
    );
    let candidacy: Candidacy = personal
        .admitted(&mut admin, "commit", add.encode())
        .unwrap();
    let mut sync = personal.signer(&phone.sync, 1);
    personal
        .admitted::<Voted>(
            &mut sync,
            "confirm",
            ((1u64, [1u8; 32]), [0u8; 64]).encode(),
        )
        .unwrap();
    assert_eq!(candidacy.set, vec![0]);
    let mut theirs = personal.signer(&tablet.sync, 1);
    let pushed: Pushed = personal
        .admitted(&mut theirs, "push", envelope(1, 1, 500).encode())
        .unwrap();
    assert_eq!(pushed.position, 1);
    personal.pass(60_000);
    personal
        .answer::<Recorded>(&mut admin, "remove", 1u32)
        .unwrap();
    personal.pass(2 * 60_000);
    personal.answer::<Recorded>(&mut sync, "alive", ()).unwrap();
    // Its session goes on; the agent refuses it there.
    assert_eq!(
        personal.answer::<Pushed>(&mut theirs, "push", envelope(1, 2, 500)),
        Err(PersonalError::NotAdmitted)
    );
    let mut other = personal.signer(&tablet.sync, 2);
    assert_eq!(personal.call(&mut other, "alive", Vec::new()).1, unknown());
    assert_eq!(
        personal.query::<Vec<Envelope>>(&tablet.sync, "since", ([7u8; 16], 0u64)),
        Err(PersonalError::NotAdmitted)
    );
}

/// A push and its read, round trip over the socket through the onion's
/// mark, for a small envelope and a largest one: the time each takes, and
/// the node's store grown an envelope.
#[test]
fn a_push_and_its_read_round_trip() {
    let mut personal = Personal::start();
    let phone = Keys::of(41);
    personal.home("assign", (phone.device(), kit()));
    let mut sync = personal.signer(&phone.sync, 1);
    personal
        .admitted::<Recorded>(&mut sync, "alive", Vec::new())
        .unwrap();
    for (len, rounds) in [(1usize << 10, 200u64), (60 << 10, 50)] {
        let started = Instant::now();
        let mut pushing = Duration::ZERO;
        for round in 0..rounds {
            let bytes = envelope(0, (len as u64) << 20 | round, len);
            let at = Instant::now();
            let pushed: Pushed = personal.answer(&mut sync, "push", bytes.clone()).unwrap();
            pushing += at.elapsed();
            let read: Vec<Envelope> = personal
                .query(&phone.sync, "since", ([7u8; 16], pushed.position - 1))
                .unwrap();
            assert_eq!(read[0].bytes, bytes);
        }
        let took = started.elapsed();
        eprintln!(
            "{rounds} envelopes of {len} B: a push and its read {:?}, the push alone {:?}",
            took / rounds as u32,
            pushing / rounds as u32,
        );
    }
}
