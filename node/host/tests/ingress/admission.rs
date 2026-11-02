//! An agent's admission at ingress, on the gated test actor
//! (`#[actor(known_keys, onion_only)]`) and its door, an agent that asks
//! nothing: an unknown key's session attempts refused before any
//! verification, writing nothing; a key admitted by another agent's
//! message creating its session, once its replica applied it; a key no
//! longer admitted keeping its session; and every kind that reads the
//! agent refused without the gateway's onion mark, a clearnet one or none,
//! over the socket and QUIC. The installs that would leave the agent's row
//! naming no declaring actor fail.

use std::io::Write;
use std::os::unix::net::UnixStream;

use vos_api::{Framing, Kind, Mark, marked};
use vos_checker::programs::package;
use vos_node::client::{signed_call, signed_query};
use vos_node::{CallError, Reply};
use vos_wire::abi::Failure;
use vos_wire::ids::derive_id;
use vos_wire::ingress::{AdmissionRefusal, CredentialPublic, Credentialed};
use vos_wire::schema::Schema;

use super::api::{connect, receive};
use super::*;

/// The gated actor's instance in its agent, and the door's in its own.
const GATED: InstanceId = InstanceId(1);
const DOOR: InstanceId = InstanceId(1);
/// The session attempts an unknown key makes.
const ATTEMPTS: usize = 10_000;

fn method(name: &str) -> MethodId {
    MethodId(derive_id("vos/method/", name))
}

fn refused(refusal: AdmissionRefusal) -> Response {
    Response::Rejected(Rejection::Admission(refusal))
}

/// A node serving its socket with the gated agent and the door's.
struct Gates {
    served: Served,
    gated: AgentId,
    door: AgentId,
    /// The gated agent's identity, which its calls are signed for.
    identity: [u8; 32],
}

impl Gates {
    fn start() -> Self {
        Self::on(Served::plain())
    }

    /// The two agents, made on `served`'s node.
    fn on(served: Served) -> Self {
        let node = &served.node;
        let gated = node.create_agent().unwrap();
        installed(smol::block_on(node.install(
            gated,
            GATED,
            &package("gated"),
            Vec::new(),
        )));
        let door = node.create_agent().unwrap();
        installed(smol::block_on(node.install(
            door,
            DOOR,
            &package("door"),
            Vec::new(),
        )));
        // The agent's record is no read of its state: any transport.
        let identity = served.client(1).identity(gated).unwrap();
        Self {
            served,
            gated,
            door,
            identity,
        }
    }

    /// A call by `key` at `sequence` of its session `name`, signed.
    fn call(
        &self,
        key: &SigningKey,
        name: u8,
        sequence: u64,
        method_name: &str,
        arguments: Vec<u8>,
    ) -> Vec<u8> {
        let session = Session {
            key: key.verifying_key().to_bytes(),
            name: [name; 16],
            t0: self.served.now(),
        };
        let call = signed_call(
            &self.identity,
            key,
            session,
            sequence,
            GATED,
            method(method_name),
            arguments,
        );
        (self.gated, call).encode()
    }

    /// A count query by `key`, signed.
    fn query(&self, key: &SigningKey) -> Vec<u8> {
        let query = signed_query(
            &self.identity,
            key,
            self.served.now() + 10_000,
            Consistency::Applied { at: 0 },
            GATED,
            method("count"),
            Vec::new(),
        );
        (self.gated, query).encode()
    }

    /// The door's call admitting `key` to the gated agent, by a client of
    /// the door.
    fn admit(&self, key: &SigningKey) {
        let arguments = (self.gated.0, GATED.0, key.verifying_key().to_bytes()).encode();
        let answer = self
            .served
            .client(2)
            .call(self.door, DOOR, method("admit"), &arguments)
            .unwrap();
        assert!(matches!(answer, Response::Ran { .. }), "{answer:?}");
    }

    /// The count, read through the onion.
    fn count(&self, stream: &mut UnixStream) -> u64 {
        let answer = ask(
            stream,
            Kind::Query,
            Mark::Onion,
            &self.query(&SigningKey::from_bytes(&[9; 32])),
        );
        done(answer)
    }

    /// The gated agent's applied index on the node.
    fn applied(&self) -> u64 {
        self.served
            .node
            .store()
            .snapshot()
            .applied(self.gated)
            .unwrap()
            .unwrap_or(0)
    }
}

/// The node's signature verifications so far.
fn verifications(node: &Node) -> u64 {
    let stats = node.stats();
    let verify = stats
        .stages
        .iter()
        .find(|stage| stage.name == "verify")
        .expect("the verify stage");
    verify.counts.iter().sum()
}

fn send(stream: &mut UnixStream, kind: Kind, mark: Mark, id: u64, body: &[u8]) {
    stream
        .write_all(&marked(Framing::Stream, kind as u16, mark, id, body))
        .unwrap();
}

/// A request of `kind` marked `mark` holding `body`: its answer.
fn ask(stream: &mut UnixStream, kind: Kind, mark: Mark, body: &[u8]) -> Response {
    send(stream, kind, mark, 1, body);
    let (answered, id, body) = receive(stream).expect("an answer");
    assert_eq!((answered, id), (kind as u16, 1));
    Response::decode_exact(&body).expect("a response")
}

/// An unknown key's 10^4 session attempts, every one a session of its
/// own, signed with no valid signature, through the onion: each refused
/// `UnknownKey`, none verified, and the agent's state not moved by one
/// write. A signature check would have answered `BadSignature`.
#[test]
fn an_unknown_keys_session_attempts_cost_no_verification_and_write_nothing() {
    let gates = Gates::start();
    let mut stream = connect(&gates.served.socket);
    let stranger = SigningKey::from_bytes(&[66; 32]);
    let count = gates.count(&mut stream);
    let (verified, applied) = (verifications(&gates.served.node), gates.applied());
    let started = Instant::now();
    // Written a batch at a time, under the connection's requests in flight.
    for batch in 0..ATTEMPTS / 500 {
        for at in 0..500 {
            let attempt = (batch * 500 + at) as u64;
            let session = Session {
                key: stranger.verifying_key().to_bytes(),
                name: {
                    let mut name = [0u8; 16];
                    name[..8].copy_from_slice(&attempt.to_le_bytes());
                    name
                },
                t0: gates.served.now(),
            };
            let call = Call {
                session,
                sequence: 1,
                instance: GATED,
                method: method("bump"),
                arguments: Vec::new(),
                signature: [attempt as u8; 64],
            };
            send(
                &mut stream,
                Kind::Call,
                Mark::Onion,
                attempt + 10,
                &(gates.gated, call).encode(),
            );
        }
        for _ in 0..500 {
            let (kind, id, body) = receive(&mut stream).expect("an answer");
            assert_eq!(kind, Kind::Call as u16);
            assert!(id >= 10);
            assert_eq!(
                Response::decode_exact(&body),
                Some(refused(AdmissionRefusal::UnknownKey))
            );
        }
    }
    let took = started.elapsed();
    eprintln!(
        "{ATTEMPTS} refused session attempts in {took:?}, {:?} each",
        took / ATTEMPTS as u32
    );
    assert_eq!(
        verifications(&gates.served.node),
        verified,
        "no verification"
    );
    assert_eq!(gates.applied(), applied, "nothing applied");
    assert_eq!(gates.count(&mut stream), count, "no bump ran");
    let session = Session {
        key: stranger.verifying_key().to_bytes(),
        name: [0; 16],
        t0: gates.served.now(),
    };
    let snapshot = gates.served.node.store().snapshot();
    assert_eq!(
        snapshot
            .get(gates.gated, &keys::session_index(&session))
            .unwrap(),
        None
    );
    assert_eq!(
        snapshot
            .get(gates.gated, &keys::key_sessions(&session.key))
            .unwrap(),
        None,
        "no session of the key"
    );
}

/// A key the door admits creates its session once the gated agent applied
/// the door's message, refused `UnknownKey` until then; a key no longer
/// admitted keeps the session it holds and creates no other.
#[test]
fn an_admitted_key_creates_its_session_and_a_revoked_one_keeps_it() {
    let gates = Gates::start();
    let mut stream = connect(&gates.served.socket);
    let member = SigningKey::from_bytes(&[67; 32]);
    let first = |gates: &Gates| gates.call(&member, 1, 1, "bump", Vec::new());
    assert_eq!(
        ask(&mut stream, Kind::Call, Mark::Onion, &first(&gates)),
        refused(AdmissionRefusal::UnknownKey)
    );
    gates.admit(&member);
    // The client retries until the replica applied the admission.
    let mut answer = refused(AdmissionRefusal::UnknownKey);
    wait_until("the admission applied", || {
        answer = ask(&mut stream, Kind::Call, Mark::Onion, &first(&gates));
        answer != refused(AdmissionRefusal::UnknownKey)
    });
    assert_eq!(done(answer), 1);
    let call = gates.call(&member, 1, 2, "bump", Vec::new());
    assert_eq!(done(ask(&mut stream, Kind::Call, Mark::Onion, &call)), 2);
    // Its own session revokes it: the session goes on, no other starts.
    let revoke = gates.call(
        &member,
        1,
        3,
        "revoke",
        member.verifying_key().to_bytes().encode(),
    );
    assert!(matches!(
        ask(&mut stream, Kind::Call, Mark::Onion, &revoke),
        Response::Ran { .. }
    ));
    let call = gates.call(&member, 1, 4, "bump", Vec::new());
    assert_eq!(done(ask(&mut stream, Kind::Call, Mark::Onion, &call)), 3);
    let other = gates.call(&member, 2, 1, "bump", Vec::new());
    assert_eq!(
        ask(&mut stream, Kind::Call, Mark::Onion, &other),
        refused(AdmissionRefusal::UnknownKey)
    );
}

/// Every kind that reads the onion-only agent, a call, a query, a
/// workflow read, a credentialed call and its schema, refused over the
/// clearnet and unmarked, before its signature or proof; through the onion
/// the call and the query run. The door's agent asks nothing.
#[test]
fn an_onion_only_agent_refuses_clearnet_and_unmarked_requests() {
    let gates = Gates::start();
    let mut stream = connect(&gates.served.socket);
    let member = SigningKey::from_bytes(&[68; 32]);
    gates.admit(&member);
    let reader = SigningKey::from_bytes(&[69; 32]);
    let read = WorkflowRead {
        key: reader.verifying_key().to_bytes(),
        not_after: gates.served.now() + 10_000,
        consistency: Consistency::Applied { at: 0 },
        workflow: WorkflowId(1),
        wait_ms: 0,
        signature: [0; 64],
    };
    let credentialed = Credentialed {
        instance: GATED,
        method: method("bump"),
        arguments: Vec::new(),
        nonce: [1; 16],
        expires_ms: gates.served.now() + 10_000,
        format: 0,
        public: CredentialPublic::Owner {
            owner: [2; 32],
            binding: [3; 32],
        },
        proof: vec![0; 64],
    };
    let requests = [
        (Kind::Call, gates.call(&member, 1, 1, "bump", Vec::new())),
        (Kind::Query, gates.query(&reader)),
        (Kind::Workflow, (gates.gated, read).encode()),
        (Kind::Credentialed, (gates.gated, credentialed).encode()),
    ];
    let verified = verifications(&gates.served.node);
    for mark in [Mark::Unmarked, Mark::Clearnet] {
        for (kind, body) in &requests {
            assert_eq!(
                ask(&mut stream, *kind, mark, body),
                refused(AdmissionRefusal::OnionOnly),
                "{kind:?} {mark:?}"
            );
        }
        send(
            &mut stream,
            Kind::Schema,
            mark,
            1,
            &(gates.gated, GATED).encode(),
        );
        let (_, _, body) = receive(&mut stream).unwrap();
        assert_eq!(body, [0], "no schema off the onion, {mark:?}");
    }
    assert_eq!(verifications(&gates.served.node), verified, "none verified");
    // Through the onion: the call runs once its admission applied, the
    // query answers, and the schema reads.
    wait_until("the admission applied", || {
        ask(&mut stream, Kind::Call, Mark::Onion, &requests[0].1)
            != refused(AdmissionRefusal::UnknownKey)
    });
    assert_eq!(gates.count(&mut stream), 1);
    send(
        &mut stream,
        Kind::Schema,
        Mark::Onion,
        1,
        &(gates.gated, GATED).encode(),
    );
    let (_, _, body) = receive(&mut stream).unwrap();
    let schema = Option::<Schema>::decode_exact(&body)
        .unwrap()
        .expect("a schema");
    assert!(schema.admission.known_keys && schema.admission.onion_only);
    // The door's agent asks nothing: unmarked, its schema reads.
    send(
        &mut stream,
        Kind::Schema,
        Mark::Unmarked,
        1,
        &(gates.door, DOOR).encode(),
    );
    let (_, _, body) = receive(&mut stream).unwrap();
    assert!(Option::<Schema>::decode_exact(&body).unwrap().is_some());
}

/// Over QUIC, as a remote gateway relays: unmarked refused, the onion's
/// mark taken.
#[test]
fn the_mark_is_read_over_quic() {
    let (served, address) = super::quic::quic_served(|_| {});
    let gates = Gates::on(served);
    let connection = super::quic::dial(
        &gates.served,
        address,
        super::quic::GATEWAY,
        vos_net::api::ALPN,
    )
    .unwrap();
    let query = gates.query(&SigningKey::from_bytes(&[70; 32]));
    let ask = |mark| {
        let (kind, body) = smol::block_on(vos_api::quic::request(
            &connection,
            Kind::Query as u16,
            mark,
            &query,
        ))
        .unwrap();
        assert_eq!(kind, Kind::Query as u16);
        Response::decode_exact(&body).unwrap()
    };
    assert_eq!(ask(Mark::Unmarked), refused(AdmissionRefusal::OnionOnly));
    assert_eq!(ask(Mark::Clearnet), refused(AdmissionRefusal::OnionOnly));
    assert_eq!(done(ask(Mark::Onion)), 0);
}

/// The agent's row names one declaring actor for good: an install of a
/// second at another instance fails `Admission`, and so does one over the
/// declaring actor of a program that declares none; an install of it over
/// itself runs.
#[test]
fn the_declaring_actor_is_one_and_stays() {
    let gates = Gates::start();
    let node = &gates.served.node;
    let failed = |reply: Result<Reply, CallError>| match reply {
        Ok(Reply::Ran(Outcome::Failed { code, .. })) => code,
        other => panic!("not failed: {other:?}"),
    };
    let second = node.install(gates.gated, InstanceId(2), &package("gated"), Vec::new());
    assert_eq!(failed(smol::block_on(second)), Failure::Admission);
    let over = node.install(gates.gated, GATED, &package("door"), Vec::new());
    assert_eq!(failed(smol::block_on(over)), Failure::Admission);
    installed(smol::block_on(node.install(
        gates.gated,
        GATED,
        &package("gated"),
        Vec::new(),
    )));
}
