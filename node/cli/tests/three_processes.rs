//! Three `vos node run` processes as one space, over QUIC through the
//! test's relay: an agent on all three takes calls through any of them and
//! sends messages to another, through the leader's SIGKILL and its
//! restart, every call applied once.

mod support;

use ed25519_dalek::SigningKey;
use support::{Options, Processes, guest, wait_until};
use vos_node::client::{Client, Operator};
use vos_node::store::View;
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MethodId};
use vos_wire::ingress::{Answer, Consistency, Install, QueryCall, query_message};
use vos_wire::keys;
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;

const COUNTER: InstanceId = InstanceId(1);
/// The counter instance the other agent's messages increment.
const INBOX: InstanceId = InstanceId(2);

/// An operator's command, at whichever node takes it.
fn at_any(space: &Processes, command: impl Fn(&Operator) -> Answer) -> Answer {
    let mut answer = None;
    wait_until("an operator's command is taken", || {
        for number in 1..=space.count {
            if !space.is_running(number) {
                continue;
            }
            if let done @ (Answer::Ran { .. } | Answer::Created(_)) =
                command(&space.operator(number))
            {
                answer = Some(done);
                return true;
            }
        }
        false
    });
    answer.unwrap()
}

fn method(schema: &Schema, name: &str) -> MethodId {
    schema
        .methods
        .iter()
        .find(|method| method.name == name.as_bytes())
        .unwrap_or_else(|| panic!("no method {name}"))
        .id
}

fn done(answer: &Answer) -> Option<u64> {
    match answer {
        Answer::Ran {
            outcome: Outcome::Done(bytes),
            ..
        } => Some(vos_wire::Decode::decode(bytes).unwrap().0),
        _ => None,
    }
}

#[test]
fn three_processes_apply_every_call_once_through_a_kill() {
    let space = Processes::start(3, Options::default());
    let counter = std::fs::read(guest(
        "test-actors/target/riscv64em-vos/release/counter.elf",
    ))
    .unwrap();
    let counter = vos_pvm_compiler::link_elf_spi(&counter).expect("links");
    let create = |space: &Processes| {
        let Answer::Created(agent) = at_any(space, |operator| {
            operator.create_agent(vec![1, 2, 3]).unwrap()
        }) else {
            unreachable!()
        };
        for instance in [INBOX, COUNTER] {
            let install = Install {
                instance,
                program: counter.clone(),
                attestables: Vec::new(),
                roles: Vec::new(),
            };
            at_any(space, |operator| operator.install(agent, &install).unwrap());
        }
        agent
    };
    let (sender, receiver) = (create(&space), create(&space));
    let mut client = Client::new(space.target(1), SigningKey::from_bytes(&[21; 32]));
    let schema = client.schema(sender, COUNTER).unwrap().unwrap();
    let (increment, forward, value) = (
        method(&schema, "increment"),
        method(&schema, "forward"),
        method(&schema, "value"),
    );
    // Each call goes again, with its sequence, until it is answered.
    let call = |client: &mut Client, method: MethodId, arguments: Vec<u8>| -> u64 {
        let mut answered = None;
        wait_until("a call is answered", || {
            answered = client
                .call(sender, COUNTER, method, &arguments)
                .ok()
                .as_ref()
                .and_then(done);
            answered.is_some()
        });
        answered.unwrap()
    };
    let (mut total, mut forwarded) = (0, 0);
    // One node down at a time, so a quorum stays.
    let mut down = None;
    for request in 1..=60u64 {
        match request {
            // Right after a forward was answered, its message may still
            // be unacknowledged: the sender's leader is killed, then the
            // receiver's.
            21 => down = Some(space.leader(sender)),
            41 => down = Some(space.leader(receiver)),
            31 | 51 => {
                space.restart(down.take().expect("a node down"));
            }
            _ => {}
        }
        if let Some(number) = down.filter(|number| space.is_running(*number)) {
            space.kill(number);
        }
        if request.is_multiple_of(4) {
            let by = request * 10;
            assert_eq!(
                call(&mut client, forward, (receiver.0, INBOX.0, by).encode()),
                by
            );
            forwarded += by;
        } else {
            total += request;
            assert_eq!(call(&mut client, increment, request.encode()), total);
        }
    }
    // Every node holds every call once, and every message once: read at
    // each node itself, which a failover to another would hide.
    let key = SigningKey::from_bytes(&[23; 32]);
    let identities = [
        (sender, client.identity(sender).unwrap()),
        (receiver, client.identity(receiver).unwrap()),
    ];
    for number in 1..=3 {
        let read = |agent: AgentId, instance: InstanceId| {
            let identity = identities
                .iter()
                .find(|(id, _)| *id == agent)
                .map(|(_, identity)| *identity)
                .unwrap();
            let not_after = vos_node::wall_clock() + 60_000;
            let public = key.verifying_key().to_bytes();
            let consistency = Consistency::Linearizable;
            let message = query_message(
                &identity,
                &public,
                not_after,
                consistency,
                instance,
                value,
                &[],
            );
            let query = QueryCall {
                key: public,
                not_after,
                consistency,
                instance,
                method: value,
                arguments: Vec::new(),
                signature: ed25519_dalek::Signer::sign(&key, &message).to_bytes(),
            };
            let path = format!("/agents/{}/queries", agent.0);
            let (_, body) =
                vos_node::client::post(space.target(number), &path, &query.encode()).ok()?;
            let (answer, _) = <Answer as vos_wire::Decode>::decode(&body).ok()?;
            done(&answer)
        };
        wait_until("every node converges", || {
            read(sender, COUNTER) == Some(total) && read(receiver, INBOX) == Some(forwarded)
        });
    }
    // Each forward's message applied once at each replica, and was sent
    // once: their pair's marks, on disk, once the nodes stopped.
    let forwards = (1..=60u64)
        .filter(|request| request.is_multiple_of(4))
        .count() as u64;
    for number in 1..=3 {
        space.kill(number);
    }
    for number in 1..=3 {
        let store = vos_node::store::Fjall::open(space.data(number).join("store")).unwrap();
        let mark = |agent: AgentId, key: &[u8]| {
            let bytes = vos_node::store::Store::snapshot(&store)
                .get(agent, key)
                .unwrap()
                .unwrap();
            let value = vos_wire::records::unstored(&bytes).unwrap();
            <u64 as vos_wire::Decode>::decode(value).unwrap().0
        };
        assert_eq!(mark(receiver, &keys::pair_in(sender)), forwards);
        assert_eq!(mark(sender, &keys::pair_out(receiver)), forwards);
    }
}
