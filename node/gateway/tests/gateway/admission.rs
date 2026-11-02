//! The transport mark on the gateway's relay path: two HTTP ports in front
//! of one node, a clearnet one and one marking as the onion service's
//! would, and the onion-only gated test actor behind them. A call over the
//! clearnet port is refused `OnionOnly`, whatever the client sent; over the
//! onion's an unknown key is refused `UnknownKey`, and a key its door
//! admitted runs.

use vos_checker::programs::package;
use vos_wire::ids::derive_id;
use vos_wire::ingress::AdmissionRefusal;

use super::*;

const GATED: InstanceId = InstanceId(1);
const DOOR: InstanceId = InstanceId(1);

fn method(name: &str) -> MethodId {
    MethodId(derive_id("vos/method/", name))
}

#[test]
fn the_gateway_marks_what_it_relays_and_an_onion_only_agent_reads_it() {
    let served = Served::start(PerAddress::default());
    let target = Target::socket(served.socket.clone());
    let operator = Operator::signing(&target, SigningKey::from_bytes(&OPERATOR), served.node.id());
    let agent = |elf: &[u8], instance| {
        let Ok(Response::Created(agent)) = operator.create_agent(Vec::new()) else {
            panic!("an agent")
        };
        installed(operator.install(agent, &install_of(instance, elf)).unwrap());
        agent
    };
    let gated = agent(&package("gated"), GATED);
    let door = agent(&package("door"), DOOR);
    let upstream = || vec![(served.node.id().0, Address::Socket(served.socket.clone()))];
    let onion = Front::start_marked(
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        upstream(),
        PerAddress::default(),
        None,
        Mark::Onion,
    );
    let identity = Client::new(&target, SigningKey::from_bytes(&[1; 32]))
        .identity(gated)
        .unwrap();
    let member = SigningKey::from_bytes(&[71; 32]);
    let call = |sequence| {
        let session = Session {
            key: member.verifying_key().to_bytes(),
            name: [1; 16],
            t0: served.now(),
        };
        let call = signed_call(
            &identity,
            &member,
            session,
            sequence,
            GATED,
            method("bump"),
            Vec::new(),
        );
        call.encode()
    };
    let path = format!("/agents/{}/calls", gated.0);
    let post = |front: &Front, body: &[u8]| {
        let (status, body, _) = exchange(front.address, &request("POST", &path, &[], body));
        (status, Response::decode_exact(&body).expect("a response"))
    };
    let refused = |refusal| (403, Response::Rejected(Rejection::Admission(refusal)));
    // The clearnet port: refused before the key is looked up.
    assert_eq!(
        post(&served.front, &call(1)),
        refused(AdmissionRefusal::OnionOnly)
    );
    // The onion's: the key is unknown until the door admits it.
    assert_eq!(
        post(&onion, &call(1)),
        refused(AdmissionRefusal::UnknownKey)
    );
    let admitted = Client::new(&target, SigningKey::from_bytes(&[2; 32]))
        .call(
            door,
            DOOR,
            method("admit"),
            &(gated.0, GATED.0, member.verifying_key().to_bytes()).encode(),
        )
        .unwrap();
    assert!(matches!(admitted, Response::Ran { .. }), "{admitted:?}");
    let mut answer = refused(AdmissionRefusal::UnknownKey);
    wait_until("the admission applied", || {
        answer = post(&onion, &call(1));
        answer != refused(AdmissionRefusal::UnknownKey)
    });
    assert!(matches!(answer, (200, Response::Ran { .. })), "{answer:?}");
    // Its session held, the clearnet still refuses it.
    assert_eq!(
        post(&served.front, &call(2)),
        refused(AdmissionRefusal::OnionOnly)
    );
    assert!(matches!(
        post(&onion, &call(2)),
        (200, Response::Ran { .. })
    ));
}
