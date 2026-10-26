//! One client over every transport: HTTP, the node API's socket and its
//! QUIC endpoint, its calls in their sequence, its queries, the schema and
//! the node's key; and the operator signing its commands on each, the
//! envelope over HTTP in the `Authorization` header.

use super::quic::{GATEWAY, quic_served};
use super::*;

#[test]
fn a_client_and_an_operator_answer_alike_over_every_transport() {
    let (served, address) = quic_served(|_| {});
    let targets = [
        served.target.clone(),
        Target::socket(served.socket.clone()),
        Target::quic(&format!("quic://{address}"), served.node.id().0, GATEWAY).unwrap(),
    ];
    let mut total = 0;
    for (at, target) in targets.iter().enumerate() {
        assert_eq!(client::node_id(target).unwrap(), served.node.id());
        let schema = client::schema(target, served.agent, COUNTER)
            .unwrap()
            .expect("the schema");
        assert_eq!(schema.method_id("increment"), Some(served.increment));
        let mut client = Client::new(target, SigningKey::from_bytes(&[40 + at as u8; 32]));
        for by in 1..=3u64 {
            total += by;
            let answer = client
                .call(served.agent, COUNTER, served.increment, &by.encode())
                .unwrap();
            assert_eq!(done(answer), total, "{at}");
        }
        assert_eq!(served.value(&client), total);
        let operator =
            Operator::signing(target, SigningKey::from_bytes(&OPERATOR), served.node.id());
        assert!(matches!(
            operator.create_agent(Vec::new()).unwrap(),
            Response::Created(_)
        ));
        assert!(matches!(
            operator.status(served.agent).unwrap(),
            Response::Status(_)
        ));
        assert!(matches!(operator.stats().unwrap(), Response::Stats(_)));
        let stranger =
            Operator::signing(target, SigningKey::from_bytes(&[3; 32]), served.node.id());
        assert_eq!(
            stranger.stats().unwrap(),
            Response::Rejected(Rejection::Unauthorized)
        );
    }
}

/// An operator whose clock is off signs again once, at the node's time
/// its refusal reports.
#[test]
fn an_operator_off_the_nodes_clock_signs_again_at_its_time() {
    let served = Served::plain();
    served.clock.fetch_add(10 * 60_000, Ordering::SeqCst);
    let operator = Operator::signing(
        &Target::socket(served.socket.clone()),
        SigningKey::from_bytes(&OPERATOR),
        served.node.id(),
    );
    assert!(matches!(
        operator.create_agent(Vec::new()).unwrap(),
        Response::Created(_)
    ));
}
